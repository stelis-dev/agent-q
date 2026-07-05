#include "sui_zklogin_proposal_state.h"

#include <string.h>

#include "mbedtls/sha256.h"
#include "protocol/json_input.h"
#include "protocol/base64.h"
#include "protocol_input_encoding.h"
#include "sensitive_memory.h"
#include "transport/timeout_window.h"

extern "C" {
#include "byte_conversions.h"
}

namespace stopwatch_target {
namespace {

constexpr size_t kBase64ZkLoginPublicKeyMaxChars =
    ((kSuiZkLoginPublicKeyMaxBytes + 2) / 3) * 4;
constexpr size_t kDecodedClaimMaxBytes = 384;

struct SuiZkLoginProposalState {
    bool active = false;
    SuiZkLoginProposalStage stage = SuiZkLoginProposalStage::idle;
    char request_id[signing::kRequestIdSize] = {};
    char session_id[kSessionIdSize] = {};
    signing::TimeoutWindow request_window = signing::kTimeoutWindowNone;
    SuiZkLoginCredentialRecord record = {};

    void clear()
    {
        wipe_sensitive_buffer(&record, sizeof(record));
        memset(this, 0, sizeof(*this));
        stage = SuiZkLoginProposalStage::idle;
    }
};

SuiZkLoginProposalState g_state;
SuiZkLoginCredentialRecord g_begin_record = {};

void clear_credential_record(SuiZkLoginCredentialRecord* record)
{
    if (record != nullptr) {
        wipe_sensitive_buffer(record, sizeof(*record));
    }
}

const char* json_string_or_null(JsonVariantConst value)
{
    const char* output = nullptr;
    if (!signing::json_value_c_string(value, &output)) {
        return nullptr;
    }
    return output;
}

bool copy_nonempty_limited(const char* input, char* output, size_t output_size)
{
    if (input == nullptr || output == nullptr || output_size == 0) {
        return false;
    }
    const size_t length = strlen(input);
    if (length == 0 || length >= output_size) {
        return false;
    }
    memcpy(output, input, length + 1);
    return true;
}

bool string_eq(const char* left, const char* right)
{
    return left != nullptr && right != nullptr && strcmp(left, right) == 0;
}

bool object_has_only_keys(JsonObjectConst object, const char* const* keys, size_t key_count)
{
    return signing::json_object_fields_supported(object, keys, key_count);
}

bool base64url_char_bits(char c, uint8_t bits[6])
{
    const char* alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const char* found = strchr(alphabet, c);
    if (found == nullptr || bits == nullptr) {
        return false;
    }
    const uint8_t value = static_cast<uint8_t>(found - alphabet);
    for (size_t index = 0; index < 6; ++index) {
        bits[index] = static_cast<uint8_t>((value >> (5 - index)) & 1);
    }
    return true;
}

bool decode_tightly_packed_base64url(
    const char* value,
    uint8_t index_mod4,
    char* output,
    size_t output_size)
{
    if (value == nullptr || output == nullptr || output_size == 0 ||
        index_mod4 > 2) {
        return false;
    }
    output[0] = '\0';
    const size_t input_length = strlen(value);
    if (input_length < 2 || input_length >= kSuiZkLoginIssBase64BufferSize) {
        return false;
    }

    uint8_t bits[kSuiZkLoginIssBase64BufferSize * 6] = {};
    size_t bit_count = 0;
    for (size_t char_index = 0; char_index < input_length; ++char_index) {
        uint8_t char_bits[6] = {};
        if (!base64url_char_bits(value[char_index], char_bits)) {
            return false;
        }
        memcpy(bits + bit_count, char_bits, sizeof(char_bits));
        bit_count += sizeof(char_bits);
    }

    size_t start_bit = 0;
    if (index_mod4 == 1) {
        start_bit = 2;
    } else if (index_mod4 == 2) {
        start_bit = 4;
    }
    const uint8_t last_offset =
        static_cast<uint8_t>((index_mod4 + input_length - 1) % 4);
    size_t trim_end = 0;
    if (last_offset == 3) {
        trim_end = 0;
    } else if (last_offset == 2) {
        trim_end = 2;
    } else if (last_offset == 1) {
        trim_end = 4;
    } else {
        return false;
    }
    if (start_bit + trim_end > bit_count) {
        return false;
    }
    bit_count -= trim_end;
    const size_t payload_bits = bit_count - start_bit;
    if (payload_bits == 0 || (payload_bits % 8) != 0) {
        return false;
    }
    const size_t byte_count = payload_bits / 8;
    if (byte_count == 0 || byte_count >= output_size ||
        byte_count > kDecodedClaimMaxBytes) {
        return false;
    }
    for (size_t byte_index = 0; byte_index < byte_count; ++byte_index) {
        uint8_t byte = 0;
        for (size_t bit_index = 0; bit_index < 8; ++bit_index) {
            byte = static_cast<uint8_t>(
                (byte << 1) | bits[start_bit + byte_index * 8 + bit_index]);
        }
        if (byte < 0x20 || byte > 0x7E) {
            return false;
        }
        output[byte_index] = static_cast<char>(byte);
    }
    output[byte_count] = '\0';
    return true;
}

bool copy_json_string_value(
    const char* json,
    const char* prefix,
    char* output,
    size_t output_size)
{
    if (json == nullptr || prefix == nullptr || output == nullptr || output_size == 0) {
        return false;
    }
    output[0] = '\0';
    const size_t prefix_len = strlen(prefix);
    if (strncmp(json, prefix, prefix_len) != 0) {
        return false;
    }
    const char* cursor = json + prefix_len;
    size_t offset = 0;
    while (*cursor != '\0' && *cursor != '"') {
        const char c = *cursor++;
        if (c == '\\') {
            return false;
        }
        if (offset + 1 >= output_size) {
            return false;
        }
        output[offset++] = c;
    }
    if (*cursor != '"') {
        return false;
    }
    ++cursor;
    if (*cursor != ',' && *cursor != '}') {
        return false;
    }
    output[offset] = '\0';
    return offset > 0;
}

bool extract_issuer(
    const SuiZkLoginIssBase64Details& details,
    char* issuer,
    size_t issuer_size)
{
    char claim[kDecodedClaimMaxBytes + 1] = {};
    if (!decode_tightly_packed_base64url(
            details.value,
            details.index_mod4,
            claim,
            sizeof(claim))) {
        return false;
    }
    char extracted[kSuiZkLoginIssuerBufferSize] = {};
    if (!copy_json_string_value(claim, "\"iss\":\"", extracted, sizeof(extracted))) {
        return false;
    }
    const char* normalized =
        strcmp(extracted, "accounts.google.com") == 0
            ? "https://accounts.google.com"
            : extracted;
    return copy_nonempty_limited(normalized, issuer, issuer_size);
}

bool parse_proof_point_string(JsonVariantConst value, char* output, size_t output_size)
{
    const char* text = json_string_or_null(value);
    if (!copy_nonempty_limited(text, output, output_size)) {
        return false;
    }
    if (text[0] == '0' && text[1] != '\0') {
        return false;
    }
    for (const char* cursor = text; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9') {
            return false;
        }
    }
    return true;
}

bool parse_proof_point_array(
    JsonVariantConst value,
    size_t expected_count,
    char output[][kSuiZkLoginProofPointBufferSize])
{
    if (!value.is<JsonArrayConst>()) {
        return false;
    }
    JsonArrayConst array = value.as<JsonArrayConst>();
    if (array.size() != expected_count) {
        return false;
    }
    for (size_t index = 0; index < expected_count; ++index) {
        if (!parse_proof_point_string(
                array[index],
                output[index],
                kSuiZkLoginProofPointBufferSize)) {
            return false;
        }
    }
    return true;
}

bool parse_proof_points(JsonVariantConst value, SuiZkLoginProofPoints* output)
{
    if (output == nullptr || !value.is<JsonObjectConst>()) {
        return false;
    }
    JsonObjectConst object = value.as<JsonObjectConst>();
    constexpr const char* kKeys[] = {"a", "b", "c"};
    if (!object_has_only_keys(object, kKeys, 3) ||
        !parse_proof_point_array(
            object["a"],
            kSuiZkLoginProofPointACount,
            output->a) ||
        !parse_proof_point_array(
            object["c"],
            kSuiZkLoginProofPointCCount,
            output->c) ||
        !object["b"].is<JsonArrayConst>()) {
        return false;
    }
    JsonArrayConst b = object["b"].as<JsonArrayConst>();
    if (b.size() != kSuiZkLoginProofPointBOuterCount) {
        return false;
    }
    for (size_t row = 0; row < kSuiZkLoginProofPointBOuterCount; ++row) {
        if (!parse_proof_point_array(
                b[row],
                kSuiZkLoginProofPointBInnerCount,
                output->b[row])) {
            return false;
        }
    }
    return true;
}

bool parse_inputs(JsonVariantConst value, SuiZkLoginSignatureInputs* output)
{
    if (output == nullptr || !value.is<JsonObjectConst>()) {
        return false;
    }
    JsonObjectConst object = value.as<JsonObjectConst>();
    constexpr const char* kKeys[] = {
        "proofPoints",
        "issBase64Details",
        "headerBase64",
        "addressSeed",
    };
    if (!object_has_only_keys(object, kKeys, 4) ||
        !parse_proof_points(object["proofPoints"], &output->proof_points) ||
        !copy_nonempty_limited(
            json_string_or_null(object["headerBase64"]),
            output->header_base64,
            sizeof(output->header_base64)) ||
        !copy_nonempty_limited(
            json_string_or_null(object["addressSeed"]),
            output->address_seed,
            sizeof(output->address_seed)) ||
        !object["issBase64Details"].is<JsonObjectConst>()) {
        return false;
    }
    JsonObjectConst details = object["issBase64Details"].as<JsonObjectConst>();
    constexpr const char* kDetailKeys[] = {"value", "indexMod4"};
    if (!object_has_only_keys(details, kDetailKeys, 2) ||
        !copy_nonempty_limited(
            json_string_or_null(details["value"]),
            output->iss_base64_details.value,
            sizeof(output->iss_base64_details.value)) ||
        !details["indexMod4"].is<uint8_t>()) {
        return false;
    }
    const uint8_t index_mod4 = details["indexMod4"].as<uint8_t>();
    if (index_mod4 > 2) {
        return false;
    }
    output->iss_base64_details.index_mod4 = index_mod4;
    return true;
}

bool append_hash_string(mbedtls_sha256_context* context, const char* value)
{
    static const uint8_t kSep = 0;
    return context != nullptr &&
           value != nullptr &&
           mbedtls_sha256_update(context, reinterpret_cast<const uint8_t*>(value), strlen(value)) == 0 &&
           mbedtls_sha256_update(context, &kSep, 1) == 0;
}

bool append_hash_proof_points(
    mbedtls_sha256_context* context,
    const SuiZkLoginProofPoints& points)
{
    for (size_t index = 0; index < kSuiZkLoginProofPointACount; ++index) {
        if (!append_hash_string(context, points.a[index])) {
            return false;
        }
    }
    for (size_t row = 0; row < kSuiZkLoginProofPointBOuterCount; ++row) {
        for (size_t column = 0; column < kSuiZkLoginProofPointBInnerCount; ++column) {
            if (!append_hash_string(context, points.b[row][column])) {
                return false;
            }
        }
    }
    for (size_t index = 0; index < kSuiZkLoginProofPointCCount; ++index) {
        if (!append_hash_string(context, points.c[index])) {
            return false;
        }
    }
    return true;
}

bool compute_proof_hash(SuiZkLoginProofRecord* record)
{
    if (record == nullptr) {
        return false;
    }
    uint8_t digest[32] = {};
    mbedtls_sha256_context context;
    mbedtls_sha256_init(&context);
    const bool ok =
        mbedtls_sha256_starts(&context, 0) == 0 &&
        append_hash_string(&context, "signing.sui.zklogin.proof.v0") &&
        append_hash_string(&context, record->network) &&
        append_hash_string(&context, record->address) &&
        append_hash_string(&context, record->issuer) &&
        append_hash_string(&context, record->address_seed) &&
        append_hash_string(&context, record->max_epoch) &&
        append_hash_string(&context, record->inputs.header_base64) &&
        append_hash_string(&context, record->inputs.iss_base64_details.value) &&
        append_hash_proof_points(&context, record->inputs.proof_points) &&
        mbedtls_sha256_finish(&context, digest) == 0;
    mbedtls_sha256_free(&context);
    if (!ok) {
        return false;
    }
    constexpr const char* kPrefix = "sha256:";
    memcpy(record->proof_hash, kPrefix, 7);
    bytes_to_hex(digest, sizeof(digest), record->proof_hash + 7);
    wipe_sensitive_buffer(digest, sizeof(digest));
    return true;
}

bool parse_public_key(const char* base64, SuiZkLoginProofRecord* record)
{
    if (base64 == nullptr || record == nullptr) {
        return false;
    }
    size_t decoded_size = 0;
    if (!decode_canonical_base64_input(
            base64,
            kBase64ZkLoginPublicKeyMaxChars,
            record->public_key,
            sizeof(record->public_key),
            &decoded_size) ||
        decoded_size < kSuiZkLoginPublicKeyMinBytes ||
        decoded_size > kSuiZkLoginPublicKeyMaxBytes) {
        return false;
    }
    record->public_key_size = decoded_size;
    return true;
}

SuiZkLoginProposalBeginResult parse_params(
    JsonVariantConst params,
    SuiZkLoginProofRecord* record)
{
    if (record == nullptr || !params.is<JsonObjectConst>()) {
        return SuiZkLoginProposalBeginResult::invalid_argument;
    }
    memset(record, 0, sizeof(*record));
    JsonObjectConst object = params.as<JsonObjectConst>();
    constexpr const char* kKeys[] = {
        "chain",
        "credential",
        "network",
        "address",
        "publicKey",
        "maxEpoch",
        "inputs",
    };
    if (!object_has_only_keys(object, kKeys, 7) ||
        !string_eq(json_string_or_null(object["chain"]), "sui") ||
        !string_eq(json_string_or_null(object["credential"]), "zklogin") ||
        !copy_nonempty_limited(
            json_string_or_null(object["network"]),
            record->network,
            sizeof(record->network)) ||
        !copy_nonempty_limited(
            json_string_or_null(object["address"]),
            record->address,
            sizeof(record->address)) ||
        !copy_nonempty_limited(
            json_string_or_null(object["maxEpoch"]),
            record->max_epoch,
            sizeof(record->max_epoch)) ||
        !parse_public_key(json_string_or_null(object["publicKey"]), record) ||
        !parse_inputs(object["inputs"], &record->inputs) ||
        !copy_nonempty_limited(
            record->inputs.address_seed,
            record->address_seed,
            sizeof(record->address_seed)) ||
        !extract_issuer(
            record->inputs.iss_base64_details,
            record->issuer,
            sizeof(record->issuer))) {
        memset(record, 0, sizeof(*record));
        return SuiZkLoginProposalBeginResult::invalid_proof;
    }
    if (!compute_proof_hash(record)) {
        memset(record, 0, sizeof(*record));
        return SuiZkLoginProposalBeginResult::encode_error;
    }
    if (!validate_sui_zklogin_proof_record(record)) {
        memset(record, 0, sizeof(*record));
        return SuiZkLoginProposalBeginResult::invalid_proof;
    }
    return SuiZkLoginProposalBeginResult::ok;
}

bool valid_request_and_session(const char* request_id, const char* session_id)
{
    return request_id != nullptr &&
           signing::request_id_format_valid(request_id) &&
           session_id_format_valid(session_id);
}

}  // namespace

void sui_zklogin_proposal_state_init()
{
    sui_zklogin_proposal_state_clear();
}

bool sui_zklogin_proposal_state_active()
{
    return g_state.active;
}

void sui_zklogin_proposal_state_clear()
{
    g_state.clear();
}

SuiZkLoginProposalSnapshot sui_zklogin_proposal_state_snapshot()
{
    return SuiZkLoginProposalSnapshot{
        g_state.active,
        g_state.stage,
        g_state.request_id,
        g_state.session_id,
        g_state.request_window,
        g_state.record.proof.address,
        g_state.record.proof.network,
        g_state.record.proof.issuer,
        g_state.record.proof.max_epoch,
        g_state.record.proof.proof_hash,
    };
}

SuiZkLoginProposalBeginResult sui_zklogin_proposal_state_begin(
    JsonVariantConst params,
    const char* request_id,
    const char* session_id,
    uint32_t now_ms,
    signing::TimeoutWindow request_window,
    const uint8_t prepared_seed[kSuiEd25519SeedBytes])
{
    g_state.clear();
    if (!valid_request_and_session(request_id, session_id) ||
        prepared_seed == nullptr) {
        return SuiZkLoginProposalBeginResult::invalid_argument;
    }
    if (!signing::timeout_window_valid_and_open_at(request_window, now_ms)) {
        return SuiZkLoginProposalBeginResult::invalid_argument;
    }
    clear_credential_record(&g_begin_record);
    memcpy(g_begin_record.prepared_seed, prepared_seed, kSuiEd25519SeedBytes);
    const SuiZkLoginProposalBeginResult parse_result =
        parse_params(params, &g_begin_record.proof);
    if (parse_result != SuiZkLoginProposalBeginResult::ok) {
        clear_credential_record(&g_begin_record);
        return parse_result;
    }
    if (!validate_sui_zklogin_credential_record(&g_begin_record)) {
        clear_credential_record(&g_begin_record);
        return SuiZkLoginProposalBeginResult::invalid_proof;
    }

    memcpy(&g_state.record, &g_begin_record, sizeof(g_state.record));
    clear_credential_record(&g_begin_record);
    strlcpy(g_state.request_id, request_id, sizeof(g_state.request_id));
    strlcpy(g_state.session_id, session_id, sizeof(g_state.session_id));
    g_state.request_window = request_window;
    g_state.stage = SuiZkLoginProposalStage::reviewing;
    g_state.active = true;
    return SuiZkLoginProposalBeginResult::ok;
}

SuiZkLoginProposalTransitionResult sui_zklogin_proposal_continue_to_auth(
    uint32_t now_ms)
{
    if (!g_state.active) {
        return SuiZkLoginProposalTransitionResult::inactive;
    }
    if (g_state.stage != SuiZkLoginProposalStage::reviewing) {
        return SuiZkLoginProposalTransitionResult::wrong_stage;
    }
    if (signing::timeout_window_reached(g_state.request_window, now_ms)) {
        return SuiZkLoginProposalTransitionResult::timed_out;
    }
    g_state.stage = SuiZkLoginProposalStage::auth_entry;
    return SuiZkLoginProposalTransitionResult::ok;
}

SuiZkLoginProposalTransitionResult sui_zklogin_proposal_return_to_review(
    uint32_t now_ms)
{
    if (!g_state.active) {
        return SuiZkLoginProposalTransitionResult::inactive;
    }
    if (g_state.stage != SuiZkLoginProposalStage::auth_entry) {
        return SuiZkLoginProposalTransitionResult::wrong_stage;
    }
    if (signing::timeout_window_reached(g_state.request_window, now_ms)) {
        return SuiZkLoginProposalTransitionResult::timed_out;
    }
    g_state.stage = SuiZkLoginProposalStage::reviewing;
    return SuiZkLoginProposalTransitionResult::ok;
}

SuiZkLoginProposalTransitionResult sui_zklogin_proposal_mark_auth_verifying()
{
    if (!g_state.active) {
        return SuiZkLoginProposalTransitionResult::inactive;
    }
    if (g_state.stage != SuiZkLoginProposalStage::auth_entry) {
        return SuiZkLoginProposalTransitionResult::wrong_stage;
    }
    g_state.stage = SuiZkLoginProposalStage::auth_verifying;
    return SuiZkLoginProposalTransitionResult::ok;
}

SuiZkLoginProposalTransitionResult sui_zklogin_proposal_return_to_auth_entry()
{
    if (!g_state.active) {
        return SuiZkLoginProposalTransitionResult::inactive;
    }
    if (g_state.stage != SuiZkLoginProposalStage::auth_verifying) {
        return SuiZkLoginProposalTransitionResult::wrong_stage;
    }
    g_state.stage = SuiZkLoginProposalStage::auth_entry;
    return SuiZkLoginProposalTransitionResult::ok;
}

bool sui_zklogin_proposal_deadline_reached(uint32_t now_ms)
{
    return g_state.active &&
           signing::timeout_window_reached(g_state.request_window, now_ms);
}

SuiZkLoginProposalTerminalResult sui_zklogin_proposal_record_rejected()
{
    return g_state.active
               ? SuiZkLoginProposalTerminalResult::rejected
               : SuiZkLoginProposalTerminalResult::invalid_state;
}

SuiZkLoginProposalTerminalResult sui_zklogin_proposal_record_timed_out()
{
    return g_state.active
               ? SuiZkLoginProposalTerminalResult::timed_out
               : SuiZkLoginProposalTerminalResult::invalid_state;
}

SuiZkLoginProposalTerminalResult sui_zklogin_proposal_record_ui_error()
{
    return g_state.active
               ? SuiZkLoginProposalTerminalResult::ui_error
               : SuiZkLoginProposalTerminalResult::invalid_state;
}

SuiZkLoginProposalTerminalResult sui_zklogin_proposal_record_consistency_error()
{
    return g_state.active
               ? SuiZkLoginProposalTerminalResult::consistency_error
               : SuiZkLoginProposalTerminalResult::invalid_state;
}

SuiZkLoginProposalTerminalResult sui_zklogin_proposal_commit()
{
    if (!g_state.active ||
        g_state.stage != SuiZkLoginProposalStage::auth_verifying) {
        return SuiZkLoginProposalTerminalResult::invalid_state;
    }
    g_state.stage = SuiZkLoginProposalStage::committing;
    switch (store_sui_zklogin_credential(&g_state.record)) {
        case SuiZkLoginCredentialWriteResult::stored:
            return SuiZkLoginProposalTerminalResult::activated;
        case SuiZkLoginCredentialWriteResult::storage_error:
            return SuiZkLoginProposalTerminalResult::storage_error;
        case SuiZkLoginCredentialWriteResult::consistency_error:
            return SuiZkLoginProposalTerminalResult::consistency_error;
        case SuiZkLoginCredentialWriteResult::invalid_record:
        default:
            return SuiZkLoginProposalTerminalResult::invalid_proof;
    }
}

}  // namespace stopwatch_target
