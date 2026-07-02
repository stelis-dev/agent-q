#include "sui_zklogin_proof_store.h"

#include <string.h>

#include "bip39.h"
#include "sui_account_store.h"
#include "sui_network.h"
#include "numeric/u64_decimal.h"
#include "esp_err.h"
#include "esp_log.h"
#include "nvs.h"

extern "C" {
#include "byte_conversions.h"
#include "lib/monocypher/monocypher.h"
}

namespace signing {
namespace {

constexpr const char* kTag = "SuiZkLogin";
constexpr const char* kNvsNamespace = "signing";
constexpr const char* kProofRecordKey = "sui_zkl_proof";
constexpr uint8_t kStoredRecordMagic[4] = {'A', 'Q', 'Z', 'L'};
constexpr uint8_t kStoredRecordVersion = 0;
constexpr const char* kMaxU256Decimal =
    "115792089237316195423570985008687907853269984665640564039457584007913129639935";

struct StoredSuiZkLoginProofRecord {
    uint8_t magic[4];
    uint8_t version;
    uint8_t public_key_size_be[2];
    uint8_t reserved;
    char network[kSuiNetworkBufferSize];
    char address[kSuiAddressBufferSize];
    uint8_t public_key[kSuiZkLoginPublicKeyMaxBytes];
    char issuer[kSuiZkLoginIssuerBufferSize];
    char address_seed[kSuiZkLoginAddressSeedBufferSize];
    char max_epoch[kSuiZkLoginMaxEpochBufferSize];
    SuiZkLoginSignatureInputs inputs;
    char proof_hash[kSuiZkLoginProofHashBufferSize];
};

static_assert(
    sizeof(StoredSuiZkLoginProofRecord) <= kSuiZkLoginProofRecordMaxBytes,
    "Sui zkLogin proof record must stay within the Step 0 storage cap");

void clear_record(SuiZkLoginProofRecord* record)
{
    if (record != nullptr) {
        memset(record, 0, sizeof(*record));
    }
}

void clear_identity(SuiActiveIdentity* identity)
{
    if (identity != nullptr) {
        memset(identity, 0, sizeof(*identity));
        identity->kind = SuiActiveIdentityKind::error;
        identity->error = SuiActiveIdentityError::native_account_unavailable;
    }
}

void set_u16_be(uint16_t value, uint8_t out[2])
{
    out[0] = static_cast<uint8_t>((value >> 8) & 0xFF);
    out[1] = static_cast<uint8_t>(value & 0xFF);
}

uint16_t read_u16_be(const uint8_t in[2])
{
    return static_cast<uint16_t>((static_cast<uint16_t>(in[0]) << 8) | in[1]);
}

bool bounded_c_string_length(const char* value, size_t max_chars, size_t* out)
{
    if (value == nullptr || out == nullptr) {
        return false;
    }
    for (size_t index = 0; index <= max_chars; ++index) {
        if (value[index] == '\0') {
            *out = index;
            return true;
        }
    }
    return false;
}

bool exact_c_string_length(const char* value, size_t expected)
{
    size_t length = 0;
    return bounded_c_string_length(value, expected, &length) && length == expected;
}

bool is_lower_hex(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

bool is_valid_sui_address(const char* value)
{
    if (value == nullptr ||
        !exact_c_string_length(value, kSuiAddressBufferSize - 1) ||
        value[0] != '0' ||
        value[1] != 'x') {
        return false;
    }
    for (size_t index = 2; index < kSuiAddressBufferSize - 1; ++index) {
        if (!is_lower_hex(value[index])) {
            return false;
        }
    }
    return true;
}

bool is_valid_proof_hash(const char* value)
{
    constexpr const char* kPrefix = "sha256:";
    constexpr size_t kPrefixSize = 7;
    if (value == nullptr ||
        !exact_c_string_length(value, kSuiZkLoginProofHashBufferSize - 1) ||
        memcmp(value, kPrefix, kPrefixSize) != 0) {
        return false;
    }
    for (size_t index = kPrefixSize; index < kSuiZkLoginProofHashBufferSize - 1; ++index) {
        if (!is_lower_hex(value[index])) {
            return false;
        }
    }
    return true;
}

bool is_base64url_no_padding_char(char c)
{
    return (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           c == '-' ||
           c == '_';
}

bool is_base64url_no_padding_string(const char* value, size_t max_chars)
{
    size_t length = 0;
    if (!bounded_c_string_length(value, max_chars, &length) || length == 0) {
        return false;
    }
    for (size_t index = 0; index < length; ++index) {
        if (!is_base64url_no_padding_char(value[index])) {
            return false;
        }
    }
    return true;
}

bool is_canonical_decimal_string_with_max(const char* value, size_t max_digits)
{
    size_t length = 0;
    if (!bounded_c_string_length(value, max_digits, &length) || length == 0) {
        return false;
    }
    if (length > 1 && value[0] == '0') {
        return false;
    }
    for (size_t index = 0; index < length; ++index) {
        if (value[index] < '0' || value[index] > '9') {
            return false;
        }
    }
    return true;
}

bool decimal_string_lte(const char* left, const char* right)
{
    if (left == nullptr || right == nullptr) {
        return false;
    }
    const size_t left_len = strlen(left);
    const size_t right_len = strlen(right);
    if (left_len != right_len) {
        return left_len < right_len;
    }
    return strcmp(left, right) <= 0;
}

bool is_canonical_u256_decimal_string(const char* value)
{
    return is_canonical_decimal_string_with_max(
               value,
               kSuiZkLoginAddressSeedBufferSize - 1) &&
           decimal_string_lte(value, kMaxU256Decimal);
}

bool parse_u256_decimal_to_be32(const char* value, uint8_t out[32])
{
    if (out != nullptr) {
        memset(out, 0, 32);
    }
    if (value == nullptr || out == nullptr || !is_canonical_u256_decimal_string(value)) {
        return false;
    }

    for (const char* cursor = value; *cursor != '\0'; ++cursor) {
        uint16_t carry = static_cast<uint16_t>(*cursor - '0');
        for (int index = 31; index >= 0; --index) {
            const uint16_t updated =
                static_cast<uint16_t>(out[index]) * 10u + carry;
            out[index] = static_cast<uint8_t>(updated & 0xFF);
            carry = static_cast<uint16_t>(updated >> 8);
        }
        if (carry != 0) {
            memset(out, 0, 32);
            return false;
        }
    }
    return true;
}

bool validate_proof_points(const SuiZkLoginProofPoints& points)
{
    for (size_t index = 0; index < kSuiZkLoginProofPointACount; ++index) {
        if (!is_canonical_decimal_string_with_max(
                points.a[index],
                kSuiZkLoginProofPointBufferSize - 1)) {
            return false;
        }
    }
    for (size_t row = 0; row < kSuiZkLoginProofPointBOuterCount; ++row) {
        for (size_t column = 0; column < kSuiZkLoginProofPointBInnerCount; ++column) {
            if (!is_canonical_decimal_string_with_max(
                    points.b[row][column],
                    kSuiZkLoginProofPointBufferSize - 1)) {
                return false;
            }
        }
    }
    for (size_t index = 0; index < kSuiZkLoginProofPointCCount; ++index) {
        if (!is_canonical_decimal_string_with_max(
                points.c[index],
                kSuiZkLoginProofPointBufferSize - 1)) {
            return false;
        }
    }
    return true;
}

bool validate_inputs(const SuiZkLoginSignatureInputs& inputs, const char* address_seed)
{
    return validate_proof_points(inputs.proof_points) &&
           inputs.iss_base64_details.index_mod4 <= 2 &&
           is_base64url_no_padding_string(
               inputs.iss_base64_details.value,
               kSuiZkLoginIssBase64BufferSize - 1) &&
           is_base64url_no_padding_string(
               inputs.header_base64,
               kSuiZkLoginHeaderBase64BufferSize - 1) &&
           is_canonical_u256_decimal_string(inputs.address_seed) &&
           address_seed != nullptr &&
           strcmp(inputs.address_seed, address_seed) == 0;
}

bool validate_public_identifier(const SuiZkLoginProofRecord& record)
{
    if (record.public_key_size < kSuiZkLoginPublicKeyMinBytes ||
        record.public_key_size > kSuiZkLoginPublicKeyMaxBytes ||
        record.public_key[0] != kSuiSignatureSchemeFlagZkLogin) {
        return false;
    }

    const size_t issuer_len = record.public_key[1];
    const size_t expected_size = 2 + issuer_len + 32;
    if (record.public_key_size != expected_size) {
        return false;
    }

    size_t stored_issuer_len = 0;
    if (!bounded_c_string_length(
            record.issuer,
            kSuiZkLoginIssuerBufferSize - 1,
            &stored_issuer_len) ||
        stored_issuer_len != issuer_len ||
        memcmp(record.public_key + 2, record.issuer, issuer_len) != 0) {
        return false;
    }

    uint8_t address_seed[32] = {};
    if (!parse_u256_decimal_to_be32(record.address_seed, address_seed)) {
        return false;
    }
    const bool seed_matches =
        memcmp(record.public_key + 2 + issuer_len, address_seed, sizeof(address_seed)) == 0;
    wipe_sensitive_buffer(address_seed, sizeof(address_seed));
    if (!seed_matches) {
        return false;
    }

    char derived_address[kSuiAddressBufferSize] = {};
    return derive_sui_address_from_scheme_prefixed_public_key(
               record.public_key,
               record.public_key_size,
               derived_address,
               sizeof(derived_address)) &&
           strcmp(derived_address, record.address) == 0;
}

bool record_to_stored(
    const SuiZkLoginProofRecord& record,
    StoredSuiZkLoginProofRecord* stored)
{
    if (stored == nullptr || !validate_sui_zklogin_proof_record(&record)) {
        return false;
    }
    memset(stored, 0, sizeof(*stored));
    memcpy(stored->magic, kStoredRecordMagic, sizeof(kStoredRecordMagic));
    stored->version = kStoredRecordVersion;
    set_u16_be(static_cast<uint16_t>(record.public_key_size), stored->public_key_size_be);
    memcpy(stored->network, record.network, sizeof(stored->network));
    memcpy(stored->address, record.address, sizeof(stored->address));
    memcpy(stored->public_key, record.public_key, record.public_key_size);
    memcpy(stored->issuer, record.issuer, sizeof(stored->issuer));
    memcpy(stored->address_seed, record.address_seed, sizeof(stored->address_seed));
    memcpy(stored->max_epoch, record.max_epoch, sizeof(stored->max_epoch));
    memcpy(&stored->inputs, &record.inputs, sizeof(stored->inputs));
    memcpy(stored->proof_hash, record.proof_hash, sizeof(stored->proof_hash));
    return true;
}

bool stored_to_record(
    const StoredSuiZkLoginProofRecord& stored,
    SuiZkLoginProofRecord* record)
{
    if (record == nullptr) {
        return false;
    }
    clear_record(record);
    if (memcmp(stored.magic, kStoredRecordMagic, sizeof(kStoredRecordMagic)) != 0 ||
        stored.version != kStoredRecordVersion ||
        stored.reserved != 0) {
        return false;
    }

    const uint16_t public_key_size = read_u16_be(stored.public_key_size_be);
    if (public_key_size > kSuiZkLoginPublicKeyMaxBytes) {
        return false;
    }

    memcpy(record->network, stored.network, sizeof(record->network));
    memcpy(record->address, stored.address, sizeof(record->address));
    memcpy(record->public_key, stored.public_key, public_key_size);
    record->public_key_size = public_key_size;
    memcpy(record->issuer, stored.issuer, sizeof(record->issuer));
    memcpy(record->address_seed, stored.address_seed, sizeof(record->address_seed));
    memcpy(record->max_epoch, stored.max_epoch, sizeof(record->max_epoch));
    memcpy(&record->inputs, &stored.inputs, sizeof(record->inputs));
    memcpy(record->proof_hash, stored.proof_hash, sizeof(record->proof_hash));
    if (!validate_sui_zklogin_proof_record(record)) {
        clear_record(record);
        return false;
    }
    return true;
}

SuiZkLoginProofRecordStatus read_stored_record(
    StoredSuiZkLoginProofRecord* stored,
    bool log_failures)
{
    if (stored == nullptr) {
        return SuiZkLoginProofRecordStatus::storage_error;
    }
    memset(stored, 0, sizeof(*stored));

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READONLY, &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return SuiZkLoginProofRecordStatus::missing;
    }
    if (result != ESP_OK) {
        if (log_failures) {
            ESP_LOGW(kTag, "NVS open failed while reading zkLogin proof: %s", esp_err_to_name(result));
        }
        return SuiZkLoginProofRecordStatus::storage_error;
    }

    size_t blob_size = 0;
    result = nvs_get_blob(nvs, kProofRecordKey, nullptr, &blob_size);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return SuiZkLoginProofRecordStatus::missing;
    }
    if (result != ESP_OK) {
        nvs_close(nvs);
        if (log_failures) {
            ESP_LOGW(kTag, "zkLogin proof size read failed: %s", esp_err_to_name(result));
        }
        return SuiZkLoginProofRecordStatus::storage_error;
    }
    if (blob_size != sizeof(*stored)) {
        nvs_close(nvs);
        return SuiZkLoginProofRecordStatus::invalid;
    }

    result = nvs_get_blob(nvs, kProofRecordKey, stored, &blob_size);
    nvs_close(nvs);
    if (result != ESP_OK || blob_size != sizeof(*stored)) {
        memset(stored, 0, sizeof(*stored));
        if (log_failures) {
            ESP_LOGW(kTag, "zkLogin proof read failed: %s", esp_err_to_name(result));
        }
        return SuiZkLoginProofRecordStatus::storage_error;
    }
    return SuiZkLoginProofRecordStatus::active;
}

bool write_stored_record(const StoredSuiZkLoginProofRecord& stored)
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while storing zkLogin proof: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_set_blob(nvs, kProofRecordKey, &stored, sizeof(stored));
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "zkLogin proof write failed: %s", esp_err_to_name(result));
        return false;
    }
    return true;
}

}  // namespace

bool derive_sui_address_from_scheme_prefixed_public_key(
    const uint8_t* public_key,
    size_t public_key_size,
    char* address_out,
    size_t address_out_size)
{
    if (address_out != nullptr && address_out_size > 0) {
        memset(address_out, 0, address_out_size);
    }
    if (public_key == nullptr || public_key_size == 0 ||
        address_out == nullptr || address_out_size < kSuiAddressBufferSize) {
        return false;
    }

    uint8_t address[32] = {};
    crypto_blake2b(address, sizeof(address), public_key, public_key_size);
    address_out[0] = '0';
    address_out[1] = 'x';
    bytes_to_hex(address, sizeof(address), address_out + 2);
    wipe_sensitive_buffer(address, sizeof(address));
    return true;
}

bool validate_sui_zklogin_proof_record(const SuiZkLoginProofRecord* record)
{
    return record != nullptr &&
           sui_network_supported(record->network) &&
           is_valid_sui_address(record->address) &&
           is_canonical_u256_decimal_string(record->address_seed) &&
           is_canonical_u64_decimal_string(record->max_epoch) &&
           validate_inputs(record->inputs, record->address_seed) &&
           is_valid_proof_hash(record->proof_hash) &&
           validate_public_identifier(*record);
}

SuiZkLoginProofRecordStatus sui_zklogin_proof_record_status()
{
    StoredSuiZkLoginProofRecord stored = {};
    const SuiZkLoginProofRecordStatus status = read_stored_record(&stored, false);
    if (status != SuiZkLoginProofRecordStatus::active) {
        return status;
    }
    SuiZkLoginProofRecord record = {};
    return stored_to_record(stored, &record)
               ? SuiZkLoginProofRecordStatus::active
               : SuiZkLoginProofRecordStatus::invalid;
}

SuiZkLoginProofRecordStatus read_sui_zklogin_proof_record(
    SuiZkLoginProofRecord* out)
{
    clear_record(out);
    if (out == nullptr) {
        return SuiZkLoginProofRecordStatus::storage_error;
    }

    StoredSuiZkLoginProofRecord stored = {};
    const SuiZkLoginProofRecordStatus status = read_stored_record(&stored, true);
    if (status != SuiZkLoginProofRecordStatus::active) {
        return status;
    }
    if (!stored_to_record(stored, out)) {
        return SuiZkLoginProofRecordStatus::invalid;
    }
    return SuiZkLoginProofRecordStatus::active;
}

SuiZkLoginProofRecordWriteResult store_sui_zklogin_proof_record(
    const SuiZkLoginProofRecord* record)
{
    if (!validate_sui_zklogin_proof_record(record)) {
        return SuiZkLoginProofRecordWriteResult::invalid_record;
    }

    StoredSuiZkLoginProofRecord stored = {};
    if (!record_to_stored(*record, &stored)) {
        return SuiZkLoginProofRecordWriteResult::invalid_record;
    }
    if (!write_stored_record(stored)) {
        return SuiZkLoginProofRecordWriteResult::storage_error;
    }

    StoredSuiZkLoginProofRecord readback = {};
    if (read_stored_record(&readback, true) != SuiZkLoginProofRecordStatus::active ||
        memcmp(&readback, &stored, sizeof(stored)) != 0) {
        return SuiZkLoginProofRecordWriteResult::consistency_error;
    }
    return SuiZkLoginProofRecordWriteResult::stored;
}

bool wipe_sui_zklogin_proof_record()
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return true;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while wiping zkLogin proof: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_erase_key(nvs, kProofRecordKey);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return true;
    }
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "zkLogin proof wipe failed: %s", esp_err_to_name(result));
        return false;
    }
    return true;
}

SuiActiveIdentity resolve_active_sui_identity()
{
    SuiActiveIdentity identity = {};
    clear_identity(&identity);

    SuiZkLoginProofRecord proof = {};
    const SuiZkLoginProofRecordStatus proof_status =
        read_sui_zklogin_proof_record(&proof);
    if (proof_status == SuiZkLoginProofRecordStatus::active) {
        identity.kind = SuiActiveIdentityKind::zklogin;
        identity.error = SuiActiveIdentityError::none;
        memcpy(identity.address, proof.address, sizeof(identity.address));
        memcpy(identity.public_key, proof.public_key, proof.public_key_size);
        identity.public_key_size = proof.public_key_size;
        memcpy(&identity.zklogin, &proof, sizeof(identity.zklogin));
        return identity;
    }
    if (proof_status == SuiZkLoginProofRecordStatus::invalid ||
        proof_status == SuiZkLoginProofRecordStatus::storage_error) {
        identity.kind = SuiActiveIdentityKind::error;
        identity.error = SuiActiveIdentityError::proof_storage_error;
        return identity;
    }

    uint8_t raw_public_key[kSuiEd25519PublicKeyBytes] = {};
    char address[kSuiAddressBufferSize] = {};
    const SuiAccountDerivationResult account_result =
        derive_sui_ed25519_account_from_stored_root(
            raw_public_key,
            address,
            sizeof(address));
    if (account_result != SuiAccountDerivationResult::ok) {
        wipe_sensitive_buffer(raw_public_key, sizeof(raw_public_key));
        identity.kind = SuiActiveIdentityKind::error;
        identity.error = SuiActiveIdentityError::native_account_unavailable;
        return identity;
    }

    identity.kind = SuiActiveIdentityKind::native;
    identity.error = SuiActiveIdentityError::none;
    memcpy(identity.address, address, sizeof(identity.address));
    identity.public_key[0] = kSuiSignatureSchemeFlagEd25519;
    memcpy(identity.public_key + 1, raw_public_key, sizeof(raw_public_key));
    identity.public_key_size = kSuiSchemePrefixedEd25519PublicKeyBytes;
    wipe_sensitive_buffer(raw_public_key, sizeof(raw_public_key));
    return identity;
}

}  // namespace signing
