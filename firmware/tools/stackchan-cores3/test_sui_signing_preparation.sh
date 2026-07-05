#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
COMMON_SUI_DIR="${COMMON_ROOT}/sui"
FIXTURE_DIR="${COMMON_SUI_DIR}/testdata/sui_transaction_facts"
COVERAGE_MATRIX="${COMMON_SUI_DIR}/testdata/sui_transaction_authorization_coverage.tsv"
DEFAULT_RUNTIME_DIR="${REPO_ROOT}/.firmware-cache/signing-crypto/microsui-lib"
CRYPTO_ROOT="${SIGNING_CRYPTO_ROOT:-${DEFAULT_RUNTIME_DIR}}"
MICROSUI_CORE="${CRYPTO_ROOT}/src/microsui_core"
CXX_BIN="${CXX:-c++}"
CC_BIN="${CC:-cc}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-sui-signing-preparation.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/firmware_common"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/firmware_common/policy"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/firmware_common/sui"

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fstream>
#include <map>
#include <string>
#include <vector>

#include "sui_signing_preparation.h"
#include "sui_account_store.h"
#include "sui_signing_authority.h"
#include "sui_zklogin_proof_store.h"

extern "C" {
#include "byte_conversions.h"
}

namespace {

bool g_digest_ok = true;
signing::SuiAccountDerivationResult g_derivation_result =
    signing::SuiAccountDerivationResult::ok;
signing::SuiActiveIdentityKind g_active_identity_kind =
    signing::SuiActiveIdentityKind::native;
signing::SuiActiveIdentityError g_active_identity_error =
    signing::SuiActiveIdentityError::none;
char g_derived_address[signing::kSuiAddressBufferSize] =
    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
char g_zklogin_network[signing::kSuiNetworkBufferSize] = "devnet";
bool g_read_account_settings_ok = true;
signing::SuiAccountSettings g_account_settings = {false};

int hex_value(char value)
{
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return 10 + value - 'a';
    }
    if (value >= 'A' && value <= 'F') {
        return 10 + value - 'A';
    }
    return -1;
}

std::vector<uint8_t> read_hex(const char* path)
{
    FILE* file = fopen(path, "rb");
    assert(file != nullptr);
    std::string hex;
    int ch = 0;
    while ((ch = fgetc(file)) != EOF) {
        if (!isspace(ch)) {
            hex.push_back(static_cast<char>(ch));
        }
    }
    fclose(file);
    assert((hex.size() % 2) == 0);
    std::vector<uint8_t> bytes(hex.size() / 2);
    for (size_t index = 0; index < bytes.size(); ++index) {
        const int high = hex_value(hex[index * 2]);
        const int low = hex_value(hex[index * 2 + 1]);
        assert(high >= 0 && low >= 0);
        bytes[index] = static_cast<uint8_t>((high << 4) | low);
    }
    return bytes;
}

std::string base64(const std::vector<uint8_t>& bytes)
{
    std::string out(((bytes.size() + 2) / 3) * 4 + 1, '\0');
    assert(bytes_to_base64(bytes.data(), bytes.size(), out.data(), out.size()) == 0);
    out.resize(strlen(out.c_str()));
    return out;
}

std::vector<std::string> split_tabs(const std::string& line)
{
    std::vector<std::string> parts;
    size_t offset = 0;
    while (true) {
        const size_t tab = line.find('\t', offset);
        if (tab == std::string::npos) {
            parts.push_back(line.substr(offset));
            return parts;
        }
        parts.push_back(line.substr(offset, tab - offset));
        offset = tab + 1;
    }
}

struct MatrixRow {
    std::map<std::string, std::string> fields;
};

const std::string& field(const MatrixRow& row, const char* name)
{
    const auto found = row.fields.find(name);
    assert(found != row.fields.end());
    return found->second;
}

std::vector<MatrixRow> read_matrix(const std::string& path)
{
    std::ifstream input(path);
    assert(input.good());
    std::vector<std::string> headers;
    std::vector<MatrixRow> rows;
    std::string line;
    while (std::getline(input, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        std::vector<std::string> columns = split_tabs(line);
        if (headers.empty()) {
            headers = columns;
            assert(!headers.empty() && headers[0] == "fixture");
            continue;
        }
        assert(columns.size() == headers.size());
        MatrixRow row;
        for (size_t index = 0; index < headers.size(); ++index) {
            row.fields[headers[index]] = columns[index];
        }
        rows.push_back(row);
    }
    assert(!rows.empty());
    return rows;
}

signing::SuiUserAuthorizationOutcome expected_user_authorization_outcome(
    const MatrixRow& row)
{
    const std::string& user_gate = field(row, "expected_user_gate_after_adapter");
    if (user_gate == "ok_review_pending") {
        return signing::SuiUserAuthorizationOutcome::offline_facts_review;
    }
    if (user_gate == "blind_signing_confirmation") {
        return signing::SuiUserAuthorizationOutcome::blind_signing;
    }
    return signing::SuiUserAuthorizationOutcome::unavailable;
}

signing::SuiPolicyAuthorizationOutcome expected_policy_authorization_outcome(
    const MatrixRow& row)
{
    const std::string& parse_result = field(row, "full_facts_parse_result");
    if (parse_result == "ok") {
        return signing::SuiPolicyAuthorizationOutcome::policy_evaluation;
    }
    return signing::SuiPolicyAuthorizationOutcome::unavailable;
}

const char* preparation_result_outcome(signing::SuiSigningPreparationResult result)
{
    switch (result) {
        case signing::SuiSigningPreparationResult::ok:
            return "ok";
        case signing::SuiSigningPreparationResult::malformed_transaction:
            return "malformed_transaction";
        case signing::SuiSigningPreparationResult::unsupported_transaction:
            return "unsupported_transaction";
        case signing::SuiSigningPreparationResult::invalid_account:
            return "invalid_account";
        default:
            return "other_error";
    }
}

std::string user_outcome_for_prepared(
    signing::SuiSigningPreparationResult result,
    const signing::SuiPreparedSignTransaction& prepared)
{
    if (result != signing::SuiSigningPreparationResult::ok) {
        return preparation_result_outcome(result);
    }
    if (!prepared.user_mode_authorization_covered) {
        return "unsupported_transaction";
    }
    if (prepared.user_authorization_outcome ==
        signing::SuiUserAuthorizationOutcome::offline_facts_review) {
        return "offline_facts_review_confirmation";
    }
    if (prepared.user_authorization_outcome ==
        signing::SuiUserAuthorizationOutcome::blind_signing) {
        return "blind_signing_confirmation";
    }
    return "unsupported_transaction";
}

std::string policy_outcome_for_prepared(
    signing::SuiSigningPreparationResult result,
    const signing::SuiPreparedSignTransaction& prepared)
{
    (void)prepared;
    if (result != signing::SuiSigningPreparationResult::ok) {
        return preparation_result_outcome(result);
    }
    return "policy_rejected";
}

void verify_matrix_final_outcomes(const std::string& root, const std::string& matrix_path)
{
    for (const MatrixRow& row : read_matrix(matrix_path)) {
        const std::string fixture = field(row, "fixture");
        const std::vector<uint8_t> bytes = read_hex((root + "/" + fixture + ".bcs.hex").c_str());
        signing::SuiPreparedSignTransaction tx = {};
        const signing::SuiSigningPreparationResult result =
            signing::prepare_sui_sign_transaction(
                signing::SupportedSignRoute::sui_sign_transaction,
                "devnet",
                base64(bytes).c_str(),
                bytes.size(),
                &tx);

        const std::string user_outcome = user_outcome_for_prepared(result, tx);
        const std::string policy_outcome = policy_outcome_for_prepared(result, tx);
        assert(user_outcome == field(row, "final_user_mode_outcome"));
        assert(policy_outcome == field(row, "final_policy_mode_outcome"));
        if (result == signing::SuiSigningPreparationResult::ok) {
            assert(tx.user_authorization_outcome == expected_user_authorization_outcome(row));
            assert(tx.policy_authorization_outcome == expected_policy_authorization_outcome(row));
        }
        signing::clear_prepared_sui_sign_transaction(&tx);
    }
}

}  // namespace

namespace signing {

void wipe_sensitive_buffer(void* data, size_t size)
{
    volatile unsigned char* cursor = static_cast<volatile unsigned char*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

bool approval_history_digest_payload(
    const uint8_t* payload,
    size_t payload_size,
    char* digest_out,
    size_t digest_out_size)
{
    if (!::g_digest_ok || payload == nullptr || payload_size == 0 || digest_out_size < 72) {
        return false;
    }
    snprintf(digest_out, digest_out_size,
             "%s", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    return true;
}

SuiAccountDerivationResult derive_sui_ed25519_account_from_stored_root(
    uint8_t* public_key,
    char* address,
    size_t address_size)
{
    if (::g_derivation_result != SuiAccountDerivationResult::ok) {
        return ::g_derivation_result;
    }
    memset(public_key, 0xA5, kSuiEd25519PublicKeyBytes);
    snprintf(address, address_size, "%s", ::g_derived_address);
    return SuiAccountDerivationResult::ok;
}

SuiActiveIdentity resolve_active_sui_identity()
{
    SuiActiveIdentity identity = {};
    if (::g_active_identity_kind == SuiActiveIdentityKind::error) {
        identity.kind = SuiActiveIdentityKind::error;
        identity.error = ::g_active_identity_error;
        return identity;
    }
    if (::g_derivation_result != SuiAccountDerivationResult::ok) {
        identity.kind = SuiActiveIdentityKind::error;
        identity.error = SuiActiveIdentityError::native_account_unavailable;
        return identity;
    }
    identity.kind = ::g_active_identity_kind;
    identity.error = SuiActiveIdentityError::none;
    snprintf(identity.address, sizeof(identity.address), "%s", ::g_derived_address);
    identity.public_key[0] = identity.kind == SuiActiveIdentityKind::zklogin
                                 ? kSuiSignatureSchemeFlagZkLogin
                                 : kSuiSignatureSchemeFlagEd25519;
    identity.public_key_size = identity.kind == SuiActiveIdentityKind::zklogin
                                   ? kSuiZkLoginPublicKeyMinBytes
                                   : kSuiSchemePrefixedEd25519PublicKeyBytes;
    if (identity.kind == SuiActiveIdentityKind::zklogin) {
        snprintf(identity.zklogin.network, sizeof(identity.zklogin.network), "%s", ::g_zklogin_network);
    }
    return identity;
}

SuiSigningAccountBindingResult verify_sui_signing_active_account_binding(
    const SuiPolicySubjectFacts& facts,
    const SuiActiveIdentity& active_identity,
    const SuiAccountSettings& account_settings)
{
    if (active_identity.kind == SuiActiveIdentityKind::error) {
        return active_identity.error == SuiActiveIdentityError::native_account_unavailable
                   ? SuiSigningAccountBindingResult::account_unavailable
                   : SuiSigningAccountBindingResult::active_identity_unavailable;
    }
    if (strcmp(facts.sender, active_identity.address) != 0) {
        return SuiSigningAccountBindingResult::account_mismatch;
    }
    return strcmp(facts.gas_owner, active_identity.address) == 0 ||
                   account_settings.accept_gas_sponsor
               ? SuiSigningAccountBindingResult::ok
               : SuiSigningAccountBindingResult::account_mismatch;
}

SuiSigningActiveIdentityNetworkResult verify_sui_signing_active_identity_network(
    const SuiActiveIdentity& active_identity,
    const char* request_network)
{
    if (active_identity.kind == SuiActiveIdentityKind::error) {
        return active_identity.error == SuiActiveIdentityError::native_account_unavailable
                   ? SuiSigningActiveIdentityNetworkResult::account_unavailable
                   : SuiSigningActiveIdentityNetworkResult::active_identity_unavailable;
    }
    if (active_identity.kind == SuiActiveIdentityKind::zklogin) {
        if (request_network == nullptr || request_network[0] == '\0') {
            return SuiSigningActiveIdentityNetworkResult::network_mismatch;
        }
        return strcmp(active_identity.zklogin.network, request_network) == 0
                   ? SuiSigningActiveIdentityNetworkResult::ok
                   : SuiSigningActiveIdentityNetworkResult::network_mismatch;
    }
    return active_identity.kind == SuiActiveIdentityKind::native
               ? SuiSigningActiveIdentityNetworkResult::ok
               : SuiSigningActiveIdentityNetworkResult::active_identity_unavailable;
}

SuiSigningActiveIdentityNetworkResult verify_sui_signing_active_identity_network(
    const char* request_network)
{
    return verify_sui_signing_active_identity_network(resolve_active_sui_identity(), request_network);
}

bool read_sui_account_settings(SuiAccountSettings* settings)
{
    if (settings != nullptr) {
        *settings = kDefaultSuiAccountSettings;
    }
    if (!::g_read_account_settings_ok || settings == nullptr) {
        return false;
    }
    *settings = ::g_account_settings;
    return true;
}

}  // namespace signing

int main(int argc, char** argv)
{
    assert(argc == 3);
    const std::string root = argv[1];
    const std::string matrix = argv[2];
    verify_matrix_final_outcomes(root, matrix);

    const std::vector<uint8_t> valid = read_hex((root + "/valid_sui_transfer_tx.bcs.hex").c_str());
    const std::vector<uint8_t> malformed = read_hex((root + "/malformed_short_tx.bcs.hex").c_str());
    const std::vector<uint8_t> result_reference_transfer =
        read_hex((root + "/result_reference_transfer_tx.bcs.hex").c_str());
    const std::vector<uint8_t> publish = read_hex((root + "/publish_tx.bcs.hex").c_str());
    const std::vector<uint8_t> sponsored =
        read_hex((root + "/sponsored_gas_owner_tx.bcs.hex").c_str());

    signing::SuiPreparedSignTransaction tx = {};
    assert(signing::prepare_sui_sign_transaction(
               signing::SupportedSignRoute::sui_sign_transaction,
               "devnet",
               base64(valid).c_str(),
               valid.size(),
               &tx) == signing::SuiSigningPreparationResult::ok);
    assert(tx.tx_bytes_size == valid.size());
    assert(strcmp(tx.network, "devnet") == 0);
    assert(tx.sui_policy_subject.command_count == 2);
    assert(tx.sui_policy_subject.commands[0].kind == signing::SuiCommandFactKind::split_coins);
    assert(tx.sui_policy_subject.commands[1].kind == signing::SuiCommandFactKind::transfer_objects);
    assert(tx.sui_review.status == signing::SuiReviewSummaryStatus::ok);
    assert(tx.sui_review.row_count > 0);
    assert(tx.user_mode_authorization_covered);
    assert(tx.policy_mode_authorization_covered);
    assert(tx.sui_offline_policy_facts != nullptr);
    assert(tx.sui_offline_policy_facts->completeness ==
           signing::SuiOfflinePolicyFactsCompleteness::complete);
    assert(tx.user_authorization_outcome ==
           signing::SuiUserAuthorizationOutcome::offline_facts_review);
    assert(tx.policy_authorization_outcome ==
           signing::SuiPolicyAuthorizationOutcome::policy_evaluation);
    signing::clear_prepared_sui_sign_transaction(&tx);
    assert(tx.tx_bytes_size == 0);
    assert(tx.sui_offline_policy_facts == nullptr);

    assert(signing::prepare_sui_sign_transaction(
               signing::SupportedSignRoute::sui_sign_transaction,
               "devnet",
               base64(malformed).c_str(),
               malformed.size(),
               &tx) == signing::SuiSigningPreparationResult::malformed_transaction);
    assert(signing::prepare_sui_sign_transaction(
               signing::SupportedSignRoute::sui_sign_transaction,
               "devnet",
               base64(result_reference_transfer).c_str(),
               result_reference_transfer.size(),
               &tx) == signing::SuiSigningPreparationResult::ok);
    assert(tx.sui_policy_subject.command_count > 0);
    assert(tx.sui_review.status == signing::SuiReviewSummaryStatus::ok);
    assert(tx.user_mode_authorization_covered);
    assert(tx.policy_mode_authorization_covered);
    assert(tx.user_authorization_outcome ==
           signing::SuiUserAuthorizationOutcome::offline_facts_review);
    assert(tx.policy_authorization_outcome ==
           signing::SuiPolicyAuthorizationOutcome::policy_evaluation);
    signing::clear_prepared_sui_sign_transaction(&tx);
    assert(signing::prepare_sui_sign_transaction(
               signing::SupportedSignRoute::sui_sign_transaction,
               "devnet",
               base64(publish).c_str(),
               publish.size(),
               &tx) == signing::SuiSigningPreparationResult::ok);
    assert(tx.tx_bytes_size == publish.size());
    assert(tx.sui_review.status == signing::SuiReviewSummaryStatus::insufficient_review);
    assert(tx.user_mode_authorization_covered);
    assert(tx.policy_mode_authorization_covered);
    assert(tx.user_authorization_outcome ==
           signing::SuiUserAuthorizationOutcome::blind_signing);
    assert(tx.policy_authorization_outcome ==
           signing::SuiPolicyAuthorizationOutcome::policy_evaluation);
    signing::clear_prepared_sui_sign_transaction(&tx);
    assert(signing::prepare_sui_sign_transaction(
               signing::SupportedSignRoute::sui_sign_transaction,
               "devnet",
               base64(valid).c_str(),
               valid.size() - 1,
               &tx) == signing::SuiSigningPreparationResult::invalid_params);
    assert(signing::prepare_sui_sign_transaction(
               signing::SupportedSignRoute::sui_sign_transaction,
               "devnet",
               base64(valid).c_str(),
               valid.size() + 1,
               &tx) == signing::SuiSigningPreparationResult::invalid_params);
    const std::vector<uint8_t> max_sized_malformed_tx(
        signing::kSuiSignTransactionTxBytesMaxBytes,
        0xA5);
    assert(signing::prepare_sui_sign_transaction(
               signing::SupportedSignRoute::sui_sign_transaction,
               "devnet",
               base64(max_sized_malformed_tx).c_str(),
               max_sized_malformed_tx.size(),
               &tx) == signing::SuiSigningPreparationResult::malformed_transaction);
    const std::vector<uint8_t> oversized_tx(signing::kSuiSignTransactionTxBytesMaxBytes + 1, 0xA5);
    assert(signing::prepare_sui_sign_transaction(
               signing::SupportedSignRoute::sui_sign_transaction,
               "devnet",
               base64(oversized_tx).c_str(),
               oversized_tx.size(),
               &tx) == signing::SuiSigningPreparationResult::payload_too_large);

    assert(signing::prepare_sui_sign_transaction(
               signing::SupportedSignRoute::sui_sign_transaction,
               "devnet",
               base64(sponsored).c_str(),
               sponsored.size(),
               &tx) == signing::SuiSigningPreparationResult::invalid_account);

    ::g_account_settings.accept_gas_sponsor = true;
    assert(signing::prepare_sui_sign_transaction(
               signing::SupportedSignRoute::sui_sign_transaction,
               "devnet",
               base64(sponsored).c_str(),
               sponsored.size(),
               &tx) == signing::SuiSigningPreparationResult::ok);
    assert(strcmp(tx.sui_policy_subject.sender,
                  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0);
    assert(strcmp(tx.sui_policy_subject.gas_owner,
                  "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee") == 0);
    assert(tx.user_mode_authorization_covered);
    assert(tx.user_authorization_outcome ==
           signing::SuiUserAuthorizationOutcome::offline_facts_review);
    assert(tx.policy_mode_authorization_covered);
    assert(tx.policy_authorization_outcome ==
           signing::SuiPolicyAuthorizationOutcome::policy_evaluation);
    assert(tx.sui_offline_policy_facts != nullptr);
    assert(tx.sui_offline_policy_facts->sponsored);
    assert(strcmp(tx.sui_offline_policy_facts->gas_owner,
                  "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee") == 0);
    assert(strcmp(tx.sui_offline_policy_facts->gas_budget_raw, "50000000") == 0);
    assert(strcmp(tx.sui_offline_policy_facts->gas_price_raw, "1000") == 0);
    signing::clear_prepared_sui_sign_transaction(&tx);

    snprintf(::g_derived_address,
             sizeof(::g_derived_address),
             "%s",
             "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    assert(signing::prepare_sui_sign_transaction(
               signing::SupportedSignRoute::sui_sign_transaction,
               "devnet",
               base64(sponsored).c_str(),
               sponsored.size(),
               &tx) == signing::SuiSigningPreparationResult::invalid_account);
    snprintf(::g_derived_address,
             sizeof(::g_derived_address),
             "%s",
             "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    ::g_account_settings.accept_gas_sponsor = false;

    ::g_read_account_settings_ok = false;
    assert(signing::prepare_sui_sign_transaction(
               signing::SupportedSignRoute::sui_sign_transaction,
               "devnet",
               base64(valid).c_str(),
               valid.size(),
               &tx) == signing::SuiSigningPreparationResult::invalid_account);
    ::g_read_account_settings_ok = true;

    snprintf(::g_derived_address,
             sizeof(::g_derived_address),
             "%s",
             "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    assert(signing::prepare_sui_sign_transaction(
               signing::SupportedSignRoute::sui_sign_transaction,
               "devnet",
               base64(valid).c_str(),
               valid.size(),
               &tx) == signing::SuiSigningPreparationResult::invalid_account);
    snprintf(::g_derived_address,
             sizeof(::g_derived_address),
             "%s",
             "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    ::g_active_identity_kind = signing::SuiActiveIdentityKind::error;
    ::g_active_identity_error = signing::SuiActiveIdentityError::proof_storage_error;
    assert(signing::prepare_sui_sign_transaction(
               signing::SupportedSignRoute::sui_sign_transaction,
               "devnet",
               base64(valid).c_str(),
               valid.size(),
               &tx) == signing::SuiSigningPreparationResult::active_identity_unavailable);
    ::g_active_identity_kind = signing::SuiActiveIdentityKind::native;
    ::g_active_identity_error = signing::SuiActiveIdentityError::none;
    assert(signing::verify_sui_signing_active_identity_network(
               signing::resolve_active_sui_identity(),
               nullptr) == signing::SuiSigningActiveIdentityNetworkResult::ok);

    ::g_active_identity_kind = signing::SuiActiveIdentityKind::zklogin;
    snprintf(::g_zklogin_network, sizeof(::g_zklogin_network), "%s", "testnet");
    assert(signing::prepare_sui_sign_transaction(
               signing::SupportedSignRoute::sui_sign_transaction,
               "devnet",
               base64(valid).c_str(),
               valid.size(),
               &tx) == signing::SuiSigningPreparationResult::invalid_network);
    ::g_active_identity_kind = signing::SuiActiveIdentityKind::native;

    ::g_digest_ok = false;
    assert(signing::prepare_sui_sign_transaction(
               signing::SupportedSignRoute::sui_sign_transaction,
               "devnet",
               base64(valid).c_str(),
               valid.size(),
               &tx) == signing::SuiSigningPreparationResult::digest_error);
    ::g_digest_ok = true;

    signing::SuiPreparedPersonalMessage message = {};
    const std::string personal = "SGVsbG8=";
    assert(signing::prepare_sui_sign_personal_message(
               signing::SupportedSignRoute::sui_sign_personal_message,
               "devnet",
               personal.c_str(),
               5,
               &message) == signing::SuiSigningPreparationResult::ok);
    assert(message.message_size == 5);
    assert(strcmp(message.account_address,
                  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0);
    signing::clear_prepared_sui_sign_personal_message(&message);

    ::g_active_identity_kind = signing::SuiActiveIdentityKind::zklogin;
    snprintf(::g_zklogin_network, sizeof(::g_zklogin_network), "%s", "testnet");
    assert(signing::prepare_sui_sign_personal_message(
               signing::SupportedSignRoute::sui_sign_personal_message,
               "devnet",
               personal.c_str(),
               5,
               &message) == signing::SuiSigningPreparationResult::invalid_network);
    snprintf(::g_zklogin_network, sizeof(::g_zklogin_network), "%s", "devnet");
    assert(signing::prepare_sui_sign_personal_message(
               signing::SupportedSignRoute::sui_sign_personal_message,
               "devnet",
               personal.c_str(),
               5,
               &message) == signing::SuiSigningPreparationResult::ok);
    assert(message.message_size == 5);
    assert(strcmp(message.account_address,
                  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0);
    signing::clear_prepared_sui_sign_personal_message(&message);
    ::g_active_identity_kind = signing::SuiActiveIdentityKind::native;

    assert(signing::prepare_sui_sign_personal_message(
               signing::SupportedSignRoute::sui_sign_personal_message,
               "devnet",
               personal.c_str(),
               4,
               &message) == signing::SuiSigningPreparationResult::invalid_params);
    assert(signing::prepare_sui_sign_personal_message(
               signing::SupportedSignRoute::sui_sign_personal_message,
               "devnet",
               personal.c_str(),
               6,
               &message) == signing::SuiSigningPreparationResult::invalid_params);
    const std::vector<uint8_t> oversized_message(signing::kSuiSignPersonalMessageMaxBytes + 1, 0x5A);
    assert(signing::prepare_sui_sign_personal_message(
               signing::SupportedSignRoute::sui_sign_personal_message,
               "devnet",
               base64(oversized_message).c_str(),
               oversized_message.size(),
               &message) == signing::SuiSigningPreparationResult::payload_too_large);

    ::g_derivation_result = signing::SuiAccountDerivationResult::root_material_unavailable;
    assert(signing::prepare_sui_sign_personal_message(
               signing::SupportedSignRoute::sui_sign_personal_message,
               "devnet",
               personal.c_str(),
               5,
               &message) == signing::SuiSigningPreparationResult::account_unavailable);
    return 0;
}
CPP

"${CC_BIN}" -c "${MICROSUI_CORE}/byte_conversions.c" -o "${TMP_DIR}/byte_conversions.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${RUNTIME_DIR}" \
  -I"${TMP_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${COMMON_SUI_DIR}" \
  -I"${MICROSUI_CORE}" \
  "${TMP_DIR}/test.cpp" \
  "${RUNTIME_DIR}/sui_signing_preparation.cpp" \
  "${COMMON_ROOT}/protocol/base64.cpp" \
  "${COMMON_SUI_DIR}/sign_transaction_adapter.cpp" \
  "${COMMON_SUI_DIR}/offline_policy_facts.cpp" \
  "${COMMON_SUI_DIR}/transaction_facts.cpp" \
  "${COMMON_SUI_DIR}/bcs_reader.cpp" \
  "${TMP_DIR}/byte_conversions.o" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test" "${FIXTURE_DIR}" "${COVERAGE_MATRIX}"
echo "Sui signing preparation tests passed"
