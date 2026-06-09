#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common/agent_q"
COMMON_SUI_DIR="${COMMON_ROOT}/sui"
FIXTURE_DIR="${COMMON_SUI_DIR}/testdata/sui_transaction_facts"
DEFAULT_SIGNING_DIR="${REPO_ROOT}/.firmware-cache/signing-crypto/microsui-lib"
SIGNING_ROOT="${AGENT_Q_SIGNING_CRYPTO_ROOT:-${DEFAULT_SIGNING_DIR}}"
SIGNING_CORE="${SIGNING_ROOT}/src/microsui_core"
CXX_BIN="${CXX:-c++}"
CC_BIN="${CC:-cc}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-sui-signing-preparation.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/agent_q_common"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/agent_q_common/policy"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/agent_q_common/sui"

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#include "agent_q_sui_signing_preparation.h"
#include "agent_q_sui_account_store.h"
#include "agent_q_sui_signing_authority.h"

extern "C" {
#include "byte_conversions.h"
}

namespace {

bool g_digest_ok = true;
agent_q::AgentQSuiSigningAccountBindingResult g_binding_result =
    agent_q::AgentQSuiSigningAccountBindingResult::ok;
agent_q::SuiAccountDerivationResult g_derivation_result =
    agent_q::SuiAccountDerivationResult::ok;

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

}  // namespace

namespace agent_q {

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

AgentQSuiSigningAccountBindingResult verify_sui_signing_stored_account_binding(
    const SuiTransferFacts&)
{
    return ::g_binding_result;
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
    snprintf(address, address_size,
             "%s", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    return SuiAccountDerivationResult::ok;
}

}  // namespace agent_q

int main(int argc, char** argv)
{
    assert(argc == 2);
    const std::string root = argv[1];
    const std::vector<uint8_t> valid = read_hex((root + "/valid_sui_transfer_tx.bcs.hex").c_str());
    const std::vector<uint8_t> malformed = read_hex((root + "/malformed_short_tx.bcs.hex").c_str());
    const std::vector<uint8_t> unsupported =
        read_hex((root + "/unsupported_result_reference_transfer_tx.bcs.hex").c_str());

    agent_q::AgentQSuiPreparedSignTransaction tx = {};
    assert(agent_q::prepare_sui_sign_transaction(
               agent_q::AgentQSupportedSignRoute::sui_sign_transaction,
               "devnet",
               base64(valid).c_str(),
               valid.size(),
               &tx) == agent_q::AgentQSuiSigningPreparationResult::ok);
    assert(tx.tx_bytes_size == valid.size());
    assert(strcmp(tx.network, "devnet") == 0);
    agent_q::clear_prepared_sui_sign_transaction(&tx);
    assert(tx.tx_bytes_size == 0);

    assert(agent_q::prepare_sui_sign_transaction(
               agent_q::AgentQSupportedSignRoute::sui_sign_transaction,
               "devnet",
               base64(malformed).c_str(),
               malformed.size(),
               &tx) == agent_q::AgentQSuiSigningPreparationResult::malformed_transaction);
    assert(agent_q::prepare_sui_sign_transaction(
               agent_q::AgentQSupportedSignRoute::sui_sign_transaction,
               "devnet",
               base64(unsupported).c_str(),
               unsupported.size(),
               &tx) == agent_q::AgentQSuiSigningPreparationResult::unsupported_transaction);
    assert(agent_q::prepare_sui_sign_transaction(
               agent_q::AgentQSupportedSignRoute::sui_sign_transaction,
               "devnet",
               base64(valid).c_str(),
               valid.size() - 1,
               &tx) == agent_q::AgentQSuiSigningPreparationResult::invalid_params);
    assert(agent_q::prepare_sui_sign_transaction(
               agent_q::AgentQSupportedSignRoute::sui_sign_transaction,
               "devnet",
               base64(valid).c_str(),
               valid.size() + 1,
               &tx) == agent_q::AgentQSuiSigningPreparationResult::invalid_params);
    const std::vector<uint8_t> oversized_tx(agent_q::kAgentQSuiSignTransactionTxBytesMaxBytes + 1, 0xA5);
    assert(agent_q::prepare_sui_sign_transaction(
               agent_q::AgentQSupportedSignRoute::sui_sign_transaction,
               "devnet",
               base64(oversized_tx).c_str(),
               oversized_tx.size(),
               &tx) == agent_q::AgentQSuiSigningPreparationResult::unsupported_payload_size);

    ::g_binding_result = agent_q::AgentQSuiSigningAccountBindingResult::account_mismatch;
    assert(agent_q::prepare_sui_sign_transaction(
               agent_q::AgentQSupportedSignRoute::sui_sign_transaction,
               "devnet",
               base64(valid).c_str(),
               valid.size(),
               &tx) == agent_q::AgentQSuiSigningPreparationResult::invalid_account);
    ::g_binding_result = agent_q::AgentQSuiSigningAccountBindingResult::ok;

    ::g_digest_ok = false;
    assert(agent_q::prepare_sui_sign_transaction(
               agent_q::AgentQSupportedSignRoute::sui_sign_transaction,
               "devnet",
               base64(valid).c_str(),
               valid.size(),
               &tx) == agent_q::AgentQSuiSigningPreparationResult::digest_error);
    ::g_digest_ok = true;

    agent_q::AgentQSuiPreparedPersonalMessage message = {};
    const std::string personal = "SGVsbG8=";
    assert(agent_q::prepare_sui_sign_personal_message(
               agent_q::AgentQSupportedSignRoute::sui_sign_personal_message,
               "devnet",
               personal.c_str(),
               5,
               &message) == agent_q::AgentQSuiSigningPreparationResult::ok);
    assert(message.message_size == 5);
    assert(strcmp(message.account_address,
                  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0);
    agent_q::clear_prepared_sui_sign_personal_message(&message);

    assert(agent_q::prepare_sui_sign_personal_message(
               agent_q::AgentQSupportedSignRoute::sui_sign_personal_message,
               "devnet",
               personal.c_str(),
               4,
               &message) == agent_q::AgentQSuiSigningPreparationResult::invalid_params);
    assert(agent_q::prepare_sui_sign_personal_message(
               agent_q::AgentQSupportedSignRoute::sui_sign_personal_message,
               "devnet",
               personal.c_str(),
               6,
               &message) == agent_q::AgentQSuiSigningPreparationResult::invalid_params);
    const std::vector<uint8_t> oversized_message(agent_q::kAgentQSuiSignPersonalMessageMaxBytes + 1, 0x5A);
    assert(agent_q::prepare_sui_sign_personal_message(
               agent_q::AgentQSupportedSignRoute::sui_sign_personal_message,
               "devnet",
               base64(oversized_message).c_str(),
               oversized_message.size(),
               &message) == agent_q::AgentQSuiSigningPreparationResult::unsupported_payload_size);

    ::g_derivation_result = agent_q::SuiAccountDerivationResult::root_material_unavailable;
    assert(agent_q::prepare_sui_sign_personal_message(
               agent_q::AgentQSupportedSignRoute::sui_sign_personal_message,
               "devnet",
               personal.c_str(),
               5,
               &message) == agent_q::AgentQSuiSigningPreparationResult::account_unavailable);
    return 0;
}
CPP

"${CC_BIN}" -c "${SIGNING_CORE}/byte_conversions.c" -o "${TMP_DIR}/byte_conversions.o"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${AGENT_Q_DIR}" \
  -I"${TMP_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${COMMON_SUI_DIR}" \
  -I"${SIGNING_CORE}" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_sui_signing_preparation.cpp" \
  "${AGENT_Q_DIR}/agent_q_base64.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_sign_transaction_adapter.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_transaction_facts.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_bcs_reader.cpp" \
  "${TMP_DIR}/byte_conversions.o" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test" "${FIXTURE_DIR}"
echo "Sui signing preparation tests passed"
