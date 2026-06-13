#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_sign_transaction_policy_runtime.sh

Compiles the StackChan CoreS3 sign_transaction_policy runtime boundary against
prepared Sui transaction input, the common Sui facts parser, and the common
policy runtime. It verifies default policy rejection, bounded policy sign
approval, unsupported methods, invalid prepared input, and policy metadata.
This test uses only host compilers and does NOT require ESP-IDF.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common/agent_q"
COMMON_POLICY_DIR="${COMMON_ROOT}/policy"
COMMON_SUI_DIR="${COMMON_ROOT}/sui"
FIXTURE_DIR="${COMMON_SUI_DIR}/testdata/sui_transaction_facts"
for required in \
  "${FIXTURE_DIR}/valid_sui_transfer_tx.bcs.hex" \
  "${COMMON_ROOT}/agent_q_u64_decimal.h" \
  "${AGENT_Q_DIR}/agent_q_sign_transaction_policy_runtime.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_schema.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_v0.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_runtime.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_bcs_reader.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_method_adapter.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_transaction_facts.cpp"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    echo "Run firmware/tools/stackchan-cores3/build.sh first if generated dependencies are missing." >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-sign-transaction-policy-runtime.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/agent_q_common" "${TMP_DIR}/stubs"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/agent_q_common/policy"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/agent_q_common/sui"

cat >"${TMP_DIR}/stubs/esp_log.h" <<'H'
#pragma once

#define ESP_LOGI(tag, format, ...) do { (void)(tag); } while (0)
#define ESP_LOGW(tag, format, ...) do { (void)(tag); } while (0)
#define ESP_LOGE(tag, format, ...) do { (void)(tag); } while (0)
H

cat >"${TMP_DIR}/sign_transaction_policy_runtime_test.cpp" <<'CPP'
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fstream>
#include <string>
#include <vector>

#include "agent_q_sign_transaction_policy_runtime.h"
#include "agent_q_policy_store.h"
#include "agent_q_sui_account_store.h"
#include "agent_q_common/policy/agent_q_policy_v0.h"
#include "agent_q_common/sui/agent_q_sui_method_adapter.h"
#include "agent_q_common/sui/agent_q_sui_transaction_facts.h"

namespace {

constexpr const char* kPolicyHash =
    "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3";
constexpr const char* kPayloadDigest =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

int failures = 0;
agent_q::AgentQPolicyAction g_policy_action = agent_q::AgentQPolicyAction::reject;
bool g_policy_has_rule = false;
const char* g_rule_id = "sign-small-sui-transfer";
const char* g_allowed_recipient = nullptr;
const char* g_gas_price_bound = "1000000000";
bool g_account_available = true;
const char* g_stored_address = nullptr;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

void clobber_stack()
{
    volatile char buffer[4096] = {};
    for (size_t index = 0; index < sizeof(buffer); ++index) {
        buffer[index] = static_cast<char>(index & 0x7F);
    }
}

uint8_t hex_value(char c)
{
    if (c >= '0' && c <= '9') {
        return static_cast<uint8_t>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return static_cast<uint8_t>(c - 'a' + 10);
    }
    if (c >= 'A' && c <= 'F') {
        return static_cast<uint8_t>(c - 'A' + 10);
    }
    fprintf(stderr, "Invalid fixture hex char: %c\n", c);
    exit(1);
}

std::vector<uint8_t> read_hex_fixture(const char* path)
{
    std::ifstream input(path);
    if (!input) {
        fprintf(stderr, "Could not open fixture: %s\n", path);
        exit(1);
    }
    std::string hex;
    input >> hex;
    if ((hex.size() % 2) != 0) {
        fprintf(stderr, "Fixture has odd hex length\n");
        exit(1);
    }
    std::vector<uint8_t> bytes(hex.size() / 2);
    for (size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<uint8_t>(
            (hex_value(hex[index * 2]) << 4) | hex_value(hex[index * 2 + 1]));
    }
    return bytes;
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

bool load_default_policy(AgentQPolicyDocument* out, void*)
{
    if (out == nullptr) {
        return false;
    }
    static const char* recipient_values[1] = {};
    recipient_values[0] = ::g_allowed_recipient;
    static AgentQPolicyCriterion criteria[10] = {};
    criteria[0] = AgentQPolicyCriterion{
        "common.intent",
        AgentQPolicyOperator::eq,
        kAgentQPolicyIntentSingleAssetTransfer,
        nullptr,
        0,
    };
    criteria[1] = AgentQPolicyCriterion{
        "sui.command_shape",
        AgentQPolicyOperator::eq,
        kAgentQSuiPolicyCommandShapeRestrictedTransfer,
        nullptr,
        0,
    };
    criteria[2] = AgentQPolicyCriterion{
        "sui.command_count",
        AgentQPolicyOperator::eq,
        "2",
        nullptr,
        0,
    };
    criteria[3] = AgentQPolicyCriterion{
        "sui.command0_kind",
        AgentQPolicyOperator::eq,
        kAgentQSuiPolicyCommandKindSplitCoins,
        nullptr,
        0,
    };
    criteria[4] = AgentQPolicyCriterion{
        "sui.command1_kind",
        AgentQPolicyOperator::eq,
        kAgentQSuiPolicyCommandKindTransferObjects,
        nullptr,
        0,
    };
    criteria[5] = AgentQPolicyCriterion{
        "sui.coin_type",
        AgentQPolicyOperator::eq,
        "0x2::sui::SUI",
        nullptr,
        0,
    };
    criteria[6] = AgentQPolicyCriterion{
        "sui.recipient_address",
        AgentQPolicyOperator::in,
        nullptr,
        recipient_values,
        1,
    };
    criteria[7] = AgentQPolicyCriterion{
        "sui.amount_raw",
        AgentQPolicyOperator::lte,
        "1000000",
        nullptr,
        0,
    };
    criteria[8] = AgentQPolicyCriterion{
        "sui.gas_budget",
        AgentQPolicyOperator::lte,
        "50000000",
        nullptr,
        0,
    };
    criteria[9] = AgentQPolicyCriterion{
        "sui.gas_price",
        AgentQPolicyOperator::lte,
        ::g_gas_price_bound,
        nullptr,
        0,
    };
    static AgentQPolicyRule rule = {};
    rule = AgentQPolicyRule{
        ::g_rule_id,
        kAgentQSuiPolicyChain,
        kAgentQSuiPolicyOperationSignTransaction,
        ::g_policy_action,
        criteria,
        sizeof(criteria) / sizeof(criteria[0]),
    };
    *out = AgentQPolicyDocument{
        kAgentQPolicyV0Schema,
        AgentQPolicyAction::reject,
        ::g_policy_has_rule ? &rule : nullptr,
        ::g_policy_has_rule ? 1U : 0U,
    };
    return true;
}

bool store_default_policy()
{
    return false;
}

bool wipe_policy()
{
    return false;
}

AgentQPolicyStoreStatus active_policy_status()
{
    return AgentQPolicyStoreStatus::active;
}

AgentQPolicyProvider active_policy_provider()
{
    return AgentQPolicyProvider{load_default_policy, nullptr};
}

bool read_active_policy_summary(AgentQStoredPolicySummary* out)
{
    if (out == nullptr) {
        return false;
    }
    out->schema = kAgentQStoredPolicySchema;
    memcpy(out->policy_id, ::kPolicyHash, kAgentQPolicyIdSize);
    out->default_action = "reject";
    out->rule_count = ::g_policy_has_rule ? 1U : 0U;
    return true;
}

SuiAccountDerivationResult derive_sui_ed25519_account_from_stored_root(
    uint8_t public_key_out[kSuiEd25519PublicKeyBytes],
    char* address_out,
    size_t address_out_size)
{
    if (!::g_account_available) {
        return SuiAccountDerivationResult::root_material_unavailable;
    }
    if (public_key_out == nullptr ||
        address_out == nullptr ||
        address_out_size < kSuiAddressBufferSize ||
        ::g_stored_address == nullptr) {
        return SuiAccountDerivationResult::derivation_error;
    }
    memset(public_key_out, 0x42, kSuiEd25519PublicKeyBytes);
    strlcpy(address_out, ::g_stored_address, address_out_size);
    return SuiAccountDerivationResult::ok;
}

bool approval_history_digest_payload(const uint8_t*, size_t, char* output, size_t output_size)
{
    if (output == nullptr || output_size != kAgentQApprovalHistoryDigestSize) {
        return false;
    }
    memcpy(output, ::kPayloadDigest, kAgentQApprovalHistoryDigestSize);
    return true;
}

}  // namespace agent_q

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: sign_transaction_policy_runtime_test <valid_tx_hex_fixture>\n");
        return 2;
    }

    const std::vector<uint8_t> tx_bytes = read_hex_fixture(argv[1]);
    agent_q::SuiTransactionPolicyFacts sui_facts = {};
    const agent_q::SuiTransactionFactsResult facts_result =
        agent_q::parse_sui_transaction_policy_facts(tx_bytes.data(), tx_bytes.size(), &sui_facts);
    expect(facts_result == agent_q::SuiTransactionFactsResult::ok,
           "fixture parses as supported restricted transfer");
    ::g_allowed_recipient = sui_facts.restricted_transfer.recipient;
    ::g_gas_price_bound = sui_facts.gas_price;
    ::g_account_available = true;
    ::g_stored_address = sui_facts.sender;

    agent_q::AgentQSuiPreparedSignTransaction prepared = {};
    prepared.route = agent_q::AgentQSupportedSignRoute::sui_sign_transaction;
    snprintf(prepared.network, sizeof(prepared.network), "%s", "devnet");
    prepared.tx_bytes = static_cast<uint8_t*>(malloc(tx_bytes.size()));
    assert(prepared.tx_bytes != nullptr);
    memcpy(prepared.tx_bytes, tx_bytes.data(), tx_bytes.size());
    prepared.tx_bytes_size = tx_bytes.size();
    snprintf(prepared.payload_digest, sizeof(prepared.payload_digest), "%s", kPayloadDigest);
    prepared.sui_facts = sui_facts;

    ::g_policy_has_rule = false;
    ::g_policy_action = agent_q::AgentQPolicyAction::reject;
    const agent_q::AgentQSignTransactionPolicyRuntimeResult rejected =
        agent_q::evaluate_sign_transaction_policy(prepared);
    clobber_stack();
    expect(rejected.status == agent_q::AgentQSignTransactionPolicyRuntimeStatus::policy_rejected,
           "default policy rejects sign_transaction_policy");
    expect(strcmp(rejected.code, "policy_rejected") == 0,
           "default policy rejection code");
    expect(strcmp(rejected.chain, "sui") == 0 &&
               strcmp(rejected.method, "sign_transaction") == 0,
           "policy rejection preserves chain and method");
    expect(strcmp(rejected.reason_code, "policy_rejected") == 0,
           "policy rejection preserves reason code");
    expect(strcmp(rejected.payload_digest, kPayloadDigest) == 0,
           "policy rejection preserves payload digest");
    expect(strcmp(rejected.policy_hash, kPolicyHash) == 0,
           "policy rejection preserves policy hash");
    expect(strcmp(rejected.rule_ref, "default") == 0,
           "default policy rejection records default rule ref");
    expect(rejected.tx_bytes_size == 0, "policy rejection does not expose signable tx bytes");

    ::g_policy_has_rule = true;
    ::g_policy_action = agent_q::AgentQPolicyAction::sign;
    ::g_rule_id = "sign-small-sui-transfer";
    const agent_q::AgentQSignTransactionPolicyRuntimeResult approved =
        agent_q::evaluate_sign_transaction_policy(prepared);
    expect(approved.status == agent_q::AgentQSignTransactionPolicyRuntimeStatus::policy_authorized,
           "bounded policy sign rule approves sign_transaction_policy");
    expect(strcmp(approved.code, "policy_signed") == 0,
           "policy approval code");
    expect(strcmp(approved.rule_ref, "sign-small-sui-transfer") == 0,
           "policy approval records matched sign rule id");
    expect(approved.tx_bytes_size == tx_bytes.size(), "policy approval owns signable tx bytes");
    expect(memcmp(approved.tx_bytes, tx_bytes.data(), tx_bytes.size()) == 0,
           "policy approval preserves signable tx bytes");

    std::vector<uint8_t> max_policy_payload(
        agent_q::kAgentQSuiSignTransactionTxBytesMaxBytes,
        0x6B);
    agent_q::AgentQSuiPreparedSignTransaction max_prepared = prepared;
    max_prepared.tx_bytes = max_policy_payload.data();
    max_prepared.tx_bytes_size = max_policy_payload.size();
    const agent_q::AgentQSignTransactionPolicyRuntimeResult max_approved =
        agent_q::evaluate_sign_transaction_policy(max_prepared);
    expect(max_approved.status == agent_q::AgentQSignTransactionPolicyRuntimeStatus::policy_authorized,
           "bounded policy sign rule can authorize max-size prepared payload");
    expect(max_approved.tx_bytes == max_policy_payload.data(),
           "policy approval preserves max-size signable payload pointer");
    expect(max_approved.tx_bytes_size == max_policy_payload.size(),
           "policy approval preserves max-size signable payload size");

    agent_q::AgentQSignTransactionPolicyRuntimeResult cleared = approved;
    agent_q::clear_sign_transaction_policy_runtime_result(&cleared);
    expect(cleared.code == nullptr && cleared.tx_bytes_size == 0,
           "clearing sign_transaction_policy result wipes public metadata");

    agent_q::AgentQSuiPreparedSignTransaction unsupported_prepared = prepared;
    unsupported_prepared.route = agent_q::AgentQSupportedSignRoute::unsupported;
    const agent_q::AgentQSignTransactionPolicyRuntimeResult unsupported =
        agent_q::evaluate_sign_transaction_policy(unsupported_prepared);
    expect(unsupported.status == agent_q::AgentQSignTransactionPolicyRuntimeStatus::unsupported_method,
           "unknown method returns unsupported method status");
    expect(strcmp(unsupported.code, "unsupported_method") == 0,
           "unknown method reports unsupported_method");

    agent_q::AgentQSuiPreparedSignTransaction invalid_prepared = prepared;
    invalid_prepared.tx_bytes_size = 0;
    const agent_q::AgentQSignTransactionPolicyRuntimeResult invalid =
        agent_q::evaluate_sign_transaction_policy(invalid_prepared);
    expect(invalid.status == agent_q::AgentQSignTransactionPolicyRuntimeStatus::invalid_params,
           "invalid prepared Sui transaction returns protocol invalid params");
    expect(strcmp(invalid.code, "invalid_params") == 0,
           "invalid prepared Sui transaction code is invalid_params");

    if (failures != 0) {
        fprintf(stderr, "%d sign_transaction_policy runtime test(s) failed\n", failures);
        return 1;
    }
    printf("sign_transaction_policy runtime tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${TMP_DIR}" \
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_ROOT}" \
  -I"${COMMON_POLICY_DIR}" \
  -I"${COMMON_SUI_DIR}" \
  "${TMP_DIR}/sign_transaction_policy_runtime_test.cpp" \
  "${AGENT_Q_DIR}/agent_q_sign_transaction_policy_runtime.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_schema.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_v0.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_runtime.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_bcs_reader.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_method_adapter.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_transaction_facts.cpp" \
  -o "${TMP_DIR}/sign_transaction_policy_runtime_test"

"${TMP_DIR}/sign_transaction_policy_runtime_test" "${FIXTURE_DIR}/valid_sui_transfer_tx.bcs.hex"
