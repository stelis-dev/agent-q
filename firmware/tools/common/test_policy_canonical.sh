#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/common/test_policy_canonical.sh

Compiles the common Agent-Q policy canonicalization helpers with a host C++
compiler. This test does not require ESP-IDF and does not depend on .WORK paths.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common/agent_q"
COMMON_POLICY_DIR="${COMMON_ROOT}/policy"
COMMON_SUI_DIR="${COMMON_ROOT}/sui"

for required in \
  "${COMMON_ROOT}/agent_q_u64_decimal.h" \
  "${COMMON_POLICY_DIR}/agent_q_policy_canonical.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_canonical.h" \
  "${COMMON_POLICY_DIR}/agent_q_policy_schema.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_schema.h" \
  "${COMMON_POLICY_DIR}/agent_q_policy_u64.h" \
  "${COMMON_POLICY_DIR}/agent_q_policy_v0.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_v0.h" \
  "${COMMON_SUI_DIR}/agent_q_sui_method_adapter.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_method_adapter.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required file: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-policy-canonical.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/policy_canonical_test.cpp" <<'CPP'
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "agent_q_policy_canonical.h"
#include "agent_q_policy_v0.h"
#include "agent_q_sui_method_adapter.h"

namespace {

int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

void expect_status(
    const char* label,
    agent_q::AgentQPolicyCanonicalStatus actual,
    agent_q::AgentQPolicyCanonicalStatus expected)
{
    if (actual != expected) {
        fprintf(stderr, "FAILED: %s expected %s got %s\n",
                label,
                agent_q::agent_q_policy_canonical_status_name(expected),
                agent_q::agent_q_policy_canonical_status_name(actual));
        ++failures;
    }
}

agent_q::AgentQPolicyDocument default_policy()
{
    return agent_q::AgentQPolicyDocument{
        agent_q::kAgentQPolicyV0Schema,
        agent_q::AgentQPolicyAction::reject,
        nullptr,
        0,
    };
}

agent_q::AgentQPolicyFacts matching_sui_facts()
{
    static const agent_q::AgentQPolicyFact entries[] = {
        {"common.chain", agent_q::AgentQPolicyValueType::string, "sui"},
        {"common.method", agent_q::AgentQPolicyValueType::string, "sign_transaction"},
        {"common.network", agent_q::AgentQPolicyValueType::string, "devnet"},
        {"common.intent", agent_q::AgentQPolicyValueType::string, "single_asset_transfer"},
        {"sui.amount_raw", agent_q::AgentQPolicyValueType::u64_decimal, "1000"},
        {"sui.recipient_address", agent_q::AgentQPolicyValueType::string, "0xabc"},
    };
    static const agent_q::AgentQPolicyMethodDescriptor method =
        agent_q::sui_sign_transaction_policy_method_descriptor();
    return agent_q::AgentQPolicyFacts{
        entries,
        sizeof(entries) / sizeof(entries[0]),
        method.field_descriptors,
        method.field_descriptor_count,
    };
}

}  // namespace

int main()
{
    const agent_q::AgentQPolicyMethodDescriptor sui_methods[] = {
        agent_q::sui_sign_transaction_policy_method_descriptor(),
    };

    agent_q::AgentQPolicyCanonicalDocument canonical = {};
    expect_status(
        "default policy canonicalizes",
        agent_q::canonicalize_agent_q_policy_v0(default_policy(), sui_methods, 1, &canonical),
        agent_q::AgentQPolicyCanonicalStatus::ok);

    uint8_t record[agent_q::kAgentQPolicyMaxCanonicalRecordBytes] = {};
    size_t record_size = 0;
    expect_status(
        "default policy encodes",
        agent_q::encode_agent_q_policy_v0_canonical_record(
            canonical, record, sizeof(record), &record_size),
        agent_q::AgentQPolicyCanonicalStatus::ok);
    const uint8_t expected_default[] = {
        'A', 'Q', 'P', '0',
        1, 1, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    expect(record_size == sizeof(expected_default), "default policy keeps existing 16-byte record size");
    expect(memcmp(record, expected_default, sizeof(expected_default)) == 0, "default policy record bytes");

    memset(record, 0xA5, sizeof(record));
    record_size = 0;
    expect_status(
        "default policy helper encodes",
        agent_q::encode_agent_q_policy_v0_default_record(record, sizeof(record), &record_size),
        agent_q::AgentQPolicyCanonicalStatus::ok);
    expect(record_size == sizeof(expected_default), "default helper keeps existing 16-byte record size");
    expect(memcmp(record, expected_default, sizeof(expected_default)) == 0, "default helper record bytes");

    agent_q::AgentQPolicyCanonicalDocument decoded = {};
    expect_status(
        "default policy decodes",
        agent_q::decode_agent_q_policy_v0_canonical_record(record, record_size, &decoded),
        agent_q::AgentQPolicyCanonicalStatus::ok);
    expect(decoded.rule_count == 0, "decoded default rule count");

    const char* networks[] = {"devnet", "testnet"};
    const agent_q::AgentQPolicyCriterion criteria[] = {
        {"common.network", agent_q::AgentQPolicyOperator::in, nullptr, networks, 2},
        {"sui.amount_raw", agent_q::AgentQPolicyOperator::lte, "2000", nullptr, 0},
    };
    const agent_q::AgentQPolicyRule rule = {
        "small-sui-reject",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::reject,
        criteria,
        2,
    };
    const agent_q::AgentQPolicyDocument reject_policy = {
        agent_q::kAgentQPolicyV0Schema,
        agent_q::AgentQPolicyAction::reject,
        &rule,
        1,
    };
    expect_status(
        "reject-only Sui policy canonicalizes",
        agent_q::canonicalize_agent_q_policy_v0(reject_policy, sui_methods, 1, &canonical),
        agent_q::AgentQPolicyCanonicalStatus::ok);

    const agent_q::AgentQPolicyRule digit_rule_id_rule = {
        "1_rule",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::reject,
        criteria,
        2,
    };
    const agent_q::AgentQPolicyDocument digit_rule_id_policy = {
        agent_q::kAgentQPolicyV0Schema,
        agent_q::AgentQPolicyAction::reject,
        &digit_rule_id_rule,
        1,
    };
    expect_status(
        "digit-prefixed rule id is rejected",
        agent_q::canonicalize_agent_q_policy_v0(digit_rule_id_policy, sui_methods, 1, &canonical),
        agent_q::AgentQPolicyCanonicalStatus::invalid_policy);

    expect_status(
        "reject-only Sui policy re-canonicalizes after invalid rule id",
        agent_q::canonicalize_agent_q_policy_v0(reject_policy, sui_methods, 1, &canonical),
        agent_q::AgentQPolicyCanonicalStatus::ok);
    expect_status(
        "reject-only Sui policy encodes",
        agent_q::encode_agent_q_policy_v0_canonical_record(canonical, record, sizeof(record), &record_size),
        agent_q::AgentQPolicyCanonicalStatus::ok);
    expect(record_size > sizeof(expected_default), "custom policy record extends default header");

    memset(&decoded, 0, sizeof(decoded));
    expect_status(
        "reject-only Sui policy decodes",
        agent_q::decode_agent_q_policy_v0_canonical_record(record, record_size, &decoded),
        agent_q::AgentQPolicyCanonicalStatus::ok);
    expect(decoded.rule_count == 1, "decoded custom rule count");

    uint8_t invalid_rule_id_record[agent_q::kAgentQPolicyMaxCanonicalRecordBytes] = {};
    memcpy(invalid_rule_id_record, record, record_size);
    invalid_rule_id_record[sizeof(expected_default) + 1] = 'B';
    expect_status(
        "decoded canonical record rejects invalid rule id",
        agent_q::decode_agent_q_policy_v0_canonical_record(invalid_rule_id_record, record_size, &decoded),
        agent_q::AgentQPolicyCanonicalStatus::invalid_policy);
    expect_status(
        "reject-only Sui policy re-decodes after invalid record test",
        agent_q::decode_agent_q_policy_v0_canonical_record(record, record_size, &decoded),
        agent_q::AgentQPolicyCanonicalStatus::ok);

    agent_q::AgentQPolicyRuntimeView view = {};
    expect(agent_q::agent_q_policy_canonical_to_runtime_view(decoded, &view), "decoded canonical policy creates runtime view");
    const agent_q::AgentQPolicyDecision decision =
        agent_q::evaluate_agent_q_policy_v0(view.document, matching_sui_facts());
    expect(decision.action == agent_q::AgentQPolicyAction::reject, "runtime view action");
    expect(decision.reason == agent_q::AgentQPolicyDecisionReason::matched_rule, "runtime view matched rule");
    expect(decision.rule_id != nullptr && strcmp(decision.rule_id, "small-sui-reject") == 0, "runtime view rule id");

    uint8_t record_with_trailer[agent_q::kAgentQPolicyMaxCanonicalRecordBytes] = {};
    memcpy(record_with_trailer, record, record_size);
    record_with_trailer[record_size] = 0;
    expect_status(
        "trailing canonical bytes are rejected",
        agent_q::decode_agent_q_policy_v0_canonical_record(record_with_trailer, record_size + 1, &decoded),
        agent_q::AgentQPolicyCanonicalStatus::invalid_policy);

    uint8_t malformed_record[agent_q::kAgentQPolicyMaxCanonicalRecordBytes] = {};
    memcpy(malformed_record, record, record_size);
    malformed_record[6] = 255;
    expect_status(
        "invalid encoded default action is rejected",
        agent_q::decode_agent_q_policy_v0_canonical_record(malformed_record, record_size, &decoded),
        agent_q::AgentQPolicyCanonicalStatus::invalid_policy);

    memcpy(malformed_record, record, record_size);
    malformed_record[8] = 1;
    expect_status(
        "nonzero encoded reserved byte is rejected",
        agent_q::decode_agent_q_policy_v0_canonical_record(malformed_record, record_size, &decoded),
        agent_q::AgentQPolicyCanonicalStatus::invalid_policy);

    agent_q::AgentQPolicyCanonicalDocument malformed_canonical = canonical;
    malformed_canonical.rules[0].action = static_cast<agent_q::AgentQPolicyAction>(255);
    expect_status(
        "invalid canonical action is rejected",
        agent_q::encode_agent_q_policy_v0_canonical_record(
            malformed_canonical, record, sizeof(record), &record_size),
        agent_q::AgentQPolicyCanonicalStatus::invalid_policy);

    malformed_canonical = canonical;
    malformed_canonical.rules[0].criteria[0].op = static_cast<agent_q::AgentQPolicyOperator>(255);
    expect_status(
        "invalid canonical operator is rejected",
        agent_q::encode_agent_q_policy_v0_canonical_record(
            malformed_canonical, record, sizeof(record), &record_size),
        agent_q::AgentQPolicyCanonicalStatus::invalid_policy);

    malformed_canonical = canonical;
    malformed_canonical.string_pool[malformed_canonical.rules[0].id.offset] = 'B';
    expect_status(
        "invalid canonical rule id is rejected",
        agent_q::encode_agent_q_policy_v0_canonical_record(
            malformed_canonical, record, sizeof(record), &record_size),
        agent_q::AgentQPolicyCanonicalStatus::invalid_policy);

    malformed_canonical = canonical;
    malformed_canonical.string_pool[malformed_canonical.rules[0].criteria[0].field.offset] = 'S';
    expect_status(
        "invalid canonical field id is rejected",
        agent_q::encode_agent_q_policy_v0_canonical_record(
            malformed_canonical, record, sizeof(record), &record_size),
        agent_q::AgentQPolicyCanonicalStatus::invalid_policy);

    malformed_canonical = canonical;
    malformed_canonical.rules[0].action = agent_q::AgentQPolicyAction::sign;
    malformed_canonical.rules[0].criterion_count = 0;
    expect_status(
        "non-reject canonical rule requires criteria",
        agent_q::encode_agent_q_policy_v0_canonical_record(
            malformed_canonical, record, sizeof(record), &record_size),
        agent_q::AgentQPolicyCanonicalStatus::invalid_policy);

    agent_q::AgentQPolicyRule unsupported_sign_rule = rule;
    unsupported_sign_rule.id = "sign-sui-devnet-transfer";
    unsupported_sign_rule.action = agent_q::AgentQPolicyAction::sign;
    const agent_q::AgentQPolicyDocument unsupported_sign_policy = {
        agent_q::kAgentQPolicyV0Schema,
        agent_q::AgentQPolicyAction::reject,
        &unsupported_sign_rule,
        1,
    };
    expect_status(
        "automatic sign remains unsupported",
        agent_q::canonicalize_agent_q_policy_v0(unsupported_sign_policy, sui_methods, 1, &canonical),
        agent_q::AgentQPolicyCanonicalStatus::unsupported_action);

    agent_q::AgentQPolicyRule unknown_method = rule;
    unknown_method.operation = "sign_personal_message";
    const agent_q::AgentQPolicyDocument unknown_method_policy = {
        agent_q::kAgentQPolicyV0Schema,
        agent_q::AgentQPolicyAction::reject,
        &unknown_method,
        1,
    };
    expect_status(
        "unknown method is rejected",
        agent_q::canonicalize_agent_q_policy_v0(unknown_method_policy, sui_methods, 1, &canonical),
        agent_q::AgentQPolicyCanonicalStatus::unsupported_method);

    const agent_q::AgentQPolicyCriterion unknown_field[] = {
        {"sui.unknown", agent_q::AgentQPolicyOperator::eq, "x", nullptr, 0},
    };
    agent_q::AgentQPolicyRule unknown_field_rule = rule;
    unknown_field_rule.criteria = unknown_field;
    unknown_field_rule.criterion_count = 1;
    const agent_q::AgentQPolicyDocument unknown_field_policy = {
        agent_q::kAgentQPolicyV0Schema,
        agent_q::AgentQPolicyAction::reject,
        &unknown_field_rule,
        1,
    };
    expect_status(
        "unknown field is rejected",
        agent_q::canonicalize_agent_q_policy_v0(unknown_field_policy, sui_methods, 1, &canonical),
        agent_q::AgentQPolicyCanonicalStatus::unsupported_field);

    const agent_q::AgentQPolicyFieldDescriptor duplicate_fields[] = {
        {"sui.amount_raw", agent_q::AgentQPolicyValueType::u64_decimal, true, false, true},
        {"sui.amount_raw", agent_q::AgentQPolicyValueType::u64_decimal, true, false, true},
    };
    const agent_q::AgentQPolicyMethodDescriptor malformed_methods[] = {
        {
            "sui",
            "sign_transaction",
            duplicate_fields,
            sizeof(duplicate_fields) / sizeof(duplicate_fields[0]),
            true,
            false,
            nullptr,
            0,
        },
    };
    expect_status(
        "malformed method descriptor is rejected before policy use",
        agent_q::canonicalize_agent_q_policy_v0(reject_policy, malformed_methods, 1, &canonical),
        agent_q::AgentQPolicyCanonicalStatus::invalid_argument);

    const agent_q::AgentQPolicyCriterion malformed_lte[] = {
        {"sui.amount_raw", agent_q::AgentQPolicyOperator::lte, "18446744073709551616", nullptr, 0},
    };
    agent_q::AgentQPolicyRule malformed_rule = rule;
    malformed_rule.criteria = malformed_lte;
    malformed_rule.criterion_count = 1;
    const agent_q::AgentQPolicyDocument malformed_policy = {
        agent_q::kAgentQPolicyV0Schema,
        agent_q::AgentQPolicyAction::reject,
        &malformed_rule,
        1,
    };
    expect_status(
        "u64 overflow is rejected",
        agent_q::canonicalize_agent_q_policy_v0(malformed_policy, sui_methods, 1, &canonical),
        agent_q::AgentQPolicyCanonicalStatus::invalid_policy);

    expect_status(
        "reject-only Sui policy canonicalizes before small-buffer test",
        agent_q::canonicalize_agent_q_policy_v0(reject_policy, sui_methods, 1, &canonical),
        agent_q::AgentQPolicyCanonicalStatus::ok);
    expect_status(
        "small output buffer is rejected",
        agent_q::encode_agent_q_policy_v0_canonical_record(canonical, record, 1, &record_size),
        agent_q::AgentQPolicyCanonicalStatus::output_too_small);

    if (failures != 0) {
        fprintf(stderr, "Policy canonical tests failed: %d\n", failures);
        return 1;
    }
    printf("Policy canonical tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${COMMON_ROOT}" \
  -I"${COMMON_POLICY_DIR}" \
  -I"${COMMON_SUI_DIR}" \
  "${TMP_DIR}/policy_canonical_test.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_canonical.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_schema.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_v0.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_method_adapter.cpp" \
  -o "${TMP_DIR}/policy_canonical_test"

"${TMP_DIR}/policy_canonical_test"
