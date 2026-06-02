#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: tools/firmware/stackchan-cores3/test_policy_proposal_parser.sh

Compiles the StackChan CoreS3 policy proposal parser against ArduinoJson and
the common policy canonicalizer with a host C++ compiler. This test does not
require ESP-IDF, but it uses the pinned StackChan ArduinoJson source by default.
Set ARDUINOJSON_ROOT to override the ArduinoJson source root.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TARGET_ROOT="${REPO_ROOT}/products/firmware/src/stackchan-cores3"
COMMON_ROOT="${REPO_ROOT}/products/firmware/src/common/agent_q"
COMMON_POLICY_DIR="${COMMON_ROOT}/policy"
COMMON_SUI_DIR="${COMMON_ROOT}/sui"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${COMMON_ROOT}/agent_q_u64_decimal.h" \
  "${TARGET_ROOT}/agent_q/agent_q_policy_proposal_parser.cpp" \
  "${TARGET_ROOT}/agent_q/agent_q_policy_proposal_parser.h" \
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
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-policy-proposal-parser.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/agent_q_common"
ln -s "${COMMON_POLICY_DIR}" "${TMP_DIR}/agent_q_common/policy"

cat >"${TMP_DIR}/policy_proposal_parser_test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include <ArduinoJson.h>

#include "agent_q_policy_canonical.h"
#include "agent_q_policy_proposal_parser.h"
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
    agent_q::AgentQPolicyProposalParseStatus actual,
    agent_q::AgentQPolicyProposalParseStatus expected)
{
    if (actual != expected) {
        fprintf(stderr, "FAILED: %s expected %s got %s\n",
                label,
                agent_q::agent_q_policy_proposal_parse_status_name(expected),
                agent_q::agent_q_policy_proposal_parse_status_name(actual));
        ++failures;
    }
}

void expect_canonical_status(
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

JsonDocument parse_json(const char* label, const char* json)
{
    JsonDocument document;
    const DeserializationError error = deserializeJson(document, json);
    if (error) {
        fprintf(stderr, "%s: test JSON did not parse: %s\n%s\n", label, error.c_str(), json);
        ++failures;
    }
    return document;
}

const agent_q::AgentQPolicyMethodDescriptor kMethods[] = {
    agent_q::sui_sign_transaction_policy_method_descriptor(),
};

agent_q::AgentQPolicyProposalParseStatus parse_policy(
    const char* label,
    const char* json,
    agent_q::AgentQParsedPolicyProposal* out)
{
    JsonDocument document = parse_json(label, json);
    return agent_q::parse_agent_q_policy_proposal(
        document.as<JsonVariantConst>(),
        kMethods,
        sizeof(kMethods) / sizeof(kMethods[0]),
        out);
}

}  // namespace

int main()
{
    static agent_q::AgentQParsedPolicyProposal proposal = {};
    agent_q::AgentQPolicyCanonicalDocument canonical = {};
    uint8_t record[agent_q::kAgentQPolicyMaxCanonicalRecordBytes] = {};
    size_t record_size = 0;

    expect_status(
        "default reject policy parses",
        parse_policy(
            "default",
            R"JSON({"schema":"agentq.policy.v0","defaultAction":"reject","rules":[]})JSON",
            &proposal),
        agent_q::AgentQPolicyProposalParseStatus::ok);
    expect(proposal.document.rule_count == 0, "default reject rule count");
    expect_canonical_status(
        "default parsed policy canonicalizes",
        agent_q::canonicalize_agent_q_policy_v0(proposal.document, kMethods, 1, &canonical),
        agent_q::AgentQPolicyCanonicalStatus::ok);

    expect_status(
        "valid Sui reject policy parses",
        parse_policy(
            "valid",
            R"JSON({
              "schema":"agentq.policy.v0",
              "defaultAction":"reject",
              "rules":[{
                "id":"reject-sui-mainnet-transfer",
                "chain":"sui",
                "method":"sign_transaction",
                "action":"reject",
                "criteria":[
                  {"field":"common.network","op":"eq","value":"mainnet"},
                  {"field":"sui.amount_raw","op":"lte","value":"1000"},
                  {"field":"sui.recipient_address","op":"in","values":["0xabc","0xdef"]}
                ]
              }]
            })JSON",
            &proposal),
        agent_q::AgentQPolicyProposalParseStatus::ok);
    expect(proposal.document.rule_count == 1, "valid policy rule count");
    expect(proposal.rules[0].criterion_count == 3, "valid policy criterion count");
    expect_canonical_status(
        "valid parsed policy canonicalizes",
        agent_q::canonicalize_agent_q_policy_v0(proposal.document, kMethods, 1, &canonical),
        agent_q::AgentQPolicyCanonicalStatus::ok);
    expect_canonical_status(
        "valid parsed policy encodes",
        agent_q::encode_agent_q_policy_v0_canonical_record(canonical, record, sizeof(record), &record_size),
        agent_q::AgentQPolicyCanonicalStatus::ok);
    expect(record_size > agent_q::kAgentQPolicyDefaultCanonicalRecordBytes, "valid encoded record is custom");

    expect_status(
        "rule id must be history-safe",
        parse_policy(
            "invalid-rule-id",
            R"JSON({"schema":"agentq.policy.v0","defaultAction":"reject","rules":[{"id":"1_rule","chain":"sui","method":"sign_transaction","action":"reject","criteria":[{"field":"common.network","op":"eq","value":"mainnet"}]}]})JSON",
            &proposal),
        agent_q::AgentQPolicyProposalParseStatus::invalid_policy);

    expect_status(
        "unknown top-level key rejected",
        parse_policy(
            "unknown-top-level",
            R"JSON({"schema":"agentq.policy.v0","defaultAction":"reject","rules":[],"extra":true})JSON",
            &proposal),
        agent_q::AgentQPolicyProposalParseStatus::invalid_policy);
    expect_status(
        "embedded nul top-level key rejected",
        parse_policy(
            "embedded-nul-top-level-key",
            R"JSON({"schema\u0000x":"agentq.policy.v0","defaultAction":"reject","rules":[]})JSON",
            &proposal),
        agent_q::AgentQPolicyProposalParseStatus::invalid_policy);

    expect_status(
        "unsupported method rejected",
        parse_policy(
            "unsupported-method",
            R"JSON({"schema":"agentq.policy.v0","defaultAction":"reject","rules":[{"id":"r","chain":"sui","method":"sign_personal_message","action":"reject","criteria":[]}]})JSON",
            &proposal),
        agent_q::AgentQPolicyProposalParseStatus::unsupported_method);

    expect_status(
        "unsupported ask action rejected",
        parse_policy(
            "unsupported-action",
            R"JSON({"schema":"agentq.policy.v0","defaultAction":"reject","rules":[{"id":"r","chain":"sui","method":"sign_transaction","action":"ask","criteria":[{"field":"common.network","op":"eq","value":"mainnet"}]}]})JSON",
            &proposal),
        agent_q::AgentQPolicyProposalParseStatus::unsupported_action);

    expect_status(
        "unknown field rejected",
        parse_policy(
            "unknown-field",
            R"JSON({"schema":"agentq.policy.v0","defaultAction":"reject","rules":[{"id":"r","chain":"sui","method":"sign_transaction","action":"reject","criteria":[{"field":"sui.unknown","op":"eq","value":"x"}]}]})JSON",
            &proposal),
        agent_q::AgentQPolicyProposalParseStatus::unsupported_field);

    expect_status(
        "eq with values rejected",
        parse_policy(
            "eq-values",
            R"JSON({"schema":"agentq.policy.v0","defaultAction":"reject","rules":[{"id":"r","chain":"sui","method":"sign_transaction","action":"reject","criteria":[{"field":"common.network","op":"eq","value":"mainnet","values":["testnet"]}]}]})JSON",
            &proposal),
        agent_q::AgentQPolicyProposalParseStatus::invalid_policy);

    expect_status(
        "in with scalar rejected",
        parse_policy(
            "in-scalar",
            R"JSON({"schema":"agentq.policy.v0","defaultAction":"reject","rules":[{"id":"r","chain":"sui","method":"sign_transaction","action":"reject","criteria":[{"field":"common.network","op":"in","value":"mainnet","values":["testnet"]}]}]})JSON",
            &proposal),
        agent_q::AgentQPolicyProposalParseStatus::invalid_policy);

    expect_status(
        "u64 overflow rejected",
        parse_policy(
            "u64-overflow",
            R"JSON({"schema":"agentq.policy.v0","defaultAction":"reject","rules":[{"id":"r","chain":"sui","method":"sign_transaction","action":"reject","criteria":[{"field":"sui.amount_raw","op":"lte","value":"18446744073709551616"}]}]})JSON",
            &proposal),
        agent_q::AgentQPolicyProposalParseStatus::invalid_policy);

    expect_status(
        "u64 leading zero rejected",
        parse_policy(
            "u64-leading-zero",
            R"JSON({"schema":"agentq.policy.v0","defaultAction":"reject","rules":[{"id":"r","chain":"sui","method":"sign_transaction","action":"reject","criteria":[{"field":"sui.amount_raw","op":"lte","value":"0001"}]}]})JSON",
            &proposal),
        agent_q::AgentQPolicyProposalParseStatus::invalid_policy);
    expect_status(
        "embedded nul scalar rejected",
        parse_policy(
            "embedded-nul-scalar",
            R"JSON({"schema":"agentq.policy.v0","defaultAction":"reject","rules":[{"id":"r","chain":"sui","method":"sign_transaction","action":"reject","criteria":[{"field":"common.network","op":"eq","value":"mainnet\u0000suffix"}]}]})JSON",
            &proposal),
        agent_q::AgentQPolicyProposalParseStatus::invalid_policy);

    JsonDocument oversized;
    JsonObject policy = oversized.to<JsonObject>();
    policy["schema"] = "agentq.policy.v0";
    policy["defaultAction"] = "reject";
    JsonArray rules = policy["rules"].to<JsonArray>();
    JsonObject rule = rules.add<JsonObject>();
    rule["id"] = "r";
    rule["chain"] = "sui";
    rule["method"] = "sign_transaction";
    rule["action"] = "reject";
    JsonArray criteria = rule["criteria"].to<JsonArray>();
    JsonObject criterion = criteria.add<JsonObject>();
    criterion["field"] = "common.network";
    criterion["op"] = "eq";
    char large_value[agent_q::kAgentQPolicyProposalMaxSerializedObjectBytes + 1] = {};
    memset(large_value, 'a', sizeof(large_value) - 1);
    criterion["value"] = large_value;
    expect_status(
        "oversized serialized policy object rejected",
        agent_q::parse_agent_q_policy_proposal(
            oversized.as<JsonVariantConst>(),
            kMethods,
            sizeof(kMethods) / sizeof(kMethods[0]),
            &proposal),
        agent_q::AgentQPolicyProposalParseStatus::too_large);

    if (failures != 0) {
        fprintf(stderr, "Policy proposal parser tests failed: %d\n", failures);
        return 1;
    }
    printf("Policy proposal parser tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${TMP_DIR}" \
  -I"${TARGET_ROOT}/agent_q" \
  -I"${COMMON_ROOT}" \
  -I"${COMMON_POLICY_DIR}" \
  -I"${COMMON_SUI_DIR}" \
  "${TMP_DIR}/policy_proposal_parser_test.cpp" \
  "${TARGET_ROOT}/agent_q/agent_q_policy_proposal_parser.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_canonical.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_schema.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_v0.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_method_adapter.cpp" \
  -o "${TMP_DIR}/policy_proposal_parser_test"

"${TMP_DIR}/policy_proposal_parser_test"
