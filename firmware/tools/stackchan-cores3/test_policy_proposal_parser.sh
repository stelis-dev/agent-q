#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_policy_proposal_parser.sh

Compiles the StackChan CoreS3 current policy proposal parser against
ArduinoJson and the current common policy document implementation with a host
C++ compiler. This test does not require ESP-IDF, but it uses the pinned
StackChan ArduinoJson source by default. Set ARDUINOJSON_ROOT to override the
ArduinoJson source root.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TARGET_ROOT="${REPO_ROOT}/firmware/src/stackchan-cores3"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common/agent_q"
COMMON_POLICY_DIR="${COMMON_ROOT}/policy"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${COMMON_ROOT}/agent_q_u64_decimal.h" \
  "${TARGET_ROOT}/agent_q/agent_q_policy_proposal_parser.cpp" \
  "${TARGET_ROOT}/agent_q/agent_q_policy_proposal_parser.h" \
  "${COMMON_POLICY_DIR}/agent_q_policy_document.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_document.h" \
  "${COMMON_POLICY_DIR}/agent_q_policy_u64.h"; do
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

#include "agent_q_policy_proposal_parser.h"
#include "agent_q_common/policy/agent_q_policy_document.h"

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

agent_q::AgentQPolicyProposalParseStatus parse_policy(
    const char* label,
    const char* json,
    agent_q::AgentQParsedPolicyProposal* out)
{
    JsonDocument document = parse_json(label, json);
    return agent_q::parse_agent_q_policy_proposal(document.as<JsonVariantConst>(), out);
}

}  // namespace

int main()
{
    auto* proposal = new agent_q::AgentQParsedPolicyProposal();
    auto* canonical = new agent_q::AgentQCurrentPolicyCanonicalDocument();
    uint8_t* record = new uint8_t[agent_q::kAgentQCurrentPolicyMaxCanonicalRecordBytes]();
    size_t record_size = 0;

    expect_status(
        "empty default-reject policy parses",
        parse_policy(
            "empty",
            R"JSON({"schema":"agentq.policy","defaultAction":"reject","blockchains":[]})JSON",
            proposal),
        agent_q::AgentQPolicyProposalParseStatus::ok);
    expect(proposal->document.blockchain_count == 0, "empty policy has no blockchain scopes");
    expect(agent_q::canonicalize_agent_q_current_policy_document(proposal->document, canonical) ==
               agent_q::AgentQCurrentPolicyDocumentStatus::ok,
           "empty parsed policy canonicalizes");
    expect(agent_q::encode_agent_q_current_policy_canonical_record(
               *canonical,
               record,
               agent_q::kAgentQCurrentPolicyMaxCanonicalRecordBytes,
               &record_size) == agent_q::AgentQCurrentPolicyDocumentStatus::ok,
           "empty parsed policy encodes");
    expect(record_size == agent_q::kAgentQCurrentPolicyDefaultCanonicalRecordBytes,
           "empty policy encodes as default-reject record");

    expect_status(
        "current scoped empty policy parses",
        parse_policy(
            "scoped-empty",
            R"JSON({
              "schema":"agentq.policy",
              "defaultAction":"reject",
              "blockchains":[{
                "blockchain":"sui",
                "networks":[{
                  "network":"testnet",
                  "policies":[]
                }]
              }]
            })JSON",
            proposal),
        agent_q::AgentQPolicyProposalParseStatus::ok);
    expect(proposal->document.blockchain_count == 1, "scoped empty policy blockchain count");
    expect(proposal->network_count == 1, "scoped empty policy network count");
    expect(proposal->policy_count == 0, "scoped empty policy count");
    expect(proposal->condition_count == 0, "scoped empty condition count");
    expect(strcmp(proposal->blockchains[0].blockchain, "sui") == 0, "blockchain scope is sui");
    expect(strcmp(proposal->networks[0].network, "testnet") == 0, "network scope is testnet");
    expect(agent_q::canonicalize_agent_q_current_policy_document(proposal->document, canonical) ==
               agent_q::AgentQCurrentPolicyDocumentStatus::ok,
           "scoped empty parsed policy canonicalizes");
    expect(agent_q::encode_agent_q_current_policy_canonical_record(
               *canonical,
               record,
               agent_q::kAgentQCurrentPolicyMaxCanonicalRecordBytes,
               &record_size) == agent_q::AgentQCurrentPolicyDocumentStatus::ok,
           "scoped empty parsed policy encodes");
    expect(record_size > agent_q::kAgentQCurrentPolicyDefaultCanonicalRecordBytes,
           "scoped empty encoded record includes scope body");

    expect_status(
        "non-empty current policy entries parse",
        parse_policy(
            "non-empty",
            R"JSON({
              "schema":"agentq.policy",
              "defaultAction":"reject",
              "blockchains":[{
                "blockchain":"sui",
                "networks":[{
                  "network":"testnet",
                  "policies":[{
                    "id":"sign-small-sui",
                    "action":"sign",
                    "conditions":[
                      {"field":"sui.token_sources.type","op":"eq","value":"0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI"},
                      {"field":"sui.token_totals_by_type.amount_raw","where":{"type":"0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI"},"op":"lte","value":"1000000000"},
                      {"field":"sui.token_unknown_amount_present","op":"eq","value":"false"}
                    ]
                  }]
                }]
              }]
            })JSON",
            proposal),
        agent_q::AgentQPolicyProposalParseStatus::ok);
    expect(proposal->document.blockchain_count == 1, "non-empty policy blockchain count");
    expect(proposal->network_count == 1, "non-empty policy network count");
    expect(proposal->policy_count == 1, "non-empty policy count");
    expect(proposal->condition_count == 3, "non-empty condition count");
    expect(strcmp(proposal->policies[0].id, "sign-small-sui") == 0, "non-empty policy id");
    expect(proposal->policies[0].action == agent_q::AgentQCurrentPolicyAction::sign,
           "non-empty policy action");
    expect(strcmp(proposal->conditions[0].field, "sui.token_sources.type") == 0,
           "first condition field");
    expect(proposal->conditions[0].op == agent_q::AgentQCurrentPolicyOperator::eq,
           "first condition op");
    expect(strcmp(proposal->conditions[0].values[0], "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI") == 0,
           "first condition value");
    expect(strcmp(proposal->conditions[1].field, "sui.token_totals_by_type.amount_raw") == 0,
           "second condition field");
    expect(strcmp(proposal->conditions[1].where_type, "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI") == 0,
           "second condition selector");

    expect_status(
        "flat rules key is rejected",
        parse_policy(
            "flat",
            R"JSON({"schema":"agentq.policy","defaultAction":"reject","rules":[]})JSON",
            proposal),
        agent_q::AgentQPolicyProposalParseStatus::invalid_policy);
    expect_status(
        "unsupported schema is rejected",
        parse_policy(
            "unsupported-schema",
            R"JSON({"schema":"other.policy","defaultAction":"reject","blockchains":[]})JSON",
            proposal),
        agent_q::AgentQPolicyProposalParseStatus::invalid_policy);
    expect_status(
        "unknown top-level key rejected",
        parse_policy(
            "unknown-top-level",
            R"JSON({"schema":"agentq.policy","defaultAction":"reject","blockchains":[],"extra":true})JSON",
            proposal),
        agent_q::AgentQPolicyProposalParseStatus::invalid_policy);
    expect_status(
        "network is not a condition field",
        parse_policy(
            "network-condition",
            R"JSON({"schema":"agentq.policy","defaultAction":"reject","blockchains":[{"blockchain":"sui","networks":[{"network":"testnet","policies":[{"id":"bad-network-field","action":"reject","conditions":[{"field":"network","op":"eq","value":"testnet"}]}]}]}]})JSON",
            proposal),
        agent_q::AgentQPolicyProposalParseStatus::unsupported_field);
    expect_status(
        "unknown field rejected",
        parse_policy(
            "unknown-field",
            R"JSON({"schema":"agentq.policy","defaultAction":"reject","blockchains":[{"blockchain":"sui","networks":[{"network":"testnet","policies":[{"id":"unknown-field","action":"reject","conditions":[{"field":"sui.unknown","op":"eq","value":"x"}]}]}]}]})JSON",
            proposal),
        agent_q::AgentQPolicyProposalParseStatus::unsupported_field);
    expect_status(
        "unsupported operator rejected",
        parse_policy(
            "unsupported-op",
            R"JSON({"schema":"agentq.policy","defaultAction":"reject","blockchains":[{"blockchain":"sui","networks":[{"network":"testnet","policies":[{"id":"bad-op","action":"reject","conditions":[{"field":"sui.gas_budget_raw","op":"contains","value":"1000"}]}]}]}]})JSON",
            proposal),
        agent_q::AgentQPolicyProposalParseStatus::invalid_policy);
    expect_status(
        "token total amount missing selector rejected",
        parse_policy(
            "missing-selector",
            R"JSON({"schema":"agentq.policy","defaultAction":"reject","blockchains":[{"blockchain":"sui","networks":[{"network":"testnet","policies":[{"id":"missing-selector","action":"sign","conditions":[{"field":"sui.token_totals_by_type.amount_raw","op":"lte","value":"1000000000"}]}]}]}]})JSON",
            proposal),
        agent_q::AgentQPolicyProposalParseStatus::invalid_policy);
    expect_status(
        "where selector on scalar field rejected",
        parse_policy(
            "forbidden-selector",
            R"JSON({"schema":"agentq.policy","defaultAction":"reject","blockchains":[{"blockchain":"sui","networks":[{"network":"testnet","policies":[{"id":"forbidden-selector","action":"reject","conditions":[{"field":"sui.gas_budget_raw","where":{"type":"0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI"},"op":"lte","value":"10000000"}]}]}]}]})JSON",
            proposal),
        agent_q::AgentQPolicyProposalParseStatus::invalid_policy);
    expect_status(
        "u64 overflow rejected",
        parse_policy(
            "u64-overflow",
            R"JSON({"schema":"agentq.policy","defaultAction":"reject","blockchains":[{"blockchain":"sui","networks":[{"network":"testnet","policies":[{"id":"u64-overflow","action":"reject","conditions":[{"field":"sui.gas_budget_raw","op":"lte","value":"18446744073709551616"}]}]}]}]})JSON",
            proposal),
        agent_q::AgentQPolicyProposalParseStatus::invalid_policy);
    expect_status(
        "u64 leading zero rejected",
        parse_policy(
            "u64-leading-zero",
            R"JSON({"schema":"agentq.policy","defaultAction":"reject","blockchains":[{"blockchain":"sui","networks":[{"network":"testnet","policies":[{"id":"u64-leading-zero","action":"reject","conditions":[{"field":"sui.gas_budget_raw","op":"lte","value":"0001"}]}]}]}]})JSON",
            proposal),
        agent_q::AgentQPolicyProposalParseStatus::invalid_policy);
    expect_status(
        "sign policy requires conditions",
        parse_policy(
            "empty-sign",
            R"JSON({"schema":"agentq.policy","defaultAction":"reject","blockchains":[{"blockchain":"sui","networks":[{"network":"testnet","policies":[{"id":"empty-sign","action":"sign","conditions":[]}]}]}]})JSON",
            proposal),
        agent_q::AgentQPolicyProposalParseStatus::invalid_policy);
    expect_status(
        "duplicate policy id rejected in scope",
        parse_policy(
            "duplicate-policy",
            R"JSON({"schema":"agentq.policy","defaultAction":"reject","blockchains":[{"blockchain":"sui","networks":[{"network":"testnet","policies":[{"id":"same","action":"reject","conditions":[]},{"id":"same","action":"reject","conditions":[]}]}]}]})JSON",
            proposal),
        agent_q::AgentQPolicyProposalParseStatus::invalid_policy);
    expect_status(
        "duplicate network rejected in blockchain scope",
        parse_policy(
            "duplicate-network",
            R"JSON({"schema":"agentq.policy","defaultAction":"reject","blockchains":[{"blockchain":"sui","networks":[{"network":"testnet","policies":[]},{"network":"testnet","policies":[]}]}]})JSON",
            proposal),
        agent_q::AgentQPolicyProposalParseStatus::invalid_policy);
    expect_status(
        "duplicate blockchain rejected",
        parse_policy(
            "duplicate-blockchain",
            R"JSON({"schema":"agentq.policy","defaultAction":"reject","blockchains":[{"blockchain":"sui","networks":[]},{"blockchain":"sui","networks":[]}]})JSON",
            proposal),
        agent_q::AgentQPolicyProposalParseStatus::invalid_policy);

    delete[] record;
    delete canonical;
    delete proposal;

    if (failures != 0) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("policy proposal parser tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}" \
  -I"${TARGET_ROOT}/agent_q" \
  -I"${COMMON_ROOT}" \
  -I"${ARDUINOJSON_ROOT}" \
  "${TMP_DIR}/policy_proposal_parser_test.cpp" \
  "${TARGET_ROOT}/agent_q/agent_q_policy_proposal_parser.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_document.cpp" \
  -o "${TMP_DIR}/policy_proposal_parser_test"

"${TMP_DIR}/policy_proposal_parser_test"
