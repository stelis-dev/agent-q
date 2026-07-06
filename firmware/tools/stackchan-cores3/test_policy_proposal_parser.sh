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
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
COMMON_POLICY_DIR="${COMMON_ROOT}/policy"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

for required in \
  "${ARDUINOJSON_ROOT}/ArduinoJson.h" \
  "${COMMON_ROOT}/numeric/u64_decimal.h" \
  "${REPO_ROOT}/firmware/src/common/policy/policy_proposal_parser.cpp" \
  "${REPO_ROOT}/firmware/src/common/policy/policy_proposal_parser.h" \
  "${COMMON_POLICY_DIR}/document.cpp" \
  "${COMMON_POLICY_DIR}/document.h" \
  "${COMMON_POLICY_DIR}/u64.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required file: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-policy-proposal-parser.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT
mkdir -p "${TMP_DIR}/firmware_common"
ln -s "${COMMON_POLICY_DIR}" "${TMP_DIR}/firmware_common/policy"

cat >"${TMP_DIR}/policy_proposal_parser_test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include <ArduinoJson.h>

#include "policy/policy_proposal_parser.h"
#include "firmware_common/policy/document.h"

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
    signing::PolicyProposalParseStatus actual,
    signing::PolicyProposalParseStatus expected)
{
    if (actual != expected) {
        fprintf(stderr, "FAILED: %s expected %s got %s\n",
                label,
                signing::policy_proposal_parse_status_name(expected),
                signing::policy_proposal_parse_status_name(actual));
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

signing::PolicyProposalParseStatus parse_policy(
    const char* label,
    const char* json,
    signing::ParsedPolicyProposal* out)
{
    JsonDocument document = parse_json(label, json);
    return signing::parse_signing_policy_proposal(document.as<JsonVariantConst>(), out);
}

}  // namespace

int main()
{
    auto* proposal = new signing::ParsedPolicyProposal();
    auto* canonical = new signing::CurrentPolicyCanonicalDocument();
    uint8_t* record = new uint8_t[signing::kCurrentPolicyMaxCanonicalRecordBytes]();
    size_t record_size = 0;

    expect_status(
        "empty default-reject policy parses",
        parse_policy(
            "empty",
            R"JSON({"schema":"signing.policy","defaultAction":"reject","blockchains":[]})JSON",
            proposal),
        signing::PolicyProposalParseStatus::ok);
    expect(proposal->document.blockchain_count == 0, "empty policy has no blockchain scopes");
    expect(signing::canonicalize_current_policy_document(proposal->document, canonical) ==
               signing::CurrentPolicyDocumentStatus::ok,
           "empty parsed policy canonicalizes");
    expect(signing::encode_current_policy_canonical_record(
               *canonical,
               record,
               signing::kCurrentPolicyMaxCanonicalRecordBytes,
               &record_size) == signing::CurrentPolicyDocumentStatus::ok,
           "empty parsed policy encodes");
    expect(record_size == signing::kCurrentPolicyDefaultCanonicalRecordBytes,
           "empty policy encodes as default-reject record");

    expect_status(
        "current scoped empty policy parses",
        parse_policy(
            "scoped-empty",
            R"JSON({
              "schema":"signing.policy",
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
        signing::PolicyProposalParseStatus::ok);
    expect(proposal->document.blockchain_count == 1, "scoped empty policy blockchain count");
    expect(proposal->network_count == 1, "scoped empty policy network count");
    expect(proposal->policy_count == 0, "scoped empty policy count");
    expect(proposal->condition_count == 0, "scoped empty condition count");
    expect(strcmp(proposal->blockchains[0].blockchain, "sui") == 0, "blockchain scope is sui");
    expect(strcmp(proposal->networks[0].network, "testnet") == 0, "network scope is testnet");
    expect(signing::canonicalize_current_policy_document(proposal->document, canonical) ==
               signing::CurrentPolicyDocumentStatus::ok,
           "scoped empty parsed policy canonicalizes");
    expect(signing::encode_current_policy_canonical_record(
               *canonical,
               record,
               signing::kCurrentPolicyMaxCanonicalRecordBytes,
               &record_size) == signing::CurrentPolicyDocumentStatus::ok,
           "scoped empty parsed policy encodes");
    expect(record_size > signing::kCurrentPolicyDefaultCanonicalRecordBytes,
           "scoped empty encoded record includes scope body");

    expect_status(
        "non-empty current policy entries parse",
        parse_policy(
            "non-empty",
            R"JSON({
              "schema":"signing.policy",
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
        signing::PolicyProposalParseStatus::ok);
    expect(proposal->document.blockchain_count == 1, "non-empty policy blockchain count");
    expect(proposal->network_count == 1, "non-empty policy network count");
    expect(proposal->policy_count == 1, "non-empty policy count");
    expect(proposal->condition_count == 3, "non-empty condition count");
    expect(strcmp(proposal->policies[0].id, "sign-small-sui") == 0, "non-empty policy id");
    expect(proposal->policies[0].action == signing::CurrentPolicyAction::sign,
           "non-empty policy action");
    expect(strcmp(proposal->conditions[0].field, "sui.token_sources.type") == 0,
           "first condition field");
    expect(proposal->conditions[0].op == signing::CurrentPolicyOperator::eq,
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
            R"JSON({"schema":"signing.policy","defaultAction":"reject","rules":[]})JSON",
            proposal),
        signing::PolicyProposalParseStatus::invalid_policy);
    expect_status(
        "unsupported schema is rejected",
        parse_policy(
            "unsupported-schema",
            R"JSON({"schema":"other.policy","defaultAction":"reject","blockchains":[]})JSON",
            proposal),
        signing::PolicyProposalParseStatus::invalid_policy);
    expect_status(
        "unknown top-level key rejected",
        parse_policy(
            "unknown-top-level",
            R"JSON({"schema":"signing.policy","defaultAction":"reject","blockchains":[],"extra":true})JSON",
            proposal),
        signing::PolicyProposalParseStatus::invalid_policy);
    expect_status(
        "network is not a condition field",
        parse_policy(
            "network-condition",
            R"JSON({"schema":"signing.policy","defaultAction":"reject","blockchains":[{"blockchain":"sui","networks":[{"network":"testnet","policies":[{"id":"bad-network-field","action":"reject","conditions":[{"field":"network","op":"eq","value":"testnet"}]}]}]}]})JSON",
            proposal),
        signing::PolicyProposalParseStatus::unsupported_field);
    expect_status(
        "unknown field rejected",
        parse_policy(
            "unknown-field",
            R"JSON({"schema":"signing.policy","defaultAction":"reject","blockchains":[{"blockchain":"sui","networks":[{"network":"testnet","policies":[{"id":"unknown-field","action":"reject","conditions":[{"field":"sui.unknown","op":"eq","value":"x"}]}]}]}]})JSON",
            proposal),
        signing::PolicyProposalParseStatus::unsupported_field);
    expect_status(
        "unsupported operator rejected",
        parse_policy(
            "unsupported-op",
            R"JSON({"schema":"signing.policy","defaultAction":"reject","blockchains":[{"blockchain":"sui","networks":[{"network":"testnet","policies":[{"id":"bad-op","action":"reject","conditions":[{"field":"sui.gas_budget_raw","op":"contains","value":"1000"}]}]}]}]})JSON",
            proposal),
        signing::PolicyProposalParseStatus::invalid_policy);
    expect_status(
        "token total amount missing selector rejected",
        parse_policy(
            "missing-selector",
            R"JSON({"schema":"signing.policy","defaultAction":"reject","blockchains":[{"blockchain":"sui","networks":[{"network":"testnet","policies":[{"id":"missing-selector","action":"sign","conditions":[{"field":"sui.token_totals_by_type.amount_raw","op":"lte","value":"1000000000"}]}]}]}]})JSON",
            proposal),
        signing::PolicyProposalParseStatus::invalid_policy);
    expect_status(
        "where selector on scalar field rejected",
        parse_policy(
            "forbidden-selector",
            R"JSON({"schema":"signing.policy","defaultAction":"reject","blockchains":[{"blockchain":"sui","networks":[{"network":"testnet","policies":[{"id":"forbidden-selector","action":"reject","conditions":[{"field":"sui.gas_budget_raw","where":{"type":"0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI"},"op":"lte","value":"10000000"}]}]}]}]})JSON",
            proposal),
        signing::PolicyProposalParseStatus::invalid_policy);
    expect_status(
        "u64 overflow rejected",
        parse_policy(
            "u64-overflow",
            R"JSON({"schema":"signing.policy","defaultAction":"reject","blockchains":[{"blockchain":"sui","networks":[{"network":"testnet","policies":[{"id":"u64-overflow","action":"reject","conditions":[{"field":"sui.gas_budget_raw","op":"lte","value":"18446744073709551616"}]}]}]}]})JSON",
            proposal),
        signing::PolicyProposalParseStatus::invalid_policy);
    expect_status(
        "u64 leading zero rejected",
        parse_policy(
            "u64-leading-zero",
            R"JSON({"schema":"signing.policy","defaultAction":"reject","blockchains":[{"blockchain":"sui","networks":[{"network":"testnet","policies":[{"id":"u64-leading-zero","action":"reject","conditions":[{"field":"sui.gas_budget_raw","op":"lte","value":"0001"}]}]}]}]})JSON",
            proposal),
        signing::PolicyProposalParseStatus::invalid_policy);
    expect_status(
        "sign policy requires conditions",
        parse_policy(
            "empty-sign",
            R"JSON({"schema":"signing.policy","defaultAction":"reject","blockchains":[{"blockchain":"sui","networks":[{"network":"testnet","policies":[{"id":"empty-sign","action":"sign","conditions":[]}]}]}]})JSON",
            proposal),
        signing::PolicyProposalParseStatus::invalid_policy);
    expect_status(
        "duplicate policy id rejected in scope",
        parse_policy(
            "duplicate-policy",
            R"JSON({"schema":"signing.policy","defaultAction":"reject","blockchains":[{"blockchain":"sui","networks":[{"network":"testnet","policies":[{"id":"same","action":"reject","conditions":[]},{"id":"same","action":"reject","conditions":[]}]}]}]})JSON",
            proposal),
        signing::PolicyProposalParseStatus::invalid_policy);
    expect_status(
        "duplicate network rejected in blockchain scope",
        parse_policy(
            "duplicate-network",
            R"JSON({"schema":"signing.policy","defaultAction":"reject","blockchains":[{"blockchain":"sui","networks":[{"network":"testnet","policies":[]},{"network":"testnet","policies":[]}]}]})JSON",
            proposal),
        signing::PolicyProposalParseStatus::invalid_policy);
    expect_status(
        "duplicate blockchain rejected",
        parse_policy(
            "duplicate-blockchain",
            R"JSON({"schema":"signing.policy","defaultAction":"reject","blockchains":[{"blockchain":"sui","networks":[]},{"blockchain":"sui","networks":[]}]})JSON",
            proposal),
        signing::PolicyProposalParseStatus::invalid_policy);

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
  -I"${TARGET_ROOT}/runtime" \
  -I"${COMMON_ROOT}" \
  -I"${ARDUINOJSON_ROOT}" \
  "${TMP_DIR}/policy_proposal_parser_test.cpp" \
  "${REPO_ROOT}/firmware/src/common/policy/policy_proposal_parser.cpp" \
  "${COMMON_POLICY_DIR}/document.cpp" \
  -o "${TMP_DIR}/policy_proposal_parser_test"

"${TMP_DIR}/policy_proposal_parser_test"
