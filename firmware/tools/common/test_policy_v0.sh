#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/common/test_policy_v0.sh

Compiles the common Agent-Q policy evaluator/runtime boundary with a host C++
compiler and checks Sui programmable-transaction policy facts against positive
and negative policy cases.
This test does not require ESP-IDF and does not depend on .WORK paths.
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
FIXTURE_DIR="${COMMON_SUI_DIR}/testdata/sui_transaction_facts"
CONTRACT_PATH="${REPO_ROOT}/specs/sui-sign-transaction-policy-contract.tsv"

node "${REPO_ROOT}/tools/generate_sui_policy_contract.mjs" --check

for required in \
  "${COMMON_ROOT}/agent_q_u64_decimal.h" \
  "${COMMON_POLICY_DIR}/agent_q_policy_v0.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_v0.h" \
  "${COMMON_POLICY_DIR}/agent_q_policy_schema.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_schema.h" \
  "${COMMON_POLICY_DIR}/agent_q_policy_u64.h" \
  "${COMMON_POLICY_DIR}/agent_q_policy_runtime.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_runtime.h" \
  "${COMMON_SUI_DIR}/agent_q_sui_bcs_reader.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_method_adapter.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_method_adapter.h" \
  "${COMMON_SUI_DIR}/agent_q_sui_token_flow_facts.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_token_flow_facts.h" \
  "${COMMON_SUI_DIR}/agent_q_sui_transaction_facts.cpp" \
  "${CONTRACT_PATH}" \
  "${FIXTURE_DIR}/valid_sui_transfer_tx.bcs.hex" \
  "${FIXTURE_DIR}/merge_coins_tx.bcs.hex"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required file: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-policy-v0.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/policy_v0_test.cpp" <<'CPP'
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <sstream>
#include <vector>

#include "agent_q_u64_decimal.h"
#include "agent_q_policy_v0.h"
#include "agent_q_policy_runtime_test.h"
#include "agent_q_sui_method_adapter.h"
#include "agent_q_sui_transaction_facts.h"

namespace {

struct PolicyContractField {
    std::string field;
    agent_q::AgentQPolicyValueType type;
    bool allow_eq;
    bool allow_in;
    bool allow_lte;
};

struct PolicyContractSignBound {
    std::string kind;
    std::string field;
    std::string value;
};

struct PolicyContract {
    std::vector<PolicyContractField> fields;
    std::vector<PolicyContractSignBound> sign_bounds;
};

std::string read_file(const char* path)
{
    FILE* file = fopen(path, "rb");
    if (file == nullptr) {
        fprintf(stderr, "Could not open %s\n", path);
        exit(1);
    }
    std::string data;
    char buffer[4096];
    while (true) {
        const size_t read = fread(buffer, 1, sizeof(buffer), file);
        if (read != 0) {
            data.append(buffer, read);
        }
        if (read < sizeof(buffer)) {
            if (ferror(file)) {
                fprintf(stderr, "Could not read %s\n", path);
                fclose(file);
                exit(1);
            }
            break;
        }
    }
    fclose(file);
    return data;
}

bool parse_contract_bool(const std::string& value, bool* out)
{
    if (out == nullptr) {
        return false;
    }
    if (value == "yes") {
        *out = true;
        return true;
    }
    if (value == "no") {
        *out = false;
        return true;
    }
    return false;
}

bool parse_contract_type(const std::string& value, agent_q::AgentQPolicyValueType* out)
{
    if (out == nullptr) {
        return false;
    }
    if (value == "string") {
        *out = agent_q::AgentQPolicyValueType::string;
        return true;
    }
    if (value == "u64_decimal") {
        *out = agent_q::AgentQPolicyValueType::u64_decimal;
        return true;
    }
    return false;
}

std::string replace_first_placeholder(const std::string& pattern, size_t value)
{
    const std::string placeholder = "{}";
    const size_t offset = pattern.find(placeholder);
    if (offset == std::string::npos) {
        return pattern;
    }
    std::string output = pattern;
    output.replace(offset, placeholder.size(), std::to_string(value));
    return output;
}

PolicyContractField make_contract_field(
    const std::string& field,
    const std::string& type_name,
    const std::string& allow_eq,
    const std::string& allow_in,
    const std::string& allow_lte,
    int* failures)
{
    PolicyContractField output = {};
    output.field = field;
    if (!parse_contract_type(type_name, &output.type) ||
        !parse_contract_bool(allow_eq, &output.allow_eq) ||
        !parse_contract_bool(allow_in, &output.allow_in) ||
        !parse_contract_bool(allow_lte, &output.allow_lte)) {
        fprintf(stderr, "Invalid policy contract field row for %s\n", field.c_str());
        *failures += 1;
    }
    return output;
}

PolicyContract read_policy_contract(const char* path, int* failures)
{
    PolicyContract contract = {};
    const std::string raw = read_file(path);
    std::istringstream lines(raw);
    std::string line;
    size_t line_number = 0;
    while (std::getline(lines, line)) {
        ++line_number;
        if (line.empty() || line[0] == '#') {
            continue;
        }
        std::istringstream columns(line);
        std::vector<std::string> parts;
        std::string part;
        while (columns >> part) {
            parts.push_back(part);
        }
        if (parts.empty()) {
            continue;
        }
        if (parts[0] == "field" && parts.size() == 6) {
            contract.fields.push_back(make_contract_field(
                parts[1],
                parts[2],
                parts[3],
                parts[4],
                parts[5],
                failures));
            continue;
        }
        if (parts[0] == "generated" && parts.size() == 7) {
            const size_t count = static_cast<size_t>(strtoull(parts[2].c_str(), nullptr, 10));
            for (size_t index = 0; index < count; ++index) {
                contract.fields.push_back(make_contract_field(
                    replace_first_placeholder(parts[1], index),
                    parts[3],
                    parts[4],
                    parts[5],
                    parts[6],
                    failures));
            }
            continue;
        }
        if (parts[0] == "generated2" && parts.size() == 8) {
            const size_t outer_count = static_cast<size_t>(strtoull(parts[2].c_str(), nullptr, 10));
            const size_t inner_count = static_cast<size_t>(strtoull(parts[3].c_str(), nullptr, 10));
            for (size_t outer = 0; outer < outer_count; ++outer) {
                for (size_t inner = 0; inner < inner_count; ++inner) {
                    contract.fields.push_back(make_contract_field(
                        replace_first_placeholder(
                            replace_first_placeholder(parts[1], outer),
                            inner),
                        parts[4],
                        parts[5],
                        parts[6],
                        parts[7],
                        failures));
                }
            }
            continue;
        }
        if ((parts[0] == "sign_eq" && parts.size() == 3) ||
            (parts[0] == "sign_string" && parts.size() == 2) ||
            (parts[0] == "sign_string_eq" && parts.size() == 2) ||
            (parts[0] == "sign_lte" && parts.size() == 2)) {
            contract.sign_bounds.push_back(PolicyContractSignBound{
                parts[0],
                parts[1],
                parts.size() == 3 ? parts[2] : "",
            });
            continue;
        }
        fprintf(stderr, "Invalid policy contract row at line %zu: %s\n", line_number, line.c_str());
        *failures += 1;
    }
    return contract;
}

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

std::vector<uint8_t> read_hex_fixture(const char* path)
{
    const std::string raw = read_file(path);
    std::string hex;
    for (char ch : raw) {
        if (!isspace(static_cast<unsigned char>(ch))) {
            hex.push_back(ch);
        }
    }
    if (hex.size() % 2 != 0) {
        fprintf(stderr, "Odd-length hex fixture: %s\n", path);
        exit(1);
    }
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t index = 0; index < hex.size(); index += 2) {
        const int high = hex_value(hex[index]);
        const int low = hex_value(hex[index + 1]);
        if (high < 0 || low < 0) {
            fprintf(stderr, "Invalid hex fixture: %s\n", path);
            exit(1);
        }
        bytes.push_back(static_cast<uint8_t>((high << 4) | low));
    }
    return bytes;
}

void expect_decision(
    const char* label,
    const agent_q::AgentQPolicyDocument& policy,
    const agent_q::AgentQPolicyFacts& facts,
    agent_q::AgentQPolicyAction expected_action,
    agent_q::AgentQPolicyDecisionReason expected_reason,
    const char* expected_rule_id,
    int* failures)
{
    const agent_q::AgentQPolicyDecision decision = agent_q::evaluate_agent_q_policy_v0(policy, facts);
    if (decision.action != expected_action || decision.reason != expected_reason ||
        ((expected_rule_id == nullptr) != (decision.rule_id == nullptr)) ||
        (expected_rule_id != nullptr && strcmp(expected_rule_id, decision.rule_id) != 0)) {
        fprintf(stderr, "%s mismatch\n  expected: %s/%s/%s\n  actual:   %s/%s/%s\n",
                label,
                agent_q::agent_q_policy_action_name(expected_action),
                agent_q::agent_q_policy_decision_reason_name(expected_reason),
                expected_rule_id == nullptr ? "(none)" : expected_rule_id,
                agent_q::agent_q_policy_action_name(decision.action),
                agent_q::agent_q_policy_decision_reason_name(decision.reason),
                decision.rule_id == nullptr ? "(none)" : decision.rule_id);
        *failures += 1;
    }
}

void expect_runtime_decision(
    const char* label,
    const agent_q::AgentQPolicyProvider& provider,
    const agent_q::AgentQPolicyFacts& facts,
    agent_q::AgentQPolicyAction expected_action,
    agent_q::AgentQPolicyDecisionReason expected_reason,
    const char* expected_rule_id,
    int* failures)
{
    const agent_q::AgentQPolicyDecision decision =
        agent_q::evaluate_agent_q_policy_runtime(provider, facts);
    if (decision.action != expected_action || decision.reason != expected_reason ||
        ((expected_rule_id == nullptr) != (decision.rule_id == nullptr)) ||
        (expected_rule_id != nullptr && strcmp(expected_rule_id, decision.rule_id) != 0)) {
        fprintf(stderr, "%s mismatch\n  expected: %s/%s/%s\n  actual:   %s/%s/%s\n",
                label,
                agent_q::agent_q_policy_action_name(expected_action),
                agent_q::agent_q_policy_decision_reason_name(expected_reason),
                expected_rule_id == nullptr ? "(none)" : expected_rule_id,
                agent_q::agent_q_policy_action_name(decision.action),
                agent_q::agent_q_policy_decision_reason_name(decision.reason),
                decision.rule_id == nullptr ? "(none)" : decision.rule_id);
        *failures += 1;
    }
}

void expect_method_runtime_decision(
    const char* label,
    const agent_q::AgentQPolicyProvider& provider,
    const agent_q::AgentQPolicyFacts& facts,
    const agent_q::AgentQPolicyMethodDescriptor* methods,
    size_t method_count,
    agent_q::AgentQPolicyAction expected_action,
    agent_q::AgentQPolicyDecisionReason expected_reason,
    const char* expected_rule_id,
    int* failures)
{
    const agent_q::AgentQPolicyDecision decision =
        agent_q::evaluate_agent_q_policy_runtime(provider, facts, methods, method_count);
    if (decision.action != expected_action || decision.reason != expected_reason ||
        ((expected_rule_id == nullptr) != (decision.rule_id == nullptr)) ||
        (expected_rule_id != nullptr && strcmp(expected_rule_id, decision.rule_id) != 0)) {
        fprintf(stderr, "%s mismatch\n  expected: %s/%s/%s\n  actual:   %s/%s/%s\n",
                label,
                agent_q::agent_q_policy_action_name(expected_action),
                agent_q::agent_q_policy_decision_reason_name(expected_reason),
                expected_rule_id == nullptr ? "(none)" : expected_rule_id,
                agent_q::agent_q_policy_action_name(decision.action),
                agent_q::agent_q_policy_decision_reason_name(decision.reason),
                decision.rule_id == nullptr ? "(none)" : decision.rule_id);
        *failures += 1;
    }
}

void expect_u64_format(uint64_t value, const char* expected, int* failures)
{
    char buffer[agent_q::kAgentQU64DecimalBufferBytes] = {};
    if (!agent_q::format_u64_decimal(value, buffer, sizeof(buffer)) ||
        strcmp(buffer, expected) != 0) {
        fprintf(stderr, "u64 format mismatch\n  expected: %s\n  actual:   %s\n",
                expected,
                buffer);
        *failures += 1;
    }
}

const agent_q::AgentQPolicyFieldDescriptor* find_policy_contract_descriptor(
    const char* field,
    const agent_q::AgentQPolicyMethodDescriptor& method)
{
    const agent_q::AgentQPolicyFieldDescriptor* common =
        agent_q::agent_q_policy_find_common_field_descriptor(field);
    if (common != nullptr) {
        return common;
    }
    for (size_t index = 0; index < method.field_descriptor_count; ++index) {
        const agent_q::AgentQPolicyFieldDescriptor& descriptor = method.field_descriptors[index];
        if (strcmp(descriptor.field, field) == 0) {
            return &descriptor;
        }
    }
    return nullptr;
}

const PolicyContractField* find_contract_field(
    const PolicyContract& contract,
    const char* field)
{
    for (const PolicyContractField& entry : contract.fields) {
        if (entry.field == field) {
            return &entry;
        }
    }
    return nullptr;
}

agent_q::AgentQPolicyOperator sign_bound_operator(const std::string& kind)
{
    if (kind == "sign_lte") {
        return agent_q::AgentQPolicyOperator::lte;
    }
    return agent_q::AgentQPolicyOperator::eq;
}

std::string sign_bound_value(const PolicyContractSignBound& bound)
{
    if (bound.kind == "sign_eq") {
        return bound.value;
    }
    if (bound.kind == "sign_lte") {
        return "1";
    }
    if (bound.field == "sui.sender_address" ||
        bound.field == "sui.gas_owner_address" ||
        bound.field == "sui.recipient0_address") {
        return "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    }
    if (bound.field == "sui.expiration_kind") {
        return "none";
    }
    return "value";
}

bool build_sign_rule_from_contract(
    const PolicyContract& contract,
    size_t omitted_bound,
    std::vector<std::string>* field_storage,
    std::vector<std::string>* value_storage,
    std::vector<agent_q::AgentQPolicyCriterion>* criteria,
    agent_q::AgentQPolicyRule* rule)
{
    if (field_storage == nullptr || value_storage == nullptr || criteria == nullptr || rule == nullptr) {
        return false;
    }
    field_storage->clear();
    value_storage->clear();
    criteria->clear();
    field_storage->reserve(contract.sign_bounds.size());
    value_storage->reserve(contract.sign_bounds.size());
    criteria->reserve(contract.sign_bounds.size());
    for (size_t index = 0; index < contract.sign_bounds.size(); ++index) {
        if (index == omitted_bound) {
            continue;
        }
        const PolicyContractSignBound& bound = contract.sign_bounds[index];
        field_storage->push_back(bound.field);
        value_storage->push_back(sign_bound_value(bound));
    }
    size_t storage_index = 0;
    for (size_t index = 0; index < contract.sign_bounds.size(); ++index) {
        if (index == omitted_bound) {
            continue;
        }
        const PolicyContractSignBound& bound = contract.sign_bounds[index];
        criteria->push_back(agent_q::AgentQPolicyCriterion{
            field_storage->at(storage_index).c_str(),
            sign_bound_operator(bound.kind),
            value_storage->at(storage_index).c_str(),
            nullptr,
            0,
        });
        ++storage_index;
    }
    *rule = agent_q::AgentQPolicyRule{
        "contract-sign",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::sign,
        criteria->empty() ? nullptr : criteria->data(),
        criteria->size(),
    };
    return true;
}

void verify_policy_contract_parity(
    const PolicyContract& contract,
    int* failures)
{
    const agent_q::AgentQPolicyMethodDescriptor method =
        agent_q::sui_sign_transaction_policy_method_descriptor();
    const size_t expected_field_count =
        agent_q::kAgentQPolicyCommonFieldDescriptorCount + method.field_descriptor_count;
    if (contract.fields.size() != expected_field_count) {
        fprintf(stderr,
                "policy contract field count mismatch: expected %zu actual %zu\n",
                expected_field_count,
                contract.fields.size());
        *failures += 1;
    }
    for (const PolicyContractField& field : contract.fields) {
        const agent_q::AgentQPolicyFieldDescriptor* descriptor =
            find_policy_contract_descriptor(field.field.c_str(), method);
        if (descriptor == nullptr) {
            fprintf(stderr, "policy contract field missing from firmware descriptor: %s\n", field.field.c_str());
            *failures += 1;
            continue;
        }
        if (descriptor->type != field.type ||
            descriptor->allow_eq != field.allow_eq ||
            descriptor->allow_in != field.allow_in ||
            descriptor->allow_lte != field.allow_lte) {
            fprintf(stderr, "policy contract descriptor mismatch for %s\n", field.field.c_str());
            *failures += 1;
        }
    }
    for (size_t index = 0; index < agent_q::kAgentQPolicyCommonFieldDescriptorCount; ++index) {
        if (find_contract_field(contract, agent_q::kAgentQPolicyCommonFieldDescriptors[index].field) == nullptr) {
            fprintf(stderr,
                    "firmware common descriptor missing from policy contract: %s\n",
                    agent_q::kAgentQPolicyCommonFieldDescriptors[index].field);
            *failures += 1;
        }
    }
    for (size_t index = 0; index < method.field_descriptor_count; ++index) {
        if (find_contract_field(contract, method.field_descriptors[index].field) == nullptr) {
            fprintf(stderr,
                    "firmware Sui descriptor missing from policy contract: %s\n",
                    method.field_descriptors[index].field);
            *failures += 1;
        }
    }

    std::vector<std::string> fields;
    std::vector<std::string> values;
    std::vector<agent_q::AgentQPolicyCriterion> criteria;
    agent_q::AgentQPolicyRule sign_rule = {};
    if (!build_sign_rule_from_contract(
            contract,
            static_cast<size_t>(-1),
            &fields,
            &values,
            &criteria,
            &sign_rule) ||
        !agent_q::sui_sign_transaction_policy_sign_rule_is_bounded(sign_rule)) {
        fprintf(stderr, "policy contract sign bounds should satisfy firmware Sui sign-rule validator\n");
        *failures += 1;
    }
    for (size_t omitted = 0; omitted < contract.sign_bounds.size(); ++omitted) {
        if (!build_sign_rule_from_contract(contract, omitted, &fields, &values, &criteria, &sign_rule)) {
            fprintf(stderr, "could not build policy contract sign rule\n");
            *failures += 1;
            continue;
        }
        if (agent_q::sui_sign_transaction_policy_sign_rule_is_bounded(sign_rule)) {
            fprintf(stderr,
                    "policy contract sign bound is not enforced by firmware validator: %s\n",
                    contract.sign_bounds[omitted].field.c_str());
            *failures += 1;
        }
    }
}

agent_q::AgentQPolicyDocument one_rule_policy(const agent_q::AgentQPolicyRule* rule)
{
    return agent_q::AgentQPolicyDocument{
        agent_q::kAgentQPolicyV0Schema,
        agent_q::AgentQPolicyAction::reject,
        rule,
        1,
    };
}

struct FixedPolicyProviderContext {
    agent_q::AgentQPolicyDocument policy;
};

bool load_fixed_policy(agent_q::AgentQPolicyDocument* out, void* context)
{
    if (out == nullptr || context == nullptr) {
        return false;
    }
    *out = static_cast<FixedPolicyProviderContext*>(context)->policy;
    return true;
}

bool load_missing_policy(agent_q::AgentQPolicyDocument* out, void* context)
{
    (void)out;
    (void)context;
    return false;
}

agent_q::SuiTransactionFactsResult parse_policy_subject(
    const uint8_t* bytes,
    size_t size,
    const char* request_network,
    agent_q::AgentQSuiSignTransactionPolicySubject* out)
{
    if (out != nullptr) {
        *out = {};
    }
    agent_q::SuiParsedTransactionFacts parsed = {};
    const agent_q::SuiTransactionFactsResult result =
        agent_q::parse_sui_parsed_transaction_facts(bytes, size, &parsed);
    if (result != agent_q::SuiTransactionFactsResult::ok) {
        return result;
    }
    return agent_q::build_sui_sign_transaction_policy_subject(parsed, request_network, out)
               ? agent_q::SuiTransactionFactsResult::ok
               : agent_q::SuiTransactionFactsResult::unsupported_shape;
}

}  // namespace

int main(int argc, char** argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s /path/to/fixture_dir /path/to/policy_contract.tsv\n", argv[0]);
        return 2;
    }

    const std::string fixture_dir = argv[1];
    const std::string contract_path = argv[2];
    int failures = 0;

    const PolicyContract contract = read_policy_contract(contract_path.c_str(), &failures);
    verify_policy_contract_parity(contract, &failures);

    expect_u64_format(0, "0", &failures);
    expect_u64_format(1, "1", &failures);
    expect_u64_format(1000000, "1000000", &failures);
    expect_u64_format(UINT64_MAX, "18446744073709551615", &failures);
    char small_buffer[2] = {};
    if (agent_q::format_u64_decimal(100, small_buffer, sizeof(small_buffer))) {
        fprintf(stderr, "u64 formatter should reject undersized output buffers\n");
        failures += 1;
    }

    const std::vector<uint8_t> valid =
        read_hex_fixture((fixture_dir + "/valid_sui_transfer_tx.bcs.hex").c_str());
    agent_q::AgentQSuiSignTransactionPolicySubject sui_subject = {};
    const agent_q::SuiTransactionFactsResult parse_result =
        parse_policy_subject(valid.data(), valid.size(), "testnet", &sui_subject);
    if (parse_result != agent_q::SuiTransactionFactsResult::ok) {
        fprintf(stderr, "valid Sui transfer fixture did not parse\n");
        return 1;
    }
    const agent_q::SuiPolicySubjectFacts& sui_facts = sui_subject.transaction;

    agent_q::AgentQSuiSignTransactionPolicyFacts policy_facts = {};
    if (!agent_q::make_sui_sign_transaction_policy_facts(sui_subject, &policy_facts)) {
        fprintf(stderr, "Sui method adapter rejected valid transfer facts\n");
        return 1;
    }
    const agent_q::AgentQPolicyFacts facts = policy_facts.facts;

    const agent_q::AgentQPolicyProvider default_policy_provider =
        agent_q::agent_q_default_reject_policy_provider();
    expect_runtime_decision(
        "runtime default reject policy",
        default_policy_provider,
        facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::default_reject,
        nullptr,
        &failures);

    const agent_q::AgentQPolicyProvider missing_policy_provider = {load_missing_policy, nullptr};
    expect_runtime_decision(
        "runtime missing policy provider",
        missing_policy_provider,
        facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::invalid_policy,
        nullptr,
        &failures);

    const agent_q::AgentQPolicyProvider null_policy_provider = {nullptr, nullptr};
    expect_runtime_decision(
        "runtime null policy provider",
        null_policy_provider,
        facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::invalid_policy,
        nullptr,
        &failures);

    agent_q::AgentQSuiSignTransactionPolicySubject missing_gas_owner_subject = sui_subject;
    missing_gas_owner_subject.transaction.gas_owner[0] = '\0';
    agent_q::AgentQSuiSignTransactionPolicyFacts invalid_owner_facts = {};
    if (agent_q::make_sui_sign_transaction_policy_facts(
            missing_gas_owner_subject,
            &invalid_owner_facts)) {
        fprintf(stderr, "Sui method adapter accepted missing gas owner\n");
        failures += 1;
    }
    agent_q::AgentQSuiSignTransactionPolicySubject sponsored_gas_owner_subject = sui_subject;
    snprintf(
        sponsored_gas_owner_subject.transaction.gas_owner,
        sizeof(sponsored_gas_owner_subject.transaction.gas_owner),
        "%s",
        "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    if (!agent_q::make_sui_sign_transaction_policy_facts(
            sponsored_gas_owner_subject,
            &invalid_owner_facts)) {
        fprintf(stderr, "Sui method adapter rejected parse-derived sender/gas-owner mismatch facts\n");
        failures += 1;
    }

    const agent_q::AgentQPolicyCriterion allow_criteria[] = {
        {"common.intent", agent_q::AgentQPolicyOperator::eq, agent_q::kAgentQPolicyIntentProgrammableTransaction, nullptr, 0},
        {"sui.sender_address", agent_q::AgentQPolicyOperator::eq, sui_facts.sender, nullptr, 0},
        {"sui.command_count", agent_q::AgentQPolicyOperator::eq, "2", nullptr, 0},
        {"sui.command0_kind", agent_q::AgentQPolicyOperator::eq, agent_q::kAgentQSuiPolicyCommandKindSplitCoins, nullptr, 0},
        {"sui.command1_kind", agent_q::AgentQPolicyOperator::eq, agent_q::kAgentQSuiPolicyCommandKindTransferObjects, nullptr, 0},
        {"sui.gas_budget", agent_q::AgentQPolicyOperator::lte, "50000000", nullptr, 0},
        {"sui.gas_price", agent_q::AgentQPolicyOperator::lte, sui_facts.gas_price, nullptr, 0},
    };
    const agent_q::AgentQPolicyRule matching_rule = {
        "reject-transfer-shape",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::reject,
        allow_criteria,
        sizeof(allow_criteria) / sizeof(allow_criteria[0]),
    };
    const agent_q::AgentQPolicyDocument matching_policy = one_rule_policy(&matching_rule);
    expect_decision(
        "matching reject rule",
        matching_policy,
        facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::matched_rule,
        "reject-transfer-shape",
        &failures);

    agent_q::AgentQSuiSignTransactionPolicySubject mainnet_subject = {};
    if (parse_policy_subject(valid.data(), valid.size(), "mainnet", &mainnet_subject) !=
        agent_q::SuiTransactionFactsResult::ok) {
        fprintf(stderr, "valid Sui transfer fixture did not parse with mainnet context\n");
        failures += 1;
    }

    agent_q::AgentQSuiSignTransactionPolicySubject invalid_network_subject = {};
    if (parse_policy_subject(valid.data(), valid.size(), "unknownnet", &invalid_network_subject) ==
        agent_q::SuiTransactionFactsResult::ok) {
        fprintf(stderr, "Sui method adapter accepted unsupported request network\n");
        failures += 1;
    }

    const agent_q::AgentQPolicyCriterion token_limit_criteria[] = {
        {"sui.sui_total_out_complete", agent_q::AgentQPolicyOperator::eq, "yes", nullptr, 0},
        {"sui.sui_total_out_raw", agent_q::AgentQPolicyOperator::lte, "1000000", nullptr, 0},
        {"sui.recipient0_amount_raw", agent_q::AgentQPolicyOperator::lte, "1000000", nullptr, 0},
    };
    const agent_q::AgentQPolicyRule token_limit_rule = {
        "reject-token-limit",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::reject,
        token_limit_criteria,
        sizeof(token_limit_criteria) / sizeof(token_limit_criteria[0]),
    };
    expect_decision(
        "token amount facts match",
        one_rule_policy(&token_limit_rule),
        facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::matched_rule,
        "reject-token-limit",
        &failures);

    const agent_q::AgentQPolicyCriterion token_limit_too_low_criteria[] = {
        {"sui.sui_total_out_complete", agent_q::AgentQPolicyOperator::eq, "yes", nullptr, 0},
        {"sui.sui_total_out_raw", agent_q::AgentQPolicyOperator::lte, "999999", nullptr, 0},
    };
    const agent_q::AgentQPolicyRule token_limit_too_low_rule = {
        "reject-token-limit-too-low",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::reject,
        token_limit_too_low_criteria,
        sizeof(token_limit_too_low_criteria) / sizeof(token_limit_too_low_criteria[0]),
    };
    expect_decision(
        "token amount over limit does not match",
        one_rule_policy(&token_limit_too_low_rule),
        facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::default_reject,
        nullptr,
        &failures);

    const agent_q::AgentQPolicyCriterion complete_transfer_sign_criteria[] = {
        {"common.chain", agent_q::AgentQPolicyOperator::eq, "sui", nullptr, 0},
        {"common.method", agent_q::AgentQPolicyOperator::eq, "sign_transaction", nullptr, 0},
        {"common.intent", agent_q::AgentQPolicyOperator::eq, agent_q::kAgentQPolicyIntentProgrammableTransaction, nullptr, 0},
        {"sui.transaction_kind", agent_q::AgentQPolicyOperator::eq, "programmable_transaction", nullptr, 0},
        {"sui.sender_address", agent_q::AgentQPolicyOperator::eq, sui_facts.sender, nullptr, 0},
        {"sui.gas_owner_address", agent_q::AgentQPolicyOperator::eq, sui_facts.gas_owner, nullptr, 0},
        {"sui.gas_budget", agent_q::AgentQPolicyOperator::lte, "50000000", nullptr, 0},
        {"sui.gas_price", agent_q::AgentQPolicyOperator::lte, sui_facts.gas_price, nullptr, 0},
        {"sui.expiration_kind", agent_q::AgentQPolicyOperator::eq, "none", nullptr, 0},
        {"sui.sui_total_out_complete", agent_q::AgentQPolicyOperator::eq, "yes", nullptr, 0},
        {"sui.sui_total_out_raw", agent_q::AgentQPolicyOperator::lte, "1000000", nullptr, 0},
        {"sui.command_count", agent_q::AgentQPolicyOperator::eq, "2", nullptr, 0},
        {"sui.command0_kind", agent_q::AgentQPolicyOperator::eq, agent_q::kAgentQSuiPolicyCommandKindSplitCoins, nullptr, 0},
        {"sui.command1_kind", agent_q::AgentQPolicyOperator::eq, agent_q::kAgentQSuiPolicyCommandKindTransferObjects, nullptr, 0},
        {"sui.recipient_count", agent_q::AgentQPolicyOperator::eq, "1", nullptr, 0},
        {"sui.recipient0_address", agent_q::AgentQPolicyOperator::eq, sui_subject.token_flow.recipient0_address, nullptr, 0},
        {"sui.recipient0_amount_raw", agent_q::AgentQPolicyOperator::lte, "1000000", nullptr, 0},
        {"sui.coin_flow0_source_kind", agent_q::AgentQPolicyOperator::eq, "split_result", nullptr, 0},
        {"sui.coin_flow0_asset_state", agent_q::AgentQPolicyOperator::eq, "proven_sui", nullptr, 0},
        {"sui.coin_flow0_amount_known", agent_q::AgentQPolicyOperator::eq, "yes", nullptr, 0},
        {"sui.coin_flow0_sink_kind", agent_q::AgentQPolicyOperator::eq, "transfer_recipient", nullptr, 0},
    };
    const agent_q::AgentQPolicyRule complete_transfer_sign_rule = {
        "sign-complete-transfer",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::sign,
        complete_transfer_sign_criteria,
        sizeof(complete_transfer_sign_criteria) / sizeof(complete_transfer_sign_criteria[0]),
    };
    if (!agent_q::sui_sign_transaction_policy_sign_rule_is_bounded(complete_transfer_sign_rule)) {
        fprintf(stderr, "complete transfer sign rule should be bounded by the Sui method adapter\n");
        failures += 1;
    }
    char complete_transfer_sign_summary[128] = {};
    if (!agent_q::sui_sign_transaction_policy_build_sign_rule_summary(
            complete_transfer_sign_rule,
            complete_transfer_sign_summary,
            sizeof(complete_transfer_sign_summary)) ||
        strstr(complete_transfer_sign_summary, "GasCoin split-result transfer") == nullptr ||
        strstr(complete_transfer_sign_summary, "amt<=1000000") == nullptr ||
        strstr(complete_transfer_sign_summary, "total<=1000000") == nullptr ||
        strstr(complete_transfer_sign_summary, "gas<=50000000/") == nullptr) {
        fprintf(stderr,
                "complete transfer sign summary mismatch: %s\n",
                complete_transfer_sign_summary);
        failures += 1;
    }
    expect_decision(
        "generic policy evaluator keeps sign disabled without method descriptors",
        one_rule_policy(&complete_transfer_sign_rule),
        facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::invalid_policy,
        nullptr,
        &failures);
    const agent_q::AgentQPolicyMethodDescriptor sui_methods[] = {
        agent_q::sui_sign_transaction_policy_method_descriptor(),
    };
    FixedPolicyProviderContext complete_transfer_sign_context = {
        one_rule_policy(&complete_transfer_sign_rule),
    };
    const agent_q::AgentQPolicyProvider complete_transfer_sign_provider = {
        load_fixed_policy,
        &complete_transfer_sign_context,
    };
    expect_method_runtime_decision(
        "method-aware runtime authorizes bounded transfer sign rule",
        complete_transfer_sign_provider,
        facts,
        sui_methods,
        sizeof(sui_methods) / sizeof(sui_methods[0]),
        agent_q::AgentQPolicyAction::sign,
        agent_q::AgentQPolicyDecisionReason::matched_rule,
        "sign-complete-transfer",
        &failures);

    const std::vector<uint8_t> move_call_tx =
        read_hex_fixture((fixture_dir + "/move_call_tx.bcs.hex").c_str());
    agent_q::AgentQSuiSignTransactionPolicySubject move_call_subject = {};
    const agent_q::SuiTransactionFactsResult move_call_parse_result =
        parse_policy_subject(move_call_tx.data(), move_call_tx.size(), "testnet", &move_call_subject);
    const agent_q::SuiPolicySubjectFacts& move_call_sui_facts = move_call_subject.transaction;
    if (move_call_parse_result != agent_q::SuiTransactionFactsResult::ok ||
        move_call_sui_facts.command_count != 1 ||
        move_call_sui_facts.commands[0].kind != agent_q::SuiCommandFactKind::move_call ||
        !move_call_sui_facts.commands[0].has_move_call ||
        move_call_sui_facts.commands[0].type_argument_count != 1 ||
        move_call_sui_facts.commands[0].move_call_type_args[0][0] == '\0') {
        fprintf(stderr, "MoveCall fixture did not produce generic policy subject facts\n");
        failures += 1;
    }
    char move_call_type_arg_count[agent_q::kSuiU64StringBufferSize] = {};
    snprintf(
        move_call_type_arg_count,
        sizeof(move_call_type_arg_count),
        "%u",
        static_cast<unsigned>(move_call_sui_facts.commands[0].type_argument_count));
    agent_q::AgentQSuiSignTransactionPolicyFacts move_call_policy_facts = {};
    if (!agent_q::make_sui_sign_transaction_policy_facts(
            move_call_subject,
            &move_call_policy_facts)) {
        fprintf(stderr, "Sui method adapter rejected generic MoveCall policy facts\n");
        failures += 1;
    }
    const agent_q::AgentQPolicyCriterion move_call_sign_criteria[] = {
        {"sui.command_count", agent_q::AgentQPolicyOperator::eq, "1", nullptr, 0},
        {"sui.command0_kind", agent_q::AgentQPolicyOperator::eq, agent_q::kAgentQSuiPolicyCommandKindMoveCall, nullptr, 0},
        {"sui.command0_move_call_package", agent_q::AgentQPolicyOperator::eq, move_call_sui_facts.commands[0].move_call_package, nullptr, 0},
        {"sui.command0_move_call_module", agent_q::AgentQPolicyOperator::eq, move_call_sui_facts.commands[0].move_call_module, nullptr, 0},
        {"sui.command0_move_call_function", agent_q::AgentQPolicyOperator::eq, move_call_sui_facts.commands[0].move_call_function, nullptr, 0},
        {"sui.command0_move_call_type_args", agent_q::AgentQPolicyOperator::eq, move_call_type_arg_count, nullptr, 0},
        {"sui.command0_move_call_type_arg0", agent_q::AgentQPolicyOperator::eq, move_call_sui_facts.commands[0].move_call_type_args[0], nullptr, 0},
        {"sui.gas_budget", agent_q::AgentQPolicyOperator::lte, move_call_sui_facts.gas_budget, nullptr, 0},
        {"sui.gas_price", agent_q::AgentQPolicyOperator::lte, move_call_sui_facts.gas_price, nullptr, 0},
    };
    const agent_q::AgentQPolicyRule move_call_sign_rule = {
        "sign-specific-move-call",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::sign,
        move_call_sign_criteria,
        sizeof(move_call_sign_criteria) / sizeof(move_call_sign_criteria[0]),
    };
    char unsupported_sign_summary[128] = {};
    if (agent_q::sui_sign_transaction_policy_build_sign_rule_summary(
            move_call_sign_rule,
            unsupported_sign_summary,
            sizeof(unsupported_sign_summary))) {
        fprintf(stderr, "MoveCall sign rule should not produce a bounded sign summary\n");
        failures += 1;
    }
    expect_decision(
        "MoveCall sign rule is outside the current automatic signing contract",
        one_rule_policy(&move_call_sign_rule),
        move_call_policy_facts.facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::invalid_policy,
        nullptr,
        &failures);

    const agent_q::AgentQPolicyCriterion move_call_missing_type_arg_criteria[] = {
        {"sui.command_count", agent_q::AgentQPolicyOperator::eq, "1", nullptr, 0},
        {"sui.command0_kind", agent_q::AgentQPolicyOperator::eq, agent_q::kAgentQSuiPolicyCommandKindMoveCall, nullptr, 0},
        {"sui.command0_move_call_package", agent_q::AgentQPolicyOperator::eq, move_call_sui_facts.commands[0].move_call_package, nullptr, 0},
        {"sui.command0_move_call_module", agent_q::AgentQPolicyOperator::eq, move_call_sui_facts.commands[0].move_call_module, nullptr, 0},
        {"sui.command0_move_call_function", agent_q::AgentQPolicyOperator::eq, move_call_sui_facts.commands[0].move_call_function, nullptr, 0},
        {"sui.gas_budget", agent_q::AgentQPolicyOperator::lte, move_call_sui_facts.gas_budget, nullptr, 0},
        {"sui.gas_price", agent_q::AgentQPolicyOperator::lte, move_call_sui_facts.gas_price, nullptr, 0},
    };
    const agent_q::AgentQPolicyRule move_call_missing_type_arg_rule = {
        "sign-move-call-missing-type-arg-bound",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::sign,
        move_call_missing_type_arg_criteria,
        sizeof(move_call_missing_type_arg_criteria) / sizeof(move_call_missing_type_arg_criteria[0]),
    };
    expect_decision(
        "MoveCall sign rule missing type-arg bound remains invalid",
        one_rule_policy(&move_call_missing_type_arg_rule),
        move_call_policy_facts.facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::invalid_policy,
        nullptr,
        &failures);

    const agent_q::AgentQPolicyCriterion missing_command_coverage_sign_criteria[] = {
        {"sui.command_count", agent_q::AgentQPolicyOperator::eq, "2", nullptr, 0},
        {"sui.command0_kind", agent_q::AgentQPolicyOperator::eq, agent_q::kAgentQSuiPolicyCommandKindMoveCall, nullptr, 0},
        {"sui.command0_move_call_package", agent_q::AgentQPolicyOperator::eq, move_call_sui_facts.commands[0].move_call_package, nullptr, 0},
        {"sui.command0_move_call_module", agent_q::AgentQPolicyOperator::eq, move_call_sui_facts.commands[0].move_call_module, nullptr, 0},
        {"sui.command0_move_call_function", agent_q::AgentQPolicyOperator::eq, move_call_sui_facts.commands[0].move_call_function, nullptr, 0},
        {"sui.command0_move_call_type_args", agent_q::AgentQPolicyOperator::eq, move_call_type_arg_count, nullptr, 0},
        {"sui.command0_move_call_type_arg0", agent_q::AgentQPolicyOperator::eq, move_call_sui_facts.commands[0].move_call_type_args[0], nullptr, 0},
        {"sui.gas_budget", agent_q::AgentQPolicyOperator::lte, move_call_sui_facts.gas_budget, nullptr, 0},
        {"sui.gas_price", agent_q::AgentQPolicyOperator::lte, move_call_sui_facts.gas_price, nullptr, 0},
    };
    const agent_q::AgentQPolicyRule missing_command_coverage_sign_rule = {
        "sign-missing-command-coverage",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::sign,
        missing_command_coverage_sign_criteria,
        sizeof(missing_command_coverage_sign_criteria) / sizeof(missing_command_coverage_sign_criteria[0]),
    };
    expect_decision(
        "sign rule missing command coverage is invalid",
        one_rule_policy(&missing_command_coverage_sign_rule),
        facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::invalid_policy,
        nullptr,
        &failures);

    const char* multiple_packages[] = {
        move_call_sui_facts.commands[0].move_call_package,
        "0x1111111111111111111111111111111111111111111111111111111111111111",
    };
    const agent_q::AgentQPolicyCriterion multi_package_sign_criteria[] = {
        {"sui.command_count", agent_q::AgentQPolicyOperator::eq, "1", nullptr, 0},
        {"sui.command0_kind", agent_q::AgentQPolicyOperator::eq, agent_q::kAgentQSuiPolicyCommandKindMoveCall, nullptr, 0},
        {"sui.command0_move_call_package", agent_q::AgentQPolicyOperator::in, nullptr, multiple_packages, 2},
        {"sui.command0_move_call_module", agent_q::AgentQPolicyOperator::eq, move_call_sui_facts.commands[0].move_call_module, nullptr, 0},
        {"sui.command0_move_call_function", agent_q::AgentQPolicyOperator::eq, move_call_sui_facts.commands[0].move_call_function, nullptr, 0},
        {"sui.command0_move_call_type_args", agent_q::AgentQPolicyOperator::eq, move_call_type_arg_count, nullptr, 0},
        {"sui.command0_move_call_type_arg0", agent_q::AgentQPolicyOperator::eq, move_call_sui_facts.commands[0].move_call_type_args[0], nullptr, 0},
        {"sui.gas_budget", agent_q::AgentQPolicyOperator::lte, move_call_sui_facts.gas_budget, nullptr, 0},
        {"sui.gas_price", agent_q::AgentQPolicyOperator::lte, move_call_sui_facts.gas_price, nullptr, 0},
    };
    const agent_q::AgentQPolicyRule multi_package_sign_rule = {
        "sign-multi-package",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::sign,
        multi_package_sign_criteria,
        sizeof(multi_package_sign_criteria) / sizeof(multi_package_sign_criteria[0]),
    };
    expect_decision(
        "multi-package sign rule missing common policy bounds is invalid",
        one_rule_policy(&multi_package_sign_rule),
        move_call_policy_facts.facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::invalid_policy,
        nullptr,
        &failures);

    const agent_q::AgentQPolicyRule second_sign_rule = {
        "sign-second-move-call",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::sign,
        move_call_sign_criteria,
        sizeof(move_call_sign_criteria) / sizeof(move_call_sign_criteria[0]),
    };
    const agent_q::AgentQPolicyRule two_sign_rules[] = {move_call_sign_rule, second_sign_rule};
    const agent_q::AgentQPolicyDocument two_sign_rule_policy = {
        agent_q::kAgentQPolicyV0Schema,
        agent_q::AgentQPolicyAction::reject,
        two_sign_rules,
        sizeof(two_sign_rules) / sizeof(two_sign_rules[0]),
    };
    expect_decision(
        "multiple sign rules remain invalid",
        two_sign_rule_policy,
        move_call_policy_facts.facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::invalid_policy,
        nullptr,
        &failures);

    const agent_q::AgentQPolicyRule later_match_rule = {
        "later-reject-small-sui-transfer",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::reject,
        allow_criteria,
        sizeof(allow_criteria) / sizeof(allow_criteria[0]),
    };
    const agent_q::AgentQPolicyRule first_match_rules[] = {matching_rule, later_match_rule};
    const agent_q::AgentQPolicyDocument first_match_policy = {
        agent_q::kAgentQPolicyV0Schema,
        agent_q::AgentQPolicyAction::reject,
        first_match_rules,
        2,
    };
    expect_decision(
        "first matching reject rule",
        first_match_policy,
        facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::matched_rule,
        "reject-transfer-shape",
        &failures);

    const agent_q::AgentQPolicyCriterion wrong_command_kind_criteria[] = {
        {"sui.command0_kind", agent_q::AgentQPolicyOperator::eq, agent_q::kAgentQSuiPolicyCommandKindMoveCall, nullptr, 0},
    };
    const agent_q::AgentQPolicyRule wrong_command_kind_rule = {
        "wrong-command-kind",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::reject,
        wrong_command_kind_criteria,
        1,
    };
    expect_decision(
        "command kind not allowed",
        one_rule_policy(&wrong_command_kind_rule),
        facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::default_reject,
        nullptr,
        &failures);

    const agent_q::AgentQPolicyCriterion command_count_limit_criteria[] = {
        {"sui.command_count", agent_q::AgentQPolicyOperator::lte, "1", nullptr, 0},
    };
    const agent_q::AgentQPolicyRule command_count_limit_rule = {
        "command-count-limit",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::reject,
        command_count_limit_criteria,
        1,
    };
    expect_decision(
        "command count over limit",
        one_rule_policy(&command_count_limit_rule),
        facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::default_reject,
        nullptr,
        &failures);

    const agent_q::AgentQPolicyCriterion gas_limit_criteria[] = {
        {"sui.gas_budget", agent_q::AgentQPolicyOperator::lte, "49999999", nullptr, 0},
    };
    const agent_q::AgentQPolicyRule gas_limit_rule = {
        "gas-limit",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::reject,
        gas_limit_criteria,
        1,
    };
    expect_decision(
        "gas over limit",
        one_rule_policy(&gas_limit_rule),
        facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::default_reject,
        nullptr,
        &failures);

    const agent_q::AgentQPolicyDocument invalid_default_policy = {
        agent_q::kAgentQPolicyV0Schema,
        static_cast<agent_q::AgentQPolicyAction>(255),
        &matching_rule,
        1,
    };
    expect_decision(
        "non-reject default action",
        invalid_default_policy,
        facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::invalid_policy,
        nullptr,
        &failures);

    FixedPolicyProviderContext invalid_policy_context = {invalid_default_policy};
    const agent_q::AgentQPolicyProvider invalid_policy_provider = {
        load_fixed_policy,
        &invalid_policy_context,
    };
    expect_runtime_decision(
        "runtime invalid policy provider",
        invalid_policy_provider,
        facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::invalid_policy,
        nullptr,
        &failures);

    const agent_q::AgentQPolicyCriterion unknown_criterion[] = {
        {"common.unknown", agent_q::AgentQPolicyOperator::eq, "devnet", nullptr, 0},
    };
    const agent_q::AgentQPolicyRule unknown_criterion_rule = {
        "unknown-criterion",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::reject,
        unknown_criterion,
        1,
    };
    expect_decision(
        "unknown criterion",
        one_rule_policy(&unknown_criterion_rule),
        facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::invalid_policy,
        nullptr,
        &failures);

    const agent_q::AgentQPolicyCriterion unsupported_op[] = {
        {"common.intent", static_cast<agent_q::AgentQPolicyOperator>(99), agent_q::kAgentQPolicyIntentProgrammableTransaction, nullptr, 0},
    };
    const agent_q::AgentQPolicyRule unsupported_op_rule = {
        "unsupported-op",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::reject,
        unsupported_op,
        1,
    };
    expect_decision(
        "unsupported operator",
        one_rule_policy(&unsupported_op_rule),
        facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::invalid_policy,
        nullptr,
        &failures);

    const agent_q::AgentQPolicyCriterion malformed_amount[] = {
        {"sui.gas_budget", agent_q::AgentQPolicyOperator::lte, "10.5", nullptr, 0},
    };
    const agent_q::AgentQPolicyRule malformed_amount_rule = {
        "malformed-amount",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::reject,
        malformed_amount,
        1,
    };
    expect_decision(
        "malformed numeric criterion",
        one_rule_policy(&malformed_amount_rule),
        facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::invalid_policy,
        nullptr,
        &failures);

    const agent_q::AgentQPolicyCriterion overflow_amount[] = {
        {"sui.gas_budget", agent_q::AgentQPolicyOperator::lte, "18446744073709551616", nullptr, 0},
    };
    const agent_q::AgentQPolicyRule overflow_amount_rule = {
        "overflow-amount",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::reject,
        overflow_amount,
        1,
    };
    expect_decision(
        "overflow numeric criterion",
        one_rule_policy(&overflow_amount_rule),
        facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::invalid_policy,
        nullptr,
        &failures);

    const char* allowed_intents[] = {agent_q::kAgentQPolicyIntentProgrammableTransaction};
    const agent_q::AgentQPolicyCriterion eq_with_list[] = {
        {"common.intent", agent_q::AgentQPolicyOperator::eq, agent_q::kAgentQPolicyIntentProgrammableTransaction, allowed_intents, 1},
    };
    const agent_q::AgentQPolicyRule eq_with_list_rule = {
        "eq-with-list",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::reject,
        eq_with_list,
        1,
    };
    expect_decision(
        "eq criterion with values list",
        one_rule_policy(&eq_with_list_rule),
        facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::invalid_policy,
        nullptr,
        &failures);

    const agent_q::AgentQPolicyCriterion lte_with_list[] = {
        {"sui.gas_budget", agent_q::AgentQPolicyOperator::lte, "1000000", allowed_intents, 1},
    };
    const agent_q::AgentQPolicyRule lte_with_list_rule = {
        "lte-with-list",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::reject,
        lte_with_list,
        1,
    };
    expect_decision(
        "lte criterion with values list",
        one_rule_policy(&lte_with_list_rule),
        facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::invalid_policy,
        nullptr,
        &failures);

    const agent_q::AgentQPolicyCriterion in_with_scalar[] = {
        {"common.intent", agent_q::AgentQPolicyOperator::in, agent_q::kAgentQPolicyIntentProgrammableTransaction, allowed_intents, 1},
    };
    const agent_q::AgentQPolicyRule in_with_scalar_rule = {
        "in-with-scalar",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::reject,
        in_with_scalar,
        1,
    };
    expect_decision(
        "in criterion with scalar value",
        one_rule_policy(&in_with_scalar_rule),
        facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::invalid_policy,
        nullptr,
        &failures);

    const agent_q::AgentQPolicyFieldDescriptor numeric_in_descriptors[] = {
        {"test.amount", agent_q::AgentQPolicyValueType::u64_decimal, false, true, false},
    };
    const agent_q::AgentQPolicyFact numeric_in_entries[] = {
        {"common.chain", agent_q::AgentQPolicyValueType::string, "sui"},
        {"common.method", agent_q::AgentQPolicyValueType::string, "sign_transaction"},
        {"test.amount", agent_q::AgentQPolicyValueType::u64_decimal, "2"},
    };
    const agent_q::AgentQPolicyFacts numeric_in_facts = {
        numeric_in_entries,
        sizeof(numeric_in_entries) / sizeof(numeric_in_entries[0]),
        numeric_in_descriptors,
        sizeof(numeric_in_descriptors) / sizeof(numeric_in_descriptors[0]),
    };
    const char* numeric_in_values[] = {"1", "2"};
    const agent_q::AgentQPolicyCriterion numeric_in_criteria[] = {
        {"test.amount", agent_q::AgentQPolicyOperator::in, nullptr, numeric_in_values, 2},
    };
    const agent_q::AgentQPolicyRule numeric_in_rule = {
        "numeric-in",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::reject,
        numeric_in_criteria,
        1,
    };
    expect_decision(
        "numeric in criterion match",
        one_rule_policy(&numeric_in_rule),
        numeric_in_facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::matched_rule,
        "numeric-in",
        &failures);

    const char* malformed_numeric_in_values[] = {"1", "not-a-u64"};
    const agent_q::AgentQPolicyCriterion malformed_numeric_in_criteria[] = {
        {"test.amount", agent_q::AgentQPolicyOperator::in, nullptr, malformed_numeric_in_values, 2},
    };
    const agent_q::AgentQPolicyRule malformed_numeric_in_rule = {
        "malformed-numeric-in",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::reject,
        malformed_numeric_in_criteria,
        1,
    };
    expect_decision(
        "numeric in criterion rejects malformed value",
        one_rule_policy(&malformed_numeric_in_rule),
        numeric_in_facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::invalid_policy,
        nullptr,
        &failures);

    const agent_q::AgentQPolicyFacts malformed_descriptor_facts = {
        facts.entries,
        facts.entry_count,
        nullptr,
        1,
    };
    expect_decision(
        "descriptor envelope is validated before policy criteria",
        matching_policy,
        malformed_descriptor_facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::unsupported_facts,
        nullptr,
        &failures);

    agent_q::AgentQPolicyFact unsupported_fact_entries[agent_q::kAgentQSuiSignTransactionPolicyFactCount] = {};
    memcpy(unsupported_fact_entries, policy_facts.entries, sizeof(unsupported_fact_entries));
    for (size_t index = 0; index < facts.entry_count; ++index) {
        agent_q::AgentQPolicyFact& fact = unsupported_fact_entries[index];
        if (strcmp(fact.field, "sui.gas_budget") == 0) {
            fact.value = "not-a-u64";
        }
    }
    const agent_q::AgentQPolicyFacts unsupported_facts = {
        unsupported_fact_entries,
        facts.entry_count,
        facts.field_descriptors,
        facts.field_descriptor_count,
    };
    expect_decision(
        "malformed unsupported facts",
        matching_policy,
        unsupported_facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::unsupported_facts,
        nullptr,
        &failures);

    FixedPolicyProviderContext matching_policy_context = {matching_policy};
    const agent_q::AgentQPolicyProvider matching_policy_provider = {
        load_fixed_policy,
        &matching_policy_context,
    };
    expect_runtime_decision(
        "runtime matching reject rule",
        matching_policy_provider,
        facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::matched_rule,
        "reject-transfer-shape",
        &failures);
    expect_runtime_decision(
        "runtime unsupported facts",
        matching_policy_provider,
        unsupported_facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::unsupported_facts,
        nullptr,
        &failures);

    const std::vector<uint8_t> unsupported_tx =
        read_hex_fixture((fixture_dir + "/merge_coins_tx.bcs.hex").c_str());
    agent_q::AgentQSuiSignTransactionPolicySubject unsupported_subject = {};
    const agent_q::SuiTransactionFactsResult unsupported_parse_result =
        parse_policy_subject(unsupported_tx.data(), unsupported_tx.size(), "testnet", &unsupported_subject);
    if (unsupported_parse_result == agent_q::SuiTransactionFactsResult::ok &&
        unsupported_subject.transaction.command_count == 0) {
        fprintf(stderr, "parsed Sui fixture should preserve generic command facts\n");
        failures += 1;
    }

    if (failures != 0) {
        fprintf(stderr, "Policy v0 tests FAILED: %d\n", failures);
        return 1;
    }
    printf("Policy v0 tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" \
  -std=c++17 \
  -Wall \
  -Wextra \
  -Werror \
  -I"${COMMON_ROOT}" \
  -I"${COMMON_POLICY_DIR}" \
  -I"${COMMON_SUI_DIR}" \
  "${TMP_DIR}/policy_v0_test.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_schema.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_v0.cpp" \
  "${COMMON_POLICY_DIR}/agent_q_policy_runtime.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_bcs_reader.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_method_adapter.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_token_flow_facts.cpp" \
  "${COMMON_SUI_DIR}/agent_q_sui_transaction_facts.cpp" \
  -o "${TMP_DIR}/policy_v0_test"

"${TMP_DIR}/policy_v0_test" "${FIXTURE_DIR}" "${CONTRACT_PATH}"
