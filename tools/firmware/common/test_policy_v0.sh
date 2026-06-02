#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: tools/firmware/common/test_policy_v0.sh

Compiles the common Agent-Q policy evaluator/runtime boundary with a host C++
compiler and checks Sui restricted-transfer facts against positive and negative
policy cases.
This test does not require ESP-IDF and does not depend on .WORK paths.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMMON_ROOT="${REPO_ROOT}/products/firmware/src/common/agent_q"
COMMON_POLICY_DIR="${COMMON_ROOT}/policy"
COMMON_SUI_DIR="${COMMON_ROOT}/sui"
FIXTURE_DIR="${COMMON_SUI_DIR}/testdata/sui_transaction_facts"

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
  "${COMMON_SUI_DIR}/agent_q_sui_transaction_facts.cpp" \
  "${FIXTURE_DIR}/valid_sui_transfer_tx.bcs.hex" \
  "${FIXTURE_DIR}/unsupported_merge_coins_tx.bcs.hex"; do
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
#include <vector>

#include "agent_q_u64_decimal.h"
#include "agent_q_policy_v0.h"
#include "agent_q_policy_runtime.h"
#include "agent_q_sui_method_adapter.h"
#include "agent_q_sui_transaction_facts.h"

namespace {

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

}  // namespace

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s /path/to/fixture_dir\n", argv[0]);
        return 2;
    }

    const std::string fixture_dir = argv[1];
    int failures = 0;

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
    agent_q::SuiTransferFacts sui_facts = {};
    const agent_q::SuiTransactionFactsResult parse_result =
        agent_q::parse_sui_transfer_facts(valid.data(), valid.size(), &sui_facts);
    if (parse_result != agent_q::SuiTransactionFactsResult::ok) {
        fprintf(stderr, "valid Sui transfer fixture did not parse\n");
        return 1;
    }

    agent_q::AgentQSuiSignTransactionPolicyFacts policy_facts = {};
    if (!agent_q::make_sui_sign_transaction_policy_facts(sui_facts, "devnet", &policy_facts)) {
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

    agent_q::AgentQSuiSignTransactionPolicyFacts missing_network_facts = {};
    if (agent_q::make_sui_sign_transaction_policy_facts(sui_facts, "", &missing_network_facts)) {
        fprintf(stderr, "Sui method adapter accepted missing network context\n");
        failures += 1;
    }

    const char* allowed_recipients[] = {sui_facts.recipient};
    const char* other_recipients[] = {
        "0x1111111111111111111111111111111111111111111111111111111111111111",
    };

    const agent_q::AgentQPolicyCriterion allow_criteria[] = {
        {"common.network", agent_q::AgentQPolicyOperator::eq, "devnet", nullptr, 0},
        {"common.intent", agent_q::AgentQPolicyOperator::eq, agent_q::kAgentQPolicyIntentSingleAssetTransfer, nullptr, 0},
        {"sui.sender_address", agent_q::AgentQPolicyOperator::eq, sui_facts.sender, nullptr, 0},
        {"sui.recipient_address", agent_q::AgentQPolicyOperator::in, nullptr, allowed_recipients, 1},
        {"sui.amount_raw", agent_q::AgentQPolicyOperator::lte, "1000000", nullptr, 0},
        {"sui.gas_budget", agent_q::AgentQPolicyOperator::lte, "50000000", nullptr, 0},
        {"sui.gas_price", agent_q::AgentQPolicyOperator::lte, sui_facts.gas_price, nullptr, 0},
    };
    const agent_q::AgentQPolicyRule sign_rule = {
        "sign-small-sui-transfer",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::sign,
        allow_criteria,
        sizeof(allow_criteria) / sizeof(allow_criteria[0]),
    };
    const agent_q::AgentQPolicyDocument sign_policy = one_rule_policy(&sign_rule);
    expect_decision(
        "matching sign rule",
        sign_policy,
        facts,
        agent_q::AgentQPolicyAction::sign,
        agent_q::AgentQPolicyDecisionReason::matched_rule,
        "sign-small-sui-transfer",
        &failures);

    const agent_q::AgentQPolicyRule ask_rule = {
        "ask-small-sui-transfer",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::ask,
        allow_criteria,
        sizeof(allow_criteria) / sizeof(allow_criteria[0]),
    };
    const agent_q::AgentQPolicyRule first_match_rules[] = {ask_rule, sign_rule};
    const agent_q::AgentQPolicyDocument first_match_policy = {
        agent_q::kAgentQPolicyV0Schema,
        agent_q::AgentQPolicyAction::reject,
        first_match_rules,
        2,
    };
    expect_decision(
        "first matching ask rule",
        first_match_policy,
        facts,
        agent_q::AgentQPolicyAction::ask,
        agent_q::AgentQPolicyDecisionReason::matched_rule,
        "ask-small-sui-transfer",
        &failures);

    const agent_q::AgentQPolicyRule reject_rule = {
        "reject-small-sui-transfer",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::reject,
        allow_criteria,
        sizeof(allow_criteria) / sizeof(allow_criteria[0]),
    };
    const agent_q::AgentQPolicyDocument reject_policy = one_rule_policy(&reject_rule);
    expect_decision(
        "matching reject rule",
        reject_policy,
        facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::matched_rule,
        "reject-small-sui-transfer",
        &failures);

    const agent_q::AgentQPolicyCriterion wrong_recipient_criteria[] = {
        {"sui.recipient_address", agent_q::AgentQPolicyOperator::in, nullptr, other_recipients, 1},
    };
    const agent_q::AgentQPolicyRule wrong_recipient_rule = {
        "wrong-recipient",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::sign,
        wrong_recipient_criteria,
        1,
    };
    expect_decision(
        "recipient not allowed",
        one_rule_policy(&wrong_recipient_rule),
        facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::default_reject,
        nullptr,
        &failures);

    const agent_q::AgentQPolicyCriterion amount_limit_criteria[] = {
        {"sui.amount_raw", agent_q::AgentQPolicyOperator::lte, "999999", nullptr, 0},
    };
    const agent_q::AgentQPolicyRule amount_limit_rule = {
        "amount-limit",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::sign,
        amount_limit_criteria,
        1,
    };
    expect_decision(
        "amount over limit",
        one_rule_policy(&amount_limit_rule),
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
        agent_q::AgentQPolicyAction::sign,
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
        agent_q::AgentQPolicyAction::ask,
        &sign_rule,
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

    const agent_q::AgentQPolicyRule broad_sign_rule = {
        "broad-sign",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::sign,
        nullptr,
        0,
    };
    expect_decision(
        "broad sign without criteria",
        one_rule_policy(&broad_sign_rule),
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
        agent_q::AgentQPolicyAction::sign,
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
        {"common.network", static_cast<agent_q::AgentQPolicyOperator>(99), "devnet", nullptr, 0},
    };
    const agent_q::AgentQPolicyRule unsupported_op_rule = {
        "unsupported-op",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::sign,
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
        {"sui.amount_raw", agent_q::AgentQPolicyOperator::lte, "10.5", nullptr, 0},
    };
    const agent_q::AgentQPolicyRule malformed_amount_rule = {
        "malformed-amount",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::sign,
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
        {"sui.amount_raw", agent_q::AgentQPolicyOperator::lte, "18446744073709551616", nullptr, 0},
    };
    const agent_q::AgentQPolicyRule overflow_amount_rule = {
        "overflow-amount",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::sign,
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

    const agent_q::AgentQPolicyCriterion eq_with_list[] = {
        {"common.network", agent_q::AgentQPolicyOperator::eq, "devnet", allowed_recipients, 1},
    };
    const agent_q::AgentQPolicyRule eq_with_list_rule = {
        "eq-with-list",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::sign,
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
        {"sui.amount_raw", agent_q::AgentQPolicyOperator::lte, "1000000", allowed_recipients, 1},
    };
    const agent_q::AgentQPolicyRule lte_with_list_rule = {
        "lte-with-list",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::sign,
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
        {"sui.recipient_address", agent_q::AgentQPolicyOperator::in, sui_facts.recipient, allowed_recipients, 1},
    };
    const agent_q::AgentQPolicyRule in_with_scalar_rule = {
        "in-with-scalar",
        "sui",
        "sign_transaction",
        agent_q::AgentQPolicyAction::sign,
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
        agent_q::AgentQPolicyAction::sign,
        numeric_in_criteria,
        1,
    };
    expect_decision(
        "numeric in criterion match",
        one_rule_policy(&numeric_in_rule),
        numeric_in_facts,
        agent_q::AgentQPolicyAction::sign,
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
        agent_q::AgentQPolicyAction::sign,
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
        sign_policy,
        malformed_descriptor_facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::unsupported_facts,
        nullptr,
        &failures);

    agent_q::AgentQPolicyFact unsupported_fact_entries[agent_q::kAgentQSuiTransferPolicyFactCount] = {};
    memcpy(unsupported_fact_entries, policy_facts.entries, sizeof(unsupported_fact_entries));
    for (agent_q::AgentQPolicyFact& fact : unsupported_fact_entries) {
        if (strcmp(fact.field, "sui.amount_raw") == 0) {
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
        sign_policy,
        unsupported_facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::unsupported_facts,
        nullptr,
        &failures);

    FixedPolicyProviderContext sign_policy_context = {sign_policy};
    const agent_q::AgentQPolicyProvider sign_policy_provider = {
        load_fixed_policy,
        &sign_policy_context,
    };
    expect_runtime_decision(
        "runtime matching sign rule",
        sign_policy_provider,
        facts,
        agent_q::AgentQPolicyAction::sign,
        agent_q::AgentQPolicyDecisionReason::matched_rule,
        "sign-small-sui-transfer",
        &failures);
    expect_runtime_decision(
        "runtime unsupported facts",
        sign_policy_provider,
        unsupported_facts,
        agent_q::AgentQPolicyAction::reject,
        agent_q::AgentQPolicyDecisionReason::unsupported_facts,
        nullptr,
        &failures);

    const std::vector<uint8_t> unsupported_tx =
        read_hex_fixture((fixture_dir + "/unsupported_merge_coins_tx.bcs.hex").c_str());
    sui_facts = {};
    const agent_q::SuiTransactionFactsResult unsupported_parse_result =
        agent_q::parse_sui_transfer_facts(unsupported_tx.data(), unsupported_tx.size(), &sui_facts);
    if (unsupported_parse_result != agent_q::SuiTransactionFactsResult::unsupported) {
        fprintf(stderr, "unsupported Sui fixture should be rejected by facts parser\n");
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
  "${COMMON_SUI_DIR}/agent_q_sui_transaction_facts.cpp" \
  -o "${TMP_DIR}/policy_v0_test"

"${TMP_DIR}/policy_v0_test" "${FIXTURE_DIR}"
