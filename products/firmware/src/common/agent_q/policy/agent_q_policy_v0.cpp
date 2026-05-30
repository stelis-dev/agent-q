#include "agent_q_policy_v0.h"

#include <string.h>

namespace agent_q {
namespace {

constexpr size_t kMaxPolicyRules = 16;
constexpr size_t kMaxRuleCriteria = 8;
constexpr size_t kMaxCriterionValues = 16;
constexpr size_t kMaxU64DecimalDigits = 20;
constexpr const char* kMaxU64DecimalString = "18446744073709551615";

AgentQPolicyDecision reject_decision(AgentQPolicyDecisionReason reason)
{
    return AgentQPolicyDecision{AgentQPolicyAction::reject, nullptr, reason};
}

bool string_present(const char* value)
{
    return value != nullptr && value[0] != '\0';
}

bool string_eq(const char* left, const char* right)
{
    return left != nullptr && right != nullptr && strcmp(left, right) == 0;
}

bool is_known_action(AgentQPolicyAction action)
{
    switch (action) {
        case AgentQPolicyAction::reject:
        case AgentQPolicyAction::ask:
        case AgentQPolicyAction::sign:
            return true;
    }
    return false;
}

bool is_known_criterion_type(AgentQPolicyCriterionType type)
{
    switch (type) {
        case AgentQPolicyCriterionType::network:
        case AgentQPolicyCriterionType::kind:
        case AgentQPolicyCriterionType::recipient:
        case AgentQPolicyCriterionType::amount:
        case AgentQPolicyCriterionType::gas_budget:
            return true;
    }
    return false;
}

bool is_known_operator(AgentQPolicyOperator op)
{
    switch (op) {
        case AgentQPolicyOperator::eq:
        case AgentQPolicyOperator::in:
        case AgentQPolicyOperator::lte:
            return true;
    }
    return false;
}

bool is_decimal_u64_string(const char* value)
{
    if (!string_present(value)) {
        return false;
    }
    size_t length = 0;
    for (const char* cursor = value; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9') {
            return false;
        }
        ++length;
        if (length > kMaxU64DecimalDigits) {
            return false;
        }
    }
    if (length == kMaxU64DecimalDigits && strcmp(value, kMaxU64DecimalString) > 0) {
        return false;
    }
    return true;
}

const char* skip_leading_zeroes(const char* value)
{
    while (value[0] == '0' && value[1] != '\0') {
        ++value;
    }
    return value;
}

int compare_decimal_u64_strings(const char* left, const char* right)
{
    const char* normalized_left = skip_leading_zeroes(left);
    const char* normalized_right = skip_leading_zeroes(right);
    const size_t left_len = strlen(normalized_left);
    const size_t right_len = strlen(normalized_right);
    if (left_len < right_len) {
        return -1;
    }
    if (left_len > right_len) {
        return 1;
    }
    const int cmp = strcmp(normalized_left, normalized_right);
    if (cmp < 0) {
        return -1;
    }
    if (cmp > 0) {
        return 1;
    }
    return 0;
}

bool validate_decimal_limit(const char* value)
{
    return is_decimal_u64_string(value);
}

bool validate_criterion(const AgentQPolicyCriterion& criterion)
{
    if (!is_known_criterion_type(criterion.type) || !is_known_operator(criterion.op)) {
        return false;
    }

    switch (criterion.type) {
        case AgentQPolicyCriterionType::network:
        case AgentQPolicyCriterionType::kind:
            return criterion.op == AgentQPolicyOperator::eq && string_present(criterion.value);
        case AgentQPolicyCriterionType::recipient:
            if (criterion.op != AgentQPolicyOperator::in || criterion.values == nullptr ||
                criterion.value_count == 0 || criterion.value_count > kMaxCriterionValues) {
                return false;
            }
            for (size_t index = 0; index < criterion.value_count; ++index) {
                if (!string_present(criterion.values[index])) {
                    return false;
                }
            }
            return true;
        case AgentQPolicyCriterionType::amount:
        case AgentQPolicyCriterionType::gas_budget:
            return criterion.op == AgentQPolicyOperator::lte &&
                   validate_decimal_limit(criterion.value);
    }
    return false;
}

bool validate_rule(const AgentQPolicyRule& rule)
{
    if (!string_present(rule.id) || !string_present(rule.chain) ||
        !string_present(rule.operation) || !is_known_action(rule.action)) {
        return false;
    }
    if (rule.criterion_count > kMaxRuleCriteria ||
        (rule.criterion_count != 0 && rule.criteria == nullptr)) {
        return false;
    }
    if (rule.action != AgentQPolicyAction::reject && rule.criterion_count == 0) {
        return false;
    }
    for (size_t index = 0; index < rule.criterion_count; ++index) {
        if (!validate_criterion(rule.criteria[index])) {
            return false;
        }
    }
    return true;
}

bool validate_policy(const AgentQPolicyDocument& policy)
{
    if (policy.schema != kAgentQPolicyV0Schema ||
        policy.default_action != AgentQPolicyAction::reject ||
        policy.rule_count > kMaxPolicyRules ||
        (policy.rule_count != 0 && policy.rules == nullptr)) {
        return false;
    }
    for (size_t index = 0; index < policy.rule_count; ++index) {
        if (!validate_rule(policy.rules[index])) {
            return false;
        }
    }
    return true;
}

bool validate_facts(const AgentQTransactionFacts& facts)
{
    return string_present(facts.chain) && string_present(facts.operation) &&
           string_present(facts.network) && string_present(facts.kind) &&
           string_present(facts.recipient) && is_decimal_u64_string(facts.amount) &&
           is_decimal_u64_string(facts.gas_budget);
}

bool criterion_matches(const AgentQPolicyCriterion& criterion, const AgentQTransactionFacts& facts)
{
    switch (criterion.type) {
        case AgentQPolicyCriterionType::network:
            return string_eq(facts.network, criterion.value);
        case AgentQPolicyCriterionType::kind:
            return string_eq(facts.kind, criterion.value);
        case AgentQPolicyCriterionType::recipient:
            for (size_t index = 0; index < criterion.value_count; ++index) {
                if (string_eq(facts.recipient, criterion.values[index])) {
                    return true;
                }
            }
            return false;
        case AgentQPolicyCriterionType::amount:
            return compare_decimal_u64_strings(facts.amount, criterion.value) <= 0;
        case AgentQPolicyCriterionType::gas_budget:
            return compare_decimal_u64_strings(facts.gas_budget, criterion.value) <= 0;
    }
    return false;
}

bool rule_matches(const AgentQPolicyRule& rule, const AgentQTransactionFacts& facts)
{
    if (!string_eq(rule.chain, facts.chain) || !string_eq(rule.operation, facts.operation)) {
        return false;
    }
    for (size_t index = 0; index < rule.criterion_count; ++index) {
        if (!criterion_matches(rule.criteria[index], facts)) {
            return false;
        }
    }
    return true;
}

}  // namespace

const char* agent_q_policy_action_name(AgentQPolicyAction action)
{
    switch (action) {
        case AgentQPolicyAction::reject:
            return "reject";
        case AgentQPolicyAction::ask:
            return "ask";
        case AgentQPolicyAction::sign:
            return "sign";
    }
    return "unknown";
}

const char* agent_q_policy_decision_reason_name(AgentQPolicyDecisionReason reason)
{
    switch (reason) {
        case AgentQPolicyDecisionReason::matched_rule:
            return "matched_rule";
        case AgentQPolicyDecisionReason::default_reject:
            return "default_reject";
        case AgentQPolicyDecisionReason::invalid_policy:
            return "invalid_policy";
        case AgentQPolicyDecisionReason::unsupported_facts:
            return "unsupported_facts";
    }
    return "unknown";
}

AgentQPolicyDecision evaluate_agent_q_policy_v0(
    const AgentQPolicyDocument& policy,
    const AgentQTransactionFacts& facts)
{
    if (!validate_policy(policy)) {
        return reject_decision(AgentQPolicyDecisionReason::invalid_policy);
    }
    if (!validate_facts(facts)) {
        return reject_decision(AgentQPolicyDecisionReason::unsupported_facts);
    }

    for (size_t index = 0; index < policy.rule_count; ++index) {
        const AgentQPolicyRule& rule = policy.rules[index];
        if (rule_matches(rule, facts)) {
            return AgentQPolicyDecision{rule.action, rule.id, AgentQPolicyDecisionReason::matched_rule};
        }
    }

    return reject_decision(AgentQPolicyDecisionReason::default_reject);
}

}  // namespace agent_q
