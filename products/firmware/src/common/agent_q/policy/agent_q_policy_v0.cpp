#include "agent_q_policy_v0.h"

#include <string.h>

namespace agent_q {
namespace {

constexpr size_t kMaxPolicyRules = 16;
constexpr size_t kMaxRuleCriteria = 8;
constexpr size_t kMaxCriterionValues = 16;
constexpr size_t kMaxPolicyFacts = 24;
constexpr size_t kMaxPolicyFieldDescriptors = 24;
constexpr size_t kMaxPolicyFieldIdLength = 48;
constexpr size_t kMaxU64DecimalDigits = 20;
constexpr const char* kMaxU64DecimalString = "18446744073709551615";

constexpr AgentQPolicyFieldDescriptor kCommonFieldRegistry[] = {
    {"common.chain", AgentQPolicyValueType::string, true, true, false},
    {"common.method", AgentQPolicyValueType::string, true, true, false},
    {"common.network", AgentQPolicyValueType::string, true, true, false},
    {"common.intent", AgentQPolicyValueType::string, true, true, false},
};

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

bool is_safe_field_id(const char* value)
{
    if (!string_present(value)) {
        return false;
    }

    size_t length = 0;
    bool has_dot = false;
    for (const char* cursor = value; *cursor != '\0'; ++cursor) {
        const char ch = *cursor;
        const bool valid_char =
            (ch >= 'a' && ch <= 'z') ||
            (ch >= '0' && ch <= '9') ||
            ch == '_' ||
            ch == '.';
        if (!valid_char) {
            return false;
        }
        if (ch == '.') {
            if (has_dot || cursor == value || cursor[1] == '\0') {
                return false;
            }
            has_dot = true;
        }
        ++length;
        if (length > kMaxPolicyFieldIdLength) {
            return false;
        }
    }
    return has_dot;
}

bool is_known_value_type(AgentQPolicyValueType type)
{
    switch (type) {
        case AgentQPolicyValueType::string:
        case AgentQPolicyValueType::u64_decimal:
            return true;
    }
    return false;
}

const AgentQPolicyFieldDescriptor* find_common_field_descriptor(const char* field)
{
    for (const AgentQPolicyFieldDescriptor& descriptor : kCommonFieldRegistry) {
        if (string_eq(descriptor.field, field)) {
            return &descriptor;
        }
    }
    return nullptr;
}

const AgentQPolicyFieldDescriptor* find_adapter_field_descriptor(
    const AgentQPolicyFacts& facts,
    const char* field)
{
    if (facts.field_descriptors == nullptr) {
        return nullptr;
    }
    for (size_t index = 0; index < facts.field_descriptor_count; ++index) {
        const AgentQPolicyFieldDescriptor& descriptor = facts.field_descriptors[index];
        if (string_eq(descriptor.field, field)) {
            return &descriptor;
        }
    }
    return nullptr;
}

const AgentQPolicyFieldDescriptor* find_field_descriptor(
    const AgentQPolicyFacts& facts,
    const char* field)
{
    const AgentQPolicyFieldDescriptor* descriptor = find_common_field_descriptor(field);
    if (descriptor != nullptr) {
        return descriptor;
    }
    return find_adapter_field_descriptor(facts, field);
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

bool operator_allowed(const AgentQPolicyFieldDescriptor& descriptor, AgentQPolicyOperator op)
{
    switch (op) {
        case AgentQPolicyOperator::eq:
            return descriptor.allow_eq;
        case AgentQPolicyOperator::in:
            return descriptor.allow_in;
        case AgentQPolicyOperator::lte:
            return descriptor.allow_lte;
    }
    return false;
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

bool validate_criterion(
    const AgentQPolicyCriterion& criterion,
    const AgentQPolicyFacts& facts)
{
    const AgentQPolicyFieldDescriptor* descriptor =
        find_field_descriptor(facts, criterion.field);
    if (descriptor == nullptr || !is_known_operator(criterion.op) ||
        !operator_allowed(*descriptor, criterion.op)) {
        return false;
    }

    switch (criterion.op) {
        case AgentQPolicyOperator::eq:
        case AgentQPolicyOperator::lte:
            if (!string_present(criterion.value) ||
                criterion.values != nullptr || criterion.value_count != 0) {
                return false;
            }
            return descriptor->type != AgentQPolicyValueType::u64_decimal ||
                   is_decimal_u64_string(criterion.value);
        case AgentQPolicyOperator::in:
            if (criterion.value != nullptr ||
                criterion.values == nullptr || criterion.value_count == 0 ||
                criterion.value_count > kMaxCriterionValues) {
                return false;
            }
            for (size_t index = 0; index < criterion.value_count; ++index) {
                if (!string_present(criterion.values[index]) ||
                    (descriptor->type == AgentQPolicyValueType::u64_decimal &&
                     !is_decimal_u64_string(criterion.values[index]))) {
                    return false;
                }
            }
            return true;
    }
    return false;
}

bool validate_rule(
    const AgentQPolicyRule& rule,
    const AgentQPolicyFacts& facts)
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
        if (!validate_criterion(rule.criteria[index], facts)) {
            return false;
        }
    }
    return true;
}

bool validate_policy(
    const AgentQPolicyDocument& policy,
    const AgentQPolicyFacts& facts)
{
    if (policy.schema != kAgentQPolicyV0Schema ||
        policy.default_action != AgentQPolicyAction::reject ||
        policy.rule_count > kMaxPolicyRules ||
        (policy.rule_count != 0 && policy.rules == nullptr)) {
        return false;
    }
    for (size_t index = 0; index < policy.rule_count; ++index) {
        if (!validate_rule(policy.rules[index], facts)) {
            return false;
        }
    }
    return true;
}

const AgentQPolicyFact* find_fact(
    const AgentQPolicyFacts& facts,
    const char* field)
{
    if (facts.entries == nullptr) {
        return nullptr;
    }
    for (size_t index = 0; index < facts.entry_count; ++index) {
        const AgentQPolicyFact& fact = facts.entries[index];
        if (string_eq(fact.field, field)) {
            return &fact;
        }
    }
    return nullptr;
}

bool validate_field_descriptor(const AgentQPolicyFieldDescriptor& descriptor)
{
    if (!is_safe_field_id(descriptor.field) ||
        strncmp(descriptor.field, "common.", 7) == 0 ||
        !is_known_value_type(descriptor.type)) {
        return false;
    }
    return descriptor.allow_eq || descriptor.allow_in || descriptor.allow_lte;
}

bool validate_field_descriptors(const AgentQPolicyFacts& facts)
{
    if (facts.field_descriptor_count == 0) {
        return facts.field_descriptors == nullptr;
    }
    if (facts.field_descriptors == nullptr ||
        facts.field_descriptor_count > kMaxPolicyFieldDescriptors) {
        return false;
    }
    for (size_t index = 0; index < facts.field_descriptor_count; ++index) {
        if (!validate_field_descriptor(facts.field_descriptors[index])) {
            return false;
        }
        for (size_t other = index + 1; other < facts.field_descriptor_count; ++other) {
            if (string_eq(
                    facts.field_descriptors[index].field,
                    facts.field_descriptors[other].field)) {
                return false;
            }
        }
    }
    return true;
}

bool validate_fact(
    const AgentQPolicyFact& fact,
    const AgentQPolicyFacts& facts)
{
    const AgentQPolicyFieldDescriptor* descriptor =
        find_field_descriptor(facts, fact.field);
    if (descriptor == nullptr || descriptor->type != fact.type || !string_present(fact.value)) {
        return false;
    }
    return fact.type != AgentQPolicyValueType::u64_decimal ||
           is_decimal_u64_string(fact.value);
}

bool validate_facts(const AgentQPolicyFacts& facts)
{
    if (facts.entries == nullptr || facts.entry_count == 0 ||
        facts.entry_count > kMaxPolicyFacts) {
        return false;
    }
    if (!validate_field_descriptors(facts)) {
        return false;
    }
    for (size_t index = 0; index < facts.entry_count; ++index) {
        if (!validate_fact(facts.entries[index], facts)) {
            return false;
        }
        for (size_t other = index + 1; other < facts.entry_count; ++other) {
            if (string_eq(facts.entries[index].field, facts.entries[other].field)) {
                return false;
            }
        }
    }
    return find_fact(facts, "common.chain") != nullptr &&
           find_fact(facts, "common.method") != nullptr;
}

bool criterion_matches(const AgentQPolicyCriterion& criterion, const AgentQPolicyFacts& facts)
{
    const AgentQPolicyFact* fact = find_fact(facts, criterion.field);
    if (fact == nullptr) {
        return false;
    }
    switch (criterion.op) {
        case AgentQPolicyOperator::eq:
            return string_eq(fact->value, criterion.value);
        case AgentQPolicyOperator::in:
            for (size_t index = 0; index < criterion.value_count; ++index) {
                if (string_eq(fact->value, criterion.values[index])) {
                    return true;
                }
            }
            return false;
        case AgentQPolicyOperator::lte:
            return compare_decimal_u64_strings(fact->value, criterion.value) <= 0;
    }
    return false;
}

bool rule_matches(const AgentQPolicyRule& rule, const AgentQPolicyFacts& facts)
{
    const AgentQPolicyFact* chain =
        find_fact(facts, "common.chain");
    const AgentQPolicyFact* method =
        find_fact(facts, "common.method");
    if (chain == nullptr || method == nullptr ||
        !string_eq(rule.chain, chain->value) || !string_eq(rule.operation, method->value)) {
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
    const AgentQPolicyFacts& facts)
{
    if (!validate_facts(facts)) {
        return reject_decision(AgentQPolicyDecisionReason::unsupported_facts);
    }
    if (!validate_policy(policy, facts)) {
        return reject_decision(AgentQPolicyDecisionReason::invalid_policy);
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
