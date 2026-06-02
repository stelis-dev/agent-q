#include "agent_q_policy_v0.h"

#include <string.h>

#include "agent_q_policy_schema.h"
#include "agent_q_policy_u64.h"

namespace agent_q {
namespace {

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
    const AgentQPolicyFieldDescriptor* descriptor = agent_q_policy_find_common_field_descriptor(field);
    if (descriptor != nullptr) {
        return descriptor;
    }
    return find_adapter_field_descriptor(facts, field);
}

bool validate_criterion(
    const AgentQPolicyCriterion& criterion,
    const AgentQPolicyFacts& facts)
{
    const AgentQPolicyFieldDescriptor* descriptor =
        find_field_descriptor(facts, criterion.field);
    if (descriptor == nullptr || !agent_q_policy_is_known_operator(criterion.op) ||
        !agent_q_policy_operator_allowed(*descriptor, criterion.op)) {
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
                   agent_q_policy_is_decimal_u64_string(criterion.value);
        case AgentQPolicyOperator::in:
            if (criterion.value != nullptr ||
                criterion.values == nullptr || criterion.value_count == 0 ||
                criterion.value_count > kAgentQPolicyMaxCriterionValues) {
                return false;
            }
            for (size_t index = 0; index < criterion.value_count; ++index) {
                if (!string_present(criterion.values[index]) ||
                    (descriptor->type == AgentQPolicyValueType::u64_decimal &&
                     !agent_q_policy_is_decimal_u64_string(criterion.values[index]))) {
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
        !string_present(rule.operation) || !agent_q_policy_is_known_action(rule.action)) {
        return false;
    }
    if (rule.criterion_count > kAgentQPolicyMaxRuleCriteria ||
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
        policy.rule_count > kAgentQPolicyMaxRules ||
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

bool validate_field_descriptors(const AgentQPolicyFacts& facts)
{
    return agent_q_policy_validate_adapter_field_descriptors(
        facts.field_descriptors,
        facts.field_descriptor_count);
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
           agent_q_policy_is_decimal_u64_string(fact.value);
}

bool validate_facts(const AgentQPolicyFacts& facts)
{
    if (facts.entries == nullptr || facts.entry_count == 0 ||
        facts.entry_count > kAgentQPolicyMaxFacts) {
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
            return agent_q_policy_compare_decimal_u64_strings(fact->value, criterion.value) <= 0;
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
