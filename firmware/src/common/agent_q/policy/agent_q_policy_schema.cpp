#include "agent_q_policy_schema.h"

#include <string.h>

#include "agent_q_policy_u64.h"

namespace agent_q {
namespace {

bool string_present(const char* value)
{
    return value != nullptr && value[0] != '\0';
}

bool string_eq(const char* left, const char* right)
{
    return left != nullptr && right != nullptr && strcmp(left, right) == 0;
}

const AgentQPolicyFieldDescriptor* find_adapter_field_descriptor(
    const AgentQPolicyMethodDescriptor& descriptor,
    const char* field)
{
    if (descriptor.field_descriptors == nullptr) {
        return nullptr;
    }
    for (size_t index = 0; index < descriptor.field_descriptor_count; ++index) {
        if (string_eq(descriptor.field_descriptors[index].field, field)) {
            return &descriptor.field_descriptors[index];
        }
    }
    return nullptr;
}

const AgentQPolicyFieldDescriptor* find_method_field_descriptor(
    const AgentQPolicyMethodDescriptor& descriptor,
    const char* field)
{
    const AgentQPolicyFieldDescriptor* common =
        agent_q_policy_find_common_field_descriptor(field);
    if (common != nullptr) {
        return common;
    }
    return find_adapter_field_descriptor(descriptor, field);
}

const AgentQPolicyActionConstraint* find_action_constraint(
    const AgentQPolicyMethodDescriptor& descriptor,
    AgentQPolicyAction action)
{
    if (descriptor.action_constraints == nullptr) {
        return nullptr;
    }
    for (size_t index = 0; index < descriptor.action_constraint_count; ++index) {
        if (descriptor.action_constraints[index].action == action) {
            return &descriptor.action_constraints[index];
        }
    }
    return nullptr;
}

bool scalar_or_list_contains_value(
    const AgentQPolicyCriterion& criterion,
    const char* value)
{
    if (value == nullptr) {
        return true;
    }
    if (criterion.op == AgentQPolicyOperator::in) {
        if (criterion.values == nullptr) {
            return false;
        }
        for (size_t index = 0; index < criterion.value_count; ++index) {
            if (string_eq(criterion.values[index], value)) {
                return true;
            }
        }
        return false;
    }
    return string_eq(criterion.value, value);
}

bool criterion_satisfies_requirement(
    const AgentQPolicyCriterion& criterion,
    const AgentQPolicyRequiredCriterion& requirement)
{
    return string_eq(criterion.field, requirement.field) &&
           criterion.op == requirement.op &&
           scalar_or_list_contains_value(criterion, requirement.value);
}

bool rule_contains_required_criterion(
    const AgentQPolicyRule& rule,
    const AgentQPolicyRequiredCriterion& requirement)
{
    if (rule.criteria == nullptr) {
        return false;
    }
    for (size_t index = 0; index < rule.criterion_count; ++index) {
        if (criterion_satisfies_requirement(rule.criteria[index], requirement)) {
            return true;
        }
    }
    return false;
}

bool validate_required_criterion(
    const AgentQPolicyMethodDescriptor& descriptor,
    const AgentQPolicyRequiredCriterion& requirement)
{
    const AgentQPolicyFieldDescriptor* field_descriptor =
        find_method_field_descriptor(descriptor, requirement.field);
    if (field_descriptor == nullptr ||
        !agent_q_policy_is_known_operator(requirement.op) ||
        !agent_q_policy_operator_allowed(*field_descriptor, requirement.op)) {
        return false;
    }
    if (requirement.value == nullptr) {
        return true;
    }
    if (!string_present(requirement.value)) {
        return false;
    }
    return field_descriptor->type != AgentQPolicyValueType::u64_decimal ||
           agent_q_policy_is_decimal_u64_string(requirement.value);
}

bool validate_action_constraints(const AgentQPolicyMethodDescriptor& descriptor)
{
    if (descriptor.action_constraint_count == 0) {
        return descriptor.action_constraints == nullptr &&
               !descriptor.supports_ask &&
               !descriptor.supports_sign;
    }
    if (descriptor.action_constraints == nullptr ||
        descriptor.action_constraint_count > kAgentQPolicyMaxActionConstraints) {
        return false;
    }
    for (size_t index = 0; index < descriptor.action_constraint_count; ++index) {
        const AgentQPolicyActionConstraint& constraint = descriptor.action_constraints[index];
        if (!agent_q_policy_is_known_action(constraint.action) ||
            constraint.required_criteria == nullptr ||
            constraint.required_criterion_count == 0 ||
            constraint.required_criterion_count > kAgentQPolicyMaxRuleCriteria) {
            return false;
        }
        for (size_t other = index + 1; other < descriptor.action_constraint_count; ++other) {
            if (descriptor.action_constraints[other].action == constraint.action) {
                return false;
            }
        }
        for (size_t required_index = 0; required_index < constraint.required_criterion_count; ++required_index) {
            const AgentQPolicyRequiredCriterion& requirement =
                constraint.required_criteria[required_index];
            if (!validate_required_criterion(descriptor, requirement)) {
                return false;
            }
            for (size_t other = required_index + 1; other < constraint.required_criterion_count; ++other) {
                const AgentQPolicyRequiredCriterion& other_requirement =
                    constraint.required_criteria[other];
                if (string_eq(requirement.field, other_requirement.field)) {
                    return false;
                }
            }
        }
    }
    return (!descriptor.supports_ask ||
            find_action_constraint(descriptor, AgentQPolicyAction::ask) != nullptr) &&
           (!descriptor.supports_sign ||
            find_action_constraint(descriptor, AgentQPolicyAction::sign) != nullptr);
}

}  // namespace

const AgentQPolicyFieldDescriptor
    kAgentQPolicyCommonFieldDescriptors[kAgentQPolicyCommonFieldDescriptorCount] = {
        {"common.chain", AgentQPolicyValueType::string, true, true, false},
        {"common.method", AgentQPolicyValueType::string, true, true, false},
        {"common.network", AgentQPolicyValueType::string, true, true, false},
        {"common.intent", AgentQPolicyValueType::string, true, true, false},
    };

bool agent_q_policy_is_known_action(AgentQPolicyAction action)
{
    switch (action) {
        case AgentQPolicyAction::reject:
        case AgentQPolicyAction::ask:
        case AgentQPolicyAction::sign:
            return true;
    }
    return false;
}

bool agent_q_policy_is_known_operator(AgentQPolicyOperator op)
{
    switch (op) {
        case AgentQPolicyOperator::eq:
        case AgentQPolicyOperator::in:
        case AgentQPolicyOperator::lte:
            return true;
    }
    return false;
}

bool agent_q_policy_is_known_value_type(AgentQPolicyValueType type)
{
    switch (type) {
        case AgentQPolicyValueType::string:
        case AgentQPolicyValueType::u64_decimal:
            return true;
    }
    return false;
}

bool agent_q_policy_is_identifier_string(const char* value, size_t max_length)
{
    if (!string_present(value) || max_length == 0) {
        return false;
    }

    size_t length = 0;
    for (const char* cursor = value; *cursor != '\0'; ++cursor) {
        const char ch = *cursor;
        const bool valid_char =
            (ch >= 'a' && ch <= 'z') ||
            (ch >= '0' && ch <= '9') ||
            ch == '_' ||
            ch == '-' ||
            ch == '.' ||
            ch == ':' ||
            ch == '/';
        if (!valid_char) {
            return false;
        }
        ++length;
        if (length > max_length) {
            return false;
        }
    }
    return true;
}

bool agent_q_policy_is_rule_id_string(const char* value)
{
    if (!string_present(value)) {
        return false;
    }

    size_t length = 0;
    for (const char* cursor = value; *cursor != '\0'; ++cursor) {
        const char ch = *cursor;
        const bool valid_char =
            (ch >= 'a' && ch <= 'z') ||
            (ch >= '0' && ch <= '9') ||
            ch == '_' ||
            ch == '-' ||
            ch == '.' ||
            ch == ':' ||
            ch == '/';
        if (!valid_char || (length == 0 && !(ch >= 'a' && ch <= 'z'))) {
            return false;
        }
        ++length;
        if (length > kAgentQPolicyMaxRuleIdLength) {
            return false;
        }
    }
    return true;
}

bool agent_q_policy_is_safe_field_id(const char* value)
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
        if (length > kAgentQPolicyMaxFieldIdLength) {
            return false;
        }
    }
    return has_dot;
}

bool agent_q_policy_operator_allowed(
    const AgentQPolicyFieldDescriptor& descriptor,
    AgentQPolicyOperator op)
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

bool agent_q_policy_method_supports_action(
    const AgentQPolicyMethodDescriptor& descriptor,
    AgentQPolicyAction action)
{
    switch (action) {
        case AgentQPolicyAction::reject:
            return descriptor.supports_reject;
        case AgentQPolicyAction::ask:
            return descriptor.supports_ask;
        case AgentQPolicyAction::sign:
            return descriptor.supports_sign;
    }
    return false;
}

const AgentQPolicyFieldDescriptor* agent_q_policy_find_common_field_descriptor(
    const char* field)
{
    for (size_t index = 0; index < kAgentQPolicyCommonFieldDescriptorCount; ++index) {
        const AgentQPolicyFieldDescriptor& descriptor = kAgentQPolicyCommonFieldDescriptors[index];
        if (string_eq(descriptor.field, field)) {
            return &descriptor;
        }
    }
    return nullptr;
}

bool agent_q_policy_validate_adapter_field_descriptor(
    const AgentQPolicyFieldDescriptor& descriptor)
{
    if (!agent_q_policy_is_safe_field_id(descriptor.field) ||
        strncmp(descriptor.field, "common.", 7) == 0 ||
        !agent_q_policy_is_known_value_type(descriptor.type)) {
        return false;
    }
    return descriptor.allow_eq || descriptor.allow_in || descriptor.allow_lte;
}

bool agent_q_policy_validate_adapter_field_descriptors(
    const AgentQPolicyFieldDescriptor* descriptors,
    size_t descriptor_count)
{
    if (descriptor_count == 0) {
        return descriptors == nullptr;
    }
    if (descriptors == nullptr || descriptor_count > kAgentQPolicyMaxFieldDescriptors) {
        return false;
    }
    for (size_t index = 0; index < descriptor_count; ++index) {
        if (!agent_q_policy_validate_adapter_field_descriptor(descriptors[index])) {
            return false;
        }
        for (size_t other = index + 1; other < descriptor_count; ++other) {
            if (string_eq(descriptors[index].field, descriptors[other].field)) {
                return false;
            }
        }
    }
    return true;
}

bool agent_q_policy_validate_method_descriptor(
    const AgentQPolicyMethodDescriptor& descriptor)
{
    if (!agent_q_policy_is_identifier_string(descriptor.chain, kAgentQPolicyMaxChainIdLength) ||
        !agent_q_policy_is_identifier_string(descriptor.operation, kAgentQPolicyMaxOperationLength) ||
        (!descriptor.supports_reject && !descriptor.supports_ask && !descriptor.supports_sign)) {
        return false;
    }
    return agent_q_policy_validate_adapter_field_descriptors(
               descriptor.field_descriptors,
               descriptor.field_descriptor_count) &&
           validate_action_constraints(descriptor);
}

bool agent_q_policy_validate_method_descriptors(
    const AgentQPolicyMethodDescriptor* descriptors,
    size_t descriptor_count)
{
    if (descriptor_count == 0) {
        return descriptors == nullptr;
    }
    if (descriptors == nullptr || descriptor_count > kAgentQPolicyMaxMethodDescriptors) {
        return false;
    }
    for (size_t index = 0; index < descriptor_count; ++index) {
        if (!agent_q_policy_validate_method_descriptor(descriptors[index])) {
            return false;
        }
        for (size_t other = index + 1; other < descriptor_count; ++other) {
            if (string_eq(descriptors[index].chain, descriptors[other].chain) &&
                string_eq(descriptors[index].operation, descriptors[other].operation)) {
                return false;
            }
        }
    }
    return true;
}

bool agent_q_policy_rule_satisfies_action_constraints(
    const AgentQPolicyMethodDescriptor& descriptor,
    const AgentQPolicyRule& rule)
{
    const AgentQPolicyActionConstraint* constraint =
        find_action_constraint(descriptor, rule.action);
    if (constraint == nullptr) {
        return rule.action == AgentQPolicyAction::reject;
    }
    for (size_t index = 0; index < constraint->required_criterion_count; ++index) {
        if (!rule_contains_required_criterion(rule, constraint->required_criteria[index])) {
            return false;
        }
    }
    return true;
}

}  // namespace agent_q
