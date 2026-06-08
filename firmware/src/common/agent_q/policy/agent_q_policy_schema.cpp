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

}  // namespace

const AgentQPolicyFieldDescriptor
    kAgentQPolicyCommonFieldDescriptors[kAgentQPolicyCommonFieldDescriptorCount] = {
        {"common.chain", AgentQPolicyValueType::string, true, true, false},
        {"common.method", AgentQPolicyValueType::string, true, true, false},
        {"common.intent", AgentQPolicyValueType::string, true, true, false},
    };

bool agent_q_policy_is_known_action(AgentQPolicyAction action)
{
    switch (action) {
        case AgentQPolicyAction::reject:
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

static bool agent_q_policy_is_known_value_type(AgentQPolicyValueType type)
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
        (!descriptor.supports_reject && !descriptor.supports_sign)) {
        return false;
    }
    return agent_q_policy_validate_adapter_field_descriptors(
        descriptor.field_descriptors,
        descriptor.field_descriptor_count);
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

namespace {

bool criterion_eq(const AgentQPolicyCriterion& criterion, const char* field, const char* value)
{
    return criterion.field != nullptr &&
           criterion.value != nullptr &&
           strcmp(criterion.field, field) == 0 &&
           criterion.op == AgentQPolicyOperator::eq &&
           strcmp(criterion.value, value) == 0;
}

bool criterion_lte(const AgentQPolicyCriterion& criterion, const char* field)
{
    return criterion.field != nullptr &&
           criterion.value != nullptr &&
           strcmp(criterion.field, field) == 0 &&
           criterion.op == AgentQPolicyOperator::lte &&
           agent_q_policy_is_decimal_u64_string(criterion.value);
}

bool criterion_recipient_bounded(const AgentQPolicyCriterion& criterion)
{
    if (criterion.field == nullptr ||
        strcmp(criterion.field, "sui.recipient_address") != 0) {
        return false;
    }
    if (criterion.op == AgentQPolicyOperator::eq) {
        return string_present(criterion.value);
    }
    return criterion.op == AgentQPolicyOperator::in &&
           criterion.values != nullptr &&
           criterion.value_count == 1;
}

}  // namespace

bool agent_q_policy_sign_rule_is_bounded(const AgentQPolicyRule& rule)
{
    if (rule.action != AgentQPolicyAction::sign) {
        return true;
    }
    if (!string_eq(rule.chain, "sui") ||
        !string_eq(rule.operation, "sign_transaction") ||
        rule.criteria == nullptr ||
        rule.criterion_count == 0) {
        return false;
    }

    bool has_intent = false;
    bool has_shape = false;
    bool has_asset = false;
    bool has_recipient = false;
    bool has_amount_bound = false;
    bool has_gas_budget_bound = false;
    bool has_gas_price_bound = false;
    for (size_t index = 0; index < rule.criterion_count; ++index) {
        const AgentQPolicyCriterion& criterion = rule.criteria[index];
        has_intent = has_intent ||
            criterion_eq(criterion, "common.intent", "single_asset_transfer");
        has_shape = has_shape ||
            criterion_eq(criterion, "sui.command_shape", "restricted_transfer");
        has_asset = has_asset ||
            criterion_eq(criterion, "sui.coin_type", "0x2::sui::SUI");
        has_recipient = has_recipient || criterion_recipient_bounded(criterion);
        has_amount_bound = has_amount_bound || criterion_lte(criterion, "sui.amount_raw");
        has_gas_budget_bound = has_gas_budget_bound || criterion_lte(criterion, "sui.gas_budget");
        has_gas_price_bound = has_gas_price_bound || criterion_lte(criterion, "sui.gas_price");
    }
    return has_intent &&
           has_shape &&
           has_asset &&
           has_recipient &&
           has_amount_bound &&
           has_gas_budget_bound &&
           has_gas_price_bound;
}

bool agent_q_policy_sign_rule_count_is_supported(const AgentQPolicyDocument& policy)
{
    if (policy.rule_count != 0 && policy.rules == nullptr) {
        return false;
    }
    size_t sign_rule_count = 0;
    for (size_t index = 0; index < policy.rule_count; ++index) {
        if (policy.rules[index].action == AgentQPolicyAction::sign) {
            ++sign_rule_count;
            if (sign_rule_count > 1) {
                return false;
            }
        }
    }
    return true;
}

}  // namespace agent_q
