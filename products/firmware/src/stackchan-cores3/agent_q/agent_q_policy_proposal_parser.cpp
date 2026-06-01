#include "agent_q_policy_proposal_parser.h"

#include <string.h>

#include "agent_q_common/policy/agent_q_policy_u64.h"
#include "agent_q_json_input.h"

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

const char* json_string_or_null(JsonVariantConst value)
{
    const char* output = nullptr;
    if (!agent_q_json_value_c_string(value, &output)) {
        return nullptr;
    }
    return output;
}

bool object_has_only_keys(JsonObjectConst object, const char* const* keys, size_t key_count)
{
    for (JsonPairConst item : object) {
        bool known = false;
        for (size_t index = 0; index < key_count; ++index) {
            if (agent_q_json_string_equals(item.key(), keys[index])) {
                known = true;
                break;
            }
        }
        if (!known) {
            return false;
        }
    }
    return true;
}

bool object_contains_key(JsonObjectConst object, const char* expected)
{
    for (JsonPairConst item : object) {
        if (agent_q_json_string_equals(item.key(), expected)) {
            return true;
        }
    }
    return false;
}

bool copy_string(
    AgentQParsedPolicyProposal* proposal,
    const char* input,
    size_t max_length,
    const char** output)
{
    if (proposal == nullptr || output == nullptr || !string_present(input) || max_length == 0) {
        return false;
    }
    const size_t length = strlen(input);
    if (length == 0 || length > max_length ||
        proposal->string_pool_size >= sizeof(proposal->string_pool) ||
        length + 1 > sizeof(proposal->string_pool) - proposal->string_pool_size) {
        return false;
    }

    char* destination = proposal->string_pool + proposal->string_pool_size;
    memcpy(destination, input, length + 1);
    proposal->string_pool_size += length + 1;
    *output = destination;
    return true;
}

bool parse_action(const char* value, AgentQPolicyAction* out)
{
    if (out == nullptr) {
        return false;
    }
    if (string_eq(value, "reject")) {
        *out = AgentQPolicyAction::reject;
        return true;
    }
    if (string_eq(value, "ask")) {
        *out = AgentQPolicyAction::ask;
        return true;
    }
    if (string_eq(value, "sign")) {
        *out = AgentQPolicyAction::sign;
        return true;
    }
    return false;
}

bool parse_operator(const char* value, AgentQPolicyOperator* out)
{
    if (out == nullptr) {
        return false;
    }
    if (string_eq(value, "eq")) {
        *out = AgentQPolicyOperator::eq;
        return true;
    }
    if (string_eq(value, "in")) {
        *out = AgentQPolicyOperator::in;
        return true;
    }
    if (string_eq(value, "lte")) {
        *out = AgentQPolicyOperator::lte;
        return true;
    }
    return false;
}

const AgentQPolicyMethodDescriptor* find_method_descriptor(
    const AgentQPolicyMethodDescriptor* descriptors,
    size_t descriptor_count,
    const char* chain,
    const char* method)
{
    if (descriptors == nullptr) {
        return nullptr;
    }
    for (size_t index = 0; index < descriptor_count; ++index) {
        if (string_eq(descriptors[index].chain, chain) &&
            string_eq(descriptors[index].operation, method)) {
            return &descriptors[index];
        }
    }
    return nullptr;
}

const AgentQPolicyFieldDescriptor* find_field_descriptor(
    const AgentQPolicyMethodDescriptor& method,
    const char* field)
{
    const AgentQPolicyFieldDescriptor* common =
        agent_q_policy_find_common_field_descriptor(field);
    if (common != nullptr) {
        return common;
    }
    if (method.field_descriptors == nullptr) {
        return nullptr;
    }
    for (size_t index = 0; index < method.field_descriptor_count; ++index) {
        if (string_eq(method.field_descriptors[index].field, field)) {
            return &method.field_descriptors[index];
        }
    }
    return nullptr;
}

AgentQPolicyProposalParseStatus parse_criterion(
    JsonVariantConst criterion_variant,
    const AgentQPolicyMethodDescriptor& method,
    AgentQParsedPolicyProposal* proposal,
    size_t rule_index,
    size_t criterion_index)
{
    if (!criterion_variant.is<JsonObjectConst>()) {
        return AgentQPolicyProposalParseStatus::invalid_policy;
    }
    JsonObjectConst criterion_object = criterion_variant.as<JsonObjectConst>();
    constexpr const char* kAllowedKeys[] = {"field", "op", "value", "values"};
    if (!object_has_only_keys(criterion_object, kAllowedKeys, sizeof(kAllowedKeys) / sizeof(kAllowedKeys[0]))) {
        return AgentQPolicyProposalParseStatus::invalid_policy;
    }

    const char* field = json_string_or_null(criterion_object["field"]);
    const char* op_text = json_string_or_null(criterion_object["op"]);
    AgentQPolicyOperator op = AgentQPolicyOperator::eq;
    if (!agent_q_policy_is_safe_field_id(field) || !parse_operator(op_text, &op)) {
        return AgentQPolicyProposalParseStatus::invalid_policy;
    }

    const AgentQPolicyFieldDescriptor* descriptor = find_field_descriptor(method, field);
    if (descriptor == nullptr || !agent_q_policy_operator_allowed(*descriptor, op)) {
        return AgentQPolicyProposalParseStatus::unsupported_field;
    }

    AgentQPolicyCriterion& output = proposal->criteria[rule_index][criterion_index];
    output = {};
    output.op = op;
    if (!copy_string(proposal, field, kAgentQPolicyMaxFieldIdLength, &output.field)) {
        return AgentQPolicyProposalParseStatus::invalid_policy;
    }

    if (op == AgentQPolicyOperator::in) {
        if (object_contains_key(criterion_object, "value") ||
            !criterion_object["values"].is<JsonArrayConst>()) {
            return AgentQPolicyProposalParseStatus::invalid_policy;
        }
        JsonArrayConst values = criterion_object["values"].as<JsonArrayConst>();
        const size_t value_count = values.size();
        if (value_count == 0 || value_count > kAgentQPolicyMaxCriterionValues) {
            return AgentQPolicyProposalParseStatus::invalid_policy;
        }
        for (size_t value_index = 0; value_index < value_count; ++value_index) {
            const char* value = json_string_or_null(values[value_index]);
            if (!string_present(value) ||
                (descriptor->type == AgentQPolicyValueType::u64_decimal &&
                 !agent_q_policy_is_canonical_decimal_u64_string(value)) ||
                !copy_string(
                    proposal,
                    value,
                    kAgentQPolicyMaxValueLength,
                    &proposal->values[rule_index][criterion_index][value_index])) {
                return AgentQPolicyProposalParseStatus::invalid_policy;
            }
        }
        output.values = proposal->values[rule_index][criterion_index];
        output.value_count = value_count;
        return AgentQPolicyProposalParseStatus::ok;
    }

    if (object_contains_key(criterion_object, "values")) {
        return AgentQPolicyProposalParseStatus::invalid_policy;
    }
    const char* value = json_string_or_null(criterion_object["value"]);
    if (!string_present(value) ||
        (descriptor->type == AgentQPolicyValueType::u64_decimal &&
         !agent_q_policy_is_canonical_decimal_u64_string(value)) ||
        !copy_string(proposal, value, kAgentQPolicyMaxValueLength, &output.value)) {
        return AgentQPolicyProposalParseStatus::invalid_policy;
    }
    return AgentQPolicyProposalParseStatus::ok;
}

AgentQPolicyProposalParseStatus parse_rule(
    JsonVariantConst rule_variant,
    const AgentQPolicyMethodDescriptor* method_descriptors,
    size_t method_descriptor_count,
    AgentQParsedPolicyProposal* proposal,
    size_t rule_index)
{
    if (!rule_variant.is<JsonObjectConst>()) {
        return AgentQPolicyProposalParseStatus::invalid_policy;
    }
    JsonObjectConst rule_object = rule_variant.as<JsonObjectConst>();
    constexpr const char* kAllowedKeys[] = {"id", "chain", "method", "action", "criteria"};
    if (!object_has_only_keys(rule_object, kAllowedKeys, sizeof(kAllowedKeys) / sizeof(kAllowedKeys[0]))) {
        return AgentQPolicyProposalParseStatus::invalid_policy;
    }

    const char* id = json_string_or_null(rule_object["id"]);
    const char* chain = json_string_or_null(rule_object["chain"]);
    const char* method = json_string_or_null(rule_object["method"]);
    const char* action_text = json_string_or_null(rule_object["action"]);
    AgentQPolicyAction action = AgentQPolicyAction::reject;
    if (!agent_q_policy_is_identifier_string(id, kAgentQPolicyMaxRuleIdLength) ||
        !agent_q_policy_is_identifier_string(chain, kAgentQPolicyMaxChainIdLength) ||
        !agent_q_policy_is_identifier_string(method, kAgentQPolicyMaxOperationLength) ||
        !parse_action(action_text, &action)) {
        return AgentQPolicyProposalParseStatus::invalid_policy;
    }

    const AgentQPolicyMethodDescriptor* method_descriptor =
        find_method_descriptor(method_descriptors, method_descriptor_count, chain, method);
    if (method_descriptor == nullptr) {
        return AgentQPolicyProposalParseStatus::unsupported_method;
    }
    if (!agent_q_policy_method_supports_action(*method_descriptor, action)) {
        return AgentQPolicyProposalParseStatus::unsupported_action;
    }

    if (!rule_object["criteria"].is<JsonArrayConst>()) {
        return AgentQPolicyProposalParseStatus::invalid_policy;
    }
    JsonArrayConst criteria = rule_object["criteria"].as<JsonArrayConst>();
    const size_t criterion_count = criteria.size();
    if (criterion_count > kAgentQPolicyMaxRuleCriteria ||
        (action != AgentQPolicyAction::reject && criterion_count == 0)) {
        return AgentQPolicyProposalParseStatus::invalid_policy;
    }

    AgentQPolicyRule& output = proposal->rules[rule_index];
    output = {};
    output.action = action;
    output.criterion_count = criterion_count;
    output.criteria = criterion_count == 0 ? nullptr : proposal->criteria[rule_index];

    if (!copy_string(proposal, id, kAgentQPolicyMaxRuleIdLength, &output.id) ||
        !copy_string(proposal, chain, kAgentQPolicyMaxChainIdLength, &output.chain) ||
        !copy_string(proposal, method, kAgentQPolicyMaxOperationLength, &output.operation)) {
        return AgentQPolicyProposalParseStatus::invalid_policy;
    }

    for (size_t criterion_index = 0; criterion_index < criterion_count; ++criterion_index) {
        const AgentQPolicyProposalParseStatus status =
            parse_criterion(criteria[criterion_index], *method_descriptor, proposal, rule_index, criterion_index);
        if (status != AgentQPolicyProposalParseStatus::ok) {
            return status;
        }
    }
    return AgentQPolicyProposalParseStatus::ok;
}

}  // namespace

AgentQPolicyProposalParseStatus parse_agent_q_policy_proposal(
    JsonVariantConst policy,
    const AgentQPolicyMethodDescriptor* method_descriptors,
    size_t method_descriptor_count,
    AgentQParsedPolicyProposal* out)
{
    if (out == nullptr) {
        return AgentQPolicyProposalParseStatus::invalid_argument;
    }
    memset(out, 0, sizeof(*out));

    if (!policy.is<JsonObjectConst>()) {
        return AgentQPolicyProposalParseStatus::invalid_policy;
    }
    if (measureJson(policy) > kAgentQPolicyProposalMaxSerializedObjectBytes) {
        return AgentQPolicyProposalParseStatus::too_large;
    }
    if (!agent_q_policy_validate_method_descriptors(method_descriptors, method_descriptor_count)) {
        return AgentQPolicyProposalParseStatus::invalid_argument;
    }

    JsonObjectConst policy_object = policy.as<JsonObjectConst>();
    constexpr const char* kAllowedKeys[] = {"schema", "defaultAction", "rules"};
    if (!object_has_only_keys(policy_object, kAllowedKeys, sizeof(kAllowedKeys) / sizeof(kAllowedKeys[0])) ||
        !string_eq(json_string_or_null(policy_object["schema"]), kAgentQPolicyProposalSchema) ||
        !string_eq(json_string_or_null(policy_object["defaultAction"]), "reject") ||
        !policy_object["rules"].is<JsonArrayConst>()) {
        return AgentQPolicyProposalParseStatus::invalid_policy;
    }

    JsonArrayConst rules = policy_object["rules"].as<JsonArrayConst>();
    const size_t rule_count = rules.size();
    if (rule_count > kAgentQPolicyMaxRules) {
        return AgentQPolicyProposalParseStatus::invalid_policy;
    }

    out->document = AgentQPolicyDocument{
        kAgentQPolicyV0Schema,
        AgentQPolicyAction::reject,
        rule_count == 0 ? nullptr : out->rules,
        rule_count,
    };

    for (size_t rule_index = 0; rule_index < rule_count; ++rule_index) {
        const AgentQPolicyProposalParseStatus status =
            parse_rule(rules[rule_index], method_descriptors, method_descriptor_count, out, rule_index);
        if (status != AgentQPolicyProposalParseStatus::ok) {
            memset(out, 0, sizeof(*out));
            return status;
        }
    }
    return AgentQPolicyProposalParseStatus::ok;
}

const char* agent_q_policy_proposal_parse_status_name(
    AgentQPolicyProposalParseStatus status)
{
    switch (status) {
        case AgentQPolicyProposalParseStatus::ok:
            return "ok";
        case AgentQPolicyProposalParseStatus::invalid_argument:
            return "invalid_argument";
        case AgentQPolicyProposalParseStatus::too_large:
            return "too_large";
        case AgentQPolicyProposalParseStatus::invalid_policy:
            return "invalid_policy";
        case AgentQPolicyProposalParseStatus::unsupported_method:
            return "unsupported_method";
        case AgentQPolicyProposalParseStatus::unsupported_action:
            return "unsupported_action";
        case AgentQPolicyProposalParseStatus::unsupported_field:
            return "unsupported_field";
    }
    return "unknown";
}

}  // namespace agent_q
