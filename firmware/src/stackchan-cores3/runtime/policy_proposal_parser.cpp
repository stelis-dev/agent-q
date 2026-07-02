#include "policy_proposal_parser.h"

#include <string.h>

#include "protocol/json_input.h"

namespace signing {
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
    if (!json_value_c_string(value, &output)) {
        return nullptr;
    }
    return output;
}

bool object_has_only_keys(JsonObjectConst object, const char* const* keys, size_t key_count)
{
    for (JsonPairConst item : object) {
        bool known = false;
        for (size_t index = 0; index < key_count; ++index) {
            if (json_string_equals(item.key(), keys[index])) {
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
        if (json_string_equals(item.key(), expected)) {
            return true;
        }
    }
    return false;
}

bool copy_string(
    ParsedPolicyProposal* proposal,
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

bool parse_action(const char* value, CurrentPolicyAction* out)
{
    if (out == nullptr) {
        return false;
    }
    if (string_eq(value, "reject")) {
        *out = CurrentPolicyAction::reject;
        return true;
    }
    if (string_eq(value, "sign")) {
        *out = CurrentPolicyAction::sign;
        return true;
    }
    return false;
}

bool parse_operator(const char* value, CurrentPolicyOperator* out)
{
    if (out == nullptr) {
        return false;
    }
    if (string_eq(value, "eq")) {
        *out = CurrentPolicyOperator::eq;
        return true;
    }
    if (string_eq(value, "in")) {
        *out = CurrentPolicyOperator::in;
        return true;
    }
    if (string_eq(value, "not_in")) {
        *out = CurrentPolicyOperator::not_in;
        return true;
    }
    if (string_eq(value, "lte")) {
        *out = CurrentPolicyOperator::lte;
        return true;
    }
    if (string_eq(value, "contains")) {
        *out = CurrentPolicyOperator::contains;
        return true;
    }
    if (string_eq(value, "not_contains")) {
        *out = CurrentPolicyOperator::not_contains;
        return true;
    }
    if (string_eq(value, "all_in")) {
        *out = CurrentPolicyOperator::all_in;
        return true;
    }
    if (string_eq(value, "none_in")) {
        *out = CurrentPolicyOperator::none_in;
        return true;
    }
    return false;
}

bool copy_condition_values(
    JsonObjectConst condition_object,
    const CurrentPolicyFieldDescriptor& descriptor,
    CurrentPolicyOperator op,
    ParsedPolicyProposal* proposal,
    CurrentPolicyCondition* output)
{
    if (proposal == nullptr || output == nullptr) {
        return false;
    }
    if (current_policy_operator_uses_value_list(op)) {
        if (object_contains_key(condition_object, "value") ||
            !condition_object["values"].is<JsonArrayConst>()) {
            return false;
        }
        JsonArrayConst values = condition_object["values"].as<JsonArrayConst>();
        const size_t value_count = values.size();
        if (value_count == 0 || value_count > kCurrentPolicyMaxConditionValues) {
            return false;
        }
        for (size_t value_index = 0; value_index < value_count; ++value_index) {
            const char* value = json_string_or_null(values[value_index]);
            if (!current_policy_value_valid(descriptor.value_kind, value) ||
                !copy_string(
                    proposal,
                    value,
                    kCurrentPolicyMaxValueLength,
                    &proposal->values[proposal->condition_count][value_index])) {
                return false;
            }
        }
        output->values = proposal->values[proposal->condition_count];
        output->value_count = value_count;
        return true;
    }

    if (object_contains_key(condition_object, "values")) {
        return false;
    }
    const char* value = json_string_or_null(condition_object["value"]);
    if (!current_policy_value_valid(descriptor.value_kind, value) ||
        !copy_string(
            proposal,
            value,
            kCurrentPolicyMaxValueLength,
            &proposal->values[proposal->condition_count][0])) {
        return false;
    }
    output->values = proposal->values[proposal->condition_count];
    output->value_count = 1;
    return true;
}

bool copy_condition_where(
    JsonObjectConst condition_object,
    ParsedPolicyProposal* proposal,
    CurrentPolicyCondition* output)
{
    if (proposal == nullptr || output == nullptr) {
        return false;
    }
    if (!object_contains_key(condition_object, "where")) {
        output->where_type = nullptr;
        return true;
    }
    if (!condition_object["where"].is<JsonObjectConst>()) {
        return false;
    }
    JsonObjectConst where_object = condition_object["where"].as<JsonObjectConst>();
    constexpr const char* kAllowedKeys[] = {"type"};
    if (!object_has_only_keys(where_object, kAllowedKeys, sizeof(kAllowedKeys) / sizeof(kAllowedKeys[0]))) {
        return false;
    }
    const char* type = json_string_or_null(where_object["type"]);
    if (!current_policy_value_valid(CurrentPolicyValueKind::string, type) ||
        strstr(type, "::") == nullptr ||
        !copy_string(proposal, type, kCurrentPolicyMaxValueLength, &output->where_type)) {
        return false;
    }
    return true;
}

PolicyProposalParseStatus parse_condition(
    JsonVariantConst condition_variant,
    ParsedPolicyProposal* proposal,
    CurrentPolicyCondition* output)
{
    if (proposal == nullptr || output == nullptr ||
        !condition_variant.is<JsonObjectConst>()) {
        return PolicyProposalParseStatus::invalid_policy;
    }
    JsonObjectConst condition_object = condition_variant.as<JsonObjectConst>();
    constexpr const char* kAllowedKeys[] = {"field", "op", "value", "values", "where"};
    if (!object_has_only_keys(condition_object, kAllowedKeys, sizeof(kAllowedKeys) / sizeof(kAllowedKeys[0]))) {
        return PolicyProposalParseStatus::invalid_policy;
    }
    if (proposal->condition_count >= kCurrentPolicyMaxTotalConditions) {
        return PolicyProposalParseStatus::invalid_policy;
    }

    const char* field = json_string_or_null(condition_object["field"]);
    const char* op_text = json_string_or_null(condition_object["op"]);
    CurrentPolicyOperator op = CurrentPolicyOperator::eq;
    const CurrentPolicyFieldDescriptor* descriptor =
        current_policy_find_field_descriptor(field);
    if (descriptor == nullptr) {
        return PolicyProposalParseStatus::unsupported_field;
    }
    if (!parse_operator(op_text, &op) ||
        !current_policy_operator_allowed(*descriptor, op)) {
        return PolicyProposalParseStatus::invalid_policy;
    }

    *output = {};
    output->op = op;
    if (!copy_string(proposal, field, kCurrentPolicyMaxFieldIdLength, &output->field) ||
        !copy_condition_where(condition_object, proposal, output) ||
        !copy_condition_values(condition_object, *descriptor, op, proposal, output)) {
        return PolicyProposalParseStatus::invalid_policy;
    }
    proposal->condition_count += 1;
    return PolicyProposalParseStatus::ok;
}

PolicyProposalParseStatus parse_policy(
    JsonVariantConst policy_variant,
    ParsedPolicyProposal* proposal,
    CurrentPolicy* output)
{
    if (proposal == nullptr || output == nullptr ||
        !policy_variant.is<JsonObjectConst>()) {
        return PolicyProposalParseStatus::invalid_policy;
    }
    JsonObjectConst policy_object = policy_variant.as<JsonObjectConst>();
    constexpr const char* kAllowedKeys[] = {"id", "action", "conditions"};
    if (!object_has_only_keys(policy_object, kAllowedKeys, sizeof(kAllowedKeys) / sizeof(kAllowedKeys[0])) ||
        !policy_object["conditions"].is<JsonArrayConst>()) {
        return PolicyProposalParseStatus::invalid_policy;
    }
    if (proposal->policy_count >= kCurrentPolicyMaxTotalPolicies) {
        return PolicyProposalParseStatus::invalid_policy;
    }

    const char* id = json_string_or_null(policy_object["id"]);
    const char* action_text = json_string_or_null(policy_object["action"]);
    CurrentPolicyAction action = CurrentPolicyAction::reject;
    if (!current_policy_is_safe_policy_id(id) ||
        !parse_action(action_text, &action)) {
        return PolicyProposalParseStatus::invalid_policy;
    }

    JsonArrayConst conditions = policy_object["conditions"].as<JsonArrayConst>();
    const size_t condition_count = conditions.size();
    if (condition_count > kCurrentPolicyMaxConditionsPerPolicy ||
        (action == CurrentPolicyAction::sign && condition_count == 0) ||
        proposal->condition_count + condition_count > kCurrentPolicyMaxTotalConditions) {
        return PolicyProposalParseStatus::invalid_policy;
    }

    *output = {};
    output->action = action;
    output->condition_count = condition_count;
    output->conditions = condition_count == 0 ? nullptr : &proposal->conditions[proposal->condition_count];
    if (!copy_string(proposal, id, kCurrentPolicyMaxPolicyIdLength, &output->id)) {
        return PolicyProposalParseStatus::invalid_policy;
    }
    for (size_t condition_index = 0; condition_index < condition_count; ++condition_index) {
        const PolicyProposalParseStatus status =
            parse_condition(conditions[condition_index], proposal, &proposal->conditions[proposal->condition_count]);
        if (status != PolicyProposalParseStatus::ok) {
            return status;
        }
    }
    proposal->policy_count += 1;
    return PolicyProposalParseStatus::ok;
}

PolicyProposalParseStatus parse_network(
    JsonVariantConst network_variant,
    ParsedPolicyProposal* proposal,
    CurrentPolicyNetworkScope* output)
{
    if (proposal == nullptr || output == nullptr ||
        !network_variant.is<JsonObjectConst>()) {
        return PolicyProposalParseStatus::invalid_policy;
    }
    JsonObjectConst network_object = network_variant.as<JsonObjectConst>();
    constexpr const char* kAllowedKeys[] = {"network", "policies"};
    if (!object_has_only_keys(network_object, kAllowedKeys, sizeof(kAllowedKeys) / sizeof(kAllowedKeys[0])) ||
        !network_object["policies"].is<JsonArrayConst>()) {
        return PolicyProposalParseStatus::invalid_policy;
    }
    if (proposal->network_count >= kCurrentPolicyMaxTotalNetworks) {
        return PolicyProposalParseStatus::invalid_policy;
    }

    const char* network = json_string_or_null(network_object["network"]);
    if (!current_policy_is_supported_network(network)) {
        return PolicyProposalParseStatus::invalid_policy;
    }
    JsonArrayConst policies = network_object["policies"].as<JsonArrayConst>();
    const size_t policy_count = policies.size();
    if (policy_count > kCurrentPolicyMaxPoliciesPerNetwork ||
        proposal->policy_count + policy_count > kCurrentPolicyMaxTotalPolicies) {
        return PolicyProposalParseStatus::invalid_policy;
    }

    *output = {};
    output->policy_count = policy_count;
    output->policies = policy_count == 0 ? nullptr : &proposal->policies[proposal->policy_count];
    if (!copy_string(proposal, network, kCurrentPolicyMaxNetworkLength, &output->network)) {
        return PolicyProposalParseStatus::invalid_policy;
    }
    for (size_t policy_index = 0; policy_index < policy_count; ++policy_index) {
        const PolicyProposalParseStatus status =
            parse_policy(policies[policy_index], proposal, &proposal->policies[proposal->policy_count]);
        if (status != PolicyProposalParseStatus::ok) {
            return status;
        }
    }
    proposal->network_count += 1;
    return PolicyProposalParseStatus::ok;
}

PolicyProposalParseStatus parse_blockchain(
    JsonVariantConst blockchain_variant,
    ParsedPolicyProposal* proposal,
    CurrentPolicyBlockchainScope* output)
{
    if (proposal == nullptr || output == nullptr ||
        !blockchain_variant.is<JsonObjectConst>()) {
        return PolicyProposalParseStatus::invalid_policy;
    }
    JsonObjectConst blockchain_object = blockchain_variant.as<JsonObjectConst>();
    constexpr const char* kAllowedKeys[] = {"blockchain", "networks"};
    if (!object_has_only_keys(blockchain_object, kAllowedKeys, sizeof(kAllowedKeys) / sizeof(kAllowedKeys[0])) ||
        !blockchain_object["networks"].is<JsonArrayConst>()) {
        return PolicyProposalParseStatus::invalid_policy;
    }

    const char* blockchain = json_string_or_null(blockchain_object["blockchain"]);
    if (!current_policy_is_supported_blockchain(blockchain)) {
        return PolicyProposalParseStatus::invalid_policy;
    }
    JsonArrayConst networks = blockchain_object["networks"].as<JsonArrayConst>();
    const size_t network_count = networks.size();
    if (network_count > kCurrentPolicyMaxNetworksPerBlockchain ||
        proposal->network_count + network_count > kCurrentPolicyMaxTotalNetworks) {
        return PolicyProposalParseStatus::invalid_policy;
    }

    *output = {};
    output->network_count = network_count;
    output->networks = network_count == 0 ? nullptr : &proposal->networks[proposal->network_count];
    if (!copy_string(proposal, blockchain, kCurrentPolicyMaxBlockchainLength, &output->blockchain)) {
        return PolicyProposalParseStatus::invalid_policy;
    }
    for (size_t network_index = 0; network_index < network_count; ++network_index) {
        const PolicyProposalParseStatus status =
            parse_network(networks[network_index], proposal, &proposal->networks[proposal->network_count]);
        if (status != PolicyProposalParseStatus::ok) {
            return status;
        }
    }
    return PolicyProposalParseStatus::ok;
}

}  // namespace

PolicyProposalParseStatus parse_signing_policy_proposal(
    JsonVariantConst policy,
    ParsedPolicyProposal* out)
{
    if (out == nullptr) {
        return PolicyProposalParseStatus::invalid_argument;
    }
    memset(out, 0, sizeof(*out));

    if (!policy.is<JsonObjectConst>()) {
        return PolicyProposalParseStatus::invalid_policy;
    }
    if (measureJson(policy) > kPolicyProposalMaxSerializedObjectBytes) {
        return PolicyProposalParseStatus::too_large;
    }

    JsonObjectConst policy_object = policy.as<JsonObjectConst>();
    constexpr const char* kAllowedKeys[] = {"schema", "defaultAction", "blockchains"};
    if (!object_has_only_keys(policy_object, kAllowedKeys, sizeof(kAllowedKeys) / sizeof(kAllowedKeys[0])) ||
        !string_eq(json_string_or_null(policy_object["schema"]), kCurrentPolicySchema) ||
        !string_eq(json_string_or_null(policy_object["defaultAction"]), "reject") ||
        !policy_object["blockchains"].is<JsonArrayConst>()) {
        return PolicyProposalParseStatus::invalid_policy;
    }

    JsonArrayConst blockchains = policy_object["blockchains"].as<JsonArrayConst>();
    const size_t blockchain_count = blockchains.size();
    if (blockchain_count > kCurrentPolicyMaxBlockchains) {
        return PolicyProposalParseStatus::invalid_policy;
    }

    out->document = CurrentPolicyDocument{
        kCurrentPolicySchema,
        CurrentPolicyAction::reject,
        blockchain_count == 0 ? nullptr : out->blockchains,
        blockchain_count,
    };

    for (size_t blockchain_index = 0; blockchain_index < blockchain_count; ++blockchain_index) {
        const PolicyProposalParseStatus status =
            parse_blockchain(blockchains[blockchain_index], out, &out->blockchains[blockchain_index]);
        if (status != PolicyProposalParseStatus::ok) {
            memset(out, 0, sizeof(*out));
            return status;
        }
    }
    if (validate_current_policy_document(out->document) !=
        CurrentPolicyDocumentStatus::ok) {
        memset(out, 0, sizeof(*out));
        return PolicyProposalParseStatus::invalid_policy;
    }
    return PolicyProposalParseStatus::ok;
}

const char* policy_proposal_parse_status_name(
    PolicyProposalParseStatus status)
{
    switch (status) {
        case PolicyProposalParseStatus::ok:
            return "ok";
        case PolicyProposalParseStatus::invalid_argument:
            return "invalid_argument";
        case PolicyProposalParseStatus::too_large:
            return "too_large";
        case PolicyProposalParseStatus::invalid_policy:
            return "invalid_policy";
        case PolicyProposalParseStatus::unsupported_field:
            return "unsupported_field";
    }
    return "unknown";
}

}  // namespace signing
