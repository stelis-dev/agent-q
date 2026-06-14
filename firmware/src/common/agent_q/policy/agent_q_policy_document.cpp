#include "agent_q_policy_document.h"

#include <string.h>

#include "agent_q_policy_u64.h"

namespace agent_q {
namespace {

constexpr uint8_t kStoredPolicyFormatVersion = 0;
constexpr uint8_t kStoredPolicyActionReject = 0;
constexpr uint8_t kStoredPolicyActionSign = 1;
constexpr uint8_t kStoredPolicyOperatorEq = 0;
constexpr uint8_t kStoredPolicyOperatorIn = 1;
constexpr uint8_t kStoredPolicyOperatorNotIn = 2;
constexpr uint8_t kStoredPolicyOperatorLte = 3;
constexpr uint8_t kStoredPolicyOperatorContains = 4;
constexpr uint8_t kStoredPolicyOperatorNotContains = 5;
constexpr uint8_t kStoredPolicyOperatorAllIn = 6;
constexpr uint8_t kStoredPolicyOperatorNoneIn = 7;

struct StoredPolicyHeader {
    uint8_t magic[4];
    uint8_t format_version;
    uint8_t default_action;
    uint8_t blockchain_count;
    uint8_t reserved[9];
};

static_assert(sizeof(StoredPolicyHeader) == 16, "Stored policy header must stay fixed-size");
static_assert(
    sizeof(StoredPolicyHeader) == kAgentQCurrentPolicyDefaultCanonicalRecordBytes,
    "Default current policy record size must match the stored policy header");

bool string_present(const char* value)
{
    return value != nullptr && value[0] != '\0';
}

bool string_eq(const char* left, const char* right)
{
    return left != nullptr && right != nullptr && strcmp(left, right) == 0;
}

bool string_contains(const char* value, const char* needle)
{
    return value != nullptr && needle != nullptr && strstr(value, needle) != nullptr;
}

bool is_current_schema(const char* value)
{
    return string_eq(value, kAgentQCurrentPolicySchema);
}

bool is_known_action(AgentQCurrentPolicyAction action)
{
    switch (action) {
        case AgentQCurrentPolicyAction::reject:
        case AgentQCurrentPolicyAction::sign:
            return true;
    }
    return false;
}

bool is_known_operator(AgentQCurrentPolicyOperator op)
{
    switch (op) {
        case AgentQCurrentPolicyOperator::eq:
        case AgentQCurrentPolicyOperator::in:
        case AgentQCurrentPolicyOperator::not_in:
        case AgentQCurrentPolicyOperator::lte:
        case AgentQCurrentPolicyOperator::contains:
        case AgentQCurrentPolicyOperator::not_contains:
        case AgentQCurrentPolicyOperator::all_in:
        case AgentQCurrentPolicyOperator::none_in:
            return true;
    }
    return false;
}

bool operator_uses_single_value(AgentQCurrentPolicyOperator op)
{
    return op == AgentQCurrentPolicyOperator::eq ||
           op == AgentQCurrentPolicyOperator::lte ||
           op == AgentQCurrentPolicyOperator::contains ||
           op == AgentQCurrentPolicyOperator::not_contains;
}

bool condition_field_requires_where_type(const char* field)
{
    return string_eq(field, "sui.token_totals_by_type.amount_raw");
}

bool condition_field_allows_where_type(const char* field)
{
    return condition_field_requires_where_type(field);
}

bool policy_type_tag_selector_valid(const char* value)
{
    return agent_q_current_policy_value_valid(AgentQCurrentPolicyValueKind::string, value) &&
           string_contains(value, "::");
}

bool validate_condition_where_type(const char* field, const char* where_type)
{
    if (condition_field_requires_where_type(field)) {
        return policy_type_tag_selector_valid(where_type);
    }
    if (string_present(where_type)) {
        return false;
    }
    return !condition_field_allows_where_type(field);
}

uint8_t encode_action(AgentQCurrentPolicyAction action)
{
    switch (action) {
        case AgentQCurrentPolicyAction::reject:
            return kStoredPolicyActionReject;
        case AgentQCurrentPolicyAction::sign:
            return kStoredPolicyActionSign;
    }
    return 0xFF;
}

bool decode_action(uint8_t value, AgentQCurrentPolicyAction* output)
{
    if (output == nullptr) {
        return false;
    }
    switch (value) {
        case kStoredPolicyActionReject:
            *output = AgentQCurrentPolicyAction::reject;
            return true;
        case kStoredPolicyActionSign:
            *output = AgentQCurrentPolicyAction::sign;
            return true;
        default:
            return false;
    }
}

uint8_t encode_operator(AgentQCurrentPolicyOperator op)
{
    switch (op) {
        case AgentQCurrentPolicyOperator::eq:
            return kStoredPolicyOperatorEq;
        case AgentQCurrentPolicyOperator::in:
            return kStoredPolicyOperatorIn;
        case AgentQCurrentPolicyOperator::not_in:
            return kStoredPolicyOperatorNotIn;
        case AgentQCurrentPolicyOperator::lte:
            return kStoredPolicyOperatorLte;
        case AgentQCurrentPolicyOperator::contains:
            return kStoredPolicyOperatorContains;
        case AgentQCurrentPolicyOperator::not_contains:
            return kStoredPolicyOperatorNotContains;
        case AgentQCurrentPolicyOperator::all_in:
            return kStoredPolicyOperatorAllIn;
        case AgentQCurrentPolicyOperator::none_in:
            return kStoredPolicyOperatorNoneIn;
    }
    return 0xFF;
}

bool decode_operator(uint8_t value, AgentQCurrentPolicyOperator* output)
{
    if (output == nullptr) {
        return false;
    }
    switch (value) {
        case kStoredPolicyOperatorEq:
            *output = AgentQCurrentPolicyOperator::eq;
            return true;
        case kStoredPolicyOperatorIn:
            *output = AgentQCurrentPolicyOperator::in;
            return true;
        case kStoredPolicyOperatorNotIn:
            *output = AgentQCurrentPolicyOperator::not_in;
            return true;
        case kStoredPolicyOperatorLte:
            *output = AgentQCurrentPolicyOperator::lte;
            return true;
        case kStoredPolicyOperatorContains:
            *output = AgentQCurrentPolicyOperator::contains;
            return true;
        case kStoredPolicyOperatorNotContains:
            *output = AgentQCurrentPolicyOperator::not_contains;
            return true;
        case kStoredPolicyOperatorAllIn:
            *output = AgentQCurrentPolicyOperator::all_in;
            return true;
        case kStoredPolicyOperatorNoneIn:
            *output = AgentQCurrentPolicyOperator::none_in;
            return true;
        default:
            return false;
    }
}

const char* get_string(
    const AgentQCurrentPolicyCanonicalDocument& policy,
    const AgentQCurrentPolicyCanonicalString& value)
{
    const size_t offset = value.offset;
    const size_t length = value.length;
    if (length == 0 ||
        offset >= sizeof(policy.string_pool) ||
        offset + length >= sizeof(policy.string_pool) ||
        offset + length >= policy.string_pool_size ||
        policy.string_pool[offset + length] != '\0') {
        return nullptr;
    }
    return policy.string_pool + offset;
}

bool add_string(
    AgentQCurrentPolicyCanonicalDocument* policy,
    const char* input,
    size_t max_length,
    AgentQCurrentPolicyCanonicalString* output)
{
    if (policy == nullptr || output == nullptr || !string_present(input) || max_length == 0) {
        return false;
    }
    const size_t length = strlen(input);
    if (length == 0 || length > max_length ||
        policy->string_pool_size >= sizeof(policy->string_pool) ||
        length + 1 > sizeof(policy->string_pool) - policy->string_pool_size ||
        policy->string_pool_size > UINT16_MAX ||
        length > UINT16_MAX) {
        return false;
    }

    output->offset = static_cast<uint16_t>(policy->string_pool_size);
    output->length = static_cast<uint16_t>(length);
    memcpy(policy->string_pool + policy->string_pool_size, input, length + 1);
    policy->string_pool_size += length + 1;
    return true;
}

bool add_string_bytes(
    AgentQCurrentPolicyCanonicalDocument* policy,
    const uint8_t* input,
    size_t length,
    size_t max_length,
    AgentQCurrentPolicyCanonicalString* output)
{
    if (policy == nullptr || output == nullptr || input == nullptr ||
        length == 0 || length > max_length ||
        policy->string_pool_size >= sizeof(policy->string_pool) ||
        length + 1 > sizeof(policy->string_pool) - policy->string_pool_size ||
        policy->string_pool_size > UINT16_MAX ||
        length > UINT16_MAX) {
        return false;
    }
    for (size_t index = 0; index < length; ++index) {
        if (input[index] == 0) {
            return false;
        }
    }

    output->offset = static_cast<uint16_t>(policy->string_pool_size);
    output->length = static_cast<uint16_t>(length);
    memcpy(policy->string_pool + policy->string_pool_size, input, length);
    policy->string_pool[policy->string_pool_size + length] = '\0';
    policy->string_pool_size += length + 1;
    return true;
}

bool append_u8(uint8_t value, uint8_t* output, size_t capacity, size_t* offset)
{
    if (output == nullptr || offset == nullptr || *offset >= capacity) {
        return false;
    }
    output[*offset] = value;
    *offset += 1;
    return true;
}

bool append_u16(uint16_t value, uint8_t* output, size_t capacity, size_t* offset)
{
    return append_u8(static_cast<uint8_t>((value >> 8) & 0xFF), output, capacity, offset) &&
           append_u8(static_cast<uint8_t>(value & 0xFF), output, capacity, offset);
}

bool append_bytes(const void* bytes, size_t size, uint8_t* output, size_t capacity, size_t* offset)
{
    if (bytes == nullptr || output == nullptr || offset == nullptr || *offset > capacity ||
        size > capacity - *offset) {
        return false;
    }
    memcpy(output + *offset, bytes, size);
    *offset += size;
    return true;
}

bool append_string(const char* value, uint8_t* output, size_t capacity, size_t* offset)
{
    if (!string_present(value)) {
        return false;
    }
    const size_t length = strlen(value);
    if (length > UINT16_MAX) {
        return false;
    }
    return append_u16(static_cast<uint16_t>(length), output, capacity, offset) &&
           append_bytes(value, length, output, capacity, offset);
}

bool read_u8(const uint8_t* record, size_t record_size, size_t* offset, uint8_t* output)
{
    if (record == nullptr || offset == nullptr || output == nullptr || *offset >= record_size) {
        return false;
    }
    *output = record[*offset];
    *offset += 1;
    return true;
}

bool read_u16(const uint8_t* record, size_t record_size, size_t* offset, uint16_t* output)
{
    uint8_t hi = 0;
    uint8_t lo = 0;
    if (!read_u8(record, record_size, offset, &hi) ||
        !read_u8(record, record_size, offset, &lo) ||
        output == nullptr) {
        return false;
    }
    *output = static_cast<uint16_t>((static_cast<uint16_t>(hi) << 8) | lo);
    return true;
}

bool read_string(
    const uint8_t* record,
    size_t record_size,
    size_t* offset,
    AgentQCurrentPolicyCanonicalDocument* policy,
    size_t max_length,
    AgentQCurrentPolicyCanonicalString* output)
{
    uint16_t length = 0;
    if (!read_u16(record, record_size, offset, &length) ||
        *offset > record_size ||
        length > record_size - *offset ||
        !add_string_bytes(policy, record + *offset, length, max_length, output)) {
        return false;
    }
    *offset += length;
    return true;
}

bool validate_condition_shape(const AgentQCurrentPolicyCondition& condition)
{
    const AgentQCurrentPolicyFieldDescriptor* descriptor =
        agent_q_current_policy_find_field_descriptor(condition.field);
    if (descriptor == nullptr ||
        !is_known_operator(condition.op) ||
        !agent_q_current_policy_operator_allowed(*descriptor, condition.op)) {
        return false;
    }
    if (condition.values == nullptr ||
        condition.value_count == 0 ||
        condition.value_count > kAgentQCurrentPolicyMaxConditionValues) {
        return false;
    }
    if (operator_uses_single_value(condition.op) && condition.value_count != 1) {
        return false;
    }
    if (!validate_condition_where_type(condition.field, condition.where_type)) {
        return false;
    }
    for (size_t index = 0; index < condition.value_count; ++index) {
        if (!agent_q_current_policy_value_valid(descriptor->value_kind, condition.values[index])) {
            return false;
        }
    }
    return true;
}

bool validate_policy_shape(const AgentQCurrentPolicy& policy)
{
    if (!agent_q_current_policy_is_safe_policy_id(policy.id) ||
        !is_known_action(policy.action) ||
        policy.condition_count > kAgentQCurrentPolicyMaxConditionsPerPolicy ||
        (policy.condition_count != 0 && policy.conditions == nullptr)) {
        return false;
    }
    if (policy.action == AgentQCurrentPolicyAction::sign && policy.condition_count == 0) {
        return false;
    }
    for (size_t index = 0; index < policy.condition_count; ++index) {
        if (!validate_condition_shape(policy.conditions[index])) {
            return false;
        }
    }
    return true;
}

bool duplicate_string(const char* value, const char* const* seen, size_t seen_count)
{
    if (value == nullptr || seen == nullptr) {
        return false;
    }
    for (size_t index = 0; index < seen_count; ++index) {
        if (string_eq(value, seen[index])) {
            return true;
        }
    }
    return false;
}

bool validate_document_shape(
    const AgentQCurrentPolicyDocument& policy,
    size_t* total_networks,
    size_t* total_policies,
    size_t* total_conditions)
{
    if (total_networks != nullptr) {
        *total_networks = 0;
    }
    if (total_policies != nullptr) {
        *total_policies = 0;
    }
    if (total_conditions != nullptr) {
        *total_conditions = 0;
    }
    if (!is_current_schema(policy.schema) ||
        policy.default_action != AgentQCurrentPolicyAction::reject ||
        policy.blockchain_count > kAgentQCurrentPolicyMaxBlockchains ||
        (policy.blockchain_count != 0 && policy.blockchains == nullptr)) {
        return false;
    }

    const char* seen_blockchains[kAgentQCurrentPolicyMaxBlockchains] = {};
    for (size_t blockchain_index = 0; blockchain_index < policy.blockchain_count; ++blockchain_index) {
        const AgentQCurrentPolicyBlockchainScope& blockchain = policy.blockchains[blockchain_index];
        if (!agent_q_current_policy_is_supported_blockchain(blockchain.blockchain) ||
            duplicate_string(blockchain.blockchain, seen_blockchains, blockchain_index) ||
            blockchain.network_count > kAgentQCurrentPolicyMaxNetworksPerBlockchain ||
            (blockchain.network_count != 0 && blockchain.networks == nullptr)) {
            return false;
        }
        seen_blockchains[blockchain_index] = blockchain.blockchain;

        const char* seen_networks[kAgentQCurrentPolicyMaxNetworksPerBlockchain] = {};
        for (size_t network_index = 0; network_index < blockchain.network_count; ++network_index) {
            const AgentQCurrentPolicyNetworkScope& network = blockchain.networks[network_index];
            if (!agent_q_current_policy_is_supported_network(network.network) ||
                duplicate_string(network.network, seen_networks, network_index) ||
                network.policy_count > kAgentQCurrentPolicyMaxPoliciesPerNetwork ||
                (network.policy_count != 0 && network.policies == nullptr)) {
                return false;
            }
            seen_networks[network_index] = network.network;
            if (total_networks != nullptr) {
                *total_networks += 1;
                if (*total_networks > kAgentQCurrentPolicyMaxTotalNetworks) {
                    return false;
                }
            }

            const char* seen_policies[kAgentQCurrentPolicyMaxPoliciesPerNetwork] = {};
            for (size_t policy_index = 0; policy_index < network.policy_count; ++policy_index) {
                const AgentQCurrentPolicy& current_policy = network.policies[policy_index];
                if (!validate_policy_shape(current_policy) ||
                    duplicate_string(current_policy.id, seen_policies, policy_index)) {
                    return false;
                }
                seen_policies[policy_index] = current_policy.id;
                if (total_policies != nullptr) {
                    *total_policies += 1;
                    if (*total_policies > kAgentQCurrentPolicyMaxTotalPolicies) {
                        return false;
                    }
                }
                if (total_conditions != nullptr) {
                    *total_conditions += current_policy.condition_count;
                    if (*total_conditions > kAgentQCurrentPolicyMaxTotalConditions) {
                        return false;
                    }
                }
            }
        }
    }
    return true;
}

AgentQCurrentPolicyDocumentStatus copy_condition(
    const AgentQCurrentPolicyCondition& input,
    AgentQCurrentPolicyCanonicalDocument* policy,
    AgentQCurrentPolicyCanonicalCondition* output)
{
    if (policy == nullptr || output == nullptr || !validate_condition_shape(input)) {
        return AgentQCurrentPolicyDocumentStatus::invalid_policy;
    }
    *output = {};
    output->op = input.op;
    output->value_count = input.value_count;
    if (!add_string(policy, input.field, kAgentQCurrentPolicyMaxFieldIdLength, &output->field)) {
        return AgentQCurrentPolicyDocumentStatus::invalid_policy;
    }
    if (string_present(input.where_type)) {
        output->has_where_type = true;
        if (!add_string(policy, input.where_type, kAgentQCurrentPolicyMaxValueLength, &output->where_type)) {
            return AgentQCurrentPolicyDocumentStatus::invalid_policy;
        }
    }
    for (size_t index = 0; index < input.value_count; ++index) {
        if (!add_string(policy, input.values[index], kAgentQCurrentPolicyMaxValueLength, &output->values[index])) {
            return AgentQCurrentPolicyDocumentStatus::invalid_policy;
        }
    }
    return AgentQCurrentPolicyDocumentStatus::ok;
}

bool validate_canonical_condition_shape(
    const AgentQCurrentPolicyCanonicalDocument& policy,
    const AgentQCurrentPolicyCanonicalCondition& condition)
{
    const char* field = get_string(policy, condition.field);
    const AgentQCurrentPolicyFieldDescriptor* descriptor =
        agent_q_current_policy_find_field_descriptor(field);
    if (descriptor == nullptr ||
        !is_known_operator(condition.op) ||
        !agent_q_current_policy_operator_allowed(*descriptor, condition.op) ||
        condition.value_count == 0 ||
        condition.value_count > kAgentQCurrentPolicyMaxConditionValues ||
        (operator_uses_single_value(condition.op) && condition.value_count != 1)) {
        return false;
    }
    for (size_t index = 0; index < condition.value_count; ++index) {
        const char* value = get_string(policy, condition.values[index]);
        if (!agent_q_current_policy_value_valid(descriptor->value_kind, value)) {
            return false;
        }
    }
    const char* where_type = condition.has_where_type ? get_string(policy, condition.where_type) : nullptr;
    if (!validate_condition_where_type(field, where_type)) {
        return false;
    }
    return true;
}

bool validate_canonical_shape(const AgentQCurrentPolicyCanonicalDocument& policy)
{
    if (policy.default_action != AgentQCurrentPolicyAction::reject ||
        policy.blockchain_count > kAgentQCurrentPolicyMaxBlockchains ||
        policy.total_network_count > kAgentQCurrentPolicyMaxTotalNetworks ||
        policy.total_policy_count > kAgentQCurrentPolicyMaxTotalPolicies ||
        policy.total_condition_count > kAgentQCurrentPolicyMaxTotalConditions ||
        policy.string_pool_size > sizeof(policy.string_pool)) {
        return false;
    }

    size_t counted_networks = 0;
    size_t counted_policies = 0;
    size_t counted_conditions = 0;
    const char* seen_blockchains[kAgentQCurrentPolicyMaxBlockchains] = {};
    for (size_t blockchain_index = 0; blockchain_index < policy.blockchain_count; ++blockchain_index) {
        const AgentQCurrentPolicyCanonicalBlockchainScope& blockchain = policy.blockchains[blockchain_index];
        const char* blockchain_name = get_string(policy, blockchain.blockchain);
        if (!agent_q_current_policy_is_supported_blockchain(blockchain_name) ||
            duplicate_string(blockchain_name, seen_blockchains, blockchain_index) ||
            blockchain.network_count > kAgentQCurrentPolicyMaxNetworksPerBlockchain) {
            return false;
        }
        seen_blockchains[blockchain_index] = blockchain_name;

        const char* seen_networks[kAgentQCurrentPolicyMaxNetworksPerBlockchain] = {};
        for (size_t network_index = 0; network_index < blockchain.network_count; ++network_index) {
            const AgentQCurrentPolicyCanonicalNetworkScope& network = blockchain.networks[network_index];
            const char* network_name = get_string(policy, network.network);
            if (!agent_q_current_policy_is_supported_network(network_name) ||
                duplicate_string(network_name, seen_networks, network_index) ||
                network.policy_count > kAgentQCurrentPolicyMaxPoliciesPerNetwork) {
                return false;
            }
            seen_networks[network_index] = network_name;
            counted_networks += 1;

            const char* seen_policies[kAgentQCurrentPolicyMaxPoliciesPerNetwork] = {};
            for (size_t policy_index = 0; policy_index < network.policy_count; ++policy_index) {
                const AgentQCurrentPolicyCanonicalPolicy& current_policy = network.policies[policy_index];
                const char* policy_id = get_string(policy, current_policy.id);
                if (!agent_q_current_policy_is_safe_policy_id(policy_id) ||
                    duplicate_string(policy_id, seen_policies, policy_index) ||
                    !is_known_action(current_policy.action) ||
                    current_policy.condition_count > kAgentQCurrentPolicyMaxConditionsPerPolicy ||
                    (current_policy.action == AgentQCurrentPolicyAction::sign &&
                     current_policy.condition_count == 0)) {
                    return false;
                }
                seen_policies[policy_index] = policy_id;
                counted_policies += 1;
                counted_conditions += current_policy.condition_count;
                if (counted_networks > kAgentQCurrentPolicyMaxTotalNetworks ||
                    counted_policies > kAgentQCurrentPolicyMaxTotalPolicies ||
                    counted_conditions > kAgentQCurrentPolicyMaxTotalConditions) {
                    return false;
                }
                for (size_t condition_index = 0; condition_index < current_policy.condition_count; ++condition_index) {
                    if (!validate_canonical_condition_shape(policy, current_policy.conditions[condition_index])) {
                        return false;
                    }
                }
            }
        }
    }
    return counted_networks == policy.total_network_count &&
           counted_policies == policy.total_policy_count &&
           counted_conditions == policy.total_condition_count;
}

}  // namespace

const AgentQCurrentPolicyFieldDescriptor kAgentQCurrentPolicyFieldDescriptors[] = {
    {"sui.gas_budget_raw", AgentQCurrentPolicyValueKind::u64_decimal, true, false, false, true, false, false, false, false},
    {"sui.gas_price_raw", AgentQCurrentPolicyValueKind::u64_decimal, true, false, false, true, false, false, false, false},
    {"sui.gas_owner", AgentQCurrentPolicyValueKind::string, true, true, true, false, false, false, false, false},
    {"sui.sponsored", AgentQCurrentPolicyValueKind::bool_string, true, false, false, false, false, false, false, false},
    {"sui.command_count", AgentQCurrentPolicyValueKind::u64_decimal, true, false, false, true, false, false, false, false},
    {"sui.command_kinds", AgentQCurrentPolicyValueKind::string, false, false, false, false, true, true, true, true},
    {"sui.move_call_packages", AgentQCurrentPolicyValueKind::string, false, false, false, false, true, true, true, true},
    {"sui.move_call_modules", AgentQCurrentPolicyValueKind::string, false, false, false, false, true, true, true, true},
    {"sui.move_call_functions", AgentQCurrentPolicyValueKind::string, false, false, false, false, true, true, true, true},
    {"sui.publish_present", AgentQCurrentPolicyValueKind::bool_string, true, false, false, false, false, false, false, false},
    {"sui.upgrade_present", AgentQCurrentPolicyValueKind::bool_string, true, false, false, false, false, false, false, false},
    {"sui.recipient_addresses", AgentQCurrentPolicyValueKind::string, false, false, false, false, true, true, true, true},
    {"sui.pure_address_arguments", AgentQCurrentPolicyValueKind::string, false, false, false, false, true, true, false, true},
    {"sui.token_sources.type", AgentQCurrentPolicyValueKind::string, true, true, true, false, false, false, false, false},
    {"sui.token_sources.source", AgentQCurrentPolicyValueKind::string, true, true, false, false, false, false, false, false},
    {"sui.token_sources.amount_raw", AgentQCurrentPolicyValueKind::u64_decimal, true, false, false, true, false, false, false, false},
    {"sui.token_totals_by_type.amount_raw", AgentQCurrentPolicyValueKind::u64_decimal, true, false, false, true, false, false, false, false},
    {"sui.token_unknown_amount_present", AgentQCurrentPolicyValueKind::bool_string, true, false, false, false, false, false, false, false},
};

const size_t kAgentQCurrentPolicyFieldDescriptorCount =
    sizeof(kAgentQCurrentPolicyFieldDescriptors) / sizeof(kAgentQCurrentPolicyFieldDescriptors[0]);

const char* agent_q_current_policy_action_name(AgentQCurrentPolicyAction action)
{
    switch (action) {
        case AgentQCurrentPolicyAction::reject:
            return "reject";
        case AgentQCurrentPolicyAction::sign:
            return "sign";
    }
    return "";
}

const char* agent_q_current_policy_operator_name(AgentQCurrentPolicyOperator op)
{
    switch (op) {
        case AgentQCurrentPolicyOperator::eq:
            return "eq";
        case AgentQCurrentPolicyOperator::in:
            return "in";
        case AgentQCurrentPolicyOperator::not_in:
            return "not_in";
        case AgentQCurrentPolicyOperator::lte:
            return "lte";
        case AgentQCurrentPolicyOperator::contains:
            return "contains";
        case AgentQCurrentPolicyOperator::not_contains:
            return "not_contains";
        case AgentQCurrentPolicyOperator::all_in:
            return "all_in";
        case AgentQCurrentPolicyOperator::none_in:
            return "none_in";
    }
    return "";
}

const char* agent_q_current_policy_document_status_name(AgentQCurrentPolicyDocumentStatus status)
{
    switch (status) {
        case AgentQCurrentPolicyDocumentStatus::ok:
            return "ok";
        case AgentQCurrentPolicyDocumentStatus::invalid_argument:
            return "invalid_argument";
        case AgentQCurrentPolicyDocumentStatus::invalid_policy:
            return "invalid_policy";
        case AgentQCurrentPolicyDocumentStatus::unsupported_field:
            return "unsupported_field";
        case AgentQCurrentPolicyDocumentStatus::output_too_small:
            return "output_too_small";
    }
    return "unknown";
}

bool agent_q_current_policy_is_supported_blockchain(const char* value)
{
    return string_eq(value, "sui");
}

bool agent_q_current_policy_is_supported_network(const char* value)
{
    return string_eq(value, "mainnet") ||
           string_eq(value, "testnet") ||
           string_eq(value, "devnet") ||
           string_eq(value, "localnet");
}

bool agent_q_current_policy_is_safe_identifier(const char* value, size_t max_length)
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

bool agent_q_current_policy_is_safe_policy_id(const char* value)
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
        if (length > kAgentQCurrentPolicyMaxPolicyIdLength) {
            return false;
        }
    }
    return true;
}

const AgentQCurrentPolicyFieldDescriptor* agent_q_current_policy_find_field_descriptor(
    const char* field)
{
    for (size_t index = 0; index < kAgentQCurrentPolicyFieldDescriptorCount; ++index) {
        if (string_eq(kAgentQCurrentPolicyFieldDescriptors[index].field, field)) {
            return &kAgentQCurrentPolicyFieldDescriptors[index];
        }
    }
    return nullptr;
}

bool agent_q_current_policy_operator_allowed(
    const AgentQCurrentPolicyFieldDescriptor& descriptor,
    AgentQCurrentPolicyOperator op)
{
    switch (op) {
        case AgentQCurrentPolicyOperator::eq:
            return descriptor.allow_eq;
        case AgentQCurrentPolicyOperator::in:
            return descriptor.allow_in;
        case AgentQCurrentPolicyOperator::not_in:
            return descriptor.allow_not_in;
        case AgentQCurrentPolicyOperator::lte:
            return descriptor.allow_lte;
        case AgentQCurrentPolicyOperator::contains:
            return descriptor.allow_contains;
        case AgentQCurrentPolicyOperator::not_contains:
            return descriptor.allow_not_contains;
        case AgentQCurrentPolicyOperator::all_in:
            return descriptor.allow_all_in;
        case AgentQCurrentPolicyOperator::none_in:
            return descriptor.allow_none_in;
    }
    return false;
}

bool agent_q_current_policy_value_valid(
    AgentQCurrentPolicyValueKind kind,
    const char* value)
{
    if (!string_present(value) || strlen(value) > kAgentQCurrentPolicyMaxValueLength) {
        return false;
    }
    switch (kind) {
        case AgentQCurrentPolicyValueKind::string:
            for (const char* cursor = value; *cursor != '\0'; ++cursor) {
                const unsigned char ch = static_cast<unsigned char>(*cursor);
                if (ch < 0x20 || ch > 0x7E) {
                    return false;
                }
            }
            return true;
        case AgentQCurrentPolicyValueKind::u64_decimal:
            return agent_q_policy_is_canonical_decimal_u64_string(value);
        case AgentQCurrentPolicyValueKind::bool_string:
            return string_eq(value, "true") || string_eq(value, "false");
    }
    return false;
}

bool agent_q_current_policy_operator_uses_value_list(AgentQCurrentPolicyOperator op)
{
    return !operator_uses_single_value(op);
}

AgentQCurrentPolicyDocumentStatus validate_agent_q_current_policy_document(
    const AgentQCurrentPolicyDocument& policy)
{
    size_t total_networks = 0;
    size_t total_policies = 0;
    size_t total_conditions = 0;
    return validate_document_shape(policy, &total_networks, &total_policies, &total_conditions)
               ? AgentQCurrentPolicyDocumentStatus::ok
               : AgentQCurrentPolicyDocumentStatus::invalid_policy;
}

AgentQCurrentPolicyDocumentStatus canonicalize_agent_q_current_policy_document(
    const AgentQCurrentPolicyDocument& policy,
    AgentQCurrentPolicyCanonicalDocument* out)
{
    if (out == nullptr) {
        return AgentQCurrentPolicyDocumentStatus::invalid_argument;
    }
    memset(out, 0, sizeof(*out));

    size_t total_networks = 0;
    size_t total_policies = 0;
    size_t total_conditions = 0;
    if (!validate_document_shape(policy, &total_networks, &total_policies, &total_conditions)) {
        return AgentQCurrentPolicyDocumentStatus::invalid_policy;
    }

    out->default_action = AgentQCurrentPolicyAction::reject;
    out->blockchain_count = policy.blockchain_count;
    out->total_network_count = total_networks;
    out->total_policy_count = total_policies;
    out->total_condition_count = total_conditions;

    for (size_t blockchain_index = 0; blockchain_index < policy.blockchain_count; ++blockchain_index) {
        const AgentQCurrentPolicyBlockchainScope& input_blockchain = policy.blockchains[blockchain_index];
        AgentQCurrentPolicyCanonicalBlockchainScope& output_blockchain = out->blockchains[blockchain_index];
        output_blockchain.network_count = input_blockchain.network_count;
        if (!add_string(out, input_blockchain.blockchain, kAgentQCurrentPolicyMaxBlockchainLength, &output_blockchain.blockchain)) {
            memset(out, 0, sizeof(*out));
            return AgentQCurrentPolicyDocumentStatus::invalid_policy;
        }
        for (size_t network_index = 0; network_index < input_blockchain.network_count; ++network_index) {
            const AgentQCurrentPolicyNetworkScope& input_network = input_blockchain.networks[network_index];
            AgentQCurrentPolicyCanonicalNetworkScope& output_network = output_blockchain.networks[network_index];
            output_network.policy_count = input_network.policy_count;
            if (!add_string(out, input_network.network, kAgentQCurrentPolicyMaxNetworkLength, &output_network.network)) {
                memset(out, 0, sizeof(*out));
                return AgentQCurrentPolicyDocumentStatus::invalid_policy;
            }
            for (size_t policy_index = 0; policy_index < input_network.policy_count; ++policy_index) {
                const AgentQCurrentPolicy& input_policy = input_network.policies[policy_index];
                AgentQCurrentPolicyCanonicalPolicy& output_policy = output_network.policies[policy_index];
                output_policy.action = input_policy.action;
                output_policy.condition_count = input_policy.condition_count;
                if (!add_string(out, input_policy.id, kAgentQCurrentPolicyMaxPolicyIdLength, &output_policy.id)) {
                    memset(out, 0, sizeof(*out));
                    return AgentQCurrentPolicyDocumentStatus::invalid_policy;
                }
                for (size_t condition_index = 0; condition_index < input_policy.condition_count; ++condition_index) {
                    const AgentQCurrentPolicyDocumentStatus status = copy_condition(
                        input_policy.conditions[condition_index],
                        out,
                        &output_policy.conditions[condition_index]);
                    if (status != AgentQCurrentPolicyDocumentStatus::ok) {
                        memset(out, 0, sizeof(*out));
                        return status;
                    }
                }
            }
        }
    }
    return AgentQCurrentPolicyDocumentStatus::ok;
}

bool agent_q_current_policy_canonical_to_runtime_view(
    const AgentQCurrentPolicyCanonicalDocument& policy,
    AgentQCurrentPolicyRuntimeView* out)
{
    if (out == nullptr || !validate_canonical_shape(policy)) {
        return false;
    }
    memset(out, 0, sizeof(*out));

    size_t network_cursor = 0;
    size_t policy_cursor = 0;
    size_t condition_cursor = 0;
    for (size_t blockchain_index = 0; blockchain_index < policy.blockchain_count; ++blockchain_index) {
        const AgentQCurrentPolicyCanonicalBlockchainScope& input_blockchain = policy.blockchains[blockchain_index];
        AgentQCurrentPolicyBlockchainScope& output_blockchain = out->blockchains[blockchain_index];
        output_blockchain.blockchain = get_string(policy, input_blockchain.blockchain);
        output_blockchain.network_count = input_blockchain.network_count;
        output_blockchain.networks = input_blockchain.network_count == 0 ? nullptr : &out->networks[network_cursor];
        for (size_t network_index = 0; network_index < input_blockchain.network_count; ++network_index) {
            const AgentQCurrentPolicyCanonicalNetworkScope& input_network = input_blockchain.networks[network_index];
            AgentQCurrentPolicyNetworkScope& output_network = out->networks[network_cursor++];
            output_network.network = get_string(policy, input_network.network);
            output_network.policy_count = input_network.policy_count;
            output_network.policies = input_network.policy_count == 0 ? nullptr : &out->policies[policy_cursor];
            for (size_t policy_index = 0; policy_index < input_network.policy_count; ++policy_index) {
                const AgentQCurrentPolicyCanonicalPolicy& input_policy = input_network.policies[policy_index];
                AgentQCurrentPolicy& output_policy = out->policies[policy_cursor++];
                output_policy.id = get_string(policy, input_policy.id);
                output_policy.action = input_policy.action;
                output_policy.condition_count = input_policy.condition_count;
                output_policy.conditions = input_policy.condition_count == 0 ? nullptr : &out->conditions[condition_cursor];
                for (size_t condition_index = 0; condition_index < input_policy.condition_count; ++condition_index) {
                    const AgentQCurrentPolicyCanonicalCondition& input_condition = input_policy.conditions[condition_index];
                    AgentQCurrentPolicyCondition& output_condition = out->conditions[condition_cursor];
                    output_condition.field = get_string(policy, input_condition.field);
                    output_condition.where_type =
                        input_condition.has_where_type ? get_string(policy, input_condition.where_type) : nullptr;
                    output_condition.op = input_condition.op;
                    output_condition.value_count = input_condition.value_count;
                    for (size_t value_index = 0; value_index < input_condition.value_count; ++value_index) {
                        out->values[condition_cursor][value_index] =
                            get_string(policy, input_condition.values[value_index]);
                    }
                    output_condition.values = out->values[condition_cursor];
                    condition_cursor += 1;
                }
            }
        }
    }

    out->document = AgentQCurrentPolicyDocument{
        kAgentQCurrentPolicySchema,
        policy.default_action,
        policy.blockchain_count == 0 ? nullptr : out->blockchains,
        policy.blockchain_count,
    };
    return true;
}

AgentQCurrentPolicyDocumentStatus validate_agent_q_current_policy_canonical_document(
    const AgentQCurrentPolicyCanonicalDocument& policy)
{
    return validate_canonical_shape(policy)
               ? AgentQCurrentPolicyDocumentStatus::ok
               : AgentQCurrentPolicyDocumentStatus::invalid_policy;
}

AgentQCurrentPolicyDocumentStatus encode_agent_q_current_policy_canonical_record(
    const AgentQCurrentPolicyCanonicalDocument& policy,
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size)
{
    if (output_size != nullptr) {
        *output_size = 0;
    }
    if (output == nullptr || output_capacity == 0 || output_size == nullptr) {
        return AgentQCurrentPolicyDocumentStatus::invalid_argument;
    }
    memset(output, 0, output_capacity);

    if (!validate_canonical_shape(policy) || policy.blockchain_count > UINT8_MAX) {
        return AgentQCurrentPolicyDocumentStatus::invalid_policy;
    }

    StoredPolicyHeader header = {
        {'A', 'Q', 'P', 'D'},
        kStoredPolicyFormatVersion,
        encode_action(policy.default_action),
        static_cast<uint8_t>(policy.blockchain_count),
        {},
    };

    size_t offset = 0;
    if (!append_bytes(&header, sizeof(header), output, output_capacity, &offset)) {
        return AgentQCurrentPolicyDocumentStatus::output_too_small;
    }
    for (size_t blockchain_index = 0; blockchain_index < policy.blockchain_count; ++blockchain_index) {
        const AgentQCurrentPolicyCanonicalBlockchainScope& blockchain = policy.blockchains[blockchain_index];
        if (blockchain.network_count > UINT8_MAX ||
            !append_string(get_string(policy, blockchain.blockchain), output, output_capacity, &offset) ||
            !append_u8(static_cast<uint8_t>(blockchain.network_count), output, output_capacity, &offset)) {
            return AgentQCurrentPolicyDocumentStatus::output_too_small;
        }
        for (size_t network_index = 0; network_index < blockchain.network_count; ++network_index) {
            const AgentQCurrentPolicyCanonicalNetworkScope& network = blockchain.networks[network_index];
            if (network.policy_count > UINT8_MAX ||
                !append_string(get_string(policy, network.network), output, output_capacity, &offset) ||
                !append_u8(static_cast<uint8_t>(network.policy_count), output, output_capacity, &offset)) {
                return AgentQCurrentPolicyDocumentStatus::output_too_small;
            }
            for (size_t policy_index = 0; policy_index < network.policy_count; ++policy_index) {
                const AgentQCurrentPolicyCanonicalPolicy& current_policy = network.policies[policy_index];
                if (current_policy.condition_count > UINT16_MAX ||
                    !append_string(get_string(policy, current_policy.id), output, output_capacity, &offset) ||
                    !append_u8(encode_action(current_policy.action), output, output_capacity, &offset) ||
                    !append_u16(static_cast<uint16_t>(current_policy.condition_count), output, output_capacity, &offset)) {
                    return AgentQCurrentPolicyDocumentStatus::output_too_small;
                }
                for (size_t condition_index = 0; condition_index < current_policy.condition_count; ++condition_index) {
                    const AgentQCurrentPolicyCanonicalCondition& condition = current_policy.conditions[condition_index];
                    if (condition.value_count > UINT8_MAX ||
                        !append_string(get_string(policy, condition.field), output, output_capacity, &offset) ||
                        !append_u8(condition.has_where_type ? 1 : 0, output, output_capacity, &offset) ||
                        (condition.has_where_type &&
                         !append_string(get_string(policy, condition.where_type), output, output_capacity, &offset)) ||
                        !append_u8(encode_operator(condition.op), output, output_capacity, &offset) ||
                        !append_u8(static_cast<uint8_t>(condition.value_count), output, output_capacity, &offset)) {
                        return AgentQCurrentPolicyDocumentStatus::output_too_small;
                    }
                    for (size_t value_index = 0; value_index < condition.value_count; ++value_index) {
                        if (!append_string(get_string(policy, condition.values[value_index]), output, output_capacity, &offset)) {
                            return AgentQCurrentPolicyDocumentStatus::output_too_small;
                        }
                    }
                }
            }
        }
    }
    *output_size = offset;
    return AgentQCurrentPolicyDocumentStatus::ok;
}

AgentQCurrentPolicyDocumentStatus encode_agent_q_current_policy_default_record(
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size)
{
    if (output_size != nullptr) {
        *output_size = 0;
    }
    if (output == nullptr || output_capacity == 0 || output_size == nullptr) {
        return AgentQCurrentPolicyDocumentStatus::invalid_argument;
    }
    memset(output, 0, output_capacity);

    const StoredPolicyHeader header = {
        {'A', 'Q', 'P', 'D'},
        kStoredPolicyFormatVersion,
        kStoredPolicyActionReject,
        0,
        {},
    };
    size_t offset = 0;
    if (!append_bytes(&header, sizeof(header), output, output_capacity, &offset)) {
        return AgentQCurrentPolicyDocumentStatus::output_too_small;
    }
    *output_size = offset;
    return AgentQCurrentPolicyDocumentStatus::ok;
}

AgentQCurrentPolicyDocumentStatus decode_agent_q_current_policy_canonical_record(
    const uint8_t* record,
    size_t record_size,
    AgentQCurrentPolicyCanonicalDocument* out)
{
    if (out == nullptr) {
        return AgentQCurrentPolicyDocumentStatus::invalid_argument;
    }
    memset(out, 0, sizeof(*out));
    if (record == nullptr || record_size < sizeof(StoredPolicyHeader)) {
        return AgentQCurrentPolicyDocumentStatus::invalid_argument;
    }

    StoredPolicyHeader header = {};
    memcpy(&header, record, sizeof(header));
    if (memcmp(header.magic, "AQPD", sizeof(header.magic)) != 0 ||
        header.format_version != kStoredPolicyFormatVersion ||
        header.blockchain_count > kAgentQCurrentPolicyMaxBlockchains) {
        return AgentQCurrentPolicyDocumentStatus::invalid_policy;
    }
    for (size_t index = 0; index < sizeof(header.reserved); ++index) {
        if (header.reserved[index] != 0) {
            return AgentQCurrentPolicyDocumentStatus::invalid_policy;
        }
    }
    if (!decode_action(header.default_action, &out->default_action) ||
        out->default_action != AgentQCurrentPolicyAction::reject) {
        memset(out, 0, sizeof(*out));
        return AgentQCurrentPolicyDocumentStatus::invalid_policy;
    }

    out->blockchain_count = header.blockchain_count;
    size_t offset = sizeof(header);
    for (size_t blockchain_index = 0; blockchain_index < out->blockchain_count; ++blockchain_index) {
        AgentQCurrentPolicyCanonicalBlockchainScope& blockchain = out->blockchains[blockchain_index];
        uint8_t network_count = 0;
        if (!read_string(record, record_size, &offset, out, kAgentQCurrentPolicyMaxBlockchainLength, &blockchain.blockchain) ||
            !read_u8(record, record_size, &offset, &network_count) ||
            network_count > kAgentQCurrentPolicyMaxNetworksPerBlockchain) {
            memset(out, 0, sizeof(*out));
            return AgentQCurrentPolicyDocumentStatus::invalid_policy;
        }
        blockchain.network_count = network_count;
        out->total_network_count += network_count;
        if (out->total_network_count > kAgentQCurrentPolicyMaxTotalNetworks) {
            memset(out, 0, sizeof(*out));
            return AgentQCurrentPolicyDocumentStatus::invalid_policy;
        }
        for (size_t network_index = 0; network_index < blockchain.network_count; ++network_index) {
            AgentQCurrentPolicyCanonicalNetworkScope& network = blockchain.networks[network_index];
            uint8_t policy_count = 0;
            if (!read_string(record, record_size, &offset, out, kAgentQCurrentPolicyMaxNetworkLength, &network.network) ||
                !read_u8(record, record_size, &offset, &policy_count) ||
                policy_count > kAgentQCurrentPolicyMaxPoliciesPerNetwork) {
                memset(out, 0, sizeof(*out));
                return AgentQCurrentPolicyDocumentStatus::invalid_policy;
            }
            network.policy_count = policy_count;
            out->total_policy_count += policy_count;
            if (out->total_policy_count > kAgentQCurrentPolicyMaxTotalPolicies) {
                memset(out, 0, sizeof(*out));
                return AgentQCurrentPolicyDocumentStatus::invalid_policy;
            }
            for (size_t policy_index = 0; policy_index < network.policy_count; ++policy_index) {
                AgentQCurrentPolicyCanonicalPolicy& current_policy = network.policies[policy_index];
                uint8_t action = 0;
                uint16_t condition_count = 0;
                if (!read_string(record, record_size, &offset, out, kAgentQCurrentPolicyMaxPolicyIdLength, &current_policy.id) ||
                    !read_u8(record, record_size, &offset, &action) ||
                    !decode_action(action, &current_policy.action) ||
                    !read_u16(record, record_size, &offset, &condition_count) ||
                    condition_count > kAgentQCurrentPolicyMaxConditionsPerPolicy) {
                    memset(out, 0, sizeof(*out));
                    return AgentQCurrentPolicyDocumentStatus::invalid_policy;
                }
                current_policy.condition_count = condition_count;
                out->total_condition_count += condition_count;
                if (out->total_condition_count > kAgentQCurrentPolicyMaxTotalConditions) {
                    memset(out, 0, sizeof(*out));
                    return AgentQCurrentPolicyDocumentStatus::invalid_policy;
                }
                for (size_t condition_index = 0; condition_index < current_policy.condition_count; ++condition_index) {
                    AgentQCurrentPolicyCanonicalCondition& condition = current_policy.conditions[condition_index];
                    uint8_t has_where_type = 0;
                    uint8_t op = 0;
                    uint8_t value_count = 0;
                    if (!read_string(record, record_size, &offset, out, kAgentQCurrentPolicyMaxFieldIdLength, &condition.field) ||
                        !read_u8(record, record_size, &offset, &has_where_type) ||
                        has_where_type > 1 ||
                        (has_where_type == 1 &&
                         !read_string(record, record_size, &offset, out, kAgentQCurrentPolicyMaxValueLength, &condition.where_type)) ||
                        !read_u8(record, record_size, &offset, &op) ||
                        !decode_operator(op, &condition.op) ||
                        !read_u8(record, record_size, &offset, &value_count) ||
                        value_count == 0 ||
                        value_count > kAgentQCurrentPolicyMaxConditionValues) {
                        memset(out, 0, sizeof(*out));
                        return AgentQCurrentPolicyDocumentStatus::invalid_policy;
                    }
                    condition.has_where_type = has_where_type == 1;
                    condition.value_count = value_count;
                    for (size_t value_index = 0; value_index < condition.value_count; ++value_index) {
                        if (!read_string(record, record_size, &offset, out, kAgentQCurrentPolicyMaxValueLength, &condition.values[value_index])) {
                            memset(out, 0, sizeof(*out));
                            return AgentQCurrentPolicyDocumentStatus::invalid_policy;
                        }
                    }
                }
            }
        }
    }

    if (offset != record_size || !validate_canonical_shape(*out)) {
        memset(out, 0, sizeof(*out));
        return AgentQCurrentPolicyDocumentStatus::invalid_policy;
    }
    return AgentQCurrentPolicyDocumentStatus::ok;
}

}  // namespace agent_q
