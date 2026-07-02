#include "document.h"

#include <string.h>

#include "u64.h"

namespace signing {
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
    sizeof(StoredPolicyHeader) == kCurrentPolicyDefaultCanonicalRecordBytes,
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
    return string_eq(value, kCurrentPolicySchema);
}

bool is_known_action(CurrentPolicyAction action)
{
    switch (action) {
        case CurrentPolicyAction::reject:
        case CurrentPolicyAction::sign:
            return true;
    }
    return false;
}

bool is_known_operator(CurrentPolicyOperator op)
{
    switch (op) {
        case CurrentPolicyOperator::eq:
        case CurrentPolicyOperator::in:
        case CurrentPolicyOperator::not_in:
        case CurrentPolicyOperator::lte:
        case CurrentPolicyOperator::contains:
        case CurrentPolicyOperator::not_contains:
        case CurrentPolicyOperator::all_in:
        case CurrentPolicyOperator::none_in:
            return true;
    }
    return false;
}

bool operator_uses_single_value(CurrentPolicyOperator op)
{
    return op == CurrentPolicyOperator::eq ||
           op == CurrentPolicyOperator::lte ||
           op == CurrentPolicyOperator::contains ||
           op == CurrentPolicyOperator::not_contains;
}

bool policy_type_tag_selector_valid(const char* value)
{
    return current_policy_value_valid(CurrentPolicyValueKind::string, value) &&
           string_contains(value, "::");
}

bool validate_condition_where_type(
    const CurrentPolicyFieldDescriptor& descriptor,
    const char* where_type)
{
    switch (descriptor.where_type_requirement) {
        case CurrentPolicyWhereTypeRequirement::required:
            return policy_type_tag_selector_valid(where_type);
        case CurrentPolicyWhereTypeRequirement::forbidden:
            return !string_present(where_type);
    }
    return false;
}

uint8_t encode_action(CurrentPolicyAction action)
{
    switch (action) {
        case CurrentPolicyAction::reject:
            return kStoredPolicyActionReject;
        case CurrentPolicyAction::sign:
            return kStoredPolicyActionSign;
    }
    return 0xFF;
}

bool decode_action(uint8_t value, CurrentPolicyAction* output)
{
    if (output == nullptr) {
        return false;
    }
    switch (value) {
        case kStoredPolicyActionReject:
            *output = CurrentPolicyAction::reject;
            return true;
        case kStoredPolicyActionSign:
            *output = CurrentPolicyAction::sign;
            return true;
        default:
            return false;
    }
}

uint8_t encode_operator(CurrentPolicyOperator op)
{
    switch (op) {
        case CurrentPolicyOperator::eq:
            return kStoredPolicyOperatorEq;
        case CurrentPolicyOperator::in:
            return kStoredPolicyOperatorIn;
        case CurrentPolicyOperator::not_in:
            return kStoredPolicyOperatorNotIn;
        case CurrentPolicyOperator::lte:
            return kStoredPolicyOperatorLte;
        case CurrentPolicyOperator::contains:
            return kStoredPolicyOperatorContains;
        case CurrentPolicyOperator::not_contains:
            return kStoredPolicyOperatorNotContains;
        case CurrentPolicyOperator::all_in:
            return kStoredPolicyOperatorAllIn;
        case CurrentPolicyOperator::none_in:
            return kStoredPolicyOperatorNoneIn;
    }
    return 0xFF;
}

bool decode_operator(uint8_t value, CurrentPolicyOperator* output)
{
    if (output == nullptr) {
        return false;
    }
    switch (value) {
        case kStoredPolicyOperatorEq:
            *output = CurrentPolicyOperator::eq;
            return true;
        case kStoredPolicyOperatorIn:
            *output = CurrentPolicyOperator::in;
            return true;
        case kStoredPolicyOperatorNotIn:
            *output = CurrentPolicyOperator::not_in;
            return true;
        case kStoredPolicyOperatorLte:
            *output = CurrentPolicyOperator::lte;
            return true;
        case kStoredPolicyOperatorContains:
            *output = CurrentPolicyOperator::contains;
            return true;
        case kStoredPolicyOperatorNotContains:
            *output = CurrentPolicyOperator::not_contains;
            return true;
        case kStoredPolicyOperatorAllIn:
            *output = CurrentPolicyOperator::all_in;
            return true;
        case kStoredPolicyOperatorNoneIn:
            *output = CurrentPolicyOperator::none_in;
            return true;
        default:
            return false;
    }
}

const char* get_string(
    const CurrentPolicyCanonicalDocument& policy,
    const CurrentPolicyCanonicalString& value)
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
    CurrentPolicyCanonicalDocument* policy,
    const char* input,
    size_t max_length,
    CurrentPolicyCanonicalString* output)
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
    CurrentPolicyCanonicalDocument* policy,
    const uint8_t* input,
    size_t length,
    size_t max_length,
    CurrentPolicyCanonicalString* output)
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
    CurrentPolicyCanonicalDocument* policy,
    size_t max_length,
    CurrentPolicyCanonicalString* output)
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

bool validate_condition_shape(const CurrentPolicyCondition& condition)
{
    const CurrentPolicyFieldDescriptor* descriptor =
        current_policy_find_field_descriptor(condition.field);
    if (descriptor == nullptr ||
        !is_known_operator(condition.op) ||
        !current_policy_operator_allowed(*descriptor, condition.op)) {
        return false;
    }
    if (condition.values == nullptr ||
        condition.value_count == 0 ||
        condition.value_count > kCurrentPolicyMaxConditionValues) {
        return false;
    }
    if (operator_uses_single_value(condition.op) && condition.value_count != 1) {
        return false;
    }
    if (!validate_condition_where_type(*descriptor, condition.where_type)) {
        return false;
    }
    for (size_t index = 0; index < condition.value_count; ++index) {
        if (!current_policy_value_valid(descriptor->value_kind, condition.values[index])) {
            return false;
        }
    }
    return true;
}

bool validate_policy_shape(const CurrentPolicy& policy)
{
    if (!current_policy_is_safe_policy_id(policy.id) ||
        !is_known_action(policy.action) ||
        policy.condition_count > kCurrentPolicyMaxConditionsPerPolicy ||
        (policy.condition_count != 0 && policy.conditions == nullptr)) {
        return false;
    }
    if (policy.action == CurrentPolicyAction::sign && policy.condition_count == 0) {
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
    const CurrentPolicyDocument& policy,
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
        policy.default_action != CurrentPolicyAction::reject ||
        policy.blockchain_count > kCurrentPolicyMaxBlockchains ||
        (policy.blockchain_count != 0 && policy.blockchains == nullptr)) {
        return false;
    }

    const char* seen_blockchains[kCurrentPolicyMaxBlockchains] = {};
    for (size_t blockchain_index = 0; blockchain_index < policy.blockchain_count; ++blockchain_index) {
        const CurrentPolicyBlockchainScope& blockchain = policy.blockchains[blockchain_index];
        if (!current_policy_is_supported_blockchain(blockchain.blockchain) ||
            duplicate_string(blockchain.blockchain, seen_blockchains, blockchain_index) ||
            blockchain.network_count > kCurrentPolicyMaxNetworksPerBlockchain ||
            (blockchain.network_count != 0 && blockchain.networks == nullptr)) {
            return false;
        }
        seen_blockchains[blockchain_index] = blockchain.blockchain;

        const char* seen_networks[kCurrentPolicyMaxNetworksPerBlockchain] = {};
        for (size_t network_index = 0; network_index < blockchain.network_count; ++network_index) {
            const CurrentPolicyNetworkScope& network = blockchain.networks[network_index];
            if (!current_policy_is_supported_network(network.network) ||
                duplicate_string(network.network, seen_networks, network_index) ||
                network.policy_count > kCurrentPolicyMaxPoliciesPerNetwork ||
                (network.policy_count != 0 && network.policies == nullptr)) {
                return false;
            }
            seen_networks[network_index] = network.network;
            if (total_networks != nullptr) {
                *total_networks += 1;
                if (*total_networks > kCurrentPolicyMaxTotalNetworks) {
                    return false;
                }
            }

            const char* seen_policies[kCurrentPolicyMaxPoliciesPerNetwork] = {};
            for (size_t policy_index = 0; policy_index < network.policy_count; ++policy_index) {
                const CurrentPolicy& current_policy = network.policies[policy_index];
                if (!validate_policy_shape(current_policy) ||
                    duplicate_string(current_policy.id, seen_policies, policy_index)) {
                    return false;
                }
                seen_policies[policy_index] = current_policy.id;
                if (total_policies != nullptr) {
                    *total_policies += 1;
                    if (*total_policies > kCurrentPolicyMaxTotalPolicies) {
                        return false;
                    }
                }
                if (total_conditions != nullptr) {
                    *total_conditions += current_policy.condition_count;
                    if (*total_conditions > kCurrentPolicyMaxTotalConditions) {
                        return false;
                    }
                }
            }
        }
    }
    return true;
}

CurrentPolicyDocumentStatus copy_condition(
    const CurrentPolicyCondition& input,
    CurrentPolicyCanonicalDocument* policy,
    CurrentPolicyCanonicalCondition* output)
{
    if (policy == nullptr || output == nullptr || !validate_condition_shape(input)) {
        return CurrentPolicyDocumentStatus::invalid_policy;
    }
    *output = {};
    output->op = input.op;
    output->value_count = input.value_count;
    if (!add_string(policy, input.field, kCurrentPolicyMaxFieldIdLength, &output->field)) {
        return CurrentPolicyDocumentStatus::invalid_policy;
    }
    if (string_present(input.where_type)) {
        output->has_where_type = true;
        if (!add_string(policy, input.where_type, kCurrentPolicyMaxValueLength, &output->where_type)) {
            return CurrentPolicyDocumentStatus::invalid_policy;
        }
    }
    for (size_t index = 0; index < input.value_count; ++index) {
        if (!add_string(policy, input.values[index], kCurrentPolicyMaxValueLength, &output->values[index])) {
            return CurrentPolicyDocumentStatus::invalid_policy;
        }
    }
    return CurrentPolicyDocumentStatus::ok;
}

bool validate_canonical_condition_shape(
    const CurrentPolicyCanonicalDocument& policy,
    const CurrentPolicyCanonicalCondition& condition)
{
    const char* field = get_string(policy, condition.field);
    const CurrentPolicyFieldDescriptor* descriptor =
        current_policy_find_field_descriptor(field);
    if (descriptor == nullptr ||
        !is_known_operator(condition.op) ||
        !current_policy_operator_allowed(*descriptor, condition.op) ||
        condition.value_count == 0 ||
        condition.value_count > kCurrentPolicyMaxConditionValues ||
        (operator_uses_single_value(condition.op) && condition.value_count != 1)) {
        return false;
    }
    for (size_t index = 0; index < condition.value_count; ++index) {
        const char* value = get_string(policy, condition.values[index]);
        if (!current_policy_value_valid(descriptor->value_kind, value)) {
            return false;
        }
    }
    const char* where_type = condition.has_where_type ? get_string(policy, condition.where_type) : nullptr;
    if (!validate_condition_where_type(*descriptor, where_type)) {
        return false;
    }
    return true;
}

bool validate_canonical_shape(const CurrentPolicyCanonicalDocument& policy)
{
    if (policy.default_action != CurrentPolicyAction::reject ||
        policy.blockchain_count > kCurrentPolicyMaxBlockchains ||
        policy.total_network_count > kCurrentPolicyMaxTotalNetworks ||
        policy.total_policy_count > kCurrentPolicyMaxTotalPolicies ||
        policy.total_condition_count > kCurrentPolicyMaxTotalConditions ||
        policy.string_pool_size > sizeof(policy.string_pool)) {
        return false;
    }

    size_t counted_networks = 0;
    size_t counted_policies = 0;
    size_t counted_conditions = 0;
    const char* seen_blockchains[kCurrentPolicyMaxBlockchains] = {};
    for (size_t blockchain_index = 0; blockchain_index < policy.blockchain_count; ++blockchain_index) {
        const CurrentPolicyCanonicalBlockchainScope& blockchain = policy.blockchains[blockchain_index];
        const char* blockchain_name = get_string(policy, blockchain.blockchain);
        if (!current_policy_is_supported_blockchain(blockchain_name) ||
            duplicate_string(blockchain_name, seen_blockchains, blockchain_index) ||
            blockchain.network_count > kCurrentPolicyMaxNetworksPerBlockchain) {
            return false;
        }
        seen_blockchains[blockchain_index] = blockchain_name;

        const char* seen_networks[kCurrentPolicyMaxNetworksPerBlockchain] = {};
        for (size_t network_index = 0; network_index < blockchain.network_count; ++network_index) {
            const CurrentPolicyCanonicalNetworkScope& network = blockchain.networks[network_index];
            const char* network_name = get_string(policy, network.network);
            if (!current_policy_is_supported_network(network_name) ||
                duplicate_string(network_name, seen_networks, network_index) ||
                network.policy_count > kCurrentPolicyMaxPoliciesPerNetwork) {
                return false;
            }
            seen_networks[network_index] = network_name;
            counted_networks += 1;

            const char* seen_policies[kCurrentPolicyMaxPoliciesPerNetwork] = {};
            for (size_t policy_index = 0; policy_index < network.policy_count; ++policy_index) {
                const CurrentPolicyCanonicalPolicy& current_policy = network.policies[policy_index];
                const char* policy_id = get_string(policy, current_policy.id);
                if (!current_policy_is_safe_policy_id(policy_id) ||
                    duplicate_string(policy_id, seen_policies, policy_index) ||
                    !is_known_action(current_policy.action) ||
                    current_policy.condition_count > kCurrentPolicyMaxConditionsPerPolicy ||
                    (current_policy.action == CurrentPolicyAction::sign &&
                     current_policy.condition_count == 0)) {
                    return false;
                }
                seen_policies[policy_index] = policy_id;
                counted_policies += 1;
                counted_conditions += current_policy.condition_count;
                if (counted_networks > kCurrentPolicyMaxTotalNetworks ||
                    counted_policies > kCurrentPolicyMaxTotalPolicies ||
                    counted_conditions > kCurrentPolicyMaxTotalConditions) {
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

const CurrentPolicyFieldDescriptor kCurrentPolicyFieldDescriptors[] = {
    {"sui.gas_budget_raw", CurrentPolicyValueKind::u64_decimal, CurrentPolicyWhereTypeRequirement::forbidden, CurrentPolicyEvaluationKind::sui_gas_budget_raw, true, false, false, true, false, false, false, false},
    {"sui.gas_price_raw", CurrentPolicyValueKind::u64_decimal, CurrentPolicyWhereTypeRequirement::forbidden, CurrentPolicyEvaluationKind::sui_gas_price_raw, true, false, false, true, false, false, false, false},
    {"sui.gas_owner", CurrentPolicyValueKind::string, CurrentPolicyWhereTypeRequirement::forbidden, CurrentPolicyEvaluationKind::sui_gas_owner, true, true, true, false, false, false, false, false},
    {"sui.sponsored", CurrentPolicyValueKind::bool_string, CurrentPolicyWhereTypeRequirement::forbidden, CurrentPolicyEvaluationKind::sui_sponsored, true, false, false, false, false, false, false, false},
    {"sui.command_count", CurrentPolicyValueKind::u64_decimal, CurrentPolicyWhereTypeRequirement::forbidden, CurrentPolicyEvaluationKind::sui_command_count, true, false, false, true, false, false, false, false},
    {"sui.command_kinds", CurrentPolicyValueKind::string, CurrentPolicyWhereTypeRequirement::forbidden, CurrentPolicyEvaluationKind::sui_command_kinds, false, false, false, false, true, true, true, true},
    {"sui.move_call_packages", CurrentPolicyValueKind::string, CurrentPolicyWhereTypeRequirement::forbidden, CurrentPolicyEvaluationKind::sui_move_call_packages, false, false, false, false, true, true, true, true},
    {"sui.move_call_modules", CurrentPolicyValueKind::string, CurrentPolicyWhereTypeRequirement::forbidden, CurrentPolicyEvaluationKind::sui_move_call_modules, false, false, false, false, true, true, true, true},
    {"sui.move_call_functions", CurrentPolicyValueKind::string, CurrentPolicyWhereTypeRequirement::forbidden, CurrentPolicyEvaluationKind::sui_move_call_functions, false, false, false, false, true, true, true, true},
    {"sui.publish_present", CurrentPolicyValueKind::bool_string, CurrentPolicyWhereTypeRequirement::forbidden, CurrentPolicyEvaluationKind::sui_publish_present, true, false, false, false, false, false, false, false},
    {"sui.upgrade_present", CurrentPolicyValueKind::bool_string, CurrentPolicyWhereTypeRequirement::forbidden, CurrentPolicyEvaluationKind::sui_upgrade_present, true, false, false, false, false, false, false, false},
    {"sui.recipient_addresses", CurrentPolicyValueKind::string, CurrentPolicyWhereTypeRequirement::forbidden, CurrentPolicyEvaluationKind::sui_recipient_addresses, false, false, false, false, true, true, true, true},
    {"sui.pure_address_arguments", CurrentPolicyValueKind::string, CurrentPolicyWhereTypeRequirement::forbidden, CurrentPolicyEvaluationKind::sui_pure_address_arguments, false, false, false, false, true, true, false, true},
    {"sui.token_sources.type", CurrentPolicyValueKind::string, CurrentPolicyWhereTypeRequirement::forbidden, CurrentPolicyEvaluationKind::sui_token_sources_type, true, true, true, false, false, false, false, false},
    {"sui.token_sources.source", CurrentPolicyValueKind::string, CurrentPolicyWhereTypeRequirement::forbidden, CurrentPolicyEvaluationKind::sui_token_sources_source, true, true, false, false, false, false, false, false},
    {"sui.token_sources.amount_raw", CurrentPolicyValueKind::u64_decimal, CurrentPolicyWhereTypeRequirement::forbidden, CurrentPolicyEvaluationKind::sui_token_sources_amount_raw, true, false, false, true, false, false, false, false},
    {"sui.token_totals_by_type.amount_raw", CurrentPolicyValueKind::u64_decimal, CurrentPolicyWhereTypeRequirement::required, CurrentPolicyEvaluationKind::sui_token_totals_by_type_amount_raw, true, false, false, true, false, false, false, false},
    {"sui.token_unknown_amount_present", CurrentPolicyValueKind::bool_string, CurrentPolicyWhereTypeRequirement::forbidden, CurrentPolicyEvaluationKind::sui_token_unknown_amount_present, true, false, false, false, false, false, false, false},
};

const size_t kCurrentPolicyFieldDescriptorCount =
    sizeof(kCurrentPolicyFieldDescriptors) / sizeof(kCurrentPolicyFieldDescriptors[0]);

const char* current_policy_action_name(CurrentPolicyAction action)
{
    switch (action) {
        case CurrentPolicyAction::reject:
            return "reject";
        case CurrentPolicyAction::sign:
            return "sign";
    }
    return "";
}

const char* current_policy_operator_name(CurrentPolicyOperator op)
{
    switch (op) {
        case CurrentPolicyOperator::eq:
            return "eq";
        case CurrentPolicyOperator::in:
            return "in";
        case CurrentPolicyOperator::not_in:
            return "not_in";
        case CurrentPolicyOperator::lte:
            return "lte";
        case CurrentPolicyOperator::contains:
            return "contains";
        case CurrentPolicyOperator::not_contains:
            return "not_contains";
        case CurrentPolicyOperator::all_in:
            return "all_in";
        case CurrentPolicyOperator::none_in:
            return "none_in";
    }
    return "";
}

const char* current_policy_document_status_name(CurrentPolicyDocumentStatus status)
{
    switch (status) {
        case CurrentPolicyDocumentStatus::ok:
            return "ok";
        case CurrentPolicyDocumentStatus::invalid_argument:
            return "invalid_argument";
        case CurrentPolicyDocumentStatus::invalid_policy:
            return "invalid_policy";
        case CurrentPolicyDocumentStatus::unsupported_field:
            return "unsupported_field";
        case CurrentPolicyDocumentStatus::output_too_small:
            return "output_too_small";
    }
    return "unknown";
}

bool current_policy_is_supported_blockchain(const char* value)
{
    return string_eq(value, "sui");
}

bool current_policy_is_supported_network(const char* value)
{
    return string_eq(value, "mainnet") ||
           string_eq(value, "testnet") ||
           string_eq(value, "devnet") ||
           string_eq(value, "localnet");
}

bool current_policy_is_safe_identifier(const char* value, size_t max_length)
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

bool current_policy_is_safe_policy_id(const char* value)
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
        if (length > kCurrentPolicyMaxPolicyIdLength) {
            return false;
        }
    }
    return true;
}

const CurrentPolicyFieldDescriptor* current_policy_find_field_descriptor(
    const char* field)
{
    for (size_t index = 0; index < kCurrentPolicyFieldDescriptorCount; ++index) {
        if (string_eq(kCurrentPolicyFieldDescriptors[index].field, field)) {
            return &kCurrentPolicyFieldDescriptors[index];
        }
    }
    return nullptr;
}

bool current_policy_operator_allowed(
    const CurrentPolicyFieldDescriptor& descriptor,
    CurrentPolicyOperator op)
{
    switch (op) {
        case CurrentPolicyOperator::eq:
            return descriptor.allow_eq;
        case CurrentPolicyOperator::in:
            return descriptor.allow_in;
        case CurrentPolicyOperator::not_in:
            return descriptor.allow_not_in;
        case CurrentPolicyOperator::lte:
            return descriptor.allow_lte;
        case CurrentPolicyOperator::contains:
            return descriptor.allow_contains;
        case CurrentPolicyOperator::not_contains:
            return descriptor.allow_not_contains;
        case CurrentPolicyOperator::all_in:
            return descriptor.allow_all_in;
        case CurrentPolicyOperator::none_in:
            return descriptor.allow_none_in;
    }
    return false;
}

bool current_policy_value_valid(
    CurrentPolicyValueKind kind,
    const char* value)
{
    if (!string_present(value) || strlen(value) > kCurrentPolicyMaxValueLength) {
        return false;
    }
    switch (kind) {
        case CurrentPolicyValueKind::string:
            for (const char* cursor = value; *cursor != '\0'; ++cursor) {
                const unsigned char ch = static_cast<unsigned char>(*cursor);
                if (ch < 0x20 || ch > 0x7E) {
                    return false;
                }
            }
            return true;
        case CurrentPolicyValueKind::u64_decimal:
            return policy_is_canonical_decimal_u64_string(value);
        case CurrentPolicyValueKind::bool_string:
            return string_eq(value, "true") || string_eq(value, "false");
    }
    return false;
}

bool current_policy_operator_uses_value_list(CurrentPolicyOperator op)
{
    return !operator_uses_single_value(op);
}

CurrentPolicyDocumentStatus validate_current_policy_document(
    const CurrentPolicyDocument& policy)
{
    size_t total_networks = 0;
    size_t total_policies = 0;
    size_t total_conditions = 0;
    return validate_document_shape(policy, &total_networks, &total_policies, &total_conditions)
               ? CurrentPolicyDocumentStatus::ok
               : CurrentPolicyDocumentStatus::invalid_policy;
}

CurrentPolicyDocumentStatus canonicalize_current_policy_document(
    const CurrentPolicyDocument& policy,
    CurrentPolicyCanonicalDocument* out)
{
    if (out == nullptr) {
        return CurrentPolicyDocumentStatus::invalid_argument;
    }
    memset(out, 0, sizeof(*out));

    size_t total_networks = 0;
    size_t total_policies = 0;
    size_t total_conditions = 0;
    if (!validate_document_shape(policy, &total_networks, &total_policies, &total_conditions)) {
        return CurrentPolicyDocumentStatus::invalid_policy;
    }

    out->default_action = CurrentPolicyAction::reject;
    out->blockchain_count = policy.blockchain_count;
    out->total_network_count = total_networks;
    out->total_policy_count = total_policies;
    out->total_condition_count = total_conditions;

    for (size_t blockchain_index = 0; blockchain_index < policy.blockchain_count; ++blockchain_index) {
        const CurrentPolicyBlockchainScope& input_blockchain = policy.blockchains[blockchain_index];
        CurrentPolicyCanonicalBlockchainScope& output_blockchain = out->blockchains[blockchain_index];
        output_blockchain.network_count = input_blockchain.network_count;
        if (!add_string(out, input_blockchain.blockchain, kCurrentPolicyMaxBlockchainLength, &output_blockchain.blockchain)) {
            memset(out, 0, sizeof(*out));
            return CurrentPolicyDocumentStatus::invalid_policy;
        }
        for (size_t network_index = 0; network_index < input_blockchain.network_count; ++network_index) {
            const CurrentPolicyNetworkScope& input_network = input_blockchain.networks[network_index];
            CurrentPolicyCanonicalNetworkScope& output_network = output_blockchain.networks[network_index];
            output_network.policy_count = input_network.policy_count;
            if (!add_string(out, input_network.network, kCurrentPolicyMaxNetworkLength, &output_network.network)) {
                memset(out, 0, sizeof(*out));
                return CurrentPolicyDocumentStatus::invalid_policy;
            }
            for (size_t policy_index = 0; policy_index < input_network.policy_count; ++policy_index) {
                const CurrentPolicy& input_policy = input_network.policies[policy_index];
                CurrentPolicyCanonicalPolicy& output_policy = output_network.policies[policy_index];
                output_policy.action = input_policy.action;
                output_policy.condition_count = input_policy.condition_count;
                if (!add_string(out, input_policy.id, kCurrentPolicyMaxPolicyIdLength, &output_policy.id)) {
                    memset(out, 0, sizeof(*out));
                    return CurrentPolicyDocumentStatus::invalid_policy;
                }
                for (size_t condition_index = 0; condition_index < input_policy.condition_count; ++condition_index) {
                    const CurrentPolicyDocumentStatus status = copy_condition(
                        input_policy.conditions[condition_index],
                        out,
                        &output_policy.conditions[condition_index]);
                    if (status != CurrentPolicyDocumentStatus::ok) {
                        memset(out, 0, sizeof(*out));
                        return status;
                    }
                }
            }
        }
    }
    return CurrentPolicyDocumentStatus::ok;
}

bool current_policy_canonical_to_runtime_view(
    const CurrentPolicyCanonicalDocument& policy,
    CurrentPolicyRuntimeView* out)
{
    if (out == nullptr || !validate_canonical_shape(policy)) {
        return false;
    }
    memset(out, 0, sizeof(*out));

    size_t network_cursor = 0;
    size_t policy_cursor = 0;
    size_t condition_cursor = 0;
    for (size_t blockchain_index = 0; blockchain_index < policy.blockchain_count; ++blockchain_index) {
        const CurrentPolicyCanonicalBlockchainScope& input_blockchain = policy.blockchains[blockchain_index];
        CurrentPolicyBlockchainScope& output_blockchain = out->blockchains[blockchain_index];
        output_blockchain.blockchain = get_string(policy, input_blockchain.blockchain);
        output_blockchain.network_count = input_blockchain.network_count;
        output_blockchain.networks = input_blockchain.network_count == 0 ? nullptr : &out->networks[network_cursor];
        for (size_t network_index = 0; network_index < input_blockchain.network_count; ++network_index) {
            const CurrentPolicyCanonicalNetworkScope& input_network = input_blockchain.networks[network_index];
            CurrentPolicyNetworkScope& output_network = out->networks[network_cursor++];
            output_network.network = get_string(policy, input_network.network);
            output_network.policy_count = input_network.policy_count;
            output_network.policies = input_network.policy_count == 0 ? nullptr : &out->policies[policy_cursor];
            for (size_t policy_index = 0; policy_index < input_network.policy_count; ++policy_index) {
                const CurrentPolicyCanonicalPolicy& input_policy = input_network.policies[policy_index];
                CurrentPolicy& output_policy = out->policies[policy_cursor++];
                output_policy.id = get_string(policy, input_policy.id);
                output_policy.action = input_policy.action;
                output_policy.condition_count = input_policy.condition_count;
                output_policy.conditions = input_policy.condition_count == 0 ? nullptr : &out->conditions[condition_cursor];
                for (size_t condition_index = 0; condition_index < input_policy.condition_count; ++condition_index) {
                    const CurrentPolicyCanonicalCondition& input_condition = input_policy.conditions[condition_index];
                    CurrentPolicyCondition& output_condition = out->conditions[condition_cursor];
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

    out->document = CurrentPolicyDocument{
        kCurrentPolicySchema,
        policy.default_action,
        policy.blockchain_count == 0 ? nullptr : out->blockchains,
        policy.blockchain_count,
    };
    return true;
}

CurrentPolicyDocumentStatus validate_current_policy_canonical_document(
    const CurrentPolicyCanonicalDocument& policy)
{
    return validate_canonical_shape(policy)
               ? CurrentPolicyDocumentStatus::ok
               : CurrentPolicyDocumentStatus::invalid_policy;
}

CurrentPolicyDocumentStatus encode_current_policy_canonical_record(
    const CurrentPolicyCanonicalDocument& policy,
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size)
{
    if (output_size != nullptr) {
        *output_size = 0;
    }
    if (output == nullptr || output_capacity == 0 || output_size == nullptr) {
        return CurrentPolicyDocumentStatus::invalid_argument;
    }
    memset(output, 0, output_capacity);

    if (!validate_canonical_shape(policy) || policy.blockchain_count > UINT8_MAX) {
        return CurrentPolicyDocumentStatus::invalid_policy;
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
        return CurrentPolicyDocumentStatus::output_too_small;
    }
    for (size_t blockchain_index = 0; blockchain_index < policy.blockchain_count; ++blockchain_index) {
        const CurrentPolicyCanonicalBlockchainScope& blockchain = policy.blockchains[blockchain_index];
        if (blockchain.network_count > UINT8_MAX ||
            !append_string(get_string(policy, blockchain.blockchain), output, output_capacity, &offset) ||
            !append_u8(static_cast<uint8_t>(blockchain.network_count), output, output_capacity, &offset)) {
            return CurrentPolicyDocumentStatus::output_too_small;
        }
        for (size_t network_index = 0; network_index < blockchain.network_count; ++network_index) {
            const CurrentPolicyCanonicalNetworkScope& network = blockchain.networks[network_index];
            if (network.policy_count > UINT8_MAX ||
                !append_string(get_string(policy, network.network), output, output_capacity, &offset) ||
                !append_u8(static_cast<uint8_t>(network.policy_count), output, output_capacity, &offset)) {
                return CurrentPolicyDocumentStatus::output_too_small;
            }
            for (size_t policy_index = 0; policy_index < network.policy_count; ++policy_index) {
                const CurrentPolicyCanonicalPolicy& current_policy = network.policies[policy_index];
                if (current_policy.condition_count > UINT16_MAX ||
                    !append_string(get_string(policy, current_policy.id), output, output_capacity, &offset) ||
                    !append_u8(encode_action(current_policy.action), output, output_capacity, &offset) ||
                    !append_u16(static_cast<uint16_t>(current_policy.condition_count), output, output_capacity, &offset)) {
                    return CurrentPolicyDocumentStatus::output_too_small;
                }
                for (size_t condition_index = 0; condition_index < current_policy.condition_count; ++condition_index) {
                    const CurrentPolicyCanonicalCondition& condition = current_policy.conditions[condition_index];
                    if (condition.value_count > UINT8_MAX ||
                        !append_string(get_string(policy, condition.field), output, output_capacity, &offset) ||
                        !append_u8(condition.has_where_type ? 1 : 0, output, output_capacity, &offset) ||
                        (condition.has_where_type &&
                         !append_string(get_string(policy, condition.where_type), output, output_capacity, &offset)) ||
                        !append_u8(encode_operator(condition.op), output, output_capacity, &offset) ||
                        !append_u8(static_cast<uint8_t>(condition.value_count), output, output_capacity, &offset)) {
                        return CurrentPolicyDocumentStatus::output_too_small;
                    }
                    for (size_t value_index = 0; value_index < condition.value_count; ++value_index) {
                        if (!append_string(get_string(policy, condition.values[value_index]), output, output_capacity, &offset)) {
                            return CurrentPolicyDocumentStatus::output_too_small;
                        }
                    }
                }
            }
        }
    }
    *output_size = offset;
    return CurrentPolicyDocumentStatus::ok;
}

CurrentPolicyDocumentStatus encode_current_policy_default_record(
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size)
{
    if (output_size != nullptr) {
        *output_size = 0;
    }
    if (output == nullptr || output_capacity == 0 || output_size == nullptr) {
        return CurrentPolicyDocumentStatus::invalid_argument;
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
        return CurrentPolicyDocumentStatus::output_too_small;
    }
    *output_size = offset;
    return CurrentPolicyDocumentStatus::ok;
}

CurrentPolicyDocumentStatus decode_current_policy_canonical_record(
    const uint8_t* record,
    size_t record_size,
    CurrentPolicyCanonicalDocument* out)
{
    if (out == nullptr) {
        return CurrentPolicyDocumentStatus::invalid_argument;
    }
    memset(out, 0, sizeof(*out));
    if (record == nullptr || record_size < sizeof(StoredPolicyHeader)) {
        return CurrentPolicyDocumentStatus::invalid_argument;
    }

    StoredPolicyHeader header = {};
    memcpy(&header, record, sizeof(header));
    if (memcmp(header.magic, "AQPD", sizeof(header.magic)) != 0 ||
        header.format_version != kStoredPolicyFormatVersion ||
        header.blockchain_count > kCurrentPolicyMaxBlockchains) {
        return CurrentPolicyDocumentStatus::invalid_policy;
    }
    for (size_t index = 0; index < sizeof(header.reserved); ++index) {
        if (header.reserved[index] != 0) {
            return CurrentPolicyDocumentStatus::invalid_policy;
        }
    }
    if (!decode_action(header.default_action, &out->default_action) ||
        out->default_action != CurrentPolicyAction::reject) {
        memset(out, 0, sizeof(*out));
        return CurrentPolicyDocumentStatus::invalid_policy;
    }

    out->blockchain_count = header.blockchain_count;
    size_t offset = sizeof(header);
    for (size_t blockchain_index = 0; blockchain_index < out->blockchain_count; ++blockchain_index) {
        CurrentPolicyCanonicalBlockchainScope& blockchain = out->blockchains[blockchain_index];
        uint8_t network_count = 0;
        if (!read_string(record, record_size, &offset, out, kCurrentPolicyMaxBlockchainLength, &blockchain.blockchain) ||
            !read_u8(record, record_size, &offset, &network_count) ||
            network_count > kCurrentPolicyMaxNetworksPerBlockchain) {
            memset(out, 0, sizeof(*out));
            return CurrentPolicyDocumentStatus::invalid_policy;
        }
        blockchain.network_count = network_count;
        out->total_network_count += network_count;
        if (out->total_network_count > kCurrentPolicyMaxTotalNetworks) {
            memset(out, 0, sizeof(*out));
            return CurrentPolicyDocumentStatus::invalid_policy;
        }
        for (size_t network_index = 0; network_index < blockchain.network_count; ++network_index) {
            CurrentPolicyCanonicalNetworkScope& network = blockchain.networks[network_index];
            uint8_t policy_count = 0;
            if (!read_string(record, record_size, &offset, out, kCurrentPolicyMaxNetworkLength, &network.network) ||
                !read_u8(record, record_size, &offset, &policy_count) ||
                policy_count > kCurrentPolicyMaxPoliciesPerNetwork) {
                memset(out, 0, sizeof(*out));
                return CurrentPolicyDocumentStatus::invalid_policy;
            }
            network.policy_count = policy_count;
            out->total_policy_count += policy_count;
            if (out->total_policy_count > kCurrentPolicyMaxTotalPolicies) {
                memset(out, 0, sizeof(*out));
                return CurrentPolicyDocumentStatus::invalid_policy;
            }
            for (size_t policy_index = 0; policy_index < network.policy_count; ++policy_index) {
                CurrentPolicyCanonicalPolicy& current_policy = network.policies[policy_index];
                uint8_t action = 0;
                uint16_t condition_count = 0;
                if (!read_string(record, record_size, &offset, out, kCurrentPolicyMaxPolicyIdLength, &current_policy.id) ||
                    !read_u8(record, record_size, &offset, &action) ||
                    !decode_action(action, &current_policy.action) ||
                    !read_u16(record, record_size, &offset, &condition_count) ||
                    condition_count > kCurrentPolicyMaxConditionsPerPolicy) {
                    memset(out, 0, sizeof(*out));
                    return CurrentPolicyDocumentStatus::invalid_policy;
                }
                current_policy.condition_count = condition_count;
                out->total_condition_count += condition_count;
                if (out->total_condition_count > kCurrentPolicyMaxTotalConditions) {
                    memset(out, 0, sizeof(*out));
                    return CurrentPolicyDocumentStatus::invalid_policy;
                }
                for (size_t condition_index = 0; condition_index < current_policy.condition_count; ++condition_index) {
                    CurrentPolicyCanonicalCondition& condition = current_policy.conditions[condition_index];
                    uint8_t has_where_type = 0;
                    uint8_t op = 0;
                    uint8_t value_count = 0;
                    if (!read_string(record, record_size, &offset, out, kCurrentPolicyMaxFieldIdLength, &condition.field) ||
                        !read_u8(record, record_size, &offset, &has_where_type) ||
                        has_where_type > 1 ||
                        (has_where_type == 1 &&
                         !read_string(record, record_size, &offset, out, kCurrentPolicyMaxValueLength, &condition.where_type)) ||
                        !read_u8(record, record_size, &offset, &op) ||
                        !decode_operator(op, &condition.op) ||
                        !read_u8(record, record_size, &offset, &value_count) ||
                        value_count == 0 ||
                        value_count > kCurrentPolicyMaxConditionValues) {
                        memset(out, 0, sizeof(*out));
                        return CurrentPolicyDocumentStatus::invalid_policy;
                    }
                    condition.has_where_type = has_where_type == 1;
                    condition.value_count = value_count;
                    for (size_t value_index = 0; value_index < condition.value_count; ++value_index) {
                        if (!read_string(record, record_size, &offset, out, kCurrentPolicyMaxValueLength, &condition.values[value_index])) {
                            memset(out, 0, sizeof(*out));
                            return CurrentPolicyDocumentStatus::invalid_policy;
                        }
                    }
                }
            }
        }
    }

    if (offset != record_size || !validate_canonical_shape(*out)) {
        memset(out, 0, sizeof(*out));
        return CurrentPolicyDocumentStatus::invalid_policy;
    }
    return CurrentPolicyDocumentStatus::ok;
}

}  // namespace signing
