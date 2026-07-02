#pragma once

#include <stddef.h>
#include <stdint.h>

namespace signing {

constexpr const char* kCurrentPolicySchema = "signing.policy";

constexpr size_t kCurrentPolicyMaxBlockchains = 4;
constexpr size_t kCurrentPolicyMaxNetworksPerBlockchain = 8;
constexpr size_t kCurrentPolicyMaxPoliciesPerNetwork = 16;
constexpr size_t kCurrentPolicyMaxConditionsPerPolicy = 64;
constexpr size_t kCurrentPolicyMaxConditionValues = 16;
constexpr size_t kCurrentPolicyMaxTotalNetworks = 16;
constexpr size_t kCurrentPolicyMaxTotalPolicies = 64;
constexpr size_t kCurrentPolicyMaxTotalConditions = 256;
constexpr size_t kCurrentPolicyMaxPolicyIdLength = 32;
constexpr size_t kCurrentPolicyMaxBlockchainLength = 32;
constexpr size_t kCurrentPolicyMaxNetworkLength = 32;
constexpr size_t kCurrentPolicyMaxFieldIdLength = 64;
constexpr size_t kCurrentPolicyMaxValueLength = 255;
constexpr size_t kCurrentPolicyDefaultCanonicalRecordBytes = 16;
constexpr size_t kCurrentPolicyMaxCanonicalRecordBytes = 16384;
constexpr size_t kCurrentPolicyCanonicalStringPoolBytes = 16384;

enum class CurrentPolicyAction {
    reject,
    sign,
};

enum class CurrentPolicyOperator {
    eq,
    in,
    not_in,
    lte,
    contains,
    not_contains,
    all_in,
    none_in,
};

enum class CurrentPolicyValueKind {
    string,
    u64_decimal,
    bool_string,
};

enum class CurrentPolicyWhereTypeRequirement {
    forbidden,
    required,
};

enum class CurrentPolicyEvaluationKind {
    sui_gas_budget_raw,
    sui_gas_price_raw,
    sui_gas_owner,
    sui_sponsored,
    sui_command_count,
    sui_command_kinds,
    sui_move_call_packages,
    sui_move_call_modules,
    sui_move_call_functions,
    sui_publish_present,
    sui_upgrade_present,
    sui_recipient_addresses,
    sui_pure_address_arguments,
    sui_token_sources_type,
    sui_token_sources_source,
    sui_token_sources_amount_raw,
    sui_token_totals_by_type_amount_raw,
    sui_token_unknown_amount_present,
};

enum class CurrentPolicyDocumentStatus {
    ok,
    invalid_argument,
    invalid_policy,
    unsupported_field,
    output_too_small,
};

struct CurrentPolicyFieldDescriptor {
    const char* field;
    CurrentPolicyValueKind value_kind;
    CurrentPolicyWhereTypeRequirement where_type_requirement;
    CurrentPolicyEvaluationKind evaluation_kind;
    bool allow_eq;
    bool allow_in;
    bool allow_not_in;
    bool allow_lte;
    bool allow_contains;
    bool allow_not_contains;
    bool allow_all_in;
    bool allow_none_in;
};

struct CurrentPolicyCondition {
    const char* field;
    CurrentPolicyOperator op;
    const char* const* values;
    size_t value_count;
    const char* where_type;
};

struct CurrentPolicy {
    const char* id;
    CurrentPolicyAction action;
    const CurrentPolicyCondition* conditions;
    size_t condition_count;
};

struct CurrentPolicyNetworkScope {
    const char* network;
    const CurrentPolicy* policies;
    size_t policy_count;
};

struct CurrentPolicyBlockchainScope {
    const char* blockchain;
    const CurrentPolicyNetworkScope* networks;
    size_t network_count;
};

struct CurrentPolicyDocument {
    const char* schema;
    CurrentPolicyAction default_action;
    const CurrentPolicyBlockchainScope* blockchains;
    size_t blockchain_count;
};

struct CurrentPolicyCanonicalString {
    uint16_t offset;
    uint16_t length;
};

struct CurrentPolicyCanonicalCondition {
    CurrentPolicyCanonicalString field;
    bool has_where_type;
    CurrentPolicyCanonicalString where_type;
    CurrentPolicyOperator op;
    CurrentPolicyCanonicalString values[kCurrentPolicyMaxConditionValues];
    size_t value_count;
};

struct CurrentPolicyCanonicalPolicy {
    CurrentPolicyCanonicalString id;
    CurrentPolicyAction action;
    CurrentPolicyCanonicalCondition conditions[kCurrentPolicyMaxConditionsPerPolicy];
    size_t condition_count;
};

struct CurrentPolicyCanonicalNetworkScope {
    CurrentPolicyCanonicalString network;
    CurrentPolicyCanonicalPolicy policies[kCurrentPolicyMaxPoliciesPerNetwork];
    size_t policy_count;
};

struct CurrentPolicyCanonicalBlockchainScope {
    CurrentPolicyCanonicalString blockchain;
    CurrentPolicyCanonicalNetworkScope networks[kCurrentPolicyMaxNetworksPerBlockchain];
    size_t network_count;
};

struct CurrentPolicyCanonicalDocument {
    CurrentPolicyAction default_action;
    CurrentPolicyCanonicalBlockchainScope blockchains[kCurrentPolicyMaxBlockchains];
    size_t blockchain_count;
    size_t total_network_count;
    size_t total_policy_count;
    size_t total_condition_count;
    char string_pool[kCurrentPolicyCanonicalStringPoolBytes];
    size_t string_pool_size;
};

struct CurrentPolicyRuntimeView {
    CurrentPolicyCondition conditions[kCurrentPolicyMaxTotalConditions];
    const char* values[kCurrentPolicyMaxTotalConditions][kCurrentPolicyMaxConditionValues];
    CurrentPolicy policies[kCurrentPolicyMaxTotalPolicies];
    CurrentPolicyNetworkScope networks[kCurrentPolicyMaxTotalNetworks];
    CurrentPolicyBlockchainScope blockchains[kCurrentPolicyMaxBlockchains];
    CurrentPolicyDocument document;
};

extern const CurrentPolicyFieldDescriptor kCurrentPolicyFieldDescriptors[];
extern const size_t kCurrentPolicyFieldDescriptorCount;

const char* current_policy_action_name(CurrentPolicyAction action);
const char* current_policy_operator_name(CurrentPolicyOperator op);
const char* current_policy_document_status_name(CurrentPolicyDocumentStatus status);

bool current_policy_is_supported_blockchain(const char* value);
bool current_policy_is_supported_network(const char* value);
bool current_policy_is_safe_identifier(const char* value, size_t max_length);
bool current_policy_is_safe_policy_id(const char* value);
const CurrentPolicyFieldDescriptor* current_policy_find_field_descriptor(
    const char* field);
bool current_policy_operator_allowed(
    const CurrentPolicyFieldDescriptor& descriptor,
    CurrentPolicyOperator op);
bool current_policy_value_valid(
    CurrentPolicyValueKind kind,
    const char* value);
bool current_policy_operator_uses_value_list(CurrentPolicyOperator op);

CurrentPolicyDocumentStatus validate_current_policy_document(
    const CurrentPolicyDocument& policy);

CurrentPolicyDocumentStatus canonicalize_current_policy_document(
    const CurrentPolicyDocument& policy,
    CurrentPolicyCanonicalDocument* out);

bool current_policy_canonical_to_runtime_view(
    const CurrentPolicyCanonicalDocument& policy,
    CurrentPolicyRuntimeView* out);

CurrentPolicyDocumentStatus validate_current_policy_canonical_document(
    const CurrentPolicyCanonicalDocument& policy);

CurrentPolicyDocumentStatus encode_current_policy_canonical_record(
    const CurrentPolicyCanonicalDocument& policy,
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size);

CurrentPolicyDocumentStatus encode_current_policy_default_record(
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size);

CurrentPolicyDocumentStatus decode_current_policy_canonical_record(
    const uint8_t* record,
    size_t record_size,
    CurrentPolicyCanonicalDocument* out);

}  // namespace signing
