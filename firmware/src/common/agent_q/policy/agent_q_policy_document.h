#pragma once

#include <stddef.h>
#include <stdint.h>

namespace agent_q {

constexpr const char* kAgentQCurrentPolicySchema = "agentq.policy";

constexpr size_t kAgentQCurrentPolicyMaxBlockchains = 4;
constexpr size_t kAgentQCurrentPolicyMaxNetworksPerBlockchain = 8;
constexpr size_t kAgentQCurrentPolicyMaxPoliciesPerNetwork = 16;
constexpr size_t kAgentQCurrentPolicyMaxConditionsPerPolicy = 64;
constexpr size_t kAgentQCurrentPolicyMaxConditionValues = 16;
constexpr size_t kAgentQCurrentPolicyMaxTotalNetworks = 16;
constexpr size_t kAgentQCurrentPolicyMaxTotalPolicies = 64;
constexpr size_t kAgentQCurrentPolicyMaxTotalConditions = 256;
constexpr size_t kAgentQCurrentPolicyMaxPolicyIdLength = 32;
constexpr size_t kAgentQCurrentPolicyMaxBlockchainLength = 32;
constexpr size_t kAgentQCurrentPolicyMaxNetworkLength = 32;
constexpr size_t kAgentQCurrentPolicyMaxFieldIdLength = 64;
constexpr size_t kAgentQCurrentPolicyMaxValueLength = 255;
constexpr size_t kAgentQCurrentPolicyDefaultCanonicalRecordBytes = 16;
constexpr size_t kAgentQCurrentPolicyMaxCanonicalRecordBytes = 16384;
constexpr size_t kAgentQCurrentPolicyCanonicalStringPoolBytes = 16384;

enum class AgentQCurrentPolicyAction {
    reject,
    sign,
};

enum class AgentQCurrentPolicyOperator {
    eq,
    in,
    not_in,
    lte,
    contains,
    not_contains,
    all_in,
    none_in,
};

enum class AgentQCurrentPolicyValueKind {
    string,
    u64_decimal,
    bool_string,
};

enum class AgentQCurrentPolicyDocumentStatus {
    ok,
    invalid_argument,
    invalid_policy,
    unsupported_field,
    output_too_small,
};

struct AgentQCurrentPolicyFieldDescriptor {
    const char* field;
    AgentQCurrentPolicyValueKind value_kind;
    bool allow_eq;
    bool allow_in;
    bool allow_not_in;
    bool allow_lte;
    bool allow_contains;
    bool allow_not_contains;
    bool allow_all_in;
    bool allow_none_in;
};

struct AgentQCurrentPolicyCondition {
    const char* field;
    AgentQCurrentPolicyOperator op;
    const char* const* values;
    size_t value_count;
    const char* where_type;
};

struct AgentQCurrentPolicy {
    const char* id;
    AgentQCurrentPolicyAction action;
    const AgentQCurrentPolicyCondition* conditions;
    size_t condition_count;
};

struct AgentQCurrentPolicyNetworkScope {
    const char* network;
    const AgentQCurrentPolicy* policies;
    size_t policy_count;
};

struct AgentQCurrentPolicyBlockchainScope {
    const char* blockchain;
    const AgentQCurrentPolicyNetworkScope* networks;
    size_t network_count;
};

struct AgentQCurrentPolicyDocument {
    const char* schema;
    AgentQCurrentPolicyAction default_action;
    const AgentQCurrentPolicyBlockchainScope* blockchains;
    size_t blockchain_count;
};

struct AgentQCurrentPolicyCanonicalString {
    uint16_t offset;
    uint16_t length;
};

struct AgentQCurrentPolicyCanonicalCondition {
    AgentQCurrentPolicyCanonicalString field;
    bool has_where_type;
    AgentQCurrentPolicyCanonicalString where_type;
    AgentQCurrentPolicyOperator op;
    AgentQCurrentPolicyCanonicalString values[kAgentQCurrentPolicyMaxConditionValues];
    size_t value_count;
};

struct AgentQCurrentPolicyCanonicalPolicy {
    AgentQCurrentPolicyCanonicalString id;
    AgentQCurrentPolicyAction action;
    AgentQCurrentPolicyCanonicalCondition conditions[kAgentQCurrentPolicyMaxConditionsPerPolicy];
    size_t condition_count;
};

struct AgentQCurrentPolicyCanonicalNetworkScope {
    AgentQCurrentPolicyCanonicalString network;
    AgentQCurrentPolicyCanonicalPolicy policies[kAgentQCurrentPolicyMaxPoliciesPerNetwork];
    size_t policy_count;
};

struct AgentQCurrentPolicyCanonicalBlockchainScope {
    AgentQCurrentPolicyCanonicalString blockchain;
    AgentQCurrentPolicyCanonicalNetworkScope networks[kAgentQCurrentPolicyMaxNetworksPerBlockchain];
    size_t network_count;
};

struct AgentQCurrentPolicyCanonicalDocument {
    AgentQCurrentPolicyAction default_action;
    AgentQCurrentPolicyCanonicalBlockchainScope blockchains[kAgentQCurrentPolicyMaxBlockchains];
    size_t blockchain_count;
    size_t total_network_count;
    size_t total_policy_count;
    size_t total_condition_count;
    char string_pool[kAgentQCurrentPolicyCanonicalStringPoolBytes];
    size_t string_pool_size;
};

struct AgentQCurrentPolicyRuntimeView {
    AgentQCurrentPolicyCondition conditions[kAgentQCurrentPolicyMaxTotalConditions];
    const char* values[kAgentQCurrentPolicyMaxTotalConditions][kAgentQCurrentPolicyMaxConditionValues];
    AgentQCurrentPolicy policies[kAgentQCurrentPolicyMaxTotalPolicies];
    AgentQCurrentPolicyNetworkScope networks[kAgentQCurrentPolicyMaxTotalNetworks];
    AgentQCurrentPolicyBlockchainScope blockchains[kAgentQCurrentPolicyMaxBlockchains];
    AgentQCurrentPolicyDocument document;
};

extern const AgentQCurrentPolicyFieldDescriptor kAgentQCurrentPolicyFieldDescriptors[];
extern const size_t kAgentQCurrentPolicyFieldDescriptorCount;

const char* agent_q_current_policy_action_name(AgentQCurrentPolicyAction action);
const char* agent_q_current_policy_operator_name(AgentQCurrentPolicyOperator op);
const char* agent_q_current_policy_document_status_name(AgentQCurrentPolicyDocumentStatus status);

bool agent_q_current_policy_is_supported_blockchain(const char* value);
bool agent_q_current_policy_is_supported_network(const char* value);
bool agent_q_current_policy_is_safe_identifier(const char* value, size_t max_length);
bool agent_q_current_policy_is_safe_policy_id(const char* value);
const AgentQCurrentPolicyFieldDescriptor* agent_q_current_policy_find_field_descriptor(
    const char* field);
bool agent_q_current_policy_operator_allowed(
    const AgentQCurrentPolicyFieldDescriptor& descriptor,
    AgentQCurrentPolicyOperator op);
bool agent_q_current_policy_value_valid(
    AgentQCurrentPolicyValueKind kind,
    const char* value);
bool agent_q_current_policy_operator_uses_value_list(AgentQCurrentPolicyOperator op);

AgentQCurrentPolicyDocumentStatus validate_agent_q_current_policy_document(
    const AgentQCurrentPolicyDocument& policy);

AgentQCurrentPolicyDocumentStatus canonicalize_agent_q_current_policy_document(
    const AgentQCurrentPolicyDocument& policy,
    AgentQCurrentPolicyCanonicalDocument* out);

bool agent_q_current_policy_canonical_to_runtime_view(
    const AgentQCurrentPolicyCanonicalDocument& policy,
    AgentQCurrentPolicyRuntimeView* out);

AgentQCurrentPolicyDocumentStatus validate_agent_q_current_policy_canonical_document(
    const AgentQCurrentPolicyCanonicalDocument& policy);

AgentQCurrentPolicyDocumentStatus encode_agent_q_current_policy_canonical_record(
    const AgentQCurrentPolicyCanonicalDocument& policy,
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size);

AgentQCurrentPolicyDocumentStatus encode_agent_q_current_policy_default_record(
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size);

AgentQCurrentPolicyDocumentStatus decode_agent_q_current_policy_canonical_record(
    const uint8_t* record,
    size_t record_size,
    AgentQCurrentPolicyCanonicalDocument* out);

}  // namespace agent_q
