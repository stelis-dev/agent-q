#pragma once

#include <stddef.h>

#include "agent_q_policy_v0.h"

namespace agent_q {

constexpr size_t kAgentQPolicyMaxRules = 16;
constexpr size_t kAgentQPolicyMaxRuleCriteria = 96;
constexpr size_t kAgentQPolicyMaxCriterionValues = 16;
constexpr size_t kAgentQPolicyMaxFacts = 96;
constexpr size_t kAgentQPolicyMaxFieldDescriptors = 96;
constexpr size_t kAgentQPolicyMaxFieldIdLength = 48;
constexpr size_t kAgentQPolicyMaxRuleIdLength = 32;
constexpr size_t kAgentQPolicyMaxChainIdLength = 32;
constexpr size_t kAgentQPolicyMaxOperationLength = 64;
constexpr size_t kAgentQPolicyMaxValueLength = 256;
constexpr size_t kAgentQPolicyDefaultCanonicalRecordBytes = 16;
constexpr size_t kAgentQPolicyMaxCanonicalRecordBytes = 16384;
constexpr size_t kAgentQPolicyCanonicalStringPoolBytes = 16384;
constexpr size_t kAgentQPolicyCommonFieldDescriptorCount = 3;
constexpr size_t kAgentQPolicyMaxMethodDescriptors = 16;

extern const AgentQPolicyFieldDescriptor
    kAgentQPolicyCommonFieldDescriptors[kAgentQPolicyCommonFieldDescriptorCount];

using AgentQPolicySignRuleValidator = bool (*)(const AgentQPolicyRule& rule);

struct AgentQPolicyMethodDescriptor {
    const char* chain;
    const char* operation;
    const AgentQPolicyFieldDescriptor* field_descriptors;
    size_t field_descriptor_count;
    bool supports_reject;
    bool supports_sign;
    AgentQPolicySignRuleValidator sign_rule_validator;
};

bool agent_q_policy_is_known_action(AgentQPolicyAction action);
bool agent_q_policy_is_known_operator(AgentQPolicyOperator op);
bool agent_q_policy_is_identifier_string(const char* value, size_t max_length);
bool agent_q_policy_is_rule_id_string(const char* value);
bool agent_q_policy_is_safe_field_id(const char* value);
bool agent_q_policy_operator_allowed(
    const AgentQPolicyFieldDescriptor& descriptor,
    AgentQPolicyOperator op);

const AgentQPolicyFieldDescriptor* agent_q_policy_find_common_field_descriptor(
    const char* field);

bool agent_q_policy_validate_adapter_field_descriptor(
    const AgentQPolicyFieldDescriptor& descriptor);
bool agent_q_policy_validate_adapter_field_descriptors(
    const AgentQPolicyFieldDescriptor* descriptors,
    size_t descriptor_count);
bool agent_q_policy_validate_method_descriptor(
    const AgentQPolicyMethodDescriptor& descriptor);
bool agent_q_policy_validate_method_descriptors(
    const AgentQPolicyMethodDescriptor* descriptors,
    size_t descriptor_count);
bool agent_q_policy_method_sign_rule_is_bounded(
    const AgentQPolicyMethodDescriptor& descriptor,
    const AgentQPolicyRule& rule);
bool agent_q_policy_sign_rule_is_bounded(const AgentQPolicyRule& rule);
bool agent_q_policy_sign_rule_count_is_supported(const AgentQPolicyDocument& policy);

}  // namespace agent_q
