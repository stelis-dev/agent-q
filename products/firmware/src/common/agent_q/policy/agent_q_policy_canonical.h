#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_policy_schema.h"

namespace agent_q {

enum class AgentQPolicyCanonicalStatus {
    ok,
    invalid_argument,
    invalid_policy,
    unsupported_method,
    unsupported_action,
    unsupported_field,
    output_too_small,
};

struct AgentQPolicyCanonicalString {
    uint16_t offset;
    uint16_t length;
};

struct AgentQPolicyCanonicalCriterion {
    AgentQPolicyCanonicalString field;
    AgentQPolicyOperator op;
    AgentQPolicyCanonicalString value;
    AgentQPolicyCanonicalString values[kAgentQPolicyMaxCriterionValues];
    size_t value_count;
};

struct AgentQPolicyCanonicalRule {
    AgentQPolicyCanonicalString id;
    AgentQPolicyCanonicalString chain;
    AgentQPolicyCanonicalString operation;
    AgentQPolicyAction action;
    AgentQPolicyCanonicalCriterion criteria[kAgentQPolicyMaxRuleCriteria];
    size_t criterion_count;
};

struct AgentQPolicyCanonicalDocument {
    uint32_t schema;
    AgentQPolicyAction default_action;
    AgentQPolicyCanonicalRule rules[kAgentQPolicyMaxRules];
    size_t rule_count;
    char string_pool[kAgentQPolicyCanonicalStringPoolBytes];
    size_t string_pool_size;
};

struct AgentQPolicyRuntimeView {
    AgentQPolicyCriterion criteria[kAgentQPolicyMaxRules][kAgentQPolicyMaxRuleCriteria];
    const char* values[kAgentQPolicyMaxRules][kAgentQPolicyMaxRuleCriteria][kAgentQPolicyMaxCriterionValues];
    AgentQPolicyRule rules[kAgentQPolicyMaxRules];
    AgentQPolicyDocument document;
};

AgentQPolicyCanonicalStatus canonicalize_agent_q_policy_v0(
    const AgentQPolicyDocument& policy,
    const AgentQPolicyMethodDescriptor* method_descriptors,
    size_t method_descriptor_count,
    AgentQPolicyCanonicalDocument* out);

bool agent_q_policy_canonical_to_runtime_view(
    const AgentQPolicyCanonicalDocument& policy,
    AgentQPolicyRuntimeView* out);

AgentQPolicyCanonicalStatus encode_agent_q_policy_v0_canonical_record(
    const AgentQPolicyCanonicalDocument& policy,
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size);

AgentQPolicyCanonicalStatus encode_agent_q_policy_v0_default_record(
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size);

const char* agent_q_policy_canonical_status_name(AgentQPolicyCanonicalStatus status);

}  // namespace agent_q
