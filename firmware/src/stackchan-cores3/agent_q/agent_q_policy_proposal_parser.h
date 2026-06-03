#pragma once

#include <ArduinoJson.h>

#include "agent_q_common/policy/agent_q_policy_schema.h"

namespace agent_q {

constexpr const char* kAgentQPolicyProposalSchema = "agentq.policy.v0";
constexpr size_t kAgentQPolicyProposalMaxSerializedObjectBytes =
    kAgentQPolicyMaxCanonicalRecordBytes;

enum class AgentQPolicyProposalParseStatus {
    ok,
    invalid_argument,
    too_large,
    invalid_policy,
    unsupported_method,
    unsupported_field,
};

struct AgentQParsedPolicyProposal {
    // Large caller-owned parse workspace. Firmware runtime code must keep this
    // in static or module-owned storage, not on the USB request task stack.
    AgentQPolicyCriterion criteria[kAgentQPolicyMaxRules][kAgentQPolicyMaxRuleCriteria];
    const char* values[kAgentQPolicyMaxRules][kAgentQPolicyMaxRuleCriteria][kAgentQPolicyMaxCriterionValues];
    AgentQPolicyRule rules[kAgentQPolicyMaxRules];
    AgentQPolicyDocument document;
    char string_pool[kAgentQPolicyCanonicalStringPoolBytes];
    size_t string_pool_size;
};

AgentQPolicyProposalParseStatus parse_agent_q_policy_proposal(
    JsonVariantConst policy,
    const AgentQPolicyMethodDescriptor* method_descriptors,
    size_t method_descriptor_count,
    AgentQParsedPolicyProposal* out);

const char* agent_q_policy_proposal_parse_status_name(
    AgentQPolicyProposalParseStatus status);

}  // namespace agent_q
