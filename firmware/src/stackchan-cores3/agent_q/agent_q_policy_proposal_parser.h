#pragma once

#include <ArduinoJson.h>

#include "agent_q_common/policy/agent_q_policy_document.h"

namespace agent_q {

constexpr size_t kAgentQPolicyProposalMaxSerializedObjectBytes =
    kAgentQCurrentPolicyMaxCanonicalRecordBytes;

enum class AgentQPolicyProposalParseStatus {
    ok,
    invalid_argument,
    too_large,
    invalid_policy,
    unsupported_field,
};

struct AgentQParsedPolicyProposal {
    AgentQCurrentPolicyCondition conditions[kAgentQCurrentPolicyMaxTotalConditions];
    const char* values[kAgentQCurrentPolicyMaxTotalConditions][kAgentQCurrentPolicyMaxConditionValues];
    AgentQCurrentPolicy policies[kAgentQCurrentPolicyMaxTotalPolicies];
    AgentQCurrentPolicyNetworkScope networks[kAgentQCurrentPolicyMaxTotalNetworks];
    AgentQCurrentPolicyBlockchainScope blockchains[kAgentQCurrentPolicyMaxBlockchains];
    AgentQCurrentPolicyDocument document;
    char string_pool[kAgentQCurrentPolicyCanonicalStringPoolBytes];
    size_t string_pool_size;
    size_t condition_count;
    size_t policy_count;
    size_t network_count;
};

AgentQPolicyProposalParseStatus parse_agent_q_policy_proposal(
    JsonVariantConst policy,
    AgentQParsedPolicyProposal* out);

const char* agent_q_policy_proposal_parse_status_name(
    AgentQPolicyProposalParseStatus status);

}  // namespace agent_q
