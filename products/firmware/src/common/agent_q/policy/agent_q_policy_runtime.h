#pragma once

#include "agent_q_policy_v0.h"

namespace agent_q {

struct AgentQPolicyProvider {
    bool (*load)(AgentQPolicyDocument* out, void* context);
    void* context;
};

AgentQPolicyProvider agent_q_default_reject_policy_provider();

bool load_agent_q_default_reject_policy(AgentQPolicyDocument* out, void* context);

AgentQPolicyDecision evaluate_agent_q_policy_runtime(
    const AgentQPolicyProvider& provider,
    const AgentQPolicyFacts& facts);

}  // namespace agent_q
