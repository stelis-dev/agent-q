#pragma once

#include "agent_q_policy_v0.h"

namespace agent_q {

struct AgentQPolicyProvider {
    bool (*load)(AgentQPolicyDocument* out, void* context);
    void* context;
};

AgentQPolicyDecision evaluate_agent_q_policy_runtime(
    const AgentQPolicyProvider& provider,
    const AgentQPolicyFacts& facts);

}  // namespace agent_q
