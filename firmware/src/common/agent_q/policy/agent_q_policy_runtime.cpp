#include "agent_q_policy_runtime.h"

namespace agent_q {
namespace {

AgentQPolicyDecision reject_invalid_policy()
{
    return AgentQPolicyDecision{
        AgentQPolicyAction::reject,
        nullptr,
        AgentQPolicyDecisionReason::invalid_policy,
    };
}

}  // namespace

static bool load_agent_q_default_reject_policy(AgentQPolicyDocument* out, void* context);

AgentQPolicyProvider agent_q_default_reject_policy_provider()
{
    return AgentQPolicyProvider{load_agent_q_default_reject_policy, nullptr};
}

static bool load_agent_q_default_reject_policy(AgentQPolicyDocument* out, void* context)
{
    (void)context;
    if (out == nullptr) {
        return false;
    }
    *out = AgentQPolicyDocument{
        kAgentQPolicyV0Schema,
        AgentQPolicyAction::reject,
        nullptr,
        0,
    };
    return true;
}

AgentQPolicyDecision evaluate_agent_q_policy_runtime(
    const AgentQPolicyProvider& provider,
    const AgentQPolicyFacts& facts)
{
    return evaluate_agent_q_policy_runtime(provider, facts, nullptr, 0);
}

AgentQPolicyDecision evaluate_agent_q_policy_runtime(
    const AgentQPolicyProvider& provider,
    const AgentQPolicyFacts& facts,
    const AgentQPolicyMethodDescriptor* method_descriptors,
    size_t method_descriptor_count)
{
    if (provider.load == nullptr) {
        return reject_invalid_policy();
    }

    AgentQPolicyDocument policy = {};
    if (!provider.load(&policy, provider.context)) {
        return reject_invalid_policy();
    }

    return evaluate_agent_q_policy_v0_for_methods(
        policy,
        facts,
        method_descriptors,
        method_descriptor_count);
}

}  // namespace agent_q
