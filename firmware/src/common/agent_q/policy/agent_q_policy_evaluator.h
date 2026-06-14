#pragma once

#include "agent_q_policy_document.h"
#include "agent_q_common/sui/agent_q_sui_offline_policy_facts.h"

namespace agent_q {

enum class AgentQCurrentPolicyEvaluationStatus {
    invalid_argument,
    facts_incomplete,
    no_matching_scope,
    no_matching_policy,
    rejected,
    authorized,
};

struct AgentQCurrentPolicyEvaluationResult {
    AgentQCurrentPolicyEvaluationStatus status;
    const char* reason_code;
    const char* rule_ref;
};

AgentQCurrentPolicyEvaluationResult evaluate_agent_q_current_policy_for_sui_sign_transaction(
    const AgentQCurrentPolicyDocument& policy,
    const char* network,
    const SuiOfflinePolicyConditionFacts& facts);

}  // namespace agent_q
