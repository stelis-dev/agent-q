#pragma once

#include <stddef.h>
#include <stdint.h>

namespace agent_q {

constexpr uint32_t kAgentQPolicyV0Schema = 1;

enum class AgentQPolicyAction {
    reject,
    ask,
    sign,
};

enum class AgentQPolicyDecisionReason {
    matched_rule,
    default_reject,
    invalid_policy,
    unsupported_facts,
};

enum class AgentQPolicyCriterionType {
    network,
    kind,
    recipient,
    amount,
    gas_budget,
};

enum class AgentQPolicyOperator {
    eq,
    in,
    lte,
};

struct AgentQPolicyCriterion {
    AgentQPolicyCriterionType type;
    AgentQPolicyOperator op;
    const char* value;
    const char* const* values;
    size_t value_count;
};

struct AgentQPolicyRule {
    const char* id;
    const char* chain;
    const char* operation;
    AgentQPolicyAction action;
    const AgentQPolicyCriterion* criteria;
    size_t criterion_count;
};

struct AgentQPolicyDocument {
    uint32_t schema;
    AgentQPolicyAction default_action;
    const AgentQPolicyRule* rules;
    size_t rule_count;
};

struct AgentQTransactionFacts {
    const char* chain;
    const char* operation;
    const char* network;
    const char* kind;
    const char* recipient;
    const char* amount;
    const char* gas_budget;
};

struct AgentQPolicyDecision {
    AgentQPolicyAction action;
    const char* rule_id;
    AgentQPolicyDecisionReason reason;
};

const char* agent_q_policy_action_name(AgentQPolicyAction action);
const char* agent_q_policy_decision_reason_name(AgentQPolicyDecisionReason reason);

AgentQPolicyDecision evaluate_agent_q_policy_v0(
    const AgentQPolicyDocument& policy,
    const AgentQTransactionFacts& facts);

}  // namespace agent_q
