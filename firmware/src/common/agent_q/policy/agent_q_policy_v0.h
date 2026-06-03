#pragma once

#include <stddef.h>
#include <stdint.h>

namespace agent_q {

constexpr uint32_t kAgentQPolicyV0Schema = 1;

enum class AgentQPolicyAction {
    reject,
    sign,
};

enum class AgentQPolicyDecisionReason {
    matched_rule,
    default_reject,
    invalid_policy,
    unsupported_facts,
};

enum class AgentQPolicyValueType {
    string,
    u64_decimal,
};

enum class AgentQPolicyOperator {
    eq,
    in,
    lte,
};

struct AgentQPolicyCriterion {
    const char* field;
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

struct AgentQPolicyFact {
    const char* field;
    AgentQPolicyValueType type;
    const char* value;
};

struct AgentQPolicyFieldDescriptor {
    const char* field;
    AgentQPolicyValueType type;
    bool allow_eq;
    bool allow_in;
    bool allow_lte;
};

struct AgentQPolicyFacts {
    const AgentQPolicyFact* entries;
    size_t entry_count;
    const AgentQPolicyFieldDescriptor* field_descriptors;
    size_t field_descriptor_count;
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
    const AgentQPolicyFacts& facts);

}  // namespace agent_q
