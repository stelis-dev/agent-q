#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_common/policy/agent_q_policy_runtime.h"

namespace agent_q {

constexpr const char* kAgentQStoredPolicySchema = "agentq.policy.v0";
constexpr size_t kAgentQPolicyIdSize = 72;  // "sha256:" + 64 hex chars + NUL.

struct AgentQStoredPolicySummary {
    const char* schema;
    char policy_id[kAgentQPolicyIdSize];
    const char* default_action;
    size_t rule_count;
};

enum class AgentQPolicyStoreStatus {
    active,
    missing,
    invalid,
    storage_error,
};

enum class AgentQPolicyStoreWriteResult {
    applied,
    unchanged_failure,
    consistency_error,
    invalid_record,
};

bool store_default_policy();
AgentQPolicyStoreWriteResult store_active_policy_record(const uint8_t* record, size_t record_size);
bool wipe_policy();
AgentQPolicyStoreStatus active_policy_status();

AgentQPolicyProvider active_policy_provider();
bool read_active_policy_summary(AgentQStoredPolicySummary* out);

}  // namespace agent_q
