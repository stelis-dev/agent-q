#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_common/policy/agent_q_policy_schema.h"

namespace agent_q {

enum class AgentQPolicyUpdateMarkerStatus {
    clear,
    pending,
    invalid,
    storage_error,
};

enum class AgentQPolicyUpdateHighestAction {
    reject,
};

enum class AgentQPolicyUpdateMarkerBeginResult {
    written,
    invalid_input,
    storage_error,
    pending_after_error,
};

constexpr size_t kAgentQPolicyUpdateDigestBytes = 32;

AgentQPolicyUpdateMarkerStatus policy_update_marker_status();
AgentQPolicyUpdateMarkerBeginResult policy_update_marker_begin(
    const uint8_t* policy_digest,
    size_t policy_digest_size,
    size_t rule_count,
    AgentQPolicyUpdateHighestAction highest_action);
bool policy_update_marker_clear();

}  // namespace agent_q
