#pragma once

#include "agent_q_policy_update_flow.h"

namespace agent_q {

bool usb_policy_propose_outcome_write(
    const char* id,
    const char* status,
    const char* reason_code,
    const AgentQPolicyUpdateFlowSnapshot* policy);

}  // namespace agent_q
