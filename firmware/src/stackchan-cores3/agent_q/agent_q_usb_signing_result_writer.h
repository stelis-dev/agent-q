#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_policy_signing_execution.h"
#include "agent_q_user_signing_critical_section.h"
#include "agent_q_user_signing_flow.h"

namespace agent_q {

bool usb_signing_result_write_user_signed(
    const char* id,
    const char* session_id,
    const char* authorization,
    const AgentQUserSigningFlowCoreSnapshot& snapshot,
    const AgentQUserSigningOutput& signing_output);

bool usb_signing_result_write_user_terminal(
    const char* id,
    const char* session_id,
    const uint8_t* request_identity,
    const char* method,
    AgentQUserSigningTerminalResult result);

bool usb_signing_result_write_policy_execution(
    const char* id,
    const char* session_id,
    const uint8_t* request_identity,
    const AgentQPolicySigningExecutionResult& result);

}  // namespace agent_q
