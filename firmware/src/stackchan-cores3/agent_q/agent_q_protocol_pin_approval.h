#pragma once

#include <stddef.h>

#include "agent_q_local_pin_auth.h"
#include "agent_q_request_id.h"
#include "agent_q_session.h"
#include "agent_q_timeout_window.h"
#include "freertos/FreeRTOS.h"

namespace agent_q {

constexpr size_t kAgentQProtocolPinRequestIdSize = kAgentQRequestIdSize;

enum class AgentQProtocolPinApprovalPurpose {
    none,
    connect,
    policy_update,
};

struct AgentQProtocolPinApprovalSnapshot {
    bool active;
    AgentQProtocolPinApprovalPurpose purpose;
    const char* request_id;
    const char* session_id;
    AgentQTimeoutWindow request_window;
    AgentQTimeoutWindow pin_input_window;
};

void protocol_pin_approval_clear();
bool protocol_pin_approval_active();
AgentQProtocolPinApprovalSnapshot protocol_pin_approval_snapshot();

bool protocol_pin_approval_begin_connect(
    const char* request_id,
    TickType_t now,
    AgentQTimeoutWindow request_window);
bool protocol_pin_approval_begin_policy_update(
    const char* request_id,
    const char* session_id,
    TickType_t now,
    AgentQTimeoutWindow request_window);

bool protocol_pin_approval_request_id_for_local_pin_purpose(
    AgentQLocalPinAuthPurpose purpose,
    char* output,
    size_t output_size);
bool protocol_pin_approval_refresh_deadline_for_local_pin_purpose(
    AgentQLocalPinAuthPurpose purpose,
    TickType_t now);
bool protocol_pin_approval_pause_deadline_for_local_pin_purpose(
    AgentQLocalPinAuthPurpose purpose,
    TickType_t now);
bool protocol_pin_approval_deadline_reached_for_local_pin_purpose(
    AgentQLocalPinAuthPurpose purpose,
    TickType_t now);

bool protocol_pin_approval_policy_update_session_matches(const char* session_id);
bool protocol_pin_approval_policy_update_request_id(char* output, size_t output_size);
AgentQSessionValidationResult protocol_pin_approval_validate_policy_update_session();

}  // namespace agent_q
