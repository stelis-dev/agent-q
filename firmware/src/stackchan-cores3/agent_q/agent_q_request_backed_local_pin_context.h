#pragma once

#include <stddef.h>

#include "agent_q_local_pin_auth.h"
#include "agent_q_timeout_window.h"
#include "freertos/FreeRTOS.h"

namespace agent_q {

enum class AgentQRequestBackedLocalPinOwner {
    none,
    protocol_pin_approval,
    user_signing,
};

AgentQRequestBackedLocalPinOwner request_backed_local_pin_owner_for_purpose(
    AgentQLocalPinAuthPurpose purpose);
bool request_backed_local_pin_purpose(AgentQLocalPinAuthPurpose purpose);
bool request_backed_local_pin_request_id(
    AgentQLocalPinAuthPurpose purpose,
    char* output,
    size_t output_size);
AgentQTimeoutWindow request_backed_local_pin_cap_input_window(
    AgentQLocalPinAuthPurpose purpose,
    AgentQTimeoutWindow input_window);
bool request_backed_local_pin_resume_input_window(
    AgentQLocalPinAuthPurpose purpose,
    TickType_t now);
bool request_backed_local_pin_pause_input_window(
    AgentQLocalPinAuthPurpose purpose,
    TickType_t now);
bool request_backed_local_pin_deadline_reached(
    AgentQLocalPinAuthPurpose purpose,
    TickType_t now);

}  // namespace agent_q
