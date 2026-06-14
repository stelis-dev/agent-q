#include "agent_q_protocol_pin_approval.h"

#include <stdint.h>
#include <string.h>

#include "agent_q_protocol_input_copy.h"

namespace agent_q {
namespace {

struct ProtocolPinApprovalState {
    bool active = false;
    AgentQProtocolPinApprovalPurpose purpose = AgentQProtocolPinApprovalPurpose::none;
    char request_id[kAgentQProtocolPinRequestIdSize] = {};
    char session_id[kAgentQSessionIdSize] = {};
    AgentQTimeoutWindow request_window = kAgentQTimeoutWindowNone;
    AgentQTimeoutWindow pin_input_window = kAgentQTimeoutWindowNone;
    AgentQPausedTimeoutWindow paused_pin_input_window = kAgentQPausedTimeoutWindowNone;

    void clear()
    {
        active = false;
        purpose = AgentQProtocolPinApprovalPurpose::none;
        request_id[0] = '\0';
        session_id[0] = '\0';
        request_window = kAgentQTimeoutWindowNone;
        pin_input_window = kAgentQTimeoutWindowNone;
        paused_pin_input_window = kAgentQPausedTimeoutWindowNone;
    }
};

ProtocolPinApprovalState g_state;

bool local_pin_purpose_matches(
    AgentQProtocolPinApprovalPurpose protocol_purpose,
    AgentQLocalPinAuthPurpose local_purpose)
{
    return (protocol_purpose == AgentQProtocolPinApprovalPurpose::connect &&
            local_purpose == AgentQLocalPinAuthPurpose::connect) ||
           (protocol_purpose == AgentQProtocolPinApprovalPurpose::policy_update &&
            local_purpose == AgentQLocalPinAuthPurpose::policy_update);
}

}  // namespace

void protocol_pin_approval_clear()
{
    g_state.clear();
}

bool protocol_pin_approval_active()
{
    return g_state.active;
}

AgentQProtocolPinApprovalSnapshot protocol_pin_approval_snapshot()
{
    return AgentQProtocolPinApprovalSnapshot{
        g_state.active,
        g_state.purpose,
        g_state.request_id,
        g_state.session_id,
        g_state.request_window,
        g_state.pin_input_window,
    };
}

bool protocol_pin_approval_begin_connect(
    const char* request_id,
    TickType_t now,
    AgentQTimeoutWindow request_window)
{
    if (g_state.active || !timeout_window_valid_and_open_at(request_window, now)) {
        return false;
    }
    ProtocolPinApprovalState next = {};
    if (!copy_nonempty_c_string(request_id, next.request_id, sizeof(next.request_id))) {
        return false;
    }
    next.active = true;
    next.purpose = AgentQProtocolPinApprovalPurpose::connect;
    next.request_window = request_window;
    next.pin_input_window = request_window;
    g_state = next;
    return true;
}

bool protocol_pin_approval_begin_policy_update(
    const char* request_id,
    const char* session_id,
    TickType_t now,
    AgentQTimeoutWindow request_window)
{
    if (g_state.active || !timeout_window_valid_and_open_at(request_window, now)) {
        return false;
    }
    ProtocolPinApprovalState next = {};
    if (!copy_nonempty_c_string(request_id, next.request_id, sizeof(next.request_id)) ||
        !copy_nonempty_c_string(session_id, next.session_id, sizeof(next.session_id))) {
        return false;
    }
    next.active = true;
    next.purpose = AgentQProtocolPinApprovalPurpose::policy_update;
    next.request_window = request_window;
    next.pin_input_window = request_window;
    g_state = next;
    return true;
}

bool protocol_pin_approval_request_id_for_local_pin_purpose(
    AgentQLocalPinAuthPurpose purpose,
    char* output,
    size_t output_size)
{
    if (output == nullptr || output_size == 0) {
        return false;
    }
    output[0] = '\0';
    if (!g_state.active || !local_pin_purpose_matches(g_state.purpose, purpose)) {
        return false;
    }
    return copy_nonempty_c_string(g_state.request_id, output, output_size);
}

bool protocol_pin_approval_refresh_deadline_for_local_pin_purpose(
    AgentQLocalPinAuthPurpose purpose,
    TickType_t now)
{
    if (!g_state.active ||
        !local_pin_purpose_matches(g_state.purpose, purpose)) {
        return false;
    }
    const AgentQTimeoutWindow resumed =
        timeout_window_resume_at(g_state.paused_pin_input_window, now);
    if (!timeout_window_valid(resumed)) {
        return false;
    }
    g_state.pin_input_window = resumed;
    g_state.paused_pin_input_window = kAgentQPausedTimeoutWindowNone;
    return true;
}

bool protocol_pin_approval_pause_deadline_for_local_pin_purpose(
    AgentQLocalPinAuthPurpose purpose,
    TickType_t now)
{
    if (!g_state.active ||
        !local_pin_purpose_matches(g_state.purpose, purpose)) {
        return false;
    }
    if (timeout_window_reached(g_state.pin_input_window, now)) {
        return false;
    }
    g_state.paused_pin_input_window =
        timeout_window_pause_at(g_state.pin_input_window, now);
    if (!timeout_paused_window_valid(g_state.paused_pin_input_window)) {
        g_state.paused_pin_input_window = kAgentQPausedTimeoutWindowNone;
        return false;
    }
    g_state.pin_input_window = kAgentQTimeoutWindowNone;
    return true;
}

bool protocol_pin_approval_deadline_reached_for_local_pin_purpose(
    AgentQLocalPinAuthPurpose purpose,
    TickType_t now)
{
    if (!g_state.active || !local_pin_purpose_matches(g_state.purpose, purpose)) {
        return false;
    }
    return timeout_window_reached(g_state.pin_input_window, now);
}

bool protocol_pin_approval_policy_update_session_matches(const char* session_id)
{
    return g_state.active &&
           g_state.purpose == AgentQProtocolPinApprovalPurpose::policy_update &&
           g_state.session_id[0] != '\0' &&
           session_id != nullptr &&
           strcmp(g_state.session_id, session_id) == 0;
}

bool protocol_pin_approval_policy_update_request_id(char* output, size_t output_size)
{
    if (output == nullptr || output_size == 0) {
        return false;
    }
    output[0] = '\0';
    if (!g_state.active ||
        g_state.purpose != AgentQProtocolPinApprovalPurpose::policy_update) {
        return false;
    }
    return copy_nonempty_c_string(g_state.request_id, output, output_size);
}

AgentQSessionValidationResult protocol_pin_approval_validate_policy_update_session()
{
    if (!g_state.active ||
        g_state.purpose != AgentQProtocolPinApprovalPurpose::policy_update ||
        g_state.session_id[0] == '\0') {
        return AgentQSessionValidationResult::missing;
    }
    return session_validate(g_state.session_id);
}

}  // namespace agent_q
