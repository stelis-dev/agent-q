#include "agent_q_protocol_pin_approval.h"

#include <stdint.h>
#include <string.h>

namespace agent_q {
namespace {

struct ProtocolPinApprovalState {
    bool active = false;
    AgentQProtocolPinApprovalPurpose purpose = AgentQProtocolPinApprovalPurpose::none;
    char request_id[kAgentQProtocolPinRequestIdSize] = {};
    char session_id[kAgentQSessionIdSize] = {};
    TickType_t deadline = 0;
    TickType_t approval_deadline = 0;

    void clear()
    {
        active = false;
        purpose = AgentQProtocolPinApprovalPurpose::none;
        request_id[0] = '\0';
        session_id[0] = '\0';
        deadline = 0;
        approval_deadline = 0;
    }
};

ProtocolPinApprovalState g_state;

bool copy_nonempty_c_string(const char* input, char* output, size_t output_size)
{
    if (input == nullptr || input[0] == '\0' || output == nullptr || output_size == 0) {
        return false;
    }
    size_t index = 0;
    while (input[index] != '\0' && index + 1 < output_size) {
        output[index] = input[index];
        ++index;
    }
    if (input[index] != '\0') {
        output[0] = '\0';
        return false;
    }
    output[index] = '\0';
    return true;
}

bool local_pin_purpose_matches(
    AgentQProtocolPinApprovalPurpose protocol_purpose,
    AgentQLocalPinAuthPurpose local_purpose)
{
    return (protocol_purpose == AgentQProtocolPinApprovalPurpose::connect &&
            local_purpose == AgentQLocalPinAuthPurpose::connect) ||
           (protocol_purpose == AgentQProtocolPinApprovalPurpose::policy_update &&
            local_purpose == AgentQLocalPinAuthPurpose::policy_update);
}

bool tick_reached(TickType_t now, TickType_t deadline)
{
    return deadline != 0 &&
           static_cast<int32_t>(now - deadline) >= 0;
}

TickType_t cap_deadline(TickType_t deadline, TickType_t cap)
{
    if (deadline == 0 || cap == 0) {
        return deadline;
    }
    return tick_reached(deadline, cap) ? cap : deadline;
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
        g_state.deadline,
        g_state.approval_deadline,
    };
}

bool protocol_pin_approval_begin_connect(
    const char* request_id,
    TickType_t deadline)
{
    if (g_state.active) {
        return false;
    }
    ProtocolPinApprovalState next = {};
    if (!copy_nonempty_c_string(request_id, next.request_id, sizeof(next.request_id))) {
        return false;
    }
    next.active = true;
    next.purpose = AgentQProtocolPinApprovalPurpose::connect;
    next.deadline = deadline;
    next.approval_deadline = deadline;
    g_state = next;
    return true;
}

bool protocol_pin_approval_begin_policy_update(
    const char* request_id,
    const char* session_id,
    TickType_t deadline)
{
    if (g_state.active) {
        return false;
    }
    ProtocolPinApprovalState next = {};
    if (!copy_nonempty_c_string(request_id, next.request_id, sizeof(next.request_id)) ||
        !copy_nonempty_c_string(session_id, next.session_id, sizeof(next.session_id))) {
        return false;
    }
    next.active = true;
    next.purpose = AgentQProtocolPinApprovalPurpose::policy_update;
    next.deadline = deadline;
    next.approval_deadline = deadline;
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

TickType_t protocol_pin_approval_retry_deadline_for_local_pin_purpose(
    AgentQLocalPinAuthPurpose purpose,
    TickType_t fallback_deadline)
{
    if (g_state.active &&
        g_state.approval_deadline != 0 &&
        local_pin_purpose_matches(g_state.purpose, purpose)) {
        return cap_deadline(fallback_deadline, g_state.approval_deadline);
    }
    return fallback_deadline;
}

bool protocol_pin_approval_refresh_deadline_for_local_pin_purpose(
    AgentQLocalPinAuthPurpose purpose,
    TickType_t deadline)
{
    if (!g_state.active ||
        deadline == 0 ||
        !local_pin_purpose_matches(g_state.purpose, purpose)) {
        return false;
    }
    g_state.deadline = cap_deadline(deadline, g_state.approval_deadline);
    return true;
}

bool protocol_pin_approval_pause_deadline_for_local_pin_purpose(
    AgentQLocalPinAuthPurpose purpose)
{
    if (!g_state.active ||
        !local_pin_purpose_matches(g_state.purpose, purpose)) {
        return false;
    }
    g_state.deadline = 0;
    return true;
}

bool protocol_pin_approval_deadline_reached_for_local_pin_purpose(
    AgentQLocalPinAuthPurpose purpose,
    TickType_t now)
{
    if (!g_state.active || !local_pin_purpose_matches(g_state.purpose, purpose)) {
        return false;
    }
    return tick_reached(now, g_state.approval_deadline) ||
           tick_reached(now, g_state.deadline);
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
