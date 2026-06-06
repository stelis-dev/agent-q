#include "agent_q_connect_approval.h"

#include <stdint.h>
#include <string.h>

namespace agent_q {
namespace {

struct ConnectApprovalState {
    bool active = false;
    char request_id[kAgentQConnectApprovalRequestIdSize] = {};
    char gateway_name[kAgentQConnectApprovalGatewayNameSize] = {};
    AgentQTimeoutWindow approval_window = kAgentQTimeoutWindowNone;
    AgentQConnectApprovalChoice choice = AgentQConnectApprovalChoice::none;

    void clear()
    {
        active = false;
        request_id[0] = '\0';
        gateway_name[0] = '\0';
        approval_window = kAgentQTimeoutWindowNone;
        choice = AgentQConnectApprovalChoice::none;
    }
};

ConnectApprovalState g_state;

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

}  // namespace

void connect_approval_clear()
{
    g_state.clear();
}

bool connect_approval_active()
{
    return g_state.active;
}

bool connect_approval_awaiting_choice()
{
    return g_state.active && g_state.choice == AgentQConnectApprovalChoice::none;
}

AgentQConnectApprovalSnapshot connect_approval_snapshot()
{
    return AgentQConnectApprovalSnapshot{
        g_state.active,
        g_state.request_id,
        g_state.gateway_name,
        g_state.approval_window,
        g_state.choice,
    };
}

bool connect_approval_begin(
    const char* request_id,
    const char* gateway_name,
    AgentQTimeoutWindow approval_window)
{
    if (g_state.active) {
        return false;
    }
    ConnectApprovalState next = {};
    if (!timeout_window_valid(approval_window)) {
        return false;
    }
    if (!copy_nonempty_c_string(request_id, next.request_id, sizeof(next.request_id)) ||
        !copy_nonempty_c_string(gateway_name, next.gateway_name, sizeof(next.gateway_name))) {
        return false;
    }
    next.active = true;
    next.approval_window = approval_window;
    g_state = next;
    return true;
}

bool connect_approval_choose(AgentQConnectApprovalChoice choice)
{
    if (!connect_approval_awaiting_choice() ||
        choice == AgentQConnectApprovalChoice::none) {
        return false;
    }
    g_state.choice = choice;
    return true;
}

bool connect_approval_deadline_reached(TickType_t now)
{
    return g_state.active && timeout_window_reached(g_state.approval_window, now);
}

bool connect_approval_request_id(char* output, size_t output_size)
{
    if (output == nullptr || output_size == 0) {
        return false;
    }
    output[0] = '\0';
    if (!g_state.active) {
        return false;
    }
    return copy_nonempty_c_string(g_state.request_id, output, output_size);
}

}  // namespace agent_q
