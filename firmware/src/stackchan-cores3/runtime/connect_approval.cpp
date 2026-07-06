#include "connect_approval.h"

#include <stdint.h>
#include <string.h>

#include "protocol/protocol_input_copy.h"

namespace signing {
namespace {

struct ConnectApprovalState {
    bool active = false;
    char request_id[kConnectApprovalRequestIdSize] = {};
    char client_name[kConnectApprovalClientNameSize] = {};
    TimeoutWindow approval_window = kTimeoutWindowNone;
    ConnectApprovalChoice choice = ConnectApprovalChoice::none;

    void clear()
    {
        active = false;
        request_id[0] = '\0';
        client_name[0] = '\0';
        approval_window = kTimeoutWindowNone;
        choice = ConnectApprovalChoice::none;
    }
};

ConnectApprovalState g_state;

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
    return g_state.active && g_state.choice == ConnectApprovalChoice::none;
}

ConnectApprovalSnapshot connect_approval_snapshot()
{
    return ConnectApprovalSnapshot{
        g_state.active,
        g_state.request_id,
        g_state.client_name,
        g_state.approval_window,
        g_state.choice,
    };
}

bool connect_approval_begin(
    const char* request_id,
    const char* client_name,
    TickType_t now,
    TimeoutWindow approval_window)
{
    if (g_state.active) {
        return false;
    }
    ConnectApprovalState next = {};
    if (!timeout_window_valid_and_open_at(approval_window, now)) {
        return false;
    }
    if (!copy_nonempty_c_string(request_id, next.request_id, sizeof(next.request_id)) ||
        !copy_nonempty_c_string(client_name, next.client_name, sizeof(next.client_name))) {
        return false;
    }
    next.active = true;
    next.approval_window = approval_window;
    g_state = next;
    return true;
}

bool connect_approval_review_action_available(TickType_t now)
{
    return connect_approval_awaiting_choice() &&
           timeout_window_valid(g_state.approval_window) &&
           !timeout_window_reached(g_state.approval_window, now);
}

bool connect_approval_choose(ConnectApprovalChoice choice, TickType_t now)
{
    if (!connect_approval_review_action_available(now) ||
        choice == ConnectApprovalChoice::none) {
        return false;
    }
    g_state.choice = choice;
    return true;
}

bool connect_approval_return_to_review(TickType_t now, TimeoutWindow approval_window)
{
    if (!g_state.active ||
        !timeout_window_valid_and_open_at(approval_window, now)) {
        return false;
    }
    g_state.choice = ConnectApprovalChoice::none;
    g_state.approval_window = approval_window;
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

}  // namespace signing
