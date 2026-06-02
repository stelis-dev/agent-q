#include "agent_q_usb_link_state.h"

#include <stdint.h>

namespace agent_q {
namespace {

struct UsbLinkState {
    bool known = false;
    bool connected = false;
    TickType_t next_poll = 0;

    void clear()
    {
        known = false;
        connected = false;
        next_poll = 0;
    }
};

UsbLinkState g_state;

bool tick_reached(TickType_t now, TickType_t deadline)
{
    return deadline == 0 || static_cast<int32_t>(now - deadline) >= 0;
}

}  // namespace

void usb_link_state_clear()
{
    g_state.clear();
}

AgentQUsbLinkStateSnapshot usb_link_state_snapshot()
{
    return AgentQUsbLinkStateSnapshot{
        g_state.known,
        g_state.connected,
        g_state.next_poll,
    };
}

AgentQUsbLinkEvent usb_link_state_observe(
    bool connected,
    TickType_t now,
    TickType_t poll_interval)
{
    if (!tick_reached(now, g_state.next_poll)) {
        return AgentQUsbLinkEvent::not_due;
    }

    g_state.next_poll = now + poll_interval;

    if (!g_state.known) {
        g_state.known = true;
        g_state.connected = connected;
        return AgentQUsbLinkEvent::initial_observed;
    }

    if (connected == g_state.connected) {
        return connected ? AgentQUsbLinkEvent::unchanged_connected
                         : AgentQUsbLinkEvent::unchanged_disconnected;
    }

    g_state.connected = connected;
    return connected ? AgentQUsbLinkEvent::connected
                     : AgentQUsbLinkEvent::disconnected;
}

}  // namespace agent_q
