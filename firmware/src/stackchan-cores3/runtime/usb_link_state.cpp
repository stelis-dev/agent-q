#include "usb_link_state.h"

#include <stdint.h>

namespace signing {
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

UsbLinkStateSnapshot usb_link_state_snapshot()
{
    return UsbLinkStateSnapshot{
        g_state.known,
        g_state.connected,
        g_state.next_poll,
    };
}

UsbLinkEvent usb_link_state_observe(
    bool connected,
    TickType_t now,
    TickType_t poll_interval)
{
    if (!tick_reached(now, g_state.next_poll)) {
        return UsbLinkEvent::not_due;
    }

    g_state.next_poll = now + poll_interval;

    if (!g_state.known) {
        g_state.known = true;
        g_state.connected = connected;
        return UsbLinkEvent::initial_observed;
    }

    if (connected == g_state.connected) {
        return connected ? UsbLinkEvent::unchanged_connected
                         : UsbLinkEvent::unchanged_disconnected;
    }

    g_state.connected = connected;
    return connected ? UsbLinkEvent::connected
                     : UsbLinkEvent::disconnected;
}

}  // namespace signing
