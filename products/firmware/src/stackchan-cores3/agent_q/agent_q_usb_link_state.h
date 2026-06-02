#pragma once

#include "freertos/FreeRTOS.h"

namespace agent_q {

enum class AgentQUsbLinkEvent {
    not_due,
    initial_observed,
    unchanged_connected,
    unchanged_disconnected,
    connected,
    disconnected,
};

struct AgentQUsbLinkStateSnapshot {
    bool known;
    bool connected;
    TickType_t next_poll;
};

void usb_link_state_clear();
AgentQUsbLinkStateSnapshot usb_link_state_snapshot();
AgentQUsbLinkEvent usb_link_state_observe(
    bool connected,
    TickType_t now,
    TickType_t poll_interval);

}  // namespace agent_q
