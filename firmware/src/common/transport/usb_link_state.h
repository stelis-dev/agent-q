#pragma once

#include "freertos/FreeRTOS.h"

namespace signing {

enum class UsbLinkEvent {
    not_due,
    initial_observed,
    unchanged_connected,
    unchanged_disconnected,
    connected,
    disconnected,
};

struct UsbLinkStateSnapshot {
    bool known;
    bool connected;
    TickType_t next_poll;
};

void usb_link_state_clear();
UsbLinkStateSnapshot usb_link_state_snapshot();
UsbLinkEvent usb_link_state_observe(
    bool connected,
    TickType_t now,
    TickType_t poll_interval);

}  // namespace signing
