#pragma once

#include "freertos/FreeRTOS.h"

#include "transport/usb_link_state.h"

namespace signing {

// Debounce USB host-link loss. A transient drop should not immediately tear a
// Firmware session down; a sustained disconnect confirms the loss.
enum class UsbGraceAction {
    none,
    suspend,
    confirm,
    resume,
};

struct UsbGraceState {
    bool pending = false;
    TickType_t pending_since = 0;
};

UsbGraceAction usb_session_grace_step(
    UsbLinkEvent event,
    TickType_t now,
    TickType_t grace_ticks,
    UsbGraceState& state);

}  // namespace signing
