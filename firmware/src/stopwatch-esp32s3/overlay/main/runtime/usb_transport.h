#pragma once

#include <firmware_common/protocol/request_id.h>
#include <stdint.h>

#include "state_projection.h"

namespace stopwatch_target {

struct UsbRuntimeState {
    LocalAuthProjectionStatus auth_status;
    bool locally_unlocked;
    bool ui_busy;
};

struct UsbStatus {
    bool ready;
    bool connected;
    uint32_t received_lines;
    uint32_t status_responses;
    uint32_t rejected_connects;
    uint32_t invalid_lines;
    char last_id[signing::kRequestIdSize];
    char last_method[32];
    char last_error[32];
};

bool usb_transport_init();
void usb_transport_poll();
UsbStatus usb_transport_status();
void usb_transport_set_runtime_state(UsbRuntimeState state);

}  // namespace stopwatch_target
