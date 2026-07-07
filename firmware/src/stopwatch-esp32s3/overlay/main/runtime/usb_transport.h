#pragma once

#include <firmware_common/protocol/request_id.h>
#include <transport/timeout_window.h>
#include <stdint.h>

#include "state_projection.h"

namespace stopwatch_target {

struct UsbRuntimeState {
    LocalAuthProjectionStatus auth_status;
    bool locally_unlocked;
    bool ui_busy;
};

enum class UsbPendingRequestKind {
    none,
    connect,
    credential_propose,
    policy_propose,
    sign_transaction,
    sign_personal_message,
};

struct UsbPendingRequest {
    UsbPendingRequestKind kind;
    char id[signing::kRequestIdSize];
    char label[240];
    signing::TimeoutWindow request_window;
};

struct UsbIdentificationDisplay {
    bool active;
    char code[5];
};

enum class UsbSigningNoticeKind {
    info,
    rejected,
    error,
    success,
};

struct UsbSigningNotice {
    bool active;
    UsbSigningNoticeKind kind;
    char message[48];
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
bool usb_transport_projected_device_state_is_error();
void usb_transport_invalidate_projected_state_cache();
UsbPendingRequest usb_transport_pending_request();
UsbIdentificationDisplay usb_transport_identification_display();
UsbSigningNotice usb_transport_signing_notice();
bool usb_transport_approve_pending_request();
bool usb_transport_reject_pending_request(const char* error_code);
void usb_transport_clear_session_scoped_state();

}  // namespace stopwatch_target
