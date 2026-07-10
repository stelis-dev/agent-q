#pragma once

#include <firmware_common/protocol/request_id.h>
#include <transport/timeout_window.h>
#include <stdint.h>

#include "state_projection.h"

namespace stopwatch_target {

struct ProtocolRuntimeState {
    LocalAuthProjectionStatus auth_status;
    bool locally_unlocked;
    bool ui_busy;
};

enum class PendingRequestKind {
    none,
    connect,
    credential_propose,
    policy_propose,
    sign_transaction,
    sign_personal_message,
};

struct PendingRequest {
    PendingRequestKind kind;
    char id[signing::kRequestIdSize];
    char label[240];
    signing::TimeoutWindow request_window;
};

struct IdentificationDisplay {
    bool active;
    char code[5];
};

enum class SigningNoticeKind {
    info,
    rejected,
    error,
    success,
};

struct SigningNotice {
    bool active;
    SigningNoticeKind kind;
    char message[48];
};

struct ProtocolStatus {
    bool usb_ready;
    bool usb_connected;
    uint32_t received_lines;
    uint32_t status_responses;
    uint32_t rejected_connects;
    uint32_t invalid_lines;
    char last_id[signing::kRequestIdSize];
    char last_method[32];
    char last_error[32];
};

void protocol_runtime_init();
void protocol_runtime_poll();
ProtocolStatus protocol_runtime_status();
void protocol_runtime_set_state(ProtocolRuntimeState state);
bool protocol_runtime_projected_device_state_is_error();
void protocol_runtime_invalidate_projected_state_cache();
PendingRequest protocol_runtime_pending_request();
IdentificationDisplay protocol_runtime_identification_display();
SigningNotice protocol_runtime_signing_notice();
bool protocol_runtime_approve_pending_request();
bool protocol_runtime_reject_pending_request(const char* error_code);
void protocol_runtime_clear_session_scoped_state();
bool protocol_runtime_local_transport_entry_allowed();

}  // namespace stopwatch_target
