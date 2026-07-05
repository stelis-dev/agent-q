#pragma once

#include <stddef.h>

#include "local_pin_auth.h"
#include "protocol/request_id.h"
#include "session.h"
#include "transport/timeout_window.h"
#include "freertos/FreeRTOS.h"

namespace signing {

constexpr size_t kProtocolPinRequestIdSize = kRequestIdSize;

enum class ProtocolPinApprovalPurpose {
    none,
    connect,
    policy_update,
    sui_zklogin_proposal,
};

struct ProtocolPinApprovalSnapshot {
    bool active;
    ProtocolPinApprovalPurpose purpose;
    const char* request_id;
    const char* session_id;
    TimeoutWindow request_window;
    TimeoutWindow pin_input_window;
};

void protocol_pin_approval_clear();
bool protocol_pin_approval_active();
ProtocolPinApprovalSnapshot protocol_pin_approval_snapshot();

bool protocol_pin_approval_begin_connect(
    const char* request_id,
    TickType_t now,
    TimeoutWindow request_window);
bool protocol_pin_approval_begin_policy_update(
    const char* request_id,
    const char* session_id,
    TickType_t now,
    TimeoutWindow request_window);
bool protocol_pin_approval_begin_sui_zklogin_proposal(
    const char* request_id,
    const char* session_id,
    TickType_t now,
    TimeoutWindow request_window);

bool protocol_pin_approval_request_id_for_local_pin_purpose(
    LocalPinAuthPurpose purpose,
    char* output,
    size_t output_size);
bool protocol_pin_approval_refresh_deadline_for_local_pin_purpose(
    LocalPinAuthPurpose purpose,
    TickType_t now);
bool protocol_pin_approval_pause_deadline_for_local_pin_purpose(
    LocalPinAuthPurpose purpose,
    TickType_t now);
bool protocol_pin_approval_deadline_reached_for_local_pin_purpose(
    LocalPinAuthPurpose purpose,
    TickType_t now);

bool protocol_pin_approval_policy_update_session_matches(const char* session_id);
bool protocol_pin_approval_policy_update_request_id(char* output, size_t output_size);
SessionValidationResult protocol_pin_approval_validate_policy_update_session();
bool protocol_pin_approval_sui_zklogin_proposal_session_matches(const char* session_id);
bool protocol_pin_approval_sui_zklogin_proposal_request_id(char* output, size_t output_size);
SessionValidationResult protocol_pin_approval_validate_sui_zklogin_proposal_session();

}  // namespace signing
