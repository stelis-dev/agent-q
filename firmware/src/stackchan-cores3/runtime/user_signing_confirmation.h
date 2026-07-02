#pragma once

#include "local_auth_worker.h"
#include "timeout_window.h"
#include "user_signing_flow.h"
#include "freertos/FreeRTOS.h"

namespace signing {

enum class UserSigningConfirmationResult {
    ok,
    inactive,
    wrong_stage,
    invalid_argument,
    invalid_session,
    invalid_deadline,
    deadline_expired,
    deadline_not_reached,
    session_still_active,
    not_ready,
    wrong_pin,
    locked,
    auth_unavailable,
    local_pin_busy,
    local_pin_unavailable,
    history_error,
    stale_state,
    busy,
};

UserSigningConfirmationResult
user_signing_confirmation_accept_review_and_begin_pin(
    TickType_t now,
    TimeoutWindow pin_input_window);

UserSigningConfirmationResult
user_signing_confirmation_complete_pin_verify_job_and_write_history(
    const LocalAuthWorkerResult& worker_result,
    TickType_t now,
    TickType_t lockout_until,
    UserSigningHistoryWriteFn write_fn,
    void* context);
UserSigningConfirmationResult
user_signing_confirmation_mark_pin_verification_started(TickType_t now);

UserSigningConfirmationResult user_signing_confirmation_return_to_review_from_pin(
    TickType_t now,
    TimeoutWindow review_window);
UserSigningConfirmationResult
user_signing_confirmation_record_device_rejected();
UserSigningConfirmationResult
user_signing_confirmation_record_timeout(TickType_t now);
UserSigningConfirmationResult
user_signing_confirmation_cancel_for_disconnect(const char* session_id);
UserSigningConfirmationResult
user_signing_confirmation_cancel_for_session_loss();
UserSigningConfirmationResult
user_signing_confirmation_cancel_for_pin_loss();

}  // namespace signing
