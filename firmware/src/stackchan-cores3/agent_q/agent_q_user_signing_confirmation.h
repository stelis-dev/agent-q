#pragma once

#include "agent_q_local_auth_worker.h"
#include "agent_q_timeout_window.h"
#include "agent_q_user_signing_flow.h"
#include "freertos/FreeRTOS.h"

namespace agent_q {

enum class AgentQUserSigningConfirmationResult {
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

AgentQUserSigningConfirmationResult
user_signing_confirmation_accept_review_and_begin_pin(
    TickType_t now,
    AgentQTimeoutWindow pin_input_window);

AgentQUserSigningConfirmationResult
user_signing_confirmation_complete_pin_verify_job_and_write_history(
    const AgentQLocalAuthWorkerResult& worker_result,
    TickType_t now,
    AgentQTimeoutWindow retry_window,
    TickType_t lockout_until,
    AgentQUserSigningHistoryWriteFn write_fn,
    void* context);
AgentQUserSigningConfirmationResult
user_signing_confirmation_mark_pin_verification_started();

AgentQUserSigningConfirmationResult
user_signing_confirmation_record_device_rejected();
AgentQUserSigningConfirmationResult
user_signing_confirmation_record_timeout(TickType_t now);
AgentQUserSigningConfirmationResult
user_signing_confirmation_cancel_for_disconnect(const char* session_id);
AgentQUserSigningConfirmationResult
user_signing_confirmation_cancel_for_session_loss();
AgentQUserSigningConfirmationResult
user_signing_confirmation_cancel_for_pin_loss();

bool user_signing_confirmation_pin_active();

}  // namespace agent_q
