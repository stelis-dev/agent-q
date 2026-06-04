#pragma once

#include "agent_q_local_auth_worker.h"
#include "agent_q_sign_by_user_flow.h"
#include "freertos/FreeRTOS.h"

namespace agent_q {

enum class AgentQSignByUserConfirmationResult {
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

AgentQSignByUserConfirmationResult
sign_by_user_confirmation_accept_review_and_begin_pin(
    TickType_t now,
    TickType_t pin_deadline);

AgentQSignByUserConfirmationResult
sign_by_user_confirmation_complete_pin_verify_job_and_write_history(
    const AgentQLocalAuthWorkerResult& worker_result,
    TickType_t now,
    TickType_t retry_deadline,
    TickType_t lockout_until,
    AgentQSignByUserHistoryWriteFn write_fn,
    void* context);
AgentQSignByUserConfirmationResult
sign_by_user_confirmation_mark_pin_verification_started();

AgentQSignByUserConfirmationResult
sign_by_user_confirmation_record_device_rejected();
AgentQSignByUserConfirmationResult
sign_by_user_confirmation_record_timeout(TickType_t now);
AgentQSignByUserConfirmationResult
sign_by_user_confirmation_cancel_for_disconnect(const char* session_id);
AgentQSignByUserConfirmationResult
sign_by_user_confirmation_cancel_for_session_loss();
AgentQSignByUserConfirmationResult
sign_by_user_confirmation_cancel_for_pin_loss();

bool sign_by_user_confirmation_pin_active();

}  // namespace agent_q
