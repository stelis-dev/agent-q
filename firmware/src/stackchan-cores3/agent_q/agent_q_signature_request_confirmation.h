#pragma once

#include "agent_q_local_auth_worker.h"
#include "agent_q_signature_request_flow.h"
#include "freertos/FreeRTOS.h"

namespace agent_q {

enum class AgentQSignatureRequestConfirmationResult {
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

AgentQSignatureRequestConfirmationResult
signature_request_confirmation_accept_review_and_begin_pin(
    TickType_t now,
    TickType_t pin_deadline);

AgentQSignatureRequestConfirmationResult
signature_request_confirmation_complete_pin_verify_job_and_write_history(
    const AgentQLocalAuthWorkerResult& worker_result,
    TickType_t now,
    TickType_t retry_deadline,
    TickType_t lockout_until,
    AgentQSignatureRequestHistoryWriteFn write_fn,
    void* context);

AgentQSignatureRequestConfirmationResult
signature_request_confirmation_record_device_rejected();
AgentQSignatureRequestConfirmationResult
signature_request_confirmation_record_timeout(TickType_t now);
AgentQSignatureRequestConfirmationResult
signature_request_confirmation_cancel_for_disconnect(const char* session_id);
AgentQSignatureRequestConfirmationResult
signature_request_confirmation_cancel_for_session_loss();
AgentQSignatureRequestConfirmationResult
signature_request_confirmation_cancel_for_pin_loss();

bool signature_request_confirmation_pin_active();

}  // namespace agent_q
