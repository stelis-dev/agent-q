#include "agent_q_sign_transaction_user_confirmation.h"

#include <string.h>

#include "agent_q_local_pin_auth.h"
#include "agent_q_local_pin_auth_signature_internal.h"

namespace agent_q {

namespace {

struct SignaturePinBinding {
    bool active = false;
    AgentQLocalPinAuthSignatureBinding pin = {};
    AgentQSignTransactionUserFlowSnapshot flow = {};
};

SignaturePinBinding g_signature_pin_binding;
uint32_t g_next_signature_pin_token = 1;

AgentQSignTransactionUserConfirmationResult map_transition(
    AgentQSignTransactionUserTransitionResult result)
{
    switch (result) {
        case AgentQSignTransactionUserTransitionResult::ok:
            return AgentQSignTransactionUserConfirmationResult::ok;
        case AgentQSignTransactionUserTransitionResult::inactive:
            return AgentQSignTransactionUserConfirmationResult::inactive;
        case AgentQSignTransactionUserTransitionResult::wrong_stage:
            return AgentQSignTransactionUserConfirmationResult::wrong_stage;
        case AgentQSignTransactionUserTransitionResult::invalid_argument:
            return AgentQSignTransactionUserConfirmationResult::invalid_argument;
        case AgentQSignTransactionUserTransitionResult::invalid_session:
            return AgentQSignTransactionUserConfirmationResult::invalid_session;
        case AgentQSignTransactionUserTransitionResult::invalid_deadline:
            return AgentQSignTransactionUserConfirmationResult::invalid_deadline;
        case AgentQSignTransactionUserTransitionResult::deadline_expired:
            return AgentQSignTransactionUserConfirmationResult::deadline_expired;
        case AgentQSignTransactionUserTransitionResult::deadline_not_reached:
            return AgentQSignTransactionUserConfirmationResult::deadline_not_reached;
        case AgentQSignTransactionUserTransitionResult::session_still_active:
            return AgentQSignTransactionUserConfirmationResult::session_still_active;
        case AgentQSignTransactionUserTransitionResult::history_error:
            return AgentQSignTransactionUserConfirmationResult::history_error;
        case AgentQSignTransactionUserTransitionResult::stale_state:
            return AgentQSignTransactionUserConfirmationResult::stale_state;
        case AgentQSignTransactionUserTransitionResult::busy:
            return AgentQSignTransactionUserConfirmationResult::busy;
        case AgentQSignTransactionUserTransitionResult::output_too_small:
        case AgentQSignTransactionUserTransitionResult::payload_unavailable:
        case AgentQSignTransactionUserTransitionResult::payload_not_consumed:
            return AgentQSignTransactionUserConfirmationResult::wrong_stage;
    }
    return AgentQSignTransactionUserConfirmationResult::wrong_stage;
}

bool signature_pin_active()
{
    const AgentQLocalPinAuthSnapshot snapshot = local_pin_auth_snapshot(0);
    return snapshot.flow_active &&
           snapshot.purpose == AgentQLocalPinAuthPurpose::sign_transaction_user;
}

bool signature_pin_stage(AgentQLocalPinAuthStage stage)
{
    const AgentQLocalPinAuthSnapshot snapshot = local_pin_auth_snapshot(0);
    return snapshot.flow_active &&
           snapshot.purpose == AgentQLocalPinAuthPurpose::sign_transaction_user &&
           snapshot.stage == stage;
}

bool tick_reached(TickType_t deadline, TickType_t now)
{
    return deadline != 0 &&
           static_cast<int32_t>(now - deadline) >= 0;
}

TickType_t cap_to_request_deadline(
    TickType_t request_deadline,
    TickType_t deadline)
{
    if (request_deadline == 0) {
        return deadline;
    }
    return tick_reached(request_deadline, deadline)
               ? request_deadline
               : deadline;
}

uint32_t next_signature_pin_token()
{
    const uint32_t token = g_next_signature_pin_token++;
    if (g_next_signature_pin_token == 0) {
        g_next_signature_pin_token = 1;
    }
    return token == 0 ? next_signature_pin_token() : token;
}

bool flow_matches_expected(
    const AgentQSignTransactionUserFlowSnapshot& expected,
    AgentQSignTransactionUserStage stage)
{
    const AgentQSignTransactionUserFlowSnapshot current =
        sign_transaction_user_flow_snapshot();
    return expected.active &&
           current.active &&
           current.stage == stage &&
           strcmp(current.request_id, expected.request_id) == 0 &&
           strcmp(current.session_id, expected.session_id) == 0 &&
           strcmp(current.chain, expected.chain) == 0 &&
           strcmp(current.method, expected.method) == 0 &&
           strcmp(current.network, expected.network) == 0 &&
           strcmp(current.payload_digest, expected.payload_digest) == 0 &&
           current.signable_payload_size == expected.signable_payload_size &&
           current.signable_payload_available == expected.signable_payload_available;
}

bool signature_pin_bound_to_flow(
    AgentQLocalPinAuthStage pin_stage,
    AgentQSignTransactionUserStage flow_stage)
{
    return g_signature_pin_binding.active &&
           signature_pin_stage(pin_stage) &&
           local_pin_auth_sign_transaction_user_matches(g_signature_pin_binding.pin) &&
           flow_matches_expected(g_signature_pin_binding.flow, flow_stage);
}

void clear_signature_pin_if_active()
{
    if (signature_pin_active()) {
        local_pin_auth_clear_flow();
    }
    g_signature_pin_binding = {};
}

AgentQSignTransactionUserConfirmationResult clear_expected_flow_and_pin(
    const AgentQSignTransactionUserFlowSnapshot& expected)
{
    clear_signature_pin_if_active();
    if (!flow_matches_expected(expected, AgentQSignTransactionUserStage::pin_entry)) {
        return AgentQSignTransactionUserConfirmationResult::stale_state;
    }
    return map_transition(sign_transaction_user_flow_cancel_for_pin_loss());
}

AgentQSignTransactionUserConfirmationResult
record_verified_pin_and_write_history(
    TickType_t now,
    AgentQSignTransactionUserHistoryWriteFn write_fn,
    void* context,
    const AgentQSignTransactionUserFlowSnapshot& expected)
{
    if (write_fn == nullptr) {
        return AgentQSignTransactionUserConfirmationResult::invalid_argument;
    }
    if (!flow_matches_expected(expected, AgentQSignTransactionUserStage::pin_entry)) {
        return AgentQSignTransactionUserConfirmationResult::stale_state;
    }

    const AgentQSignTransactionUserTransitionResult result =
        sign_transaction_user_flow_record_pin_verified_and_write_confirmation_history(
            now,
            write_fn,
            context);
    clear_signature_pin_if_active();
    return map_transition(result);
}

}  // namespace

AgentQSignTransactionUserConfirmationResult
sign_transaction_user_confirmation_accept_review_and_begin_pin(
    TickType_t now,
    TickType_t pin_deadline)
{
    const AgentQSignTransactionUserFlowSnapshot flow =
        sign_transaction_user_flow_snapshot();
    if (!flow.active) {
        return AgentQSignTransactionUserConfirmationResult::inactive;
    }
    if (flow.stage != AgentQSignTransactionUserStage::reviewing) {
        return AgentQSignTransactionUserConfirmationResult::wrong_stage;
    }
    if (pin_deadline == 0) {
        return AgentQSignTransactionUserConfirmationResult::invalid_deadline;
    }
    if (local_pin_auth_flow_active()) {
        return AgentQSignTransactionUserConfirmationResult::local_pin_busy;
    }
    const TickType_t capped_pin_deadline =
        cap_to_request_deadline(flow.request_deadline, pin_deadline);
    SignaturePinBinding next_binding = {};
    next_binding.active = true;
    next_binding.pin.token = next_signature_pin_token();
    next_binding.flow = flow;
    if (!local_pin_auth_begin_sign_transaction_user(next_binding.pin, capped_pin_deadline)) {
        return AgentQSignTransactionUserConfirmationResult::local_pin_unavailable;
    }

    const AgentQSignTransactionUserTransitionResult accepted =
        sign_transaction_user_flow_accept_review(now, capped_pin_deadline);
    if (accepted != AgentQSignTransactionUserTransitionResult::ok) {
        local_pin_auth_clear_flow();
        return map_transition(accepted);
    }
    g_signature_pin_binding = next_binding;
    return AgentQSignTransactionUserConfirmationResult::ok;
}

AgentQSignTransactionUserConfirmationResult
sign_transaction_user_confirmation_complete_pin_verify_job_and_write_history(
    const AgentQLocalAuthWorkerResult& worker_result,
    TickType_t now,
    TickType_t retry_deadline,
    TickType_t lockout_until,
    AgentQSignTransactionUserHistoryWriteFn write_fn,
    void* context)
{
    if (!signature_pin_bound_to_flow(
            AgentQLocalPinAuthStage::pin_verifying,
            AgentQSignTransactionUserStage::pin_entry)) {
        return AgentQSignTransactionUserConfirmationResult::wrong_stage;
    }
    const AgentQSignTransactionUserFlowSnapshot expected = g_signature_pin_binding.flow;
    if (write_fn == nullptr) {
        clear_expected_flow_and_pin(expected);
        return AgentQSignTransactionUserConfirmationResult::invalid_argument;
    }
    if (sign_transaction_user_flow_deadline_reached(now)) {
        clear_signature_pin_if_active();
        const AgentQSignTransactionUserTransitionResult timeout =
            sign_transaction_user_flow_record_timeout(now);
        return timeout == AgentQSignTransactionUserTransitionResult::ok
                   ? AgentQSignTransactionUserConfirmationResult::deadline_expired
                   : map_transition(timeout);
    }

    const AgentQLocalPinAuthSignatureVerifyResult result =
        local_pin_auth_complete_sign_transaction_user_verify_job(
            worker_result,
            cap_to_request_deadline(expected.request_deadline, retry_deadline),
            lockout_until);
    switch (result) {
        case AgentQLocalPinAuthSignatureVerifyResult::verified:
            return record_verified_pin_and_write_history(now, write_fn, context, expected);
        case AgentQLocalPinAuthSignatureVerifyResult::not_ready:
            return AgentQSignTransactionUserConfirmationResult::not_ready;
        case AgentQLocalPinAuthSignatureVerifyResult::auth_unavailable:
            clear_expected_flow_and_pin(expected);
            return AgentQSignTransactionUserConfirmationResult::auth_unavailable;
        case AgentQLocalPinAuthSignatureVerifyResult::locked: {
            const AgentQSignTransactionUserTransitionResult refresh =
                sign_transaction_user_flow_refresh_pin_deadline(retry_deadline);
            if (refresh != AgentQSignTransactionUserTransitionResult::ok) {
                clear_signature_pin_if_active();
                return map_transition(refresh);
            }
            return AgentQSignTransactionUserConfirmationResult::locked;
        }
        case AgentQLocalPinAuthSignatureVerifyResult::wrong_pin: {
            const AgentQSignTransactionUserTransitionResult refresh =
                sign_transaction_user_flow_refresh_pin_deadline(retry_deadline);
            if (refresh != AgentQSignTransactionUserTransitionResult::ok) {
                clear_signature_pin_if_active();
                return map_transition(refresh);
            }
            return AgentQSignTransactionUserConfirmationResult::wrong_pin;
        }
    }
    return AgentQSignTransactionUserConfirmationResult::wrong_stage;
}

AgentQSignTransactionUserConfirmationResult
sign_transaction_user_confirmation_mark_pin_verification_started()
{
    if (!signature_pin_bound_to_flow(
            AgentQLocalPinAuthStage::pin_verifying,
            AgentQSignTransactionUserStage::pin_entry)) {
        return AgentQSignTransactionUserConfirmationResult::wrong_stage;
    }
    return map_transition(sign_transaction_user_flow_pause_pin_deadline());
}

AgentQSignTransactionUserConfirmationResult
sign_transaction_user_confirmation_record_device_rejected()
{
    clear_signature_pin_if_active();
    return map_transition(sign_transaction_user_flow_record_device_rejected());
}

AgentQSignTransactionUserConfirmationResult
sign_transaction_user_confirmation_record_timeout(TickType_t now)
{
    clear_signature_pin_if_active();
    return map_transition(sign_transaction_user_flow_record_timeout(now));
}

AgentQSignTransactionUserConfirmationResult
sign_transaction_user_confirmation_cancel_for_disconnect(const char* session_id)
{
    if (signature_pin_active() &&
        (!g_signature_pin_binding.active ||
         !local_pin_auth_sign_transaction_user_matches(g_signature_pin_binding.pin))) {
        clear_signature_pin_if_active();
    }
    const AgentQSignTransactionUserTransitionResult result =
        sign_transaction_user_flow_cancel_for_disconnect(session_id);
    if (result != AgentQSignTransactionUserTransitionResult::busy) {
        clear_signature_pin_if_active();
    }
    return map_transition(result);
}

AgentQSignTransactionUserConfirmationResult
sign_transaction_user_confirmation_cancel_for_session_loss()
{
    if (signature_pin_active() &&
        (!g_signature_pin_binding.active ||
         !local_pin_auth_sign_transaction_user_matches(g_signature_pin_binding.pin))) {
        clear_signature_pin_if_active();
    }
    const AgentQSignTransactionUserTransitionResult result =
        sign_transaction_user_flow_cancel_for_session_loss();
    if (result != AgentQSignTransactionUserTransitionResult::busy) {
        clear_signature_pin_if_active();
    }
    return map_transition(result);
}

AgentQSignTransactionUserConfirmationResult
sign_transaction_user_confirmation_cancel_for_pin_loss()
{
    if (!signature_pin_active()) {
        return AgentQSignTransactionUserConfirmationResult::inactive;
    }
    if (!g_signature_pin_binding.active ||
        !local_pin_auth_sign_transaction_user_matches(g_signature_pin_binding.pin)) {
        clear_signature_pin_if_active();
        return map_transition(sign_transaction_user_flow_cancel_for_pin_loss());
    }
    return clear_expected_flow_and_pin(g_signature_pin_binding.flow);
}

bool sign_transaction_user_confirmation_pin_active()
{
    return signature_pin_active();
}

}  // namespace agent_q
