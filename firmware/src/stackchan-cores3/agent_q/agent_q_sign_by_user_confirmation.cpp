#include "agent_q_sign_by_user_confirmation.h"

#include <string.h>

#include "agent_q_local_pin_auth.h"
#include "agent_q_local_pin_auth_signature_internal.h"

namespace agent_q {

namespace {

struct SignaturePinBinding {
    bool active = false;
    AgentQLocalPinAuthSignatureBinding pin = {};
    AgentQSignByUserFlowSnapshot flow = {};
};

SignaturePinBinding g_signature_pin_binding;
uint32_t g_next_signature_pin_token = 1;

AgentQSignByUserConfirmationResult map_transition(
    AgentQSignByUserTransitionResult result)
{
    switch (result) {
        case AgentQSignByUserTransitionResult::ok:
            return AgentQSignByUserConfirmationResult::ok;
        case AgentQSignByUserTransitionResult::inactive:
            return AgentQSignByUserConfirmationResult::inactive;
        case AgentQSignByUserTransitionResult::wrong_stage:
            return AgentQSignByUserConfirmationResult::wrong_stage;
        case AgentQSignByUserTransitionResult::invalid_argument:
            return AgentQSignByUserConfirmationResult::invalid_argument;
        case AgentQSignByUserTransitionResult::invalid_session:
            return AgentQSignByUserConfirmationResult::invalid_session;
        case AgentQSignByUserTransitionResult::invalid_deadline:
            return AgentQSignByUserConfirmationResult::invalid_deadline;
        case AgentQSignByUserTransitionResult::deadline_expired:
            return AgentQSignByUserConfirmationResult::deadline_expired;
        case AgentQSignByUserTransitionResult::deadline_not_reached:
            return AgentQSignByUserConfirmationResult::deadline_not_reached;
        case AgentQSignByUserTransitionResult::session_still_active:
            return AgentQSignByUserConfirmationResult::session_still_active;
        case AgentQSignByUserTransitionResult::history_error:
            return AgentQSignByUserConfirmationResult::history_error;
        case AgentQSignByUserTransitionResult::stale_state:
            return AgentQSignByUserConfirmationResult::stale_state;
        case AgentQSignByUserTransitionResult::busy:
            return AgentQSignByUserConfirmationResult::busy;
        case AgentQSignByUserTransitionResult::output_too_small:
        case AgentQSignByUserTransitionResult::payload_unavailable:
        case AgentQSignByUserTransitionResult::payload_not_consumed:
            return AgentQSignByUserConfirmationResult::wrong_stage;
    }
    return AgentQSignByUserConfirmationResult::wrong_stage;
}

bool signature_pin_active()
{
    const AgentQLocalPinAuthSnapshot snapshot = local_pin_auth_snapshot(0);
    return snapshot.flow_active &&
           snapshot.purpose == AgentQLocalPinAuthPurpose::sign_by_user;
}

bool signature_pin_stage(AgentQLocalPinAuthStage stage)
{
    const AgentQLocalPinAuthSnapshot snapshot = local_pin_auth_snapshot(0);
    return snapshot.flow_active &&
           snapshot.purpose == AgentQLocalPinAuthPurpose::sign_by_user &&
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
    const AgentQSignByUserFlowSnapshot& expected,
    AgentQSignByUserStage stage)
{
    const AgentQSignByUserFlowSnapshot current =
        sign_by_user_flow_snapshot();
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
    AgentQSignByUserStage flow_stage)
{
    return g_signature_pin_binding.active &&
           signature_pin_stage(pin_stage) &&
           local_pin_auth_sign_by_user_matches(g_signature_pin_binding.pin) &&
           flow_matches_expected(g_signature_pin_binding.flow, flow_stage);
}

void clear_signature_pin_if_active()
{
    if (signature_pin_active()) {
        local_pin_auth_clear_flow();
    }
    g_signature_pin_binding = {};
}

AgentQSignByUserConfirmationResult clear_expected_flow_and_pin(
    const AgentQSignByUserFlowSnapshot& expected)
{
    clear_signature_pin_if_active();
    if (!flow_matches_expected(expected, AgentQSignByUserStage::pin_entry)) {
        return AgentQSignByUserConfirmationResult::stale_state;
    }
    return map_transition(sign_by_user_flow_cancel_for_pin_loss());
}

AgentQSignByUserConfirmationResult
record_verified_pin_and_write_history(
    TickType_t now,
    AgentQSignByUserHistoryWriteFn write_fn,
    void* context,
    const AgentQSignByUserFlowSnapshot& expected)
{
    if (write_fn == nullptr) {
        return AgentQSignByUserConfirmationResult::invalid_argument;
    }
    if (!flow_matches_expected(expected, AgentQSignByUserStage::pin_entry)) {
        return AgentQSignByUserConfirmationResult::stale_state;
    }

    const AgentQSignByUserTransitionResult result =
        sign_by_user_flow_record_pin_verified_and_write_confirmation_history(
            now,
            write_fn,
            context);
    clear_signature_pin_if_active();
    return map_transition(result);
}

}  // namespace

AgentQSignByUserConfirmationResult
sign_by_user_confirmation_accept_review_and_begin_pin(
    TickType_t now,
    TickType_t pin_deadline)
{
    const AgentQSignByUserFlowSnapshot flow =
        sign_by_user_flow_snapshot();
    if (!flow.active) {
        return AgentQSignByUserConfirmationResult::inactive;
    }
    if (flow.stage != AgentQSignByUserStage::reviewing) {
        return AgentQSignByUserConfirmationResult::wrong_stage;
    }
    if (pin_deadline == 0) {
        return AgentQSignByUserConfirmationResult::invalid_deadline;
    }
    if (local_pin_auth_flow_active()) {
        return AgentQSignByUserConfirmationResult::local_pin_busy;
    }
    const TickType_t capped_pin_deadline =
        cap_to_request_deadline(flow.request_deadline, pin_deadline);
    SignaturePinBinding next_binding = {};
    next_binding.active = true;
    next_binding.pin.token = next_signature_pin_token();
    next_binding.flow = flow;
    if (!local_pin_auth_begin_sign_by_user(next_binding.pin, capped_pin_deadline)) {
        return AgentQSignByUserConfirmationResult::local_pin_unavailable;
    }

    const AgentQSignByUserTransitionResult accepted =
        sign_by_user_flow_accept_review(now, capped_pin_deadline);
    if (accepted != AgentQSignByUserTransitionResult::ok) {
        local_pin_auth_clear_flow();
        return map_transition(accepted);
    }
    g_signature_pin_binding = next_binding;
    return AgentQSignByUserConfirmationResult::ok;
}

AgentQSignByUserConfirmationResult
sign_by_user_confirmation_complete_pin_verify_job_and_write_history(
    const AgentQLocalAuthWorkerResult& worker_result,
    TickType_t now,
    TickType_t retry_deadline,
    TickType_t lockout_until,
    AgentQSignByUserHistoryWriteFn write_fn,
    void* context)
{
    if (!signature_pin_bound_to_flow(
            AgentQLocalPinAuthStage::pin_verifying,
            AgentQSignByUserStage::pin_entry)) {
        return AgentQSignByUserConfirmationResult::wrong_stage;
    }
    const AgentQSignByUserFlowSnapshot expected = g_signature_pin_binding.flow;
    if (write_fn == nullptr) {
        clear_expected_flow_and_pin(expected);
        return AgentQSignByUserConfirmationResult::invalid_argument;
    }
    if (sign_by_user_flow_deadline_reached(now)) {
        clear_signature_pin_if_active();
        const AgentQSignByUserTransitionResult timeout =
            sign_by_user_flow_record_timeout(now);
        return timeout == AgentQSignByUserTransitionResult::ok
                   ? AgentQSignByUserConfirmationResult::deadline_expired
                   : map_transition(timeout);
    }

    const AgentQLocalPinAuthSignatureVerifyResult result =
        local_pin_auth_complete_sign_by_user_verify_job(
            worker_result,
            cap_to_request_deadline(expected.request_deadline, retry_deadline),
            lockout_until);
    switch (result) {
        case AgentQLocalPinAuthSignatureVerifyResult::verified:
            return record_verified_pin_and_write_history(now, write_fn, context, expected);
        case AgentQLocalPinAuthSignatureVerifyResult::not_ready:
            return AgentQSignByUserConfirmationResult::not_ready;
        case AgentQLocalPinAuthSignatureVerifyResult::auth_unavailable:
            clear_expected_flow_and_pin(expected);
            return AgentQSignByUserConfirmationResult::auth_unavailable;
        case AgentQLocalPinAuthSignatureVerifyResult::locked: {
            const AgentQSignByUserTransitionResult refresh =
                sign_by_user_flow_refresh_pin_deadline(retry_deadline);
            if (refresh != AgentQSignByUserTransitionResult::ok) {
                clear_signature_pin_if_active();
                return map_transition(refresh);
            }
            return AgentQSignByUserConfirmationResult::locked;
        }
        case AgentQLocalPinAuthSignatureVerifyResult::wrong_pin: {
            const AgentQSignByUserTransitionResult refresh =
                sign_by_user_flow_refresh_pin_deadline(retry_deadline);
            if (refresh != AgentQSignByUserTransitionResult::ok) {
                clear_signature_pin_if_active();
                return map_transition(refresh);
            }
            return AgentQSignByUserConfirmationResult::wrong_pin;
        }
    }
    return AgentQSignByUserConfirmationResult::wrong_stage;
}

AgentQSignByUserConfirmationResult
sign_by_user_confirmation_mark_pin_verification_started()
{
    if (!signature_pin_bound_to_flow(
            AgentQLocalPinAuthStage::pin_verifying,
            AgentQSignByUserStage::pin_entry)) {
        return AgentQSignByUserConfirmationResult::wrong_stage;
    }
    return map_transition(sign_by_user_flow_pause_pin_deadline());
}

AgentQSignByUserConfirmationResult
sign_by_user_confirmation_record_device_rejected()
{
    clear_signature_pin_if_active();
    return map_transition(sign_by_user_flow_record_device_rejected());
}

AgentQSignByUserConfirmationResult
sign_by_user_confirmation_record_timeout(TickType_t now)
{
    clear_signature_pin_if_active();
    return map_transition(sign_by_user_flow_record_timeout(now));
}

AgentQSignByUserConfirmationResult
sign_by_user_confirmation_cancel_for_disconnect(const char* session_id)
{
    if (signature_pin_active() &&
        (!g_signature_pin_binding.active ||
         !local_pin_auth_sign_by_user_matches(g_signature_pin_binding.pin))) {
        clear_signature_pin_if_active();
    }
    const AgentQSignByUserTransitionResult result =
        sign_by_user_flow_cancel_for_disconnect(session_id);
    if (result != AgentQSignByUserTransitionResult::busy) {
        clear_signature_pin_if_active();
    }
    return map_transition(result);
}

AgentQSignByUserConfirmationResult
sign_by_user_confirmation_cancel_for_session_loss()
{
    if (signature_pin_active() &&
        (!g_signature_pin_binding.active ||
         !local_pin_auth_sign_by_user_matches(g_signature_pin_binding.pin))) {
        clear_signature_pin_if_active();
    }
    const AgentQSignByUserTransitionResult result =
        sign_by_user_flow_cancel_for_session_loss();
    if (result != AgentQSignByUserTransitionResult::busy) {
        clear_signature_pin_if_active();
    }
    return map_transition(result);
}

AgentQSignByUserConfirmationResult
sign_by_user_confirmation_cancel_for_pin_loss()
{
    if (!signature_pin_active()) {
        return AgentQSignByUserConfirmationResult::inactive;
    }
    if (!g_signature_pin_binding.active ||
        !local_pin_auth_sign_by_user_matches(g_signature_pin_binding.pin)) {
        clear_signature_pin_if_active();
        return map_transition(sign_by_user_flow_cancel_for_pin_loss());
    }
    return clear_expected_flow_and_pin(g_signature_pin_binding.flow);
}

bool sign_by_user_confirmation_pin_active()
{
    return signature_pin_active();
}

}  // namespace agent_q
