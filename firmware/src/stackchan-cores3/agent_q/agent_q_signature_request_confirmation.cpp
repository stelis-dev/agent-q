#include "agent_q_signature_request_confirmation.h"

#include <string.h>

#include "agent_q_local_pin_auth.h"
#include "agent_q_local_pin_auth_signature_internal.h"

namespace agent_q {

namespace {

struct SignaturePinBinding {
    bool active = false;
    AgentQLocalPinAuthSignatureBinding pin = {};
    AgentQSignatureRequestFlowSnapshot flow = {};
};

SignaturePinBinding g_signature_pin_binding;
uint32_t g_next_signature_pin_token = 1;

AgentQSignatureRequestConfirmationResult map_transition(
    AgentQSignatureRequestTransitionResult result)
{
    switch (result) {
        case AgentQSignatureRequestTransitionResult::ok:
            return AgentQSignatureRequestConfirmationResult::ok;
        case AgentQSignatureRequestTransitionResult::inactive:
            return AgentQSignatureRequestConfirmationResult::inactive;
        case AgentQSignatureRequestTransitionResult::wrong_stage:
            return AgentQSignatureRequestConfirmationResult::wrong_stage;
        case AgentQSignatureRequestTransitionResult::invalid_argument:
            return AgentQSignatureRequestConfirmationResult::invalid_argument;
        case AgentQSignatureRequestTransitionResult::invalid_session:
            return AgentQSignatureRequestConfirmationResult::invalid_session;
        case AgentQSignatureRequestTransitionResult::invalid_deadline:
            return AgentQSignatureRequestConfirmationResult::invalid_deadline;
        case AgentQSignatureRequestTransitionResult::deadline_expired:
            return AgentQSignatureRequestConfirmationResult::deadline_expired;
        case AgentQSignatureRequestTransitionResult::deadline_not_reached:
            return AgentQSignatureRequestConfirmationResult::deadline_not_reached;
        case AgentQSignatureRequestTransitionResult::session_still_active:
            return AgentQSignatureRequestConfirmationResult::session_still_active;
        case AgentQSignatureRequestTransitionResult::history_error:
            return AgentQSignatureRequestConfirmationResult::history_error;
        case AgentQSignatureRequestTransitionResult::stale_state:
            return AgentQSignatureRequestConfirmationResult::stale_state;
        case AgentQSignatureRequestTransitionResult::busy:
            return AgentQSignatureRequestConfirmationResult::busy;
        case AgentQSignatureRequestTransitionResult::output_too_small:
        case AgentQSignatureRequestTransitionResult::payload_unavailable:
        case AgentQSignatureRequestTransitionResult::payload_not_consumed:
            return AgentQSignatureRequestConfirmationResult::wrong_stage;
    }
    return AgentQSignatureRequestConfirmationResult::wrong_stage;
}

bool signature_pin_active()
{
    const AgentQLocalPinAuthSnapshot snapshot = local_pin_auth_snapshot(0);
    return snapshot.flow_active &&
           snapshot.purpose == AgentQLocalPinAuthPurpose::signature_request;
}

bool signature_pin_stage(AgentQLocalPinAuthStage stage)
{
    const AgentQLocalPinAuthSnapshot snapshot = local_pin_auth_snapshot(0);
    return snapshot.flow_active &&
           snapshot.purpose == AgentQLocalPinAuthPurpose::signature_request &&
           snapshot.stage == stage;
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
    const AgentQSignatureRequestFlowSnapshot& expected,
    AgentQSignatureRequestStage stage)
{
    const AgentQSignatureRequestFlowSnapshot current =
        signature_request_flow_snapshot();
    return expected.active &&
           current.active &&
           current.stage == stage &&
           strcmp(current.request_id, expected.request_id) == 0 &&
           strcmp(current.session_id, expected.session_id) == 0 &&
           strcmp(current.chain, expected.chain) == 0 &&
           strcmp(current.method, expected.method) == 0 &&
           strcmp(current.network, expected.network) == 0 &&
           strcmp(current.payload_digest, expected.payload_digest) == 0 &&
           current.confirmation_deadline == expected.confirmation_deadline &&
           current.signable_payload_size == expected.signable_payload_size &&
           current.signable_payload_available == expected.signable_payload_available;
}

bool signature_pin_bound_to_flow(
    AgentQLocalPinAuthStage pin_stage,
    AgentQSignatureRequestStage flow_stage)
{
    return g_signature_pin_binding.active &&
           signature_pin_stage(pin_stage) &&
           local_pin_auth_signature_request_matches(g_signature_pin_binding.pin) &&
           flow_matches_expected(g_signature_pin_binding.flow, flow_stage);
}

void clear_signature_pin_if_active()
{
    if (signature_pin_active()) {
        local_pin_auth_clear_flow();
    }
    g_signature_pin_binding = {};
}

AgentQSignatureRequestConfirmationResult clear_expected_flow_and_pin(
    const AgentQSignatureRequestFlowSnapshot& expected)
{
    clear_signature_pin_if_active();
    if (!flow_matches_expected(expected, AgentQSignatureRequestStage::pin_entry)) {
        return AgentQSignatureRequestConfirmationResult::stale_state;
    }
    return map_transition(signature_request_flow_cancel_for_pin_loss());
}

AgentQSignatureRequestConfirmationResult
record_verified_pin_and_write_history(
    TickType_t now,
    AgentQSignatureRequestHistoryWriteFn write_fn,
    void* context,
    const AgentQSignatureRequestFlowSnapshot& expected)
{
    if (write_fn == nullptr) {
        return AgentQSignatureRequestConfirmationResult::invalid_argument;
    }
    if (!flow_matches_expected(expected, AgentQSignatureRequestStage::pin_entry)) {
        return AgentQSignatureRequestConfirmationResult::stale_state;
    }

    const AgentQSignatureRequestTransitionResult result =
        signature_request_flow_record_pin_verified_and_write_confirmation_history(
            now,
            write_fn,
            context);
    clear_signature_pin_if_active();
    return map_transition(result);
}

}  // namespace

AgentQSignatureRequestConfirmationResult
signature_request_confirmation_accept_review_and_begin_pin(
    TickType_t now,
    TickType_t pin_deadline)
{
    const AgentQSignatureRequestFlowSnapshot flow =
        signature_request_flow_snapshot();
    if (!flow.active) {
        return AgentQSignatureRequestConfirmationResult::inactive;
    }
    if (flow.stage != AgentQSignatureRequestStage::reviewing) {
        return AgentQSignatureRequestConfirmationResult::wrong_stage;
    }
    if (pin_deadline == 0) {
        return AgentQSignatureRequestConfirmationResult::invalid_deadline;
    }
    if (local_pin_auth_flow_active()) {
        return AgentQSignatureRequestConfirmationResult::local_pin_busy;
    }
    SignaturePinBinding next_binding = {};
    next_binding.active = true;
    next_binding.pin.token = next_signature_pin_token();
    next_binding.flow = flow;
    if (!local_pin_auth_begin_signature_request(next_binding.pin, pin_deadline)) {
        return AgentQSignatureRequestConfirmationResult::local_pin_unavailable;
    }

    const AgentQSignatureRequestTransitionResult accepted =
        signature_request_flow_accept_review(now, pin_deadline);
    if (accepted != AgentQSignatureRequestTransitionResult::ok) {
        local_pin_auth_clear_flow();
        return map_transition(accepted);
    }
    g_signature_pin_binding = next_binding;
    return AgentQSignatureRequestConfirmationResult::ok;
}

AgentQSignatureRequestConfirmationResult
signature_request_confirmation_complete_pin_verify_job_and_write_history(
    const AgentQLocalAuthWorkerResult& worker_result,
    TickType_t now,
    TickType_t retry_deadline,
    TickType_t lockout_until,
    AgentQSignatureRequestHistoryWriteFn write_fn,
    void* context)
{
    if (!signature_pin_bound_to_flow(
            AgentQLocalPinAuthStage::pin_verifying,
            AgentQSignatureRequestStage::pin_entry)) {
        return AgentQSignatureRequestConfirmationResult::wrong_stage;
    }
    const AgentQSignatureRequestFlowSnapshot expected = g_signature_pin_binding.flow;
    if (write_fn == nullptr) {
        clear_expected_flow_and_pin(expected);
        return AgentQSignatureRequestConfirmationResult::invalid_argument;
    }

    const AgentQLocalPinAuthSignatureVerifyResult result =
        local_pin_auth_complete_signature_request_verify_job(
            worker_result,
            retry_deadline,
            lockout_until);
    switch (result) {
        case AgentQLocalPinAuthSignatureVerifyResult::verified:
            return record_verified_pin_and_write_history(now, write_fn, context, expected);
        case AgentQLocalPinAuthSignatureVerifyResult::not_ready:
            return AgentQSignatureRequestConfirmationResult::not_ready;
        case AgentQLocalPinAuthSignatureVerifyResult::auth_unavailable:
            clear_expected_flow_and_pin(expected);
            return AgentQSignatureRequestConfirmationResult::auth_unavailable;
        case AgentQLocalPinAuthSignatureVerifyResult::locked: {
            if (signature_request_flow_deadline_reached(now)) {
                clear_signature_pin_if_active();
                const AgentQSignatureRequestTransitionResult timeout =
                    signature_request_flow_record_timeout(now);
                return timeout == AgentQSignatureRequestTransitionResult::ok
                           ? AgentQSignatureRequestConfirmationResult::deadline_expired
                           : map_transition(timeout);
            }
            const AgentQSignatureRequestTransitionResult refresh =
                signature_request_flow_refresh_pin_deadline(retry_deadline);
            if (refresh != AgentQSignatureRequestTransitionResult::ok) {
                clear_signature_pin_if_active();
                return map_transition(refresh);
            }
            return AgentQSignatureRequestConfirmationResult::locked;
        }
        case AgentQLocalPinAuthSignatureVerifyResult::wrong_pin: {
            if (signature_request_flow_deadline_reached(now)) {
                clear_signature_pin_if_active();
                const AgentQSignatureRequestTransitionResult timeout =
                    signature_request_flow_record_timeout(now);
                return timeout == AgentQSignatureRequestTransitionResult::ok
                           ? AgentQSignatureRequestConfirmationResult::deadline_expired
                           : map_transition(timeout);
            }
            const AgentQSignatureRequestTransitionResult refresh =
                signature_request_flow_refresh_pin_deadline(retry_deadline);
            if (refresh != AgentQSignatureRequestTransitionResult::ok) {
                clear_signature_pin_if_active();
                return map_transition(refresh);
            }
            return AgentQSignatureRequestConfirmationResult::wrong_pin;
        }
    }
    return AgentQSignatureRequestConfirmationResult::wrong_stage;
}

AgentQSignatureRequestConfirmationResult
signature_request_confirmation_mark_pin_verification_started()
{
    if (!signature_pin_bound_to_flow(
            AgentQLocalPinAuthStage::pin_verifying,
            AgentQSignatureRequestStage::pin_entry)) {
        return AgentQSignatureRequestConfirmationResult::wrong_stage;
    }
    return map_transition(signature_request_flow_pause_pin_deadline());
}

AgentQSignatureRequestConfirmationResult
signature_request_confirmation_record_device_rejected()
{
    clear_signature_pin_if_active();
    return map_transition(signature_request_flow_record_device_rejected());
}

AgentQSignatureRequestConfirmationResult
signature_request_confirmation_record_timeout(TickType_t now)
{
    clear_signature_pin_if_active();
    return map_transition(signature_request_flow_record_timeout(now));
}

AgentQSignatureRequestConfirmationResult
signature_request_confirmation_cancel_for_disconnect(const char* session_id)
{
    if (signature_pin_active() &&
        (!g_signature_pin_binding.active ||
         !local_pin_auth_signature_request_matches(g_signature_pin_binding.pin))) {
        clear_signature_pin_if_active();
    }
    const AgentQSignatureRequestTransitionResult result =
        signature_request_flow_cancel_for_disconnect(session_id);
    if (result != AgentQSignatureRequestTransitionResult::busy) {
        clear_signature_pin_if_active();
    }
    return map_transition(result);
}

AgentQSignatureRequestConfirmationResult
signature_request_confirmation_cancel_for_session_loss()
{
    if (signature_pin_active() &&
        (!g_signature_pin_binding.active ||
         !local_pin_auth_signature_request_matches(g_signature_pin_binding.pin))) {
        clear_signature_pin_if_active();
    }
    const AgentQSignatureRequestTransitionResult result =
        signature_request_flow_cancel_for_session_loss();
    if (result != AgentQSignatureRequestTransitionResult::busy) {
        clear_signature_pin_if_active();
    }
    return map_transition(result);
}

AgentQSignatureRequestConfirmationResult
signature_request_confirmation_cancel_for_pin_loss()
{
    if (!signature_pin_active()) {
        return AgentQSignatureRequestConfirmationResult::inactive;
    }
    if (!g_signature_pin_binding.active ||
        !local_pin_auth_signature_request_matches(g_signature_pin_binding.pin)) {
        clear_signature_pin_if_active();
        return map_transition(signature_request_flow_cancel_for_pin_loss());
    }
    return clear_expected_flow_and_pin(g_signature_pin_binding.flow);
}

bool signature_request_confirmation_pin_active()
{
    return signature_pin_active();
}

}  // namespace agent_q
