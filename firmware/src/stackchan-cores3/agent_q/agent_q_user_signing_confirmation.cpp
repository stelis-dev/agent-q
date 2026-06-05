#include "agent_q_user_signing_confirmation.h"

#include <string.h>

#include "agent_q_local_pin_auth.h"
#include "agent_q_local_pin_auth_signature_internal.h"

namespace agent_q {

namespace {

struct SignaturePinBinding {
    bool active = false;
    AgentQLocalPinAuthSignatureBinding pin = {};
    AgentQUserSigningFlowSnapshot flow = {};
};

SignaturePinBinding g_signature_pin_binding;
uint32_t g_next_signature_pin_token = 1;

AgentQUserSigningConfirmationResult map_transition(
    AgentQUserSigningTransitionResult result)
{
    switch (result) {
        case AgentQUserSigningTransitionResult::ok:
            return AgentQUserSigningConfirmationResult::ok;
        case AgentQUserSigningTransitionResult::inactive:
            return AgentQUserSigningConfirmationResult::inactive;
        case AgentQUserSigningTransitionResult::wrong_stage:
            return AgentQUserSigningConfirmationResult::wrong_stage;
        case AgentQUserSigningTransitionResult::invalid_argument:
            return AgentQUserSigningConfirmationResult::invalid_argument;
        case AgentQUserSigningTransitionResult::invalid_session:
            return AgentQUserSigningConfirmationResult::invalid_session;
        case AgentQUserSigningTransitionResult::invalid_deadline:
            return AgentQUserSigningConfirmationResult::invalid_deadline;
        case AgentQUserSigningTransitionResult::deadline_expired:
            return AgentQUserSigningConfirmationResult::deadline_expired;
        case AgentQUserSigningTransitionResult::deadline_not_reached:
            return AgentQUserSigningConfirmationResult::deadline_not_reached;
        case AgentQUserSigningTransitionResult::session_still_active:
            return AgentQUserSigningConfirmationResult::session_still_active;
        case AgentQUserSigningTransitionResult::history_error:
            return AgentQUserSigningConfirmationResult::history_error;
        case AgentQUserSigningTransitionResult::stale_state:
            return AgentQUserSigningConfirmationResult::stale_state;
        case AgentQUserSigningTransitionResult::busy:
            return AgentQUserSigningConfirmationResult::busy;
        case AgentQUserSigningTransitionResult::output_too_small:
        case AgentQUserSigningTransitionResult::payload_unavailable:
        case AgentQUserSigningTransitionResult::payload_not_consumed:
            return AgentQUserSigningConfirmationResult::wrong_stage;
    }
    return AgentQUserSigningConfirmationResult::wrong_stage;
}

bool signature_pin_active()
{
    const AgentQLocalPinAuthSnapshot snapshot = local_pin_auth_snapshot(0);
    return snapshot.flow_active &&
           snapshot.purpose == AgentQLocalPinAuthPurpose::user_signing;
}

bool signature_pin_stage(AgentQLocalPinAuthStage stage)
{
    const AgentQLocalPinAuthSnapshot snapshot = local_pin_auth_snapshot(0);
    return snapshot.flow_active &&
           snapshot.purpose == AgentQLocalPinAuthPurpose::user_signing &&
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
    const AgentQUserSigningFlowSnapshot& expected,
    AgentQUserSigningStage stage)
{
    const AgentQUserSigningFlowSnapshot current =
        user_signing_flow_snapshot();
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
    AgentQUserSigningStage flow_stage)
{
    return g_signature_pin_binding.active &&
           signature_pin_stage(pin_stage) &&
           local_pin_auth_user_signing_matches(g_signature_pin_binding.pin) &&
           flow_matches_expected(g_signature_pin_binding.flow, flow_stage);
}

void clear_signature_pin_if_active()
{
    if (signature_pin_active()) {
        local_pin_auth_clear_flow();
    }
    g_signature_pin_binding = {};
}

AgentQUserSigningConfirmationResult clear_expected_flow_and_pin(
    const AgentQUserSigningFlowSnapshot& expected)
{
    clear_signature_pin_if_active();
    if (!flow_matches_expected(expected, AgentQUserSigningStage::pin_entry)) {
        return AgentQUserSigningConfirmationResult::stale_state;
    }
    return map_transition(user_signing_flow_cancel_for_pin_loss());
}

AgentQUserSigningConfirmationResult
record_verified_pin_and_write_history(
    TickType_t now,
    AgentQUserSigningHistoryWriteFn write_fn,
    void* context,
    const AgentQUserSigningFlowSnapshot& expected)
{
    if (write_fn == nullptr) {
        return AgentQUserSigningConfirmationResult::invalid_argument;
    }
    if (!flow_matches_expected(expected, AgentQUserSigningStage::pin_entry)) {
        return AgentQUserSigningConfirmationResult::stale_state;
    }

    const AgentQUserSigningTransitionResult result =
        user_signing_flow_record_pin_verified_and_write_confirmation_history(
            now,
            write_fn,
            context);
    clear_signature_pin_if_active();
    return map_transition(result);
}

}  // namespace

AgentQUserSigningConfirmationResult
user_signing_confirmation_accept_review_and_begin_pin(
    TickType_t now,
    TickType_t pin_deadline)
{
    const AgentQUserSigningFlowSnapshot flow =
        user_signing_flow_snapshot();
    if (!flow.active) {
        return AgentQUserSigningConfirmationResult::inactive;
    }
    if (flow.stage != AgentQUserSigningStage::reviewing) {
        return AgentQUserSigningConfirmationResult::wrong_stage;
    }
    if (pin_deadline == 0) {
        return AgentQUserSigningConfirmationResult::invalid_deadline;
    }
    if (local_pin_auth_flow_active()) {
        return AgentQUserSigningConfirmationResult::local_pin_busy;
    }
    const TickType_t capped_pin_deadline =
        cap_to_request_deadline(flow.request_deadline, pin_deadline);
    SignaturePinBinding next_binding = {};
    next_binding.active = true;
    next_binding.pin.token = next_signature_pin_token();
    next_binding.flow = flow;
    if (!local_pin_auth_begin_user_signing(next_binding.pin, capped_pin_deadline)) {
        return AgentQUserSigningConfirmationResult::local_pin_unavailable;
    }

    const AgentQUserSigningTransitionResult accepted =
        user_signing_flow_accept_review(now, capped_pin_deadline);
    if (accepted != AgentQUserSigningTransitionResult::ok) {
        local_pin_auth_clear_flow();
        return map_transition(accepted);
    }
    g_signature_pin_binding = next_binding;
    return AgentQUserSigningConfirmationResult::ok;
}

AgentQUserSigningConfirmationResult
user_signing_confirmation_complete_pin_verify_job_and_write_history(
    const AgentQLocalAuthWorkerResult& worker_result,
    TickType_t now,
    TickType_t retry_deadline,
    TickType_t lockout_until,
    AgentQUserSigningHistoryWriteFn write_fn,
    void* context)
{
    if (!signature_pin_bound_to_flow(
            AgentQLocalPinAuthStage::pin_verifying,
            AgentQUserSigningStage::pin_entry)) {
        return AgentQUserSigningConfirmationResult::wrong_stage;
    }
    const AgentQUserSigningFlowSnapshot expected = g_signature_pin_binding.flow;
    if (write_fn == nullptr) {
        clear_expected_flow_and_pin(expected);
        return AgentQUserSigningConfirmationResult::invalid_argument;
    }
    if (user_signing_flow_deadline_reached(now)) {
        clear_signature_pin_if_active();
        const AgentQUserSigningTransitionResult timeout =
            user_signing_flow_record_timeout(now);
        return timeout == AgentQUserSigningTransitionResult::ok
                   ? AgentQUserSigningConfirmationResult::deadline_expired
                   : map_transition(timeout);
    }

    const AgentQLocalPinAuthSignatureVerifyResult result =
        local_pin_auth_complete_user_signing_verify_job(
            worker_result,
            cap_to_request_deadline(expected.request_deadline, retry_deadline),
            lockout_until);
    switch (result) {
        case AgentQLocalPinAuthSignatureVerifyResult::verified:
            return record_verified_pin_and_write_history(now, write_fn, context, expected);
        case AgentQLocalPinAuthSignatureVerifyResult::not_ready:
            return AgentQUserSigningConfirmationResult::not_ready;
        case AgentQLocalPinAuthSignatureVerifyResult::auth_unavailable:
            clear_expected_flow_and_pin(expected);
            return AgentQUserSigningConfirmationResult::auth_unavailable;
        case AgentQLocalPinAuthSignatureVerifyResult::locked: {
            const AgentQUserSigningTransitionResult refresh =
                user_signing_flow_refresh_pin_deadline(retry_deadline);
            if (refresh != AgentQUserSigningTransitionResult::ok) {
                clear_signature_pin_if_active();
                return map_transition(refresh);
            }
            return AgentQUserSigningConfirmationResult::locked;
        }
        case AgentQLocalPinAuthSignatureVerifyResult::wrong_pin: {
            const AgentQUserSigningTransitionResult refresh =
                user_signing_flow_refresh_pin_deadline(retry_deadline);
            if (refresh != AgentQUserSigningTransitionResult::ok) {
                clear_signature_pin_if_active();
                return map_transition(refresh);
            }
            return AgentQUserSigningConfirmationResult::wrong_pin;
        }
    }
    return AgentQUserSigningConfirmationResult::wrong_stage;
}

AgentQUserSigningConfirmationResult
user_signing_confirmation_mark_pin_verification_started()
{
    if (!signature_pin_bound_to_flow(
            AgentQLocalPinAuthStage::pin_verifying,
            AgentQUserSigningStage::pin_entry)) {
        return AgentQUserSigningConfirmationResult::wrong_stage;
    }
    return map_transition(user_signing_flow_pause_pin_deadline());
}

AgentQUserSigningConfirmationResult
user_signing_confirmation_record_device_rejected()
{
    clear_signature_pin_if_active();
    return map_transition(user_signing_flow_record_device_rejected());
}

AgentQUserSigningConfirmationResult
user_signing_confirmation_record_timeout(TickType_t now)
{
    clear_signature_pin_if_active();
    return map_transition(user_signing_flow_record_timeout(now));
}

AgentQUserSigningConfirmationResult
user_signing_confirmation_cancel_for_disconnect(const char* session_id)
{
    if (signature_pin_active() &&
        (!g_signature_pin_binding.active ||
         !local_pin_auth_user_signing_matches(g_signature_pin_binding.pin))) {
        clear_signature_pin_if_active();
    }
    const AgentQUserSigningTransitionResult result =
        user_signing_flow_cancel_for_disconnect(session_id);
    if (result != AgentQUserSigningTransitionResult::busy) {
        clear_signature_pin_if_active();
    }
    return map_transition(result);
}

AgentQUserSigningConfirmationResult
user_signing_confirmation_cancel_for_session_loss()
{
    if (signature_pin_active() &&
        (!g_signature_pin_binding.active ||
         !local_pin_auth_user_signing_matches(g_signature_pin_binding.pin))) {
        clear_signature_pin_if_active();
    }
    const AgentQUserSigningTransitionResult result =
        user_signing_flow_cancel_for_session_loss();
    if (result != AgentQUserSigningTransitionResult::busy) {
        clear_signature_pin_if_active();
    }
    return map_transition(result);
}

AgentQUserSigningConfirmationResult
user_signing_confirmation_cancel_for_pin_loss()
{
    if (!signature_pin_active()) {
        return AgentQUserSigningConfirmationResult::inactive;
    }
    if (!g_signature_pin_binding.active ||
        !local_pin_auth_user_signing_matches(g_signature_pin_binding.pin)) {
        clear_signature_pin_if_active();
        return map_transition(user_signing_flow_cancel_for_pin_loss());
    }
    return clear_expected_flow_and_pin(g_signature_pin_binding.flow);
}

bool user_signing_confirmation_pin_active()
{
    return signature_pin_active();
}

}  // namespace agent_q
