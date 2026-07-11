#include "user_signing_confirmation.h"

#include <string.h>

#include "local_pin_auth.h"
#include "local_pin_auth_signature_internal.h"

namespace signing {

namespace {

struct SignaturePinBinding {
    bool active = false;
    LocalPinAuthSignatureBinding pin = {};
    UserSigningFlowCoreSnapshot flow = {};
};

SignaturePinBinding g_signature_pin_binding;
uint32_t g_next_signature_pin_token = 1;

UserSigningConfirmationResult map_transition(
    UserSigningTransitionResult result)
{
    switch (result) {
        case UserSigningTransitionResult::ok:
            return UserSigningConfirmationResult::ok;
        case UserSigningTransitionResult::inactive:
            return UserSigningConfirmationResult::inactive;
        case UserSigningTransitionResult::wrong_stage:
            return UserSigningConfirmationResult::wrong_stage;
        case UserSigningTransitionResult::invalid_argument:
            return UserSigningConfirmationResult::invalid_argument;
        case UserSigningTransitionResult::invalid_session:
            return UserSigningConfirmationResult::invalid_session;
        case UserSigningTransitionResult::invalid_deadline:
            return UserSigningConfirmationResult::invalid_deadline;
        case UserSigningTransitionResult::deadline_expired:
            return UserSigningConfirmationResult::deadline_expired;
        case UserSigningTransitionResult::deadline_not_reached:
            return UserSigningConfirmationResult::deadline_not_reached;
        case UserSigningTransitionResult::session_still_active:
            return UserSigningConfirmationResult::session_still_active;
        case UserSigningTransitionResult::history_error:
            return UserSigningConfirmationResult::history_error;
        case UserSigningTransitionResult::stale_state:
            return UserSigningConfirmationResult::stale_state;
        case UserSigningTransitionResult::busy:
            return UserSigningConfirmationResult::busy;
        case UserSigningTransitionResult::output_too_small:
        case UserSigningTransitionResult::payload_unavailable:
        case UserSigningTransitionResult::payload_not_consumed:
            return UserSigningConfirmationResult::wrong_stage;
    }
    return UserSigningConfirmationResult::wrong_stage;
}

bool signature_pin_active()
{
    const LocalPinAuthSnapshot snapshot = local_pin_auth_snapshot(0);
    return snapshot.flow_active &&
           snapshot.purpose == LocalPinAuthPurpose::user_signing;
}

bool signature_pin_stage(LocalPinAuthStage stage)
{
    const LocalPinAuthSnapshot snapshot = local_pin_auth_snapshot(0);
    return snapshot.flow_active &&
           snapshot.purpose == LocalPinAuthPurpose::user_signing &&
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
    const UserSigningFlowCoreSnapshot& expected,
    UserSigningStage stage)
{
    const UserSigningFlowCoreSnapshot current =
        user_signing_flow_core_snapshot();
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
    LocalPinAuthStage pin_stage,
    UserSigningStage flow_stage)
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

UserSigningConfirmationResult clear_expected_flow_and_pin(
    const UserSigningFlowCoreSnapshot& expected)
{
    clear_signature_pin_if_active();
    if (!flow_matches_expected(expected, UserSigningStage::pin_entry)) {
        return UserSigningConfirmationResult::stale_state;
    }
    return map_transition(user_signing_flow_cancel_for_pin_loss());
}

UserSigningConfirmationResult
record_verified_pin_and_write_history(
    TickType_t now,
    UserSigningHistoryWriteFn write_fn,
    void* context,
    const UserSigningFlowCoreSnapshot& expected)
{
    if (write_fn == nullptr) {
        return UserSigningConfirmationResult::invalid_argument;
    }
    if (!flow_matches_expected(expected, UserSigningStage::pin_entry)) {
        return UserSigningConfirmationResult::stale_state;
    }

    const UserSigningTransitionResult result =
        user_signing_flow_record_pin_verified_and_write_confirmation_history(
            now,
            write_fn,
            context);
    clear_signature_pin_if_active();
    return map_transition(result);
}

}  // namespace

UserSigningConfirmationResult
user_signing_confirmation_accept_review_and_begin_pin(
    TickType_t now,
    TimeoutWindow pin_input_window)
{
    if (local_pin_auth_flow_active()) {
        return UserSigningConfirmationResult::local_pin_busy;
    }
    TimeoutWindow capped_pin_input_window = kTimeoutWindowNone;
    const UserSigningConfirmationResult prepared =
        map_transition(user_signing_flow_prepare_review_pin_input_window(
            now,
            pin_input_window,
            &capped_pin_input_window));
    if (prepared != UserSigningConfirmationResult::ok) {
        return prepared;
    }
    const UserSigningFlowCoreSnapshot flow =
        user_signing_flow_core_snapshot();
    SignaturePinBinding next_binding = {};
    next_binding.active = true;
    next_binding.pin.token = next_signature_pin_token();
    next_binding.flow = flow;
    if (!local_pin_auth_begin_user_signing(
            next_binding.pin,
            now,
            capped_pin_input_window)) {
        return UserSigningConfirmationResult::local_pin_unavailable;
    }

    const UserSigningTransitionResult accepted =
        user_signing_flow_accept_review(now, capped_pin_input_window);
    if (accepted != UserSigningTransitionResult::ok) {
        local_pin_auth_clear_flow();
        return map_transition(accepted);
    }
    g_signature_pin_binding = next_binding;
    return UserSigningConfirmationResult::ok;
}

UserSigningConfirmationResult
user_signing_confirmation_complete_pin_verify_job_and_write_history(
    const LocalAuthWorkerResult& worker_result,
    TickType_t now,
    TickType_t lockout_until,
    bool authorization_available,
    UserSigningHistoryWriteFn write_fn,
    void* context)
{
    const bool bound_to_expected_flow = signature_pin_bound_to_flow(
            LocalPinAuthStage::pin_verifying,
            UserSigningStage::pin_entry);
    const UserSigningFlowCoreSnapshot expected = g_signature_pin_binding.flow;
    const LocalPinAuthSignatureVerifyResult result =
        local_pin_auth_complete_user_signing_verify_job(
            worker_result,
            lockout_until);
    if (!bound_to_expected_flow) {
        if (result != LocalPinAuthSignatureVerifyResult::not_ready) {
            local_pin_auth_clear_flow();
            g_signature_pin_binding = {};
        }
        return UserSigningConfirmationResult::wrong_stage;
    }
    if (result == LocalPinAuthSignatureVerifyResult::not_ready) {
        return UserSigningConfirmationResult::not_ready;
    }
    if (!authorization_available) {
        clear_expected_flow_and_pin(expected);
        return UserSigningConfirmationResult::auth_unavailable;
    }
    if (write_fn == nullptr) {
        clear_expected_flow_and_pin(expected);
        return UserSigningConfirmationResult::invalid_argument;
    }
    if (user_signing_flow_apply_deadline_transition(now)) {
        clear_signature_pin_if_active();
        const UserSigningTransitionResult timeout =
            user_signing_flow_record_timeout(now);
        return timeout == UserSigningTransitionResult::ok
                   ? UserSigningConfirmationResult::deadline_expired
                   : map_transition(timeout);
    }

    switch (result) {
        case LocalPinAuthSignatureVerifyResult::verified:
            return record_verified_pin_and_write_history(now, write_fn, context, expected);
        case LocalPinAuthSignatureVerifyResult::auth_unavailable:
            clear_expected_flow_and_pin(expected);
            return UserSigningConfirmationResult::auth_unavailable;
        case LocalPinAuthSignatureVerifyResult::locked:
            return UserSigningConfirmationResult::locked;
        case LocalPinAuthSignatureVerifyResult::wrong_pin: {
            const UserSigningTransitionResult refresh =
                user_signing_flow_refresh_pin_deadline(now);
            if (refresh != UserSigningTransitionResult::ok) {
                clear_signature_pin_if_active();
                return map_transition(refresh);
            }
            return UserSigningConfirmationResult::wrong_pin;
        }
        case LocalPinAuthSignatureVerifyResult::not_ready:
            break;
    }
    return UserSigningConfirmationResult::wrong_stage;
}

UserSigningConfirmationResult
user_signing_confirmation_mark_pin_verification_started(TickType_t now)
{
    if (!signature_pin_bound_to_flow(
            LocalPinAuthStage::pin_verifying,
            UserSigningStage::pin_entry)) {
        return UserSigningConfirmationResult::wrong_stage;
    }
    return map_transition(user_signing_flow_pause_pin_deadline(now));
}

UserSigningConfirmationResult user_signing_confirmation_return_to_review_from_pin(
    TickType_t now,
    TimeoutWindow review_window)
{
    if (!signature_pin_bound_to_flow(
            LocalPinAuthStage::pin_entry,
            UserSigningStage::pin_entry)) {
        return UserSigningConfirmationResult::wrong_stage;
    }
    const UserSigningTransitionResult result =
        user_signing_flow_return_to_review(now, review_window);
    if (result == UserSigningTransitionResult::ok ||
        result == UserSigningTransitionResult::invalid_session ||
        result == UserSigningTransitionResult::deadline_expired) {
        clear_signature_pin_if_active();
    }
    return map_transition(result);
}

UserSigningConfirmationResult
user_signing_confirmation_record_device_rejected()
{
    const UserSigningTransitionResult result =
        user_signing_flow_record_device_rejected();
    if (result == UserSigningTransitionResult::ok) {
        clear_signature_pin_if_active();
    }
    return map_transition(result);
}

UserSigningConfirmationResult
user_signing_confirmation_record_timeout(TickType_t now)
{
    clear_signature_pin_if_active();
    return map_transition(user_signing_flow_record_timeout(now));
}

UserSigningConfirmationResult
user_signing_confirmation_cancel_for_disconnect(const char* session_id)
{
    if (signature_pin_active() &&
        (!g_signature_pin_binding.active ||
         !local_pin_auth_user_signing_matches(g_signature_pin_binding.pin))) {
        clear_signature_pin_if_active();
    }
    const UserSigningTransitionResult result =
        user_signing_flow_cancel_for_disconnect(session_id);
    if (result != UserSigningTransitionResult::busy) {
        clear_signature_pin_if_active();
    }
    return map_transition(result);
}

UserSigningConfirmationResult
user_signing_confirmation_cancel_for_session_loss()
{
    if (signature_pin_active() &&
        (!g_signature_pin_binding.active ||
         !local_pin_auth_user_signing_matches(g_signature_pin_binding.pin))) {
        clear_signature_pin_if_active();
    }
    const UserSigningTransitionResult result =
        user_signing_flow_cancel_for_session_loss();
    if (result != UserSigningTransitionResult::busy) {
        clear_signature_pin_if_active();
    }
    return map_transition(result);
}

UserSigningConfirmationResult
user_signing_confirmation_cancel_for_pin_loss()
{
    if (!signature_pin_active()) {
        return UserSigningConfirmationResult::inactive;
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

}  // namespace signing
