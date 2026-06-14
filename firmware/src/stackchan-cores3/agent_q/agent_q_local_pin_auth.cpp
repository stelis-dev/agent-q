#include "agent_q_local_pin_auth.h"

#include <string.h>

#include "agent_q_bip39.h"
#include "agent_q_human_approval_settings.h"
#include "agent_q_local_auth.h"
#include "agent_q_local_pin_auth_signature_internal.h"
#include "agent_q_pin_attempt.h"
#include "agent_q_signing_mode.h"
#include "freertos/task.h"

namespace agent_q {
namespace {

struct AgentQLocalPinAuthState {
    char pin_entry[kLocalPinBufferSize] = {};
    char new_pin[kLocalPinBufferSize] = {};
    size_t pin_entry_length = 0;
    AgentQLocalPinAuthPurpose purpose = AgentQLocalPinAuthPurpose::none;
    AgentQLocalPinAuthStage stage = AgentQLocalPinAuthStage::none;
    AgentQHumanApprovalInputMode target_human_approval_input_mode = AgentQHumanApprovalInputMode::pin;
    AgentQSigningAuthorizationMode target_signing_authorization_mode = AgentQSigningAuthorizationMode::user;
    uint32_t auth_job_id = 0;
    AgentQTimeoutWindow input_window = kAgentQTimeoutWindowNone;
    AgentQPausedTimeoutWindow paused_input_window = kAgentQPausedTimeoutWindowNone;
    TickType_t verify_ready_at = 0;
    TickType_t commit_ready_at = 0;
    TickType_t worker_deadline = 0;
    AgentQLocalPinAuthSignatureBinding signature_binding = {};

    bool flow_active() const
    {
        return purpose != AgentQLocalPinAuthPurpose::none &&
               stage != AgentQLocalPinAuthStage::none;
    }

    void clear_pin_only()
    {
        wipe_sensitive_buffer(pin_entry, sizeof(pin_entry));
        pin_entry_length = 0;
        verify_ready_at = 0;
        commit_ready_at = 0;
        worker_deadline = 0;
    }

    void clear_new_pin()
    {
        wipe_sensitive_buffer(new_pin, sizeof(new_pin));
    }

    void clear_signature_binding()
    {
        signature_binding = {};
    }

    void clear_flow()
    {
        if (auth_job_id != 0) {
            local_auth_worker_cancel_job(auth_job_id);
        }
        wipe_sensitive_buffer(pin_entry, sizeof(pin_entry));
        wipe_sensitive_buffer(new_pin, sizeof(new_pin));
        pin_entry_length = 0;
        purpose = AgentQLocalPinAuthPurpose::none;
        stage = AgentQLocalPinAuthStage::none;
        target_human_approval_input_mode = AgentQHumanApprovalInputMode::pin;
        target_signing_authorization_mode = AgentQSigningAuthorizationMode::user;
        auth_job_id = 0;
        input_window = kAgentQTimeoutWindowNone;
        paused_input_window = kAgentQPausedTimeoutWindowNone;
        verify_ready_at = 0;
        commit_ready_at = 0;
        worker_deadline = 0;
        clear_signature_binding();
    }

    void set_input_window(AgentQTimeoutWindow window)
    {
        input_window = window;
        paused_input_window = kAgentQPausedTimeoutWindowNone;
    }

    bool pause_input_window(TickType_t now)
    {
        AgentQPausedTimeoutWindow paused = timeout_window_pause_at(input_window, now);
        if (!timeout_paused_window_valid(paused)) {
            return false;
        }
        input_window = kAgentQTimeoutWindowNone;
        paused_input_window = paused;
        return true;
    }

    bool resume_paused_input_window(TickType_t now)
    {
        AgentQTimeoutWindow resumed = timeout_window_resume_at(paused_input_window, now);
        if (!timeout_window_valid(resumed)) {
            return false;
        }
        set_input_window(resumed);
        return true;
    }
};

AgentQLocalPinAuthState g_state;

bool processing_stage(AgentQLocalPinAuthStage stage)
{
    return stage == AgentQLocalPinAuthStage::pin_verifying ||
           stage == AgentQLocalPinAuthStage::committing_setting ||
           stage == AgentQLocalPinAuthStage::committing_pin_change;
}

bool timeout_bound_processing_stage(AgentQLocalPinAuthStage stage)
{
    return stage == AgentQLocalPinAuthStage::pin_verifying ||
           stage == AgentQLocalPinAuthStage::committing_setting ||
           stage == AgentQLocalPinAuthStage::committing_pin_change;
}

AgentQLocalPinAuthLockoutReleaseResult release_lockout_if_elapsed(TickType_t now)
{
    if (!pin_attempt_lockout_elapsed_at(now)) {
        return AgentQLocalPinAuthLockoutReleaseResult::not_released;
    }
    if (timeout_paused_window_valid(g_state.paused_input_window)) {
        if (!g_state.resume_paused_input_window(now)) {
            g_state.clear_flow();
            pin_attempt_clear();
            return AgentQLocalPinAuthLockoutReleaseResult::failed;
        }
        pin_attempt_clear();
        return AgentQLocalPinAuthLockoutReleaseResult::released;
    }
    if (timeout_window_valid(g_state.input_window)) {
        pin_attempt_clear();
        return AgentQLocalPinAuthLockoutReleaseResult::released;
    }
    g_state.clear_flow();
    pin_attempt_clear();
    return AgentQLocalPinAuthLockoutReleaseResult::failed;
}

bool resume_after_wrong_pin(TickType_t now)
{
    if (!g_state.resume_paused_input_window(now)) {
        return false;
    }
    return true;
}

}  // namespace

AgentQLocalPinAuthSnapshot local_pin_auth_snapshot(TickType_t now)
{
    const bool accepts =
        g_state.flow_active() &&
        (g_state.stage == AgentQLocalPinAuthStage::pin_entry ||
         g_state.stage == AgentQLocalPinAuthStage::new_pin_entry ||
         g_state.stage == AgentQLocalPinAuthStage::repeat_pin_entry);
    return AgentQLocalPinAuthSnapshot{
        g_state.purpose,
        g_state.stage,
        g_state.pin_entry_length,
        g_state.input_window,
        g_state.target_human_approval_input_mode,
        g_state.target_signing_authorization_mode,
        g_state.flow_active(),
        accepts,
        processing_stage(g_state.stage),
        pin_attempt_locked_at(now),
    };
}

bool local_pin_auth_flow_active()
{
    return g_state.flow_active();
}

bool local_pin_auth_accepts_keypad_input()
{
    return g_state.flow_active() &&
           (g_state.stage == AgentQLocalPinAuthStage::pin_entry ||
            g_state.stage == AgentQLocalPinAuthStage::new_pin_entry ||
            g_state.stage == AgentQLocalPinAuthStage::repeat_pin_entry);
}

bool local_pin_auth_deadline_expired(TickType_t now)
{
    return timeout_window_reached(g_state.input_window, now);
}

bool local_pin_auth_processing_deadline_expired(TickType_t now)
{
    return g_state.flow_active() &&
           timeout_bound_processing_stage(g_state.stage) &&
           timeout_window_tick_reached(now, g_state.worker_deadline);
}

bool local_pin_auth_fail_processing_if_expired(TickType_t now)
{
    if (!local_pin_auth_processing_deadline_expired(now)) {
        return false;
    }
    g_state.clear_flow();
    return true;
}

AgentQLocalPinAuthLockoutReleaseResult local_pin_auth_release_lockout_if_elapsed(TickType_t now)
{
    return release_lockout_if_elapsed(now);
}

void local_pin_auth_clear_flow()
{
    g_state.clear_flow();
}

bool local_pin_auth_begin_connect(TickType_t now, AgentQTimeoutWindow input_window)
{
    g_state.clear_flow();
    if (!timeout_window_valid_and_open_at(input_window, now)) {
        return false;
    }
    g_state.purpose = AgentQLocalPinAuthPurpose::connect;
    g_state.stage = AgentQLocalPinAuthStage::pin_entry;
    g_state.set_input_window(input_window);
    return true;
}

bool local_pin_auth_begin_human_approval_input_setting(
    AgentQHumanApprovalInputMode target_human_approval_input_mode,
    TickType_t now,
    AgentQTimeoutWindow input_window)
{
    g_state.clear_flow();
    if (!timeout_window_valid_and_open_at(input_window, now)) {
        return false;
    }
    g_state.purpose = AgentQLocalPinAuthPurpose::settings_human_approval_input;
    g_state.stage = AgentQLocalPinAuthStage::pin_entry;
    g_state.target_human_approval_input_mode = target_human_approval_input_mode;
    g_state.set_input_window(input_window);
    return true;
}

bool local_pin_auth_begin_signing_mode_setting(
    AgentQSigningAuthorizationMode target_mode,
    TickType_t now,
    AgentQTimeoutWindow input_window)
{
    g_state.clear_flow();
    if (!timeout_window_valid_and_open_at(input_window, now)) {
        return false;
    }
    g_state.purpose = AgentQLocalPinAuthPurpose::settings_signing_mode;
    g_state.stage = AgentQLocalPinAuthStage::pin_entry;
    g_state.target_signing_authorization_mode = target_mode;
    g_state.set_input_window(input_window);
    return true;
}

bool local_pin_auth_begin_policy_reset_setting(TickType_t now, AgentQTimeoutWindow input_window)
{
    g_state.clear_flow();
    if (!timeout_window_valid_and_open_at(input_window, now)) {
        return false;
    }
    g_state.purpose = AgentQLocalPinAuthPurpose::settings_policy_reset;
    g_state.stage = AgentQLocalPinAuthStage::pin_entry;
    g_state.set_input_window(input_window);
    return true;
}

bool local_pin_auth_begin_change_pin(TickType_t now, AgentQTimeoutWindow input_window)
{
    g_state.clear_flow();
    if (!timeout_window_valid_and_open_at(input_window, now)) {
        return false;
    }
    g_state.purpose = AgentQLocalPinAuthPurpose::settings_change_pin;
    g_state.stage = AgentQLocalPinAuthStage::pin_entry;
    g_state.set_input_window(input_window);
    return true;
}

bool local_pin_auth_begin_policy_update(TickType_t now, AgentQTimeoutWindow input_window)
{
    g_state.clear_flow();
    if (!timeout_window_valid_and_open_at(input_window, now)) {
        return false;
    }
    g_state.purpose = AgentQLocalPinAuthPurpose::policy_update;
    g_state.stage = AgentQLocalPinAuthStage::pin_entry;
    g_state.set_input_window(input_window);
    return true;
}

bool local_pin_auth_begin_user_signing(
    const AgentQLocalPinAuthSignatureBinding& binding,
    TickType_t now,
    AgentQTimeoutWindow input_window)
{
    if (g_state.flow_active() ||
        binding.token == 0) {
        return false;
    }
    if (!timeout_window_valid_and_open_at(input_window, now)) {
        return false;
    }
    g_state.purpose = AgentQLocalPinAuthPurpose::user_signing;
    g_state.stage = AgentQLocalPinAuthStage::pin_entry;
    g_state.set_input_window(input_window);
    g_state.signature_binding = binding;
    return true;
}

bool local_pin_auth_user_signing_matches(
    const AgentQLocalPinAuthSignatureBinding& binding)
{
    return g_state.flow_active() &&
           g_state.purpose == AgentQLocalPinAuthPurpose::user_signing &&
           binding.token != 0 &&
           g_state.signature_binding.token == binding.token;
}

AgentQLocalPinAuthInputResult local_pin_auth_add_digit(char digit)
{
    const TickType_t now = xTaskGetTickCount();
    if (!local_pin_auth_accepts_keypad_input()) {
        return AgentQLocalPinAuthInputResult::inactive;
    }
    if (timeout_window_reached(g_state.input_window, now)) {
        return AgentQLocalPinAuthInputResult::inactive;
    }
    if (pin_attempt_locked_at(now)) {
        return AgentQLocalPinAuthInputResult::locked;
    }
    if (digit < '0' || digit > '9') {
        return AgentQLocalPinAuthInputResult::invalid_digit;
    }
    if (g_state.pin_entry_length >= kLocalPinDigits) {
        return AgentQLocalPinAuthInputResult::full;
    }

    g_state.pin_entry[g_state.pin_entry_length++] = digit;
    g_state.pin_entry[g_state.pin_entry_length] = '\0';
    return AgentQLocalPinAuthInputResult::accepted;
}

bool local_pin_auth_clear_pin()
{
    const TickType_t now = xTaskGetTickCount();
    if (!local_pin_auth_accepts_keypad_input() ||
        timeout_window_reached(g_state.input_window, now) ||
        pin_attempt_locked_at(now)) {
        return false;
    }
    g_state.clear_pin_only();
    return true;
}

bool local_pin_auth_backspace_pin()
{
    const TickType_t now = xTaskGetTickCount();
    if (!local_pin_auth_accepts_keypad_input() ||
        timeout_window_reached(g_state.input_window, now) ||
        pin_attempt_locked_at(now)) {
        return false;
    }
    if (g_state.pin_entry_length > 0) {
        g_state.pin_entry[--g_state.pin_entry_length] = '\0';
    }
    return true;
}

AgentQLocalPinAuthSubmitResult local_pin_auth_submit(
    TickType_t verify_ready_at,
    TickType_t commit_ready_at,
    AgentQTimeoutWindow next_input_window,
    TickType_t worker_deadline)
{
    const TickType_t now = xTaskGetTickCount();
    const AgentQLocalPinAuthLockoutReleaseResult release_result =
        release_lockout_if_elapsed(now);
    if (release_result == AgentQLocalPinAuthLockoutReleaseResult::failed) {
        return AgentQLocalPinAuthSubmitResult::unavailable_stage;
    }
    if (!local_pin_auth_accepts_keypad_input()) {
        return AgentQLocalPinAuthSubmitResult::unavailable_stage;
    }
    if (timeout_window_reached(g_state.input_window, now)) {
        return AgentQLocalPinAuthSubmitResult::unavailable_stage;
    }
    if (pin_attempt_locked_at(now)) {
        return AgentQLocalPinAuthSubmitResult::locked;
    }
    if (g_state.pin_entry_length != kLocalPinDigits ||
        !is_valid_local_pin(g_state.pin_entry)) {
        return AgentQLocalPinAuthSubmitResult::invalid_pin;
    }

    if (g_state.purpose == AgentQLocalPinAuthPurpose::settings_change_pin &&
        g_state.stage == AgentQLocalPinAuthStage::new_pin_entry) {
        memcpy(g_state.new_pin, g_state.pin_entry, sizeof(g_state.new_pin));
        g_state.new_pin[sizeof(g_state.new_pin) - 1] = '\0';
        g_state.clear_pin_only();
        g_state.stage = AgentQLocalPinAuthStage::repeat_pin_entry;
        if (!timeout_window_valid(next_input_window)) {
            g_state.clear_flow();
            return AgentQLocalPinAuthSubmitResult::unavailable_stage;
        }
        g_state.set_input_window(next_input_window);
        return AgentQLocalPinAuthSubmitResult::advanced_to_repeat_pin;
    }

    if (g_state.purpose == AgentQLocalPinAuthPurpose::settings_change_pin &&
        g_state.stage == AgentQLocalPinAuthStage::repeat_pin_entry) {
        if (strcmp(g_state.new_pin, g_state.pin_entry) != 0) {
            g_state.clear_new_pin();
            g_state.clear_pin_only();
            g_state.stage = AgentQLocalPinAuthStage::new_pin_entry;
            if (!timeout_window_valid(next_input_window)) {
                g_state.clear_flow();
                return AgentQLocalPinAuthSubmitResult::unavailable_stage;
            }
            g_state.set_input_window(next_input_window);
            return AgentQLocalPinAuthSubmitResult::mismatch_restart;
        }

        uint32_t job_id = 0;
        if (!local_auth_worker_submit_prepare_verifier(
                AgentQLocalAuthWorkerOwner::local_pin_auth,
                g_state.new_pin,
        &job_id)) {
            g_state.clear_new_pin();
            g_state.clear_pin_only();
            g_state.stage = AgentQLocalPinAuthStage::new_pin_entry;
            if (!timeout_window_valid(next_input_window)) {
                g_state.clear_flow();
                return AgentQLocalPinAuthSubmitResult::unavailable_stage;
            }
            g_state.set_input_window(next_input_window);
            return AgentQLocalPinAuthSubmitResult::worker_unavailable;
        }
        g_state.clear_new_pin();
        g_state.clear_pin_only();
        g_state.stage = AgentQLocalPinAuthStage::committing_pin_change;
        g_state.auth_job_id = job_id;
        g_state.commit_ready_at = commit_ready_at;
        g_state.worker_deadline = worker_deadline;
        g_state.set_input_window(kAgentQTimeoutWindowNone);
        return AgentQLocalPinAuthSubmitResult::started_pin_change_commit;
    }

    uint32_t job_id = 0;
    if (!g_state.pause_input_window(now)) {
        return AgentQLocalPinAuthSubmitResult::unavailable_stage;
    }
    if (!local_auth_worker_submit_verify(
            AgentQLocalAuthWorkerOwner::local_pin_auth,
            g_state.pin_entry,
            &job_id)) {
        g_state.resume_paused_input_window(now);
        return AgentQLocalPinAuthSubmitResult::worker_unavailable;
    }
    g_state.clear_pin_only();
    g_state.stage = AgentQLocalPinAuthStage::pin_verifying;
    g_state.auth_job_id = job_id;
    g_state.verify_ready_at = verify_ready_at;
    g_state.worker_deadline = worker_deadline;
    return AgentQLocalPinAuthSubmitResult::started_verification;
}

AgentQLocalPinAuthVerifyResult local_pin_auth_complete_verify_job(
    const AgentQLocalAuthWorkerResult& result,
    AgentQTimeoutWindow next_input_window,
    TickType_t lockout_until,
    TickType_t setting_commit_ready_at)
{
    if (!g_state.flow_active() ||
        g_state.stage != AgentQLocalPinAuthStage::pin_verifying ||
        g_state.auth_job_id == 0 ||
        result.job_id != g_state.auth_job_id ||
        result.owner != AgentQLocalAuthWorkerOwner::local_pin_auth ||
        result.operation != AgentQLocalAuthWorkerOperation::verify_pin) {
        return AgentQLocalPinAuthVerifyResult::not_ready;
    }
    if (g_state.purpose == AgentQLocalPinAuthPurpose::user_signing) {
        return AgentQLocalPinAuthVerifyResult::not_ready;
    }
    const TickType_t now = xTaskGetTickCount();
    if (local_pin_auth_processing_deadline_expired(now)) {
        g_state.clear_flow();
        return AgentQLocalPinAuthVerifyResult::auth_unavailable;
    }

    g_state.auth_job_id = 0;
    g_state.verify_ready_at = 0;
    g_state.worker_deadline = 0;
    if (result.status != AgentQLocalAuthWorkerStatus::ok) {
        g_state.clear_pin_only();
        return AgentQLocalPinAuthVerifyResult::auth_unavailable;
    }

    if (!result.verified) {
        g_state.clear_pin_only();
        g_state.stage = AgentQLocalPinAuthStage::pin_entry;
        const bool locked = pin_attempt_record_failure(lockout_until);
        if (locked) {
            return AgentQLocalPinAuthVerifyResult::locked;
        }
        if (!resume_after_wrong_pin(now)) {
            g_state.clear_flow();
            return AgentQLocalPinAuthVerifyResult::auth_unavailable;
        }
        return AgentQLocalPinAuthVerifyResult::wrong_pin;
    }

    g_state.clear_pin_only();
    pin_attempt_clear();

    if (g_state.purpose == AgentQLocalPinAuthPurpose::settings_change_pin) {
        g_state.stage = AgentQLocalPinAuthStage::new_pin_entry;
        if (!timeout_window_valid(next_input_window)) {
            g_state.clear_flow();
            return AgentQLocalPinAuthVerifyResult::auth_unavailable;
        }
        g_state.set_input_window(next_input_window);
        return AgentQLocalPinAuthVerifyResult::advanced_to_change_pin;
    }

    if (g_state.purpose == AgentQLocalPinAuthPurpose::settings_policy_reset) {
        return AgentQLocalPinAuthVerifyResult::verified_settings_policy_reset;
    }

    if (g_state.purpose == AgentQLocalPinAuthPurpose::settings_human_approval_input ||
        g_state.purpose == AgentQLocalPinAuthPurpose::settings_signing_mode) {
        g_state.stage = AgentQLocalPinAuthStage::committing_setting;
        g_state.commit_ready_at = setting_commit_ready_at;
        g_state.set_input_window(kAgentQTimeoutWindowNone);
        return AgentQLocalPinAuthVerifyResult::started_setting_commit;
    }

    if (g_state.purpose == AgentQLocalPinAuthPurpose::policy_update) {
        return AgentQLocalPinAuthVerifyResult::verified_policy_update;
    }

    return AgentQLocalPinAuthVerifyResult::verified_connect;
}

AgentQLocalPinAuthSignatureVerifyResult local_pin_auth_complete_user_signing_verify_job(
    const AgentQLocalAuthWorkerResult& result,
    TickType_t lockout_until)
{
    if (!g_state.flow_active() ||
        g_state.purpose != AgentQLocalPinAuthPurpose::user_signing ||
        g_state.stage != AgentQLocalPinAuthStage::pin_verifying ||
        g_state.auth_job_id == 0 ||
        result.job_id != g_state.auth_job_id ||
        result.owner != AgentQLocalAuthWorkerOwner::local_pin_auth ||
        result.operation != AgentQLocalAuthWorkerOperation::verify_pin) {
        return AgentQLocalPinAuthSignatureVerifyResult::not_ready;
    }
    const TickType_t now = xTaskGetTickCount();
    if (local_pin_auth_processing_deadline_expired(now)) {
        g_state.clear_flow();
        return AgentQLocalPinAuthSignatureVerifyResult::auth_unavailable;
    }

    g_state.auth_job_id = 0;
    g_state.verify_ready_at = 0;
    g_state.worker_deadline = 0;
    if (result.status != AgentQLocalAuthWorkerStatus::ok) {
        g_state.clear_flow();
        return AgentQLocalPinAuthSignatureVerifyResult::auth_unavailable;
    }

    if (!result.verified) {
        g_state.clear_pin_only();
        g_state.stage = AgentQLocalPinAuthStage::pin_entry;
        const bool locked = pin_attempt_record_failure(lockout_until);
        if (locked) {
            return AgentQLocalPinAuthSignatureVerifyResult::locked;
        }
        if (!resume_after_wrong_pin(now)) {
            g_state.clear_flow();
            return AgentQLocalPinAuthSignatureVerifyResult::auth_unavailable;
        }
        return AgentQLocalPinAuthSignatureVerifyResult::wrong_pin;
    }

    g_state.clear_flow();
    pin_attempt_clear();
    return AgentQLocalPinAuthSignatureVerifyResult::verified;
}

AgentQLocalPinAuthCommitResult local_pin_auth_complete_pin_change_job(
    const AgentQLocalAuthWorkerResult& result)
{
    if (!g_state.flow_active() ||
        g_state.stage != AgentQLocalPinAuthStage::committing_pin_change ||
        g_state.auth_job_id == 0 ||
        result.job_id != g_state.auth_job_id ||
        result.owner != AgentQLocalAuthWorkerOwner::local_pin_auth ||
        result.operation != AgentQLocalAuthWorkerOperation::prepare_verifier_record) {
        return AgentQLocalPinAuthCommitResult::not_ready;
    }
    if (local_pin_auth_processing_deadline_expired(xTaskGetTickCount())) {
        g_state.clear_flow();
        return AgentQLocalPinAuthCommitResult::pin_change_auth_unavailable;
    }

    g_state.auth_job_id = 0;
    g_state.commit_ready_at = 0;
    g_state.worker_deadline = 0;
    if (result.status != AgentQLocalAuthWorkerStatus::ok) {
        g_state.clear_flow();
        return AgentQLocalPinAuthCommitResult::pin_change_auth_unavailable;
    }

    const bool stored = store_prepared_local_pin_verifier(&result.prepared_record);
    g_state.clear_flow();
    if (!stored) {
        if (local_auth_status() != AgentQLocalAuthStatus::active) {
            return AgentQLocalPinAuthCommitResult::pin_change_auth_unavailable;
        }
        return AgentQLocalPinAuthCommitResult::pin_change_storage_error;
    }
    return AgentQLocalPinAuthCommitResult::pin_changed;
}

AgentQLocalPinAuthCommitResult local_pin_auth_commit_if_ready(TickType_t now)
{
    if (!g_state.flow_active() ||
        g_state.stage != AgentQLocalPinAuthStage::committing_setting ||
        g_state.commit_ready_at == 0 ||
        !timeout_window_tick_reached(now, g_state.commit_ready_at)) {
        return AgentQLocalPinAuthCommitResult::not_ready;
    }

    bool stored = false;
    if (g_state.purpose == AgentQLocalPinAuthPurpose::settings_human_approval_input) {
        stored = store_human_approval_input_mode(g_state.target_human_approval_input_mode);
    } else if (g_state.purpose == AgentQLocalPinAuthPurpose::settings_signing_mode) {
        stored = store_signing_authorization_mode(g_state.target_signing_authorization_mode);
    } else {
        return AgentQLocalPinAuthCommitResult::not_ready;
    }
    g_state.clear_flow();

    if (!stored) {
        return AgentQLocalPinAuthCommitResult::storage_error;
    }

    return AgentQLocalPinAuthCommitResult::setting_stored;
}

}  // namespace agent_q
