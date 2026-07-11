#include "local_pin_auth.h"

#include <string.h>

#include "bip39.h"
#include "human_approval_settings.h"
#include "local_pin_auth_signature_internal.h"
#include "pin_attempt.h"
#include "protocol/signing_mode.h"
#include "sui_account_settings.h"
#include "freertos/task.h"

namespace signing {
namespace {

struct LocalPinAuthState {
    char pin_entry[kKeystorePinBufferBytes] = {};
    char current_pin[kKeystorePinBufferBytes] = {};
    char new_pin[kKeystorePinBufferBytes] = {};
    size_t pin_entry_length = 0;
    LocalPinAuthPurpose purpose = LocalPinAuthPurpose::none;
    LocalPinAuthStage stage = LocalPinAuthStage::none;
    HumanApprovalInputMode target_human_approval_input_mode = HumanApprovalInputMode::pin;
    AuthorizationMode target_signing_authorization_mode = AuthorizationMode::user;
    SuiAccountSettings target_sui_account_settings = kDefaultSuiAccountSettings;
    uint32_t auth_job_id = 0;
    TimeoutWindow input_window = kTimeoutWindowNone;
    PausedTimeoutWindow paused_input_window = kPausedTimeoutWindowNone;
    TickType_t verify_ready_at = 0;
    TickType_t commit_ready_at = 0;
    TickType_t worker_deadline = 0;
    LocalPinAuthSignatureBinding signature_binding = {};

    bool flow_active() const
    {
        return purpose != LocalPinAuthPurpose::none &&
               stage != LocalPinAuthStage::none;
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

    bool effectful_worker_job_active() const
    {
        return auth_job_id != 0 &&
               (stage == LocalPinAuthStage::committing_pin_change ||
                (stage == LocalPinAuthStage::pin_verifying &&
                 purpose == LocalPinAuthPurpose::unlock));
    }

    bool clear_flow()
    {
        if (effectful_worker_job_active()) {
            return false;
        }
        if (auth_job_id != 0) {
            if (!local_auth_worker_cancel_authentication(auth_job_id)) {
                return false;
            }
        }
        wipe_sensitive_buffer(pin_entry, sizeof(pin_entry));
        wipe_sensitive_buffer(current_pin, sizeof(current_pin));
        wipe_sensitive_buffer(new_pin, sizeof(new_pin));
        pin_entry_length = 0;
        purpose = LocalPinAuthPurpose::none;
        stage = LocalPinAuthStage::none;
        target_human_approval_input_mode = HumanApprovalInputMode::pin;
        target_signing_authorization_mode = AuthorizationMode::user;
        target_sui_account_settings = kDefaultSuiAccountSettings;
        auth_job_id = 0;
        input_window = kTimeoutWindowNone;
        paused_input_window = kPausedTimeoutWindowNone;
        verify_ready_at = 0;
        commit_ready_at = 0;
        worker_deadline = 0;
        clear_signature_binding();
        return true;
    }

    void set_input_window(TimeoutWindow window)
    {
        input_window = window;
        paused_input_window = kPausedTimeoutWindowNone;
    }

    bool pause_input_window(TickType_t now)
    {
        PausedTimeoutWindow paused = timeout_window_pause_at(input_window, now);
        if (!timeout_paused_window_valid(paused)) {
            return false;
        }
        input_window = kTimeoutWindowNone;
        paused_input_window = paused;
        return true;
    }

    bool resume_paused_input_window(TickType_t now)
    {
        TimeoutWindow resumed = timeout_window_resume_at(paused_input_window, now);
        if (!timeout_window_valid(resumed)) {
            return false;
        }
        set_input_window(resumed);
        return true;
    }
};

LocalPinAuthState g_state;

bool processing_stage(LocalPinAuthStage stage)
{
    return stage == LocalPinAuthStage::pin_verifying ||
           stage == LocalPinAuthStage::committing_setting ||
           stage == LocalPinAuthStage::committing_pin_change;
}

bool timeout_bound_processing_stage(
    LocalPinAuthStage stage,
    LocalPinAuthPurpose purpose)
{
    return stage == LocalPinAuthStage::pin_verifying &&
           purpose != LocalPinAuthPurpose::unlock;
}

LocalPinAuthLockoutReleaseResult release_lockout_if_elapsed(TickType_t now)
{
    if (!pin_attempt_lockout_elapsed_at(now)) {
        return LocalPinAuthLockoutReleaseResult::not_released;
    }
    if (timeout_paused_window_valid(g_state.paused_input_window)) {
        if (!g_state.resume_paused_input_window(now)) {
            g_state.clear_flow();
            pin_attempt_clear();
            return LocalPinAuthLockoutReleaseResult::failed;
        }
        pin_attempt_clear();
        return LocalPinAuthLockoutReleaseResult::released;
    }
    if (timeout_window_valid(g_state.input_window)) {
        pin_attempt_clear();
        return LocalPinAuthLockoutReleaseResult::released;
    }
    g_state.clear_flow();
    pin_attempt_clear();
    return LocalPinAuthLockoutReleaseResult::failed;
}

bool resume_after_wrong_pin(TickType_t now)
{
    if (!g_state.resume_paused_input_window(now)) {
        return false;
    }
    return true;
}

bool settings_commit_purpose(LocalPinAuthPurpose purpose)
{
    return purpose == LocalPinAuthPurpose::settings_human_approval_input ||
           purpose == LocalPinAuthPurpose::settings_signing_mode ||
           purpose == LocalPinAuthPurpose::settings_sui_accept_gas_sponsor;
}

}  // namespace

LocalPinAuthSnapshot local_pin_auth_snapshot(TickType_t now)
{
    const bool accepts =
        g_state.flow_active() &&
        (g_state.stage == LocalPinAuthStage::pin_entry ||
         g_state.stage == LocalPinAuthStage::new_pin_entry ||
         g_state.stage == LocalPinAuthStage::repeat_pin_entry);
    return LocalPinAuthSnapshot{
        g_state.purpose,
        g_state.stage,
        g_state.pin_entry_length,
        g_state.input_window,
        g_state.target_human_approval_input_mode,
        g_state.target_signing_authorization_mode,
        g_state.target_sui_account_settings,
        g_state.flow_active(),
        accepts,
        processing_stage(g_state.stage),
        pin_attempt_locked_at(now),
    };
}

bool local_pin_auth_settings_start_available()
{
    return !g_state.flow_active();
}

bool local_pin_auth_settings_purpose(LocalPinAuthPurpose purpose)
{
    return purpose == LocalPinAuthPurpose::settings_human_approval_input ||
           purpose == LocalPinAuthPurpose::settings_signing_mode ||
           purpose == LocalPinAuthPurpose::settings_policy_reset ||
           purpose == LocalPinAuthPurpose::settings_change_pin ||
           purpose == LocalPinAuthPurpose::settings_sui_accept_gas_sponsor ||
           purpose == LocalPinAuthPurpose::settings_sui_zklogin_clear;
}

HumanApprovalInputMode local_pin_auth_target_human_approval_input_mode(
    HumanApprovalInputMode current_mode)
{
    return current_mode == HumanApprovalInputMode::pin
               ? HumanApprovalInputMode::confirm
               : HumanApprovalInputMode::pin;
}

AuthorizationMode local_pin_auth_target_signing_authorization_mode(
    AuthorizationMode current_mode)
{
    return current_mode == AuthorizationMode::policy
               ? AuthorizationMode::user
               : AuthorizationMode::policy;
}

SuiAccountSettings local_pin_auth_target_sui_accept_gas_sponsor_settings(
    const SuiAccountSettings& current_settings)
{
    SuiAccountSettings target_settings = current_settings;
    target_settings.accept_gas_sponsor = !current_settings.accept_gas_sponsor;
    return target_settings;
}

bool local_pin_auth_flow_active()
{
    return g_state.flow_active();
}

bool local_pin_auth_accepts_keypad_input()
{
    return g_state.flow_active() &&
           (g_state.stage == LocalPinAuthStage::pin_entry ||
            g_state.stage == LocalPinAuthStage::new_pin_entry ||
            g_state.stage == LocalPinAuthStage::repeat_pin_entry);
}

bool local_pin_auth_deadline_expired(TickType_t now)
{
    return timeout_window_reached(g_state.input_window, now);
}

bool local_pin_auth_processing_deadline_expired(TickType_t now)
{
    return g_state.flow_active() &&
           timeout_bound_processing_stage(g_state.stage, g_state.purpose) &&
           timeout_window_tick_reached(now, g_state.worker_deadline);
}

bool local_pin_auth_fail_processing_if_expired(TickType_t now)
{
    if (!local_pin_auth_processing_deadline_expired(now)) {
        return false;
    }
    return g_state.clear_flow();
}

LocalPinAuthLockoutReleaseResult local_pin_auth_release_lockout_if_elapsed(TickType_t now)
{
    return release_lockout_if_elapsed(now);
}

bool local_pin_auth_clear_flow()
{
    return g_state.clear_flow();
}

bool local_pin_auth_begin_connect(TickType_t now, TimeoutWindow input_window)
{
    if (!g_state.clear_flow()) {
        return false;
    }
    if (!timeout_window_valid_and_open_at(input_window, now)) {
        return false;
    }
    g_state.purpose = LocalPinAuthPurpose::connect;
    g_state.stage = LocalPinAuthStage::pin_entry;
    g_state.set_input_window(input_window);
    return true;
}

bool local_pin_auth_begin_unlock(TickType_t now, TimeoutWindow input_window)
{
    if (!g_state.clear_flow()) {
        return false;
    }
    if (!timeout_window_valid_and_open_at(input_window, now)) {
        return false;
    }
    g_state.purpose = LocalPinAuthPurpose::unlock;
    g_state.stage = LocalPinAuthStage::pin_entry;
    g_state.set_input_window(input_window);
    return true;
}

bool local_pin_auth_begin_human_approval_input_setting(
    HumanApprovalInputMode target_human_approval_input_mode,
    TickType_t now,
    TimeoutWindow input_window)
{
    if (!g_state.clear_flow()) {
        return false;
    }
    if (!timeout_window_valid_and_open_at(input_window, now)) {
        return false;
    }
    g_state.purpose = LocalPinAuthPurpose::settings_human_approval_input;
    g_state.stage = LocalPinAuthStage::pin_entry;
    g_state.target_human_approval_input_mode = target_human_approval_input_mode;
    g_state.set_input_window(input_window);
    return true;
}

bool local_pin_auth_begin_signing_mode_setting(
    AuthorizationMode target_mode,
    TickType_t now,
    TimeoutWindow input_window)
{
    if (!g_state.clear_flow()) {
        return false;
    }
    if (!timeout_window_valid_and_open_at(input_window, now)) {
        return false;
    }
    g_state.purpose = LocalPinAuthPurpose::settings_signing_mode;
    g_state.stage = LocalPinAuthStage::pin_entry;
    g_state.target_signing_authorization_mode = target_mode;
    g_state.set_input_window(input_window);
    return true;
}

bool local_pin_auth_begin_sui_accept_gas_sponsor_setting(
    const SuiAccountSettings& target_settings,
    TickType_t now,
    TimeoutWindow input_window)
{
    if (!g_state.clear_flow()) {
        return false;
    }
    if (!timeout_window_valid_and_open_at(input_window, now)) {
        return false;
    }
    g_state.purpose = LocalPinAuthPurpose::settings_sui_accept_gas_sponsor;
    g_state.stage = LocalPinAuthStage::pin_entry;
    g_state.target_sui_account_settings = target_settings;
    g_state.set_input_window(input_window);
    return true;
}

bool local_pin_auth_begin_policy_reset_setting(TickType_t now, TimeoutWindow input_window)
{
    if (!g_state.clear_flow()) {
        return false;
    }
    if (!timeout_window_valid_and_open_at(input_window, now)) {
        return false;
    }
    g_state.purpose = LocalPinAuthPurpose::settings_policy_reset;
    g_state.stage = LocalPinAuthStage::pin_entry;
    g_state.set_input_window(input_window);
    return true;
}

bool local_pin_auth_begin_change_pin(TickType_t now, TimeoutWindow input_window)
{
    if (!g_state.clear_flow()) {
        return false;
    }
    if (!timeout_window_valid_and_open_at(input_window, now)) {
        return false;
    }
    g_state.purpose = LocalPinAuthPurpose::settings_change_pin;
    g_state.stage = LocalPinAuthStage::pin_entry;
    g_state.set_input_window(input_window);
    return true;
}

bool local_pin_auth_begin_sui_zklogin_clear_setting(
    TickType_t now,
    TimeoutWindow input_window)
{
    if (!g_state.clear_flow()) {
        return false;
    }
    if (!timeout_window_valid_and_open_at(input_window, now)) {
        return false;
    }
    g_state.purpose = LocalPinAuthPurpose::settings_sui_zklogin_clear;
    g_state.stage = LocalPinAuthStage::pin_entry;
    g_state.set_input_window(input_window);
    return true;
}

bool local_pin_auth_begin_policy_update(TickType_t now, TimeoutWindow input_window)
{
    if (!g_state.clear_flow()) {
        return false;
    }
    if (!timeout_window_valid_and_open_at(input_window, now)) {
        return false;
    }
    g_state.purpose = LocalPinAuthPurpose::policy_update;
    g_state.stage = LocalPinAuthStage::pin_entry;
    g_state.set_input_window(input_window);
    return true;
}

bool local_pin_auth_begin_sui_zklogin_proposal(TickType_t now, TimeoutWindow input_window)
{
    if (!g_state.clear_flow()) {
        return false;
    }
    if (!timeout_window_valid_and_open_at(input_window, now)) {
        return false;
    }
    g_state.purpose = LocalPinAuthPurpose::sui_zklogin_proposal;
    g_state.stage = LocalPinAuthStage::pin_entry;
    g_state.set_input_window(input_window);
    return true;
}

bool local_pin_auth_begin_user_signing(
    const LocalPinAuthSignatureBinding& binding,
    TickType_t now,
    TimeoutWindow input_window)
{
    if (g_state.flow_active() ||
        binding.token == 0) {
        return false;
    }
    if (!timeout_window_valid_and_open_at(input_window, now)) {
        return false;
    }
    g_state.purpose = LocalPinAuthPurpose::user_signing;
    g_state.stage = LocalPinAuthStage::pin_entry;
    g_state.set_input_window(input_window);
    g_state.signature_binding = binding;
    return true;
}

bool local_pin_auth_user_signing_matches(
    const LocalPinAuthSignatureBinding& binding)
{
    return g_state.flow_active() &&
           g_state.purpose == LocalPinAuthPurpose::user_signing &&
           binding.token != 0 &&
           g_state.signature_binding.token == binding.token;
}

LocalPinAuthInputResult local_pin_auth_add_digit(char digit)
{
    const TickType_t now = xTaskGetTickCount();
    if (!local_pin_auth_accepts_keypad_input()) {
        return LocalPinAuthInputResult::inactive;
    }
    if (timeout_window_reached(g_state.input_window, now)) {
        return LocalPinAuthInputResult::inactive;
    }
    if (pin_attempt_locked_at(now)) {
        return LocalPinAuthInputResult::locked;
    }
    if (digit < '0' || digit > '9') {
        return LocalPinAuthInputResult::invalid_digit;
    }
    if (g_state.pin_entry_length >= kKeystorePinDigits) {
        return LocalPinAuthInputResult::full;
    }

    g_state.pin_entry[g_state.pin_entry_length++] = digit;
    g_state.pin_entry[g_state.pin_entry_length] = '\0';
    return LocalPinAuthInputResult::accepted;
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

LocalPinAuthSubmitResult local_pin_auth_submit(
    TickType_t verify_ready_at,
    TickType_t commit_ready_at,
    TimeoutWindow next_input_window,
    TickType_t worker_deadline)
{
    const TickType_t now = xTaskGetTickCount();
    const LocalPinAuthLockoutReleaseResult release_result =
        release_lockout_if_elapsed(now);
    if (release_result == LocalPinAuthLockoutReleaseResult::failed) {
        return LocalPinAuthSubmitResult::unavailable_stage;
    }
    if (!local_pin_auth_accepts_keypad_input()) {
        return LocalPinAuthSubmitResult::unavailable_stage;
    }
    if (timeout_window_reached(g_state.input_window, now)) {
        return LocalPinAuthSubmitResult::unavailable_stage;
    }
    if (pin_attempt_locked_at(now)) {
        return LocalPinAuthSubmitResult::locked;
    }
    if (g_state.pin_entry_length != kKeystorePinDigits ||
        !keystore_pin_valid(g_state.pin_entry)) {
        return LocalPinAuthSubmitResult::invalid_pin;
    }

    if (g_state.purpose == LocalPinAuthPurpose::settings_change_pin &&
        g_state.stage == LocalPinAuthStage::new_pin_entry) {
        memcpy(g_state.new_pin, g_state.pin_entry, sizeof(g_state.new_pin));
        g_state.new_pin[sizeof(g_state.new_pin) - 1] = '\0';
        g_state.clear_pin_only();
        g_state.stage = LocalPinAuthStage::repeat_pin_entry;
        if (!timeout_window_valid(next_input_window)) {
            g_state.clear_flow();
            return LocalPinAuthSubmitResult::unavailable_stage;
        }
        g_state.set_input_window(next_input_window);
        return LocalPinAuthSubmitResult::advanced_to_repeat_pin;
    }

    if (g_state.purpose == LocalPinAuthPurpose::settings_change_pin &&
        g_state.stage == LocalPinAuthStage::repeat_pin_entry) {
        if (strcmp(g_state.new_pin, g_state.pin_entry) != 0) {
            g_state.clear_new_pin();
            g_state.clear_pin_only();
            g_state.stage = LocalPinAuthStage::new_pin_entry;
            if (!timeout_window_valid(next_input_window)) {
                g_state.clear_flow();
                return LocalPinAuthSubmitResult::unavailable_stage;
            }
            g_state.set_input_window(next_input_window);
            return LocalPinAuthSubmitResult::mismatch_restart;
        }

        uint32_t job_id = 0;
        if (!local_auth_worker_submit_rewrap(
                LocalAuthWorkerOwner::local_pin_auth,
                g_state.current_pin,
                g_state.new_pin,
                &job_id)) {
            wipe_sensitive_buffer(g_state.current_pin, sizeof(g_state.current_pin));
            g_state.clear_new_pin();
            g_state.clear_pin_only();
            g_state.stage = LocalPinAuthStage::new_pin_entry;
            if (!timeout_window_valid(next_input_window)) {
                g_state.clear_flow();
                return LocalPinAuthSubmitResult::unavailable_stage;
            }
            g_state.set_input_window(next_input_window);
            return LocalPinAuthSubmitResult::worker_unavailable;
        }
        wipe_sensitive_buffer(g_state.current_pin, sizeof(g_state.current_pin));
        g_state.clear_new_pin();
        g_state.clear_pin_only();
        g_state.stage = LocalPinAuthStage::committing_pin_change;
        g_state.auth_job_id = job_id;
        g_state.commit_ready_at = commit_ready_at;
        g_state.worker_deadline = worker_deadline;
        g_state.set_input_window(kTimeoutWindowNone);
        return LocalPinAuthSubmitResult::started_pin_change_commit;
    }

    uint32_t job_id = 0;
    if (!g_state.pause_input_window(now)) {
        return LocalPinAuthSubmitResult::unavailable_stage;
    }
    if (g_state.purpose == LocalPinAuthPurpose::settings_change_pin) {
        memcpy(g_state.current_pin, g_state.pin_entry, sizeof(g_state.current_pin));
    }
    const bool submitted =
        g_state.purpose == LocalPinAuthPurpose::unlock
            ? local_auth_worker_submit_unlock(
                  LocalAuthWorkerOwner::local_pin_auth,
                  g_state.pin_entry,
                  &job_id)
            : local_auth_worker_submit_authenticate(
                  LocalAuthWorkerOwner::local_pin_auth,
                  g_state.pin_entry,
                  &job_id);
    if (!submitted) {
        wipe_sensitive_buffer(g_state.current_pin, sizeof(g_state.current_pin));
        g_state.resume_paused_input_window(now);
        return LocalPinAuthSubmitResult::worker_unavailable;
    }
    g_state.clear_pin_only();
    g_state.stage = LocalPinAuthStage::pin_verifying;
    g_state.auth_job_id = job_id;
    g_state.verify_ready_at = verify_ready_at;
    g_state.worker_deadline = worker_deadline;
    return LocalPinAuthSubmitResult::started_verification;
}

LocalPinAuthVerifyResult local_pin_auth_complete_verify_job(
    const LocalAuthWorkerResult& result,
    TimeoutWindow next_input_window,
    TickType_t lockout_until,
    TickType_t setting_commit_ready_at)
{
    if (!g_state.flow_active() ||
        g_state.stage != LocalPinAuthStage::pin_verifying ||
        g_state.auth_job_id == 0 ||
        result.job_id != g_state.auth_job_id ||
        result.owner != LocalAuthWorkerOwner::local_pin_auth ||
        result.operation !=
            (g_state.purpose == LocalPinAuthPurpose::unlock
                 ? LocalAuthWorkerOperation::unlock_keystore
                 : LocalAuthWorkerOperation::authenticate_pin)) {
        return LocalPinAuthVerifyResult::not_ready;
    }
    if (g_state.purpose == LocalPinAuthPurpose::user_signing) {
        return LocalPinAuthVerifyResult::not_ready;
    }
    const TickType_t now = xTaskGetTickCount();
    const bool processing_deadline_expired =
        local_pin_auth_processing_deadline_expired(now);
    g_state.auth_job_id = 0;
    g_state.verify_ready_at = 0;
    g_state.worker_deadline = 0;
    if (processing_deadline_expired) {
        g_state.clear_flow();
        return LocalPinAuthVerifyResult::auth_unavailable;
    }

    if (result.status != LocalAuthWorkerStatus::completed) {
        g_state.clear_flow();
        return LocalPinAuthVerifyResult::auth_unavailable;
    }

    if (result.operation_status != KeystoreOperationStatus::success) {
        if (result.operation_status != KeystoreOperationStatus::wrong_pin) {
            g_state.clear_flow();
            return LocalPinAuthVerifyResult::auth_unavailable;
        }
        wipe_sensitive_buffer(g_state.current_pin, sizeof(g_state.current_pin));
        g_state.clear_pin_only();
        g_state.stage = LocalPinAuthStage::pin_entry;
        const bool locked = pin_attempt_record_failure(lockout_until);
        if (locked) {
            return LocalPinAuthVerifyResult::locked;
        }
        if (!resume_after_wrong_pin(now)) {
            g_state.clear_flow();
            return LocalPinAuthVerifyResult::auth_unavailable;
        }
        return LocalPinAuthVerifyResult::wrong_pin;
    }

    g_state.clear_pin_only();
    pin_attempt_clear();

    if (g_state.purpose == LocalPinAuthPurpose::unlock) {
        g_state.clear_flow();
        return LocalPinAuthVerifyResult::unlocked;
    }

    if (g_state.purpose == LocalPinAuthPurpose::settings_change_pin) {
        g_state.stage = LocalPinAuthStage::new_pin_entry;
        if (!timeout_window_valid(next_input_window)) {
            g_state.clear_flow();
            return LocalPinAuthVerifyResult::auth_unavailable;
        }
        g_state.set_input_window(next_input_window);
        return LocalPinAuthVerifyResult::advanced_to_change_pin;
    }

    if (g_state.purpose == LocalPinAuthPurpose::settings_policy_reset) {
        return LocalPinAuthVerifyResult::verified_settings_policy_reset;
    }

    if (g_state.purpose == LocalPinAuthPurpose::settings_sui_zklogin_clear) {
        return LocalPinAuthVerifyResult::verified_settings_sui_zklogin_clear;
    }

    if (g_state.purpose == LocalPinAuthPurpose::settings_human_approval_input ||
        g_state.purpose == LocalPinAuthPurpose::settings_signing_mode ||
        g_state.purpose == LocalPinAuthPurpose::settings_sui_accept_gas_sponsor) {
        g_state.stage = LocalPinAuthStage::committing_setting;
        g_state.commit_ready_at = setting_commit_ready_at;
        g_state.set_input_window(kTimeoutWindowNone);
        return LocalPinAuthVerifyResult::started_setting_commit;
    }

    if (g_state.purpose == LocalPinAuthPurpose::policy_update) {
        return LocalPinAuthVerifyResult::verified_policy_update;
    }

    if (g_state.purpose == LocalPinAuthPurpose::sui_zklogin_proposal) {
        return LocalPinAuthVerifyResult::verified_sui_zklogin_proposal;
    }

    return LocalPinAuthVerifyResult::verified_connect;
}

LocalPinAuthSignatureVerifyResult local_pin_auth_complete_user_signing_verify_job(
    const LocalAuthWorkerResult& result,
    TickType_t lockout_until)
{
    if (!g_state.flow_active() ||
        g_state.purpose != LocalPinAuthPurpose::user_signing ||
        g_state.stage != LocalPinAuthStage::pin_verifying ||
        g_state.auth_job_id == 0 ||
        result.job_id != g_state.auth_job_id ||
        result.owner != LocalAuthWorkerOwner::local_pin_auth ||
        result.operation != LocalAuthWorkerOperation::authenticate_pin) {
        return LocalPinAuthSignatureVerifyResult::not_ready;
    }
    const TickType_t now = xTaskGetTickCount();
    const bool processing_deadline_expired =
        local_pin_auth_processing_deadline_expired(now);
    g_state.auth_job_id = 0;
    g_state.verify_ready_at = 0;
    g_state.worker_deadline = 0;
    if (processing_deadline_expired) {
        g_state.clear_flow();
        return LocalPinAuthSignatureVerifyResult::auth_unavailable;
    }

    if (result.status != LocalAuthWorkerStatus::completed) {
        g_state.clear_flow();
        return LocalPinAuthSignatureVerifyResult::auth_unavailable;
    }

    if (result.operation_status != KeystoreOperationStatus::success) {
        if (result.operation_status != KeystoreOperationStatus::wrong_pin) {
            g_state.clear_flow();
            return LocalPinAuthSignatureVerifyResult::auth_unavailable;
        }
        g_state.clear_pin_only();
        g_state.stage = LocalPinAuthStage::pin_entry;
        const bool locked = pin_attempt_record_failure(lockout_until);
        if (locked) {
            return LocalPinAuthSignatureVerifyResult::locked;
        }
        if (!resume_after_wrong_pin(now)) {
            g_state.clear_flow();
            return LocalPinAuthSignatureVerifyResult::auth_unavailable;
        }
        return LocalPinAuthSignatureVerifyResult::wrong_pin;
    }

    g_state.clear_flow();
    pin_attempt_clear();
    return LocalPinAuthSignatureVerifyResult::verified;
}

LocalPinAuthCommitResult local_pin_auth_complete_pin_change_job(
    const LocalAuthWorkerResult& result)
{
    if (!g_state.flow_active() ||
        g_state.stage != LocalPinAuthStage::committing_pin_change ||
        g_state.auth_job_id == 0 ||
        result.job_id != g_state.auth_job_id ||
        result.owner != LocalAuthWorkerOwner::local_pin_auth ||
        result.operation != LocalAuthWorkerOperation::rewrap_keystore) {
        return LocalPinAuthCommitResult::not_ready;
    }
    const bool processing_deadline_expired =
        local_pin_auth_processing_deadline_expired(xTaskGetTickCount());
    g_state.auth_job_id = 0;
    g_state.commit_ready_at = 0;
    g_state.worker_deadline = 0;
    if (processing_deadline_expired) {
        g_state.clear_flow();
        return LocalPinAuthCommitResult::pin_change_auth_unavailable;
    }

    if (result.status != LocalAuthWorkerStatus::completed) {
        g_state.clear_flow();
        return LocalPinAuthCommitResult::pin_change_auth_unavailable;
    }

    const KeystoreOperationStatus operation_status = result.operation_status;
    g_state.clear_flow();
    if (operation_status == KeystoreOperationStatus::unchanged) {
        return LocalPinAuthCommitResult::pin_change_storage_error;
    }
    return operation_status == KeystoreOperationStatus::success
        ? LocalPinAuthCommitResult::pin_changed
        : LocalPinAuthCommitResult::pin_change_auth_unavailable;
}

LocalPinAuthCommitResult local_pin_auth_commit_if_ready(TickType_t now)
{
    if (!g_state.flow_active() ||
        g_state.stage != LocalPinAuthStage::committing_setting ||
        g_state.commit_ready_at == 0 ||
        !timeout_window_tick_reached(now, g_state.commit_ready_at)) {
        return LocalPinAuthCommitResult::not_ready;
    }

    bool stored = false;
    if (g_state.purpose == LocalPinAuthPurpose::settings_human_approval_input) {
        stored = store_human_approval_input_mode(g_state.target_human_approval_input_mode);
    } else if (g_state.purpose == LocalPinAuthPurpose::settings_signing_mode) {
        stored = store_signing_authorization_mode(g_state.target_signing_authorization_mode);
    } else if (g_state.purpose == LocalPinAuthPurpose::settings_sui_accept_gas_sponsor) {
        stored = store_sui_account_settings(g_state.target_sui_account_settings);
    } else {
        return LocalPinAuthCommitResult::not_ready;
    }
    g_state.clear_flow();

    if (!stored) {
        return LocalPinAuthCommitResult::storage_error;
    }

    return LocalPinAuthCommitResult::setting_stored;
}

LocalPinAuthSettingsCompletionResult
local_pin_auth_settings_completion_for_commit_result(
    LocalPinAuthPurpose purpose,
    LocalPinAuthCommitResult result)
{
    if (!local_pin_auth_settings_purpose(purpose)) {
        return LocalPinAuthSettingsCompletionResult::not_ready;
    }

    switch (result) {
        case LocalPinAuthCommitResult::not_ready:
            return LocalPinAuthSettingsCompletionResult::not_ready;
        case LocalPinAuthCommitResult::setting_stored:
            if (!settings_commit_purpose(purpose)) {
                return LocalPinAuthSettingsCompletionResult::not_ready;
            }
            return purpose == LocalPinAuthPurpose::settings_sui_accept_gas_sponsor
                       ? LocalPinAuthSettingsCompletionResult::sui_settings_saved
                       : LocalPinAuthSettingsCompletionResult::settings_saved;
        case LocalPinAuthCommitResult::pin_changed:
            if (purpose != LocalPinAuthPurpose::settings_change_pin) {
                return LocalPinAuthSettingsCompletionResult::not_ready;
            }
            return LocalPinAuthSettingsCompletionResult::pin_changed;
        case LocalPinAuthCommitResult::storage_error:
            if (!settings_commit_purpose(purpose)) {
                return LocalPinAuthSettingsCompletionResult::not_ready;
            }
            return purpose == LocalPinAuthPurpose::settings_sui_accept_gas_sponsor
                       ? LocalPinAuthSettingsCompletionResult::sui_settings_error
                       : LocalPinAuthSettingsCompletionResult::settings_error;
        case LocalPinAuthCommitResult::pin_change_storage_error:
            if (purpose != LocalPinAuthPurpose::settings_change_pin) {
                return LocalPinAuthSettingsCompletionResult::not_ready;
            }
            return LocalPinAuthSettingsCompletionResult::pin_change_failed;
        case LocalPinAuthCommitResult::pin_change_auth_unavailable:
            if (purpose != LocalPinAuthPurpose::settings_change_pin) {
                return LocalPinAuthSettingsCompletionResult::not_ready;
            }
            return LocalPinAuthSettingsCompletionResult::auth_error;
    }
    return LocalPinAuthSettingsCompletionResult::not_ready;
}

LocalPinAuthSettingsCompletionResult
local_pin_auth_settings_completion_for_policy_reset(bool stored)
{
    return stored
               ? LocalPinAuthSettingsCompletionResult::policy_reset
               : LocalPinAuthSettingsCompletionResult::policy_reset_failed;
}

LocalPinAuthSettingsCompletionResult
local_pin_auth_settings_completion_for_sui_zklogin_clear(bool cleared)
{
    return cleared
               ? LocalPinAuthSettingsCompletionResult::sui_proof_cleared
               : LocalPinAuthSettingsCompletionResult::sui_clear_failed;
}

}  // namespace signing
