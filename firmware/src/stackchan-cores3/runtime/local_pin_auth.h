#pragma once

#include <stddef.h>
#include <stdint.h>

#include "human_approval_settings.h"
#include "local_auth_worker.h"
#include "protocol/signing_mode.h"
#include "sui_account_settings.h"
#include "transport/timeout_window.h"
#include "freertos/FreeRTOS.h"

namespace signing {

enum class LocalPinAuthPurpose {
    none,
    connect,
    settings_human_approval_input,
    settings_signing_mode,
    settings_policy_reset,
    settings_change_pin,
    settings_sui_accept_gas_sponsor,
    settings_sui_zklogin_clear,
    policy_update,
    sui_zklogin_proposal,
    user_signing,
};

enum class LocalPinAuthStage {
    none,
    pin_entry,
    pin_verifying,
    new_pin_entry,
    repeat_pin_entry,
    committing_setting,
    committing_pin_change,
};

enum class LocalPinAuthInputResult {
    accepted,
    inactive,
    locked,
    invalid_digit,
    full,
};

enum class LocalPinAuthSubmitResult {
    started_verification,
    advanced_to_repeat_pin,
    mismatch_restart,
    started_pin_change_commit,
    invalid_pin,
    unavailable_stage,
    locked,
    worker_unavailable,
};

enum class LocalPinAuthVerifyResult {
    not_ready,
    verified_connect,
    verified_settings_policy_reset,
    verified_settings_sui_zklogin_clear,
    verified_policy_update,
    verified_sui_zklogin_proposal,
    started_setting_commit,
    advanced_to_change_pin,
    wrong_pin,
    locked,
    auth_unavailable,
};

enum class LocalPinAuthCommitResult {
    not_ready,
    setting_stored,
    pin_changed,
    storage_error,
    pin_change_storage_error,
    pin_change_auth_unavailable,
};

enum class LocalPinAuthSettingsCompletionResult {
    not_ready,
    settings_saved,
    settings_error,
    sui_settings_saved,
    sui_settings_error,
    pin_changed,
    pin_change_failed,
    auth_error,
    policy_reset,
    policy_reset_failed,
    sui_proof_cleared,
    sui_clear_failed,
};

enum class LocalPinAuthConnectRejectReason {
    invalid_state,
    ui_error,
    timeout,
    user_rejected,
    auth_unavailable,
};

enum class LocalPinAuthConnectSessionResult {
    connected,
    session_unavailable,
};

enum class LocalPinAuthLockoutReleaseResult {
    not_released,
    released,
    failed,
};

struct LocalPinAuthSnapshot {
    LocalPinAuthPurpose purpose;
    LocalPinAuthStage stage;
    size_t pin_entry_length;
    TimeoutWindow input_window;
    HumanApprovalInputMode target_human_approval_input_mode;
    AuthorizationMode target_signing_authorization_mode;
    SuiAccountSettings target_sui_account_settings;
    bool flow_active;
    bool accepts_keypad_input;
    bool processing;
    bool lockout_active;
};

LocalPinAuthSnapshot local_pin_auth_snapshot(TickType_t now);
bool local_pin_auth_settings_start_available();
bool local_pin_auth_settings_purpose(LocalPinAuthPurpose purpose);
HumanApprovalInputMode local_pin_auth_target_human_approval_input_mode(
    HumanApprovalInputMode current_mode);
AuthorizationMode local_pin_auth_target_signing_authorization_mode(
    AuthorizationMode current_mode);
SuiAccountSettings local_pin_auth_target_sui_accept_gas_sponsor_settings(
    const SuiAccountSettings& current_settings);
bool local_pin_auth_flow_active();
bool local_pin_auth_accepts_keypad_input();
bool local_pin_auth_deadline_expired(TickType_t now);
bool local_pin_auth_processing_deadline_expired(TickType_t now);
bool local_pin_auth_fail_processing_if_expired(TickType_t now);
LocalPinAuthLockoutReleaseResult local_pin_auth_release_lockout_if_elapsed(TickType_t now);

void local_pin_auth_clear_flow();
bool local_pin_auth_begin_connect(TickType_t now, TimeoutWindow input_window);
bool local_pin_auth_begin_human_approval_input_setting(
    HumanApprovalInputMode target_human_approval_input_mode,
    TickType_t now,
    TimeoutWindow input_window);
bool local_pin_auth_begin_signing_mode_setting(
    AuthorizationMode target_mode,
    TickType_t now,
    TimeoutWindow input_window);
bool local_pin_auth_begin_sui_accept_gas_sponsor_setting(
    const SuiAccountSettings& target_settings,
    TickType_t now,
    TimeoutWindow input_window);
bool local_pin_auth_begin_policy_reset_setting(TickType_t now, TimeoutWindow input_window);
bool local_pin_auth_begin_change_pin(TickType_t now, TimeoutWindow input_window);
bool local_pin_auth_begin_sui_zklogin_clear_setting(
    TickType_t now,
    TimeoutWindow input_window);
bool local_pin_auth_begin_policy_update(TickType_t now, TimeoutWindow input_window);
bool local_pin_auth_begin_sui_zklogin_proposal(TickType_t now, TimeoutWindow input_window);

LocalPinAuthInputResult local_pin_auth_add_digit(char digit);
bool local_pin_auth_clear_pin();
bool local_pin_auth_backspace_pin();
LocalPinAuthSubmitResult local_pin_auth_submit(
    TickType_t verify_ready_at,
    TickType_t commit_ready_at,
    TimeoutWindow next_input_window,
    TickType_t worker_deadline);
LocalPinAuthVerifyResult local_pin_auth_complete_verify_job(
    const LocalAuthWorkerResult& result,
    TimeoutWindow next_input_window,
    TickType_t lockout_until,
    TickType_t setting_commit_ready_at);
LocalPinAuthCommitResult local_pin_auth_complete_pin_change_job(
    const LocalAuthWorkerResult& result);
LocalPinAuthCommitResult local_pin_auth_commit_if_ready(TickType_t now);
LocalPinAuthSettingsCompletionResult
local_pin_auth_settings_completion_for_commit_result(
    LocalPinAuthPurpose purpose,
    LocalPinAuthCommitResult result);
LocalPinAuthSettingsCompletionResult
local_pin_auth_settings_completion_for_policy_reset(bool stored);
LocalPinAuthSettingsCompletionResult
local_pin_auth_settings_completion_for_sui_zklogin_clear(bool cleared);

}  // namespace signing
