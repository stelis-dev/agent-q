#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_human_approval_settings.h"
#include "agent_q_local_auth_worker.h"
#include "agent_q_signing_mode.h"
#include "agent_q_timeout_window.h"
#include "freertos/FreeRTOS.h"

namespace agent_q {

enum class AgentQLocalPinAuthPurpose {
    none,
    connect,
    settings_human_approval_input,
    settings_signing_mode,
    settings_change_pin,
    policy_update,
    user_signing,
};

enum class AgentQLocalPinAuthStage {
    none,
    pin_entry,
    pin_verifying,
    new_pin_entry,
    repeat_pin_entry,
    committing_setting,
    committing_pin_change,
};

enum class AgentQLocalPinAuthInputResult {
    accepted,
    inactive,
    locked,
    invalid_digit,
    full,
};

enum class AgentQLocalPinAuthSubmitResult {
    started_verification,
    advanced_to_repeat_pin,
    mismatch_restart,
    started_pin_change_commit,
    invalid_pin,
    unavailable_stage,
    locked,
    worker_unavailable,
};

enum class AgentQLocalPinAuthVerifyResult {
    not_ready,
    verified_connect,
    verified_policy_update,
    started_setting_commit,
    advanced_to_change_pin,
    wrong_pin,
    locked,
    auth_unavailable,
};

enum class AgentQLocalPinAuthCommitResult {
    not_ready,
    setting_stored,
    pin_changed,
    storage_error,
    pin_change_storage_error,
    pin_change_auth_unavailable,
};

enum class AgentQLocalPinAuthLockoutReleaseResult {
    not_released,
    released,
    failed,
};

struct AgentQLocalPinAuthSnapshot {
    AgentQLocalPinAuthPurpose purpose;
    AgentQLocalPinAuthStage stage;
    size_t pin_entry_length;
    AgentQTimeoutWindow input_window;
    AgentQHumanApprovalInputMode target_human_approval_input_mode;
    AgentQSigningAuthorizationMode target_signing_authorization_mode;
    bool flow_active;
    bool accepts_keypad_input;
    bool processing;
    bool lockout_active;
};

AgentQLocalPinAuthSnapshot local_pin_auth_snapshot(TickType_t now);
bool local_pin_auth_flow_active();
bool local_pin_auth_accepts_keypad_input();
bool local_pin_auth_deadline_expired(TickType_t now);
bool local_pin_auth_processing_deadline_expired(TickType_t now);
bool local_pin_auth_fail_processing_if_expired(TickType_t now);
AgentQLocalPinAuthLockoutReleaseResult local_pin_auth_release_lockout_if_elapsed(TickType_t now);

void local_pin_auth_clear_flow();
bool local_pin_auth_begin_connect(TickType_t now, AgentQTimeoutWindow input_window);
bool local_pin_auth_begin_human_approval_input_setting(
    AgentQHumanApprovalInputMode target_human_approval_input_mode,
    TickType_t now,
    AgentQTimeoutWindow input_window);
bool local_pin_auth_begin_signing_mode_setting(
    AgentQSigningAuthorizationMode target_mode,
    TickType_t now,
    AgentQTimeoutWindow input_window);
bool local_pin_auth_begin_change_pin(TickType_t now, AgentQTimeoutWindow input_window);
bool local_pin_auth_begin_policy_update(TickType_t now, AgentQTimeoutWindow input_window);

AgentQLocalPinAuthInputResult local_pin_auth_add_digit(char digit);
bool local_pin_auth_clear_pin();
bool local_pin_auth_backspace_pin();
AgentQLocalPinAuthSubmitResult local_pin_auth_submit(
    TickType_t verify_ready_at,
    TickType_t commit_ready_at,
    AgentQTimeoutWindow next_input_window,
    TickType_t worker_deadline);
AgentQLocalPinAuthVerifyResult local_pin_auth_complete_verify_job(
    const AgentQLocalAuthWorkerResult& result,
    AgentQTimeoutWindow next_input_window,
    TickType_t lockout_until,
    TickType_t setting_commit_ready_at);
AgentQLocalPinAuthCommitResult local_pin_auth_complete_pin_change_job(
    const AgentQLocalAuthWorkerResult& result);
AgentQLocalPinAuthCommitResult local_pin_auth_commit_if_ready(TickType_t now);

}  // namespace agent_q
