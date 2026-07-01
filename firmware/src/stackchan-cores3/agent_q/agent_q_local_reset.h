#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_persistent_material.h"
#include "agent_q_local_auth_worker.h"
#include "agent_q_pin_attempt.h"
#include "agent_q_timeout_window.h"
#include "freertos/FreeRTOS.h"

namespace agent_q {

constexpr uint32_t kAgentQLocalResetEntryMs = 60000;
constexpr uint32_t kAgentQLocalResetPinLockoutMs = kAgentQPinLockoutMs;
constexpr uint8_t kAgentQLocalResetMaxWrongPinAttempts = kAgentQMaxWrongPinAttempts;

enum class AgentQLocalResetStage {
    none,
    settings_menu,
    pin_entry,
    pin_verifying,
    error_recovery_confirm,
    wiping,
};

enum class AgentQLocalResetCommitResult {
    ok,
    missing_state,
    root_wipe_error,
    policy_wipe_error,
    local_auth_wipe_error,
    human_approval_setting_wipe_error,
    signing_mode_wipe_error,
    sui_account_settings_wipe_error,
    approval_history_wipe_error,
    policy_update_marker_wipe_error,
    zklogin_proof_wipe_error,
    material_remaining_error,
    reset_marker_storage_error,
    state_storage_error,
};

enum class AgentQLocalResetPinSubmitResult {
    started_verification,
    invalid_pin,
    unavailable_stage,
    locked,
    worker_unavailable,
};

enum class AgentQLocalResetPinVerifyResult {
    not_ready,
    verified,
    wrong_pin,
    locked,
    auth_unavailable,
};

enum class AgentQLocalResetLockoutReleaseResult {
    not_released,
    released,
    failed,
};

enum class AgentQLocalResetUiMaintenanceResult {
    unchanged,
    auth_unavailable,
    redraw_pin_verification_panel,
    redraw_wiping_panel,
    lockout_release_failed,
    lockout_released,
    panel_lost,
    settings_timeout,
    reset_timeout,
    error_recovery_timeout,
};

enum class AgentQLocalResetReturnToSettingsResult {
    stale,
    failed,
    started,
};

enum class AgentQLocalResetCommitFinishStatus {
    not_ready,
    committed,
};

enum class AgentQLocalResetErrorRecoveryActionResult {
    stale,
    confirmation_started,
    wipe_started,
};

struct AgentQLocalResetSnapshot {
    AgentQLocalResetStage stage;
    size_t pin_entry_length;
    AgentQTimeoutWindow input_window;
    bool lockout_active;
    bool flow_active;
};

struct AgentQLocalResetPersistenceOps {
    void (*clear_active_session)();
    bool (*persist_unprovisioned_state)();
    void (*record_material_failure)(AgentQPersistentMaterialRuntimeFailure failure);
};

struct AgentQLocalResetCommitFinishResult {
    AgentQLocalResetCommitFinishStatus status;
    AgentQLocalResetCommitResult commit_result;
};

AgentQLocalResetSnapshot local_reset_snapshot(TickType_t now);
bool local_reset_deadline_expired(TickType_t now);
bool local_reset_fail_processing_if_expired(TickType_t now);
AgentQLocalResetLockoutReleaseResult local_reset_release_lockout_if_elapsed(TickType_t now);
bool local_reset_wipe_ready(TickType_t now);

void local_reset_wipe();
bool local_reset_wipe_active();
void local_reset_begin_settings(AgentQTimeoutWindow input_window);
void local_reset_begin_error_recovery_confirm(AgentQTimeoutWindow input_window);
bool local_reset_begin_pin_entry(AgentQTimeoutWindow input_window);
bool local_reset_begin_error_recovery_wipe(TickType_t wipe_ready_at);
bool local_reset_close_settings();
AgentQLocalResetReturnToSettingsResult local_reset_return_to_settings(
    AgentQTimeoutWindow input_window);
bool local_reset_cancel_error_recovery();
bool local_reset_begin_settings_pin_auth_handoff();
bool local_reset_begin_error_recovery_confirm_if_idle(
    AgentQTimeoutWindow input_window);
AgentQLocalResetErrorRecoveryActionResult local_reset_handle_error_recovery_confirm(
    AgentQTimeoutWindow input_window,
    TickType_t wipe_ready_at,
    bool start_available);
bool local_reset_abort_pin_verification();
AgentQLocalResetUiMaintenanceResult local_reset_handle_ui_maintenance(
    bool panel_active,
    TickType_t now);
bool local_reset_add_pin_digit(char digit);
bool local_reset_clear_pin();
bool local_reset_backspace_pin();
AgentQLocalResetPinSubmitResult local_reset_submit_pin_for_verification(
    TickType_t verify_ready_at,
    TickType_t worker_deadline);
AgentQLocalResetPinVerifyResult local_reset_complete_pin_verify_job(
    const AgentQLocalAuthWorkerResult& result,
    TickType_t lockout_until,
    TickType_t wipe_ready_at);

AgentQLocalResetCommitResult local_reset_commit_material(
    const AgentQLocalResetPersistenceOps& ops);
AgentQLocalResetCommitFinishResult local_reset_finish_commit_if_ready(
    TickType_t now,
    const AgentQLocalResetPersistenceOps& ops);
AgentQLocalResetCommitResult local_reset_resume_pending_if_needed(
    const AgentQLocalResetPersistenceOps& ops,
    bool* marker_present);

}  // namespace agent_q
