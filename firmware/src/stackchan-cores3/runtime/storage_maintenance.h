#pragma once

#include <stddef.h>
#include <stdint.h>

#include "persistent_material.h"
#include "local_auth_worker.h"
#include "pin_attempt.h"
#include "timeout_window.h"
#include "freertos/FreeRTOS.h"

namespace signing {

constexpr uint32_t kStorageMaintenanceEntryMs = 60000;
constexpr uint32_t kStorageMaintenancePinLockoutMs = kPinLockoutMs;
constexpr uint8_t kStorageMaintenanceMaxWrongPinAttempts = kMaxWrongPinAttempts;

enum class StorageMaintenanceStage {
    none,
    settings_menu,
    pin_entry,
    pin_verifying,
    error_recovery_prompt,
    error_recovery_confirm,
    committing,
};

enum class StorageMaintenanceOperation {
    none,
    settings_reset,
    wallet_erase,
};

enum class StorageMaintenanceCommitResult {
    ok,
    missing_state,
    key_unavailable,
    auth_unavailable,
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
    material_incomplete_error,
    action_marker_storage_error,
    state_storage_error,
};

enum class StorageMaintenancePinSubmitResult {
    started_verification,
    invalid_pin,
    unavailable_stage,
    locked,
    worker_unavailable,
};

enum class StorageMaintenancePinVerifyResult {
    not_ready,
    verified,
    wrong_pin,
    locked,
    auth_unavailable,
};

enum class StorageMaintenanceLockoutReleaseResult {
    not_released,
    released,
    failed,
};

enum class StorageMaintenanceUiMaintenanceResult {
    unchanged,
    auth_unavailable,
    redraw_pin_verification_panel,
    redraw_committing_panel,
    lockout_release_failed,
    lockout_released,
    panel_lost,
    settings_timeout,
    action_timeout,
    error_recovery_timeout,
};

enum class StorageMaintenanceCancelPinResult {
    stale,
    failed,
    returned_to_settings,
    returned_to_error_recovery,
};

enum class StorageMaintenanceCommitFinishStatus {
    not_ready,
    committed,
};

enum class StorageMaintenanceErrorRecoveryActionResult {
    stale,
    confirmation_started,
    commit_started,
};

struct StorageMaintenanceSnapshot {
    StorageMaintenanceStage stage;
    StorageMaintenanceOperation operation;
    size_t pin_entry_length;
    TimeoutWindow input_window;
    bool lockout_active;
    bool flow_active;
};

struct StorageMaintenancePersistenceOps {
    void (*clear_active_session)();
    bool (*persist_state)(ProvisioningPersistedState state);
    void (*record_material_failure)(PersistentMaterialRuntimeFailure failure);
};

struct StorageMaintenanceCommitFinishResult {
    StorageMaintenanceCommitFinishStatus status;
    StorageMaintenanceOperation operation;
    StorageMaintenanceCommitResult commit_result;
};

StorageMaintenanceSnapshot storage_maintenance_snapshot(TickType_t now);
bool storage_maintenance_deadline_expired(TickType_t now);
bool storage_maintenance_fail_processing_if_expired(TickType_t now);
StorageMaintenanceLockoutReleaseResult storage_maintenance_release_lockout_if_elapsed(TickType_t now);
bool storage_maintenance_commit_ready(TickType_t now);
StorageMaintenanceOperation storage_maintenance_error_recovery_operation();

void storage_maintenance_clear_flow();
bool storage_maintenance_flow_active();
void storage_maintenance_begin_settings(TimeoutWindow input_window);
void storage_maintenance_begin_error_recovery_prompt(
    TimeoutWindow input_window,
    StorageMaintenanceOperation operation);
void storage_maintenance_begin_error_recovery_confirm(
    TimeoutWindow input_window,
    StorageMaintenanceOperation operation);
bool storage_maintenance_begin_pin_entry(TimeoutWindow input_window);
bool storage_maintenance_begin_wallet_erase_pin_entry(TimeoutWindow input_window);
bool storage_maintenance_begin_error_recovery_wallet_erase(TickType_t commit_ready_at);
bool storage_maintenance_begin_error_recovery_settings_repair(TimeoutWindow input_window);
bool storage_maintenance_close_settings();
StorageMaintenanceCancelPinResult storage_maintenance_cancel_pin_entry(
    TimeoutWindow input_window);
bool storage_maintenance_cancel_error_recovery();
bool storage_maintenance_begin_settings_pin_auth_handoff();
bool storage_maintenance_begin_error_recovery_prompt_if_idle(
    TimeoutWindow input_window,
    StorageMaintenanceOperation operation);
StorageMaintenanceErrorRecoveryActionResult storage_maintenance_handle_error_recovery_confirm(
    TimeoutWindow input_window,
    TickType_t commit_ready_at,
    bool start_available);
bool storage_maintenance_abort_pin_verification();
StorageMaintenanceUiMaintenanceResult storage_maintenance_handle_ui_maintenance(
    bool panel_active,
    TickType_t now);
bool storage_maintenance_add_pin_digit(char digit);
bool storage_maintenance_clear_pin();
bool storage_maintenance_backspace_pin();
StorageMaintenancePinSubmitResult storage_maintenance_submit_pin_for_verification(
    TickType_t verify_ready_at,
    TickType_t worker_deadline);
StorageMaintenancePinVerifyResult storage_maintenance_complete_pin_verify_job(
    const LocalAuthWorkerResult& result,
    TickType_t lockout_until,
    TickType_t commit_ready_at);

StorageMaintenanceCommitResult storage_maintenance_commit_material(
    const StorageMaintenancePersistenceOps& ops);
StorageMaintenanceCommitFinishResult storage_maintenance_finish_commit_if_ready(
    TickType_t now,
    const StorageMaintenancePersistenceOps& ops);
StorageMaintenanceCommitResult storage_maintenance_resume_pending_if_needed(
    const StorageMaintenancePersistenceOps& ops,
    bool* marker_present);

}  // namespace signing
