#include "storage_maintenance.h"

#include "local_auth.h"
#include "esp_err.h"
#include "esp_log.h"
#include "freertos/task.h"
#include "nvs.h"
#include "persistent_storage_names.h"

namespace signing {
namespace {

constexpr const char* kTag = "StorageMaintenance";
constexpr const char* kNvsNamespace = kMutableSettingsNvsNamespace;
constexpr const char* kStorageMaintenancePendingKey = "storage_action";
constexpr uint8_t kWalletErasePendingMarker = 1;
constexpr uint8_t kSettingsResetPendingMarker = 2;

enum class PinEntryOrigin {
    none,
    settings_menu,
    error_recovery,
};

struct StorageMaintenanceState {
    char pin_entry[kLocalPinBufferSize] = {};
    size_t pin_entry_length = 0;
    StorageMaintenanceStage stage = StorageMaintenanceStage::none;
    StorageMaintenanceOperation operation = StorageMaintenanceOperation::none;
    PinEntryOrigin pin_entry_origin = PinEntryOrigin::none;
    uint32_t auth_job_id = 0;
    TimeoutWindow input_window = kTimeoutWindowNone;
    PausedTimeoutWindow paused_input_window = kPausedTimeoutWindowNone;
    TickType_t verify_ready_at = 0;
    TickType_t commit_ready_at = 0;
    TickType_t worker_deadline = 0;

    void wipe()
    {
        wipe_pin_only();
        stage = StorageMaintenanceStage::none;
        operation = StorageMaintenanceOperation::none;
        pin_entry_origin = PinEntryOrigin::none;
    }

    void wipe_pin_only()
    {
        if (auth_job_id != 0) {
            local_auth_worker_cancel_job(auth_job_id);
        }
        wipe_sensitive_buffer(pin_entry, sizeof(pin_entry));
        pin_entry_length = 0;
        auth_job_id = 0;
        input_window = kTimeoutWindowNone;
        paused_input_window = kPausedTimeoutWindowNone;
        verify_ready_at = 0;
        commit_ready_at = 0;
        worker_deadline = 0;
    }

    void clear_lockout()
    {
        pin_attempt_clear();
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
        input_window = resumed;
        paused_input_window = kPausedTimeoutWindowNone;
        return true;
    }
};

StorageMaintenanceState g_storage_maintenance;

bool storage_maintenance_pin_locked_at(TickType_t now)
{
    return pin_attempt_locked_at(now);
}

uint8_t marker_for_operation(StorageMaintenanceOperation operation)
{
    switch (operation) {
        case StorageMaintenanceOperation::settings_reset:
            return kSettingsResetPendingMarker;
        case StorageMaintenanceOperation::wallet_erase:
            return kWalletErasePendingMarker;
        case StorageMaintenanceOperation::none:
        default:
            return 0;
    }
}

bool valid_storage_operation(StorageMaintenanceOperation operation)
{
    return operation == StorageMaintenanceOperation::settings_reset ||
           operation == StorageMaintenanceOperation::wallet_erase;
}

bool set_storage_maintenance_pending_marker(StorageMaintenanceOperation operation)
{
    const uint8_t marker = marker_for_operation(operation);
    if (marker == 0) {
        return false;
    }

    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while setting storage action marker: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_set_u8(nvs, kStorageMaintenancePendingKey, marker);
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Storage action marker write failed: %s", esp_err_to_name(result));
        return false;
    }
    return true;
}

bool clear_storage_maintenance_pending_marker()
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while clearing storage action marker: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_erase_key(nvs, kStorageMaintenancePendingKey);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return true;
    }
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Storage action marker erase failed: %s", esp_err_to_name(result));
        return false;
    }
    return true;
}

void record_material_failure(
    const StorageMaintenancePersistenceOps& ops,
    PersistentMaterialRuntimeFailure failure)
{
    if (ops.record_material_failure != nullptr) {
        ops.record_material_failure(failure);
    }
}

bool persist_state(
    const StorageMaintenancePersistenceOps& ops,
    ProvisioningPersistedState state)
{
    return ops.persist_state != nullptr && ops.persist_state(state);
}

StorageMaintenanceCommitResult erase_wallet_material(
    const StorageMaintenancePersistenceOps& ops)
{
    if (ops.clear_active_session != nullptr) {
        ops.clear_active_session();
    }

    switch (persistent_material_wallet_erase()) {
        case PersistentMaterialWalletEraseResult::ok:
            break;
        case PersistentMaterialWalletEraseResult::root_wipe_error:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::wallet_erase_root_wipe_failed);
            return StorageMaintenanceCommitResult::root_wipe_error;
        case PersistentMaterialWalletEraseResult::policy_wipe_error:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::wallet_erase_policy_wipe_failed);
            return StorageMaintenanceCommitResult::policy_wipe_error;
        case PersistentMaterialWalletEraseResult::local_auth_wipe_error:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::wallet_erase_local_auth_wipe_failed);
            return StorageMaintenanceCommitResult::local_auth_wipe_error;
        case PersistentMaterialWalletEraseResult::human_approval_setting_wipe_error:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::wallet_erase_human_approval_setting_wipe_failed);
            return StorageMaintenanceCommitResult::human_approval_setting_wipe_error;
        case PersistentMaterialWalletEraseResult::signing_mode_wipe_error:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::wallet_erase_signing_mode_wipe_failed);
            return StorageMaintenanceCommitResult::signing_mode_wipe_error;
        case PersistentMaterialWalletEraseResult::sui_account_settings_wipe_error:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::wallet_erase_sui_account_settings_wipe_failed);
            return StorageMaintenanceCommitResult::sui_account_settings_wipe_error;
        case PersistentMaterialWalletEraseResult::approval_history_wipe_error:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::wallet_erase_approval_history_wipe_failed);
            return StorageMaintenanceCommitResult::approval_history_wipe_error;
        case PersistentMaterialWalletEraseResult::policy_update_marker_wipe_error:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::wallet_erase_policy_update_marker_wipe_failed);
            return StorageMaintenanceCommitResult::policy_update_marker_wipe_error;
        case PersistentMaterialWalletEraseResult::zklogin_proof_wipe_error:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::wallet_erase_zklogin_proof_wipe_failed);
            return StorageMaintenanceCommitResult::zklogin_proof_wipe_error;
        case PersistentMaterialWalletEraseResult::material_remaining_error:
        default:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::wallet_erase_material_remaining);
            return StorageMaintenanceCommitResult::material_remaining_error;
    }

    if (!persist_state(ops, ProvisioningPersistedState::unprovisioned)) {
        record_material_failure(ops, PersistentMaterialRuntimeFailure::wallet_erase_state_storage_failed);
        return StorageMaintenanceCommitResult::state_storage_error;
    }
    if (!clear_storage_maintenance_pending_marker()) {
        record_material_failure(ops, PersistentMaterialRuntimeFailure::wallet_erase_marker_clear_failed);
        return StorageMaintenanceCommitResult::state_storage_error;
    }

    return StorageMaintenanceCommitResult::ok;
}

StorageMaintenanceCommitResult reset_recoverable_settings(
    const StorageMaintenancePersistenceOps& ops)
{
    if (ops.clear_active_session != nullptr) {
        ops.clear_active_session();
    }

    switch (persistent_material_reset_recoverable_settings()) {
        case PersistentMaterialSettingsResetResult::ok:
            break;
        case PersistentMaterialSettingsResetResult::key_unavailable:
            return StorageMaintenanceCommitResult::key_unavailable;
        case PersistentMaterialSettingsResetResult::auth_unavailable:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::settings_reset_auth_unavailable);
            return StorageMaintenanceCommitResult::auth_unavailable;
        case PersistentMaterialSettingsResetResult::policy_store_error:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::settings_reset_policy_store_failed);
            return StorageMaintenanceCommitResult::policy_wipe_error;
        case PersistentMaterialSettingsResetResult::human_approval_setting_store_error:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::settings_reset_human_approval_setting_store_failed);
            return StorageMaintenanceCommitResult::human_approval_setting_wipe_error;
        case PersistentMaterialSettingsResetResult::signing_mode_store_error:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::settings_reset_signing_mode_store_failed);
            return StorageMaintenanceCommitResult::signing_mode_wipe_error;
        case PersistentMaterialSettingsResetResult::sui_account_settings_store_error:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::settings_reset_sui_account_settings_store_failed);
            return StorageMaintenanceCommitResult::sui_account_settings_wipe_error;
        case PersistentMaterialSettingsResetResult::approval_history_wipe_error:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::settings_reset_approval_history_wipe_failed);
            return StorageMaintenanceCommitResult::approval_history_wipe_error;
        case PersistentMaterialSettingsResetResult::policy_update_marker_wipe_error:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::settings_reset_policy_update_marker_wipe_failed);
            return StorageMaintenanceCommitResult::policy_update_marker_wipe_error;
        case PersistentMaterialSettingsResetResult::zklogin_proof_wipe_error:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::settings_reset_zklogin_proof_wipe_failed);
            return StorageMaintenanceCommitResult::zklogin_proof_wipe_error;
        case PersistentMaterialSettingsResetResult::material_incomplete_error:
        default:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::settings_reset_material_incomplete);
            return StorageMaintenanceCommitResult::material_incomplete_error;
    }

    if (!persist_state(ops, ProvisioningPersistedState::provisioned)) {
        record_material_failure(ops, PersistentMaterialRuntimeFailure::settings_reset_state_storage_failed);
        return StorageMaintenanceCommitResult::state_storage_error;
    }
    if (!clear_storage_maintenance_pending_marker()) {
        record_material_failure(ops, PersistentMaterialRuntimeFailure::settings_reset_marker_clear_failed);
        return StorageMaintenanceCommitResult::state_storage_error;
    }

    return StorageMaintenanceCommitResult::ok;
}

}  // namespace

StorageMaintenanceSnapshot storage_maintenance_snapshot(TickType_t now)
{
    return StorageMaintenanceSnapshot{
        g_storage_maintenance.stage,
        g_storage_maintenance.operation,
        g_storage_maintenance.pin_entry_length,
        g_storage_maintenance.input_window,
        storage_maintenance_pin_locked_at(now),
        g_storage_maintenance.stage != StorageMaintenanceStage::none,
    };
}

bool storage_maintenance_deadline_expired(TickType_t now)
{
    return timeout_window_reached(g_storage_maintenance.input_window, now);
}

static bool storage_maintenance_processing_deadline_expired(TickType_t now)
{
    return g_storage_maintenance.stage == StorageMaintenanceStage::pin_verifying &&
           timeout_window_tick_reached(now, g_storage_maintenance.worker_deadline);
}

bool storage_maintenance_fail_processing_if_expired(TickType_t now)
{
    if (!storage_maintenance_processing_deadline_expired(now)) {
        return false;
    }
    g_storage_maintenance.wipe();
    return true;
}

StorageMaintenanceLockoutReleaseResult storage_maintenance_release_lockout_if_elapsed(TickType_t now)
{
    if (g_storage_maintenance.stage != StorageMaintenanceStage::pin_entry ||
        !pin_attempt_lockout_elapsed_at(now)) {
        return StorageMaintenanceLockoutReleaseResult::not_released;
    }

    if (timeout_paused_window_valid(g_storage_maintenance.paused_input_window)) {
        if (!g_storage_maintenance.resume_paused_input_window(now)) {
            g_storage_maintenance.wipe();
            pin_attempt_clear();
            return StorageMaintenanceLockoutReleaseResult::failed;
        }
        pin_attempt_clear();
        return StorageMaintenanceLockoutReleaseResult::released;
    }
    if (timeout_window_valid(g_storage_maintenance.input_window)) {
        pin_attempt_clear();
        return StorageMaintenanceLockoutReleaseResult::released;
    }
    g_storage_maintenance.wipe();
    pin_attempt_clear();
    return StorageMaintenanceLockoutReleaseResult::failed;
}

bool storage_maintenance_commit_ready(TickType_t now)
{
    return g_storage_maintenance.stage == StorageMaintenanceStage::committing &&
           timeout_window_tick_reached(now, g_storage_maintenance.commit_ready_at);
}

void storage_maintenance_clear_flow()
{
    g_storage_maintenance.wipe();
}

bool storage_maintenance_flow_active()
{
    return g_storage_maintenance.stage != StorageMaintenanceStage::none;
}

void storage_maintenance_begin_settings(TimeoutWindow input_window)
{
    g_storage_maintenance.wipe();
    if (!timeout_window_valid(input_window)) {
        return;
    }
    g_storage_maintenance.stage = StorageMaintenanceStage::settings_menu;
    g_storage_maintenance.operation = StorageMaintenanceOperation::none;
    g_storage_maintenance.input_window = input_window;
}

void storage_maintenance_begin_error_recovery_prompt(
    TimeoutWindow input_window,
    StorageMaintenanceOperation operation)
{
    g_storage_maintenance.wipe();
    if (!timeout_window_valid(input_window) ||
        !valid_storage_operation(operation)) {
        return;
    }
    g_storage_maintenance.stage = StorageMaintenanceStage::error_recovery_prompt;
    g_storage_maintenance.operation = operation;
    g_storage_maintenance.input_window = input_window;
}

void storage_maintenance_begin_error_recovery_confirm(
    TimeoutWindow input_window,
    StorageMaintenanceOperation operation)
{
    g_storage_maintenance.wipe();
    if (!timeout_window_valid(input_window) ||
        !valid_storage_operation(operation)) {
        return;
    }
    g_storage_maintenance.stage = StorageMaintenanceStage::error_recovery_confirm;
    g_storage_maintenance.operation = operation;
    g_storage_maintenance.input_window = input_window;
}

bool storage_maintenance_begin_pin_entry(TimeoutWindow input_window)
{
    if (g_storage_maintenance.stage != StorageMaintenanceStage::settings_menu ||
        !timeout_window_valid(input_window)) {
        return false;
    }

    pin_attempt_release_if_elapsed(xTaskGetTickCount());
    g_storage_maintenance.wipe_pin_only();
    g_storage_maintenance.stage = StorageMaintenanceStage::pin_entry;
    g_storage_maintenance.operation = StorageMaintenanceOperation::settings_reset;
    g_storage_maintenance.pin_entry_origin = PinEntryOrigin::settings_menu;
    g_storage_maintenance.input_window = input_window;
    return true;
}

bool storage_maintenance_begin_wallet_erase_pin_entry(TimeoutWindow input_window)
{
    if (!storage_maintenance_begin_pin_entry(input_window)) {
        return false;
    }
    g_storage_maintenance.operation = StorageMaintenanceOperation::wallet_erase;
    return true;
}

bool storage_maintenance_begin_error_recovery_wallet_erase(TickType_t commit_ready_at)
{
    if (g_storage_maintenance.stage != StorageMaintenanceStage::error_recovery_confirm ||
        g_storage_maintenance.operation != StorageMaintenanceOperation::wallet_erase) {
        return false;
    }
    g_storage_maintenance.wipe_pin_only();
    g_storage_maintenance.clear_lockout();
    g_storage_maintenance.stage = StorageMaintenanceStage::committing;
    g_storage_maintenance.operation = StorageMaintenanceOperation::wallet_erase;
    g_storage_maintenance.commit_ready_at = commit_ready_at;
    return true;
}

bool storage_maintenance_begin_error_recovery_settings_repair(TimeoutWindow input_window)
{
    if ((g_storage_maintenance.stage != StorageMaintenanceStage::error_recovery_prompt &&
         g_storage_maintenance.stage != StorageMaintenanceStage::error_recovery_confirm) ||
        g_storage_maintenance.operation != StorageMaintenanceOperation::settings_reset ||
        !timeout_window_valid(input_window)) {
        return false;
    }

    pin_attempt_release_if_elapsed(xTaskGetTickCount());
    g_storage_maintenance.wipe_pin_only();
    g_storage_maintenance.stage = StorageMaintenanceStage::pin_entry;
    g_storage_maintenance.operation = StorageMaintenanceOperation::settings_reset;
    g_storage_maintenance.pin_entry_origin = PinEntryOrigin::error_recovery;
    g_storage_maintenance.input_window = input_window;
    return true;
}

bool storage_maintenance_close_settings()
{
    if (g_storage_maintenance.stage != StorageMaintenanceStage::settings_menu) {
        return false;
    }
    g_storage_maintenance.wipe();
    return true;
}

StorageMaintenanceCancelPinResult storage_maintenance_cancel_pin_entry(
    TimeoutWindow input_window)
{
    if (g_storage_maintenance.stage != StorageMaintenanceStage::pin_entry) {
        return StorageMaintenanceCancelPinResult::stale;
    }

    const PinEntryOrigin origin = g_storage_maintenance.pin_entry_origin;
    if (origin == PinEntryOrigin::error_recovery) {
        storage_maintenance_begin_error_recovery_prompt(
            input_window,
            StorageMaintenanceOperation::settings_reset);
        return g_storage_maintenance.stage == StorageMaintenanceStage::error_recovery_prompt
                   ? StorageMaintenanceCancelPinResult::returned_to_error_recovery
                   : StorageMaintenanceCancelPinResult::failed;
    }
    if (origin != PinEntryOrigin::settings_menu) {
        g_storage_maintenance.wipe();
        return StorageMaintenanceCancelPinResult::failed;
    }
    storage_maintenance_begin_settings(input_window);
    return g_storage_maintenance.stage == StorageMaintenanceStage::settings_menu
               ? StorageMaintenanceCancelPinResult::returned_to_settings
               : StorageMaintenanceCancelPinResult::failed;
}

bool storage_maintenance_cancel_error_recovery()
{
    if (g_storage_maintenance.stage != StorageMaintenanceStage::error_recovery_prompt &&
        g_storage_maintenance.stage != StorageMaintenanceStage::error_recovery_confirm) {
        return false;
    }
    g_storage_maintenance.wipe();
    return true;
}

bool storage_maintenance_begin_settings_pin_auth_handoff()
{
    if (g_storage_maintenance.stage != StorageMaintenanceStage::settings_menu) {
        return false;
    }
    g_storage_maintenance.wipe();
    return true;
}

bool storage_maintenance_begin_error_recovery_prompt_if_idle(
    TimeoutWindow input_window,
    StorageMaintenanceOperation operation)
{
    if (g_storage_maintenance.stage != StorageMaintenanceStage::none) {
        return false;
    }
    storage_maintenance_begin_error_recovery_prompt(input_window, operation);
    return g_storage_maintenance.stage == StorageMaintenanceStage::error_recovery_prompt;
}

StorageMaintenanceErrorRecoveryActionResult storage_maintenance_handle_error_recovery_confirm(
    TimeoutWindow input_window,
    TickType_t commit_ready_at,
    bool start_available)
{
    if (g_storage_maintenance.stage == StorageMaintenanceStage::none) {
        (void)input_window;
        (void)start_available;
        return StorageMaintenanceErrorRecoveryActionResult::stale;
    }
    if (g_storage_maintenance.stage == StorageMaintenanceStage::error_recovery_prompt) {
        if (g_storage_maintenance.operation != StorageMaintenanceOperation::wallet_erase) {
            return StorageMaintenanceErrorRecoveryActionResult::stale;
        }
        storage_maintenance_begin_error_recovery_confirm(
            input_window,
            StorageMaintenanceOperation::wallet_erase);
        return g_storage_maintenance.stage == StorageMaintenanceStage::error_recovery_confirm
                   ? StorageMaintenanceErrorRecoveryActionResult::confirmation_started
                   : StorageMaintenanceErrorRecoveryActionResult::stale;
    }
    if (g_storage_maintenance.stage != StorageMaintenanceStage::error_recovery_confirm) {
        return StorageMaintenanceErrorRecoveryActionResult::stale;
    }
    if (!storage_maintenance_begin_error_recovery_wallet_erase(commit_ready_at)) {
        return StorageMaintenanceErrorRecoveryActionResult::stale;
    }
    return StorageMaintenanceErrorRecoveryActionResult::commit_started;
}

bool storage_maintenance_abort_pin_verification()
{
    if (g_storage_maintenance.stage != StorageMaintenanceStage::pin_verifying) {
        return false;
    }
    g_storage_maintenance.wipe();
    return true;
}

StorageMaintenanceUiMaintenanceResult storage_maintenance_handle_ui_maintenance(
    bool panel_active,
    TickType_t now)
{
    if (g_storage_maintenance.stage == StorageMaintenanceStage::none) {
        return StorageMaintenanceUiMaintenanceResult::unchanged;
    }
    if (g_storage_maintenance.stage == StorageMaintenanceStage::pin_verifying) {
        if (storage_maintenance_fail_processing_if_expired(now)) {
            return StorageMaintenanceUiMaintenanceResult::auth_unavailable;
        }
        if (!panel_active) {
            return StorageMaintenanceUiMaintenanceResult::redraw_pin_verification_panel;
        }
        return StorageMaintenanceUiMaintenanceResult::unchanged;
    }
    if (g_storage_maintenance.stage == StorageMaintenanceStage::committing) {
        if (!panel_active) {
            return StorageMaintenanceUiMaintenanceResult::redraw_committing_panel;
        }
        return StorageMaintenanceUiMaintenanceResult::unchanged;
    }

    const StorageMaintenanceLockoutReleaseResult lockout_release =
        storage_maintenance_release_lockout_if_elapsed(now);
    if (lockout_release == StorageMaintenanceLockoutReleaseResult::failed) {
        return StorageMaintenanceUiMaintenanceResult::lockout_release_failed;
    }
    if (lockout_release == StorageMaintenanceLockoutReleaseResult::released) {
        return StorageMaintenanceUiMaintenanceResult::lockout_released;
    }

    const bool expired = storage_maintenance_deadline_expired(now);
    if (panel_active && !expired) {
        return StorageMaintenanceUiMaintenanceResult::unchanged;
    }

    const StorageMaintenanceStage stage = g_storage_maintenance.stage;
    if (!panel_active) {
        g_storage_maintenance.wipe();
    }
    if (!expired) {
        return StorageMaintenanceUiMaintenanceResult::panel_lost;
    }
    if (stage == StorageMaintenanceStage::settings_menu) {
        return StorageMaintenanceUiMaintenanceResult::settings_timeout;
    }
    if (stage == StorageMaintenanceStage::error_recovery_prompt ||
        stage == StorageMaintenanceStage::error_recovery_confirm) {
        return StorageMaintenanceUiMaintenanceResult::error_recovery_timeout;
    }
    return StorageMaintenanceUiMaintenanceResult::action_timeout;
}

bool storage_maintenance_add_pin_digit(char digit)
{
    const TickType_t now = xTaskGetTickCount();
    if (g_storage_maintenance.stage != StorageMaintenanceStage::pin_entry ||
        timeout_window_reached(g_storage_maintenance.input_window, now) ||
        storage_maintenance_pin_locked_at(now) ||
        digit < '0' || digit > '9') {
        return false;
    }
    if (g_storage_maintenance.pin_entry_length >= kLocalPinDigits) {
        return false;
    }

    g_storage_maintenance.pin_entry[g_storage_maintenance.pin_entry_length++] = digit;
    g_storage_maintenance.pin_entry[g_storage_maintenance.pin_entry_length] = '\0';
    return true;
}

bool storage_maintenance_clear_pin()
{
    const TickType_t now = xTaskGetTickCount();
    if (g_storage_maintenance.stage != StorageMaintenanceStage::pin_entry ||
        timeout_window_reached(g_storage_maintenance.input_window, now) ||
        storage_maintenance_pin_locked_at(now)) {
        return false;
    }

    wipe_sensitive_buffer(g_storage_maintenance.pin_entry, sizeof(g_storage_maintenance.pin_entry));
    g_storage_maintenance.pin_entry_length = 0;
    return true;
}

bool storage_maintenance_backspace_pin()
{
    const TickType_t now = xTaskGetTickCount();
    if (g_storage_maintenance.stage != StorageMaintenanceStage::pin_entry ||
        timeout_window_reached(g_storage_maintenance.input_window, now) ||
        storage_maintenance_pin_locked_at(now)) {
        return false;
    }
    if (g_storage_maintenance.pin_entry_length > 0) {
        g_storage_maintenance.pin_entry[--g_storage_maintenance.pin_entry_length] = '\0';
    }
    return true;
}

StorageMaintenancePinSubmitResult storage_maintenance_submit_pin_for_verification(
    TickType_t verify_ready_at,
    TickType_t worker_deadline)
{
    const TickType_t now = xTaskGetTickCount();
    if (g_storage_maintenance.stage != StorageMaintenanceStage::pin_entry) {
        return StorageMaintenancePinSubmitResult::unavailable_stage;
    }
    if (timeout_window_reached(g_storage_maintenance.input_window, now)) {
        return StorageMaintenancePinSubmitResult::unavailable_stage;
    }
    if (storage_maintenance_pin_locked_at(now)) {
        return StorageMaintenancePinSubmitResult::locked;
    }
    if (g_storage_maintenance.pin_entry_length != kLocalPinDigits ||
        !is_valid_local_pin(g_storage_maintenance.pin_entry)) {
        return StorageMaintenancePinSubmitResult::invalid_pin;
    }

    uint32_t job_id = 0;
    if (!g_storage_maintenance.pause_input_window(now)) {
        return StorageMaintenancePinSubmitResult::unavailable_stage;
    }
    if (!local_auth_worker_submit_verify(
            LocalAuthWorkerOwner::storage_maintenance,
            g_storage_maintenance.pin_entry,
            &job_id)) {
        g_storage_maintenance.resume_paused_input_window(now);
        return StorageMaintenancePinSubmitResult::worker_unavailable;
    }

    wipe_sensitive_buffer(g_storage_maintenance.pin_entry, sizeof(g_storage_maintenance.pin_entry));
    g_storage_maintenance.pin_entry_length = 0;
    g_storage_maintenance.stage = StorageMaintenanceStage::pin_verifying;
    g_storage_maintenance.auth_job_id = job_id;
    g_storage_maintenance.input_window = kTimeoutWindowNone;
    g_storage_maintenance.verify_ready_at = verify_ready_at;
    g_storage_maintenance.commit_ready_at = 0;
    g_storage_maintenance.worker_deadline = worker_deadline;
    return StorageMaintenancePinSubmitResult::started_verification;
}

StorageMaintenancePinVerifyResult storage_maintenance_complete_pin_verify_job(
    const LocalAuthWorkerResult& result,
    TickType_t lockout_until,
    TickType_t commit_ready_at)
{
    if (g_storage_maintenance.stage != StorageMaintenanceStage::pin_verifying ||
        g_storage_maintenance.auth_job_id == 0 ||
        result.job_id != g_storage_maintenance.auth_job_id ||
        result.owner != LocalAuthWorkerOwner::storage_maintenance ||
        result.operation != LocalAuthWorkerOperation::verify_pin) {
        return StorageMaintenancePinVerifyResult::not_ready;
    }
    if (storage_maintenance_processing_deadline_expired(xTaskGetTickCount())) {
        g_storage_maintenance.wipe();
        return StorageMaintenancePinVerifyResult::auth_unavailable;
    }

    g_storage_maintenance.auth_job_id = 0;
    g_storage_maintenance.verify_ready_at = 0;
    g_storage_maintenance.worker_deadline = 0;
    if (result.status != LocalAuthWorkerStatus::ok) {
        g_storage_maintenance.wipe();
        return StorageMaintenancePinVerifyResult::auth_unavailable;
    }

    if (!result.verified) {
        const TickType_t now = xTaskGetTickCount();
        g_storage_maintenance.stage = StorageMaintenanceStage::pin_entry;
        wipe_sensitive_buffer(g_storage_maintenance.pin_entry, sizeof(g_storage_maintenance.pin_entry));
        g_storage_maintenance.pin_entry_length = 0;
        if (pin_attempt_record_failure(lockout_until)) {
            return StorageMaintenancePinVerifyResult::locked;
        }
        if (!g_storage_maintenance.resume_paused_input_window(now)) {
            g_storage_maintenance.wipe();
            return StorageMaintenancePinVerifyResult::auth_unavailable;
        }
        return StorageMaintenancePinVerifyResult::wrong_pin;
    }

    wipe_sensitive_buffer(g_storage_maintenance.pin_entry, sizeof(g_storage_maintenance.pin_entry));
    g_storage_maintenance.pin_entry_length = 0;
    g_storage_maintenance.stage = StorageMaintenanceStage::committing;
    g_storage_maintenance.input_window = kTimeoutWindowNone;
    g_storage_maintenance.clear_lockout();
    g_storage_maintenance.commit_ready_at = commit_ready_at;
    return StorageMaintenancePinVerifyResult::verified;
}

StorageMaintenanceOperation storage_maintenance_pending_marker_operation()
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READONLY, &nvs);
    if (result != ESP_OK) {
        if (result != ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGW(kTag, "NVS open failed while checking storage action marker: %s", esp_err_to_name(result));
        }
        return StorageMaintenanceOperation::none;
    }

    uint8_t marker = 0;
    result = nvs_get_u8(nvs, kStorageMaintenancePendingKey, &marker);
    nvs_close(nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return StorageMaintenanceOperation::none;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Storage action marker read failed: %s", esp_err_to_name(result));
        return StorageMaintenanceOperation::none;
    }
    if (marker == kSettingsResetPendingMarker) {
        return StorageMaintenanceOperation::settings_reset;
    }
    if (marker == kWalletErasePendingMarker) {
        return StorageMaintenanceOperation::wallet_erase;
    }
    return StorageMaintenanceOperation::none;
}

StorageMaintenanceOperation storage_maintenance_error_recovery_operation()
{
    const StorageMaintenanceOperation pending = storage_maintenance_pending_marker_operation();
    if (pending != StorageMaintenanceOperation::none) {
        return pending;
    }
    return persistent_material_can_reset_recoverable_settings()
               ? StorageMaintenanceOperation::settings_reset
               : StorageMaintenanceOperation::wallet_erase;
}

StorageMaintenanceCommitResult storage_maintenance_commit_material(
    const StorageMaintenancePersistenceOps& ops)
{
    const StorageMaintenanceOperation operation = g_storage_maintenance.operation;
    if (g_storage_maintenance.stage != StorageMaintenanceStage::committing ||
        operation == StorageMaintenanceOperation::none) {
        return StorageMaintenanceCommitResult::missing_state;
    }
    if (!set_storage_maintenance_pending_marker(operation)) {
        ESP_LOGW(kTag, "Storage action could not create pending marker; material was not changed");
        return StorageMaintenanceCommitResult::action_marker_storage_error;
    }
    if (operation == StorageMaintenanceOperation::settings_reset) {
        return reset_recoverable_settings(ops);
    }
    return erase_wallet_material(ops);
}

StorageMaintenanceCommitFinishResult storage_maintenance_finish_commit_if_ready(
    TickType_t now,
    const StorageMaintenancePersistenceOps& ops)
{
    if (!storage_maintenance_commit_ready(now)) {
        return StorageMaintenanceCommitFinishResult{
            StorageMaintenanceCommitFinishStatus::not_ready,
            StorageMaintenanceOperation::none,
            StorageMaintenanceCommitResult::missing_state,
        };
    }

    const StorageMaintenanceOperation operation = g_storage_maintenance.operation;
    const StorageMaintenanceCommitResult result = storage_maintenance_commit_material(ops);
    g_storage_maintenance.wipe();
    return StorageMaintenanceCommitFinishResult{
        StorageMaintenanceCommitFinishStatus::committed,
        operation,
        result,
    };
}

StorageMaintenanceCommitResult storage_maintenance_resume_pending_if_needed(
    const StorageMaintenancePersistenceOps& ops,
    bool* marker_present)
{
    const StorageMaintenanceOperation operation = storage_maintenance_pending_marker_operation();
    const bool present = operation != StorageMaintenanceOperation::none;
    if (marker_present != nullptr) {
        *marker_present = present;
    }
    if (!present) {
        return StorageMaintenanceCommitResult::missing_state;
    }
    if (operation == StorageMaintenanceOperation::settings_reset) {
        return reset_recoverable_settings(ops);
    }
    return erase_wallet_material(ops);
}

}  // namespace signing
