#include "local_reset.h"

#include "local_auth.h"
#include "esp_err.h"
#include "esp_log.h"
#include "freertos/task.h"
#include "nvs.h"

namespace signing {
namespace {

constexpr const char* kTag = "LocalReset";
constexpr const char* kNvsNamespace = "signing";
constexpr const char* kLocalResetPendingKey = "reset_pending";

struct LocalResetState {
    char pin_entry[kLocalPinBufferSize] = {};
    size_t pin_entry_length = 0;
    LocalResetStage stage = LocalResetStage::none;
    uint32_t auth_job_id = 0;
    TimeoutWindow input_window = kTimeoutWindowNone;
    PausedTimeoutWindow paused_input_window = kPausedTimeoutWindowNone;
    TickType_t verify_ready_at = 0;
    TickType_t wipe_ready_at = 0;
    TickType_t worker_deadline = 0;

    void wipe()
    {
        wipe_pin_only();
        stage = LocalResetStage::none;
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
        wipe_ready_at = 0;
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

LocalResetState g_local_reset;

bool local_reset_pin_locked_at(TickType_t now)
{
    return pin_attempt_locked_at(now);
}

bool set_local_reset_pending_marker()
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while setting local reset marker: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_set_u8(nvs, kLocalResetPendingKey, 1);
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Local reset marker write failed: %s", esp_err_to_name(result));
        return false;
    }
    return true;
}

bool clear_local_reset_pending_marker()
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READWRITE, &nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "NVS open failed while clearing local reset marker: %s", esp_err_to_name(result));
        return false;
    }

    result = nvs_erase_key(nvs, kLocalResetPendingKey);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return true;
    }
    if (result == ESP_OK) {
        result = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Local reset marker erase failed: %s", esp_err_to_name(result));
        return false;
    }
    return true;
}

void record_material_failure(
    const LocalResetPersistenceOps& ops,
    PersistentMaterialRuntimeFailure failure)
{
    if (ops.record_material_failure != nullptr) {
        ops.record_material_failure(failure);
    }
}

LocalResetCommitResult wipe_persistent_material_for_local_reset(
    const LocalResetPersistenceOps& ops)
{
    if (ops.clear_active_session != nullptr) {
        ops.clear_active_session();
    }

    switch (persistent_material_wipe_all()) {
        case PersistentMaterialWipeResult::ok:
            break;
        case PersistentMaterialWipeResult::root_wipe_error:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::local_reset_root_wipe_failed);
            return LocalResetCommitResult::root_wipe_error;
        case PersistentMaterialWipeResult::policy_wipe_error:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::local_reset_policy_wipe_failed);
            return LocalResetCommitResult::policy_wipe_error;
        case PersistentMaterialWipeResult::local_auth_wipe_error:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::local_reset_local_auth_wipe_failed);
            return LocalResetCommitResult::local_auth_wipe_error;
        case PersistentMaterialWipeResult::human_approval_setting_wipe_error:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::local_reset_human_approval_setting_wipe_failed);
            return LocalResetCommitResult::human_approval_setting_wipe_error;
        case PersistentMaterialWipeResult::signing_mode_wipe_error:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::local_reset_signing_mode_wipe_failed);
            return LocalResetCommitResult::signing_mode_wipe_error;
        case PersistentMaterialWipeResult::sui_account_settings_wipe_error:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::local_reset_sui_account_settings_wipe_failed);
            return LocalResetCommitResult::sui_account_settings_wipe_error;
        case PersistentMaterialWipeResult::approval_history_wipe_error:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::local_reset_approval_history_wipe_failed);
            return LocalResetCommitResult::approval_history_wipe_error;
        case PersistentMaterialWipeResult::policy_update_marker_wipe_error:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::local_reset_policy_update_marker_wipe_failed);
            return LocalResetCommitResult::policy_update_marker_wipe_error;
        case PersistentMaterialWipeResult::zklogin_proof_wipe_error:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::local_reset_zklogin_proof_wipe_failed);
            return LocalResetCommitResult::zklogin_proof_wipe_error;
        case PersistentMaterialWipeResult::material_remaining_error:
        default:
            record_material_failure(ops, PersistentMaterialRuntimeFailure::local_reset_material_remaining);
            return LocalResetCommitResult::material_remaining_error;
    }

    if (ops.persist_unprovisioned_state == nullptr ||
        !ops.persist_unprovisioned_state()) {
        record_material_failure(ops, PersistentMaterialRuntimeFailure::local_reset_state_storage_failed);
        return LocalResetCommitResult::state_storage_error;
    }
    if (!clear_local_reset_pending_marker()) {
        record_material_failure(ops, PersistentMaterialRuntimeFailure::local_reset_marker_clear_failed);
        return LocalResetCommitResult::state_storage_error;
    }

    return LocalResetCommitResult::ok;
}

}  // namespace

LocalResetSnapshot local_reset_snapshot(TickType_t now)
{
    return LocalResetSnapshot{
        g_local_reset.stage,
        g_local_reset.pin_entry_length,
        g_local_reset.input_window,
        local_reset_pin_locked_at(now),
        g_local_reset.stage != LocalResetStage::none,
    };
}

bool local_reset_deadline_expired(TickType_t now)
{
    return timeout_window_reached(g_local_reset.input_window, now);
}

static bool local_reset_processing_deadline_expired(TickType_t now)
{
    return g_local_reset.stage == LocalResetStage::pin_verifying &&
           timeout_window_tick_reached(now, g_local_reset.worker_deadline);
}

bool local_reset_fail_processing_if_expired(TickType_t now)
{
    if (!local_reset_processing_deadline_expired(now)) {
        return false;
    }
    g_local_reset.wipe();
    return true;
}

LocalResetLockoutReleaseResult local_reset_release_lockout_if_elapsed(TickType_t now)
{
    if (g_local_reset.stage != LocalResetStage::pin_entry ||
        !pin_attempt_lockout_elapsed_at(now)) {
        return LocalResetLockoutReleaseResult::not_released;
    }

    if (timeout_paused_window_valid(g_local_reset.paused_input_window)) {
        if (!g_local_reset.resume_paused_input_window(now)) {
            g_local_reset.wipe();
            pin_attempt_clear();
            return LocalResetLockoutReleaseResult::failed;
        }
        pin_attempt_clear();
        return LocalResetLockoutReleaseResult::released;
    }
    if (timeout_window_valid(g_local_reset.input_window)) {
        pin_attempt_clear();
        return LocalResetLockoutReleaseResult::released;
    }
    g_local_reset.wipe();
    pin_attempt_clear();
    return LocalResetLockoutReleaseResult::failed;
}

bool local_reset_wipe_ready(TickType_t now)
{
    return g_local_reset.stage == LocalResetStage::wiping &&
           timeout_window_tick_reached(now, g_local_reset.wipe_ready_at);
}

void local_reset_wipe()
{
    g_local_reset.wipe();
}

bool local_reset_wipe_active()
{
    const bool active = g_local_reset.stage != LocalResetStage::none;
    g_local_reset.wipe();
    return active;
}

void local_reset_begin_settings(TimeoutWindow input_window)
{
    g_local_reset.wipe();
    if (!timeout_window_valid(input_window)) {
        return;
    }
    g_local_reset.stage = LocalResetStage::settings_menu;
    g_local_reset.input_window = input_window;
}

void local_reset_begin_error_recovery_confirm(TimeoutWindow input_window)
{
    g_local_reset.wipe();
    if (!timeout_window_valid(input_window)) {
        return;
    }
    g_local_reset.stage = LocalResetStage::error_recovery_confirm;
    g_local_reset.input_window = input_window;
}

bool local_reset_begin_pin_entry(TimeoutWindow input_window)
{
    if (g_local_reset.stage != LocalResetStage::settings_menu ||
        !timeout_window_valid(input_window)) {
        return false;
    }

    pin_attempt_release_if_elapsed(xTaskGetTickCount());
    g_local_reset.stage = LocalResetStage::pin_entry;
    g_local_reset.wipe_pin_only();
    g_local_reset.input_window = input_window;
    return true;
}

bool local_reset_begin_error_recovery_wipe(TickType_t wipe_ready_at)
{
    if (g_local_reset.stage != LocalResetStage::error_recovery_confirm) {
        return false;
    }
    g_local_reset.wipe_pin_only();
    g_local_reset.clear_lockout();
    g_local_reset.stage = LocalResetStage::wiping;
    g_local_reset.wipe_ready_at = wipe_ready_at;
    return true;
}

bool local_reset_close_settings()
{
    if (g_local_reset.stage != LocalResetStage::settings_menu) {
        return false;
    }
    g_local_reset.wipe();
    return true;
}

LocalResetReturnToSettingsResult local_reset_return_to_settings(
    TimeoutWindow input_window)
{
    if (g_local_reset.stage != LocalResetStage::pin_entry) {
        return LocalResetReturnToSettingsResult::stale;
    }
    local_reset_begin_settings(input_window);
    return g_local_reset.stage == LocalResetStage::settings_menu
               ? LocalResetReturnToSettingsResult::started
               : LocalResetReturnToSettingsResult::failed;
}

bool local_reset_cancel_error_recovery()
{
    if (g_local_reset.stage != LocalResetStage::error_recovery_confirm) {
        return false;
    }
    g_local_reset.wipe();
    return true;
}

bool local_reset_begin_settings_pin_auth_handoff()
{
    if (g_local_reset.stage != LocalResetStage::settings_menu) {
        return false;
    }
    g_local_reset.wipe();
    return true;
}

bool local_reset_begin_error_recovery_confirm_if_idle(
    TimeoutWindow input_window)
{
    if (g_local_reset.stage != LocalResetStage::none) {
        return false;
    }
    local_reset_begin_error_recovery_confirm(input_window);
    return g_local_reset.stage == LocalResetStage::error_recovery_confirm;
}

LocalResetErrorRecoveryActionResult local_reset_handle_error_recovery_confirm(
    TimeoutWindow input_window,
    TickType_t wipe_ready_at,
    bool start_available)
{
    if (g_local_reset.stage == LocalResetStage::none) {
        if (!start_available) {
            return LocalResetErrorRecoveryActionResult::stale;
        }
        local_reset_begin_error_recovery_confirm(input_window);
        return g_local_reset.stage == LocalResetStage::error_recovery_confirm
                   ? LocalResetErrorRecoveryActionResult::confirmation_started
                   : LocalResetErrorRecoveryActionResult::stale;
    }
    if (g_local_reset.stage != LocalResetStage::error_recovery_confirm) {
        return LocalResetErrorRecoveryActionResult::stale;
    }
    if (!local_reset_begin_error_recovery_wipe(wipe_ready_at)) {
        return LocalResetErrorRecoveryActionResult::stale;
    }
    return LocalResetErrorRecoveryActionResult::wipe_started;
}

bool local_reset_abort_pin_verification()
{
    if (g_local_reset.stage != LocalResetStage::pin_verifying) {
        return false;
    }
    g_local_reset.wipe();
    return true;
}

LocalResetUiMaintenanceResult local_reset_handle_ui_maintenance(
    bool panel_active,
    TickType_t now)
{
    if (g_local_reset.stage == LocalResetStage::none) {
        return LocalResetUiMaintenanceResult::unchanged;
    }
    if (g_local_reset.stage == LocalResetStage::pin_verifying) {
        if (local_reset_fail_processing_if_expired(now)) {
            return LocalResetUiMaintenanceResult::auth_unavailable;
        }
        if (!panel_active) {
            return LocalResetUiMaintenanceResult::redraw_pin_verification_panel;
        }
        return LocalResetUiMaintenanceResult::unchanged;
    }
    if (g_local_reset.stage == LocalResetStage::wiping) {
        if (!panel_active) {
            return LocalResetUiMaintenanceResult::redraw_wiping_panel;
        }
        return LocalResetUiMaintenanceResult::unchanged;
    }

    const LocalResetLockoutReleaseResult lockout_release =
        local_reset_release_lockout_if_elapsed(now);
    if (lockout_release == LocalResetLockoutReleaseResult::failed) {
        return LocalResetUiMaintenanceResult::lockout_release_failed;
    }
    if (lockout_release == LocalResetLockoutReleaseResult::released) {
        return LocalResetUiMaintenanceResult::lockout_released;
    }

    const bool expired = local_reset_deadline_expired(now);
    if (panel_active && !expired) {
        return LocalResetUiMaintenanceResult::unchanged;
    }

    const LocalResetStage stage = g_local_reset.stage;
    if (!panel_active) {
        g_local_reset.wipe();
    }
    if (!expired) {
        return LocalResetUiMaintenanceResult::panel_lost;
    }
    if (stage == LocalResetStage::settings_menu) {
        return LocalResetUiMaintenanceResult::settings_timeout;
    }
    if (stage == LocalResetStage::error_recovery_confirm) {
        return LocalResetUiMaintenanceResult::error_recovery_timeout;
    }
    return LocalResetUiMaintenanceResult::reset_timeout;
}

bool local_reset_add_pin_digit(char digit)
{
    const TickType_t now = xTaskGetTickCount();
    if (g_local_reset.stage != LocalResetStage::pin_entry ||
        timeout_window_reached(g_local_reset.input_window, now) ||
        local_reset_pin_locked_at(now) ||
        digit < '0' || digit > '9') {
        return false;
    }
    if (g_local_reset.pin_entry_length >= kLocalPinDigits) {
        return false;
    }

    g_local_reset.pin_entry[g_local_reset.pin_entry_length++] = digit;
    g_local_reset.pin_entry[g_local_reset.pin_entry_length] = '\0';
    return true;
}

bool local_reset_clear_pin()
{
    const TickType_t now = xTaskGetTickCount();
    if (g_local_reset.stage != LocalResetStage::pin_entry ||
        timeout_window_reached(g_local_reset.input_window, now) ||
        local_reset_pin_locked_at(now)) {
        return false;
    }

    wipe_sensitive_buffer(g_local_reset.pin_entry, sizeof(g_local_reset.pin_entry));
    g_local_reset.pin_entry_length = 0;
    return true;
}

bool local_reset_backspace_pin()
{
    const TickType_t now = xTaskGetTickCount();
    if (g_local_reset.stage != LocalResetStage::pin_entry ||
        timeout_window_reached(g_local_reset.input_window, now) ||
        local_reset_pin_locked_at(now)) {
        return false;
    }
    if (g_local_reset.pin_entry_length > 0) {
        g_local_reset.pin_entry[--g_local_reset.pin_entry_length] = '\0';
    }
    return true;
}

LocalResetPinSubmitResult local_reset_submit_pin_for_verification(
    TickType_t verify_ready_at,
    TickType_t worker_deadline)
{
    const TickType_t now = xTaskGetTickCount();
    if (g_local_reset.stage != LocalResetStage::pin_entry) {
        return LocalResetPinSubmitResult::unavailable_stage;
    }
    if (timeout_window_reached(g_local_reset.input_window, now)) {
        return LocalResetPinSubmitResult::unavailable_stage;
    }
    if (local_reset_pin_locked_at(now)) {
        return LocalResetPinSubmitResult::locked;
    }
    if (g_local_reset.pin_entry_length != kLocalPinDigits ||
        !is_valid_local_pin(g_local_reset.pin_entry)) {
        return LocalResetPinSubmitResult::invalid_pin;
    }

    uint32_t job_id = 0;
    if (!g_local_reset.pause_input_window(now)) {
        return LocalResetPinSubmitResult::unavailable_stage;
    }
    if (!local_auth_worker_submit_verify(
            LocalAuthWorkerOwner::local_reset,
            g_local_reset.pin_entry,
            &job_id)) {
        g_local_reset.resume_paused_input_window(now);
        return LocalResetPinSubmitResult::worker_unavailable;
    }

    wipe_sensitive_buffer(g_local_reset.pin_entry, sizeof(g_local_reset.pin_entry));
    g_local_reset.pin_entry_length = 0;
    g_local_reset.stage = LocalResetStage::pin_verifying;
    g_local_reset.auth_job_id = job_id;
    g_local_reset.input_window = kTimeoutWindowNone;
    g_local_reset.verify_ready_at = verify_ready_at;
    g_local_reset.wipe_ready_at = 0;
    g_local_reset.worker_deadline = worker_deadline;
    return LocalResetPinSubmitResult::started_verification;
}

LocalResetPinVerifyResult local_reset_complete_pin_verify_job(
    const LocalAuthWorkerResult& result,
    TickType_t lockout_until,
    TickType_t wipe_ready_at)
{
    if (g_local_reset.stage != LocalResetStage::pin_verifying ||
        g_local_reset.auth_job_id == 0 ||
        result.job_id != g_local_reset.auth_job_id ||
        result.owner != LocalAuthWorkerOwner::local_reset ||
        result.operation != LocalAuthWorkerOperation::verify_pin) {
        return LocalResetPinVerifyResult::not_ready;
    }
    if (local_reset_processing_deadline_expired(xTaskGetTickCount())) {
        g_local_reset.wipe();
        return LocalResetPinVerifyResult::auth_unavailable;
    }

    g_local_reset.auth_job_id = 0;
    g_local_reset.verify_ready_at = 0;
    g_local_reset.worker_deadline = 0;
    if (result.status != LocalAuthWorkerStatus::ok) {
        g_local_reset.wipe();
        return LocalResetPinVerifyResult::auth_unavailable;
    }

    if (!result.verified) {
        const TickType_t now = xTaskGetTickCount();
        g_local_reset.stage = LocalResetStage::pin_entry;
        wipe_sensitive_buffer(g_local_reset.pin_entry, sizeof(g_local_reset.pin_entry));
        g_local_reset.pin_entry_length = 0;
        if (pin_attempt_record_failure(lockout_until)) {
            return LocalResetPinVerifyResult::locked;
        }
        if (!g_local_reset.resume_paused_input_window(now)) {
            g_local_reset.wipe();
            return LocalResetPinVerifyResult::auth_unavailable;
        }
        return LocalResetPinVerifyResult::wrong_pin;
    }

    wipe_sensitive_buffer(g_local_reset.pin_entry, sizeof(g_local_reset.pin_entry));
    g_local_reset.pin_entry_length = 0;
    g_local_reset.stage = LocalResetStage::wiping;
    g_local_reset.input_window = kTimeoutWindowNone;
    g_local_reset.clear_lockout();
    g_local_reset.wipe_ready_at = wipe_ready_at;
    return LocalResetPinVerifyResult::verified;
}

static bool local_reset_pending_marker_present()
{
    nvs_handle_t nvs = 0;
    esp_err_t result = nvs_open(kNvsNamespace, NVS_READONLY, &nvs);
    if (result != ESP_OK) {
        if (result != ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGW(kTag, "NVS open failed while checking local reset marker: %s", esp_err_to_name(result));
        }
        return false;
    }

    uint8_t marker = 0;
    result = nvs_get_u8(nvs, kLocalResetPendingKey, &marker);
    nvs_close(nvs);
    if (result == ESP_ERR_NVS_NOT_FOUND) {
        return false;
    }
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Local reset marker read failed: %s", esp_err_to_name(result));
        return false;
    }
    return marker == 1;
}

LocalResetCommitResult local_reset_commit_material(
    const LocalResetPersistenceOps& ops)
{
    if (g_local_reset.stage != LocalResetStage::wiping) {
        return LocalResetCommitResult::missing_state;
    }
    if (!set_local_reset_pending_marker()) {
        ESP_LOGW(kTag, "Local reset could not create reset marker; material was not wiped");
        return LocalResetCommitResult::reset_marker_storage_error;
    }
    return wipe_persistent_material_for_local_reset(ops);
}

LocalResetCommitFinishResult local_reset_finish_commit_if_ready(
    TickType_t now,
    const LocalResetPersistenceOps& ops)
{
    if (!local_reset_wipe_ready(now)) {
        return LocalResetCommitFinishResult{
            LocalResetCommitFinishStatus::not_ready,
            LocalResetCommitResult::missing_state,
        };
    }

    const LocalResetCommitResult result = local_reset_commit_material(ops);
    g_local_reset.wipe();
    return LocalResetCommitFinishResult{
        LocalResetCommitFinishStatus::committed,
        result,
    };
}

LocalResetCommitResult local_reset_resume_pending_if_needed(
    const LocalResetPersistenceOps& ops,
    bool* marker_present)
{
    const bool present = local_reset_pending_marker_present();
    if (marker_present != nullptr) {
        *marker_present = present;
    }
    if (!present) {
        return LocalResetCommitResult::missing_state;
    }
    return wipe_persistent_material_for_local_reset(ops);
}

}  // namespace signing
