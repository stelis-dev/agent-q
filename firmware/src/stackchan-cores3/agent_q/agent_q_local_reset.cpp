#include "agent_q_local_reset.h"

#include "agent_q_local_auth.h"
#include "esp_err.h"
#include "esp_log.h"
#include "freertos/task.h"
#include "nvs.h"

namespace agent_q {
namespace {

constexpr const char* kTag = "AgentQLocalReset";
constexpr const char* kNvsNamespace = "agent_q";
constexpr const char* kLocalResetPendingKey = "reset_pending";

struct LocalResetState {
    char pin_entry[kLocalPinBufferSize] = {};
    size_t pin_entry_length = 0;
    AgentQLocalResetStage stage = AgentQLocalResetStage::none;
    uint32_t auth_job_id = 0;
    TickType_t deadline = 0;
    TickType_t verify_ready_at = 0;
    TickType_t wipe_ready_at = 0;
    TickType_t worker_deadline = 0;

    void wipe()
    {
        wipe_pin_only();
        stage = AgentQLocalResetStage::none;
    }

    void wipe_pin_only()
    {
        if (auth_job_id != 0) {
            local_auth_worker_cancel_job(auth_job_id);
        }
        wipe_sensitive_buffer(pin_entry, sizeof(pin_entry));
        pin_entry_length = 0;
        auth_job_id = 0;
        deadline = 0;
        verify_ready_at = 0;
        wipe_ready_at = 0;
        worker_deadline = 0;
    }

    void clear_lockout()
    {
        pin_attempt_clear();
    }
};

LocalResetState g_local_reset;

bool tick_reached(TickType_t deadline, TickType_t now)
{
    return deadline != 0 && static_cast<int32_t>(now - deadline) >= 0;
}

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
    const AgentQLocalResetPersistenceOps& ops,
    AgentQPersistentMaterialRuntimeFailure failure)
{
    if (ops.record_material_failure != nullptr) {
        ops.record_material_failure(failure);
    }
}

AgentQLocalResetCommitResult wipe_persistent_material_for_local_reset(
    const AgentQLocalResetPersistenceOps& ops)
{
    if (ops.clear_active_session != nullptr) {
        ops.clear_active_session();
    }

    switch (persistent_material_wipe_all()) {
        case AgentQPersistentMaterialWipeResult::ok:
            break;
        case AgentQPersistentMaterialWipeResult::root_wipe_error:
            record_material_failure(ops, AgentQPersistentMaterialRuntimeFailure::local_reset_root_wipe_failed);
            return AgentQLocalResetCommitResult::root_wipe_error;
        case AgentQPersistentMaterialWipeResult::policy_wipe_error:
            record_material_failure(ops, AgentQPersistentMaterialRuntimeFailure::local_reset_policy_wipe_failed);
            return AgentQLocalResetCommitResult::policy_wipe_error;
        case AgentQPersistentMaterialWipeResult::local_auth_wipe_error:
            record_material_failure(ops, AgentQPersistentMaterialRuntimeFailure::local_reset_local_auth_wipe_failed);
            return AgentQLocalResetCommitResult::local_auth_wipe_error;
        case AgentQPersistentMaterialWipeResult::connect_setting_wipe_error:
            record_material_failure(ops, AgentQPersistentMaterialRuntimeFailure::local_reset_connect_setting_wipe_failed);
            return AgentQLocalResetCommitResult::connect_setting_wipe_error;
        case AgentQPersistentMaterialWipeResult::signing_mode_wipe_error:
            record_material_failure(ops, AgentQPersistentMaterialRuntimeFailure::local_reset_signing_mode_wipe_failed);
            return AgentQLocalResetCommitResult::signing_mode_wipe_error;
        case AgentQPersistentMaterialWipeResult::approval_history_wipe_error:
            record_material_failure(ops, AgentQPersistentMaterialRuntimeFailure::local_reset_approval_history_wipe_failed);
            return AgentQLocalResetCommitResult::approval_history_wipe_error;
        case AgentQPersistentMaterialWipeResult::policy_update_marker_wipe_error:
            record_material_failure(ops, AgentQPersistentMaterialRuntimeFailure::local_reset_policy_update_marker_wipe_failed);
            return AgentQLocalResetCommitResult::policy_update_marker_wipe_error;
        case AgentQPersistentMaterialWipeResult::material_remaining_error:
        default:
            record_material_failure(ops, AgentQPersistentMaterialRuntimeFailure::local_reset_material_remaining);
            return AgentQLocalResetCommitResult::material_remaining_error;
    }

    if (ops.persist_unprovisioned_state == nullptr ||
        !ops.persist_unprovisioned_state()) {
        record_material_failure(ops, AgentQPersistentMaterialRuntimeFailure::local_reset_state_storage_failed);
        return AgentQLocalResetCommitResult::state_storage_error;
    }
    if (!clear_local_reset_pending_marker()) {
        record_material_failure(ops, AgentQPersistentMaterialRuntimeFailure::local_reset_marker_clear_failed);
        return AgentQLocalResetCommitResult::state_storage_error;
    }

    return AgentQLocalResetCommitResult::ok;
}

}  // namespace

AgentQLocalResetSnapshot local_reset_snapshot(TickType_t now)
{
    return AgentQLocalResetSnapshot{
        g_local_reset.stage,
        g_local_reset.pin_entry_length,
        local_reset_pin_locked_at(now),
        g_local_reset.stage != AgentQLocalResetStage::none,
    };
}

bool local_reset_persistent_material_exists()
{
    return persistent_material_exists();
}

bool local_reset_deadline_expired(TickType_t now)
{
    return tick_reached(g_local_reset.deadline, now);
}

bool local_reset_processing_deadline_expired(TickType_t now)
{
    return g_local_reset.stage == AgentQLocalResetStage::pin_verifying &&
           tick_reached(g_local_reset.worker_deadline, now);
}

bool local_reset_fail_processing_if_expired(TickType_t now)
{
    if (!local_reset_processing_deadline_expired(now)) {
        return false;
    }
    g_local_reset.wipe();
    return true;
}

bool local_reset_release_lockout_if_elapsed(TickType_t now)
{
    if (g_local_reset.stage != AgentQLocalResetStage::pin_entry ||
        !pin_attempt_release_if_elapsed(now)) {
        return false;
    }

    g_local_reset.deadline = now + pdMS_TO_TICKS(kAgentQLocalResetEntryMs);
    return true;
}

bool local_reset_wipe_ready(TickType_t now)
{
    return g_local_reset.stage == AgentQLocalResetStage::wiping &&
           tick_reached(g_local_reset.wipe_ready_at, now);
}

void local_reset_wipe()
{
    g_local_reset.wipe();
}

void local_reset_begin_settings(TickType_t deadline)
{
    g_local_reset.wipe();
    g_local_reset.stage = AgentQLocalResetStage::settings_menu;
    g_local_reset.deadline = deadline;
}

void local_reset_begin_error_recovery_confirm(TickType_t deadline)
{
    g_local_reset.wipe();
    g_local_reset.stage = AgentQLocalResetStage::error_recovery_confirm;
    g_local_reset.deadline = deadline;
}

bool local_reset_begin_pin_entry(TickType_t deadline)
{
    if (g_local_reset.stage != AgentQLocalResetStage::settings_menu) {
        return false;
    }

    pin_attempt_release_if_elapsed(xTaskGetTickCount());
    g_local_reset.stage = AgentQLocalResetStage::pin_entry;
    g_local_reset.wipe_pin_only();
    g_local_reset.deadline = deadline;
    return true;
}

bool local_reset_begin_error_recovery_wipe(TickType_t wipe_ready_at)
{
    if (g_local_reset.stage != AgentQLocalResetStage::error_recovery_confirm) {
        return false;
    }
    g_local_reset.wipe_pin_only();
    g_local_reset.clear_lockout();
    g_local_reset.stage = AgentQLocalResetStage::wiping;
    g_local_reset.wipe_ready_at = wipe_ready_at;
    return true;
}

bool local_reset_add_pin_digit(char digit)
{
    if (g_local_reset.stage != AgentQLocalResetStage::pin_entry ||
        tick_reached(g_local_reset.deadline, xTaskGetTickCount()) ||
        local_reset_pin_locked_at(xTaskGetTickCount()) ||
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
    if (g_local_reset.stage != AgentQLocalResetStage::pin_entry ||
        tick_reached(g_local_reset.deadline, xTaskGetTickCount()) ||
        local_reset_pin_locked_at(xTaskGetTickCount())) {
        return false;
    }

    wipe_sensitive_buffer(g_local_reset.pin_entry, sizeof(g_local_reset.pin_entry));
    g_local_reset.pin_entry_length = 0;
    return true;
}

bool local_reset_backspace_pin()
{
    if (g_local_reset.stage != AgentQLocalResetStage::pin_entry ||
        tick_reached(g_local_reset.deadline, xTaskGetTickCount()) ||
        local_reset_pin_locked_at(xTaskGetTickCount())) {
        return false;
    }
    if (g_local_reset.pin_entry_length > 0) {
        g_local_reset.pin_entry[--g_local_reset.pin_entry_length] = '\0';
    }
    return true;
}

AgentQLocalResetPinSubmitResult local_reset_submit_pin_for_verification(
    TickType_t verify_ready_at,
    TickType_t invalid_deadline,
    TickType_t worker_deadline)
{
    if (g_local_reset.stage != AgentQLocalResetStage::pin_entry) {
        return AgentQLocalResetPinSubmitResult::unavailable_stage;
    }
    if (tick_reached(g_local_reset.deadline, xTaskGetTickCount())) {
        return AgentQLocalResetPinSubmitResult::unavailable_stage;
    }
    if (local_reset_pin_locked_at(xTaskGetTickCount())) {
        return AgentQLocalResetPinSubmitResult::locked;
    }
    if (g_local_reset.pin_entry_length != kLocalPinDigits ||
        !is_valid_local_pin(g_local_reset.pin_entry)) {
        (void)invalid_deadline;
        return AgentQLocalResetPinSubmitResult::invalid_pin;
    }

    uint32_t job_id = 0;
    if (!local_auth_worker_submit_verify(
            AgentQLocalAuthWorkerOwner::local_reset,
            g_local_reset.pin_entry,
            &job_id)) {
        (void)invalid_deadline;
        return AgentQLocalResetPinSubmitResult::worker_unavailable;
    }

    wipe_sensitive_buffer(g_local_reset.pin_entry, sizeof(g_local_reset.pin_entry));
    g_local_reset.pin_entry_length = 0;
    g_local_reset.stage = AgentQLocalResetStage::pin_verifying;
    g_local_reset.auth_job_id = job_id;
    g_local_reset.deadline = 0;
    g_local_reset.verify_ready_at = verify_ready_at;
    g_local_reset.wipe_ready_at = 0;
    g_local_reset.worker_deadline = worker_deadline;
    return AgentQLocalResetPinSubmitResult::started_verification;
}

AgentQLocalResetPinVerifyResult local_reset_complete_pin_verify_job(
    const AgentQLocalAuthWorkerResult& result,
    TickType_t retry_deadline,
    TickType_t lockout_until,
    TickType_t wipe_ready_at)
{
    if (g_local_reset.stage != AgentQLocalResetStage::pin_verifying ||
        g_local_reset.auth_job_id == 0 ||
        result.job_id != g_local_reset.auth_job_id ||
        result.owner != AgentQLocalAuthWorkerOwner::local_reset ||
        result.operation != AgentQLocalAuthWorkerOperation::verify_pin) {
        return AgentQLocalResetPinVerifyResult::not_ready;
    }
    if (local_reset_processing_deadline_expired(xTaskGetTickCount())) {
        g_local_reset.wipe();
        return AgentQLocalResetPinVerifyResult::auth_unavailable;
    }

    g_local_reset.auth_job_id = 0;
    g_local_reset.verify_ready_at = 0;
    g_local_reset.worker_deadline = 0;
    if (result.status != AgentQLocalAuthWorkerStatus::ok) {
        g_local_reset.wipe_pin_only();
        return AgentQLocalResetPinVerifyResult::auth_unavailable;
    }

    if (!result.verified) {
        g_local_reset.stage = AgentQLocalResetStage::pin_entry;
        wipe_sensitive_buffer(g_local_reset.pin_entry, sizeof(g_local_reset.pin_entry));
        g_local_reset.pin_entry_length = 0;
        g_local_reset.deadline = retry_deadline;
        if (pin_attempt_record_failure(lockout_until)) {
            return AgentQLocalResetPinVerifyResult::locked;
        }
        return AgentQLocalResetPinVerifyResult::wrong_pin;
    }

    wipe_sensitive_buffer(g_local_reset.pin_entry, sizeof(g_local_reset.pin_entry));
    g_local_reset.pin_entry_length = 0;
    g_local_reset.stage = AgentQLocalResetStage::wiping;
    g_local_reset.deadline = 0;
    g_local_reset.clear_lockout();
    g_local_reset.wipe_ready_at = wipe_ready_at;
    return AgentQLocalResetPinVerifyResult::verified;
}

bool local_reset_pending_marker_present()
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

AgentQLocalResetCommitResult local_reset_commit_material(
    const AgentQLocalResetPersistenceOps& ops)
{
    if (g_local_reset.stage != AgentQLocalResetStage::wiping) {
        return AgentQLocalResetCommitResult::missing_state;
    }
    if (!set_local_reset_pending_marker()) {
        ESP_LOGW(kTag, "Local reset could not create reset marker; material was not wiped");
        return AgentQLocalResetCommitResult::reset_marker_storage_error;
    }
    return wipe_persistent_material_for_local_reset(ops);
}

AgentQLocalResetCommitResult local_reset_resume_pending_if_needed(
    const AgentQLocalResetPersistenceOps& ops,
    bool* marker_present)
{
    const bool present = local_reset_pending_marker_present();
    if (marker_present != nullptr) {
        *marker_present = present;
    }
    if (!present) {
        return AgentQLocalResetCommitResult::missing_state;
    }
    return wipe_persistent_material_for_local_reset(ops);
}

}  // namespace agent_q
