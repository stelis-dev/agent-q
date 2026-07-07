#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_storage_maintenance.sh

Compiles the StackChan CoreS3 storage maintenance state machine against host stubs and
verifies internal settings repair, Device reset, storage-action pending
marker behavior, destructive Device reset orchestration, and the shared
stored-PIN attempt budget used by storage maintenance and connect/settings PIN authorization. This test uses
only a host C++ compiler and does NOT require ESP-IDF.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
CXX_BIN="${CXX:-c++}"
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${FIRMWARE_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

if [[ ! -f "${ARDUINOJSON_ROOT}/ArduinoJson.h" ]]; then
  echo "Missing required ArduinoJson source: ${ARDUINOJSON_ROOT}/ArduinoJson.h" >&2
  echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
  exit 1
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-storage-maintenance.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/firmware_common" "${TMP_DIR}/stubs/freertos"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/firmware_common/policy"
ln -s "${COMMON_ROOT}/protocol" "${TMP_DIR}/firmware_common/protocol"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/firmware_common/sui"
ln -s "${COMMON_ROOT}/transport" "${TMP_DIR}/firmware_common/transport"

cat >"${TMP_DIR}/stubs/freertos/FreeRTOS.h" <<'H'
#pragma once

#include <stdint.h>

typedef uint32_t TickType_t;

#define pdMS_TO_TICKS(ms) (static_cast<TickType_t>(ms))
H

cat >"${TMP_DIR}/stubs/freertos/task.h" <<'H'
#pragma once

#include "freertos/FreeRTOS.h"

extern "C" TickType_t xTaskGetTickCount();
H

cat >"${TMP_DIR}/stubs/esp_err.h" <<'H'
#pragma once

typedef int esp_err_t;

#define ESP_OK 0
#define ESP_ERR_NVS_NOT_FOUND 4354

static inline const char* esp_err_to_name(esp_err_t error)
{
    return error == ESP_OK ? "ESP_OK" :
           error == ESP_ERR_NVS_NOT_FOUND ? "ESP_ERR_NVS_NOT_FOUND" :
           "ESP_ERR_TEST";
}
H

cat >"${TMP_DIR}/stubs/esp_log.h" <<'H'
#pragma once

#define ESP_LOGI(tag, format, ...) do { (void)(tag); } while (0)
#define ESP_LOGW(tag, format, ...) do { (void)(tag); } while (0)
#define ESP_LOGE(tag, format, ...) do { (void)(tag); } while (0)
H

cat >"${TMP_DIR}/stubs/nvs.h" <<'H'
#pragma once

#include "esp_err.h"

#define NVS_READONLY 1
#define NVS_READWRITE 2

typedef int nvs_handle_t;

extern "C" {
esp_err_t nvs_open(const char* name, int open_mode, nvs_handle_t* out_handle);
void nvs_close(nvs_handle_t handle);
esp_err_t nvs_get_u8(nvs_handle_t handle, const char* key, unsigned char* out_value);
esp_err_t nvs_set_u8(nvs_handle_t handle, const char* key, unsigned char value);
esp_err_t nvs_erase_key(nvs_handle_t handle, const char* key);
esp_err_t nvs_commit(nvs_handle_t handle);
}
H

cat >"${TMP_DIR}/storage_maintenance_test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "human_approval_settings.h"
#include "local_auth_test.h"
#include "local_pin_auth.h"
#include "storage_maintenance.h"
#include "policy/policy_store.h"
#include "esp_err.h"
#include "nvs.h"

namespace {

TickType_t g_now = 0;
bool g_marker_present = false;
unsigned char g_marker_value = 0;
bool g_open_fails = false;
bool g_marker_write_fails = false;
bool g_root_present = true;
bool g_policy_present = true;
bool g_auth_present = true;
bool g_human_approval_setting_present = true;
bool g_signing_mode_present = true;
bool g_approval_history_present = true;
bool g_policy_update_marker_present = true;
bool g_zklogin_proof_present = true;
bool g_sui_account_settings_present = true;
bool g_root_wipe_fails = false;
bool g_approval_history_wipe_fails = false;
bool g_policy_update_marker_wipe_fails = false;
bool g_zklogin_proof_wipe_fails = false;
bool g_sui_account_settings_wipe_fails = false;
signing::HumanApprovalInputMode g_human_approval_input_mode =
    signing::HumanApprovalInputMode::pin;
uint32_t g_last_worker_job_id = 0;
uint32_t g_last_cancelled_worker_job_id = 0;
int g_clear_session_count = 0;
int g_persist_unprovisioned_count = 0;
int g_persist_provisioned_count = 0;
int g_consistency_error_count = 0;
int failures = 0;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

signing::TimeoutWindow pin_window(TickType_t started_at, TickType_t deadline)
{
    return signing::timeout_window_from_deadline(started_at, deadline);
}

void reset_stubs()
{
    g_now = 0;
    g_marker_present = false;
    g_marker_value = 0;
    g_open_fails = false;
    g_marker_write_fails = false;
    g_root_present = true;
    g_policy_present = true;
    g_auth_present = true;
    g_human_approval_setting_present = true;
    g_signing_mode_present = true;
    g_approval_history_present = true;
    g_policy_update_marker_present = true;
    g_zklogin_proof_present = true;
    g_sui_account_settings_present = true;
    g_root_wipe_fails = false;
    g_approval_history_wipe_fails = false;
    g_policy_update_marker_wipe_fails = false;
    g_zklogin_proof_wipe_fails = false;
    g_sui_account_settings_wipe_fails = false;
    g_human_approval_input_mode = signing::HumanApprovalInputMode::pin;
    g_last_worker_job_id = 0;
    g_last_cancelled_worker_job_id = 0;
    g_clear_session_count = 0;
    g_persist_unprovisioned_count = 0;
    g_persist_provisioned_count = 0;
    g_consistency_error_count = 0;
    signing::storage_maintenance_clear_flow();
}

void clear_session()
{
    ++g_clear_session_count;
}

bool persist_state(signing::ProvisioningPersistedState state)
{
    if (state == signing::ProvisioningPersistedState::provisioned) {
        ++g_persist_provisioned_count;
    } else {
        ++g_persist_unprovisioned_count;
    }
    return true;
}

void record_material_failure(signing::PersistentMaterialRuntimeFailure)
{
    ++g_consistency_error_count;
}

signing::StorageMaintenancePersistenceOps ops()
{
    return signing::StorageMaintenancePersistenceOps{
        clear_session,
        persist_state,
        record_material_failure,
    };
}

}  // namespace

extern "C" TickType_t xTaskGetTickCount()
{
    return g_now;
}

extern "C" {

esp_err_t nvs_open(const char*, int, nvs_handle_t* out_handle)
{
    if (g_open_fails) {
        return 1;
    }
    *out_handle = 1;
    return ESP_OK;
}

void nvs_close(nvs_handle_t) {}

esp_err_t nvs_get_u8(nvs_handle_t, const char*, unsigned char* out_value)
{
    if (!g_marker_present) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    *out_value = g_marker_value;
    return ESP_OK;
}

esp_err_t nvs_set_u8(nvs_handle_t, const char*, unsigned char value)
{
    if (g_marker_write_fails) {
        return 1;
    }
    g_marker_present = true;
    g_marker_value = value;
    return ESP_OK;
}

esp_err_t nvs_erase_key(nvs_handle_t, const char*)
{
    if (!g_marker_present) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    g_marker_present = false;
    g_marker_value = 0;
    return ESP_OK;
}

esp_err_t nvs_commit(nvs_handle_t)
{
    return ESP_OK;
}

}

namespace signing {

void wipe_sensitive_buffer(void* data, size_t size)
{
    volatile unsigned char* cursor = static_cast<volatile unsigned char*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

bool has_root_material()
{
    return g_root_present;
}

bool wipe_root_material()
{
    if (g_root_wipe_fails) {
        return false;
    }
    g_root_present = false;
    return true;
}

bool store_root_material(const uint8_t*, size_t)
{
    g_root_present = true;
    return true;
}

PolicyStoreStatus active_policy_status()
{
    return g_policy_present ? PolicyStoreStatus::active : PolicyStoreStatus::missing;
}

bool wipe_policy()
{
    g_policy_present = false;
    return true;
}

bool store_default_policy()
{
    g_policy_present = true;
    return true;
}

LocalAuthStatus local_auth_status()
{
    return g_auth_present ? LocalAuthStatus::active : LocalAuthStatus::missing;
}

bool is_valid_local_pin(const char* pin)
{
    if (pin == nullptr || strlen(pin) != kLocalPinDigits) {
        return false;
    }
    for (size_t index = 0; index < kLocalPinDigits; ++index) {
        if (pin[index] < '0' || pin[index] > '9') {
            return false;
        }
    }
    return true;
}

bool clear_local_auth()
{
    g_auth_present = false;
    return true;
}

bool verify_local_pin(const char*, bool* verified)
{
    *verified = false;
    return true;
}

bool prepare_local_pin_verifier_record(const char* pin, LocalAuthPreparedRecord* out)
{
    if (!is_valid_local_pin(pin) || out == nullptr) {
        return false;
    }
    wipe_sensitive_buffer(out->bytes, sizeof(out->bytes));
    memcpy(out->bytes, pin, kLocalPinBufferSize);
    return true;
}

bool store_prepared_local_pin_verifier(const LocalAuthPreparedRecord*)
{
    return true;
}

void wipe_local_pin_verifier_record(LocalAuthPreparedRecord* prepared)
{
    if (prepared != nullptr) {
        wipe_sensitive_buffer(prepared->bytes, sizeof(prepared->bytes));
    }
}

bool wipe_human_approval_input_mode()
{
    g_human_approval_setting_present = false;
    return true;
}

bool store_signing_authorization_mode(AuthorizationMode)
{
    g_signing_mode_present = true;
    return true;
}

bool wipe_signing_authorization_mode()
{
    g_signing_mode_present = false;
    return true;
}

AuthorizationModeStatus authorization_mode_status()
{
    return g_signing_mode_present
               ? AuthorizationModeStatus::active
               : AuthorizationModeStatus::missing;
}

bool approval_history_wipe()
{
    if (g_approval_history_wipe_fails) {
        return false;
    }
    g_approval_history_present = false;
    return true;
}

ApprovalHistoryStorageStatus approval_history_status()
{
    return g_approval_history_present
               ? ApprovalHistoryStorageStatus::active
               : ApprovalHistoryStorageStatus::missing;
}

PolicyUpdateMarkerStatus policy_update_marker_status()
{
    return g_policy_update_marker_present
               ? PolicyUpdateMarkerStatus::pending
               : PolicyUpdateMarkerStatus::clear;
}

bool policy_update_marker_clear()
{
    if (g_policy_update_marker_wipe_fails) {
        return false;
    }
    g_policy_update_marker_present = false;
    return true;
}

SuiZkLoginProofRecordStatus sui_zklogin_proof_record_status()
{
    return g_zklogin_proof_present
               ? SuiZkLoginProofRecordStatus::active
               : SuiZkLoginProofRecordStatus::missing;
}

bool wipe_sui_zklogin_proof_record()
{
    if (g_zklogin_proof_wipe_fails) {
        return false;
    }
    g_zklogin_proof_present = false;
    return true;
}

bool read_sui_account_settings(SuiAccountSettings* settings)
{
    if (settings != nullptr) {
        *settings = kDefaultSuiAccountSettings;
    }
    return g_sui_account_settings_present;
}

bool store_sui_account_settings(const SuiAccountSettings&)
{
    g_sui_account_settings_present = true;
    return true;
}

bool wipe_sui_account_settings()
{
    if (g_sui_account_settings_wipe_fails) {
        return false;
    }
    g_sui_account_settings_present = false;
    return true;
}

SuiAccountSettingsStatus sui_account_settings_status()
{
    return g_sui_account_settings_present
               ? SuiAccountSettingsStatus::active
               : SuiAccountSettingsStatus::missing;
}

bool read_human_approval_input_mode(HumanApprovalInputMode* mode)
{
    if (mode == nullptr) {
        return false;
    }
    *mode = g_human_approval_input_mode;
    return true;
}

bool human_approval_requires_pin()
{
    return g_human_approval_input_mode == HumanApprovalInputMode::pin;
}

bool store_human_approval_input_mode(HumanApprovalInputMode mode)
{
    g_human_approval_setting_present = true;
    g_human_approval_input_mode = mode;
    return true;
}

HumanApprovalInputModeStatus human_approval_input_mode_status()
{
    return g_human_approval_setting_present
               ? HumanApprovalInputModeStatus::active
               : HumanApprovalInputModeStatus::missing;
}

bool store_local_pin_verifier(const char*)
{
    return true;
}

bool local_auth_worker_submit_verify(
    LocalAuthWorkerOwner,
    const char* pin,
    uint32_t* job_id)
{
    static uint32_t next_job_id = 1;
    if (job_id == nullptr || !is_valid_local_pin(pin)) {
        return false;
    }
    *job_id = next_job_id++;
    g_last_worker_job_id = *job_id;
    return true;
}

bool local_auth_worker_submit_prepare_verifier(
    LocalAuthWorkerOwner owner,
    const char* pin,
    uint32_t* job_id)
{
    return local_auth_worker_submit_verify(owner, pin, job_id);
}

bool local_auth_worker_cancel_job(uint32_t)
{
    g_last_cancelled_worker_job_id = g_last_worker_job_id;
    return true;
}

}  // namespace signing

int main()
{
    using Stage = signing::StorageMaintenanceStage;
    using Commit = signing::StorageMaintenanceCommitResult;
    using ErrorRecoveryAction = signing::StorageMaintenanceErrorRecoveryActionResult;
    using MaintenanceResult = signing::StorageMaintenanceUiMaintenanceResult;
    using CommitFinishStatus = signing::StorageMaintenanceCommitFinishStatus;

    reset_stubs();
    signing::storage_maintenance_begin_error_recovery_confirm(
        pin_window(1, 100),
        signing::StorageMaintenanceOperation::wallet_erase);
    expect(signing::storage_maintenance_snapshot(0).stage == Stage::error_recovery_confirm,
           "error recovery enters confirmation stage");
    expect(!signing::storage_maintenance_commit_ready(99), "error recovery not ready before erase");
    expect(signing::storage_maintenance_begin_error_recovery_wallet_erase(200), "error recovery begins wipe");
    expect(signing::storage_maintenance_snapshot(0).stage == Stage::committing, "error recovery uses committing stage");
    expect(!signing::storage_maintenance_commit_ready(199), "wipe waits for display delay");
    expect(signing::storage_maintenance_commit_ready(200), "wipe ready after delay");
    expect(signing::storage_maintenance_commit_material(ops()) == Commit::ok, "error recovery commit succeeds");
    expect(!g_root_present && !g_policy_present && !g_auth_present &&
               !g_human_approval_setting_present && !g_approval_history_present &&
               !g_policy_update_marker_present && !g_zklogin_proof_present &&
               !g_sui_account_settings_present,
           "error recovery wipes all persistent material, approval history, policy update marker, zkLogin proof, and Sui account settings");
    expect(!g_marker_present, "error recovery clears storage action marker");
    expect(g_clear_session_count == 1, "error recovery clears active session");
    expect(g_persist_unprovisioned_count == 1, "error recovery persists unprovisioned");

    reset_stubs();
    g_now = 1;
    signing::storage_maintenance_begin_settings(pin_window(1, 100));
    expect(signing::storage_maintenance_begin_pin_entry(pin_window(1, 100)),
           "settings action PIN entry starts");
    const char settings_pin[] = "123456";
    for (size_t index = 0; settings_pin[index] != '\0'; ++index) {
        expect(signing::storage_maintenance_add_pin_digit(settings_pin[index]),
               "settings action PIN digit accepted");
    }
    expect(signing::storage_maintenance_submit_pin_for_verification(10, 100) ==
               signing::StorageMaintenancePinSubmitResult::started_verification,
           "settings action PIN verification starts");
    signing::LocalAuthWorkerResult settings_worker_result = {};
    settings_worker_result.job_id = g_last_worker_job_id;
    settings_worker_result.owner = signing::LocalAuthWorkerOwner::storage_maintenance;
    settings_worker_result.operation = signing::LocalAuthWorkerOperation::verify_pin;
    settings_worker_result.status = signing::LocalAuthWorkerStatus::ok;
    settings_worker_result.verified = true;
    expect(signing::storage_maintenance_complete_pin_verify_job(settings_worker_result, 90, 200) ==
               signing::StorageMaintenancePinVerifyResult::verified,
           "settings action PIN verification succeeds");
    expect(signing::storage_maintenance_snapshot(10).stage == Stage::committing,
           "settings repair enters commit stage");
    expect(signing::storage_maintenance_snapshot(10).operation == signing::StorageMaintenanceOperation::settings_reset,
           "settings repair operation is tracked separately from Device reset");
    expect(signing::storage_maintenance_commit_material(ops()) == Commit::ok,
           "settings storage action commit succeeds");
    expect(g_root_present && g_auth_present,
           "settings repair preserves root material and local auth verifier");
    expect(g_policy_present && g_human_approval_setting_present &&
               g_signing_mode_present && g_sui_account_settings_present,
           "settings repair stores required mutable defaults");
    expect(!g_approval_history_present && !g_policy_update_marker_present &&
               !g_zklogin_proof_present,
           "settings action clears approval history, policy marker, and zkLogin proof");
    expect(!g_marker_present, "settings action clears pending marker");
    expect(g_clear_session_count == 1, "settings action clears active session");
    expect(g_persist_provisioned_count == 1, "settings repair persists provisioned state");
    expect(g_persist_unprovisioned_count == 0, "settings repair does not persist unprovisioned");

    reset_stubs();
    g_marker_write_fails = true;
    signing::storage_maintenance_begin_error_recovery_confirm(
        pin_window(1, 100),
        signing::StorageMaintenanceOperation::wallet_erase);
    expect(signing::storage_maintenance_begin_error_recovery_wallet_erase(100), "marker failure path enters committing");
    expect(signing::storage_maintenance_commit_material(ops()) == Commit::action_marker_storage_error,
           "marker failure aborts before committing");
    expect(g_root_present && g_policy_present && g_auth_present &&
               g_human_approval_setting_present && g_approval_history_present &&
               g_policy_update_marker_present && g_zklogin_proof_present &&
               g_sui_account_settings_present,
           "marker failure leaves material untouched");

    reset_stubs();
    g_root_wipe_fails = true;
    signing::storage_maintenance_begin_error_recovery_confirm(
        pin_window(1, 100),
        signing::StorageMaintenanceOperation::wallet_erase);
    expect(signing::storage_maintenance_begin_error_recovery_wallet_erase(100), "root failure path enters committing");
    expect(signing::storage_maintenance_commit_material(ops()) == Commit::root_wipe_error,
           "root wipe failure reports error");
    expect(g_consistency_error_count == 1, "root wipe failure enters consistency error");

    reset_stubs();
    g_policy_update_marker_wipe_fails = true;
    signing::storage_maintenance_begin_error_recovery_confirm(
        pin_window(1, 100),
        signing::StorageMaintenanceOperation::wallet_erase);
    expect(signing::storage_maintenance_begin_error_recovery_wallet_erase(100), "policy update marker failure path enters committing");
    expect(signing::storage_maintenance_commit_material(ops()) == Commit::policy_update_marker_wipe_error,
           "policy update marker wipe failure reports error");
    expect(g_consistency_error_count == 1, "policy update marker wipe failure enters consistency error");
    expect(g_policy_update_marker_present, "failed policy update marker wipe leaves marker present");

    reset_stubs();
    g_zklogin_proof_wipe_fails = true;
    signing::storage_maintenance_begin_error_recovery_confirm(
        pin_window(1, 100),
        signing::StorageMaintenanceOperation::wallet_erase);
    expect(signing::storage_maintenance_begin_error_recovery_wallet_erase(100), "zkLogin proof failure path enters committing");
    expect(signing::storage_maintenance_commit_material(ops()) == Commit::zklogin_proof_wipe_error,
           "zkLogin proof wipe failure reports error");
    expect(g_consistency_error_count == 1, "zkLogin proof wipe failure enters consistency error");
    expect(g_zklogin_proof_present, "failed zkLogin proof wipe leaves proof present");

    reset_stubs();
    g_sui_account_settings_wipe_fails = true;
    signing::storage_maintenance_begin_error_recovery_confirm(
        pin_window(1, 100),
        signing::StorageMaintenanceOperation::wallet_erase);
    expect(signing::storage_maintenance_begin_error_recovery_wallet_erase(100), "Sui account settings failure path enters committing");
    expect(signing::storage_maintenance_commit_material(ops()) == Commit::sui_account_settings_wipe_error,
           "Sui account settings wipe failure reports error");
    expect(g_consistency_error_count == 1, "Sui account settings wipe failure enters consistency error");
    expect(g_sui_account_settings_present, "failed Sui account settings wipe leaves settings present");

    reset_stubs();
    g_marker_present = true;
    g_marker_value = 1;
    bool marker_seen = false;
    expect(signing::storage_maintenance_resume_pending_if_needed(ops(), &marker_seen) == Commit::ok,
           "pending marker resumes wipe");
    expect(marker_seen, "pending marker reported");
    expect(!g_root_present && !g_policy_present && !g_auth_present &&
               !g_human_approval_setting_present && !g_approval_history_present &&
               !g_policy_update_marker_present && !g_zklogin_proof_present &&
               !g_sui_account_settings_present,
           "pending marker resume wipes all material, approval history, policy update marker, zkLogin proof, and Sui account settings");

    reset_stubs();
    expect(signing::storage_maintenance_error_recovery_operation() ==
               signing::StorageMaintenanceOperation::settings_reset,
           "repairable persistent error selects settings repair when no pending action exists");
    g_marker_present = true;
    g_marker_value = 1;
    expect(signing::storage_maintenance_error_recovery_operation() ==
               signing::StorageMaintenanceOperation::wallet_erase,
           "pending Device reset marker overrides repairable persistent state");
    g_marker_value = 2;
    expect(signing::storage_maintenance_error_recovery_operation() ==
               signing::StorageMaintenanceOperation::settings_reset,
           "pending settings repair marker selects settings repair");
    g_marker_present = false;
    g_root_present = false;
    expect(signing::storage_maintenance_error_recovery_operation() ==
               signing::StorageMaintenanceOperation::wallet_erase,
           "non-repairable persistent error selects Device reset");

    reset_stubs();
    expect(!signing::storage_maintenance_begin_error_recovery_wallet_erase(100),
           "error recovery wipe cannot start without confirmation state");

    reset_stubs();
    signing::storage_maintenance_begin_settings(pin_window(10, 100));
    expect(signing::storage_maintenance_snapshot(10).operation == signing::StorageMaintenanceOperation::none,
           "settings menu does not preselect a destructive or repair operation");

    reset_stubs();
    expect(signing::storage_maintenance_begin_error_recovery_prompt_if_idle(
               pin_window(10, 100),
               signing::StorageMaintenanceOperation::wallet_erase),
           "error recovery prompt starts only from idle state");
    expect(signing::storage_maintenance_snapshot(10).stage == Stage::error_recovery_prompt,
           "error recovery prompt owner records selected operation before drawing");
    expect(!signing::storage_maintenance_begin_error_recovery_wallet_erase(200),
           "error recovery prompt cannot skip destructive confirmation");
    expect(signing::storage_maintenance_handle_error_recovery_confirm(pin_window(10, 100), 200, true) ==
               ErrorRecoveryAction::confirmation_started,
           "error recovery prompt action opens destructive confirmation");
    expect(signing::storage_maintenance_snapshot(10).stage == Stage::error_recovery_confirm,
           "error recovery prompt advances to confirmation state");
    expect(signing::storage_maintenance_handle_error_recovery_confirm(pin_window(10, 100), 200, true) ==
               ErrorRecoveryAction::commit_started,
           "second error recovery action starts destructive commit");
    expect(signing::storage_maintenance_snapshot(10).stage == Stage::committing,
           "destructive error recovery requires confirmation before committing");

    reset_stubs();
    expect(signing::storage_maintenance_handle_error_recovery_confirm(pin_window(10, 100), 200, true) ==
               ErrorRecoveryAction::stale,
           "idle error recovery action cannot create destructive confirmation");
    expect(signing::storage_maintenance_snapshot(10).stage == Stage::none,
           "idle error recovery action leaves no active state");

    reset_stubs();
    expect(signing::storage_maintenance_handle_error_recovery_confirm(
               signing::kTimeoutWindowNone,
               200,
               true) == ErrorRecoveryAction::stale,
           "error recovery confirm action rejects invalid confirmation window");
    expect(signing::storage_maintenance_snapshot(10).stage == Stage::none,
           "invalid error recovery confirm action leaves no active state");

    reset_stubs();
    expect(signing::storage_maintenance_handle_error_recovery_confirm(
               pin_window(10, 100),
               200,
               false) == ErrorRecoveryAction::stale,
           "error recovery confirm action rejects unavailable idle start");
    expect(signing::storage_maintenance_snapshot(10).stage == Stage::none,
           "unavailable idle error recovery confirm leaves no active state");

    reset_stubs();
    signing::storage_maintenance_begin_settings(pin_window(10, 100));
    expect(signing::storage_maintenance_begin_pin_entry(pin_window(10, 100)),
           "settings-origin storage action enters PIN before cancel");
    expect(signing::storage_maintenance_cancel_pin_entry(pin_window(20, 120)) ==
               signing::StorageMaintenanceCancelPinResult::returned_to_settings,
           "settings-origin storage action PIN cancel returns to settings");
    expect(signing::storage_maintenance_snapshot(20).stage == Stage::settings_menu,
           "settings-origin PIN cancel owns settings return state");

    reset_stubs();
    signing::storage_maintenance_begin_error_recovery_confirm(
        pin_window(10, 100),
        signing::StorageMaintenanceOperation::settings_reset);
    expect(signing::storage_maintenance_begin_error_recovery_settings_repair(pin_window(10, 100)),
           "error-recovery repair enters PIN before cancel");
    expect(signing::storage_maintenance_cancel_pin_entry(pin_window(20, 120)) ==
               signing::StorageMaintenanceCancelPinResult::returned_to_error_recovery,
           "error-recovery repair PIN cancel returns to error recovery");
    expect(signing::storage_maintenance_snapshot(20).stage == Stage::error_recovery_prompt,
           "error-recovery repair PIN cancel returns to repair prompt without opening settings");

    reset_stubs();
    signing::storage_maintenance_begin_settings(pin_window(10, 100));
    expect(signing::storage_maintenance_handle_ui_maintenance(false, 50) ==
               MaintenanceResult::panel_lost,
           "settings panel loss is classified by storage maintenance owner");
    expect(signing::storage_maintenance_snapshot(50).stage == Stage::none,
           "settings panel loss clears storage maintenance state");

    reset_stubs();
    signing::storage_maintenance_begin_error_recovery_confirm(
        pin_window(10, 100),
        signing::StorageMaintenanceOperation::wallet_erase);
    expect(signing::storage_maintenance_begin_error_recovery_wallet_erase(200), "commit-finish setup enters committing");
    expect(signing::storage_maintenance_finish_commit_if_ready(199, ops()).status ==
               CommitFinishStatus::not_ready,
           "commit finish waits until wipe display delay expires");
    expect(signing::storage_maintenance_snapshot(199).stage == Stage::committing,
           "not-ready commit finish preserves committing state");
    signing::StorageMaintenanceCommitFinishResult finish =
        signing::storage_maintenance_finish_commit_if_ready(200, ops());
    expect(finish.status == CommitFinishStatus::committed &&
               finish.commit_result == Commit::ok,
           "commit finish persists storage action once ready");
    expect(signing::storage_maintenance_snapshot(200).stage == Stage::none,
           "commit finish clears storage maintenance state after persistence attempt");

    reset_stubs();
    signing::storage_maintenance_begin_settings(pin_window(100, 200));
    expect(signing::storage_maintenance_begin_pin_entry(pin_window(100, 200)),
           "action PIN entry starts before abort verification test");
    const char abort_pin[] = "123456";
    for (size_t index = 0; abort_pin[index] != '\0'; ++index) {
        expect(signing::storage_maintenance_add_pin_digit(abort_pin[index]),
               "abort verification PIN digit accepted");
    }
    g_now = 110;
    expect(signing::storage_maintenance_submit_pin_for_verification(110, 200) ==
               signing::StorageMaintenancePinSubmitResult::started_verification,
           "abort verification test starts worker job");
    expect(signing::storage_maintenance_abort_pin_verification(),
           "material-unavailable abort is owned by storage maintenance domain");
    expect(signing::storage_maintenance_snapshot(110).stage == Stage::none,
           "material-unavailable abort clears storage maintenance state");
    expect(g_last_cancelled_worker_job_id == g_last_worker_job_id,
           "material-unavailable abort cancels action verification job");

    reset_stubs();
    expect(signing::local_pin_auth_begin_connect(1, pin_window(1, 100)),
           "shared attempt setup starts connect PIN auth");
    for (int attempt = 0; attempt < 5; ++attempt) {
        g_now = 10 + attempt;
        expect(signing::local_pin_auth_add_digit('0') ==
                   signing::LocalPinAuthInputResult::accepted,
               "shared attempt setup digit 1 accepted");
        expect(signing::local_pin_auth_add_digit('0') ==
                   signing::LocalPinAuthInputResult::accepted,
               "shared attempt setup digit 2 accepted");
        expect(signing::local_pin_auth_add_digit('0') ==
                   signing::LocalPinAuthInputResult::accepted,
               "shared attempt setup digit 3 accepted");
        expect(signing::local_pin_auth_add_digit('0') ==
                   signing::LocalPinAuthInputResult::accepted,
               "shared attempt setup digit 4 accepted");
        expect(signing::local_pin_auth_add_digit('0') ==
                   signing::LocalPinAuthInputResult::accepted,
               "shared attempt setup digit 5 accepted");
        expect(signing::local_pin_auth_add_digit('0') ==
                   signing::LocalPinAuthInputResult::accepted,
               "shared attempt setup digit 6 accepted");
        expect(signing::local_pin_auth_submit(g_now, 0, pin_window(g_now, 100), 90) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "shared attempt wrong connect PIN starts verification");
        signing::LocalAuthWorkerResult worker_result = {};
        worker_result.job_id = g_last_worker_job_id;
        worker_result.owner = signing::LocalAuthWorkerOwner::local_pin_auth;
        worker_result.operation = signing::LocalAuthWorkerOperation::verify_pin;
        worker_result.status = signing::LocalAuthWorkerStatus::ok;
        worker_result.verified = false;
        const signing::LocalPinAuthVerifyResult result =
            signing::local_pin_auth_complete_verify_job(
                worker_result,
                pin_window(g_now, 100),
                80,
                0);
        expect(attempt == 4
                   ? result == signing::LocalPinAuthVerifyResult::locked
                   : result == signing::LocalPinAuthVerifyResult::wrong_pin,
               "connect PIN failures drive shared lockout");
    }
    signing::local_pin_auth_clear_flow();
    signing::storage_maintenance_begin_settings(pin_window(20, 120));
    expect(signing::storage_maintenance_begin_pin_entry(pin_window(20, 120)), "action PIN entry starts after connect failures");
    expect(signing::storage_maintenance_snapshot(20).lockout_active,
           "action PIN sees shared lockout from connect PIN failures");
    expect(signing::storage_maintenance_submit_pin_for_verification(20, 90) ==
               signing::StorageMaintenancePinSubmitResult::locked,
           "action PIN submit is locked by shared attempt budget");
    expect(signing::storage_maintenance_release_lockout_if_elapsed(80) ==
               signing::StorageMaintenanceLockoutReleaseResult::released,
           "action PIN releases elapsed shared lockout");
    expect(!signing::storage_maintenance_snapshot(80).lockout_active,
           "action PIN lockout release clears shared budget");
    signing::storage_maintenance_clear_flow();

    reset_stubs();
    g_now = 90;
    signing::storage_maintenance_begin_settings(pin_window(90, 140));
    expect(signing::storage_maintenance_begin_pin_entry(pin_window(90, 140)), "action PIN entry starts before input deadline test");
    expect(signing::storage_maintenance_add_pin_digit('1'), "action digit accepted before deadline");
    expect(signing::storage_maintenance_backspace_pin(), "action backspace accepted before deadline");
    expect(signing::storage_maintenance_clear_pin(), "action clear accepted before deadline");
    expect(signing::storage_maintenance_deadline_expired(140),
           "action digit, backspace, and clear do not extend input deadline");
    g_now = 141;
    expect(!signing::storage_maintenance_add_pin_digit('1'),
           "action digit after deadline is rejected by owner");
    expect(signing::storage_maintenance_submit_pin_for_verification(141, 200) ==
               signing::StorageMaintenancePinSubmitResult::unavailable_stage,
           "action submit after deadline does not start verification");
    signing::storage_maintenance_clear_flow();

    reset_stubs();
    signing::storage_maintenance_begin_settings(pin_window(100, 200));
    expect(signing::storage_maintenance_begin_pin_entry(pin_window(100, 200)), "action PIN entry starts before verification");
    const char action_verify_pin[] = "123456";
    for (size_t index = 0; action_verify_pin[index] != '\0'; ++index) {
        const char digit = action_verify_pin[index];
        expect(signing::storage_maintenance_add_pin_digit(digit), "action verification PIN digit accepted");
    }
    g_now = 110;
    expect(signing::storage_maintenance_submit_pin_for_verification(110, 150) ==
               signing::StorageMaintenancePinSubmitResult::started_verification,
           "action PIN verification starts");
    expect(signing::storage_maintenance_snapshot(130).stage == signing::StorageMaintenanceStage::pin_verifying,
           "action PIN verification stays active during cryptographic processing");
    g_now = 149;
    signing::LocalAuthWorkerResult action_worker_result = {};
    action_worker_result.job_id = g_last_worker_job_id;
    action_worker_result.owner = signing::LocalAuthWorkerOwner::storage_maintenance;
    action_worker_result.operation = signing::LocalAuthWorkerOperation::verify_pin;
    action_worker_result.status = signing::LocalAuthWorkerStatus::ok;
    action_worker_result.verified = false;
    expect(signing::storage_maintenance_complete_pin_verify_job(action_worker_result, 180, 0) ==
               signing::StorageMaintenancePinVerifyResult::wrong_pin,
           "action wrong PIN result before worker deadline opens retry state");
    expect(signing::storage_maintenance_snapshot(161).stage == signing::StorageMaintenanceStage::pin_entry,
           "action wrong PIN returns to PIN entry");
    expect(signing::storage_maintenance_snapshot(149).input_window.started_at == 139 &&
               signing::storage_maintenance_snapshot(149).input_window.deadline == 239,
           "action wrong PIN resumes remaining time without extending timer fill");

    reset_stubs();
    signing::storage_maintenance_begin_settings(pin_window(200, 300));
    expect(signing::storage_maintenance_begin_pin_entry(pin_window(200, 300)), "action PIN entry starts before worker timeout test");
    for (size_t index = 0; action_verify_pin[index] != '\0'; ++index) {
        const char digit = action_verify_pin[index];
        expect(signing::storage_maintenance_add_pin_digit(digit), "action timeout PIN digit accepted");
    }
    g_now = 210;
    expect(signing::storage_maintenance_submit_pin_for_verification(210, 250) ==
               signing::StorageMaintenancePinSubmitResult::started_verification,
           "action PIN worker-timeout test starts verification");
    expect(!signing::storage_maintenance_fail_processing_if_expired(249),
           "action PIN verification stays active before worker deadline");
    expect(signing::storage_maintenance_fail_processing_if_expired(250),
           "action PIN verification worker timeout clears flow");
    expect(g_last_cancelled_worker_job_id == g_last_worker_job_id,
           "action PIN verification worker timeout cancels worker job");
    expect(signing::storage_maintenance_snapshot(250).stage == signing::StorageMaintenanceStage::none,
           "action PIN verification worker timeout leaves no active storage maintenance flow");

    reset_stubs();
    signing::storage_maintenance_begin_settings(pin_window(300, 400));
    expect(signing::storage_maintenance_begin_pin_entry(pin_window(300, 400)), "action PIN entry starts before late-result test");
    for (size_t index = 0; action_verify_pin[index] != '\0'; ++index) {
        const char digit = action_verify_pin[index];
        expect(signing::storage_maintenance_add_pin_digit(digit), "action late-result PIN digit accepted");
    }
    g_now = 310;
    expect(signing::storage_maintenance_submit_pin_for_verification(310, 350) ==
               signing::StorageMaintenancePinSubmitResult::started_verification,
           "action PIN late-result test starts verification");
    g_now = 351;
    action_worker_result = {};
    action_worker_result.job_id = g_last_worker_job_id;
    action_worker_result.owner = signing::LocalAuthWorkerOwner::storage_maintenance;
    action_worker_result.operation = signing::LocalAuthWorkerOperation::verify_pin;
    action_worker_result.status = signing::LocalAuthWorkerStatus::ok;
    action_worker_result.verified = true;
    expect(signing::storage_maintenance_complete_pin_verify_job(action_worker_result, 430, 0) ==
               signing::StorageMaintenancePinVerifyResult::auth_unavailable,
           "late action PIN verification result fails closed");
    expect(signing::storage_maintenance_snapshot(351).stage == signing::StorageMaintenanceStage::none,
           "late action PIN verification result clears flow");

    if (failures != 0) {
        fprintf(stderr, "%d storage maintenance test(s) failed\n", failures);
        return 1;
    }
    printf("Storage maintenance tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 \
  -I"${TMP_DIR}/stubs" \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${RUNTIME_DIR}" -I"${TMP_DIR}/firmware_common" \
  "${RUNTIME_DIR}/pin_attempt.cpp" \
  "${RUNTIME_DIR}/persistent_material.cpp" \
  "${RUNTIME_DIR}/local_pin_auth.cpp" \
  "${RUNTIME_DIR}/storage_maintenance.cpp" \
  "${TMP_DIR}/storage_maintenance_test.cpp" \
  -o "${TMP_DIR}/storage_maintenance_test"

"${TMP_DIR}/storage_maintenance_test"
