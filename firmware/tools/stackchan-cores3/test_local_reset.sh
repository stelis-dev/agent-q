#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_local_reset.sh

Compiles the StackChan CoreS3 local reset state machine against host stubs and
verifies normal reset and error-state erase transitions, reset-pending marker
behavior, destructive wipe orchestration, and the shared stored-PIN attempt
budget used by reset and connect/settings PIN authorization. This test uses
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

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-local-reset.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/firmware_common" "${TMP_DIR}/stubs/freertos"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/firmware_common/policy"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/firmware_common/sui"

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

cat >"${TMP_DIR}/local_reset_test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "human_approval_settings.h"
#include "local_auth_test.h"
#include "local_pin_auth.h"
#include "local_reset.h"
#include "policy_store.h"
#include "esp_err.h"
#include "nvs.h"

namespace {

TickType_t g_now = 0;
bool g_marker_present = false;
bool g_open_fails = false;
bool g_marker_write_fails = false;
bool g_root_present = true;
bool g_policy_present = true;
bool g_auth_present = true;
bool g_human_approval_setting_present = true;
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
    g_open_fails = false;
    g_marker_write_fails = false;
    g_root_present = true;
    g_policy_present = true;
    g_auth_present = true;
    g_human_approval_setting_present = true;
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
    g_consistency_error_count = 0;
    signing::local_reset_wipe();
}

void clear_session()
{
    ++g_clear_session_count;
}

bool persist_unprovisioned()
{
    ++g_persist_unprovisioned_count;
    return true;
}

void record_material_failure(signing::PersistentMaterialRuntimeFailure)
{
    ++g_consistency_error_count;
}

signing::LocalResetPersistenceOps ops()
{
    return signing::LocalResetPersistenceOps{
        clear_session,
        persist_unprovisioned,
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
    *out_value = 1;
    return ESP_OK;
}

esp_err_t nvs_set_u8(nvs_handle_t, const char*, unsigned char)
{
    if (g_marker_write_fails) {
        return 1;
    }
    g_marker_present = true;
    return ESP_OK;
}

esp_err_t nvs_erase_key(nvs_handle_t, const char*)
{
    if (!g_marker_present) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    g_marker_present = false;
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

bool wipe_local_auth()
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

bool approval_history_wipe()
{
    if (g_approval_history_wipe_fails) {
        return false;
    }
    g_approval_history_present = false;
    return true;
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
    g_human_approval_input_mode = mode;
    return true;
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
    using Stage = signing::LocalResetStage;
    using Commit = signing::LocalResetCommitResult;
    using ErrorRecoveryAction = signing::LocalResetErrorRecoveryActionResult;
    using MaintenanceResult = signing::LocalResetUiMaintenanceResult;
    using CommitFinishStatus = signing::LocalResetCommitFinishStatus;

    reset_stubs();
    signing::local_reset_begin_error_recovery_confirm(pin_window(1, 100));
    expect(signing::local_reset_snapshot(0).stage == Stage::error_recovery_confirm,
           "error recovery enters confirmation stage");
    expect(!signing::local_reset_wipe_ready(99), "error recovery not ready before erase");
    expect(signing::local_reset_begin_error_recovery_wipe(200), "error recovery begins wipe");
    expect(signing::local_reset_snapshot(0).stage == Stage::wiping, "error recovery uses wiping stage");
    expect(!signing::local_reset_wipe_ready(199), "wipe waits for display delay");
    expect(signing::local_reset_wipe_ready(200), "wipe ready after delay");
    expect(signing::local_reset_commit_material(ops()) == Commit::ok, "error recovery commit succeeds");
    expect(!g_root_present && !g_policy_present && !g_auth_present &&
               !g_human_approval_setting_present && !g_approval_history_present &&
               !g_policy_update_marker_present && !g_zklogin_proof_present &&
               !g_sui_account_settings_present,
           "error recovery wipes all persistent material, approval history, policy update marker, zkLogin proof, and Sui account settings");
    expect(!g_marker_present, "error recovery clears reset marker");
    expect(g_clear_session_count == 1, "error recovery clears active session");
    expect(g_persist_unprovisioned_count == 1, "error recovery persists unprovisioned");

    reset_stubs();
    g_marker_write_fails = true;
    signing::local_reset_begin_error_recovery_confirm(pin_window(1, 100));
    expect(signing::local_reset_begin_error_recovery_wipe(100), "marker failure path enters wiping");
    expect(signing::local_reset_commit_material(ops()) == Commit::reset_marker_storage_error,
           "marker failure aborts before wiping");
    expect(g_root_present && g_policy_present && g_auth_present &&
               g_human_approval_setting_present && g_approval_history_present &&
               g_policy_update_marker_present && g_zklogin_proof_present &&
               g_sui_account_settings_present,
           "marker failure leaves material untouched");

    reset_stubs();
    g_root_wipe_fails = true;
    signing::local_reset_begin_error_recovery_confirm(pin_window(1, 100));
    expect(signing::local_reset_begin_error_recovery_wipe(100), "root failure path enters wiping");
    expect(signing::local_reset_commit_material(ops()) == Commit::root_wipe_error,
           "root wipe failure reports error");
    expect(g_consistency_error_count == 1, "root wipe failure enters consistency error");

    reset_stubs();
    g_policy_update_marker_wipe_fails = true;
    signing::local_reset_begin_error_recovery_confirm(pin_window(1, 100));
    expect(signing::local_reset_begin_error_recovery_wipe(100), "policy update marker failure path enters wiping");
    expect(signing::local_reset_commit_material(ops()) == Commit::policy_update_marker_wipe_error,
           "policy update marker wipe failure reports error");
    expect(g_consistency_error_count == 1, "policy update marker wipe failure enters consistency error");
    expect(g_policy_update_marker_present, "failed policy update marker wipe leaves marker present");

    reset_stubs();
    g_zklogin_proof_wipe_fails = true;
    signing::local_reset_begin_error_recovery_confirm(pin_window(1, 100));
    expect(signing::local_reset_begin_error_recovery_wipe(100), "zkLogin proof failure path enters wiping");
    expect(signing::local_reset_commit_material(ops()) == Commit::zklogin_proof_wipe_error,
           "zkLogin proof wipe failure reports error");
    expect(g_consistency_error_count == 1, "zkLogin proof wipe failure enters consistency error");
    expect(g_zklogin_proof_present, "failed zkLogin proof wipe leaves proof present");

    reset_stubs();
    g_sui_account_settings_wipe_fails = true;
    signing::local_reset_begin_error_recovery_confirm(pin_window(1, 100));
    expect(signing::local_reset_begin_error_recovery_wipe(100), "Sui account settings failure path enters wiping");
    expect(signing::local_reset_commit_material(ops()) == Commit::sui_account_settings_wipe_error,
           "Sui account settings wipe failure reports error");
    expect(g_consistency_error_count == 1, "Sui account settings wipe failure enters consistency error");
    expect(g_sui_account_settings_present, "failed Sui account settings wipe leaves settings present");

    reset_stubs();
    g_marker_present = true;
    bool marker_seen = false;
    expect(signing::local_reset_resume_pending_if_needed(ops(), &marker_seen) == Commit::ok,
           "pending marker resumes wipe");
    expect(marker_seen, "pending marker reported");
    expect(!g_root_present && !g_policy_present && !g_auth_present &&
               !g_human_approval_setting_present && !g_approval_history_present &&
               !g_policy_update_marker_present && !g_zklogin_proof_present &&
               !g_sui_account_settings_present,
           "pending marker resume wipes all material, approval history, policy update marker, zkLogin proof, and Sui account settings");

    reset_stubs();
    expect(!signing::local_reset_begin_error_recovery_wipe(100),
           "error recovery wipe cannot start without confirmation state");

    reset_stubs();
    signing::local_reset_begin_settings(pin_window(10, 100));
    expect(!signing::local_reset_begin_error_recovery_confirm_if_idle(pin_window(10, 100)),
           "error recovery confirmation cannot start over active settings");
    expect(signing::local_reset_snapshot(10).stage == Stage::settings_menu,
           "failed error recovery confirmation start preserves active settings state");

    reset_stubs();
    expect(signing::local_reset_begin_error_recovery_confirm_if_idle(pin_window(10, 100)),
           "error recovery confirmation starts only from idle state");
    expect(signing::local_reset_snapshot(10).stage == Stage::error_recovery_confirm,
           "error recovery confirmation owner records confirmation state");

    reset_stubs();
    expect(!signing::local_reset_begin_error_recovery_confirm_if_idle(
               signing::kTimeoutWindowNone),
           "error recovery confirmation rejects invalid window");
    expect(signing::local_reset_snapshot(10).stage == Stage::none,
           "invalid error recovery confirmation leaves no active state");

    reset_stubs();
    expect(signing::local_reset_handle_error_recovery_confirm(pin_window(10, 100), 200, true) ==
               ErrorRecoveryAction::confirmation_started,
           "error recovery confirm action starts confirmation when no flow is active");
    expect(signing::local_reset_snapshot(10).stage == Stage::error_recovery_confirm,
           "error recovery confirm action enters confirmation state");
    expect(signing::local_reset_handle_error_recovery_confirm(pin_window(10, 100), 200, false) ==
               ErrorRecoveryAction::wipe_started,
           "error recovery confirm action starts wiping from confirmation state");
    expect(signing::local_reset_snapshot(10).stage == Stage::wiping,
           "error recovery confirm action owns wiping transition");

    reset_stubs();
    expect(signing::local_reset_handle_error_recovery_confirm(
               signing::kTimeoutWindowNone,
               200,
               true) == ErrorRecoveryAction::stale,
           "error recovery confirm action rejects invalid confirmation window");
    expect(signing::local_reset_snapshot(10).stage == Stage::none,
           "invalid error recovery confirm action leaves no active state");

    reset_stubs();
    expect(signing::local_reset_handle_error_recovery_confirm(
               pin_window(10, 100),
               200,
               false) == ErrorRecoveryAction::stale,
           "error recovery confirm action rejects unavailable idle start");
    expect(signing::local_reset_snapshot(10).stage == Stage::none,
           "unavailable idle error recovery confirm leaves no active state");

    reset_stubs();
    signing::local_reset_begin_settings(pin_window(10, 100));
    expect(signing::local_reset_handle_ui_maintenance(false, 50) ==
               MaintenanceResult::panel_lost,
           "settings panel loss is classified by reset owner");
    expect(signing::local_reset_snapshot(50).stage == Stage::none,
           "settings panel loss clears local reset state");

    reset_stubs();
    signing::local_reset_begin_error_recovery_confirm(pin_window(10, 100));
    expect(signing::local_reset_begin_error_recovery_wipe(200), "commit-finish setup enters wiping");
    expect(signing::local_reset_finish_commit_if_ready(199, ops()).status ==
               CommitFinishStatus::not_ready,
           "commit finish waits until wipe display delay expires");
    expect(signing::local_reset_snapshot(199).stage == Stage::wiping,
           "not-ready commit finish preserves wiping state");
    signing::LocalResetCommitFinishResult finish =
        signing::local_reset_finish_commit_if_ready(200, ops());
    expect(finish.status == CommitFinishStatus::committed &&
               finish.commit_result == Commit::ok,
           "commit finish persists reset once ready");
    expect(signing::local_reset_snapshot(200).stage == Stage::none,
           "commit finish clears local reset state after persistence attempt");

    reset_stubs();
    signing::local_reset_begin_settings(pin_window(100, 200));
    expect(signing::local_reset_begin_pin_entry(pin_window(100, 200)),
           "reset PIN entry starts before abort verification test");
    const char abort_pin[] = "123456";
    for (size_t index = 0; abort_pin[index] != '\0'; ++index) {
        expect(signing::local_reset_add_pin_digit(abort_pin[index]),
               "abort verification PIN digit accepted");
    }
    g_now = 110;
    expect(signing::local_reset_submit_pin_for_verification(110, 200) ==
               signing::LocalResetPinSubmitResult::started_verification,
           "abort verification test starts worker job");
    expect(signing::local_reset_abort_pin_verification(),
           "material-unavailable abort is owned by reset domain");
    expect(signing::local_reset_snapshot(110).stage == Stage::none,
           "material-unavailable abort clears reset state");
    expect(g_last_cancelled_worker_job_id == g_last_worker_job_id,
           "material-unavailable abort cancels reset verification job");

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
    signing::local_reset_begin_settings(pin_window(20, 120));
    expect(signing::local_reset_begin_pin_entry(pin_window(20, 120)), "reset PIN entry starts after connect failures");
    expect(signing::local_reset_snapshot(20).lockout_active,
           "reset PIN sees shared lockout from connect PIN failures");
    expect(signing::local_reset_submit_pin_for_verification(20, 90) ==
               signing::LocalResetPinSubmitResult::locked,
           "reset PIN submit is locked by shared attempt budget");
    expect(signing::local_reset_release_lockout_if_elapsed(80) ==
               signing::LocalResetLockoutReleaseResult::released,
           "reset PIN releases elapsed shared lockout");
    expect(!signing::local_reset_snapshot(80).lockout_active,
           "reset PIN lockout release clears shared budget");
    signing::local_reset_wipe();

    reset_stubs();
    g_now = 90;
    signing::local_reset_begin_settings(pin_window(90, 140));
    expect(signing::local_reset_begin_pin_entry(pin_window(90, 140)), "reset PIN entry starts before input deadline test");
    expect(signing::local_reset_add_pin_digit('1'), "reset digit accepted before deadline");
    expect(signing::local_reset_backspace_pin(), "reset backspace accepted before deadline");
    expect(signing::local_reset_clear_pin(), "reset clear accepted before deadline");
    expect(signing::local_reset_deadline_expired(140),
           "reset digit, backspace, and clear do not extend input deadline");
    g_now = 141;
    expect(!signing::local_reset_add_pin_digit('1'),
           "reset digit after deadline is rejected by owner");
    expect(signing::local_reset_submit_pin_for_verification(141, 200) ==
               signing::LocalResetPinSubmitResult::unavailable_stage,
           "reset submit after deadline does not start verification");
    signing::local_reset_wipe();

    reset_stubs();
    signing::local_reset_begin_settings(pin_window(100, 200));
    expect(signing::local_reset_begin_pin_entry(pin_window(100, 200)), "reset PIN entry starts before verification");
    const char reset_verify_pin[] = "123456";
    for (size_t index = 0; reset_verify_pin[index] != '\0'; ++index) {
        const char digit = reset_verify_pin[index];
        expect(signing::local_reset_add_pin_digit(digit), "reset verification PIN digit accepted");
    }
    g_now = 110;
    expect(signing::local_reset_submit_pin_for_verification(110, 150) ==
               signing::LocalResetPinSubmitResult::started_verification,
           "reset PIN verification starts");
    expect(signing::local_reset_snapshot(130).stage == signing::LocalResetStage::pin_verifying,
           "reset PIN verification stays active during cryptographic processing");
    g_now = 149;
    signing::LocalAuthWorkerResult reset_worker_result = {};
    reset_worker_result.job_id = g_last_worker_job_id;
    reset_worker_result.owner = signing::LocalAuthWorkerOwner::local_reset;
    reset_worker_result.operation = signing::LocalAuthWorkerOperation::verify_pin;
    reset_worker_result.status = signing::LocalAuthWorkerStatus::ok;
    reset_worker_result.verified = false;
    expect(signing::local_reset_complete_pin_verify_job(reset_worker_result, 180, 0) ==
               signing::LocalResetPinVerifyResult::wrong_pin,
           "reset wrong PIN result before worker deadline opens retry state");
    expect(signing::local_reset_snapshot(161).stage == signing::LocalResetStage::pin_entry,
           "reset wrong PIN returns to PIN entry");
    expect(signing::local_reset_snapshot(149).input_window.started_at == 139 &&
               signing::local_reset_snapshot(149).input_window.deadline == 239,
           "reset wrong PIN resumes remaining time without resetting timer fill");

    reset_stubs();
    signing::local_reset_begin_settings(pin_window(200, 300));
    expect(signing::local_reset_begin_pin_entry(pin_window(200, 300)), "reset PIN entry starts before worker timeout test");
    for (size_t index = 0; reset_verify_pin[index] != '\0'; ++index) {
        const char digit = reset_verify_pin[index];
        expect(signing::local_reset_add_pin_digit(digit), "reset timeout PIN digit accepted");
    }
    g_now = 210;
    expect(signing::local_reset_submit_pin_for_verification(210, 250) ==
               signing::LocalResetPinSubmitResult::started_verification,
           "reset PIN worker-timeout test starts verification");
    expect(!signing::local_reset_fail_processing_if_expired(249),
           "reset PIN verification stays active before worker deadline");
    expect(signing::local_reset_fail_processing_if_expired(250),
           "reset PIN verification worker timeout clears flow");
    expect(g_last_cancelled_worker_job_id == g_last_worker_job_id,
           "reset PIN verification worker timeout cancels worker job");
    expect(signing::local_reset_snapshot(250).stage == signing::LocalResetStage::none,
           "reset PIN verification worker timeout leaves no active reset flow");

    reset_stubs();
    signing::local_reset_begin_settings(pin_window(300, 400));
    expect(signing::local_reset_begin_pin_entry(pin_window(300, 400)), "reset PIN entry starts before late-result test");
    for (size_t index = 0; reset_verify_pin[index] != '\0'; ++index) {
        const char digit = reset_verify_pin[index];
        expect(signing::local_reset_add_pin_digit(digit), "reset late-result PIN digit accepted");
    }
    g_now = 310;
    expect(signing::local_reset_submit_pin_for_verification(310, 350) ==
               signing::LocalResetPinSubmitResult::started_verification,
           "reset PIN late-result test starts verification");
    g_now = 351;
    reset_worker_result = {};
    reset_worker_result.job_id = g_last_worker_job_id;
    reset_worker_result.owner = signing::LocalAuthWorkerOwner::local_reset;
    reset_worker_result.operation = signing::LocalAuthWorkerOperation::verify_pin;
    reset_worker_result.status = signing::LocalAuthWorkerStatus::ok;
    reset_worker_result.verified = true;
    expect(signing::local_reset_complete_pin_verify_job(reset_worker_result, 430, 0) ==
               signing::LocalResetPinVerifyResult::auth_unavailable,
           "late reset PIN verification result fails closed");
    expect(signing::local_reset_snapshot(351).stage == signing::LocalResetStage::none,
           "late reset PIN verification result clears flow");

    if (failures != 0) {
        fprintf(stderr, "%d local reset test(s) failed\n", failures);
        return 1;
    }
    printf("Local reset tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 \
  -I"${TMP_DIR}/stubs" \
  -I"${TMP_DIR}" \
  -I"${RUNTIME_DIR}" -I"${TMP_DIR}/firmware_common" \
  "${RUNTIME_DIR}/pin_attempt.cpp" \
  "${RUNTIME_DIR}/persistent_material.cpp" \
  "${RUNTIME_DIR}/signing_mode.cpp" \
  "${RUNTIME_DIR}/local_pin_auth.cpp" \
  "${RUNTIME_DIR}/local_reset.cpp" \
  "${TMP_DIR}/local_reset_test.cpp" \
  -o "${TMP_DIR}/local_reset_test"

"${TMP_DIR}/local_reset_test"
