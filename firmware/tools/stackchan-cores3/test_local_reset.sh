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
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common/agent_q"
CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-local-reset.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/agent_q_common" "${TMP_DIR}/stubs/freertos"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/agent_q_common/policy"
ln -s "${COMMON_ROOT}/sui" "${TMP_DIR}/agent_q_common/sui"

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

#include "agent_q_connect_settings.h"
#include "agent_q_local_auth.h"
#include "agent_q_local_pin_auth.h"
#include "agent_q_local_reset.h"
#include "agent_q_policy_store.h"
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
bool g_connect_setting_present = true;
bool g_approval_history_present = true;
bool g_policy_update_marker_present = true;
bool g_root_wipe_fails = false;
bool g_approval_history_wipe_fails = false;
bool g_policy_update_marker_wipe_fails = false;
bool g_require_pin_on_connect = true;
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

void reset_stubs()
{
    g_now = 0;
    g_marker_present = false;
    g_open_fails = false;
    g_marker_write_fails = false;
    g_root_present = true;
    g_policy_present = true;
    g_auth_present = true;
    g_connect_setting_present = true;
    g_approval_history_present = true;
    g_policy_update_marker_present = true;
    g_root_wipe_fails = false;
    g_approval_history_wipe_fails = false;
    g_policy_update_marker_wipe_fails = false;
    g_require_pin_on_connect = true;
    g_last_worker_job_id = 0;
    g_last_cancelled_worker_job_id = 0;
    g_clear_session_count = 0;
    g_persist_unprovisioned_count = 0;
    g_consistency_error_count = 0;
    agent_q::local_reset_wipe();
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

void record_material_failure(agent_q::AgentQPersistentMaterialRuntimeFailure)
{
    ++g_consistency_error_count;
}

agent_q::AgentQLocalResetPersistenceOps ops()
{
    return agent_q::AgentQLocalResetPersistenceOps{
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

namespace agent_q {

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

AgentQPolicyStoreStatus active_policy_status()
{
    return g_policy_present ? AgentQPolicyStoreStatus::active : AgentQPolicyStoreStatus::missing;
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

AgentQLocalAuthStatus local_auth_status()
{
    return g_auth_present ? AgentQLocalAuthStatus::active : AgentQLocalAuthStatus::missing;
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

bool prepare_local_pin_verifier_record(const char* pin, AgentQLocalAuthPreparedRecord* out)
{
    if (!is_valid_local_pin(pin) || out == nullptr) {
        return false;
    }
    wipe_sensitive_buffer(out->bytes, sizeof(out->bytes));
    memcpy(out->bytes, pin, kLocalPinBufferSize);
    return true;
}

bool store_prepared_local_pin_verifier(const AgentQLocalAuthPreparedRecord*)
{
    return true;
}

void wipe_local_pin_verifier_record(AgentQLocalAuthPreparedRecord* prepared)
{
    if (prepared != nullptr) {
        wipe_sensitive_buffer(prepared->bytes, sizeof(prepared->bytes));
    }
}

bool wipe_require_pin_on_connect()
{
    g_connect_setting_present = false;
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

AgentQPolicyUpdateMarkerStatus policy_update_marker_status()
{
    return g_policy_update_marker_present
               ? AgentQPolicyUpdateMarkerStatus::pending
               : AgentQPolicyUpdateMarkerStatus::clear;
}

bool policy_update_marker_clear()
{
    if (g_policy_update_marker_wipe_fails) {
        return false;
    }
    g_policy_update_marker_present = false;
    return true;
}

bool read_require_pin_on_connect(bool* required)
{
    if (required == nullptr) {
        return false;
    }
    *required = g_require_pin_on_connect;
    return true;
}

bool connect_requires_pin()
{
    return g_require_pin_on_connect;
}

bool store_require_pin_on_connect(bool required)
{
    g_require_pin_on_connect = required;
    return true;
}

bool store_local_pin_verifier(const char*)
{
    return true;
}

bool local_auth_worker_submit_verify(
    AgentQLocalAuthWorkerOwner,
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
    AgentQLocalAuthWorkerOwner owner,
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

}  // namespace agent_q

int main()
{
    using Stage = agent_q::AgentQLocalResetStage;
    using Commit = agent_q::AgentQLocalResetCommitResult;

    reset_stubs();
    agent_q::local_reset_begin_error_recovery_confirm(100);
    expect(agent_q::local_reset_snapshot(0).stage == Stage::error_recovery_confirm,
           "error recovery enters confirmation stage");
    expect(!agent_q::local_reset_wipe_ready(99), "error recovery not ready before erase");
    expect(agent_q::local_reset_begin_error_recovery_wipe(200), "error recovery begins wipe");
    expect(agent_q::local_reset_snapshot(0).stage == Stage::wiping, "error recovery uses wiping stage");
    expect(!agent_q::local_reset_wipe_ready(199), "wipe waits for display delay");
    expect(agent_q::local_reset_wipe_ready(200), "wipe ready after delay");
    expect(agent_q::local_reset_commit_material(ops()) == Commit::ok, "error recovery commit succeeds");
    expect(!g_root_present && !g_policy_present && !g_auth_present &&
               !g_connect_setting_present && !g_approval_history_present &&
               !g_policy_update_marker_present,
           "error recovery wipes all persistent material, approval history, and policy update marker");
    expect(!g_marker_present, "error recovery clears reset marker");
    expect(g_clear_session_count == 1, "error recovery clears active session");
    expect(g_persist_unprovisioned_count == 1, "error recovery persists unprovisioned");

    reset_stubs();
    g_marker_write_fails = true;
    agent_q::local_reset_begin_error_recovery_confirm(100);
    expect(agent_q::local_reset_begin_error_recovery_wipe(100), "marker failure path enters wiping");
    expect(agent_q::local_reset_commit_material(ops()) == Commit::reset_marker_storage_error,
           "marker failure aborts before wiping");
    expect(g_root_present && g_policy_present && g_auth_present &&
               g_connect_setting_present && g_approval_history_present &&
               g_policy_update_marker_present,
           "marker failure leaves material untouched");

    reset_stubs();
    g_root_wipe_fails = true;
    agent_q::local_reset_begin_error_recovery_confirm(100);
    expect(agent_q::local_reset_begin_error_recovery_wipe(100), "root failure path enters wiping");
    expect(agent_q::local_reset_commit_material(ops()) == Commit::root_wipe_error,
           "root wipe failure reports error");
    expect(g_consistency_error_count == 1, "root wipe failure enters consistency error");

    reset_stubs();
    g_policy_update_marker_wipe_fails = true;
    agent_q::local_reset_begin_error_recovery_confirm(100);
    expect(agent_q::local_reset_begin_error_recovery_wipe(100), "policy update marker failure path enters wiping");
    expect(agent_q::local_reset_commit_material(ops()) == Commit::policy_update_marker_wipe_error,
           "policy update marker wipe failure reports error");
    expect(g_consistency_error_count == 1, "policy update marker wipe failure enters consistency error");
    expect(g_policy_update_marker_present, "failed policy update marker wipe leaves marker present");

    reset_stubs();
    g_marker_present = true;
    bool marker_seen = false;
    expect(agent_q::local_reset_resume_pending_if_needed(ops(), &marker_seen) == Commit::ok,
           "pending marker resumes wipe");
    expect(marker_seen, "pending marker reported");
    expect(!g_root_present && !g_policy_present && !g_auth_present &&
               !g_connect_setting_present && !g_approval_history_present &&
               !g_policy_update_marker_present,
           "pending marker resume wipes all material, approval history, and policy update marker");

    reset_stubs();
    expect(!agent_q::local_reset_begin_error_recovery_wipe(100),
           "error recovery wipe cannot start without confirmation state");

    reset_stubs();
    agent_q::local_pin_auth_begin_connect(100);
    for (int attempt = 0; attempt < 5; ++attempt) {
        g_now = 10 + attempt;
        expect(agent_q::local_pin_auth_add_digit('0', 100) ==
                   agent_q::AgentQLocalPinAuthInputResult::accepted,
               "shared attempt setup digit 1 accepted");
        expect(agent_q::local_pin_auth_add_digit('0', 100) ==
                   agent_q::AgentQLocalPinAuthInputResult::accepted,
               "shared attempt setup digit 2 accepted");
        expect(agent_q::local_pin_auth_add_digit('0', 100) ==
                   agent_q::AgentQLocalPinAuthInputResult::accepted,
               "shared attempt setup digit 3 accepted");
        expect(agent_q::local_pin_auth_add_digit('0', 100) ==
                   agent_q::AgentQLocalPinAuthInputResult::accepted,
               "shared attempt setup digit 4 accepted");
        expect(agent_q::local_pin_auth_add_digit('0', 100) ==
                   agent_q::AgentQLocalPinAuthInputResult::accepted,
               "shared attempt setup digit 5 accepted");
        expect(agent_q::local_pin_auth_add_digit('0', 100) ==
                   agent_q::AgentQLocalPinAuthInputResult::accepted,
               "shared attempt setup digit 6 accepted");
        expect(agent_q::local_pin_auth_submit(g_now, 0, 100, 90) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "shared attempt wrong connect PIN starts verification");
        agent_q::AgentQLocalAuthWorkerResult worker_result = {};
        worker_result.job_id = g_last_worker_job_id;
        worker_result.owner = agent_q::AgentQLocalAuthWorkerOwner::local_pin_auth;
        worker_result.operation = agent_q::AgentQLocalAuthWorkerOperation::verify_pin;
        worker_result.status = agent_q::AgentQLocalAuthWorkerStatus::ok;
        worker_result.verified = false;
        const agent_q::AgentQLocalPinAuthVerifyResult result =
            agent_q::local_pin_auth_complete_verify_job(worker_result, 100, 80, 0);
        expect(attempt == 4
                   ? result == agent_q::AgentQLocalPinAuthVerifyResult::locked
                   : result == agent_q::AgentQLocalPinAuthVerifyResult::wrong_pin,
               "connect PIN failures drive shared lockout");
    }
    agent_q::local_pin_auth_clear_flow();
    agent_q::local_reset_begin_settings(120);
    expect(agent_q::local_reset_begin_pin_entry(120), "reset PIN entry starts after connect failures");
    expect(agent_q::local_reset_snapshot(20).lockout_active,
           "reset PIN sees shared lockout from connect PIN failures");
    expect(agent_q::local_reset_submit_pin_for_verification(20, 120, 90) ==
               agent_q::AgentQLocalResetPinSubmitResult::locked,
           "reset PIN submit is locked by shared attempt budget");
    expect(agent_q::local_reset_release_lockout_if_elapsed(80),
           "reset PIN releases elapsed shared lockout");
    expect(!agent_q::local_reset_snapshot(80).lockout_active,
           "reset PIN lockout release clears shared budget");
    agent_q::local_reset_wipe();

    reset_stubs();
    g_now = 90;
    agent_q::local_reset_begin_settings(140);
    expect(agent_q::local_reset_begin_pin_entry(140), "reset PIN entry starts before input deadline test");
    expect(agent_q::local_reset_add_pin_digit('1'), "reset digit accepted before deadline");
    expect(agent_q::local_reset_backspace_pin(), "reset backspace accepted before deadline");
    expect(agent_q::local_reset_clear_pin(), "reset clear accepted before deadline");
    expect(agent_q::local_reset_deadline_expired(140),
           "reset digit, backspace, and clear do not extend input deadline");
    g_now = 141;
    expect(!agent_q::local_reset_add_pin_digit('1'),
           "reset digit after deadline is rejected by owner");
    expect(agent_q::local_reset_submit_pin_for_verification(141, 300, 200) ==
               agent_q::AgentQLocalResetPinSubmitResult::unavailable_stage,
           "reset submit after deadline does not start verification");
    agent_q::local_reset_wipe();

    reset_stubs();
    agent_q::local_reset_begin_settings(200);
    expect(agent_q::local_reset_begin_pin_entry(200), "reset PIN entry starts before verification");
    const char reset_verify_pin[] = "123456";
    for (size_t index = 0; reset_verify_pin[index] != '\0'; ++index) {
        const char digit = reset_verify_pin[index];
        expect(agent_q::local_reset_add_pin_digit(digit), "reset verification PIN digit accepted");
    }
    expect(agent_q::local_reset_submit_pin_for_verification(110, 200, 150) ==
               agent_q::AgentQLocalResetPinSubmitResult::started_verification,
           "reset PIN verification starts");
    expect(agent_q::local_reset_snapshot(130).stage == agent_q::AgentQLocalResetStage::pin_verifying,
           "reset PIN verification stays active during cryptographic processing");
    g_now = 149;
    agent_q::AgentQLocalAuthWorkerResult reset_worker_result = {};
    reset_worker_result.job_id = g_last_worker_job_id;
    reset_worker_result.owner = agent_q::AgentQLocalAuthWorkerOwner::local_reset;
    reset_worker_result.operation = agent_q::AgentQLocalAuthWorkerOperation::verify_pin;
    reset_worker_result.status = agent_q::AgentQLocalAuthWorkerStatus::ok;
    reset_worker_result.verified = false;
    expect(agent_q::local_reset_complete_pin_verify_job(reset_worker_result, 160, 180, 0) ==
               agent_q::AgentQLocalResetPinVerifyResult::wrong_pin,
           "reset wrong PIN result before worker deadline opens retry state");
    expect(agent_q::local_reset_snapshot(161).stage == agent_q::AgentQLocalResetStage::pin_entry,
           "reset wrong PIN returns to PIN entry");

    reset_stubs();
    agent_q::local_reset_begin_settings(300);
    expect(agent_q::local_reset_begin_pin_entry(300), "reset PIN entry starts before worker timeout test");
    for (size_t index = 0; reset_verify_pin[index] != '\0'; ++index) {
        const char digit = reset_verify_pin[index];
        expect(agent_q::local_reset_add_pin_digit(digit), "reset timeout PIN digit accepted");
    }
    expect(agent_q::local_reset_submit_pin_for_verification(210, 300, 250) ==
               agent_q::AgentQLocalResetPinSubmitResult::started_verification,
           "reset PIN worker-timeout test starts verification");
    expect(!agent_q::local_reset_fail_processing_if_expired(249),
           "reset PIN verification stays active before worker deadline");
    expect(agent_q::local_reset_fail_processing_if_expired(250),
           "reset PIN verification worker timeout clears flow");
    expect(g_last_cancelled_worker_job_id == g_last_worker_job_id,
           "reset PIN verification worker timeout cancels worker job");
    expect(agent_q::local_reset_snapshot(250).stage == agent_q::AgentQLocalResetStage::none,
           "reset PIN verification worker timeout leaves no active reset flow");

    reset_stubs();
    agent_q::local_reset_begin_settings(400);
    expect(agent_q::local_reset_begin_pin_entry(400), "reset PIN entry starts before late-result test");
    for (size_t index = 0; reset_verify_pin[index] != '\0'; ++index) {
        const char digit = reset_verify_pin[index];
        expect(agent_q::local_reset_add_pin_digit(digit), "reset late-result PIN digit accepted");
    }
    expect(agent_q::local_reset_submit_pin_for_verification(310, 400, 350) ==
               agent_q::AgentQLocalResetPinSubmitResult::started_verification,
           "reset PIN late-result test starts verification");
    g_now = 351;
    reset_worker_result = {};
    reset_worker_result.job_id = g_last_worker_job_id;
    reset_worker_result.owner = agent_q::AgentQLocalAuthWorkerOwner::local_reset;
    reset_worker_result.operation = agent_q::AgentQLocalAuthWorkerOperation::verify_pin;
    reset_worker_result.status = agent_q::AgentQLocalAuthWorkerStatus::ok;
    reset_worker_result.verified = true;
    expect(agent_q::local_reset_complete_pin_verify_job(reset_worker_result, 400, 430, 0) ==
               agent_q::AgentQLocalResetPinVerifyResult::auth_unavailable,
           "late reset PIN verification result fails closed");
    expect(agent_q::local_reset_snapshot(351).stage == agent_q::AgentQLocalResetStage::none,
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
  -I"${AGENT_Q_DIR}" \
  "${AGENT_Q_DIR}/agent_q_pin_attempt.cpp" \
  "${AGENT_Q_DIR}/agent_q_persistent_material.cpp" \
  "${AGENT_Q_DIR}/agent_q_signing_mode.cpp" \
  "${AGENT_Q_DIR}/agent_q_local_pin_auth.cpp" \
  "${AGENT_Q_DIR}/agent_q_local_reset.cpp" \
  "${TMP_DIR}/local_reset_test.cpp" \
  -o "${TMP_DIR}/local_reset_test"

"${TMP_DIR}/local_reset_test"
