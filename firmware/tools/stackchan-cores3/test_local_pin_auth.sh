#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_local_pin_auth.sh

Compiles the StackChan CoreS3 local PIN authorization state machine against
host stubs and verifies connect, settings toggle, change-PIN, policy update,
lockout, and deadline transitions. This test uses only a host C++ compiler and
does NOT require ESP-IDF.
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

for required in \
  "${RUNTIME_DIR}/local_pin_auth.cpp" \
  "${RUNTIME_DIR}/local_pin_auth.h" \
  "${RUNTIME_DIR}/pin_attempt.cpp" \
  "${RUNTIME_DIR}/pin_attempt.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-local-pin-auth.XXXXXX")"
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

extern "C" TickType_t xTaskGetTickCount(void);
H

cat >"${TMP_DIR}/stubs.cpp" <<'CPP'
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "human_approval_settings.h"
#include "local_auth_test.h"
#include "local_auth_worker.h"
#include "signing_mode.h"
#include "sui_account_settings.h"
#include "freertos/FreeRTOS.h"

namespace {

TickType_t g_now = 1;
char g_current_pin[signing::kLocalPinBufferSize] = "123456";
signing::HumanApprovalInputMode g_human_approval_input_mode =
    signing::HumanApprovalInputMode::pin;
signing::SuiAccountSettings g_sui_account_settings =
    signing::kDefaultSuiAccountSettings;
bool g_store_sui_account_settings_result = true;
uint32_t g_last_worker_job_id = 0;
uint32_t g_last_cancelled_worker_job_id = 0;

}  // namespace

extern "C" TickType_t xTaskGetTickCount(void)
{
    return g_now;
}

namespace signing {

void test_set_tick(TickType_t now)
{
    g_now = now;
}

bool test_current_pin_is(const char* pin)
{
    return pin != nullptr && strcmp(g_current_pin, pin) == 0;
}

signing::HumanApprovalInputMode test_human_approval_input_mode()
{
    return g_human_approval_input_mode;
}

signing::SuiAccountSettings test_sui_account_settings()
{
    return g_sui_account_settings;
}

void test_set_store_sui_account_settings_result(bool result)
{
    g_store_sui_account_settings_result = result;
}

uint32_t test_last_worker_job_id()
{
    return g_last_worker_job_id;
}

uint32_t test_last_cancelled_worker_job_id()
{
    return g_last_cancelled_worker_job_id;
}

void wipe_sensitive_buffer(void* data, size_t size)
{
    volatile uint8_t* cursor = static_cast<volatile uint8_t*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

bool is_valid_local_pin(const char* pin)
{
    if (pin == nullptr || strlen(pin) != kLocalPinDigits) {
        return false;
    }
    for (size_t index = 0; index < kLocalPinDigits; ++index) {
        if (!isdigit(static_cast<unsigned char>(pin[index]))) {
            return false;
        }
    }
    return true;
}

bool store_local_pin_verifier(const char* pin)
{
    if (!is_valid_local_pin(pin)) {
        return false;
    }
    strcpy(g_current_pin, pin);
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

bool store_prepared_local_pin_verifier(const LocalAuthPreparedRecord* prepared)
{
    if (prepared == nullptr) {
        return false;
    }
    const char* pin = reinterpret_cast<const char*>(prepared->bytes);
    if (!is_valid_local_pin(pin)) {
        return false;
    }
    strcpy(g_current_pin, pin);
    return true;
}

void wipe_local_pin_verifier_record(LocalAuthPreparedRecord* prepared)
{
    if (prepared != nullptr) {
        wipe_sensitive_buffer(prepared->bytes, sizeof(prepared->bytes));
    }
}

bool verify_local_pin(const char* pin, bool* verified)
{
    if (verified == nullptr) {
        return false;
    }
    *verified = pin != nullptr && strcmp(pin, g_current_pin) == 0;
    return true;
}

bool wipe_local_auth()
{
    return true;
}

LocalAuthStatus local_auth_status()
{
    return LocalAuthStatus::active;
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

bool store_signing_authorization_mode(AuthorizationMode)
{
    return true;
}

bool read_sui_account_settings(SuiAccountSettings* settings)
{
    if (settings == nullptr) {
        return false;
    }
    *settings = g_sui_account_settings;
    return true;
}

bool store_sui_account_settings(const SuiAccountSettings& settings)
{
    if (!g_store_sui_account_settings_result) {
        return false;
    }
    g_sui_account_settings = settings;
    return true;
}

bool wipe_human_approval_input_mode()
{
    return true;
}

bool local_auth_worker_submit_verify(
    LocalAuthWorkerOwner owner,
    const char* pin,
    uint32_t* job_id)
{
    (void)owner;
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
CPP

cat >"${TMP_DIR}/local_pin_auth_test.cpp" <<'CPP'
#include <stdio.h>

#include "local_pin_auth.h"
#include "pin_attempt.h"
#include "sui_account_settings.h"
#include "freertos/task.h"

namespace signing {
void test_set_tick(TickType_t now);
bool test_current_pin_is(const char* pin);
HumanApprovalInputMode test_human_approval_input_mode();
SuiAccountSettings test_sui_account_settings();
void test_set_store_sui_account_settings_result(bool result);
uint32_t test_last_worker_job_id();
uint32_t test_last_cancelled_worker_job_id();
}

namespace {

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

signing::TimeoutWindow test_input_window(TickType_t deadline)
{
    return pin_window(xTaskGetTickCount(), deadline);
}

void enter_pin(const char* pin)
{
    for (size_t index = 0; pin[index] != '\0'; ++index) {
        expect(signing::local_pin_auth_add_digit(pin[index]) ==
                   signing::LocalPinAuthInputResult::accepted,
               "digit accepted");
    }
}

void expect_stage(
    signing::LocalPinAuthPurpose purpose,
    signing::LocalPinAuthStage stage,
    const char* label)
{
    const signing::LocalPinAuthSnapshot snapshot =
        signing::local_pin_auth_snapshot(0);
    expect(snapshot.flow_active, label);
    expect(snapshot.purpose == purpose, label);
    expect(snapshot.stage == stage, label);
}

signing::LocalAuthWorkerResult make_verify_result(bool verified)
{
    signing::LocalAuthWorkerResult worker_result = {};
    worker_result.job_id = signing::test_last_worker_job_id();
    worker_result.owner = signing::LocalAuthWorkerOwner::local_pin_auth;
    worker_result.operation = signing::LocalAuthWorkerOperation::verify_pin;
    worker_result.status = signing::LocalAuthWorkerStatus::ok;
    worker_result.verified = verified;
    return worker_result;
}

signing::LocalAuthWorkerResult make_prepare_result(const char* pin)
{
    signing::LocalAuthWorkerResult worker_result = {};
    worker_result.job_id = signing::test_last_worker_job_id();
    worker_result.owner = signing::LocalAuthWorkerOwner::local_pin_auth;
    worker_result.operation = signing::LocalAuthWorkerOperation::prepare_verifier_record;
    worker_result.status = signing::LocalAuthWorkerStatus::ok;
    signing::prepare_local_pin_verifier_record(pin, &worker_result.prepared_record);
    return worker_result;
}

signing::LocalPinAuthVerifyResult submit_and_verify_wrong_pin(
    TickType_t now,
    TickType_t input_deadline,
    TickType_t lockout_until)
{
    signing::test_set_tick(now);
    enter_pin("000000");
    expect(signing::local_pin_auth_submit(now, 0, test_input_window(input_deadline), now + 10) ==
               signing::LocalPinAuthSubmitResult::started_verification,
           "wrong PIN starts verification");
    signing::LocalAuthWorkerResult worker_result = make_verify_result(false);
    return signing::local_pin_auth_complete_verify_job(
        worker_result,
        pin_window(now, input_deadline),
        lockout_until,
        0);
}

}  // namespace

int main()
{
    {
        constexpr TickType_t start = 100;
        constexpr TickType_t original_input_deadline = 160;
        constexpr TickType_t lockout_until = 130;
        constexpr TickType_t resumed_input_deadline = 190;

        expect(signing::local_pin_auth_begin_connect(start, pin_window(start, original_input_deadline)),
               "connect PIN auth begins before lockout test");

        for (int attempt = 0; attempt < 4; ++attempt) {
            expect(submit_and_verify_wrong_pin(start, original_input_deadline, lockout_until) ==
                       signing::LocalPinAuthVerifyResult::wrong_pin,
                   "wrong PIN before lockout");
        }
        expect(submit_and_verify_wrong_pin(start, original_input_deadline, lockout_until) ==
                   signing::LocalPinAuthVerifyResult::locked,
               "fifth wrong PIN locks the flow");
        expect(signing::local_pin_auth_snapshot(start).lockout_active,
               "snapshot reports active lockout");

        expect(signing::local_pin_auth_release_lockout_if_elapsed(lockout_until) ==
                   signing::LocalPinAuthLockoutReleaseResult::released,
               "lockout release reported");
        expect(!signing::local_pin_auth_snapshot(lockout_until).lockout_active,
               "snapshot reports released lockout");
        expect(signing::local_pin_auth_snapshot(lockout_until).input_window.deadline ==
                   resumed_input_deadline,
               "snapshot resumes the paused PIN input deadline for UI");
        expect(signing::local_pin_auth_snapshot(lockout_until).input_window.started_at ==
                   lockout_until,
               "snapshot exposes lockout-release resume start for UI");
        expect(!signing::local_pin_auth_deadline_expired(resumed_input_deadline - 1),
               "released lockout receives the paused remaining input window");
        expect(signing::local_pin_auth_deadline_expired(resumed_input_deadline),
               "resumed retry window still expires");

        signing::local_pin_auth_clear_flow();
    }

    {
        signing::test_set_tick(200);
        expect(!signing::local_pin_auth_begin_connect(200, pin_window(200, 200)),
               "expired connect PIN window is rejected");
        expect(!signing::local_pin_auth_snapshot(200).flow_active,
               "expired connect PIN window leaves flow inactive");
        expect(!signing::local_pin_auth_begin_connect(200, pin_window(100, 150)),
               "stale connect PIN window is rejected by state owner");
        expect(!signing::local_pin_auth_begin_connect(200, pin_window(220, 260)),
               "future connect PIN window is rejected by state owner");
        expect(!signing::local_pin_auth_begin_change_pin(0, signing::kTimeoutWindowNone),
               "zero local PIN auth deadline is rejected");
        expect(!signing::local_pin_auth_snapshot(200).flow_active,
               "zero local PIN auth deadline leaves flow inactive");
        expect(!signing::local_pin_auth_begin_policy_update(200, pin_window(100, 150)),
               "stale policy update PIN window is rejected by state owner");
        expect(!signing::local_pin_auth_begin_policy_update(200, pin_window(220, 260)),
               "future policy update PIN window is rejected by state owner");
        expect(!signing::local_pin_auth_begin_sui_zklogin_proposal(200, pin_window(100, 150)),
               "stale Sui zkLogin PIN window is rejected by state owner");
        expect(!signing::local_pin_auth_begin_sui_zklogin_proposal(200, pin_window(220, 260)),
               "future Sui zkLogin PIN window is rejected by state owner");
        expect(!signing::local_pin_auth_begin_sui_zklogin_clear_setting(200, pin_window(100, 150)),
               "stale Sui zkLogin clear PIN window is rejected by state owner");
        expect(!signing::local_pin_auth_begin_sui_zklogin_clear_setting(200, pin_window(220, 260)),
               "future Sui zkLogin clear PIN window is rejected by state owner");
        expect(!signing::local_pin_auth_begin_sui_accept_gas_sponsor_setting(
                   signing::SuiAccountSettings{true},
                   200,
                   pin_window(100, 150)),
               "stale Sui gas sponsor setting PIN window is rejected by state owner");
        expect(!signing::local_pin_auth_begin_sui_accept_gas_sponsor_setting(
                   signing::SuiAccountSettings{true},
                   200,
                   pin_window(220, 260)),
               "future Sui gas sponsor setting PIN window is rejected by state owner");
    }

    {
        signing::test_set_tick(200);
        expect(signing::local_pin_auth_begin_connect(200, pin_window(200, 260)),
               "connect PIN auth begins with future deadline");
        expect(signing::local_pin_auth_snapshot(200).input_window.started_at == 200,
               "snapshot exposes current PIN input start for UI");
        expect(signing::local_pin_auth_snapshot(200).input_window.deadline == 260,
               "snapshot exposes current PIN input deadline for UI");
        expect(!signing::local_pin_auth_deadline_expired(259),
               "connect deadline remains open before deadline");
        expect(signing::local_pin_auth_deadline_expired(260),
               "connect deadline expires at deadline");
        signing::local_pin_auth_clear_flow();
        expect(!signing::local_pin_auth_snapshot(260).flow_active,
               "clear flow makes local PIN auth inactive");
    }

    {
        signing::test_set_tick(200);
        expect(signing::local_pin_auth_begin_connect(200, pin_window(200, 260)),
               "connect PIN auth begins before input test");
        expect(signing::local_pin_auth_add_digit('1') ==
                   signing::LocalPinAuthInputResult::accepted,
               "digit input is accepted before deadline");
        expect(signing::local_pin_auth_backspace_pin(),
               "backspace is accepted before deadline");
        expect(signing::local_pin_auth_clear_pin(),
               "clear is accepted before deadline");
        expect(signing::local_pin_auth_deadline_expired(260),
               "digit, backspace, and clear do not extend the input deadline");
        signing::test_set_tick(261);
        expect(signing::local_pin_auth_add_digit('1') ==
                   signing::LocalPinAuthInputResult::inactive,
               "digit input after deadline is rejected by owner");
        expect(signing::local_pin_auth_submit(262, 0, test_input_window(500), 300) ==
                   signing::LocalPinAuthSubmitResult::unavailable_stage,
               "submit after deadline does not start verification");
        signing::local_pin_auth_clear_flow();
    }

    {
        signing::test_set_tick(300);
        expect(signing::local_pin_auth_begin_human_approval_input_setting(
                   signing::HumanApprovalInputMode::confirm,
                   300,
                   pin_window(300, 360)),
               "human approval setting PIN auth begins");
        enter_pin("123456");
        expect(signing::local_pin_auth_submit(301, 0, test_input_window(360), 330) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "settings toggle starts current-PIN verification");
        signing::LocalAuthWorkerResult verify_result = make_verify_result(true);
        expect(signing::local_pin_auth_complete_verify_job(verify_result, pin_window(301, 360), 0, 350) ==
                   signing::LocalPinAuthVerifyResult::started_setting_commit,
               "verified settings toggle starts commit stage");
        expect(!signing::local_pin_auth_fail_processing_if_expired(340),
               "settings toggle commit delay is not a worker processing timeout");
        expect(signing::local_pin_auth_commit_if_ready(349) ==
                   signing::LocalPinAuthCommitResult::not_ready,
               "settings toggle does not commit before delay");
        expect(signing::local_pin_auth_commit_if_ready(350) ==
                   signing::LocalPinAuthCommitResult::setting_stored,
               "settings toggle stores target setting");
        expect(signing::test_human_approval_input_mode() ==
                   signing::HumanApprovalInputMode::confirm,
               "settings toggle persisted Confirm input mode");
        expect(!signing::local_pin_auth_snapshot(305).flow_active,
               "settings toggle commit clears flow");
    }

    {
        signing::test_set_tick(320);
        expect(signing::local_pin_auth_begin_human_approval_input_setting(
                   signing::HumanApprovalInputMode::confirm,
                   320,
                   pin_window(320, 360)),
               "human approval setting PIN auth begins before wrong PIN");
        enter_pin("000000");
        expect(signing::local_pin_auth_submit(321, 0, test_input_window(350), 340) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "human approval setting wrong PIN starts verification");
        signing::LocalAuthWorkerResult verify_result = make_verify_result(false);
        expect(signing::local_pin_auth_complete_verify_job(verify_result, pin_window(321, 350), 0, 0) ==
                   signing::LocalPinAuthVerifyResult::wrong_pin,
               "human approval setting wrong PIN stays in local retry flow");
        signing::LocalPinAuthSnapshot snapshot =
            signing::local_pin_auth_snapshot(321);
        expect(snapshot.flow_active &&
                   snapshot.purpose == signing::LocalPinAuthPurpose::settings_human_approval_input &&
                   snapshot.stage == signing::LocalPinAuthStage::pin_entry,
               "human approval setting wrong PIN remains settings-owned");
        expect(snapshot.input_window.started_at == 320 &&
                   snapshot.input_window.deadline == 360,
               "human approval setting wrong PIN resumes remaining input window");
        signing::local_pin_auth_clear_flow();
    }

    {
        signing::test_set_tick(330);
        expect(signing::local_pin_auth_begin_signing_mode_setting(
                   signing::AuthorizationMode::policy,
                   330,
                   pin_window(330, 360)),
               "signing mode setting PIN auth begins before wrong PIN");
        enter_pin("000000");
        expect(signing::local_pin_auth_submit(331, 0, test_input_window(350), 340) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "signing mode setting wrong PIN starts verification");
        signing::LocalAuthWorkerResult verify_result = make_verify_result(false);
        expect(signing::local_pin_auth_complete_verify_job(verify_result, pin_window(331, 350), 0, 0) ==
                   signing::LocalPinAuthVerifyResult::wrong_pin,
               "signing mode setting wrong PIN stays in local retry flow");
        expect_stage(
            signing::LocalPinAuthPurpose::settings_signing_mode,
            signing::LocalPinAuthStage::pin_entry,
            "signing mode setting wrong PIN remains settings-owned");
        signing::local_pin_auth_clear_flow();
    }

    {
        signing::test_set_tick(335);
        expect(signing::local_pin_auth_begin_policy_reset_setting(
                   335,
                   pin_window(335, 365)),
               "policy reset setting PIN auth begins");
        enter_pin("123456");
        expect(signing::local_pin_auth_submit(336, 0, test_input_window(360), 345) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "policy reset setting starts current-PIN verification");
        signing::LocalAuthWorkerResult verify_result = make_verify_result(true);
        expect(signing::local_pin_auth_complete_verify_job(verify_result, pin_window(336, 360), 0, 0) ==
                   signing::LocalPinAuthVerifyResult::verified_settings_policy_reset,
               "verified policy reset setting stays local-settings owned");
        expect_stage(
            signing::LocalPinAuthPurpose::settings_policy_reset,
            signing::LocalPinAuthStage::pin_verifying,
            "policy reset setting waits for UI-owned commit handling");
        signing::local_pin_auth_clear_flow();
    }

    {
        signing::test_set_tick(338);
        expect(signing::local_pin_auth_begin_sui_accept_gas_sponsor_setting(
                   signing::SuiAccountSettings{true},
                   338,
                   pin_window(338, 368)),
               "Sui gas sponsor setting PIN auth begins");
        expect(signing::local_pin_auth_snapshot(338)
                   .target_sui_account_settings.accept_gas_sponsor,
               "Sui gas sponsor target is captured before PIN verification");
        enter_pin("123456");
        expect(signing::local_pin_auth_submit(339, 0, test_input_window(368), 348) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "Sui gas sponsor setting starts current-PIN verification");
        signing::LocalAuthWorkerResult verify_result = make_verify_result(true);
        expect(signing::local_pin_auth_complete_verify_job(verify_result, pin_window(339, 368), 0, 342) ==
                   signing::LocalPinAuthVerifyResult::started_setting_commit,
               "verified Sui gas sponsor setting starts commit stage");
        expect(signing::local_pin_auth_commit_if_ready(341) ==
                   signing::LocalPinAuthCommitResult::not_ready,
               "Sui gas sponsor setting does not commit before delay");
        expect(signing::local_pin_auth_commit_if_ready(342) ==
                   signing::LocalPinAuthCommitResult::setting_stored,
               "Sui gas sponsor setting stores target setting");
        expect(signing::test_sui_account_settings().accept_gas_sponsor,
               "Sui gas sponsor setting persisted");
        expect(!signing::local_pin_auth_snapshot(342).flow_active,
               "Sui gas sponsor setting commit clears flow");
    }

    {
        signing::test_set_store_sui_account_settings_result(false);
        signing::test_set_tick(339);
        expect(signing::local_pin_auth_begin_sui_accept_gas_sponsor_setting(
                   signing::SuiAccountSettings{false},
                   339,
                   pin_window(339, 369)),
               "Sui gas sponsor setting PIN auth begins before storage failure");
        enter_pin("123456");
        expect(signing::local_pin_auth_submit(340, 0, test_input_window(369), 349) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "Sui gas sponsor setting storage-failure path starts verification");
        signing::LocalAuthWorkerResult verify_result = make_verify_result(true);
        expect(signing::local_pin_auth_complete_verify_job(verify_result, pin_window(340, 369), 0, 343) ==
                   signing::LocalPinAuthVerifyResult::started_setting_commit,
               "verified Sui gas sponsor setting storage-failure path starts commit stage");
        expect(signing::local_pin_auth_commit_if_ready(343) ==
                   signing::LocalPinAuthCommitResult::storage_error,
               "Sui gas sponsor setting reports storage failure");
        expect(signing::test_sui_account_settings().accept_gas_sponsor,
               "Sui gas sponsor storage failure preserves previous value");
        expect(!signing::local_pin_auth_snapshot(343).flow_active,
               "Sui gas sponsor storage failure clears flow");
        signing::test_set_store_sui_account_settings_result(true);
    }

    {
        signing::test_set_tick(340);
        expect(signing::local_pin_auth_begin_change_pin(340, pin_window(340, 370)),
               "change PIN auth begins before current-PIN wrong PIN");
        enter_pin("000000");
        expect(signing::local_pin_auth_submit(341, 0, test_input_window(360), 350) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "change PIN current wrong PIN starts verification");
        signing::LocalAuthWorkerResult verify_result = make_verify_result(false);
        expect(signing::local_pin_auth_complete_verify_job(verify_result, pin_window(341, 360), 0, 0) ==
                   signing::LocalPinAuthVerifyResult::wrong_pin,
               "change PIN current wrong PIN stays in local retry flow");
        expect_stage(
            signing::LocalPinAuthPurpose::settings_change_pin,
            signing::LocalPinAuthStage::pin_entry,
            "change PIN current wrong PIN remains settings-owned");
        signing::local_pin_auth_clear_flow();
    }

    {
        signing::test_set_tick(350);
        expect(signing::local_pin_auth_begin_sui_zklogin_clear_setting(
                   350,
                   pin_window(350, 380)),
               "Sui zkLogin clear setting PIN auth begins");
        enter_pin("123456");
        expect(signing::local_pin_auth_submit(351, 0, test_input_window(380), 360) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "Sui zkLogin clear setting starts current-PIN verification");
        signing::LocalAuthWorkerResult verify_result = make_verify_result(true);
        expect(signing::local_pin_auth_complete_verify_job(verify_result, pin_window(351, 380), 0, 0) ==
                   signing::LocalPinAuthVerifyResult::verified_settings_sui_zklogin_clear,
               "verified Sui zkLogin clear stays local-settings owned");
        expect_stage(
            signing::LocalPinAuthPurpose::settings_sui_zklogin_clear,
            signing::LocalPinAuthStage::pin_verifying,
            "Sui zkLogin clear waits for UI-owned clear handling");
        signing::local_pin_auth_clear_flow();
    }

    {
        using Purpose = signing::LocalPinAuthPurpose;
        using Commit = signing::LocalPinAuthCommitResult;
        using Completion = signing::LocalPinAuthSettingsCompletionResult;

        expect(signing::local_pin_auth_settings_purpose(
                   Purpose::settings_human_approval_input),
               "human approval setting is classified as settings-owned");
        expect(signing::local_pin_auth_settings_purpose(
                   Purpose::settings_sui_zklogin_clear),
               "Sui zkLogin clear is classified as settings-owned");
        expect(!signing::local_pin_auth_settings_purpose(Purpose::connect),
               "connect is not classified as settings-owned");
        expect(signing::local_pin_auth_settings_start_available(),
               "settings start is available when local PIN auth is inactive");
        signing::test_set_tick(355);
        expect(signing::local_pin_auth_begin_connect(355, pin_window(355, 385)),
               "connect PIN auth begins before settings-start availability test");
        expect(!signing::local_pin_auth_settings_start_available(),
               "settings start is unavailable while local PIN auth is active");
        signing::local_pin_auth_clear_flow();
        expect(signing::local_pin_auth_target_human_approval_input_mode(
                   signing::HumanApprovalInputMode::pin) ==
                   signing::HumanApprovalInputMode::confirm,
               "human approval input target toggles PIN to Confirm");
        expect(signing::local_pin_auth_target_human_approval_input_mode(
                   signing::HumanApprovalInputMode::confirm) ==
                   signing::HumanApprovalInputMode::pin,
               "human approval input target toggles Confirm to PIN");
        expect(signing::local_pin_auth_target_signing_authorization_mode(
                   signing::AuthorizationMode::policy) ==
                   signing::AuthorizationMode::user,
               "signing authorization target toggles Policy to User");
        expect(signing::local_pin_auth_target_signing_authorization_mode(
                   signing::AuthorizationMode::user) ==
                   signing::AuthorizationMode::policy,
               "signing authorization target toggles User to Policy");
        expect(signing::local_pin_auth_target_sui_accept_gas_sponsor_settings(
                   signing::SuiAccountSettings{false}).accept_gas_sponsor,
               "Sui gas sponsor target toggles disabled to enabled");
        expect(!signing::local_pin_auth_target_sui_accept_gas_sponsor_settings(
                   signing::SuiAccountSettings{true}).accept_gas_sponsor,
               "Sui gas sponsor target toggles enabled to disabled");
        expect(signing::local_pin_auth_settings_completion_for_commit_result(
                   Purpose::connect,
                   Commit::setting_stored) == Completion::not_ready,
               "non-settings purpose does not produce a settings completion");
        expect(signing::local_pin_auth_settings_completion_for_commit_result(
                   Purpose::settings_policy_reset,
                   Commit::setting_stored) == Completion::not_ready,
               "policy reset purpose does not consume setting commit results");
        expect(signing::local_pin_auth_settings_completion_for_commit_result(
                   Purpose::settings_human_approval_input,
                   Commit::pin_changed) == Completion::not_ready,
               "non-PIN-change setting purpose does not consume PIN change results");
        expect(signing::local_pin_auth_settings_completion_for_commit_result(
                   Purpose::settings_human_approval_input,
                   Commit::setting_stored) == Completion::settings_saved,
               "human approval setting save returns settings completion");
        expect(signing::local_pin_auth_settings_completion_for_commit_result(
                   Purpose::settings_signing_mode,
                   Commit::storage_error) == Completion::settings_error,
               "signing mode storage failure returns settings error completion");
        expect(signing::local_pin_auth_settings_completion_for_commit_result(
                   Purpose::settings_sui_accept_gas_sponsor,
                   Commit::setting_stored) == Completion::sui_settings_saved,
               "Sui settings save returns Sui settings completion");
        expect(signing::local_pin_auth_settings_completion_for_commit_result(
                   Purpose::settings_sui_accept_gas_sponsor,
                   Commit::storage_error) == Completion::sui_settings_error,
               "Sui settings storage failure returns Sui settings error completion");
        expect(signing::local_pin_auth_settings_completion_for_commit_result(
                   Purpose::settings_change_pin,
                   Commit::pin_changed) == Completion::pin_changed,
               "PIN change success returns PIN changed completion");
        expect(signing::local_pin_auth_settings_completion_for_commit_result(
                   Purpose::settings_change_pin,
                   Commit::pin_change_storage_error) == Completion::pin_change_failed,
               "PIN change storage failure returns PIN change failed completion");
        expect(signing::local_pin_auth_settings_completion_for_commit_result(
                   Purpose::settings_change_pin,
                   Commit::pin_change_auth_unavailable) == Completion::auth_error,
               "PIN change auth failure returns auth error completion");
        expect(signing::local_pin_auth_settings_completion_for_policy_reset(true) ==
                   Completion::policy_reset,
               "policy reset success returns policy reset completion");
        expect(signing::local_pin_auth_settings_completion_for_policy_reset(false) ==
                   Completion::policy_reset_failed,
               "policy reset failure returns policy reset failed completion");
        expect(signing::local_pin_auth_settings_completion_for_sui_zklogin_clear(true) ==
                   Completion::sui_proof_cleared,
               "Sui zkLogin clear success returns Sui proof cleared completion");
        expect(signing::local_pin_auth_settings_completion_for_sui_zklogin_clear(false) ==
                   Completion::sui_clear_failed,
               "Sui zkLogin clear failure returns Sui clear failed completion");
    }

    {
        signing::test_set_tick(360);
        expect(signing::local_pin_auth_begin_policy_update(360, pin_window(360, 420)),
               "policy update PIN auth begins before capped retry test");
        enter_pin("000000");
        expect(signing::local_pin_auth_submit(361, 0, test_input_window(390), 380) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "policy update wrong PIN starts verification");
        signing::LocalAuthWorkerResult verify_result = make_verify_result(false);
        expect(signing::local_pin_auth_complete_verify_job(verify_result, pin_window(361, 390), 0, 0) ==
                   signing::LocalPinAuthVerifyResult::wrong_pin,
               "policy update wrong PIN resumes remaining input window");
        signing::LocalPinAuthSnapshot snapshot =
            signing::local_pin_auth_snapshot(361);
        expect(snapshot.input_window.started_at == 360 &&
                   snapshot.input_window.deadline == 420,
               "policy update retry window preserves the paused request-backed window");
        signing::local_pin_auth_clear_flow();
    }

    {
        signing::pin_attempt_clear();
        signing::test_set_tick(370);
        expect(signing::local_pin_auth_begin_connect(370, pin_window(370, 420)),
               "connect PIN auth begins before late wrong-PIN result test");
        enter_pin("000000");
        signing::test_set_tick(371);
        expect(signing::local_pin_auth_submit(371, 0, test_input_window(390), 500) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "connect late wrong-PIN result test starts verification");
        signing::test_set_tick(430);
        signing::LocalAuthWorkerResult verify_result = make_verify_result(false);
        expect(signing::local_pin_auth_complete_verify_job(verify_result, pin_window(390, 390), 0, 0) ==
                   signing::LocalPinAuthVerifyResult::wrong_pin,
               "wrong PIN result after input deadline resumes paused input window");
        signing::LocalPinAuthSnapshot snapshot =
            signing::local_pin_auth_snapshot(430);
        expect(snapshot.flow_active &&
                   snapshot.input_window.started_at == 429 &&
                   snapshot.input_window.deadline == 479,
               "late wrong PIN resumes remaining time without resetting timer fill");
        signing::local_pin_auth_clear_flow();
    }

    {
        signing::test_set_tick(400);
        expect(signing::local_pin_auth_begin_policy_update(400, pin_window(400, 460)),
               "policy update PIN auth begins");
        enter_pin("123456");
        expect(signing::local_pin_auth_submit(401, 0, test_input_window(460), 430) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "policy update starts current-PIN verification");
        signing::LocalAuthWorkerResult verify_result = make_verify_result(true);
        expect(signing::local_pin_auth_complete_verify_job(verify_result, pin_window(401, 460), 0, 0) ==
                   signing::LocalPinAuthVerifyResult::verified_policy_update,
               "verified policy update returns policy-update result");
        expect_stage(
            signing::LocalPinAuthPurpose::policy_update,
            signing::LocalPinAuthStage::pin_verifying,
            "policy update waits for caller-owned terminal handling");
        signing::local_pin_auth_clear_flow();
    }

    {
        signing::test_set_tick(410);
        expect(signing::local_pin_auth_begin_sui_zklogin_proposal(410, pin_window(410, 470)),
               "Sui zkLogin proposal PIN auth begins");
        enter_pin("123456");
        expect(signing::local_pin_auth_submit(411, 0, test_input_window(470), 440) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "Sui zkLogin proposal starts current-PIN verification");
        signing::LocalAuthWorkerResult verify_result = make_verify_result(true);
        expect(signing::local_pin_auth_complete_verify_job(verify_result, pin_window(411, 470), 0, 0) ==
                   signing::LocalPinAuthVerifyResult::verified_sui_zklogin_proposal,
               "verified Sui zkLogin proposal returns proposal outcome");
        expect_stage(
            signing::LocalPinAuthPurpose::sui_zklogin_proposal,
            signing::LocalPinAuthStage::pin_verifying,
            "Sui zkLogin proposal waits for caller-owned terminal handling");
        signing::local_pin_auth_clear_flow();
    }

    {
        signing::test_set_tick(400);
        expect(signing::local_pin_auth_begin_change_pin(400, pin_window(400, 460)),
               "change PIN auth begins");
        enter_pin("123456");
        expect(signing::local_pin_auth_submit(401, 0, test_input_window(460), 430) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "change PIN starts current-PIN verification");
        signing::LocalAuthWorkerResult verify_result = make_verify_result(true);
        expect(signing::local_pin_auth_complete_verify_job(verify_result, pin_window(401, 460), 0, 0) ==
                   signing::LocalPinAuthVerifyResult::advanced_to_change_pin,
               "verified current PIN advances to new PIN entry");
        expect_stage(
            signing::LocalPinAuthPurpose::settings_change_pin,
            signing::LocalPinAuthStage::new_pin_entry,
            "change PIN new-entry stage");

        enter_pin("654321");
        expect(signing::local_pin_auth_submit(402, 0, test_input_window(460), 430) ==
                   signing::LocalPinAuthSubmitResult::advanced_to_repeat_pin,
               "change PIN advances to repeat entry");
        expect_stage(
            signing::LocalPinAuthPurpose::settings_change_pin,
            signing::LocalPinAuthStage::repeat_pin_entry,
            "change PIN repeat-entry stage");

        enter_pin("111111");
        expect(signing::local_pin_auth_submit(403, 0, test_input_window(460), 430) ==
                   signing::LocalPinAuthSubmitResult::mismatch_restart,
               "change PIN mismatch restarts new PIN entry");
        expect_stage(
            signing::LocalPinAuthPurpose::settings_change_pin,
            signing::LocalPinAuthStage::new_pin_entry,
            "change PIN mismatch restart stage");

        enter_pin("654321");
        expect(signing::local_pin_auth_submit(404, 0, test_input_window(460), 430) ==
                   signing::LocalPinAuthSubmitResult::advanced_to_repeat_pin,
               "change PIN second new PIN advances");
        enter_pin("654321");
        expect(signing::local_pin_auth_submit(0, 405, test_input_window(460), 430) ==
                   signing::LocalPinAuthSubmitResult::started_pin_change_commit,
               "change PIN matching repeat starts commit");
        signing::LocalAuthWorkerResult prepare_result = make_prepare_result("654321");
        expect(signing::local_pin_auth_complete_pin_change_job(prepare_result) ==
                   signing::LocalPinAuthCommitResult::pin_changed,
               "change PIN stores new verifier");
        expect(signing::test_current_pin_is("654321"),
               "change PIN persisted the new PIN");
        expect(!signing::local_pin_auth_snapshot(405).flow_active,
               "change PIN commit clears flow");
    }

    {
        signing::test_set_tick(500);
        expect(signing::local_pin_auth_begin_connect(500, pin_window(500, 560)),
               "connect PIN auth begins before processing test");
        enter_pin("654321");
        expect(signing::local_pin_auth_submit(501, 0, test_input_window(560), 620) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "connect PIN starts verification");
        expect(!signing::local_pin_auth_fail_processing_if_expired(560),
               "connect PIN verification is not stopped by the input deadline");
        signing::test_set_tick(570);
        signing::LocalAuthWorkerResult verify_result = make_verify_result(true);
        expect(signing::local_pin_auth_complete_verify_job(verify_result, pin_window(560, 660), 0, 0) ==
                   signing::LocalPinAuthVerifyResult::verified_connect,
               "connect PIN verification result is accepted before worker deadline");
        signing::local_pin_auth_clear_flow();
    }

    {
        signing::test_set_tick(620);
        expect(signing::local_pin_auth_begin_connect(620, pin_window(620, 680)),
               "connect PIN auth begins before worker-timeout test");
        enter_pin("654321");
        expect(signing::local_pin_auth_submit(621, 0, test_input_window(680), 650) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "connect PIN worker-timeout test starts verification");
        expect(!signing::local_pin_auth_fail_processing_if_expired(649),
               "connect PIN verification stays active before worker deadline");
        expect(signing::local_pin_auth_fail_processing_if_expired(650),
               "connect PIN verification worker timeout closes flow");
        expect(signing::test_last_cancelled_worker_job_id() == signing::test_last_worker_job_id(),
               "connect PIN verification worker timeout cancels worker job");
        expect(!signing::local_pin_auth_snapshot(650).flow_active,
               "connect PIN verification worker timeout clears flow");
        signing::local_pin_auth_clear_flow();
    }

    {
        signing::test_set_tick(700);
        expect(signing::local_pin_auth_begin_connect(700, pin_window(700, 760)),
               "connect PIN auth begins before late-result test");
        enter_pin("654321");
        expect(signing::local_pin_auth_submit(701, 0, test_input_window(760), 720) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "connect PIN late-result test starts verification");
        signing::test_set_tick(721);
        signing::LocalAuthWorkerResult verify_result = make_verify_result(true);
        expect(signing::local_pin_auth_complete_verify_job(verify_result, pin_window(721, 760), 0, 0) ==
                   signing::LocalPinAuthVerifyResult::auth_unavailable,
               "late connect PIN verification result fails closed");
        expect(!signing::local_pin_auth_snapshot(721).flow_active,
               "late connect PIN verification result clears flow");
    }

    {
        signing::test_set_tick(600);
        expect(signing::local_pin_auth_begin_change_pin(600, pin_window(600, 660)),
               "change PIN auth begins before commit-timeout test");
        enter_pin("654321");
        expect(signing::local_pin_auth_submit(601, 0, test_input_window(660), 620) ==
                   signing::LocalPinAuthSubmitResult::started_verification,
               "change PIN current-PIN verification starts");
        signing::LocalAuthWorkerResult verify_result = make_verify_result(true);
        expect(signing::local_pin_auth_complete_verify_job(verify_result, pin_window(601, 660), 0, 0) ==
                   signing::LocalPinAuthVerifyResult::advanced_to_change_pin,
               "change PIN advances to new PIN before commit timeout test");
        enter_pin("123456");
        expect(signing::local_pin_auth_submit(602, 0, test_input_window(660), 620) ==
                   signing::LocalPinAuthSubmitResult::advanced_to_repeat_pin,
               "change PIN timeout test advances to repeat");
        enter_pin("123456");
        expect(signing::local_pin_auth_submit(0, 605, test_input_window(660), 620) ==
                   signing::LocalPinAuthSubmitResult::started_pin_change_commit,
               "change PIN commit starts before commit timeout");
        expect(!signing::local_pin_auth_fail_processing_if_expired(619),
               "change PIN commit stays active before worker deadline");
        expect(signing::local_pin_auth_fail_processing_if_expired(620),
               "change PIN commit timeout closes flow");
        expect(signing::test_last_cancelled_worker_job_id() == signing::test_last_worker_job_id(),
               "change PIN commit timeout cancels worker job");
        expect(!signing::local_pin_auth_snapshot(620).flow_active,
               "change PIN commit timeout clears flow");
    }

    if (failures != 0) {
        fprintf(stderr, "Local PIN auth tests failed: %d\n", failures);
        return 1;
    }
    printf("Local PIN auth tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${TMP_DIR}" \
  -I"${RUNTIME_DIR}" \
  "${TMP_DIR}/local_pin_auth_test.cpp" \
  "${TMP_DIR}/stubs.cpp" \
  "${RUNTIME_DIR}/local_pin_auth.cpp" \
  "${RUNTIME_DIR}/pin_attempt.cpp" \
  -o "${TMP_DIR}/local_pin_auth_test"

"${TMP_DIR}/local_pin_auth_test"
