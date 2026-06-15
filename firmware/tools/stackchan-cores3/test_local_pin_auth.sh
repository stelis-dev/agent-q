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
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common/agent_q"

for required in \
  "${AGENT_Q_DIR}/agent_q_local_pin_auth.cpp" \
  "${AGENT_Q_DIR}/agent_q_local_pin_auth.h" \
  "${AGENT_Q_DIR}/agent_q_pin_attempt.cpp" \
  "${AGENT_Q_DIR}/agent_q_pin_attempt.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

CXX_BIN="${CXX:-c++}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-local-pin-auth.XXXXXX")"
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

extern "C" TickType_t xTaskGetTickCount(void);
H

cat >"${TMP_DIR}/stubs.cpp" <<'CPP'
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "agent_q_human_approval_settings.h"
#include "agent_q_local_auth_test.h"
#include "agent_q_local_auth_worker.h"
#include "agent_q_signing_mode.h"
#include "freertos/FreeRTOS.h"

namespace {

TickType_t g_now = 1;
char g_current_pin[agent_q::kLocalPinBufferSize] = "123456";
agent_q::AgentQHumanApprovalInputMode g_human_approval_input_mode =
    agent_q::AgentQHumanApprovalInputMode::pin;
uint32_t g_last_worker_job_id = 0;
uint32_t g_last_cancelled_worker_job_id = 0;

}  // namespace

extern "C" TickType_t xTaskGetTickCount(void)
{
    return g_now;
}

namespace agent_q {

void test_set_tick(TickType_t now)
{
    g_now = now;
}

bool test_current_pin_is(const char* pin)
{
    return pin != nullptr && strcmp(g_current_pin, pin) == 0;
}

agent_q::AgentQHumanApprovalInputMode test_human_approval_input_mode()
{
    return g_human_approval_input_mode;
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

bool prepare_local_pin_verifier_record(const char* pin, AgentQLocalAuthPreparedRecord* out)
{
    if (!is_valid_local_pin(pin) || out == nullptr) {
        return false;
    }
    wipe_sensitive_buffer(out->bytes, sizeof(out->bytes));
    memcpy(out->bytes, pin, kLocalPinBufferSize);
    return true;
}

bool store_prepared_local_pin_verifier(const AgentQLocalAuthPreparedRecord* prepared)
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

void wipe_local_pin_verifier_record(AgentQLocalAuthPreparedRecord* prepared)
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

AgentQLocalAuthStatus local_auth_status()
{
    return AgentQLocalAuthStatus::active;
}

bool read_human_approval_input_mode(AgentQHumanApprovalInputMode* mode)
{
    if (mode == nullptr) {
        return false;
    }
    *mode = g_human_approval_input_mode;
    return true;
}

bool human_approval_requires_pin()
{
    return g_human_approval_input_mode == AgentQHumanApprovalInputMode::pin;
}

bool store_human_approval_input_mode(AgentQHumanApprovalInputMode mode)
{
    g_human_approval_input_mode = mode;
    return true;
}

bool store_signing_authorization_mode(AgentQSigningAuthorizationMode)
{
    return true;
}

bool wipe_human_approval_input_mode()
{
    return true;
}

bool local_auth_worker_submit_verify(
    AgentQLocalAuthWorkerOwner owner,
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
CPP

cat >"${TMP_DIR}/local_pin_auth_test.cpp" <<'CPP'
#include <stdio.h>

#include "agent_q_local_pin_auth.h"
#include "agent_q_pin_attempt.h"
#include "freertos/task.h"

namespace agent_q {
void test_set_tick(TickType_t now);
bool test_current_pin_is(const char* pin);
AgentQHumanApprovalInputMode test_human_approval_input_mode();
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

agent_q::AgentQTimeoutWindow pin_window(TickType_t started_at, TickType_t deadline)
{
    return agent_q::timeout_window_from_deadline(started_at, deadline);
}

agent_q::AgentQTimeoutWindow test_input_window(TickType_t deadline)
{
    return pin_window(xTaskGetTickCount(), deadline);
}

void enter_pin(const char* pin)
{
    for (size_t index = 0; pin[index] != '\0'; ++index) {
        expect(agent_q::local_pin_auth_add_digit(pin[index]) ==
                   agent_q::AgentQLocalPinAuthInputResult::accepted,
               "digit accepted");
    }
}

void expect_stage(
    agent_q::AgentQLocalPinAuthPurpose purpose,
    agent_q::AgentQLocalPinAuthStage stage,
    const char* label)
{
    const agent_q::AgentQLocalPinAuthSnapshot snapshot =
        agent_q::local_pin_auth_snapshot(0);
    expect(snapshot.flow_active, label);
    expect(snapshot.purpose == purpose, label);
    expect(snapshot.stage == stage, label);
}

agent_q::AgentQLocalAuthWorkerResult make_verify_result(bool verified)
{
    agent_q::AgentQLocalAuthWorkerResult worker_result = {};
    worker_result.job_id = agent_q::test_last_worker_job_id();
    worker_result.owner = agent_q::AgentQLocalAuthWorkerOwner::local_pin_auth;
    worker_result.operation = agent_q::AgentQLocalAuthWorkerOperation::verify_pin;
    worker_result.status = agent_q::AgentQLocalAuthWorkerStatus::ok;
    worker_result.verified = verified;
    return worker_result;
}

agent_q::AgentQLocalAuthWorkerResult make_prepare_result(const char* pin)
{
    agent_q::AgentQLocalAuthWorkerResult worker_result = {};
    worker_result.job_id = agent_q::test_last_worker_job_id();
    worker_result.owner = agent_q::AgentQLocalAuthWorkerOwner::local_pin_auth;
    worker_result.operation = agent_q::AgentQLocalAuthWorkerOperation::prepare_verifier_record;
    worker_result.status = agent_q::AgentQLocalAuthWorkerStatus::ok;
    agent_q::prepare_local_pin_verifier_record(pin, &worker_result.prepared_record);
    return worker_result;
}

agent_q::AgentQLocalPinAuthVerifyResult submit_and_verify_wrong_pin(
    TickType_t now,
    TickType_t input_deadline,
    TickType_t lockout_until)
{
    agent_q::test_set_tick(now);
    enter_pin("000000");
    expect(agent_q::local_pin_auth_submit(now, 0, test_input_window(input_deadline), now + 10) ==
               agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
           "wrong PIN starts verification");
    agent_q::AgentQLocalAuthWorkerResult worker_result = make_verify_result(false);
    return agent_q::local_pin_auth_complete_verify_job(
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

        expect(agent_q::local_pin_auth_begin_connect(start, pin_window(start, original_input_deadline)),
               "connect PIN auth begins before lockout test");

        for (int attempt = 0; attempt < 4; ++attempt) {
            expect(submit_and_verify_wrong_pin(start, original_input_deadline, lockout_until) ==
                       agent_q::AgentQLocalPinAuthVerifyResult::wrong_pin,
                   "wrong PIN before lockout");
        }
        expect(submit_and_verify_wrong_pin(start, original_input_deadline, lockout_until) ==
                   agent_q::AgentQLocalPinAuthVerifyResult::locked,
               "fifth wrong PIN locks the flow");
        expect(agent_q::local_pin_auth_snapshot(start).lockout_active,
               "snapshot reports active lockout");

        expect(agent_q::local_pin_auth_release_lockout_if_elapsed(lockout_until) ==
                   agent_q::AgentQLocalPinAuthLockoutReleaseResult::released,
               "lockout release reported");
        expect(!agent_q::local_pin_auth_snapshot(lockout_until).lockout_active,
               "snapshot reports released lockout");
        expect(agent_q::local_pin_auth_snapshot(lockout_until).input_window.deadline ==
                   resumed_input_deadline,
               "snapshot resumes the paused PIN input deadline for UI");
        expect(agent_q::local_pin_auth_snapshot(lockout_until).input_window.started_at ==
                   lockout_until,
               "snapshot exposes lockout-release resume start for UI");
        expect(!agent_q::local_pin_auth_deadline_expired(resumed_input_deadline - 1),
               "released lockout receives the paused remaining input window");
        expect(agent_q::local_pin_auth_deadline_expired(resumed_input_deadline),
               "resumed retry window still expires");

        agent_q::local_pin_auth_clear_flow();
    }

    {
        agent_q::test_set_tick(200);
        expect(!agent_q::local_pin_auth_begin_connect(200, pin_window(200, 200)),
               "expired connect PIN window is rejected");
        expect(!agent_q::local_pin_auth_snapshot(200).flow_active,
               "expired connect PIN window leaves flow inactive");
        expect(!agent_q::local_pin_auth_begin_connect(200, pin_window(100, 150)),
               "stale connect PIN window is rejected by state owner");
        expect(!agent_q::local_pin_auth_begin_connect(200, pin_window(220, 260)),
               "future connect PIN window is rejected by state owner");
        expect(!agent_q::local_pin_auth_begin_change_pin(0, agent_q::kAgentQTimeoutWindowNone),
               "zero local PIN auth deadline is rejected");
        expect(!agent_q::local_pin_auth_snapshot(200).flow_active,
               "zero local PIN auth deadline leaves flow inactive");
        expect(!agent_q::local_pin_auth_begin_policy_update(200, pin_window(100, 150)),
               "stale policy update PIN window is rejected by state owner");
        expect(!agent_q::local_pin_auth_begin_policy_update(200, pin_window(220, 260)),
               "future policy update PIN window is rejected by state owner");
        expect(!agent_q::local_pin_auth_begin_sui_zklogin_proposal(200, pin_window(100, 150)),
               "stale Sui zkLogin PIN window is rejected by state owner");
        expect(!agent_q::local_pin_auth_begin_sui_zklogin_proposal(200, pin_window(220, 260)),
               "future Sui zkLogin PIN window is rejected by state owner");
    }

    {
        agent_q::test_set_tick(200);
        expect(agent_q::local_pin_auth_begin_connect(200, pin_window(200, 260)),
               "connect PIN auth begins with future deadline");
        expect(agent_q::local_pin_auth_snapshot(200).input_window.started_at == 200,
               "snapshot exposes current PIN input start for UI");
        expect(agent_q::local_pin_auth_snapshot(200).input_window.deadline == 260,
               "snapshot exposes current PIN input deadline for UI");
        expect(!agent_q::local_pin_auth_deadline_expired(259),
               "connect deadline remains open before deadline");
        expect(agent_q::local_pin_auth_deadline_expired(260),
               "connect deadline expires at deadline");
        agent_q::local_pin_auth_clear_flow();
        expect(!agent_q::local_pin_auth_snapshot(260).flow_active,
               "clear flow makes local PIN auth inactive");
    }

    {
        agent_q::test_set_tick(200);
        expect(agent_q::local_pin_auth_begin_connect(200, pin_window(200, 260)),
               "connect PIN auth begins before input test");
        expect(agent_q::local_pin_auth_add_digit('1') ==
                   agent_q::AgentQLocalPinAuthInputResult::accepted,
               "digit input is accepted before deadline");
        expect(agent_q::local_pin_auth_backspace_pin(),
               "backspace is accepted before deadline");
        expect(agent_q::local_pin_auth_clear_pin(),
               "clear is accepted before deadline");
        expect(agent_q::local_pin_auth_deadline_expired(260),
               "digit, backspace, and clear do not extend the input deadline");
        agent_q::test_set_tick(261);
        expect(agent_q::local_pin_auth_add_digit('1') ==
                   agent_q::AgentQLocalPinAuthInputResult::inactive,
               "digit input after deadline is rejected by owner");
        expect(agent_q::local_pin_auth_submit(262, 0, test_input_window(500), 300) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::unavailable_stage,
               "submit after deadline does not start verification");
        agent_q::local_pin_auth_clear_flow();
    }

    {
        agent_q::test_set_tick(300);
        expect(agent_q::local_pin_auth_begin_human_approval_input_setting(
                   agent_q::AgentQHumanApprovalInputMode::confirm,
                   300,
                   pin_window(300, 360)),
               "human approval setting PIN auth begins");
        enter_pin("123456");
        expect(agent_q::local_pin_auth_submit(301, 0, test_input_window(360), 330) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "settings toggle starts current-PIN verification");
        agent_q::AgentQLocalAuthWorkerResult verify_result = make_verify_result(true);
        expect(agent_q::local_pin_auth_complete_verify_job(verify_result, pin_window(301, 360), 0, 305) ==
                   agent_q::AgentQLocalPinAuthVerifyResult::started_setting_commit,
               "verified settings toggle starts commit stage");
        expect(agent_q::local_pin_auth_commit_if_ready(304) ==
                   agent_q::AgentQLocalPinAuthCommitResult::not_ready,
               "settings toggle does not commit before delay");
        expect(agent_q::local_pin_auth_commit_if_ready(305) ==
                   agent_q::AgentQLocalPinAuthCommitResult::setting_stored,
               "settings toggle stores target setting");
        expect(agent_q::test_human_approval_input_mode() ==
                   agent_q::AgentQHumanApprovalInputMode::confirm,
               "settings toggle persisted Confirm input mode");
        expect(!agent_q::local_pin_auth_snapshot(305).flow_active,
               "settings toggle commit clears flow");
    }

    {
        agent_q::test_set_tick(320);
        expect(agent_q::local_pin_auth_begin_human_approval_input_setting(
                   agent_q::AgentQHumanApprovalInputMode::confirm,
                   320,
                   pin_window(320, 360)),
               "human approval setting PIN auth begins before wrong PIN");
        enter_pin("000000");
        expect(agent_q::local_pin_auth_submit(321, 0, test_input_window(350), 340) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "human approval setting wrong PIN starts verification");
        agent_q::AgentQLocalAuthWorkerResult verify_result = make_verify_result(false);
        expect(agent_q::local_pin_auth_complete_verify_job(verify_result, pin_window(321, 350), 0, 0) ==
                   agent_q::AgentQLocalPinAuthVerifyResult::wrong_pin,
               "human approval setting wrong PIN stays in local retry flow");
        agent_q::AgentQLocalPinAuthSnapshot snapshot =
            agent_q::local_pin_auth_snapshot(321);
        expect(snapshot.flow_active &&
                   snapshot.purpose == agent_q::AgentQLocalPinAuthPurpose::settings_human_approval_input &&
                   snapshot.stage == agent_q::AgentQLocalPinAuthStage::pin_entry,
               "human approval setting wrong PIN remains settings-owned");
        expect(snapshot.input_window.started_at == 320 &&
                   snapshot.input_window.deadline == 360,
               "human approval setting wrong PIN resumes remaining input window");
        agent_q::local_pin_auth_clear_flow();
    }

    {
        agent_q::test_set_tick(330);
        expect(agent_q::local_pin_auth_begin_signing_mode_setting(
                   agent_q::AgentQSigningAuthorizationMode::policy,
                   330,
                   pin_window(330, 360)),
               "signing mode setting PIN auth begins before wrong PIN");
        enter_pin("000000");
        expect(agent_q::local_pin_auth_submit(331, 0, test_input_window(350), 340) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "signing mode setting wrong PIN starts verification");
        agent_q::AgentQLocalAuthWorkerResult verify_result = make_verify_result(false);
        expect(agent_q::local_pin_auth_complete_verify_job(verify_result, pin_window(331, 350), 0, 0) ==
                   agent_q::AgentQLocalPinAuthVerifyResult::wrong_pin,
               "signing mode setting wrong PIN stays in local retry flow");
        expect_stage(
            agent_q::AgentQLocalPinAuthPurpose::settings_signing_mode,
            agent_q::AgentQLocalPinAuthStage::pin_entry,
            "signing mode setting wrong PIN remains settings-owned");
        agent_q::local_pin_auth_clear_flow();
    }

    {
        agent_q::test_set_tick(335);
        expect(agent_q::local_pin_auth_begin_policy_reset_setting(
                   335,
                   pin_window(335, 365)),
               "policy reset setting PIN auth begins");
        enter_pin("123456");
        expect(agent_q::local_pin_auth_submit(336, 0, test_input_window(360), 345) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "policy reset setting starts current-PIN verification");
        agent_q::AgentQLocalAuthWorkerResult verify_result = make_verify_result(true);
        expect(agent_q::local_pin_auth_complete_verify_job(verify_result, pin_window(336, 360), 0, 0) ==
                   agent_q::AgentQLocalPinAuthVerifyResult::verified_settings_policy_reset,
               "verified policy reset setting stays local-settings owned");
        expect_stage(
            agent_q::AgentQLocalPinAuthPurpose::settings_policy_reset,
            agent_q::AgentQLocalPinAuthStage::pin_verifying,
            "policy reset setting waits for UI-owned commit handling");
        agent_q::local_pin_auth_clear_flow();
    }

    {
        agent_q::test_set_tick(340);
        expect(agent_q::local_pin_auth_begin_change_pin(340, pin_window(340, 370)),
               "change PIN auth begins before current-PIN wrong PIN");
        enter_pin("000000");
        expect(agent_q::local_pin_auth_submit(341, 0, test_input_window(360), 350) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "change PIN current wrong PIN starts verification");
        agent_q::AgentQLocalAuthWorkerResult verify_result = make_verify_result(false);
        expect(agent_q::local_pin_auth_complete_verify_job(verify_result, pin_window(341, 360), 0, 0) ==
                   agent_q::AgentQLocalPinAuthVerifyResult::wrong_pin,
               "change PIN current wrong PIN stays in local retry flow");
        expect_stage(
            agent_q::AgentQLocalPinAuthPurpose::settings_change_pin,
            agent_q::AgentQLocalPinAuthStage::pin_entry,
            "change PIN current wrong PIN remains settings-owned");
        agent_q::local_pin_auth_clear_flow();
    }

    {
        agent_q::test_set_tick(360);
        expect(agent_q::local_pin_auth_begin_policy_update(360, pin_window(360, 420)),
               "policy update PIN auth begins before capped retry test");
        enter_pin("000000");
        expect(agent_q::local_pin_auth_submit(361, 0, test_input_window(390), 380) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "policy update wrong PIN starts verification");
        agent_q::AgentQLocalAuthWorkerResult verify_result = make_verify_result(false);
        expect(agent_q::local_pin_auth_complete_verify_job(verify_result, pin_window(361, 390), 0, 0) ==
                   agent_q::AgentQLocalPinAuthVerifyResult::wrong_pin,
               "policy update wrong PIN resumes remaining input window");
        agent_q::AgentQLocalPinAuthSnapshot snapshot =
            agent_q::local_pin_auth_snapshot(361);
        expect(snapshot.input_window.started_at == 360 &&
                   snapshot.input_window.deadline == 420,
               "policy update retry window preserves the paused request-backed window");
        agent_q::local_pin_auth_clear_flow();
    }

    {
        agent_q::pin_attempt_clear();
        agent_q::test_set_tick(370);
        expect(agent_q::local_pin_auth_begin_connect(370, pin_window(370, 420)),
               "connect PIN auth begins before late wrong-PIN result test");
        enter_pin("000000");
        agent_q::test_set_tick(371);
        expect(agent_q::local_pin_auth_submit(371, 0, test_input_window(390), 500) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "connect late wrong-PIN result test starts verification");
        agent_q::test_set_tick(430);
        agent_q::AgentQLocalAuthWorkerResult verify_result = make_verify_result(false);
        expect(agent_q::local_pin_auth_complete_verify_job(verify_result, pin_window(390, 390), 0, 0) ==
                   agent_q::AgentQLocalPinAuthVerifyResult::wrong_pin,
               "wrong PIN result after input deadline resumes paused input window");
        agent_q::AgentQLocalPinAuthSnapshot snapshot =
            agent_q::local_pin_auth_snapshot(430);
        expect(snapshot.flow_active &&
                   snapshot.input_window.started_at == 429 &&
                   snapshot.input_window.deadline == 479,
               "late wrong PIN resumes remaining time without resetting timer fill");
        agent_q::local_pin_auth_clear_flow();
    }

    {
        agent_q::test_set_tick(400);
        expect(agent_q::local_pin_auth_begin_policy_update(400, pin_window(400, 460)),
               "policy update PIN auth begins");
        enter_pin("123456");
        expect(agent_q::local_pin_auth_submit(401, 0, test_input_window(460), 430) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "policy update starts current-PIN verification");
        agent_q::AgentQLocalAuthWorkerResult verify_result = make_verify_result(true);
        expect(agent_q::local_pin_auth_complete_verify_job(verify_result, pin_window(401, 460), 0, 0) ==
                   agent_q::AgentQLocalPinAuthVerifyResult::verified_policy_update,
               "verified policy update returns policy-update result");
        expect_stage(
            agent_q::AgentQLocalPinAuthPurpose::policy_update,
            agent_q::AgentQLocalPinAuthStage::pin_verifying,
            "policy update waits for caller-owned terminal handling");
        agent_q::local_pin_auth_clear_flow();
    }

    {
        agent_q::test_set_tick(410);
        expect(agent_q::local_pin_auth_begin_sui_zklogin_proposal(410, pin_window(410, 470)),
               "Sui zkLogin proposal PIN auth begins");
        enter_pin("123456");
        expect(agent_q::local_pin_auth_submit(411, 0, test_input_window(470), 440) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "Sui zkLogin proposal starts current-PIN verification");
        agent_q::AgentQLocalAuthWorkerResult verify_result = make_verify_result(true);
        expect(agent_q::local_pin_auth_complete_verify_job(verify_result, pin_window(411, 470), 0, 0) ==
                   agent_q::AgentQLocalPinAuthVerifyResult::verified_sui_zklogin_proposal,
               "verified Sui zkLogin proposal returns proposal result");
        expect_stage(
            agent_q::AgentQLocalPinAuthPurpose::sui_zklogin_proposal,
            agent_q::AgentQLocalPinAuthStage::pin_verifying,
            "Sui zkLogin proposal waits for caller-owned terminal handling");
        agent_q::local_pin_auth_clear_flow();
    }

    {
        agent_q::test_set_tick(400);
        expect(agent_q::local_pin_auth_begin_change_pin(400, pin_window(400, 460)),
               "change PIN auth begins");
        enter_pin("123456");
        expect(agent_q::local_pin_auth_submit(401, 0, test_input_window(460), 430) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "change PIN starts current-PIN verification");
        agent_q::AgentQLocalAuthWorkerResult verify_result = make_verify_result(true);
        expect(agent_q::local_pin_auth_complete_verify_job(verify_result, pin_window(401, 460), 0, 0) ==
                   agent_q::AgentQLocalPinAuthVerifyResult::advanced_to_change_pin,
               "verified current PIN advances to new PIN entry");
        expect_stage(
            agent_q::AgentQLocalPinAuthPurpose::settings_change_pin,
            agent_q::AgentQLocalPinAuthStage::new_pin_entry,
            "change PIN new-entry stage");

        enter_pin("654321");
        expect(agent_q::local_pin_auth_submit(402, 0, test_input_window(460), 430) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::advanced_to_repeat_pin,
               "change PIN advances to repeat entry");
        expect_stage(
            agent_q::AgentQLocalPinAuthPurpose::settings_change_pin,
            agent_q::AgentQLocalPinAuthStage::repeat_pin_entry,
            "change PIN repeat-entry stage");

        enter_pin("111111");
        expect(agent_q::local_pin_auth_submit(403, 0, test_input_window(460), 430) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::mismatch_restart,
               "change PIN mismatch restarts new PIN entry");
        expect_stage(
            agent_q::AgentQLocalPinAuthPurpose::settings_change_pin,
            agent_q::AgentQLocalPinAuthStage::new_pin_entry,
            "change PIN mismatch restart stage");

        enter_pin("654321");
        expect(agent_q::local_pin_auth_submit(404, 0, test_input_window(460), 430) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::advanced_to_repeat_pin,
               "change PIN second new PIN advances");
        enter_pin("654321");
        expect(agent_q::local_pin_auth_submit(0, 405, test_input_window(460), 430) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_pin_change_commit,
               "change PIN matching repeat starts commit");
        agent_q::AgentQLocalAuthWorkerResult prepare_result = make_prepare_result("654321");
        expect(agent_q::local_pin_auth_complete_pin_change_job(prepare_result) ==
                   agent_q::AgentQLocalPinAuthCommitResult::pin_changed,
               "change PIN stores new verifier");
        expect(agent_q::test_current_pin_is("654321"),
               "change PIN persisted the new PIN");
        expect(!agent_q::local_pin_auth_snapshot(405).flow_active,
               "change PIN commit clears flow");
    }

    {
        agent_q::test_set_tick(500);
        expect(agent_q::local_pin_auth_begin_connect(500, pin_window(500, 560)),
               "connect PIN auth begins before processing test");
        enter_pin("654321");
        expect(agent_q::local_pin_auth_submit(501, 0, test_input_window(560), 620) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "connect PIN starts verification");
        expect(!agent_q::local_pin_auth_fail_processing_if_expired(560),
               "connect PIN verification is not stopped by the input deadline");
        agent_q::test_set_tick(570);
        agent_q::AgentQLocalAuthWorkerResult verify_result = make_verify_result(true);
        expect(agent_q::local_pin_auth_complete_verify_job(verify_result, pin_window(560, 660), 0, 0) ==
                   agent_q::AgentQLocalPinAuthVerifyResult::verified_connect,
               "connect PIN verification result is accepted before worker deadline");
        agent_q::local_pin_auth_clear_flow();
    }

    {
        agent_q::test_set_tick(620);
        expect(agent_q::local_pin_auth_begin_connect(620, pin_window(620, 680)),
               "connect PIN auth begins before worker-timeout test");
        enter_pin("654321");
        expect(agent_q::local_pin_auth_submit(621, 0, test_input_window(680), 650) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "connect PIN worker-timeout test starts verification");
        expect(!agent_q::local_pin_auth_fail_processing_if_expired(649),
               "connect PIN verification stays active before worker deadline");
        expect(agent_q::local_pin_auth_fail_processing_if_expired(650),
               "connect PIN verification worker timeout closes flow");
        expect(agent_q::test_last_cancelled_worker_job_id() == agent_q::test_last_worker_job_id(),
               "connect PIN verification worker timeout cancels worker job");
        expect(!agent_q::local_pin_auth_snapshot(650).flow_active,
               "connect PIN verification worker timeout clears flow");
        agent_q::local_pin_auth_clear_flow();
    }

    {
        agent_q::test_set_tick(700);
        expect(agent_q::local_pin_auth_begin_connect(700, pin_window(700, 760)),
               "connect PIN auth begins before late-result test");
        enter_pin("654321");
        expect(agent_q::local_pin_auth_submit(701, 0, test_input_window(760), 720) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "connect PIN late-result test starts verification");
        agent_q::test_set_tick(721);
        agent_q::AgentQLocalAuthWorkerResult verify_result = make_verify_result(true);
        expect(agent_q::local_pin_auth_complete_verify_job(verify_result, pin_window(721, 760), 0, 0) ==
                   agent_q::AgentQLocalPinAuthVerifyResult::auth_unavailable,
               "late connect PIN verification result fails closed");
        expect(!agent_q::local_pin_auth_snapshot(721).flow_active,
               "late connect PIN verification result clears flow");
    }

    {
        agent_q::test_set_tick(600);
        expect(agent_q::local_pin_auth_begin_change_pin(600, pin_window(600, 660)),
               "change PIN auth begins before commit-timeout test");
        enter_pin("654321");
        expect(agent_q::local_pin_auth_submit(601, 0, test_input_window(660), 620) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "change PIN current-PIN verification starts");
        agent_q::AgentQLocalAuthWorkerResult verify_result = make_verify_result(true);
        expect(agent_q::local_pin_auth_complete_verify_job(verify_result, pin_window(601, 660), 0, 0) ==
                   agent_q::AgentQLocalPinAuthVerifyResult::advanced_to_change_pin,
               "change PIN advances to new PIN before commit timeout test");
        enter_pin("123456");
        expect(agent_q::local_pin_auth_submit(602, 0, test_input_window(660), 620) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::advanced_to_repeat_pin,
               "change PIN timeout test advances to repeat");
        enter_pin("123456");
        expect(agent_q::local_pin_auth_submit(0, 605, test_input_window(660), 620) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_pin_change_commit,
               "change PIN commit starts before commit timeout");
        expect(!agent_q::local_pin_auth_fail_processing_if_expired(619),
               "change PIN commit stays active before worker deadline");
        expect(agent_q::local_pin_auth_fail_processing_if_expired(620),
               "change PIN commit timeout closes flow");
        expect(agent_q::test_last_cancelled_worker_job_id() == agent_q::test_last_worker_job_id(),
               "change PIN commit timeout cancels worker job");
        expect(!agent_q::local_pin_auth_snapshot(620).flow_active,
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
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/local_pin_auth_test.cpp" \
  "${TMP_DIR}/stubs.cpp" \
  "${AGENT_Q_DIR}/agent_q_local_pin_auth.cpp" \
  "${AGENT_Q_DIR}/agent_q_pin_attempt.cpp" \
  -o "${TMP_DIR}/local_pin_auth_test"

"${TMP_DIR}/local_pin_auth_test"
