#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: tools/firmware/stackchan-cores3/test_local_pin_auth.sh

Compiles the StackChan CoreS3 local PIN authorization state machine against
host stubs and verifies connect, settings toggle, change-PIN, lockout, and
deadline transitions. This test uses only a host C++ compiler and does NOT
require ESP-IDF.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_Q_DIR="${REPO_ROOT}/products/firmware/src/stackchan-cores3/agent_q"

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

mkdir -p "${TMP_DIR}/stubs/freertos"

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

#include "agent_q_connect_settings.h"
#include "agent_q_local_auth.h"
#include "freertos/FreeRTOS.h"

namespace {

TickType_t g_now = 1;
char g_current_pin[agent_q::kLocalPinBufferSize] = "123456";
bool g_require_pin_on_connect = true;

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

bool test_require_pin_on_connect()
{
    return g_require_pin_on_connect;
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

bool wipe_require_pin_on_connect()
{
    return true;
}

}  // namespace agent_q
CPP

cat >"${TMP_DIR}/local_pin_auth_test.cpp" <<'CPP'
#include <stdio.h>

#include "agent_q_local_pin_auth.h"

namespace agent_q {
void test_set_tick(TickType_t now);
bool test_current_pin_is(const char* pin);
bool test_require_pin_on_connect();
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

void enter_pin(const char* pin, TickType_t deadline)
{
    for (size_t index = 0; pin[index] != '\0'; ++index) {
        expect(agent_q::local_pin_auth_add_digit(pin[index], deadline) ==
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

agent_q::AgentQLocalPinAuthVerifyResult submit_and_verify_wrong_pin(
    TickType_t now,
    TickType_t retry_deadline,
    TickType_t lockout_until)
{
    agent_q::test_set_tick(now);
    enter_pin("000000", retry_deadline);
    expect(agent_q::local_pin_auth_submit(now, 0, retry_deadline) ==
               agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
           "wrong PIN starts verification");
    return agent_q::local_pin_auth_verify_if_ready(now, retry_deadline, lockout_until, 0);
}

}  // namespace

int main()
{
    {
        constexpr TickType_t start = 100;
        constexpr TickType_t stale_retry_deadline = 160;
        constexpr TickType_t lockout_until = 130;
        constexpr TickType_t refreshed_retry_deadline = 190;

        agent_q::local_pin_auth_begin_connect(stale_retry_deadline);

        for (int attempt = 0; attempt < 4; ++attempt) {
            expect(submit_and_verify_wrong_pin(start, stale_retry_deadline, lockout_until) ==
                       agent_q::AgentQLocalPinAuthVerifyResult::wrong_pin,
                   "wrong PIN before lockout");
        }
        expect(submit_and_verify_wrong_pin(start, stale_retry_deadline, lockout_until) ==
                   agent_q::AgentQLocalPinAuthVerifyResult::locked,
               "fifth wrong PIN locks the flow");
        expect(agent_q::local_pin_auth_snapshot(start).lockout_active,
               "snapshot reports active lockout");

        expect(agent_q::local_pin_auth_release_lockout_if_elapsed(
                   lockout_until, refreshed_retry_deadline),
               "lockout release reported");
        expect(!agent_q::local_pin_auth_snapshot(lockout_until).lockout_active,
               "snapshot reports released lockout");
        expect(!agent_q::local_pin_auth_deadline_expired(refreshed_retry_deadline - 1),
               "released lockout receives a fresh retry window");
        expect(agent_q::local_pin_auth_deadline_expired(refreshed_retry_deadline),
               "fresh retry window still expires");

        agent_q::local_pin_auth_clear_flow();
    }

    {
        agent_q::local_pin_auth_begin_connect(260);
        expect(!agent_q::local_pin_auth_deadline_expired(259),
               "connect deadline remains open before deadline");
        expect(agent_q::local_pin_auth_deadline_expired(260),
               "connect deadline expires at deadline");
        agent_q::local_pin_auth_clear_flow();
        expect(!agent_q::local_pin_auth_snapshot(260).flow_active,
               "clear flow makes local PIN auth inactive");
    }

    {
        agent_q::test_set_tick(300);
        agent_q::local_pin_auth_begin_connect_setting(false, 360);
        enter_pin("123456", 360);
        expect(agent_q::local_pin_auth_submit(301, 0, 360) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "settings toggle starts current-PIN verification");
        expect(agent_q::local_pin_auth_verify_if_ready(301, 360, 0, 305) ==
                   agent_q::AgentQLocalPinAuthVerifyResult::started_setting_commit,
               "verified settings toggle starts commit stage");
        expect(agent_q::local_pin_auth_commit_if_ready(304) ==
                   agent_q::AgentQLocalPinAuthCommitResult::not_ready,
               "settings toggle does not commit before delay");
        expect(agent_q::local_pin_auth_commit_if_ready(305) ==
                   agent_q::AgentQLocalPinAuthCommitResult::setting_stored,
               "settings toggle stores target setting");
        expect(!agent_q::test_require_pin_on_connect(),
               "settings toggle persisted PIN-on-connect OFF");
        expect(!agent_q::local_pin_auth_snapshot(305).flow_active,
               "settings toggle commit clears flow");
    }

    {
        agent_q::test_set_tick(400);
        agent_q::local_pin_auth_begin_change_pin(460);
        enter_pin("123456", 460);
        expect(agent_q::local_pin_auth_submit(401, 0, 460) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_verification,
               "change PIN starts current-PIN verification");
        expect(agent_q::local_pin_auth_verify_if_ready(401, 460, 0, 0) ==
                   agent_q::AgentQLocalPinAuthVerifyResult::advanced_to_change_pin,
               "verified current PIN advances to new PIN entry");
        expect_stage(
            agent_q::AgentQLocalPinAuthPurpose::settings_change_pin,
            agent_q::AgentQLocalPinAuthStage::new_pin_entry,
            "change PIN new-entry stage");

        enter_pin("654321", 460);
        expect(agent_q::local_pin_auth_submit(402, 0, 460) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::advanced_to_repeat_pin,
               "change PIN advances to repeat entry");
        expect_stage(
            agent_q::AgentQLocalPinAuthPurpose::settings_change_pin,
            agent_q::AgentQLocalPinAuthStage::repeat_pin_entry,
            "change PIN repeat-entry stage");

        enter_pin("111111", 460);
        expect(agent_q::local_pin_auth_submit(403, 0, 460) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::mismatch_restart,
               "change PIN mismatch restarts new PIN entry");
        expect_stage(
            agent_q::AgentQLocalPinAuthPurpose::settings_change_pin,
            agent_q::AgentQLocalPinAuthStage::new_pin_entry,
            "change PIN mismatch restart stage");

        enter_pin("654321", 460);
        expect(agent_q::local_pin_auth_submit(404, 0, 460) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::advanced_to_repeat_pin,
               "change PIN second new PIN advances");
        enter_pin("654321", 460);
        expect(agent_q::local_pin_auth_submit(0, 405, 460) ==
                   agent_q::AgentQLocalPinAuthSubmitResult::started_pin_change_commit,
               "change PIN matching repeat starts commit");
        expect(agent_q::local_pin_auth_commit_if_ready(405) ==
                   agent_q::AgentQLocalPinAuthCommitResult::pin_changed,
               "change PIN stores new verifier");
        expect(agent_q::test_current_pin_is("654321"),
               "change PIN persisted the new PIN");
        expect(!agent_q::local_pin_auth_snapshot(405).flow_active,
               "change PIN commit clears flow");
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
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/local_pin_auth_test.cpp" \
  "${TMP_DIR}/stubs.cpp" \
  "${AGENT_Q_DIR}/agent_q_local_pin_auth.cpp" \
  "${AGENT_Q_DIR}/agent_q_pin_attempt.cpp" \
  -o "${TMP_DIR}/local_pin_auth_test"

"${TMP_DIR}/local_pin_auth_test"
