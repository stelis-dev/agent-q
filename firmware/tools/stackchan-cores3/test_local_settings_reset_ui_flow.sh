#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_local_settings_reset_ui_flow.sh

Compiles the StackChan CoreS3 local settings/reset UI-flow controller against
host stubs and verifies that settings entry, reset PIN UI, settings-to-PIN-auth
handoff, persistent error recovery, and reset commit behavior live outside the
USB request server.
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

for required in \
  "${AGENT_Q_DIR}/agent_q_local_settings_reset_ui_flow.cpp" \
  "${AGENT_Q_DIR}/agent_q_local_settings_reset_ui_flow.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-local-settings-reset-ui-flow.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/stubs/freertos" "${TMP_DIR}/stubs/lvgl" "${TMP_DIR}/agent_q_common"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/agent_q_common/policy"

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

cat >"${TMP_DIR}/stubs/lvgl.h" <<'H'
#pragma once

typedef void (*lv_event_cb_t)(void*);
typedef struct {
    int x1;
    int y1;
    int x2;
    int y2;
} lv_area_t;
typedef struct _lv_obj_t lv_obj_t;
H

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <stdio.h>
#include <string.h>

#include "agent_q_local_settings_reset_ui_flow.h"
#include "agent_q_local_settings_touch_entry.h"

namespace {

int failures = 0;
TickType_t g_now = 10;
bool g_material_ready = true;
bool g_settings_available = true;
bool g_error_recovery_available = true;
bool g_consistency_error_active = false;
bool g_display_ready = true;
bool g_panel_active[12] = {};
bool g_local_reset_panel_active = false;
bool g_draw_settings = true;
bool g_draw_reset_pin = true;
bool g_draw_error_recovery = true;
bool g_draw_processing = true;
bool g_wipe_ready = false;
agent_q::AgentQLocalResetStage g_stage = agent_q::AgentQLocalResetStage::none;
agent_q::AgentQLocalResetPinSubmitResult g_submit_result =
    agent_q::AgentQLocalResetPinSubmitResult::started_verification;
agent_q::AgentQLocalResetPinVerifyResult g_verify_result =
    agent_q::AgentQLocalResetPinVerifyResult::verified;
agent_q::AgentQLocalResetCommitResult g_commit_result =
    agent_q::AgentQLocalResetCommitResult::ok;
int g_clear_touch_calls = 0;
int g_clear_panel_calls = 0;
int g_draw_settings_calls = 0;
int g_draw_reset_pin_calls = 0;
int g_draw_error_recovery_calls = 0;
int g_show_message_calls = 0;
int g_record_failure_calls = 0;
int g_commit_calls = 0;
int g_begin_settings_calls = 0;
int g_wipe_calls = 0;
const char* g_last_message = nullptr;
const char* g_last_reset_notice = nullptr;
agent_q::AgentQMessageKind g_last_kind = agent_q::AgentQMessageKind::info;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

void reset_harness()
{
    g_now = 10;
    g_material_ready = true;
    g_settings_available = true;
    g_error_recovery_available = true;
    g_consistency_error_active = false;
    g_display_ready = true;
    memset(g_panel_active, 0, sizeof(g_panel_active));
    g_local_reset_panel_active = false;
    g_draw_settings = true;
    g_draw_reset_pin = true;
    g_draw_error_recovery = true;
    g_draw_processing = true;
    g_wipe_ready = false;
    g_stage = agent_q::AgentQLocalResetStage::none;
    g_submit_result = agent_q::AgentQLocalResetPinSubmitResult::started_verification;
    g_verify_result = agent_q::AgentQLocalResetPinVerifyResult::verified;
    g_commit_result = agent_q::AgentQLocalResetCommitResult::ok;
    g_clear_touch_calls = 0;
    g_clear_panel_calls = 0;
    g_draw_settings_calls = 0;
    g_draw_reset_pin_calls = 0;
    g_draw_error_recovery_calls = 0;
    g_show_message_calls = 0;
    g_record_failure_calls = 0;
    g_commit_calls = 0;
    g_begin_settings_calls = 0;
    g_wipe_calls = 0;
    g_last_message = nullptr;
    g_last_reset_notice = nullptr;
    g_last_kind = agent_q::AgentQMessageKind::info;
}

bool material_ready() { return g_material_ready; }
bool settings_available() { return g_settings_available; }
bool error_recovery_available() { return g_error_recovery_available; }
bool consistency_error_active() { return g_consistency_error_active; }
bool display_ready() { return g_display_ready; }

bool panel_active(agent_q::AgentQUiPanelKind kind)
{
    return g_panel_active[static_cast<int>(kind)];
}

bool local_reset_panel_active()
{
    return g_local_reset_panel_active;
}

bool clear_panel(agent_q::AgentQUiPanelKind, agent_q::SensitiveUiClearPolicy)
{
    ++g_clear_panel_calls;
    return true;
}

bool clear_local_reset_panel(agent_q::SensitiveUiClearPolicy)
{
    ++g_clear_panel_calls;
    return true;
}

bool draw_settings()
{
    ++g_draw_settings_calls;
    return g_draw_settings;
}

bool draw_error_recovery(bool)
{
    ++g_draw_error_recovery_calls;
    return g_draw_error_recovery;
}

bool draw_reset_pin(const char* notice)
{
    ++g_draw_reset_pin_calls;
    g_last_reset_notice = notice;
    return g_draw_reset_pin;
}

bool draw_processing(agent_q::AgentQUiPanelKind)
{
    return g_draw_processing;
}

void clear_touch()
{
    ++g_clear_touch_calls;
}

void show_message(const char* message, agent_q::AgentQMessageKind kind)
{
    ++g_show_message_calls;
    g_last_message = message;
    g_last_kind = kind;
}

void record_failure(agent_q::AgentQPersistentMaterialRuntimeFailure)
{
    ++g_record_failure_calls;
}

void log_noop(const char*) {}

agent_q::AgentQLocalSettingsResetUiFlowOps ops()
{
    return agent_q::AgentQLocalSettingsResetUiFlowOps{
        []() { return g_now; },
        material_ready,
        settings_available,
        error_recovery_available,
        consistency_error_active,
        display_ready,
        panel_active,
        local_reset_panel_active,
        clear_panel,
        clear_local_reset_panel,
        draw_settings,
        draw_error_recovery,
        draw_reset_pin,
        draw_processing,
        clear_touch,
        show_message,
        record_failure,
        log_noop,
        log_noop,
        agent_q::AgentQLocalResetPersistenceOps{nullptr, nullptr, nullptr},
        agent_q::kAgentQLocalResetEntryMs,
        250,
        900,
        agent_q::kAgentQLocalAuthWorkerMaxMs,
    };
}

}  // namespace

extern "C" TickType_t xTaskGetTickCount()
{
    return g_now;
}

namespace agent_q {

void local_settings_touch_entry_clear()
{
    ++g_clear_touch_calls;
}

AgentQLocalResetSnapshot local_reset_snapshot(TickType_t)
{
    return AgentQLocalResetSnapshot{
        g_stage,
        0,
        kAgentQTimeoutWindowNone,
        false,
        g_stage != AgentQLocalResetStage::none,
    };
}

bool local_reset_deadline_expired(TickType_t) { return false; }
bool local_reset_fail_processing_if_expired(TickType_t) { return false; }
AgentQLocalResetLockoutReleaseResult local_reset_release_lockout_if_elapsed(TickType_t)
{
    return AgentQLocalResetLockoutReleaseResult::not_released;
}
bool local_reset_wipe_ready(TickType_t) { return g_wipe_ready; }

void local_reset_wipe()
{
    ++g_wipe_calls;
    g_stage = AgentQLocalResetStage::none;
}

void local_reset_begin_settings(AgentQTimeoutWindow)
{
    ++g_begin_settings_calls;
    g_stage = AgentQLocalResetStage::settings_menu;
}

void local_reset_begin_error_recovery_confirm(AgentQTimeoutWindow)
{
    g_stage = AgentQLocalResetStage::error_recovery_confirm;
}

bool local_reset_begin_pin_entry(AgentQTimeoutWindow)
{
    if (g_stage != AgentQLocalResetStage::settings_menu) {
        return false;
    }
    g_stage = AgentQLocalResetStage::pin_entry;
    return true;
}

bool local_reset_begin_error_recovery_wipe(TickType_t)
{
    if (g_stage != AgentQLocalResetStage::error_recovery_confirm) {
        return false;
    }
    g_stage = AgentQLocalResetStage::wiping;
    return true;
}

bool local_reset_add_pin_digit(char) { return g_stage == AgentQLocalResetStage::pin_entry; }
bool local_reset_clear_pin() { return g_stage == AgentQLocalResetStage::pin_entry; }
bool local_reset_backspace_pin() { return g_stage == AgentQLocalResetStage::pin_entry; }

AgentQLocalResetPinSubmitResult local_reset_submit_pin_for_verification(TickType_t, TickType_t)
{
    if (g_submit_result == AgentQLocalResetPinSubmitResult::started_verification) {
        g_stage = AgentQLocalResetStage::pin_verifying;
    }
    return g_submit_result;
}

AgentQLocalResetPinVerifyResult local_reset_complete_pin_verify_job(
    const AgentQLocalAuthWorkerResult&,
    TickType_t,
    TickType_t)
{
    if (g_verify_result == AgentQLocalResetPinVerifyResult::verified) {
        g_stage = AgentQLocalResetStage::wiping;
    }
    return g_verify_result;
}

AgentQLocalResetCommitResult local_reset_commit_material(const AgentQLocalResetPersistenceOps&)
{
    ++g_commit_calls;
    return g_commit_result;
}

AgentQLocalResetCommitResult local_reset_resume_pending_if_needed(
    const AgentQLocalResetPersistenceOps&,
    bool*)
{
    return AgentQLocalResetCommitResult::ok;
}

}  // namespace agent_q

int main()
{
    reset_harness();
    g_settings_available = false;
    agent_q::local_settings_reset_ui_start_from_touch(ops());
    expect(g_clear_touch_calls == 1, "unavailable settings touch clears entry");
    expect(g_draw_settings_calls == 0, "unavailable settings does not draw menu");

    reset_harness();
    agent_q::local_settings_reset_ui_start_from_touch(ops());
    expect(g_stage == agent_q::AgentQLocalResetStage::settings_menu, "settings start enters menu");
    expect(g_draw_settings_calls == 1, "settings start draws menu");

    reset_harness();
    g_stage = agent_q::AgentQLocalResetStage::settings_menu;
    expect(agent_q::local_settings_reset_ui_begin_settings_pin_auth_handoff("stale", ops()),
           "settings PIN-auth handoff accepted from menu");
    expect(g_stage == agent_q::AgentQLocalResetStage::none, "settings handoff consumes reset/menu state");

    reset_harness();
    g_stage = agent_q::AgentQLocalResetStage::settings_menu;
    agent_q::local_settings_reset_ui_start_reset_pin_from_settings_menu(ops());
    expect(g_stage == agent_q::AgentQLocalResetStage::pin_entry, "reset action enters PIN entry");
    expect(g_draw_reset_pin_calls == 1, "reset action draws PIN panel");

    reset_harness();
    g_stage = agent_q::AgentQLocalResetStage::pin_entry;
    g_submit_result = agent_q::AgentQLocalResetPinSubmitResult::invalid_pin;
    agent_q::local_settings_reset_ui_handle_reset_pin_submit(ops());
    expect(g_last_reset_notice != nullptr &&
               strcmp(g_last_reset_notice, "Enter exactly 6 digits.") == 0,
           "invalid reset PIN redraws with validation notice");

    reset_harness();
    g_stage = agent_q::AgentQLocalResetStage::pin_entry;
    g_draw_reset_pin = false;
    agent_q::local_settings_reset_ui_handle_reset_pin_digit('1', ops());
    expect(g_wipe_calls == 1, "reset PIN display failure wipes reset state");
    expect(g_last_message != nullptr && strcmp(g_last_message, "Display error") == 0,
           "reset PIN display failure shows display error");

    reset_harness();
    g_consistency_error_active = true;
    agent_q::local_settings_reset_ui_show_persistent_error_recovery_if_needed(ops());
    expect(g_draw_error_recovery_calls == 1, "persistent error draws recovery panel");

    reset_harness();
    g_wipe_ready = true;
    g_stage = agent_q::AgentQLocalResetStage::wiping;
    agent_q::local_settings_reset_ui_commit_if_ready(ops());
    expect(g_commit_calls == 1, "ready reset commit calls persistence boundary");
    expect(g_last_message != nullptr && strcmp(g_last_message, "Device reset") == 0,
           "successful reset commit reports device reset");

    if (failures != 0) {
        return 1;
    }
    printf("local settings/reset UI flow tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${TMP_DIR}" \
  -I"${AGENT_Q_DIR}" \
  "${TMP_DIR}/test.cpp" \
  "${AGENT_Q_DIR}/agent_q_local_settings_reset_ui_flow.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
