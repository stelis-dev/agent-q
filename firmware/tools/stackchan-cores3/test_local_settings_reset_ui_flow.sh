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
RUNTIME_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/runtime"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common"
CXX_BIN="${CXX:-c++}"

for required in \
  "${RUNTIME_DIR}/local_settings_reset_ui_flow.cpp" \
  "${RUNTIME_DIR}/modal_transition.cpp" \
  "${RUNTIME_DIR}/modal_transition.h" \
  "${RUNTIME_DIR}/local_settings_reset_ui_flow.h"; do
  if [[ ! -f "${required}" ]]; then
    echo "Missing required source: ${required}" >&2
    exit 1
  fi
done

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signing-local-settings-reset-ui-flow.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/stubs/freertos" "${TMP_DIR}/stubs/lvgl" "${TMP_DIR}/firmware_common"
ln -s "${COMMON_ROOT}/policy" "${TMP_DIR}/firmware_common/policy"

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

#include "local_settings_reset_ui_flow.h"
#include "local_settings_touch_entry.h"

namespace {

int failures = 0;
TickType_t g_now = 10;
bool g_material_ready = true;
bool g_settings_available = true;
bool g_error_recovery_available = true;
bool g_consistency_error_active = false;
bool g_display_ready = true;
bool g_panel_active[16] = {};
bool g_local_reset_panel_active = false;
bool g_draw_settings = true;
bool g_draw_reset_pin = true;
bool g_draw_error_recovery = true;
bool g_draw_processing = true;
bool g_wipe_ready = false;
signing::LocalResetStage g_stage = signing::LocalResetStage::none;
signing::LocalResetPinSubmitResult g_submit_result =
    signing::LocalResetPinSubmitResult::started_verification;
signing::LocalResetPinVerifyResult g_verify_result =
    signing::LocalResetPinVerifyResult::verified;
signing::LocalResetCommitResult g_commit_result =
    signing::LocalResetCommitResult::ok;
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
int g_order_counter = 0;
int g_commit_order = 0;
int g_clear_panel_order = 0;
int g_show_message_order = 0;
int g_draw_settings_order = 0;
const char* g_last_message = nullptr;
const char* g_last_reset_notice = nullptr;
signing::MessageKind g_last_kind = signing::MessageKind::info;
signing::UiPanelKind g_last_clear_panel_kind = signing::UiPanelKind::none;

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
    g_stage = signing::LocalResetStage::none;
    g_submit_result = signing::LocalResetPinSubmitResult::started_verification;
    g_verify_result = signing::LocalResetPinVerifyResult::verified;
    g_commit_result = signing::LocalResetCommitResult::ok;
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
    g_order_counter = 0;
    g_commit_order = 0;
    g_clear_panel_order = 0;
    g_show_message_order = 0;
    g_draw_settings_order = 0;
    g_last_message = nullptr;
    g_last_reset_notice = nullptr;
    g_last_kind = signing::MessageKind::info;
    g_last_clear_panel_kind = signing::UiPanelKind::none;
}

bool material_ready() { return g_material_ready; }
bool settings_available() { return g_settings_available; }
bool error_recovery_available() { return g_error_recovery_available; }
bool consistency_error_active() { return g_consistency_error_active; }
bool display_ready() { return g_display_ready; }

bool panel_active(signing::UiPanelKind kind)
{
    return g_panel_active[static_cast<int>(kind)];
}

bool local_reset_panel_active()
{
    return g_local_reset_panel_active;
}

bool clear_panel(signing::UiPanelKind kind, signing::SensitiveUiClearPolicy)
{
    ++g_clear_panel_calls;
    g_clear_panel_order = ++g_order_counter;
    g_last_clear_panel_kind = kind;
    return true;
}

bool draw_settings()
{
    ++g_draw_settings_calls;
    g_draw_settings_order = ++g_order_counter;
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

bool draw_processing(signing::UiPanelKind)
{
    return g_draw_processing;
}

void clear_touch()
{
    ++g_clear_touch_calls;
}

void show_message(const char* message, signing::MessageKind kind)
{
    ++g_show_message_calls;
    g_show_message_order = ++g_order_counter;
    g_last_message = message;
    g_last_kind = kind;
}

void record_failure(signing::PersistentMaterialRuntimeFailure)
{
    ++g_record_failure_calls;
}

void log_noop(const char*) {}

signing::LocalSettingsResetUiFlowOps ops()
{
    return signing::LocalSettingsResetUiFlowOps{
        []() { return g_now; },
        material_ready,
        settings_available,
        error_recovery_available,
        consistency_error_active,
        display_ready,
        panel_active,
        local_reset_panel_active,
        clear_panel,
        draw_settings,
        draw_error_recovery,
        draw_reset_pin,
        draw_processing,
        clear_touch,
        show_message,
        record_failure,
        log_noop,
        log_noop,
        signing::LocalResetPersistenceOps{nullptr, nullptr, nullptr},
        signing::kLocalResetEntryMs,
        250,
        900,
        signing::kLocalAuthWorkerMaxMs,
    };
}

}  // namespace

extern "C" TickType_t xTaskGetTickCount()
{
    return g_now;
}

namespace signing {

void local_settings_touch_entry_clear()
{
    ++g_clear_touch_calls;
}

LocalResetSnapshot local_reset_snapshot(TickType_t)
{
    return LocalResetSnapshot{
        g_stage,
        0,
        kTimeoutWindowNone,
        false,
        g_stage != LocalResetStage::none,
    };
}

bool local_reset_deadline_expired(TickType_t) { return false; }
bool local_reset_fail_processing_if_expired(TickType_t) { return false; }
LocalResetLockoutReleaseResult local_reset_release_lockout_if_elapsed(TickType_t)
{
    return LocalResetLockoutReleaseResult::not_released;
}
bool local_reset_wipe_ready(TickType_t) { return g_wipe_ready; }

void local_reset_wipe()
{
    ++g_wipe_calls;
    g_stage = LocalResetStage::none;
}

bool local_reset_wipe_active()
{
    const bool active = g_stage != LocalResetStage::none;
    ++g_wipe_calls;
    g_stage = LocalResetStage::none;
    return active;
}

void local_reset_begin_settings(TimeoutWindow)
{
    ++g_begin_settings_calls;
    g_stage = LocalResetStage::settings_menu;
}

void local_reset_begin_error_recovery_confirm(TimeoutWindow)
{
    g_stage = LocalResetStage::error_recovery_confirm;
}

bool local_reset_begin_pin_entry(TimeoutWindow)
{
    if (g_stage != LocalResetStage::settings_menu) {
        return false;
    }
    g_stage = LocalResetStage::pin_entry;
    return true;
}

bool local_reset_begin_error_recovery_wipe(TickType_t)
{
    if (g_stage != LocalResetStage::error_recovery_confirm) {
        return false;
    }
    g_stage = LocalResetStage::wiping;
    return true;
}

bool local_reset_close_settings()
{
    if (g_stage != LocalResetStage::settings_menu) {
        return false;
    }
    ++g_wipe_calls;
    g_stage = LocalResetStage::none;
    return true;
}

LocalResetReturnToSettingsResult local_reset_return_to_settings(TimeoutWindow)
{
    if (g_stage != LocalResetStage::pin_entry) {
        return LocalResetReturnToSettingsResult::stale;
    }
    ++g_begin_settings_calls;
    g_stage = LocalResetStage::settings_menu;
    return LocalResetReturnToSettingsResult::started;
}

bool local_reset_cancel_error_recovery()
{
    if (g_stage != LocalResetStage::error_recovery_confirm) {
        return false;
    }
    ++g_wipe_calls;
    g_stage = LocalResetStage::none;
    return true;
}

bool local_reset_begin_settings_pin_auth_handoff()
{
    if (g_stage != LocalResetStage::settings_menu) {
        return false;
    }
    ++g_wipe_calls;
    g_stage = LocalResetStage::none;
    return true;
}

bool local_reset_begin_error_recovery_confirm_if_idle(
    TimeoutWindow)
{
    if (g_stage != LocalResetStage::none) {
        return false;
    }
    g_stage = LocalResetStage::error_recovery_confirm;
    return true;
}

LocalResetErrorRecoveryActionResult local_reset_handle_error_recovery_confirm(
    TimeoutWindow,
    TickType_t,
    bool start_available)
{
    if (g_stage == LocalResetStage::none) {
        if (!start_available) {
            return LocalResetErrorRecoveryActionResult::stale;
        }
        g_stage = LocalResetStage::error_recovery_confirm;
        return LocalResetErrorRecoveryActionResult::confirmation_started;
    }
    if (g_stage != LocalResetStage::error_recovery_confirm) {
        return LocalResetErrorRecoveryActionResult::stale;
    }
    g_stage = LocalResetStage::wiping;
    return LocalResetErrorRecoveryActionResult::wipe_started;
}

bool local_reset_abort_pin_verification()
{
    if (g_stage != LocalResetStage::pin_verifying) {
        return false;
    }
    ++g_wipe_calls;
    g_stage = LocalResetStage::none;
    return true;
}

LocalResetUiMaintenanceResult local_reset_handle_ui_maintenance(
    bool panel_active,
    TickType_t)
{
    if (g_stage == LocalResetStage::pin_verifying && !panel_active) {
        return LocalResetUiMaintenanceResult::redraw_pin_verification_panel;
    }
    if (g_stage == LocalResetStage::wiping && !panel_active) {
        return LocalResetUiMaintenanceResult::redraw_wiping_panel;
    }
    return LocalResetUiMaintenanceResult::unchanged;
}

bool local_reset_add_pin_digit(char) { return g_stage == LocalResetStage::pin_entry; }
bool local_reset_clear_pin() { return g_stage == LocalResetStage::pin_entry; }
bool local_reset_backspace_pin() { return g_stage == LocalResetStage::pin_entry; }

LocalResetPinSubmitResult local_reset_submit_pin_for_verification(TickType_t, TickType_t)
{
    if (g_submit_result == LocalResetPinSubmitResult::started_verification) {
        g_stage = LocalResetStage::pin_verifying;
    }
    return g_submit_result;
}

LocalResetPinVerifyResult local_reset_complete_pin_verify_job(
    const LocalAuthWorkerResult&,
    TickType_t,
    TickType_t)
{
    if (g_verify_result == LocalResetPinVerifyResult::verified) {
        g_stage = LocalResetStage::wiping;
    }
    return g_verify_result;
}

LocalResetCommitResult local_reset_commit_material(const LocalResetPersistenceOps&)
{
    ++g_commit_calls;
    g_commit_order = ++g_order_counter;
    return g_commit_result;
}

LocalResetCommitFinishResult local_reset_finish_commit_if_ready(
    TickType_t,
    const LocalResetPersistenceOps& ops)
{
    if (!g_wipe_ready) {
        return LocalResetCommitFinishResult{
            LocalResetCommitFinishStatus::not_ready,
            LocalResetCommitResult::missing_state,
        };
    }
    const LocalResetCommitResult result = local_reset_commit_material(ops);
    ++g_wipe_calls;
    g_stage = LocalResetStage::none;
    return LocalResetCommitFinishResult{
        LocalResetCommitFinishStatus::committed,
        result,
    };
}

LocalResetCommitResult local_reset_resume_pending_if_needed(
    const LocalResetPersistenceOps&,
    bool*)
{
    return LocalResetCommitResult::ok;
}

}  // namespace signing

int main()
{
    reset_harness();
    g_settings_available = false;
    signing::local_settings_reset_ui_start_from_touch(ops());
    expect(g_clear_touch_calls == 1, "unavailable settings touch clears entry");
    expect(g_draw_settings_calls == 0, "unavailable settings does not draw menu");

    reset_harness();
    signing::local_settings_reset_ui_start_from_touch(ops());
    expect(g_stage == signing::LocalResetStage::settings_menu, "settings start enters menu");
    expect(g_draw_settings_calls == 1, "settings start draws menu");

    reset_harness();
    g_stage = signing::LocalResetStage::settings_menu;
    expect(signing::local_settings_reset_ui_begin_settings_pin_auth_handoff("stale", ops()),
           "settings PIN-auth handoff accepted from menu");
    expect(g_stage == signing::LocalResetStage::none, "settings handoff consumes reset/menu state");

    reset_harness();
    g_stage = signing::LocalResetStage::settings_menu;
    expect(signing::local_settings_reset_ui_panel_matches_stage(
               signing::UiPanelKind::sui_settings),
           "Sui settings panel is owned by settings state");

    reset_harness();
    g_stage = signing::LocalResetStage::settings_menu;
    expect(signing::local_settings_reset_ui_panel_matches_stage(
               signing::UiPanelKind::chain_settings_menu),
           "chain settings menu panel is owned by settings state");

    reset_harness();
    g_stage = signing::LocalResetStage::settings_menu;
    g_panel_active[static_cast<int>(signing::UiPanelKind::chain_settings_menu)] = true;
    signing::local_settings_reset_ui_close_settings_from_ui(ops());
    expect(g_clear_panel_calls == 1, "chain settings close clears active chain panel");
    expect(g_last_clear_panel_kind == signing::UiPanelKind::chain_settings_menu,
           "chain settings close targets chain panel");
    expect(g_wipe_calls == 1, "chain settings close wipes local settings owner");

    reset_harness();
    g_stage = signing::LocalResetStage::settings_menu;
    signing::local_settings_reset_ui_start_reset_pin_from_settings_menu(ops());
    expect(g_stage == signing::LocalResetStage::pin_entry, "reset action enters PIN entry");
    expect(g_draw_reset_pin_calls == 1, "reset action draws PIN panel");

    reset_harness();
    g_stage = signing::LocalResetStage::pin_entry;
    g_submit_result = signing::LocalResetPinSubmitResult::invalid_pin;
    signing::local_settings_reset_ui_handle_reset_pin_submit(ops());
    expect(g_last_reset_notice != nullptr &&
               strcmp(g_last_reset_notice, "Enter exactly 6 digits.") == 0,
           "invalid reset PIN redraws with validation notice");

    reset_harness();
    g_stage = signing::LocalResetStage::pin_entry;
    g_draw_reset_pin = false;
    signing::local_settings_reset_ui_handle_reset_pin_digit('1', ops());
    expect(g_wipe_calls == 1, "reset PIN display failure wipes reset state");
    expect(g_last_message != nullptr && strcmp(g_last_message, "Display error") == 0,
           "reset PIN display failure shows display error");

    reset_harness();
    g_consistency_error_active = true;
    signing::local_settings_reset_ui_show_persistent_error_recovery_if_needed(ops());
    expect(g_draw_error_recovery_calls == 1, "persistent error draws recovery panel");

    reset_harness();
    g_wipe_ready = true;
    g_stage = signing::LocalResetStage::wiping;
    g_panel_active[static_cast<int>(signing::UiPanelKind::reset_pin_entry)] = true;
    signing::local_settings_reset_ui_commit_if_ready(ops());
    expect(g_commit_calls == 1, "ready reset commit calls persistence boundary");
    expect(g_last_message != nullptr && strcmp(g_last_message, "Device reset") == 0,
           "successful reset commit reports device reset");
    expect(g_commit_order < g_show_message_order,
           "reset commit reports result only after persistence boundary");
    expect(g_show_message_order < g_clear_panel_order,
           "reset commit keeps processing panel until result overlay is prepared");

    reset_harness();
    g_stage = signing::LocalResetStage::pin_entry;
    g_panel_active[static_cast<int>(signing::UiPanelKind::reset_pin_entry)] = true;
    signing::local_settings_reset_ui_cancel_reset_from_ui("Reset canceled", ops());
    expect(g_begin_settings_calls == 1, "reset cancel returns to settings state");
    expect(g_draw_settings_calls == 1, "reset cancel draws settings menu");
    expect(g_clear_panel_calls == 1, "reset cancel clears old PIN panel");
    expect(g_draw_settings_order < g_clear_panel_order,
           "reset cancel prepares settings menu before clearing PIN panel");

    reset_harness();
    g_stage = signing::LocalResetStage::error_recovery_confirm;
    g_panel_active[static_cast<int>(signing::UiPanelKind::error_recovery)] = true;
    signing::local_settings_reset_ui_cancel_error_recovery_from_ui(ops());
    expect(g_show_message_calls == 1, "error recovery cancel shows result");
    expect(g_clear_panel_calls == 1, "error recovery cancel clears old panel");
    expect(g_show_message_order < g_clear_panel_order,
           "error recovery cancel prepares result before clearing old panel");

    reset_harness();
    g_consistency_error_active = true;
    g_error_recovery_available = false;
    signing::local_settings_reset_ui_confirm_error_recovery_from_ui(ops());
    expect(g_stage == signing::LocalResetStage::none,
           "idle error recovery confirm respects recovery availability");
    expect(g_draw_error_recovery_calls == 0,
           "unavailable idle error recovery confirm does not draw confirmation");

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
  -I"${RUNTIME_DIR}" -I"${TMP_DIR}/firmware_common" \
  "${TMP_DIR}/test.cpp" \
  "${RUNTIME_DIR}/modal_transition.cpp" \
  "${RUNTIME_DIR}/local_settings_reset_ui_flow.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
