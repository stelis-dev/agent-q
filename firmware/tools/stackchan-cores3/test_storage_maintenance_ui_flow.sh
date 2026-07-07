#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_storage_maintenance_ui_flow.sh

Compiles the StackChan CoreS3 storage maintenance UI-flow controller against
host stubs and verifies that settings entry, action PIN UI, settings-to-PIN-auth
handoff, persistent error recovery, and storage action commit behavior live outside the
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
DEFAULT_ARDUINOJSON_ROOT="${REPO_ROOT}/.firmware-cache/stackchan-cores3/StackChan/firmware/components/ArduinoJson/src"
ARDUINOJSON_ROOT="${FIRMWARE_ARDUINOJSON_ROOT:-${DEFAULT_ARDUINOJSON_ROOT}}"

if [[ ! -f "${ARDUINOJSON_ROOT}/ArduinoJson.h" ]]; then
  echo "Missing required ArduinoJson source: ${ARDUINOJSON_ROOT}/ArduinoJson.h" >&2
  echo "Run firmware/tools/stackchan-cores3/build.sh first when cache sources are missing." >&2
  exit 1
fi

for required in \
  "${RUNTIME_DIR}/storage_maintenance_ui_flow.cpp" \
  "${RUNTIME_DIR}/modal_transition.cpp" \
  "${RUNTIME_DIR}/modal_transition.h" \
  "${RUNTIME_DIR}/storage_maintenance_ui_flow.h"; do
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

#include "storage_maintenance_ui_flow.h"
#include "local_settings_touch_entry.h"

namespace {

int failures = 0;
TickType_t g_now = 10;
bool g_material_ready = true;
bool g_settings_available = true;
bool g_settings_repair_available = false;
bool g_error_recovery_available = true;
bool g_consistency_error_active = false;
bool g_display_ready = true;
bool g_panel_active[16] = {};
bool g_storage_maintenance_panel_active = false;
bool g_draw_settings = true;
bool g_draw_action_pin = true;
bool g_draw_error_recovery = true;
bool g_draw_processing = true;
bool g_commit_ready = false;
signing::StorageMaintenanceStage g_stage = signing::StorageMaintenanceStage::none;
signing::StorageMaintenanceOperation g_operation = signing::StorageMaintenanceOperation::none;
signing::StorageMaintenanceOperation g_pending_recovery_operation =
    signing::StorageMaintenanceOperation::none;
bool g_pin_entry_from_error_recovery = false;
signing::StorageMaintenancePinSubmitResult g_submit_result =
    signing::StorageMaintenancePinSubmitResult::started_verification;
signing::StorageMaintenancePinVerifyResult g_verify_result =
    signing::StorageMaintenancePinVerifyResult::verified;
signing::StorageMaintenanceCommitResult g_commit_result =
    signing::StorageMaintenanceCommitResult::ok;
int g_clear_touch_calls = 0;
int g_clear_panel_calls = 0;
int g_draw_settings_calls = 0;
int g_draw_action_pin_calls = 0;
int g_draw_error_recovery_calls = 0;
bool g_last_error_recovery_confirm = false;
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
const char* g_last_action_notice = nullptr;
signing::MessageKind g_last_kind = signing::MessageKind::info;
signing::UiPanelKind g_last_clear_panel_kind = signing::UiPanelKind::none;

void expect(bool condition, const char* label)
{
    if (!condition) {
        fprintf(stderr, "FAILED: %s\n", label);
        ++failures;
    }
}

void reset_test_harness()
{
    g_now = 10;
    g_material_ready = true;
    g_settings_available = true;
    g_settings_repair_available = false;
    g_error_recovery_available = true;
    g_consistency_error_active = false;
    g_display_ready = true;
    memset(g_panel_active, 0, sizeof(g_panel_active));
    g_storage_maintenance_panel_active = false;
    g_draw_settings = true;
    g_draw_action_pin = true;
    g_draw_error_recovery = true;
    g_draw_processing = true;
    g_commit_ready = false;
    g_stage = signing::StorageMaintenanceStage::none;
    g_operation = signing::StorageMaintenanceOperation::none;
    g_pending_recovery_operation = signing::StorageMaintenanceOperation::none;
    g_pin_entry_from_error_recovery = false;
    g_submit_result = signing::StorageMaintenancePinSubmitResult::started_verification;
    g_verify_result = signing::StorageMaintenancePinVerifyResult::verified;
    g_commit_result = signing::StorageMaintenanceCommitResult::ok;
    g_clear_touch_calls = 0;
    g_clear_panel_calls = 0;
    g_draw_settings_calls = 0;
    g_draw_action_pin_calls = 0;
    g_draw_error_recovery_calls = 0;
    g_last_error_recovery_confirm = false;
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
    g_last_action_notice = nullptr;
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

bool storage_maintenance_panel_active()
{
    return g_storage_maintenance_panel_active;
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

bool draw_error_recovery(bool confirm)
{
    ++g_draw_error_recovery_calls;
    g_last_error_recovery_confirm = confirm;
    return g_draw_error_recovery;
}

bool draw_action_pin(const char* notice)
{
    ++g_draw_action_pin_calls;
    g_last_action_notice = notice;
    return g_draw_action_pin;
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

signing::StorageMaintenanceUiFlowOps ops()
{
    return signing::StorageMaintenanceUiFlowOps{
        []() { return g_now; },
        material_ready,
        settings_available,
        error_recovery_available,
        consistency_error_active,
        display_ready,
        panel_active,
        storage_maintenance_panel_active,
        clear_panel,
        draw_settings,
        draw_error_recovery,
        draw_action_pin,
        draw_processing,
        clear_touch,
        show_message,
        record_failure,
        log_noop,
        log_noop,
        signing::StorageMaintenancePersistenceOps{nullptr, nullptr, nullptr},
        signing::kStorageMaintenanceEntryMs,
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

StorageMaintenanceSnapshot storage_maintenance_snapshot(TickType_t)
{
    return StorageMaintenanceSnapshot{
        g_stage,
        g_operation,
        0,
        kTimeoutWindowNone,
        false,
        g_stage != StorageMaintenanceStage::none,
    };
}

bool storage_maintenance_deadline_expired(TickType_t) { return false; }
bool storage_maintenance_fail_processing_if_expired(TickType_t) { return false; }
StorageMaintenanceLockoutReleaseResult storage_maintenance_release_lockout_if_elapsed(TickType_t)
{
    return StorageMaintenanceLockoutReleaseResult::not_released;
}
bool storage_maintenance_commit_ready(TickType_t) { return g_commit_ready; }

StorageMaintenanceOperation storage_maintenance_error_recovery_operation()
{
    if (g_pending_recovery_operation != StorageMaintenanceOperation::none) {
        return g_pending_recovery_operation;
    }
    return g_settings_repair_available
               ? StorageMaintenanceOperation::settings_reset
               : StorageMaintenanceOperation::wallet_erase;
}

void storage_maintenance_clear_flow()
{
    ++g_wipe_calls;
    g_stage = StorageMaintenanceStage::none;
    g_operation = StorageMaintenanceOperation::none;
}

bool storage_maintenance_flow_active()
{
    return g_stage != StorageMaintenanceStage::none;
}

void storage_maintenance_begin_settings(TimeoutWindow)
{
    ++g_begin_settings_calls;
    g_stage = StorageMaintenanceStage::settings_menu;
    g_operation = StorageMaintenanceOperation::none;
}

void storage_maintenance_begin_error_recovery_prompt(
    TimeoutWindow,
    StorageMaintenanceOperation operation)
{
    g_stage = StorageMaintenanceStage::error_recovery_prompt;
    g_operation = operation;
}

void storage_maintenance_begin_error_recovery_confirm(
    TimeoutWindow,
    StorageMaintenanceOperation operation)
{
    g_stage = StorageMaintenanceStage::error_recovery_confirm;
    g_operation = operation;
}

bool storage_maintenance_begin_pin_entry(TimeoutWindow)
{
    if (g_stage != StorageMaintenanceStage::settings_menu) {
        return false;
    }
    g_stage = StorageMaintenanceStage::pin_entry;
    g_operation = StorageMaintenanceOperation::settings_reset;
    g_pin_entry_from_error_recovery = false;
    return true;
}

bool storage_maintenance_begin_wallet_erase_pin_entry(TimeoutWindow)
{
    if (!storage_maintenance_begin_pin_entry(kTimeoutWindowNone)) {
        return false;
    }
    g_operation = StorageMaintenanceOperation::wallet_erase;
    return true;
}

bool storage_maintenance_begin_error_recovery_wallet_erase(TickType_t)
{
    if (g_stage != StorageMaintenanceStage::error_recovery_confirm) {
        return false;
    }
    g_stage = StorageMaintenanceStage::committing;
    g_operation = StorageMaintenanceOperation::wallet_erase;
    return true;
}

bool storage_maintenance_begin_error_recovery_settings_repair(TimeoutWindow)
{
    if ((g_stage != StorageMaintenanceStage::error_recovery_prompt &&
         g_stage != StorageMaintenanceStage::error_recovery_confirm) ||
        g_operation != StorageMaintenanceOperation::settings_reset) {
        return false;
    }
    g_stage = StorageMaintenanceStage::pin_entry;
    g_operation = StorageMaintenanceOperation::settings_reset;
    g_pin_entry_from_error_recovery = true;
    return true;
}

bool storage_maintenance_close_settings()
{
    if (g_stage != StorageMaintenanceStage::settings_menu) {
        return false;
    }
    ++g_wipe_calls;
    g_stage = StorageMaintenanceStage::none;
    g_operation = StorageMaintenanceOperation::none;
    return true;
}

StorageMaintenanceCancelPinResult storage_maintenance_cancel_pin_entry(TimeoutWindow)
{
    if (g_stage != StorageMaintenanceStage::pin_entry) {
        return StorageMaintenanceCancelPinResult::stale;
    }
    if (g_pin_entry_from_error_recovery) {
        g_stage = StorageMaintenanceStage::error_recovery_prompt;
        g_operation = StorageMaintenanceOperation::settings_reset;
        g_pin_entry_from_error_recovery = false;
        return StorageMaintenanceCancelPinResult::returned_to_error_recovery;
    }
    ++g_begin_settings_calls;
    g_stage = StorageMaintenanceStage::settings_menu;
    g_operation = StorageMaintenanceOperation::settings_reset;
    return StorageMaintenanceCancelPinResult::returned_to_settings;
}

bool storage_maintenance_cancel_error_recovery()
{
    if (g_stage != StorageMaintenanceStage::error_recovery_prompt &&
        g_stage != StorageMaintenanceStage::error_recovery_confirm) {
        return false;
    }
    ++g_wipe_calls;
    g_stage = StorageMaintenanceStage::none;
    g_operation = StorageMaintenanceOperation::none;
    return true;
}

bool storage_maintenance_begin_settings_pin_auth_handoff()
{
    if (g_stage != StorageMaintenanceStage::settings_menu) {
        return false;
    }
    ++g_wipe_calls;
    g_stage = StorageMaintenanceStage::none;
    g_operation = StorageMaintenanceOperation::none;
    return true;
}

bool storage_maintenance_begin_error_recovery_prompt_if_idle(
    TimeoutWindow,
    StorageMaintenanceOperation operation)
{
    if (g_stage != StorageMaintenanceStage::none) {
        return false;
    }
    g_stage = StorageMaintenanceStage::error_recovery_prompt;
    g_operation = operation;
    return true;
}

StorageMaintenanceErrorRecoveryActionResult storage_maintenance_handle_error_recovery_confirm(
    TimeoutWindow,
    TickType_t,
    bool start_available)
{
    if (g_stage == StorageMaintenanceStage::none) {
        if (!start_available) {
            return StorageMaintenanceErrorRecoveryActionResult::stale;
        }
        g_stage = StorageMaintenanceStage::error_recovery_confirm;
        g_operation = StorageMaintenanceOperation::wallet_erase;
        return StorageMaintenanceErrorRecoveryActionResult::confirmation_started;
    }
    if (g_stage == StorageMaintenanceStage::error_recovery_prompt) {
        if (g_operation != StorageMaintenanceOperation::wallet_erase) {
            return StorageMaintenanceErrorRecoveryActionResult::stale;
        }
        g_stage = StorageMaintenanceStage::error_recovery_confirm;
        g_operation = StorageMaintenanceOperation::wallet_erase;
        return StorageMaintenanceErrorRecoveryActionResult::confirmation_started;
    }
    if (g_stage != StorageMaintenanceStage::error_recovery_confirm ||
        g_operation != StorageMaintenanceOperation::wallet_erase) {
        return StorageMaintenanceErrorRecoveryActionResult::stale;
    }
    g_stage = StorageMaintenanceStage::committing;
    g_operation = StorageMaintenanceOperation::wallet_erase;
    return StorageMaintenanceErrorRecoveryActionResult::commit_started;
}

bool storage_maintenance_abort_pin_verification()
{
    if (g_stage != StorageMaintenanceStage::pin_verifying) {
        return false;
    }
    ++g_wipe_calls;
    g_stage = StorageMaintenanceStage::none;
    g_operation = StorageMaintenanceOperation::none;
    return true;
}

StorageMaintenanceUiMaintenanceResult storage_maintenance_handle_ui_maintenance(
    bool panel_active,
    TickType_t)
{
    if (g_stage == StorageMaintenanceStage::pin_verifying && !panel_active) {
        return StorageMaintenanceUiMaintenanceResult::redraw_pin_verification_panel;
    }
    if (g_stage == StorageMaintenanceStage::committing && !panel_active) {
        return StorageMaintenanceUiMaintenanceResult::redraw_committing_panel;
    }
    return StorageMaintenanceUiMaintenanceResult::unchanged;
}

bool storage_maintenance_add_pin_digit(char) { return g_stage == StorageMaintenanceStage::pin_entry; }
bool storage_maintenance_clear_pin() { return g_stage == StorageMaintenanceStage::pin_entry; }
bool storage_maintenance_backspace_pin() { return g_stage == StorageMaintenanceStage::pin_entry; }

StorageMaintenancePinSubmitResult storage_maintenance_submit_pin_for_verification(TickType_t, TickType_t)
{
    if (g_submit_result == StorageMaintenancePinSubmitResult::started_verification) {
        g_stage = StorageMaintenanceStage::pin_verifying;
    }
    return g_submit_result;
}

StorageMaintenancePinVerifyResult storage_maintenance_complete_pin_verify_job(
    const LocalAuthWorkerResult&,
    TickType_t,
    TickType_t)
{
    if (g_verify_result == StorageMaintenancePinVerifyResult::verified) {
        g_stage = StorageMaintenanceStage::committing;
        g_operation = StorageMaintenanceOperation::settings_reset;
    }
    return g_verify_result;
}

StorageMaintenanceCommitResult storage_maintenance_commit_material(const StorageMaintenancePersistenceOps&)
{
    ++g_commit_calls;
    g_commit_order = ++g_order_counter;
    return g_commit_result;
}

StorageMaintenanceCommitFinishResult storage_maintenance_finish_commit_if_ready(
    TickType_t,
    const StorageMaintenancePersistenceOps& ops)
{
    if (!g_commit_ready) {
        return StorageMaintenanceCommitFinishResult{
            StorageMaintenanceCommitFinishStatus::not_ready,
            StorageMaintenanceOperation::none,
            StorageMaintenanceCommitResult::missing_state,
        };
    }
    const StorageMaintenanceCommitResult result = storage_maintenance_commit_material(ops);
    ++g_wipe_calls;
    g_stage = StorageMaintenanceStage::none;
    const StorageMaintenanceOperation operation = g_operation;
    g_operation = StorageMaintenanceOperation::none;
    return StorageMaintenanceCommitFinishResult{
        StorageMaintenanceCommitFinishStatus::committed,
        operation,
        result,
    };
}

StorageMaintenanceCommitResult storage_maintenance_resume_pending_if_needed(
    const StorageMaintenancePersistenceOps&,
    bool*)
{
    return StorageMaintenanceCommitResult::ok;
}

}  // namespace signing

int main()
{
    reset_test_harness();
    g_settings_available = false;
    signing::storage_maintenance_ui_start_from_touch(ops());
    expect(g_clear_touch_calls == 1, "unavailable settings touch clears entry");
    expect(g_draw_settings_calls == 0, "unavailable settings does not draw menu");

    reset_test_harness();
    signing::storage_maintenance_ui_start_from_touch(ops());
    expect(g_stage == signing::StorageMaintenanceStage::settings_menu, "settings start enters menu");
    expect(g_draw_settings_calls == 1, "settings start draws menu");

    reset_test_harness();
    g_stage = signing::StorageMaintenanceStage::settings_menu;
    expect(signing::storage_maintenance_ui_begin_settings_pin_auth_handoff("stale", ops()),
           "settings PIN-auth handoff accepted from menu");
    expect(g_stage == signing::StorageMaintenanceStage::none, "settings handoff consumes settings menu state");

    reset_test_harness();
    g_stage = signing::StorageMaintenanceStage::settings_menu;
    expect(signing::storage_maintenance_ui_panel_matches_stage(
               signing::UiPanelKind::sui_settings),
           "Sui settings panel is owned by settings state");

    reset_test_harness();
    g_stage = signing::StorageMaintenanceStage::settings_menu;
    expect(signing::storage_maintenance_ui_panel_matches_stage(
               signing::UiPanelKind::chain_settings_menu),
           "chain settings menu panel is owned by settings state");

    reset_test_harness();
    g_stage = signing::StorageMaintenanceStage::pin_verifying;
    expect(signing::storage_maintenance_ui_panel_matches_stage(
               signing::UiPanelKind::action_pin_entry),
           "action PIN panel remains owned during PIN verification");

    reset_test_harness();
    g_stage = signing::StorageMaintenanceStage::committing;
    expect(signing::storage_maintenance_ui_panel_matches_stage(
               signing::UiPanelKind::action_pin_entry),
           "action PIN panel remains owned during action commit processing");
    expect(signing::storage_maintenance_ui_panel_matches_stage(
               signing::UiPanelKind::error_recovery),
           "error recovery panel remains owned during recovery commit processing");

    reset_test_harness();
    g_stage = signing::StorageMaintenanceStage::settings_menu;
    g_panel_active[static_cast<int>(signing::UiPanelKind::chain_settings_menu)] = true;
    signing::storage_maintenance_ui_close_settings_from_ui(ops());
    expect(g_clear_panel_calls == 1, "chain settings close clears active chain panel");
    expect(g_last_clear_panel_kind == signing::UiPanelKind::chain_settings_menu,
           "chain settings close targets chain panel");
    expect(g_wipe_calls == 1, "chain settings close wipes local settings owner");

    reset_test_harness();
    g_stage = signing::StorageMaintenanceStage::settings_menu;
    signing::storage_maintenance_ui_start_wallet_erase_pin_from_settings_menu(ops());
    expect(g_stage == signing::StorageMaintenanceStage::pin_entry,
           "device reset action enters PIN entry");
    expect(g_operation == signing::StorageMaintenanceOperation::wallet_erase,
           "device reset action preserves destructive operation through PIN entry");
    expect(g_draw_action_pin_calls == 1, "device reset action draws PIN panel");
    expect(g_last_action_notice != nullptr &&
               strcmp(g_last_action_notice, "Deletes wallet data.") == 0,
           "device reset action explains destructive material scope");

    reset_test_harness();
    g_stage = signing::StorageMaintenanceStage::pin_entry;
    g_submit_result = signing::StorageMaintenancePinSubmitResult::invalid_pin;
    signing::storage_maintenance_ui_handle_action_pin_submit(ops());
    expect(g_last_action_notice != nullptr &&
               strcmp(g_last_action_notice, "Enter exactly 6 digits.") == 0,
           "invalid action PIN redraws with validation notice");

    reset_test_harness();
    g_stage = signing::StorageMaintenanceStage::pin_entry;
    g_material_ready = false;
    g_settings_repair_available = false;
    signing::storage_maintenance_ui_handle_action_pin_submit(ops());
    expect(g_stage == signing::StorageMaintenanceStage::pin_verifying,
           "active storage action PIN submit does not re-run the start-availability gate");
    expect(g_show_message_calls == 0,
           "active storage action PIN submit does not fail before PIN verification");

    reset_test_harness();
    g_stage = signing::StorageMaintenanceStage::pin_verifying;
    g_material_ready = false;
    g_settings_repair_available = false;
    g_panel_active[static_cast<int>(signing::UiPanelKind::action_pin_entry)] = true;
    signing::storage_maintenance_ui_handle_auth_worker_result(
        signing::LocalAuthWorkerResult{
            1,
            signing::LocalAuthWorkerOwner::storage_maintenance,
            signing::LocalAuthWorkerOperation::verify_pin,
            signing::LocalAuthWorkerStatus::ok,
            true,
            {},
        },
        ops());
    expect(g_stage == signing::StorageMaintenanceStage::committing,
           "verified storage action PIN proceeds to commit even if settings availability is re-evaluated later");
    expect(g_show_message_calls == 0,
           "verified storage action PIN is not rejected before the persistence boundary");

    reset_test_harness();
    g_stage = signing::StorageMaintenanceStage::pin_entry;
    g_draw_action_pin = false;
    signing::storage_maintenance_ui_handle_action_pin_digit('1', ops());
    expect(g_wipe_calls == 1, "action PIN display failure clears storage maintenance state");
    expect(g_last_message != nullptr && strcmp(g_last_message, "Display error") == 0,
           "action PIN display failure shows display error");

    reset_test_harness();
    g_consistency_error_active = true;
    signing::storage_maintenance_ui_show_persistent_error_recovery_if_needed(ops());
    expect(g_draw_error_recovery_calls == 1, "persistent error draws recovery panel");
    expect(g_stage == signing::StorageMaintenanceStage::error_recovery_prompt,
           "persistent error panel records a recovery prompt state");
    expect(g_operation == signing::StorageMaintenanceOperation::wallet_erase,
           "persistent error panel records Device reset when repair is unavailable");
    expect(!g_last_error_recovery_confirm,
           "persistent error panel does not skip straight to destructive confirmation");

    reset_test_harness();
    g_commit_ready = true;
    g_stage = signing::StorageMaintenanceStage::committing;
    g_panel_active[static_cast<int>(signing::UiPanelKind::action_pin_entry)] = true;
    signing::storage_maintenance_ui_commit_if_ready(ops());
    expect(g_commit_calls == 1, "ready storage action commit calls persistence boundary");
    expect(g_last_message != nullptr && strcmp(g_last_message, "Settings repaired") == 0,
           "successful internal settings repair reports settings repaired");
    expect(g_commit_order < g_show_message_order,
           "storage action commit reports result only after persistence boundary");
    expect(g_show_message_order < g_clear_panel_order,
           "storage action commit keeps processing panel until result overlay is prepared");

    reset_test_harness();
    g_commit_ready = true;
    g_stage = signing::StorageMaintenanceStage::committing;
    g_operation = signing::StorageMaintenanceOperation::wallet_erase;
    g_panel_active[static_cast<int>(signing::UiPanelKind::action_pin_entry)] = true;
    signing::storage_maintenance_ui_commit_if_ready(ops());
    expect(g_commit_calls == 1, "ready device reset commit calls persistence boundary");
    expect(g_last_message != nullptr && strcmp(g_last_message, "Device reset") == 0,
           "successful device reset commit reports device reset");

    reset_test_harness();
    g_stage = signing::StorageMaintenanceStage::pin_entry;
    g_panel_active[static_cast<int>(signing::UiPanelKind::action_pin_entry)] = true;
    signing::storage_maintenance_ui_cancel_action_pin_from_ui("Storage action canceled", ops());
    expect(g_begin_settings_calls == 1, "storage action cancel returns to settings state");
    expect(g_draw_settings_calls == 1, "storage action cancel draws settings menu");
    expect(g_clear_panel_calls == 1, "storage action cancel clears old PIN panel");
    expect(g_draw_settings_order < g_clear_panel_order,
           "storage action cancel prepares settings menu before clearing PIN panel");

    reset_test_harness();
    g_stage = signing::StorageMaintenanceStage::error_recovery_prompt;
    g_operation = signing::StorageMaintenanceOperation::settings_reset;
    expect(signing::storage_maintenance_begin_error_recovery_settings_repair(
               signing::kTimeoutWindowNone),
           "repair cancel test enters repair PIN gate");
    g_panel_active[static_cast<int>(signing::UiPanelKind::action_pin_entry)] = true;
    signing::storage_maintenance_ui_cancel_action_pin_from_ui("Storage action canceled", ops());
    expect(g_stage == signing::StorageMaintenanceStage::error_recovery_prompt,
           "repair PIN cancel returns to error recovery prompt instead of settings");
    expect(g_begin_settings_calls == 0,
           "repair PIN cancel does not open settings");
    expect(g_draw_error_recovery_calls == 1,
           "repair PIN cancel redraws error recovery panel");
    expect(g_clear_panel_calls == 1,
           "repair PIN cancel clears old PIN panel");

    reset_test_harness();
    g_consistency_error_active = true;
    g_settings_repair_available = true;
    signing::storage_maintenance_ui_show_persistent_error_recovery_if_needed(ops());
    signing::storage_maintenance_ui_confirm_error_recovery_from_ui(ops());
    expect(g_stage == signing::StorageMaintenanceStage::pin_entry,
           "first repair click enters PIN gate");
    signing::storage_maintenance_ui_cancel_action_pin_from_ui("Storage action canceled", ops());
    expect(g_stage == signing::StorageMaintenanceStage::error_recovery_prompt,
           "repair cancel leaves a repair prompt state");
    g_settings_repair_available = false;
    signing::storage_maintenance_ui_confirm_error_recovery_from_ui(ops());
    expect(g_stage == signing::StorageMaintenanceStage::pin_entry,
           "second repair click uses stored repair operation instead of self-blocking into Device reset");
    expect(g_operation == signing::StorageMaintenanceOperation::settings_reset,
           "second repair click preserves root-preserving repair operation");
    expect(g_draw_action_pin_calls == 2,
           "second repair click draws PIN gate again");

    reset_test_harness();
    g_stage = signing::StorageMaintenanceStage::error_recovery_confirm;
    g_operation = signing::StorageMaintenanceOperation::wallet_erase;
    g_panel_active[static_cast<int>(signing::UiPanelKind::error_recovery)] = true;
    signing::storage_maintenance_ui_cancel_error_recovery_from_ui(ops());
    expect(g_show_message_calls == 1, "error recovery cancel shows result");
    expect(g_clear_panel_calls == 1, "error recovery cancel clears old panel");
    expect(g_show_message_order < g_clear_panel_order,
           "error recovery cancel prepares result before clearing old panel");

    reset_test_harness();
    g_consistency_error_active = true;
    g_settings_repair_available = true;
    signing::storage_maintenance_ui_show_persistent_error_recovery_if_needed(ops());
    g_settings_repair_available = false;
    signing::storage_maintenance_ui_confirm_error_recovery_from_ui(ops());
    expect(g_stage == signing::StorageMaintenanceStage::pin_entry,
           "settings repair button from auto-shown error panel uses stored repair state and enters PIN gate");
    expect(g_draw_action_pin_calls == 1,
           "settings repair button from auto-shown error panel draws PIN panel");
    expect(g_last_action_notice != nullptr &&
               strcmp(g_last_action_notice, "Keeps key. Resets settings.") == 0,
           "settings repair button from auto-shown error panel explains root-preserving repair action");

    reset_test_harness();
    g_consistency_error_active = true;
    g_settings_repair_available = true;
    g_pending_recovery_operation = signing::StorageMaintenanceOperation::wallet_erase;
    signing::storage_maintenance_ui_show_persistent_error_recovery_if_needed(ops());
    expect(g_operation == signing::StorageMaintenanceOperation::wallet_erase,
           "pending Device reset operation overrides live repair availability");
    signing::storage_maintenance_ui_confirm_error_recovery_from_ui(ops());
    expect(g_stage == signing::StorageMaintenanceStage::error_recovery_confirm,
           "pending Device reset recovery opens destructive confirmation");
    expect(g_last_error_recovery_confirm,
           "pending Device reset recovery shows explicit confirmation");

    reset_test_harness();
    g_consistency_error_active = true;
    g_settings_repair_available = false;
    g_panel_active[static_cast<int>(signing::UiPanelKind::error_recovery)] = true;
    signing::storage_maintenance_ui_confirm_error_recovery_from_ui(ops());
    expect(g_stage == signing::StorageMaintenanceStage::none,
           "stale error recovery panel action does not create Device reset state");
    expect(g_draw_error_recovery_calls == 0,
           "stale error recovery panel action does not redraw destructive confirmation");
    expect(g_clear_panel_calls == 1,
           "stale error recovery panel action clears stale panel");
    expect(g_last_clear_panel_kind == signing::UiPanelKind::error_recovery,
           "stale error recovery panel action clears error recovery panel");

    reset_test_harness();
    g_consistency_error_active = true;
    g_settings_repair_available = true;
    signing::storage_maintenance_ui_start_error_recovery_from_ui(ops());
    expect(g_stage == signing::StorageMaintenanceStage::error_recovery_prompt,
           "settings repair recovery starts from error recovery prompt");
    signing::storage_maintenance_ui_confirm_error_recovery_from_ui(ops());
    expect(g_stage == signing::StorageMaintenanceStage::pin_entry,
           "settings repair confirmation enters PIN gate instead of device reset");
    expect(g_draw_action_pin_calls == 1,
           "settings repair draws PIN panel");
    expect(g_last_action_notice != nullptr &&
               strcmp(g_last_action_notice, "Keeps key. Resets settings.") == 0,
           "settings repair PIN panel explains root-preserving repair action");

    reset_test_harness();
    g_consistency_error_active = true;
    g_settings_repair_available = false;
    signing::storage_maintenance_ui_show_persistent_error_recovery_if_needed(ops());
    signing::storage_maintenance_ui_confirm_error_recovery_from_ui(ops());
    expect(g_stage == signing::StorageMaintenanceStage::error_recovery_confirm,
           "first Device reset click from auto-shown panel opens destructive confirmation");
    expect(g_draw_error_recovery_calls == 2,
           "first Device reset click redraws confirmation instead of committing");
    expect(g_last_error_recovery_confirm,
           "Device reset confirmation panel is explicit");
    signing::storage_maintenance_ui_confirm_error_recovery_from_ui(ops());
    expect(g_stage == signing::StorageMaintenanceStage::committing,
           "second Device reset click starts destructive commit");

    reset_test_harness();
    g_consistency_error_active = true;
    g_error_recovery_available = false;
    signing::storage_maintenance_ui_confirm_error_recovery_from_ui(ops());
    expect(g_stage == signing::StorageMaintenanceStage::none,
           "idle error recovery confirm respects recovery availability");
    expect(g_draw_error_recovery_calls == 0,
           "unavailable idle error recovery confirm does not draw confirmation");

    if (failures != 0) {
        return 1;
    }
    printf("storage maintenance UI flow tests passed\n");
    return 0;
}
CPP

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${TMP_DIR}" \
  -I"${ARDUINOJSON_ROOT}" \
  -I"${COMMON_ROOT}" \
  -I"${RUNTIME_DIR}" -I"${TMP_DIR}/firmware_common" \
  "${TMP_DIR}/test.cpp" \
  "${RUNTIME_DIR}/modal_transition.cpp" \
  "${RUNTIME_DIR}/storage_maintenance_ui_flow.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
