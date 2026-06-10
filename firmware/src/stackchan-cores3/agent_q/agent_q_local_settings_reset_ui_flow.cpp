#include "agent_q_local_settings_reset_ui_flow.h"

#include "agent_q_local_settings_touch_entry.h"
#include "agent_q_timeout_window.h"
#include "freertos/task.h"

namespace agent_q {
namespace {

using ResetStage = AgentQLocalResetStage;
using ResetCommitResult = AgentQLocalResetCommitResult;
using ResetSubmitResult = AgentQLocalResetPinSubmitResult;
using ResetVerifyResult = AgentQLocalResetPinVerifyResult;
using ResetLockoutReleaseResult = AgentQLocalResetLockoutReleaseResult;

TickType_t now_or_zero(const AgentQLocalSettingsResetUiFlowOps& ops)
{
    return ops.now != nullptr ? ops.now() : 0;
}

AgentQTimeoutWindow window_from_now_ms(
    const AgentQLocalSettingsResetUiFlowOps& ops,
    uint32_t duration_ms)
{
    const TickType_t now = now_or_zero(ops);
    return timeout_window_from_deadline(now, now + pdMS_TO_TICKS(duration_ms));
}

void log_warn(const AgentQLocalSettingsResetUiFlowOps& ops, const char* message)
{
    if (ops.log_warn != nullptr) {
        ops.log_warn(message);
    }
}

void log_error(const AgentQLocalSettingsResetUiFlowOps& ops, const char* message)
{
    if (ops.log_error != nullptr) {
        ops.log_error(message);
    }
}

void show_result(
    const AgentQLocalSettingsResetUiFlowOps& ops,
    const char* message,
    AgentQMessageKind kind)
{
    if (ops.show_message != nullptr) {
        ops.show_message(message, kind);
    }
}

bool material_ready(const AgentQLocalSettingsResetUiFlowOps& ops)
{
    return ops.material_ready != nullptr && ops.material_ready();
}

void clear_settings_touch_entry(const AgentQLocalSettingsResetUiFlowOps& ops)
{
    if (ops.clear_settings_touch_entry != nullptr) {
        ops.clear_settings_touch_entry();
    }
}

void wipe_local_reset_scratch(
    const AgentQLocalSettingsResetUiFlowOps& ops,
    const char* reason)
{
    const bool had_reset_scratch =
        local_reset_snapshot(now_or_zero(ops)).flow_active;
    local_reset_wipe();
    clear_settings_touch_entry(ops);
    if (had_reset_scratch) {
        log_warn(ops, reason != nullptr ? reason : "local reset scratch wiped");
    }
}

bool clear_panel_if_kind(
    const AgentQLocalSettingsResetUiFlowOps& ops,
    AgentQUiPanelKind kind,
    SensitiveUiClearPolicy policy = SensitiveUiClearPolicy::wipe)
{
    return ops.clear_panel_if_kind != nullptr &&
           ops.clear_panel_if_kind(kind, policy);
}

bool clear_panel_if_local_reset_stage(
    const AgentQLocalSettingsResetUiFlowOps& ops,
    SensitiveUiClearPolicy policy = SensitiveUiClearPolicy::wipe)
{
    return ops.clear_panel_if_local_reset_stage != nullptr &&
           ops.clear_panel_if_local_reset_stage(policy);
}

bool panel_active(
    const AgentQLocalSettingsResetUiFlowOps& ops,
    AgentQUiPanelKind kind)
{
    return ops.panel_active != nullptr && ops.panel_active(kind);
}

bool display_ready(const AgentQLocalSettingsResetUiFlowOps& ops)
{
    return ops.display_ready == nullptr || ops.display_ready();
}

bool local_reset_panel_active(const AgentQLocalSettingsResetUiFlowOps& ops)
{
    return ops.local_reset_panel_active != nullptr &&
           ops.local_reset_panel_active();
}

bool draw_settings_menu_panel(const AgentQLocalSettingsResetUiFlowOps& ops)
{
    return ops.draw_settings_menu_panel != nullptr &&
           ops.draw_settings_menu_panel();
}

bool draw_error_recovery_panel(
    const AgentQLocalSettingsResetUiFlowOps& ops,
    bool confirm)
{
    return ops.draw_error_recovery_panel != nullptr &&
           ops.draw_error_recovery_panel(confirm);
}

bool draw_reset_pin_panel(
    const AgentQLocalSettingsResetUiFlowOps& ops,
    const char* notice = nullptr)
{
    return ops.draw_reset_pin_panel != nullptr &&
           ops.draw_reset_pin_panel(notice);
}

bool draw_processing_overlay_on_current_panel(
    const AgentQLocalSettingsResetUiFlowOps& ops,
    AgentQUiPanelKind kind)
{
    return ops.draw_processing_overlay_on_current_panel != nullptr &&
           ops.draw_processing_overlay_on_current_panel(kind);
}

void record_material_failure(
    const AgentQLocalSettingsResetUiFlowOps& ops,
    AgentQPersistentMaterialRuntimeFailure failure)
{
    if (ops.record_material_failure != nullptr) {
        ops.record_material_failure(failure);
    }
}

void draw_reset_pin_error_or_wipe(
    const AgentQLocalSettingsResetUiFlowOps& ops,
    const char* notice,
    const char* wipe_reason)
{
    if (draw_reset_pin_panel(ops, notice)) {
        return;
    }
    wipe_local_reset_scratch(ops, wipe_reason);
    show_result(ops, "Display error", AgentQMessageKind::error);
}

}  // namespace

bool local_settings_reset_ui_panel_matches_stage(AgentQUiPanelKind kind)
{
    const ResetStage stage = local_reset_snapshot(xTaskGetTickCount()).stage;
    return (kind == AgentQUiPanelKind::settings_menu &&
            stage == ResetStage::settings_menu) ||
           (kind == AgentQUiPanelKind::reset_pin_entry &&
            stage == ResetStage::pin_entry) ||
           (kind == AgentQUiPanelKind::error_recovery &&
            stage == ResetStage::error_recovery_confirm);
}

bool local_settings_reset_ui_accepts_reset_pin_input()
{
    return local_reset_snapshot(xTaskGetTickCount()).stage == ResetStage::pin_entry;
}

void local_settings_reset_ui_clear_if_needed(const AgentQLocalSettingsResetUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const AgentQLocalResetSnapshot reset = local_reset_snapshot(now);
    if (reset.stage == ResetStage::none) {
        return;
    }
    if (reset.stage == ResetStage::pin_verifying) {
        if (local_reset_fail_processing_if_expired(now)) {
            record_material_failure(
                ops,
                AgentQPersistentMaterialRuntimeFailure::local_reset_auth_unavailable);
            clear_panel_if_kind(
                ops,
                AgentQUiPanelKind::reset_pin_entry,
                SensitiveUiClearPolicy::preserve);
            show_result(ops, "Auth error", AgentQMessageKind::error);
            return;
        }
        if (!panel_active(ops, AgentQUiPanelKind::reset_pin_entry) &&
            !draw_reset_pin_panel(ops)) {
            wipe_local_reset_scratch(ops, "local reset PIN verification UI recovery failed");
            show_result(ops, "Display error", AgentQMessageKind::error);
        }
        return;
    }
    if (reset.stage == ResetStage::wiping) {
        if (!panel_active(ops, AgentQUiPanelKind::reset_pin_entry) &&
            !draw_reset_pin_panel(ops)) {
            log_warn(ops, "Local reset wiping panel could not be restored");
        }
        return;
    }

    const ResetLockoutReleaseResult lockout_release =
        local_reset_release_lockout_if_elapsed(now);
    if (lockout_release == ResetLockoutReleaseResult::failed) {
        wipe_local_reset_scratch(ops, "local reset PIN lockout release failed");
        show_result(ops, "Display error", AgentQMessageKind::error);
        return;
    }
    if (lockout_release == ResetLockoutReleaseResult::released) {
        draw_reset_pin_error_or_wipe(
            ops,
            "Try again.",
            "local reset PIN panel allocation failed");
        return;
    }

    const bool active = local_reset_panel_active(ops);
    const bool expired = local_reset_deadline_expired(now);
    if (active && !expired) {
        return;
    }

    if (active) {
        clear_panel_if_local_reset_stage(ops);
    } else {
        wipe_local_reset_scratch(ops, "local reset panel lost");
    }

    if (expired) {
        const char* timeout_message = "Reset canceled";
        if (reset.stage == ResetStage::settings_menu) {
            timeout_message = "Settings timed out";
        } else if (reset.stage == ResetStage::error_recovery_confirm) {
            timeout_message = "Erase canceled";
        }
        show_result(ops, timeout_message, AgentQMessageKind::timeout);
    }
}

void local_settings_reset_ui_commit_if_ready(const AgentQLocalSettingsResetUiFlowOps& ops)
{
    if (!local_reset_wipe_ready(now_or_zero(ops))) {
        return;
    }

    const ResetCommitResult result = local_reset_commit_material(ops.persistence_ops);
    clear_panel_if_kind(
        ops,
        AgentQUiPanelKind::reset_pin_entry,
        SensitiveUiClearPolicy::preserve);
    clear_panel_if_kind(
        ops,
        AgentQUiPanelKind::error_recovery,
        SensitiveUiClearPolicy::preserve);
    wipe_local_reset_scratch(ops, "local reset completed");
    switch (result) {
        case ResetCommitResult::ok:
            log_warn(ops, "Local reset completed; device returned to unprovisioned");
            show_result(ops, "Device reset", AgentQMessageKind::success);
            break;
        case ResetCommitResult::missing_state:
            log_warn(ops, "Local reset commit missing state");
            show_result(ops, "Reset unavailable", AgentQMessageKind::error);
            break;
        case ResetCommitResult::reset_marker_storage_error:
            log_warn(ops, "Local reset aborted before wiping material because the reset marker could not be stored");
            show_result(ops, "Reset error", AgentQMessageKind::error);
            break;
        case ResetCommitResult::root_wipe_error:
        case ResetCommitResult::policy_wipe_error:
        case ResetCommitResult::local_auth_wipe_error:
        case ResetCommitResult::human_approval_setting_wipe_error:
        case ResetCommitResult::signing_mode_wipe_error:
        case ResetCommitResult::approval_history_wipe_error:
        case ResetCommitResult::policy_update_marker_wipe_error:
        case ResetCommitResult::material_remaining_error:
        case ResetCommitResult::state_storage_error:
            log_error(ops, "Local reset failed and device entered consistency error");
            show_result(ops, "Reset error", AgentQMessageKind::error);
            break;
    }
}

void local_settings_reset_ui_start_from_touch(const AgentQLocalSettingsResetUiFlowOps& ops)
{
    if (ops.settings_start_available == nullptr || !ops.settings_start_available()) {
        log_warn(ops, "Local settings touch ignored because settings are unavailable");
        clear_settings_touch_entry(ops);
        return;
    }

    local_reset_begin_settings(window_from_now_ms(ops, ops.local_reset_entry_ms));
    if (!draw_settings_menu_panel(ops)) {
        wipe_local_reset_scratch(ops, "local settings display allocation failed");
        show_result(ops, "Display error", AgentQMessageKind::error);
    }
}

void local_settings_reset_ui_cancel_reset_from_ui(
    const char* message,
    const AgentQLocalSettingsResetUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    if (local_reset_snapshot(now).stage != ResetStage::pin_entry) {
        log_warn(ops, "Stale local reset cancel ignored");
        return;
    }

    clear_panel_if_kind(ops, AgentQUiPanelKind::reset_pin_entry);
    local_reset_begin_settings(window_from_now_ms(ops, ops.local_reset_entry_ms));
    if (!draw_settings_menu_panel(ops)) {
        wipe_local_reset_scratch(
            ops,
            "local settings display allocation failed after reset cancel");
        show_result(
            ops,
            message != nullptr && message[0] != '\0' ? message : "Reset canceled",
            AgentQMessageKind::error);
    }
}

void local_settings_reset_ui_close_settings_from_ui(
    const AgentQLocalSettingsResetUiFlowOps& ops)
{
    if (local_reset_snapshot(now_or_zero(ops)).stage != ResetStage::settings_menu) {
        log_warn(ops, "Stale local settings close ignored");
        return;
    }

    clear_panel_if_kind(ops, AgentQUiPanelKind::settings_menu);
    wipe_local_reset_scratch(ops, "local settings closed");
}

void local_settings_reset_ui_show_persistent_error_recovery_if_needed(
    const AgentQLocalSettingsResetUiFlowOps& ops)
{
    if (ops.persistent_consistency_error_active == nullptr ||
        !ops.persistent_consistency_error_active() ||
        ops.error_recovery_available == nullptr ||
        !ops.error_recovery_available() ||
        !display_ready(ops)) {
        return;
    }

    if (panel_active(ops, AgentQUiPanelKind::error_recovery)) {
        return;
    }

    if (!draw_error_recovery_panel(ops, false)) {
        log_warn(ops, "Persistent error recovery panel could not be shown");
    }
}

void local_settings_reset_ui_start_error_recovery_from_ui(
    const AgentQLocalSettingsResetUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const AgentQLocalResetSnapshot reset = local_reset_snapshot(now);
    if (ops.persistent_consistency_error_active == nullptr ||
        !ops.persistent_consistency_error_active() ||
        reset.flow_active ||
        ops.error_recovery_available == nullptr ||
        !ops.error_recovery_available()) {
        log_warn(ops, "Stale error recovery action ignored");
        return;
    }

    local_reset_begin_error_recovery_confirm(
        window_from_now_ms(ops, ops.local_reset_entry_ms));
    if (!draw_error_recovery_panel(ops, true)) {
        wipe_local_reset_scratch(
            ops,
            "error recovery confirmation display allocation failed");
        show_result(ops, "Display error", AgentQMessageKind::error);
    }
}

void local_settings_reset_ui_cancel_error_recovery_from_ui(
    const AgentQLocalSettingsResetUiFlowOps& ops)
{
    if (local_reset_snapshot(now_or_zero(ops)).stage !=
        ResetStage::error_recovery_confirm) {
        log_warn(ops, "Stale error recovery cancel ignored");
        return;
    }

    clear_panel_if_kind(ops, AgentQUiPanelKind::error_recovery);
    wipe_local_reset_scratch(ops, "error recovery canceled");
    show_result(ops, "Erase canceled", AgentQMessageKind::info);
}

void local_settings_reset_ui_confirm_error_recovery_from_ui(
    const AgentQLocalSettingsResetUiFlowOps& ops)
{
    const AgentQLocalResetSnapshot reset = local_reset_snapshot(now_or_zero(ops));
    if (reset.stage == ResetStage::none) {
        local_settings_reset_ui_start_error_recovery_from_ui(ops);
        return;
    }
    if (reset.stage != ResetStage::error_recovery_confirm ||
        ops.persistent_consistency_error_active == nullptr ||
        !ops.persistent_consistency_error_active()) {
        log_warn(ops, "Stale error recovery erase ignored");
        return;
    }

    if (!local_reset_begin_error_recovery_wipe(
            now_or_zero(ops) + pdMS_TO_TICKS(ops.local_processing_display_ms))) {
        log_warn(ops, "Error recovery erase could not enter wiping state");
        return;
    }

    if (!draw_processing_overlay_on_current_panel(ops, AgentQUiPanelKind::error_recovery) &&
        !draw_error_recovery_panel(ops, true)) {
        wipe_local_reset_scratch(
            ops,
            "error recovery wiping display allocation failed");
        show_result(ops, "Display error", AgentQMessageKind::error);
    }
}

void local_settings_reset_ui_start_reset_pin_from_settings_menu(
    const AgentQLocalSettingsResetUiFlowOps& ops)
{
    if (!material_ready(ops) ||
        !local_reset_begin_pin_entry(
            window_from_now_ms(ops, ops.local_reset_entry_ms))) {
        log_warn(ops, "Stale local reset menu action ignored");
        return;
    }

    if (!draw_reset_pin_panel(ops)) {
        wipe_local_reset_scratch(ops, "local reset PIN display allocation failed");
        show_result(ops, "Display error", AgentQMessageKind::error);
    }
}

bool local_settings_reset_ui_begin_settings_pin_auth_handoff(
    const char* stale_log_message,
    const AgentQLocalSettingsResetUiFlowOps& ops)
{
    const AgentQLocalResetSnapshot reset = local_reset_snapshot(now_or_zero(ops));
    if (!material_ready(ops) || reset.stage != ResetStage::settings_menu) {
        log_warn(
            ops,
            stale_log_message != nullptr && stale_log_message[0] != '\0'
                ? stale_log_message
                : "Stale local settings action ignored");
        return false;
    }
    local_reset_wipe();
    return true;
}

void local_settings_reset_ui_restore_settings_menu(
    const char* display_failure_wipe_reason,
    const char* display_failure_message,
    AgentQMessageKind display_failure_kind,
    const AgentQLocalSettingsResetUiFlowOps& ops)
{
    local_reset_begin_settings(window_from_now_ms(ops, ops.local_reset_entry_ms));
    if (draw_settings_menu_panel(ops)) {
        return;
    }
    wipe_local_reset_scratch(
        ops,
        display_failure_wipe_reason != nullptr && display_failure_wipe_reason[0] != '\0'
            ? display_failure_wipe_reason
            : "local settings display allocation failed");
    show_result(
        ops,
        display_failure_message != nullptr && display_failure_message[0] != '\0'
            ? display_failure_message
            : "Display error",
        display_failure_kind);
}

void local_settings_reset_ui_handle_reset_pin_digit(
    char digit,
    const AgentQLocalSettingsResetUiFlowOps& ops)
{
    if (!local_reset_add_pin_digit(digit)) {
        return;
    }
    draw_reset_pin_error_or_wipe(
        ops,
        nullptr,
        "local reset PIN display allocation failed");
}

void local_settings_reset_ui_handle_reset_pin_clear(
    const AgentQLocalSettingsResetUiFlowOps& ops)
{
    if (!local_reset_clear_pin()) {
        return;
    }
    draw_reset_pin_error_or_wipe(
        ops,
        nullptr,
        "local reset PIN display allocation failed");
}

void local_settings_reset_ui_handle_reset_pin_backspace(
    const AgentQLocalSettingsResetUiFlowOps& ops)
{
    if (!local_reset_backspace_pin()) {
        return;
    }
    draw_reset_pin_error_or_wipe(
        ops,
        nullptr,
        "local reset PIN display allocation failed");
}

void local_settings_reset_ui_handle_reset_pin_submit(
    const AgentQLocalSettingsResetUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    if (!material_ready(ops)) {
        wipe_local_reset_scratch(ops, "local reset material state unavailable");
        clear_panel_if_kind(
            ops,
            AgentQUiPanelKind::reset_pin_entry,
            SensitiveUiClearPolicy::preserve);
        show_result(ops, "Reset unavailable", AgentQMessageKind::error);
        return;
    }

    const ResetSubmitResult submit_result =
        local_reset_submit_pin_for_verification(
            now + pdMS_TO_TICKS(ops.local_processing_render_delay_ms),
            now + pdMS_TO_TICKS(ops.local_auth_worker_max_ms));
    if (submit_result == ResetSubmitResult::unavailable_stage) {
        log_warn(ops, "Stale local reset PIN submit ignored");
        return;
    }
    if (submit_result == ResetSubmitResult::locked) {
        return;
    }
    if (submit_result == ResetSubmitResult::worker_unavailable) {
        draw_reset_pin_error_or_wipe(
            ops,
            "Auth worker busy. Try again.",
            "local reset PIN worker unavailable display allocation failed");
        return;
    }
    if (submit_result == ResetSubmitResult::invalid_pin) {
        draw_reset_pin_error_or_wipe(
            ops,
            "Enter exactly 6 digits.",
            "local reset PIN display allocation failed");
        return;
    }

    if (!draw_processing_overlay_on_current_panel(ops, AgentQUiPanelKind::reset_pin_entry) &&
        !draw_reset_pin_panel(ops)) {
        wipe_local_reset_scratch(
            ops,
            "local reset PIN verification display allocation failed");
        clear_panel_if_kind(
            ops,
            AgentQUiPanelKind::reset_pin_entry,
            SensitiveUiClearPolicy::preserve);
        show_result(ops, "Display error", AgentQMessageKind::error);
    }
}

void local_settings_reset_ui_handle_auth_worker_result(
    const AgentQLocalAuthWorkerResult& worker_result,
    const AgentQLocalSettingsResetUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    if (!material_ready(ops)) {
        const AgentQLocalResetSnapshot reset = local_reset_snapshot(now);
        if (reset.stage != ResetStage::pin_verifying) {
            return;
        }
        wipe_local_reset_scratch(
            ops,
            "local reset material state unavailable during PIN verification");
        clear_panel_if_kind(
            ops,
            AgentQUiPanelKind::reset_pin_entry,
            SensitiveUiClearPolicy::preserve);
        show_result(ops, "Reset unavailable", AgentQMessageKind::error);
        return;
    }

    const ResetVerifyResult verify_result =
        local_reset_complete_pin_verify_job(
            worker_result,
            now + pdMS_TO_TICKS(kAgentQLocalResetPinLockoutMs),
            now + pdMS_TO_TICKS(ops.local_processing_display_ms));
    switch (verify_result) {
        case ResetVerifyResult::not_ready:
            return;
        case ResetVerifyResult::auth_unavailable:
            record_material_failure(
                ops,
                AgentQPersistentMaterialRuntimeFailure::local_reset_auth_unavailable);
            wipe_local_reset_scratch(ops, "local reset PIN verifier unavailable");
            clear_panel_if_kind(
                ops,
                AgentQUiPanelKind::reset_pin_entry,
                SensitiveUiClearPolicy::preserve);
            show_result(ops, "Auth error", AgentQMessageKind::error);
            return;
        case ResetVerifyResult::locked:
            draw_reset_pin_error_or_wipe(
                ops,
                "Too many wrong PINs. Wait 30s.",
                "local reset PIN lockout display allocation failed");
            return;
        case ResetVerifyResult::wrong_pin:
            draw_reset_pin_error_or_wipe(
                ops,
                "Wrong PIN.",
                "local reset PIN display allocation failed");
            return;
        case ResetVerifyResult::verified:
            break;
    }

    if (!panel_active(ops, AgentQUiPanelKind::reset_pin_entry) &&
        !draw_reset_pin_panel(ops)) {
        log_warn(ops, "Local reset wiping panel could not be shown");
        local_settings_reset_ui_commit_if_ready(ops);
    }
}

}  // namespace agent_q
