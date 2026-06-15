#include "agent_q_local_settings_reset_ui_flow.h"

#include "agent_q_local_settings_touch_entry.h"
#include "agent_q_modal_transition.h"
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

AgentQModalTransitionOps modal_transition_ops(const AgentQLocalSettingsResetUiFlowOps& ops)
{
    return AgentQModalTransitionOps{
        ops.clear_panel_if_kind,
        ops.draw_processing_overlay_on_current_panel,
        ops.log_warn,
    };
}

struct ErrorRecoveryPanelDrawContext {
    const AgentQLocalSettingsResetUiFlowOps* ops = nullptr;
    bool confirm = false;
};

struct ResetPinPanelDrawContext {
    const AgentQLocalSettingsResetUiFlowOps* ops = nullptr;
    const char* notice = nullptr;
};

struct SettingsPanelDrawContext {
    const AgentQLocalSettingsResetUiFlowOps* ops = nullptr;
};

struct ResetCommitResultContext {
    const AgentQLocalSettingsResetUiFlowOps* ops = nullptr;
    const char* message = nullptr;
    AgentQMessageKind kind = AgentQMessageKind::info;
};

bool draw_error_recovery_panel_for_transition(void* context)
{
    const auto* draw_context = static_cast<const ErrorRecoveryPanelDrawContext*>(context);
    return draw_context != nullptr &&
           draw_context->ops != nullptr &&
           draw_error_recovery_panel(*draw_context->ops, draw_context->confirm);
}

bool draw_reset_pin_panel_for_transition(void* context)
{
    const auto* draw_context = static_cast<const ResetPinPanelDrawContext*>(context);
    return draw_context != nullptr &&
           draw_context->ops != nullptr &&
           draw_reset_pin_panel(*draw_context->ops, draw_context->notice);
}

bool draw_settings_menu_panel_for_transition(void* context)
{
    const auto* draw_context = static_cast<const SettingsPanelDrawContext*>(context);
    return draw_context != nullptr &&
           draw_context->ops != nullptr &&
           draw_settings_menu_panel(*draw_context->ops);
}

void show_reset_commit_result_for_transition(void* context)
{
    const auto* result_context = static_cast<const ResetCommitResultContext*>(context);
    if (result_context == nullptr || result_context->ops == nullptr) {
        return;
    }
    show_result(
        *result_context->ops,
        result_context->message,
        result_context->kind);
}

AgentQUiPanelKind panel_kind_for_reset_stage(ResetStage stage)
{
    switch (stage) {
        case ResetStage::settings_menu:
            return AgentQUiPanelKind::settings_menu;
        case ResetStage::pin_entry:
        case ResetStage::pin_verifying:
        case ResetStage::wiping:
            return AgentQUiPanelKind::reset_pin_entry;
        case ResetStage::error_recovery_confirm:
            return AgentQUiPanelKind::error_recovery;
        case ResetStage::none:
        default:
            return AgentQUiPanelKind::none;
    }
}

void complete_panel_to_result(
    const AgentQLocalSettingsResetUiFlowOps& ops,
    AgentQUiPanelKind panel,
    const char* message,
    AgentQMessageKind kind)
{
    ResetCommitResultContext context{&ops, message, kind};
    if (panel == AgentQUiPanelKind::none) {
        show_reset_commit_result_for_transition(&context);
        return;
    }
    modal_transition_complete_to_result(
        modal_transition_ops(ops),
        panel,
        show_reset_commit_result_for_transition,
        &context);
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
            complete_panel_to_result(
                ops,
                AgentQUiPanelKind::reset_pin_entry,
                "Auth error",
                AgentQMessageKind::error);
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

    if (!active) {
        wipe_local_reset_scratch(ops, "local reset panel lost");
    }

    if (expired) {
        const char* timeout_message = "Reset canceled";
        if (reset.stage == ResetStage::settings_menu) {
            timeout_message = "Settings timed out";
        } else if (reset.stage == ResetStage::error_recovery_confirm) {
            timeout_message = "Erase canceled";
        }
        complete_panel_to_result(
            ops,
            active ? panel_kind_for_reset_stage(reset.stage) : AgentQUiPanelKind::none,
            timeout_message,
            AgentQMessageKind::timeout);
    }
}

void local_settings_reset_ui_commit_if_ready(const AgentQLocalSettingsResetUiFlowOps& ops)
{
    if (!local_reset_wipe_ready(now_or_zero(ops))) {
        return;
    }

    const AgentQUiPanelKind processing_panel =
        panel_active(ops, AgentQUiPanelKind::reset_pin_entry)
            ? AgentQUiPanelKind::reset_pin_entry
            : (panel_active(ops, AgentQUiPanelKind::error_recovery)
                ? AgentQUiPanelKind::error_recovery
                : AgentQUiPanelKind::none);
    const ResetCommitResult result = local_reset_commit_material(ops.persistence_ops);
    wipe_local_reset_scratch(ops, "local reset completed");
    const char* display_message = "Reset error";
    AgentQMessageKind display_kind = AgentQMessageKind::error;
    switch (result) {
        case ResetCommitResult::ok:
            log_warn(ops, "Local reset completed; device returned to unprovisioned");
            display_message = "Device reset";
            display_kind = AgentQMessageKind::success;
            break;
        case ResetCommitResult::missing_state:
            log_warn(ops, "Local reset commit missing state");
            display_message = "Reset unavailable";
            break;
        case ResetCommitResult::reset_marker_storage_error:
            log_warn(ops, "Local reset aborted before wiping material because the reset marker could not be stored");
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
            break;
    }
    ResetCommitResultContext context{&ops, display_message, display_kind};
    if (processing_panel == AgentQUiPanelKind::none) {
        show_reset_commit_result_for_transition(&context);
        return;
    }
    modal_transition_complete_processing_to_result(
        modal_transition_ops(ops),
        processing_panel,
        show_reset_commit_result_for_transition,
        &context);
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

    local_reset_begin_settings(window_from_now_ms(ops, ops.local_reset_entry_ms));
    SettingsPanelDrawContext draw_context{&ops};
    if (!modal_transition_complete_to_next_panel(
            modal_transition_ops(ops),
            AgentQUiPanelKind::reset_pin_entry,
            draw_settings_menu_panel_for_transition,
            &draw_context)) {
        wipe_local_reset_scratch(
            ops,
            "local settings display allocation failed after reset cancel");
        complete_panel_to_result(
            ops,
            AgentQUiPanelKind::reset_pin_entry,
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

    wipe_local_reset_scratch(ops, "error recovery canceled");
    complete_panel_to_result(
        ops,
        AgentQUiPanelKind::error_recovery,
        "Erase canceled",
        AgentQMessageKind::info);
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

    ErrorRecoveryPanelDrawContext draw_context{&ops, true};
    if (!modal_transition_show_processing_or_redraw_panel(
            modal_transition_ops(ops),
            AgentQUiPanelKind::error_recovery,
            draw_error_recovery_panel_for_transition,
            &draw_context)) {
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
        complete_panel_to_result(
            ops,
            AgentQUiPanelKind::reset_pin_entry,
            "Reset unavailable",
            AgentQMessageKind::error);
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

    ResetPinPanelDrawContext draw_context{&ops, nullptr};
    if (!modal_transition_show_processing_or_redraw_panel(
            modal_transition_ops(ops),
            AgentQUiPanelKind::reset_pin_entry,
            draw_reset_pin_panel_for_transition,
            &draw_context)) {
        wipe_local_reset_scratch(
            ops,
            "local reset PIN verification display allocation failed");
        complete_panel_to_result(
            ops,
            AgentQUiPanelKind::reset_pin_entry,
            "Display error",
            AgentQMessageKind::error);
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
        complete_panel_to_result(
            ops,
            AgentQUiPanelKind::reset_pin_entry,
            "Reset unavailable",
            AgentQMessageKind::error);
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
            complete_panel_to_result(
                ops,
                AgentQUiPanelKind::reset_pin_entry,
                "Auth error",
                AgentQMessageKind::error);
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
