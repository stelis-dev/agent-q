#include "local_settings_reset_ui_flow.h"

#include "local_settings_touch_entry.h"
#include "modal_transition.h"
#include "timeout_window.h"
#include "freertos/task.h"

namespace signing {
namespace {

using ResetStage = LocalResetStage;
using ResetCommitResult = LocalResetCommitResult;
using ResetCommitFinishStatus = LocalResetCommitFinishStatus;
using ResetSubmitResult = LocalResetPinSubmitResult;
using ResetVerifyResult = LocalResetPinVerifyResult;
using ResetMaintenanceResult = LocalResetUiMaintenanceResult;
using ResetReturnToSettingsResult = LocalResetReturnToSettingsResult;
using ResetErrorRecoveryActionResult = LocalResetErrorRecoveryActionResult;

TickType_t now_or_zero(const LocalSettingsResetUiFlowOps& ops)
{
    return ops.now != nullptr ? ops.now() : 0;
}

TimeoutWindow window_from_now_ms(
    const LocalSettingsResetUiFlowOps& ops,
    uint32_t duration_ms)
{
    const TickType_t now = now_or_zero(ops);
    return timeout_window_from_deadline(now, now + pdMS_TO_TICKS(duration_ms));
}

void log_warn(const LocalSettingsResetUiFlowOps& ops, const char* message)
{
    if (ops.log_warn != nullptr) {
        ops.log_warn(message);
    }
}

void log_error(const LocalSettingsResetUiFlowOps& ops, const char* message)
{
    if (ops.log_error != nullptr) {
        ops.log_error(message);
    }
}

void show_result(
    const LocalSettingsResetUiFlowOps& ops,
    const char* message,
    MessageKind kind)
{
    if (ops.show_message != nullptr) {
        ops.show_message(message, kind);
    }
}

bool material_ready(const LocalSettingsResetUiFlowOps& ops)
{
    return ops.material_ready != nullptr && ops.material_ready();
}

void clear_settings_touch_entry(const LocalSettingsResetUiFlowOps& ops)
{
    if (ops.clear_settings_touch_entry != nullptr) {
        ops.clear_settings_touch_entry();
    }
}

void wipe_local_reset_scratch(
    const LocalSettingsResetUiFlowOps& ops,
    const char* reason)
{
    const bool had_reset_scratch = local_reset_wipe_active();
    clear_settings_touch_entry(ops);
    if (had_reset_scratch) {
        log_warn(ops, reason != nullptr ? reason : "local reset scratch wiped");
    }
}

bool clear_panel_if_kind(
    const LocalSettingsResetUiFlowOps& ops,
    UiPanelKind kind,
    SensitiveUiClearPolicy policy = SensitiveUiClearPolicy::wipe)
{
    return ops.clear_panel_if_kind != nullptr &&
           ops.clear_panel_if_kind(kind, policy);
}

bool panel_active(
    const LocalSettingsResetUiFlowOps& ops,
    UiPanelKind kind)
{
    return ops.panel_active != nullptr && ops.panel_active(kind);
}

bool display_ready(const LocalSettingsResetUiFlowOps& ops)
{
    return ops.display_ready == nullptr || ops.display_ready();
}

bool local_reset_panel_active(const LocalSettingsResetUiFlowOps& ops)
{
    return ops.local_reset_panel_active != nullptr &&
           ops.local_reset_panel_active();
}

UiPanelKind active_settings_panel(const LocalSettingsResetUiFlowOps& ops)
{
    if (panel_active(ops, UiPanelKind::sui_settings)) {
        return UiPanelKind::sui_settings;
    }
    if (panel_active(ops, UiPanelKind::chain_settings_menu)) {
        return UiPanelKind::chain_settings_menu;
    }
    return UiPanelKind::settings_menu;
}

bool draw_settings_menu_panel(const LocalSettingsResetUiFlowOps& ops)
{
    return ops.draw_settings_menu_panel != nullptr &&
           ops.draw_settings_menu_panel();
}

bool draw_error_recovery_panel(
    const LocalSettingsResetUiFlowOps& ops,
    bool confirm)
{
    return ops.draw_error_recovery_panel != nullptr &&
           ops.draw_error_recovery_panel(confirm);
}

bool draw_reset_pin_panel(
    const LocalSettingsResetUiFlowOps& ops,
    const char* notice = nullptr)
{
    return ops.draw_reset_pin_panel != nullptr &&
           ops.draw_reset_pin_panel(notice);
}

ModalTransitionOps modal_transition_ops(const LocalSettingsResetUiFlowOps& ops)
{
    return ModalTransitionOps{
        ops.clear_panel_if_kind,
        ops.draw_processing_overlay_on_current_panel,
        ops.log_warn,
    };
}

struct ErrorRecoveryPanelDrawContext {
    const LocalSettingsResetUiFlowOps* ops = nullptr;
    bool confirm = false;
};

struct ResetPinPanelDrawContext {
    const LocalSettingsResetUiFlowOps* ops = nullptr;
    const char* notice = nullptr;
};

struct SettingsPanelDrawContext {
    const LocalSettingsResetUiFlowOps* ops = nullptr;
};

struct ResetCommitResultContext {
    const LocalSettingsResetUiFlowOps* ops = nullptr;
    const char* message = nullptr;
    MessageKind kind = MessageKind::info;
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

void complete_panel_to_result(
    const LocalSettingsResetUiFlowOps& ops,
    UiPanelKind panel,
    const char* message,
    MessageKind kind)
{
    ResetCommitResultContext context{&ops, message, kind};
    if (panel == UiPanelKind::none) {
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
    const LocalSettingsResetUiFlowOps& ops,
    PersistentMaterialRuntimeFailure failure)
{
    if (ops.record_material_failure != nullptr) {
        ops.record_material_failure(failure);
    }
}

void draw_reset_pin_error_or_wipe(
    const LocalSettingsResetUiFlowOps& ops,
    const char* notice,
    const char* wipe_reason)
{
    if (draw_reset_pin_panel(ops, notice)) {
        return;
    }
    wipe_local_reset_scratch(ops, wipe_reason);
    show_result(ops, "Display error", MessageKind::error);
}

void draw_error_recovery_confirm_or_wipe(
    const LocalSettingsResetUiFlowOps& ops)
{
    if (draw_error_recovery_panel(ops, true)) {
        return;
    }
    wipe_local_reset_scratch(
        ops,
        "error recovery confirmation display allocation failed");
    show_result(ops, "Display error", MessageKind::error);
}

}  // namespace

bool local_settings_reset_ui_panel_matches_stage(UiPanelKind kind)
{
    const ResetStage stage = local_reset_snapshot(xTaskGetTickCount()).stage;
    return ((kind == UiPanelKind::settings_menu ||
             kind == UiPanelKind::chain_settings_menu ||
             kind == UiPanelKind::sui_settings) &&
            stage == ResetStage::settings_menu) ||
           (kind == UiPanelKind::reset_pin_entry &&
            stage == ResetStage::pin_entry) ||
           (kind == UiPanelKind::error_recovery &&
            stage == ResetStage::error_recovery_confirm);
}

bool local_settings_reset_ui_accepts_reset_pin_input()
{
    return local_reset_snapshot(xTaskGetTickCount()).stage == ResetStage::pin_entry;
}

void local_settings_reset_ui_clear_if_needed(const LocalSettingsResetUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const bool active = local_reset_panel_active(ops);
    const UiPanelKind active_panel = active_settings_panel(ops);
    const ResetMaintenanceResult result =
        local_reset_handle_ui_maintenance(active, now);
    switch (result) {
        case ResetMaintenanceResult::unchanged:
            return;
        case ResetMaintenanceResult::auth_unavailable:
            record_material_failure(
                ops,
                PersistentMaterialRuntimeFailure::local_reset_auth_unavailable);
            complete_panel_to_result(
                ops,
                UiPanelKind::reset_pin_entry,
                "Auth error",
                MessageKind::error);
            return;
        case ResetMaintenanceResult::redraw_pin_verification_panel:
            if (!draw_reset_pin_panel(ops)) {
                wipe_local_reset_scratch(ops, "local reset PIN verification UI recovery failed");
                show_result(ops, "Display error", MessageKind::error);
            }
            return;
        case ResetMaintenanceResult::redraw_wiping_panel:
            if (!draw_reset_pin_panel(ops)) {
                log_warn(ops, "Local reset wiping panel could not be restored");
            }
            return;
        case ResetMaintenanceResult::lockout_release_failed:
            clear_settings_touch_entry(ops);
            log_warn(ops, "local reset PIN lockout release failed");
            show_result(ops, "Display error", MessageKind::error);
            return;
        case ResetMaintenanceResult::lockout_released:
            draw_reset_pin_error_or_wipe(
                ops,
                "Try again.",
                "local reset PIN panel allocation failed");
            return;
        case ResetMaintenanceResult::panel_lost:
            clear_settings_touch_entry(ops);
            log_warn(ops, "local reset panel lost");
            return;
        case ResetMaintenanceResult::settings_timeout:
            if (!active) {
                clear_settings_touch_entry(ops);
            }
            complete_panel_to_result(
                ops,
                active ? active_panel : UiPanelKind::none,
                "Settings timed out",
                MessageKind::timeout);
            return;
        case ResetMaintenanceResult::reset_timeout:
            if (!active) {
                clear_settings_touch_entry(ops);
            }
            complete_panel_to_result(
                ops,
                active ? UiPanelKind::reset_pin_entry : UiPanelKind::none,
                "Reset canceled",
                MessageKind::timeout);
            return;
        case ResetMaintenanceResult::error_recovery_timeout:
            if (!active) {
                clear_settings_touch_entry(ops);
            }
            complete_panel_to_result(
                ops,
                active ? UiPanelKind::error_recovery : UiPanelKind::none,
                "Erase canceled",
                MessageKind::timeout);
            return;
    }
}

void local_settings_reset_ui_commit_if_ready(const LocalSettingsResetUiFlowOps& ops)
{
    const UiPanelKind processing_panel =
        panel_active(ops, UiPanelKind::reset_pin_entry)
            ? UiPanelKind::reset_pin_entry
            : (panel_active(ops, UiPanelKind::error_recovery)
                ? UiPanelKind::error_recovery
                : UiPanelKind::none);
    const LocalResetCommitFinishResult finish =
        local_reset_finish_commit_if_ready(now_or_zero(ops), ops.persistence_ops);
    if (finish.status == ResetCommitFinishStatus::not_ready) {
        return;
    }

    clear_settings_touch_entry(ops);
    const char* display_message = "Reset error";
    MessageKind display_kind = MessageKind::error;
    switch (finish.commit_result) {
        case ResetCommitResult::ok:
            log_warn(ops, "Local reset completed; device returned to unprovisioned");
            display_message = "Device reset";
            display_kind = MessageKind::success;
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
        case ResetCommitResult::sui_account_settings_wipe_error:
        case ResetCommitResult::approval_history_wipe_error:
        case ResetCommitResult::policy_update_marker_wipe_error:
        case ResetCommitResult::zklogin_proof_wipe_error:
        case ResetCommitResult::material_remaining_error:
        case ResetCommitResult::state_storage_error:
            log_error(ops, "Local reset failed and device entered consistency error");
            break;
    }
    ResetCommitResultContext context{&ops, display_message, display_kind};
    if (processing_panel == UiPanelKind::none) {
        show_reset_commit_result_for_transition(&context);
        return;
    }
    modal_transition_complete_processing_to_result(
        modal_transition_ops(ops),
        processing_panel,
        show_reset_commit_result_for_transition,
        &context);
}

void local_settings_reset_ui_start_from_touch(const LocalSettingsResetUiFlowOps& ops)
{
    if (ops.settings_start_available == nullptr || !ops.settings_start_available()) {
        log_warn(ops, "Local settings touch ignored because settings are unavailable");
        clear_settings_touch_entry(ops);
        return;
    }

    local_reset_begin_settings(window_from_now_ms(ops, ops.local_reset_entry_ms));
    if (!draw_settings_menu_panel(ops)) {
        wipe_local_reset_scratch(ops, "local settings display allocation failed");
        show_result(ops, "Display error", MessageKind::error);
    }
}

void local_settings_reset_ui_cancel_reset_from_ui(
    const char* message,
    const LocalSettingsResetUiFlowOps& ops)
{
    const ResetReturnToSettingsResult result =
        local_reset_return_to_settings(
            window_from_now_ms(ops, ops.local_reset_entry_ms));
    if (result == ResetReturnToSettingsResult::stale) {
        log_warn(ops, "Stale local reset cancel ignored");
        return;
    }
    if (result == ResetReturnToSettingsResult::failed) {
        complete_panel_to_result(
            ops,
            UiPanelKind::reset_pin_entry,
            message != nullptr && message[0] != '\0' ? message : "Reset canceled",
            MessageKind::error);
        return;
    }

    SettingsPanelDrawContext draw_context{&ops};
    if (!modal_transition_complete_to_next_panel(
            modal_transition_ops(ops),
            UiPanelKind::reset_pin_entry,
            draw_settings_menu_panel_for_transition,
            &draw_context)) {
        wipe_local_reset_scratch(
            ops,
            "local settings display allocation failed after reset cancel");
        complete_panel_to_result(
            ops,
            UiPanelKind::reset_pin_entry,
            message != nullptr && message[0] != '\0' ? message : "Reset canceled",
            MessageKind::error);
    }
}

void local_settings_reset_ui_close_settings_from_ui(
    const LocalSettingsResetUiFlowOps& ops)
{
    const bool settings_active = panel_active(ops, UiPanelKind::settings_menu);
    const bool chain_settings_active = panel_active(ops, UiPanelKind::chain_settings_menu);
    const bool sui_settings_active = panel_active(ops, UiPanelKind::sui_settings);
    if (!local_reset_close_settings()) {
        log_warn(ops, "Stale local settings close ignored");
        return;
    }

    if (settings_active) {
        clear_panel_if_kind(ops, UiPanelKind::settings_menu);
    } else if (chain_settings_active) {
        clear_panel_if_kind(ops, UiPanelKind::chain_settings_menu);
    } else if (sui_settings_active) {
        clear_panel_if_kind(ops, UiPanelKind::sui_settings);
    }
    clear_settings_touch_entry(ops);
}

void local_settings_reset_ui_show_persistent_error_recovery_if_needed(
    const LocalSettingsResetUiFlowOps& ops)
{
    if (ops.persistent_consistency_error_active == nullptr ||
        !ops.persistent_consistency_error_active() ||
        ops.error_recovery_available == nullptr ||
        !ops.error_recovery_available() ||
        !display_ready(ops)) {
        return;
    }

    if (panel_active(ops, UiPanelKind::error_recovery)) {
        return;
    }

    if (!draw_error_recovery_panel(ops, false)) {
        log_warn(ops, "Persistent error recovery panel could not be shown");
    }
}

void local_settings_reset_ui_start_error_recovery_from_ui(
    const LocalSettingsResetUiFlowOps& ops)
{
    if (ops.persistent_consistency_error_active == nullptr ||
        !ops.persistent_consistency_error_active() ||
        ops.error_recovery_available == nullptr ||
        !ops.error_recovery_available()) {
        log_warn(ops, "Stale error recovery action ignored");
        return;
    }

    if (!local_reset_begin_error_recovery_confirm_if_idle(
            window_from_now_ms(ops, ops.local_reset_entry_ms))) {
        log_warn(ops, "Stale error recovery action ignored");
        return;
    }
    draw_error_recovery_confirm_or_wipe(ops);
}

void local_settings_reset_ui_cancel_error_recovery_from_ui(
    const LocalSettingsResetUiFlowOps& ops)
{
    if (!local_reset_cancel_error_recovery()) {
        log_warn(ops, "Stale error recovery cancel ignored");
        return;
    }

    clear_settings_touch_entry(ops);
    complete_panel_to_result(
        ops,
        UiPanelKind::error_recovery,
        "Erase canceled",
        MessageKind::info);
}

void local_settings_reset_ui_confirm_error_recovery_from_ui(
    const LocalSettingsResetUiFlowOps& ops)
{
    if (ops.persistent_consistency_error_active == nullptr ||
        !ops.persistent_consistency_error_active()) {
        log_warn(ops, "Stale error recovery erase ignored");
        return;
    }

    const bool error_recovery_available =
        ops.error_recovery_available != nullptr && ops.error_recovery_available();
    const ResetErrorRecoveryActionResult action =
        local_reset_handle_error_recovery_confirm(
            window_from_now_ms(ops, ops.local_reset_entry_ms),
            now_or_zero(ops) + pdMS_TO_TICKS(ops.local_processing_display_ms),
            error_recovery_available);
    switch (action) {
        case ResetErrorRecoveryActionResult::stale:
            log_warn(ops, "Stale error recovery erase ignored");
            return;
        case ResetErrorRecoveryActionResult::confirmation_started:
            draw_error_recovery_confirm_or_wipe(ops);
            return;
        case ResetErrorRecoveryActionResult::wipe_started:
            break;
    }

    ErrorRecoveryPanelDrawContext draw_context{&ops, true};
    if (!modal_transition_show_processing_or_redraw_panel(
            modal_transition_ops(ops),
            UiPanelKind::error_recovery,
            draw_error_recovery_panel_for_transition,
            &draw_context)) {
        wipe_local_reset_scratch(
            ops,
            "error recovery wiping display allocation failed");
        show_result(ops, "Display error", MessageKind::error);
    }
}

void local_settings_reset_ui_start_reset_pin_from_settings_menu(
    const LocalSettingsResetUiFlowOps& ops)
{
    if (!material_ready(ops) ||
        !local_reset_begin_pin_entry(
            window_from_now_ms(ops, ops.local_reset_entry_ms))) {
        log_warn(ops, "Stale local reset menu action ignored");
        return;
    }

    if (!draw_reset_pin_panel(ops)) {
        wipe_local_reset_scratch(ops, "local reset PIN display allocation failed");
        show_result(ops, "Display error", MessageKind::error);
    }
}

bool local_settings_reset_ui_begin_settings_pin_auth_handoff(
    const char* stale_log_message,
    const LocalSettingsResetUiFlowOps& ops)
{
    if (!material_ready(ops) ||
        !local_reset_begin_settings_pin_auth_handoff()) {
        log_warn(
            ops,
            stale_log_message != nullptr && stale_log_message[0] != '\0'
                ? stale_log_message
                : "Stale local settings action ignored");
        return false;
    }
    return true;
}

void local_settings_reset_ui_restore_settings_menu(
    const char* display_failure_wipe_reason,
    const char* display_failure_message,
    MessageKind display_failure_kind,
    const LocalSettingsResetUiFlowOps& ops)
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
    const LocalSettingsResetUiFlowOps& ops)
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
    const LocalSettingsResetUiFlowOps& ops)
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
    const LocalSettingsResetUiFlowOps& ops)
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
    const LocalSettingsResetUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    if (!material_ready(ops)) {
        wipe_local_reset_scratch(ops, "local reset material state unavailable");
        complete_panel_to_result(
            ops,
            UiPanelKind::reset_pin_entry,
            "Reset unavailable",
            MessageKind::error);
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
            UiPanelKind::reset_pin_entry,
            draw_reset_pin_panel_for_transition,
            &draw_context)) {
        wipe_local_reset_scratch(
            ops,
            "local reset PIN verification display allocation failed");
        complete_panel_to_result(
            ops,
            UiPanelKind::reset_pin_entry,
            "Display error",
            MessageKind::error);
    }
}

void local_settings_reset_ui_handle_auth_worker_result(
    const LocalAuthWorkerResult& worker_result,
    const LocalSettingsResetUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    if (!material_ready(ops)) {
        if (!local_reset_abort_pin_verification()) {
            return;
        }
        clear_settings_touch_entry(ops);
        log_warn(ops, "local reset material state unavailable during PIN verification");
        complete_panel_to_result(
            ops,
            UiPanelKind::reset_pin_entry,
            "Reset unavailable",
            MessageKind::error);
        return;
    }

    const ResetVerifyResult verify_result =
        local_reset_complete_pin_verify_job(
            worker_result,
            now + pdMS_TO_TICKS(kLocalResetPinLockoutMs),
            now + pdMS_TO_TICKS(ops.local_processing_display_ms));
    switch (verify_result) {
        case ResetVerifyResult::not_ready:
            return;
        case ResetVerifyResult::auth_unavailable:
            record_material_failure(
                ops,
                PersistentMaterialRuntimeFailure::local_reset_auth_unavailable);
            clear_settings_touch_entry(ops);
            log_warn(ops, "local reset PIN verifier unavailable");
            complete_panel_to_result(
                ops,
                UiPanelKind::reset_pin_entry,
                "Auth error",
                MessageKind::error);
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

    if (!panel_active(ops, UiPanelKind::reset_pin_entry) &&
        !draw_reset_pin_panel(ops)) {
        log_warn(ops, "Local reset wiping panel could not be shown");
        local_settings_reset_ui_commit_if_ready(ops);
    }
}

}  // namespace signing
