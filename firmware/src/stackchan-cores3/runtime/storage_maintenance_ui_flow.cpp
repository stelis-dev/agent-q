#include "storage_maintenance_ui_flow.h"

#include "local_settings_touch_entry.h"
#include "modal_transition.h"
#include "transport/timeout_window.h"
#include "freertos/task.h"

namespace signing {
namespace {

using MaintenanceStage = StorageMaintenanceStage;
using MaintenanceCommitResult = StorageMaintenanceCommitResult;
using MaintenanceCommitFinishStatus = StorageMaintenanceCommitFinishStatus;
using MaintenanceCancelPinResult = StorageMaintenanceCancelPinResult;
using MaintenanceSubmitResult = StorageMaintenancePinSubmitResult;
using MaintenanceVerifyResult = StorageMaintenancePinVerifyResult;
using MaintenanceResult = StorageMaintenanceUiMaintenanceResult;
using MaintenanceErrorRecoveryActionResult = StorageMaintenanceErrorRecoveryActionResult;

TickType_t now_or_zero(const StorageMaintenanceUiFlowOps& ops)
{
    return ops.now != nullptr ? ops.now() : 0;
}

TimeoutWindow window_from_now_ms(
    const StorageMaintenanceUiFlowOps& ops,
    uint32_t duration_ms)
{
    const TickType_t now = now_or_zero(ops);
    return timeout_window_from_deadline(now, now + pdMS_TO_TICKS(duration_ms));
}

void log_warn(const StorageMaintenanceUiFlowOps& ops, const char* message)
{
    if (ops.log_warn != nullptr) {
        ops.log_warn(message);
    }
}

void log_error(const StorageMaintenanceUiFlowOps& ops, const char* message)
{
    if (ops.log_error != nullptr) {
        ops.log_error(message);
    }
}

void show_result(
    const StorageMaintenanceUiFlowOps& ops,
    const char* message,
    MessageKind kind)
{
    if (ops.show_message != nullptr) {
        ops.show_message(message, kind);
    }
}

bool material_ready(const StorageMaintenanceUiFlowOps& ops)
{
    return ops.material_ready != nullptr && ops.material_ready();
}

void clear_settings_touch_entry(const StorageMaintenanceUiFlowOps& ops)
{
    if (ops.clear_settings_touch_entry != nullptr) {
        ops.clear_settings_touch_entry();
    }
}

bool clear_storage_maintenance_flow(
    const StorageMaintenanceUiFlowOps& ops,
    const char* reason)
{
    const bool had_storage_action_scratch = storage_maintenance_flow_active();
    if (!storage_maintenance_clear_flow()) {
        if (had_storage_action_scratch) {
            log_warn(
                ops,
                "storage maintenance state preserved until effectful auth completes");
        }
        return false;
    }
    clear_settings_touch_entry(ops);
    if (had_storage_action_scratch) {
        log_warn(ops, reason != nullptr ? reason : "storage maintenance scratch wiped");
    }
    return true;
}

bool clear_panel_if_kind(
    const StorageMaintenanceUiFlowOps& ops,
    UiPanelKind kind,
    SensitiveUiClearPolicy policy = SensitiveUiClearPolicy::wipe)
{
    return ops.clear_panel_if_kind != nullptr &&
           ops.clear_panel_if_kind(kind, policy);
}

bool panel_active(
    const StorageMaintenanceUiFlowOps& ops,
    UiPanelKind kind)
{
    return ops.panel_active != nullptr && ops.panel_active(kind);
}

bool display_ready(const StorageMaintenanceUiFlowOps& ops)
{
    return ops.display_ready == nullptr || ops.display_ready();
}

bool storage_maintenance_panel_active(const StorageMaintenanceUiFlowOps& ops)
{
    return ops.storage_maintenance_panel_active != nullptr &&
           ops.storage_maintenance_panel_active();
}

UiPanelKind active_settings_panel(const StorageMaintenanceUiFlowOps& ops)
{
    if (panel_active(ops, UiPanelKind::sui_settings)) {
        return UiPanelKind::sui_settings;
    }
    if (panel_active(ops, UiPanelKind::chain_settings_menu)) {
        return UiPanelKind::chain_settings_menu;
    }
    return UiPanelKind::settings_menu;
}

bool draw_settings_menu_panel(const StorageMaintenanceUiFlowOps& ops)
{
    return ops.draw_settings_menu_panel != nullptr &&
           ops.draw_settings_menu_panel();
}

bool draw_error_recovery_panel(
    const StorageMaintenanceUiFlowOps& ops,
    bool confirm)
{
    return ops.draw_error_recovery_panel != nullptr &&
           ops.draw_error_recovery_panel(confirm);
}

bool draw_action_pin_panel(
    const StorageMaintenanceUiFlowOps& ops,
    const char* notice = nullptr)
{
    return ops.draw_action_pin_panel != nullptr &&
           ops.draw_action_pin_panel(notice);
}

ModalTransitionOps modal_transition_ops(const StorageMaintenanceUiFlowOps& ops)
{
    return ModalTransitionOps{
        ops.clear_panel_if_kind,
        ops.draw_processing_overlay_on_current_panel,
        ops.log_warn,
    };
}

struct ErrorRecoveryPanelDrawContext {
    const StorageMaintenanceUiFlowOps* ops = nullptr;
    bool confirm = false;
};

struct ActionPinPanelDrawContext {
    const StorageMaintenanceUiFlowOps* ops = nullptr;
    const char* notice = nullptr;
};

struct SettingsPanelDrawContext {
    const StorageMaintenanceUiFlowOps* ops = nullptr;
};

struct MaintenanceCommitResultContext {
    const StorageMaintenanceUiFlowOps* ops = nullptr;
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

bool ensure_error_recovery_started(
    const StorageMaintenanceUiFlowOps& ops,
    TimeoutWindow input_window,
    StorageMaintenanceOperation operation)
{
    const StorageMaintenanceSnapshot snapshot =
        storage_maintenance_snapshot(now_or_zero(ops));
    if (snapshot.stage == MaintenanceStage::error_recovery_prompt ||
        snapshot.stage == MaintenanceStage::error_recovery_confirm) {
        return snapshot.operation == operation;
    }
    if (snapshot.stage != MaintenanceStage::none) {
        return false;
    }
    return storage_maintenance_begin_error_recovery_prompt_if_idle(
        input_window,
        operation);
}

bool draw_action_pin_panel_for_transition(void* context)
{
    const auto* draw_context = static_cast<const ActionPinPanelDrawContext*>(context);
    return draw_context != nullptr &&
           draw_context->ops != nullptr &&
           draw_action_pin_panel(*draw_context->ops, draw_context->notice);
}

bool draw_settings_menu_panel_for_transition(void* context)
{
    const auto* draw_context = static_cast<const SettingsPanelDrawContext*>(context);
    return draw_context != nullptr &&
           draw_context->ops != nullptr &&
           draw_settings_menu_panel(*draw_context->ops);
}

void show_storage_action_commit_result_for_transition(void* context)
{
    const auto* result_context = static_cast<const MaintenanceCommitResultContext*>(context);
    if (result_context == nullptr || result_context->ops == nullptr) {
        return;
    }
    show_result(
        *result_context->ops,
        result_context->message,
        result_context->kind);
}

void complete_panel_to_result(
    const StorageMaintenanceUiFlowOps& ops,
    UiPanelKind panel,
    const char* message,
    MessageKind kind)
{
    MaintenanceCommitResultContext context{&ops, message, kind};
    if (panel == UiPanelKind::none) {
        show_storage_action_commit_result_for_transition(&context);
        return;
    }
    modal_transition_complete_to_result(
        modal_transition_ops(ops),
        panel,
        show_storage_action_commit_result_for_transition,
        &context);
}

void record_material_failure(
    const StorageMaintenanceUiFlowOps& ops,
    PersistentMaterialRuntimeFailure failure)
{
    if (ops.record_material_failure != nullptr) {
        ops.record_material_failure(failure);
    }
}

const char* canceled_message_for_operation(StorageMaintenanceOperation operation)
{
    return operation == StorageMaintenanceOperation::wallet_erase
               ? "Device reset canceled"
               : "Repair canceled";
}

void draw_action_pin_error_or_wipe(
    const StorageMaintenanceUiFlowOps& ops,
    const char* notice,
    const char* wipe_reason)
{
    if (draw_action_pin_panel(ops, notice)) {
        return;
    }
    clear_storage_maintenance_flow(ops, wipe_reason);
    show_result(ops, "Display error", MessageKind::error);
}

void draw_error_recovery_confirm_or_wipe(
    const StorageMaintenanceUiFlowOps& ops)
{
    if (draw_error_recovery_panel(ops, true)) {
        return;
    }
    clear_storage_maintenance_flow(
        ops,
        "error recovery confirmation display allocation failed");
    show_result(ops, "Display error", MessageKind::error);
}

}  // namespace

bool storage_maintenance_ui_panel_matches_stage(UiPanelKind kind)
{
    const StorageMaintenanceSnapshot snapshot =
        storage_maintenance_snapshot(xTaskGetTickCount());
    switch (snapshot.stage) {
        case MaintenanceStage::settings_menu:
            return kind == UiPanelKind::settings_menu ||
                   kind == UiPanelKind::chain_settings_menu ||
                   kind == UiPanelKind::sui_settings;
        case MaintenanceStage::pin_entry:
        case MaintenanceStage::pin_verifying:
            return kind == UiPanelKind::action_pin_entry;
        case MaintenanceStage::error_recovery_prompt:
        case MaintenanceStage::error_recovery_confirm:
            return kind == UiPanelKind::error_recovery;
        case MaintenanceStage::committing:
            return kind == UiPanelKind::action_pin_entry ||
                   kind == UiPanelKind::error_recovery;
        case MaintenanceStage::none:
            return false;
    }
    return false;
}

bool storage_maintenance_ui_accepts_action_pin_input()
{
    return storage_maintenance_snapshot(xTaskGetTickCount()).stage == MaintenanceStage::pin_entry;
}

void storage_maintenance_ui_clear_if_needed(const StorageMaintenanceUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const bool active = storage_maintenance_panel_active(ops);
    const UiPanelKind active_panel = active_settings_panel(ops);
    const StorageMaintenanceSnapshot before =
        storage_maintenance_snapshot(now);
    const MaintenanceResult result =
        storage_maintenance_handle_ui_maintenance(active, now);
    switch (result) {
        case MaintenanceResult::unchanged:
            return;
        case MaintenanceResult::auth_unavailable:
            record_material_failure(
                ops,
                before.operation == StorageMaintenanceOperation::wallet_erase
                    ? PersistentMaterialRuntimeFailure::wallet_erase_auth_unavailable
                    : PersistentMaterialRuntimeFailure::settings_reset_auth_unavailable);
            complete_panel_to_result(
                ops,
                UiPanelKind::action_pin_entry,
                "Auth error",
                MessageKind::error);
            return;
        case MaintenanceResult::redraw_pin_verification_panel:
            if (!draw_action_pin_panel(ops)) {
                clear_storage_maintenance_flow(ops, "local action PIN verification UI recovery failed");
                show_result(ops, "Display error", MessageKind::error);
            }
            return;
        case MaintenanceResult::redraw_committing_panel:
            if (!draw_action_pin_panel(ops)) {
                log_warn(ops, "Storage maintenance committing panel could not be restored");
            }
            return;
        case MaintenanceResult::lockout_release_failed:
            clear_settings_touch_entry(ops);
            log_warn(ops, "local action PIN lockout release failed");
            show_result(ops, "Display error", MessageKind::error);
            return;
        case MaintenanceResult::lockout_released:
            draw_action_pin_error_or_wipe(
                ops,
                "Try again.",
                "local action PIN panel allocation failed");
            return;
        case MaintenanceResult::panel_lost:
            clear_settings_touch_entry(ops);
            log_warn(ops, "storage maintenance panel lost");
            return;
        case MaintenanceResult::settings_timeout:
            if (!active) {
                clear_settings_touch_entry(ops);
            }
            complete_panel_to_result(
                ops,
                active ? active_panel : UiPanelKind::none,
                "Settings timed out",
                MessageKind::timeout);
            return;
        case MaintenanceResult::action_timeout:
            if (!active) {
                clear_settings_touch_entry(ops);
            }
            complete_panel_to_result(
                ops,
                active ? UiPanelKind::action_pin_entry : UiPanelKind::none,
                "Settings storage action canceled",
                MessageKind::timeout);
            return;
        case MaintenanceResult::error_recovery_timeout:
            if (!active) {
                clear_settings_touch_entry(ops);
            }
            complete_panel_to_result(
                ops,
                active ? UiPanelKind::error_recovery : UiPanelKind::none,
                canceled_message_for_operation(before.operation),
                MessageKind::timeout);
            return;
    }
}

void storage_maintenance_ui_commit_if_ready(const StorageMaintenanceUiFlowOps& ops)
{
    const UiPanelKind processing_panel =
        panel_active(ops, UiPanelKind::action_pin_entry)
            ? UiPanelKind::action_pin_entry
            : (panel_active(ops, UiPanelKind::error_recovery)
                ? UiPanelKind::error_recovery
                : UiPanelKind::none);
    const StorageMaintenanceCommitFinishResult finish =
        storage_maintenance_finish_commit_if_ready(now_or_zero(ops), ops.persistence_ops);
    if (finish.status == MaintenanceCommitFinishStatus::not_ready) {
        return;
    }

    clear_settings_touch_entry(ops);
    const bool wallet_erase = finish.operation == StorageMaintenanceOperation::wallet_erase;
    const char* display_message = wallet_erase ? "Device reset error" : "Settings repair error";
    MessageKind display_kind = MessageKind::error;
    switch (finish.commit_result) {
        case MaintenanceCommitResult::ok:
            log_warn(
                ops,
                wallet_erase
                    ? "Device reset completed; device returned to unprovisioned"
                    : "Settings repaired; signing key material preserved");
            display_message = wallet_erase ? "Device reset" : "Settings repaired";
            display_kind = MessageKind::success;
            break;
        case MaintenanceCommitResult::missing_state:
            log_warn(ops, "Storage action commit missing state");
            display_message = wallet_erase ? "Device reset unavailable" : "Settings repair unavailable";
            break;
        case MaintenanceCommitResult::action_marker_storage_error:
            log_warn(ops, "Storage action aborted before changing material because the pending marker could not be stored");
            break;
        case MaintenanceCommitResult::key_unavailable:
        case MaintenanceCommitResult::auth_unavailable:
            log_error(ops, "Settings repair could not be authorized; device entered consistency error");
            break;
        case MaintenanceCommitResult::keystore_wipe_error:
        case MaintenanceCommitResult::policy_wipe_error:
        case MaintenanceCommitResult::human_approval_setting_wipe_error:
        case MaintenanceCommitResult::signing_mode_wipe_error:
        case MaintenanceCommitResult::sui_account_settings_wipe_error:
        case MaintenanceCommitResult::approval_history_wipe_error:
        case MaintenanceCommitResult::policy_update_marker_wipe_error:
        case MaintenanceCommitResult::zklogin_proof_wipe_error:
        case MaintenanceCommitResult::material_remaining_error:
        case MaintenanceCommitResult::material_incomplete_error:
        case MaintenanceCommitResult::state_storage_error:
            log_error(ops, "Storage action failed and device entered consistency error");
            break;
    }
    MaintenanceCommitResultContext context{&ops, display_message, display_kind};
    if (processing_panel == UiPanelKind::none) {
        show_storage_action_commit_result_for_transition(&context);
        return;
    }
    modal_transition_complete_processing_to_result(
        modal_transition_ops(ops),
        processing_panel,
        show_storage_action_commit_result_for_transition,
        &context);
}

void storage_maintenance_ui_start_from_touch(const StorageMaintenanceUiFlowOps& ops)
{
    if (ops.settings_start_available == nullptr || !ops.settings_start_available()) {
        log_warn(ops, "Local settings touch ignored because settings are unavailable");
        clear_settings_touch_entry(ops);
        return;
    }

    storage_maintenance_begin_settings(window_from_now_ms(ops, ops.storage_maintenance_entry_ms));
    if (!draw_settings_menu_panel(ops)) {
        clear_storage_maintenance_flow(ops, "local settings display allocation failed");
        show_result(ops, "Display error", MessageKind::error);
    }
}

void storage_maintenance_ui_cancel_action_pin_from_ui(
    const char* message,
    const StorageMaintenanceUiFlowOps& ops)
{
    const MaintenanceCancelPinResult result =
        storage_maintenance_cancel_pin_entry(
            window_from_now_ms(ops, ops.storage_maintenance_entry_ms));
    if (result == MaintenanceCancelPinResult::stale) {
        log_warn(ops, "Stale storage maintenance cancel ignored");
        return;
    }
    if (result == MaintenanceCancelPinResult::failed) {
        complete_panel_to_result(
            ops,
            UiPanelKind::action_pin_entry,
            message != nullptr && message[0] != '\0' ? message : "Storage action canceled",
            MessageKind::error);
        return;
    }

    if (result == MaintenanceCancelPinResult::returned_to_error_recovery) {
        ErrorRecoveryPanelDrawContext draw_context{&ops, false};
        if (modal_transition_complete_to_next_panel(
                modal_transition_ops(ops),
                UiPanelKind::action_pin_entry,
                draw_error_recovery_panel_for_transition,
                &draw_context)) {
            return;
        }
        clear_storage_maintenance_flow(
            ops,
            "storage error recovery display allocation failed after repair cancel");
        complete_panel_to_result(
            ops,
            UiPanelKind::action_pin_entry,
            message != nullptr && message[0] != '\0' ? message : "Storage action canceled",
            MessageKind::error);
        return;
    }

    SettingsPanelDrawContext draw_context{&ops};
    if (modal_transition_complete_to_next_panel(
            modal_transition_ops(ops),
            UiPanelKind::action_pin_entry,
            draw_settings_menu_panel_for_transition,
            &draw_context)) {
        return;
    }
    clear_storage_maintenance_flow(
        ops,
        "local settings display allocation failed after storage action cancel");
    complete_panel_to_result(
        ops,
        UiPanelKind::action_pin_entry,
        message != nullptr && message[0] != '\0' ? message : "Storage action canceled",
        MessageKind::error);
}

void storage_maintenance_ui_close_settings_from_ui(
    const StorageMaintenanceUiFlowOps& ops)
{
    const bool settings_active = panel_active(ops, UiPanelKind::settings_menu);
    const bool chain_settings_active = panel_active(ops, UiPanelKind::chain_settings_menu);
    const bool sui_settings_active = panel_active(ops, UiPanelKind::sui_settings);
    if (!storage_maintenance_close_settings()) {
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

void storage_maintenance_ui_show_persistent_error_recovery_if_needed(
    const StorageMaintenanceUiFlowOps& ops)
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

    const StorageMaintenanceSnapshot snapshot =
        storage_maintenance_snapshot(now_or_zero(ops));
    bool confirm = false;
    if (snapshot.stage == MaintenanceStage::none) {
        const StorageMaintenanceOperation operation =
            storage_maintenance_error_recovery_operation();
        if (!storage_maintenance_begin_error_recovery_prompt_if_idle(
                window_from_now_ms(ops, ops.storage_maintenance_entry_ms),
                operation)) {
            log_warn(ops, "Persistent error recovery state could not be started");
            return;
        }
    } else if (snapshot.stage == MaintenanceStage::error_recovery_prompt) {
        confirm = false;
    } else if (snapshot.stage == MaintenanceStage::error_recovery_confirm) {
        confirm = true;
    } else {
        return;
    }

    if (!draw_error_recovery_panel(ops, confirm)) {
        log_warn(ops, "Persistent error recovery panel could not be shown");
    }
}

void storage_maintenance_ui_start_error_recovery_from_ui(
    const StorageMaintenanceUiFlowOps& ops)
{
    if (ops.persistent_consistency_error_active == nullptr ||
        !ops.persistent_consistency_error_active() ||
        ops.error_recovery_available == nullptr ||
        !ops.error_recovery_available()) {
        log_warn(ops, "Stale error recovery action ignored");
        return;
    }

    const StorageMaintenanceOperation operation =
        storage_maintenance_error_recovery_operation();
    if (!storage_maintenance_begin_error_recovery_prompt_if_idle(
            window_from_now_ms(ops, ops.storage_maintenance_entry_ms),
            operation)) {
        log_warn(ops, "Stale error recovery action ignored");
        return;
    }
    if (!draw_error_recovery_panel(ops, false)) {
        clear_storage_maintenance_flow(
            ops,
            "storage error recovery display allocation failed");
        show_result(ops, "Display error", MessageKind::error);
    }
}

void storage_maintenance_ui_cancel_error_recovery_from_ui(
    const StorageMaintenanceUiFlowOps& ops)
{
    const StorageMaintenanceSnapshot snapshot =
        storage_maintenance_snapshot(now_or_zero(ops));
    if (!storage_maintenance_cancel_error_recovery()) {
        log_warn(ops, "Stale error recovery cancel ignored");
        return;
    }

    clear_settings_touch_entry(ops);
    complete_panel_to_result(
        ops,
        UiPanelKind::error_recovery,
        canceled_message_for_operation(snapshot.operation),
        MessageKind::info);
}

void storage_maintenance_ui_confirm_error_recovery_from_ui(
    const StorageMaintenanceUiFlowOps& ops)
{
    if (ops.persistent_consistency_error_active == nullptr ||
        !ops.persistent_consistency_error_active()) {
        log_warn(ops, "Stale error recovery erase ignored");
        return;
    }

    const StorageMaintenanceSnapshot snapshot =
        storage_maintenance_snapshot(now_or_zero(ops));
    if (snapshot.stage != MaintenanceStage::error_recovery_prompt &&
        snapshot.stage != MaintenanceStage::error_recovery_confirm) {
        log_warn(ops, "Stale error recovery action ignored");
        clear_panel_if_kind(ops, UiPanelKind::error_recovery);
        clear_settings_touch_entry(ops);
        return;
    }
    const bool repair_selected =
        snapshot.operation == StorageMaintenanceOperation::settings_reset;
    if (repair_selected) {
        const TimeoutWindow input_window =
            window_from_now_ms(ops, ops.storage_maintenance_entry_ms);
        if (!ensure_error_recovery_started(
                ops,
                input_window,
                StorageMaintenanceOperation::settings_reset)) {
            log_warn(ops, "Stale settings repair action ignored");
            return;
        }
        if (!storage_maintenance_begin_error_recovery_settings_repair(
                input_window)) {
            log_warn(ops, "Stale settings repair action ignored");
            return;
        }
        if (!draw_action_pin_panel(ops, "Keeps key. Resets settings.")) {
            clear_storage_maintenance_flow(ops, "settings repair PIN display allocation failed");
            show_result(ops, "Display error", MessageKind::error);
        }
        return;
    }

    const bool error_recovery_available =
        ops.error_recovery_available != nullptr && ops.error_recovery_available();
    const MaintenanceErrorRecoveryActionResult action =
        storage_maintenance_handle_error_recovery_confirm(
            window_from_now_ms(ops, ops.storage_maintenance_entry_ms),
            now_or_zero(ops) + pdMS_TO_TICKS(ops.local_processing_display_ms),
            error_recovery_available);
    switch (action) {
        case MaintenanceErrorRecoveryActionResult::stale:
            log_warn(ops, "Stale error recovery erase ignored");
            return;
        case MaintenanceErrorRecoveryActionResult::confirmation_started:
            draw_error_recovery_confirm_or_wipe(ops);
            return;
        case MaintenanceErrorRecoveryActionResult::commit_started:
            break;
    }

    ErrorRecoveryPanelDrawContext draw_context{&ops, true};
    if (!modal_transition_show_processing_or_redraw_panel(
            modal_transition_ops(ops),
            UiPanelKind::error_recovery,
            draw_error_recovery_panel_for_transition,
            &draw_context)) {
        clear_storage_maintenance_flow(
            ops,
            "error recovery committing display allocation failed");
        show_result(ops, "Display error", MessageKind::error);
    }
}

void storage_maintenance_ui_start_wallet_erase_pin_from_settings_menu(
    const StorageMaintenanceUiFlowOps& ops)
{
    if (!material_ready(ops) ||
        !storage_maintenance_begin_wallet_erase_pin_entry(
            window_from_now_ms(ops, ops.storage_maintenance_entry_ms))) {
        log_warn(ops, "Stale device reset action ignored");
        return;
    }

    if (!draw_action_pin_panel(
            ops,
            "Deletes wallet data.")) {
        clear_storage_maintenance_flow(ops, "device reset PIN display allocation failed");
        show_result(ops, "Display error", MessageKind::error);
    }
}

bool storage_maintenance_ui_begin_settings_pin_auth_handoff(
    const char* stale_log_message,
    const StorageMaintenanceUiFlowOps& ops)
{
    if (!material_ready(ops) ||
        !storage_maintenance_begin_settings_pin_auth_handoff()) {
        log_warn(
            ops,
            stale_log_message != nullptr && stale_log_message[0] != '\0'
                ? stale_log_message
                : "Stale local settings action ignored");
        return false;
    }
    return true;
}

void storage_maintenance_ui_restore_settings_menu(
    const char* display_failure_wipe_reason,
    const char* display_failure_message,
    MessageKind display_failure_kind,
    const StorageMaintenanceUiFlowOps& ops)
{
    storage_maintenance_begin_settings(window_from_now_ms(ops, ops.storage_maintenance_entry_ms));
    if (draw_settings_menu_panel(ops)) {
        return;
    }
    clear_storage_maintenance_flow(
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

void storage_maintenance_ui_handle_action_pin_digit(
    char digit,
    const StorageMaintenanceUiFlowOps& ops)
{
    if (!storage_maintenance_add_pin_digit(digit)) {
        return;
    }
    draw_action_pin_error_or_wipe(
        ops,
        nullptr,
        "local action PIN display allocation failed");
}

void storage_maintenance_ui_handle_action_pin_clear(
    const StorageMaintenanceUiFlowOps& ops)
{
    if (!storage_maintenance_clear_pin()) {
        return;
    }
    draw_action_pin_error_or_wipe(
        ops,
        nullptr,
        "local action PIN display allocation failed");
}

void storage_maintenance_ui_handle_action_pin_backspace(
    const StorageMaintenanceUiFlowOps& ops)
{
    if (!storage_maintenance_backspace_pin()) {
        return;
    }
    draw_action_pin_error_or_wipe(
        ops,
        nullptr,
        "local action PIN display allocation failed");
}

void storage_maintenance_ui_handle_action_pin_submit(
    const StorageMaintenanceUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const MaintenanceSubmitResult submit_result =
        storage_maintenance_submit_pin_for_verification(
            now + pdMS_TO_TICKS(ops.local_processing_render_delay_ms),
            now + pdMS_TO_TICKS(ops.local_auth_worker_max_ms));
    if (submit_result == MaintenanceSubmitResult::unavailable_stage) {
        log_warn(ops, "Stale local action PIN submit ignored");
        return;
    }
    if (submit_result == MaintenanceSubmitResult::locked) {
        return;
    }
    if (submit_result == MaintenanceSubmitResult::worker_unavailable) {
        draw_action_pin_error_or_wipe(
            ops,
            "Auth worker busy. Try again.",
            "local action PIN worker unavailable display allocation failed");
        return;
    }
    if (submit_result == MaintenanceSubmitResult::invalid_pin) {
        draw_action_pin_error_or_wipe(
            ops,
            "Enter exactly 6 digits.",
            "local action PIN display allocation failed");
        return;
    }

    ActionPinPanelDrawContext draw_context{&ops, nullptr};
    if (!modal_transition_show_processing_or_redraw_panel(
            modal_transition_ops(ops),
            UiPanelKind::action_pin_entry,
            draw_action_pin_panel_for_transition,
            &draw_context)) {
        clear_storage_maintenance_flow(
            ops,
            "local action PIN verification display allocation failed");
        complete_panel_to_result(
            ops,
            UiPanelKind::action_pin_entry,
            "Display error",
            MessageKind::error);
    }
}

void storage_maintenance_ui_handle_auth_worker_result(
    const LocalAuthWorkerResult& worker_result,
    const StorageMaintenanceUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const MaintenanceVerifyResult verify_result =
        storage_maintenance_complete_pin_verify_job(
            worker_result,
            now + pdMS_TO_TICKS(kStorageMaintenancePinLockoutMs),
            now + pdMS_TO_TICKS(ops.local_processing_display_ms));
    switch (verify_result) {
        case MaintenanceVerifyResult::not_ready:
            return;
        case MaintenanceVerifyResult::auth_unavailable:
            record_material_failure(
                ops,
                storage_maintenance_snapshot(now).operation == StorageMaintenanceOperation::wallet_erase
                    ? PersistentMaterialRuntimeFailure::wallet_erase_auth_unavailable
                    : PersistentMaterialRuntimeFailure::settings_reset_auth_unavailable);
            clear_settings_touch_entry(ops);
            log_warn(ops, "settings action PIN authentication unavailable");
            complete_panel_to_result(
                ops,
                UiPanelKind::action_pin_entry,
                "Auth error",
                MessageKind::error);
            return;
        case MaintenanceVerifyResult::locked:
            draw_action_pin_error_or_wipe(
                ops,
                "Too many wrong PINs. Wait 30s.",
                "local action PIN lockout display allocation failed");
            return;
        case MaintenanceVerifyResult::wrong_pin:
            draw_action_pin_error_or_wipe(
                ops,
                "Wrong PIN.",
                "local action PIN display allocation failed");
            return;
        case MaintenanceVerifyResult::verified:
            break;
    }

    if (!panel_active(ops, UiPanelKind::action_pin_entry) &&
        !draw_action_pin_panel(ops)) {
        log_warn(ops, "Storage maintenance committing panel could not be shown");
        storage_maintenance_ui_commit_if_ready(ops);
    }
}

}  // namespace signing
