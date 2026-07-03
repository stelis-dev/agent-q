#pragma once

#include <stdint.h>

#include "avatar_overlay_drawing.h"
#include "drawing_surface.h"
#include "local_auth_worker.h"
#include "storage_maintenance.h"
#include "persistent_material.h"
#include "freertos/FreeRTOS.h"

namespace signing {

struct StorageMaintenanceUiFlowOps {
    TickType_t (*now)();
    bool (*material_ready)();
    bool (*settings_start_available)();
    bool (*error_recovery_available)();
    bool (*persistent_consistency_error_active)();
    bool (*display_ready)();
    bool (*panel_active)(UiPanelKind kind);
    bool (*storage_maintenance_panel_active)();
    bool (*clear_panel_if_kind)(UiPanelKind kind, SensitiveUiClearPolicy policy);
    bool (*draw_settings_menu_panel)();
    bool (*draw_error_recovery_panel)(bool confirm);
    bool (*draw_action_pin_panel)(const char* notice);
    bool (*draw_processing_overlay_on_current_panel)(UiPanelKind kind);
    void (*clear_settings_touch_entry)();
    void (*show_message)(const char* message, MessageKind kind);
    void (*record_material_failure)(PersistentMaterialRuntimeFailure failure);
    void (*log_warn)(const char* message);
    void (*log_error)(const char* message);
    StorageMaintenancePersistenceOps persistence_ops;
    uint32_t storage_maintenance_entry_ms;
    uint32_t local_processing_render_delay_ms;
    uint32_t local_processing_display_ms;
    uint32_t local_auth_worker_max_ms;
};

bool storage_maintenance_ui_panel_matches_stage(UiPanelKind kind);
bool storage_maintenance_ui_accepts_action_pin_input();
void storage_maintenance_ui_clear_if_needed(const StorageMaintenanceUiFlowOps& ops);
void storage_maintenance_ui_commit_if_ready(const StorageMaintenanceUiFlowOps& ops);
void storage_maintenance_ui_start_from_touch(const StorageMaintenanceUiFlowOps& ops);
void storage_maintenance_ui_cancel_action_pin_from_ui(
    const char* message,
    const StorageMaintenanceUiFlowOps& ops);
void storage_maintenance_ui_close_settings_from_ui(
    const StorageMaintenanceUiFlowOps& ops);
void storage_maintenance_ui_show_persistent_error_recovery_if_needed(
    const StorageMaintenanceUiFlowOps& ops);
void storage_maintenance_ui_start_error_recovery_from_ui(
    const StorageMaintenanceUiFlowOps& ops);
void storage_maintenance_ui_cancel_error_recovery_from_ui(
    const StorageMaintenanceUiFlowOps& ops);
void storage_maintenance_ui_confirm_error_recovery_from_ui(
    const StorageMaintenanceUiFlowOps& ops);
void storage_maintenance_ui_start_wallet_erase_pin_from_settings_menu(
    const StorageMaintenanceUiFlowOps& ops);
bool storage_maintenance_ui_begin_settings_pin_auth_handoff(
    const char* stale_log_message,
    const StorageMaintenanceUiFlowOps& ops);
void storage_maintenance_ui_restore_settings_menu(
    const char* display_failure_wipe_reason,
    const char* display_failure_message,
    MessageKind display_failure_kind,
    const StorageMaintenanceUiFlowOps& ops);
void storage_maintenance_ui_handle_action_pin_digit(
    char digit,
    const StorageMaintenanceUiFlowOps& ops);
void storage_maintenance_ui_handle_action_pin_clear(
    const StorageMaintenanceUiFlowOps& ops);
void storage_maintenance_ui_handle_action_pin_backspace(
    const StorageMaintenanceUiFlowOps& ops);
void storage_maintenance_ui_handle_action_pin_submit(
    const StorageMaintenanceUiFlowOps& ops);
void storage_maintenance_ui_handle_auth_worker_result(
    const LocalAuthWorkerResult& worker_result,
    const StorageMaintenanceUiFlowOps& ops);

}  // namespace signing
