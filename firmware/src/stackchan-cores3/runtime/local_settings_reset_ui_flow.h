#pragma once

#include <stdint.h>

#include "avatar_overlay_drawing.h"
#include "drawing_surface.h"
#include "local_auth_worker.h"
#include "local_reset.h"
#include "persistent_material.h"
#include "freertos/FreeRTOS.h"

namespace signing {

struct LocalSettingsResetUiFlowOps {
    TickType_t (*now)();
    bool (*material_ready)();
    bool (*settings_start_available)();
    bool (*error_recovery_available)();
    bool (*persistent_consistency_error_active)();
    bool (*display_ready)();
    bool (*panel_active)(UiPanelKind kind);
    bool (*local_reset_panel_active)();
    bool (*clear_panel_if_kind)(UiPanelKind kind, SensitiveUiClearPolicy policy);
    bool (*draw_settings_menu_panel)();
    bool (*draw_error_recovery_panel)(bool confirm);
    bool (*draw_reset_pin_panel)(const char* notice);
    bool (*draw_processing_overlay_on_current_panel)(UiPanelKind kind);
    void (*clear_settings_touch_entry)();
    void (*show_message)(const char* message, MessageKind kind);
    void (*record_material_failure)(PersistentMaterialRuntimeFailure failure);
    void (*log_warn)(const char* message);
    void (*log_error)(const char* message);
    LocalResetPersistenceOps persistence_ops;
    uint32_t local_reset_entry_ms;
    uint32_t local_processing_render_delay_ms;
    uint32_t local_processing_display_ms;
    uint32_t local_auth_worker_max_ms;
};

bool local_settings_reset_ui_panel_matches_stage(UiPanelKind kind);
bool local_settings_reset_ui_accepts_reset_pin_input();
void local_settings_reset_ui_clear_if_needed(const LocalSettingsResetUiFlowOps& ops);
void local_settings_reset_ui_commit_if_ready(const LocalSettingsResetUiFlowOps& ops);
void local_settings_reset_ui_start_from_touch(const LocalSettingsResetUiFlowOps& ops);
void local_settings_reset_ui_cancel_reset_from_ui(
    const char* message,
    const LocalSettingsResetUiFlowOps& ops);
void local_settings_reset_ui_close_settings_from_ui(
    const LocalSettingsResetUiFlowOps& ops);
void local_settings_reset_ui_show_persistent_error_recovery_if_needed(
    const LocalSettingsResetUiFlowOps& ops);
void local_settings_reset_ui_start_error_recovery_from_ui(
    const LocalSettingsResetUiFlowOps& ops);
void local_settings_reset_ui_cancel_error_recovery_from_ui(
    const LocalSettingsResetUiFlowOps& ops);
void local_settings_reset_ui_confirm_error_recovery_from_ui(
    const LocalSettingsResetUiFlowOps& ops);
void local_settings_reset_ui_start_reset_pin_from_settings_menu(
    const LocalSettingsResetUiFlowOps& ops);
bool local_settings_reset_ui_begin_settings_pin_auth_handoff(
    const char* stale_log_message,
    const LocalSettingsResetUiFlowOps& ops);
void local_settings_reset_ui_restore_settings_menu(
    const char* display_failure_wipe_reason,
    const char* display_failure_message,
    MessageKind display_failure_kind,
    const LocalSettingsResetUiFlowOps& ops);
void local_settings_reset_ui_handle_reset_pin_digit(
    char digit,
    const LocalSettingsResetUiFlowOps& ops);
void local_settings_reset_ui_handle_reset_pin_clear(
    const LocalSettingsResetUiFlowOps& ops);
void local_settings_reset_ui_handle_reset_pin_backspace(
    const LocalSettingsResetUiFlowOps& ops);
void local_settings_reset_ui_handle_reset_pin_submit(
    const LocalSettingsResetUiFlowOps& ops);
void local_settings_reset_ui_handle_auth_worker_result(
    const LocalAuthWorkerResult& worker_result,
    const LocalSettingsResetUiFlowOps& ops);

}  // namespace signing
