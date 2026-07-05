#pragma once

#include <stddef.h>
#include <stdint.h>

#include "avatar_overlay_drawing.h"
#include "drawing_surface.h"
#include "local_auth_worker.h"
#include "provisioning_flow.h"
#include "transport/timeout_window.h"
#include "freertos/FreeRTOS.h"

namespace signing {

struct ProvisioningUiFlowOps {
    TickType_t (*now)();
    bool (*local_setup_start_allowed)();
    bool (*setup_app_action_allowed)();
    bool (*panel_active)(UiPanelKind kind);
    bool (*clear_panel_if_kind)(UiPanelKind kind, SensitiveUiClearPolicy policy);
    bool (*draw_setup_choice_panel)();
    bool (*draw_backup_phrase_display)(const char* phrase);
    bool (*draw_import_word_entry_panel)(const char* notice);
    bool (*draw_pin_setup_panel)(const char* notice);
    bool (*draw_pin_setup_processing_or_panel)();
    void (*clear_overlay)();
    void (*show_message)(const char* message, MessageKind kind);
    ProvisioningFlowCommitResult (*commit_setup_with_prepared_auth)(
        const uint8_t* root_material,
        size_t root_material_size,
        const LocalAuthPreparedRecord* prepared_auth);
    void (*log_info)(const char* message);
    void (*log_warn)(const char* message);
    uint32_t provisioning_approval_ms;
    uint32_t backup_phrase_display_ms;
    uint32_t local_pin_setup_ms;
    uint32_t local_processing_display_ms;
    uint32_t local_auth_worker_max_ms;
};

void provisioning_ui_clear_setup_choice_if_needed(const ProvisioningUiFlowOps& ops);
void provisioning_ui_clear_import_word_entry_if_needed(const ProvisioningUiFlowOps& ops);
void provisioning_ui_clear_backup_phrase_if_needed(const ProvisioningUiFlowOps& ops);
void provisioning_ui_clear_pin_setup_if_needed(const ProvisioningUiFlowOps& ops);

void provisioning_ui_show_setup_choice_from_touch(const ProvisioningUiFlowOps& ops);
void provisioning_ui_start_generate_from_setup_choice(const ProvisioningUiFlowOps& ops);
void provisioning_ui_start_import_from_setup_choice(const ProvisioningUiFlowOps& ops);
void provisioning_ui_cancel_from_local_ui(const ProvisioningUiFlowOps& ops);
void provisioning_ui_return_to_setup_choice(const ProvisioningUiFlowOps& ops);
void provisioning_ui_confirm_backup_phrase(const ProvisioningUiFlowOps& ops);

void provisioning_ui_handle_import_slot(uint8_t slot, const ProvisioningUiFlowOps& ops);
void provisioning_ui_handle_import_letter(char letter, const ProvisioningUiFlowOps& ops);
void provisioning_ui_handle_import_clear(const ProvisioningUiFlowOps& ops);
void provisioning_ui_handle_import_candidate(uint16_t word_index, const ProvisioningUiFlowOps& ops);
void provisioning_ui_handle_import_previous(const ProvisioningUiFlowOps& ops);
void provisioning_ui_handle_import_next(const ProvisioningUiFlowOps& ops);

void provisioning_ui_handle_pin_digit(char digit, const ProvisioningUiFlowOps& ops);
void provisioning_ui_handle_pin_clear(const ProvisioningUiFlowOps& ops);
void provisioning_ui_handle_pin_backspace(const ProvisioningUiFlowOps& ops);
void provisioning_ui_handle_pin_submit(const ProvisioningUiFlowOps& ops);

void provisioning_ui_handle_setup_auth_worker_result(
    LocalAuthWorkerResult& worker_result,
    const ProvisioningUiFlowOps& ops);

}  // namespace signing
