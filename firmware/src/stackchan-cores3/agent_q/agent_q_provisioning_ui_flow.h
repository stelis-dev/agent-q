#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_avatar_overlay_drawing.h"
#include "agent_q_drawing_surface.h"
#include "agent_q_local_auth_worker.h"
#include "agent_q_provisioning_flow.h"
#include "agent_q_timeout_window.h"
#include "freertos/FreeRTOS.h"

namespace agent_q {

struct AgentQProvisioningUiFlowOps {
    TickType_t (*now)();
    bool (*local_setup_start_allowed)();
    bool (*setup_app_action_allowed)();
    bool (*panel_active)(AgentQUiPanelKind kind);
    bool (*clear_panel_if_kind)(AgentQUiPanelKind kind, SensitiveUiClearPolicy policy);
    bool (*draw_setup_choice_panel)();
    bool (*draw_backup_phrase_display)(const char* phrase);
    bool (*draw_import_word_entry_panel)(const char* notice);
    bool (*draw_pin_setup_panel)(const char* notice);
    bool (*draw_pin_setup_processing_or_panel)();
    void (*clear_overlay)();
    void (*show_message)(const char* message, AgentQMessageKind kind);
    AgentQProvisioningFlowCommitResult (*commit_setup_with_prepared_auth)(
        const uint8_t* root_material,
        size_t root_material_size,
        const AgentQLocalAuthPreparedRecord* prepared_auth);
    void (*log_info)(const char* message);
    void (*log_warn)(const char* message);
    uint32_t provisioning_approval_ms;
    uint32_t backup_phrase_display_ms;
    uint32_t local_pin_setup_ms;
    uint32_t local_processing_display_ms;
    uint32_t local_auth_worker_max_ms;
};

void provisioning_ui_clear_setup_choice_if_needed(const AgentQProvisioningUiFlowOps& ops);
void provisioning_ui_clear_import_word_entry_if_needed(const AgentQProvisioningUiFlowOps& ops);
void provisioning_ui_clear_backup_phrase_if_needed(const AgentQProvisioningUiFlowOps& ops);
void provisioning_ui_clear_pin_setup_if_needed(const AgentQProvisioningUiFlowOps& ops);

void provisioning_ui_show_setup_choice_from_touch(const AgentQProvisioningUiFlowOps& ops);
void provisioning_ui_start_generate_from_setup_choice(const AgentQProvisioningUiFlowOps& ops);
void provisioning_ui_start_import_from_setup_choice(const AgentQProvisioningUiFlowOps& ops);
void provisioning_ui_cancel_from_local_ui(const AgentQProvisioningUiFlowOps& ops);
void provisioning_ui_return_to_setup_choice(const AgentQProvisioningUiFlowOps& ops);
void provisioning_ui_confirm_backup_phrase(const AgentQProvisioningUiFlowOps& ops);

void provisioning_ui_handle_import_slot(uint8_t slot, const AgentQProvisioningUiFlowOps& ops);
void provisioning_ui_handle_import_letter(char letter, const AgentQProvisioningUiFlowOps& ops);
void provisioning_ui_handle_import_clear(const AgentQProvisioningUiFlowOps& ops);
void provisioning_ui_handle_import_candidate(uint16_t word_index, const AgentQProvisioningUiFlowOps& ops);
void provisioning_ui_handle_import_previous(const AgentQProvisioningUiFlowOps& ops);
void provisioning_ui_handle_import_next(const AgentQProvisioningUiFlowOps& ops);

void provisioning_ui_handle_pin_digit(char digit, const AgentQProvisioningUiFlowOps& ops);
void provisioning_ui_handle_pin_clear(const AgentQProvisioningUiFlowOps& ops);
void provisioning_ui_handle_pin_backspace(const AgentQProvisioningUiFlowOps& ops);
void provisioning_ui_handle_pin_submit(const AgentQProvisioningUiFlowOps& ops);

void provisioning_ui_handle_setup_auth_worker_result(
    AgentQLocalAuthWorkerResult& worker_result,
    const AgentQProvisioningUiFlowOps& ops);

}  // namespace agent_q
