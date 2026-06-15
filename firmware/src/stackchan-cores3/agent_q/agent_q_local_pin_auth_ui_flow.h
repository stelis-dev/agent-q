#pragma once

#include <stdint.h>

#include "agent_q_avatar_overlay_drawing.h"
#include "agent_q_drawing_surface.h"
#include "agent_q_human_approval_settings.h"
#include "agent_q_local_auth_worker.h"
#include "agent_q_local_pin_auth.h"
#include "agent_q_persistent_material.h"
#include "agent_q_policy_update_flow.h"
#include "agent_q_signing_mode.h"
#include "agent_q_sui_zklogin_proposal_flow.h"
#include "agent_q_user_signing_confirmation.h"
#include "freertos/FreeRTOS.h"

namespace agent_q {

struct AgentQLocalPinAuthUiFlowOps {
    TickType_t (*now)();
    uint64_t (*wall_clock_ms)();
    bool (*provisioned_material_ready)();
    bool (*human_approval_requires_pin)();
    bool (*read_human_approval_input_mode)(AgentQHumanApprovalInputMode* output);
    bool (*read_signing_authorization_mode)(AgentQSigningAuthorizationMode* output);
    bool (*store_default_policy)();
    bool (*begin_settings_pin_auth_handoff)(const char* stale_log_message);
    void (*restore_settings_menu)(
        const char* display_failure_wipe_reason,
        const char* display_failure_message,
        AgentQMessageKind display_failure_kind);
    bool (*clear_panel_if_kind)(AgentQUiPanelKind kind, SensitiveUiClearPolicy policy);
    bool (*local_pin_panel_visible)();
    bool (*draw_local_pin_auth_panel)(const char* notice);
    bool (*draw_processing_overlay_on_current_panel)(AgentQUiPanelKind kind);
    void (*show_message)(const char* message, AgentQMessageKind kind);
    void (*record_material_failure)(AgentQPersistentMaterialRuntimeFailure failure);
    void (*clear_connect_approval)();
    bool (*connect_approval_return_to_review)(TickType_t now, AgentQTimeoutWindow window);
    void (*show_connect_review)();
    bool (*replace_active_session)();
    bool (*write_error)(const char* id, const char* code, const char* message);
    bool (*write_connect_approved)(const char* id);
    bool (*write_connect_rejected)(const char* id, const char* code, const char* message);
    void (*log_connect_session_creation_failed)(const char* id);
    void (*log_connect_pin_approved)(const char* id);
    void (*log_write_failure)(const char* response_type, const char* id);
    bool (*show_policy_update_review)();
    bool (*require_pending_policy_update_session)(const char* request_id);
    bool (*write_policy_propose_result_with_current_policy)(
        const char* request_id,
        const char* status,
        const char* reason);
    void (*finish_policy_update_terminal)(
        const char* request_id,
        AgentQPolicyUpdateFlowTerminalResult result);
    void (*finish_policy_update_error_terminal)(
        const char* request_id,
        const char* error_code,
        const char* error_message,
        const char* display_message);
    bool (*require_pending_sui_zklogin_proposal_session)(const char* request_id);
    void (*finish_sui_zklogin_proposal_terminal)(
        const char* request_id,
        AgentQSuiZkLoginProposalTerminalResult result);
    void (*finish_sui_zklogin_proposal_error_terminal)(
        const char* request_id,
        const char* error_code,
        const char* error_message,
        const char* display_message);
    bool (*show_sui_zklogin_review)();
    bool (*show_user_signing_review)();
    AgentQUserSigningHistoryWriteFn write_user_signing_confirmation_history;
    void (*execute_user_signing_critical_section_and_finish)(const char* request_id);
    void (*finish_user_signing_terminal)(const char* request_id);
    void (*finish_user_signing_error_terminal)(
        const char* request_id,
        const char* error_code,
        const char* error_message,
        const char* display_message);
    void (*log_warn)(const char* message);
    uint32_t connect_approval_ms;
    uint32_t provisioning_approval_ms;
    uint32_t local_pin_input_window_ms;
    uint32_t local_processing_render_delay_ms;
    uint32_t local_processing_display_ms;
    uint32_t local_auth_worker_max_ms;
    uint32_t local_reset_entry_ms;
};

bool local_pin_auth_ui_panel_matches_stage(AgentQUiPanelKind kind);
bool local_pin_auth_ui_accepts_keypad_input();
bool local_pin_auth_ui_begin_connect(
    const char* request_id,
    const AgentQLocalPinAuthUiFlowOps& ops);
bool local_pin_auth_ui_begin_sui_zklogin_proposal(
    const char* request_id,
    const AgentQLocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_start_settings_human_approval_input(
    const AgentQLocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_start_settings_signing_mode(
    const AgentQLocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_start_settings_policy_reset(
    const AgentQLocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_start_settings_change_pin(
    const AgentQLocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_cancel(
    const char* message,
    const AgentQLocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_handle_digit(
    char digit,
    const AgentQLocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_handle_clear(const AgentQLocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_handle_backspace(const AgentQLocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_handle_submit(const AgentQLocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_commit_setting_if_ready(
    const AgentQLocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_handle_verify_worker_result(
    const AgentQLocalAuthWorkerResult& worker_result,
    const AgentQLocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_handle_prepare_worker_result(
    const AgentQLocalAuthWorkerResult& worker_result,
    const AgentQLocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_clear_if_needed(const AgentQLocalPinAuthUiFlowOps& ops);

}  // namespace agent_q
