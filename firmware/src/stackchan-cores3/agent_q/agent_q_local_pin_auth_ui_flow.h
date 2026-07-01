#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_avatar_overlay_drawing.h"
#include "agent_q_drawing_surface.h"
#include "agent_q_human_approval_settings.h"
#include "agent_q_local_auth_worker.h"
#include "agent_q_local_pin_auth.h"
#include "agent_q_persistent_material.h"
#include "agent_q_policy_update_flow.h"
#include "agent_q_signing_mode.h"
#include "agent_q_sui_account_settings.h"
#include "agent_q_sui_zklogin_proposal_flow.h"
#include "agent_q_user_signing_confirmation.h"
#include "freertos/FreeRTOS.h"

namespace agent_q {

enum class AgentQLocalPinAuthPolicyUpdateUnavailableReason {
    material_unavailable,
    auth_unavailable,
};

enum class AgentQLocalPinAuthSuiZkLoginPinBeginResult {
    started,
    unavailable,
    pin_unavailable,
};

enum class AgentQLocalPinAuthConnectPinBeginResult {
    started,
    unavailable,
    pin_unavailable,
};

struct AgentQLocalPinAuthTimingOps {
    TickType_t (*now)();
    uint64_t (*wall_clock_ms)();
    uint32_t connect_approval_ms;
    uint32_t provisioning_approval_ms;
    uint32_t local_pin_input_window_ms;
    uint32_t local_processing_render_delay_ms;
    uint32_t local_processing_display_ms;
    uint32_t local_auth_worker_max_ms;
    uint32_t local_reset_entry_ms;
};

struct AgentQLocalPinAuthDisplayOps {
    bool (*clear_panel_if_kind)(AgentQUiPanelKind kind, SensitiveUiClearPolicy policy);
    bool (*local_pin_panel_visible)();
    bool (*draw_local_pin_auth_panel)(const char* notice);
    bool (*draw_processing_overlay_on_current_panel)(AgentQUiPanelKind kind);
    void (*show_message)(const char* message, AgentQMessageKind kind);
    void (*log_write_failure)(const char* response_type, const char* id);
    void (*log_warn)(const char* message);
};

struct AgentQLocalPinAuthMaterialSettingsOps {
    bool (*provisioned_material_ready)();
    void (*record_material_failure)(AgentQPersistentMaterialRuntimeFailure failure);
    bool (*human_approval_requires_pin)();
    bool (*read_human_approval_input_mode)(AgentQHumanApprovalInputMode* output);
    bool (*read_signing_authorization_mode)(AgentQSigningAuthorizationMode* output);
    bool (*read_sui_account_settings)(AgentQSuiAccountSettings* output);
    AgentQLocalPinAuthSettingsCompletionResult (*complete_policy_reset_setting)();
    bool (*sui_zklogin_proof_clear_available)();
    AgentQLocalPinAuthSettingsCompletionResult (*complete_sui_zklogin_clear_setting)();
    bool (*begin_settings_pin_auth_handoff)(const char* stale_log_message);
    void (*restore_settings_menu)(
        const char* display_failure_wipe_reason,
        const char* display_failure_message,
        AgentQMessageKind display_failure_kind);
    void (*restore_sui_settings)(
        const char* display_failure_wipe_reason,
        const char* display_failure_message,
        AgentQMessageKind display_failure_kind);
};

struct AgentQLocalPinAuthRequestOps {
    bool (*request_id_for_pin)(
        AgentQLocalPinAuthPurpose purpose,
        char* output,
        size_t output_size);
};

struct AgentQLocalPinAuthConnectOps {
    AgentQLocalPinAuthConnectPinBeginResult (*begin_connect_pin_auth)(
        const char* request_id,
        TickType_t now,
        AgentQTimeoutWindow request_window);
    void (*write_connect_rejected_from_pin)(
        const char* request_id,
        AgentQLocalPinAuthConnectRejectReason reason);
    void (*finish_connect_rejection_cleanup)(bool clear_protocol_pin);
    bool (*return_connect_review_from_pin)(TickType_t now, AgentQTimeoutWindow window);
    void (*show_connect_review)();
    AgentQLocalPinAuthConnectSessionResult (*replace_connect_session_from_pin)(
        const char* request_id);
    void (*finish_connect_session_error)(const char* request_id);
    void (*finish_connect_approved)(const char* request_id);
};

struct AgentQLocalPinAuthPolicyUpdateOps {
    bool (*show_policy_update_review)();
    bool (*require_pending_policy_update_session)(const char* request_id);
    AgentQPolicyUpdateFlowTransitionResult (*return_policy_update_review_from_pin)(
        TickType_t now,
        AgentQTimeoutWindow window);
    AgentQPolicyUpdateFlowTransitionResult (*return_policy_update_pin_entry_from_pin)();
    AgentQPolicyUpdateFlowTerminalResult (*record_policy_update_ui_error_from_pin)();
    AgentQPolicyUpdateFlowTerminalResult (*record_policy_update_timed_out_from_pin)(
        uint64_t uptime_ms);
    AgentQPolicyUpdateFlowTerminalResult (*commit_policy_update_from_pin)(
        uint64_t uptime_ms);
    void (*finish_policy_update_unavailable_from_pin)(
        const char* request_id,
        AgentQLocalPinAuthPolicyUpdateUnavailableReason reason);
    void (*finish_policy_update_terminal)(
        const char* request_id,
        AgentQPolicyUpdateFlowTerminalResult result);
    void (*finish_policy_update_error_terminal)(
        const char* request_id,
        const char* error_code,
        const char* error_message,
        const char* display_message);
};

struct AgentQLocalPinAuthSuiZkLoginOps {
    bool (*require_pending_sui_zklogin_proposal_session)(const char* request_id);
    AgentQLocalPinAuthSuiZkLoginPinBeginResult (*begin_sui_zklogin_proposal_pin_from_review)(
        const char* request_id,
        TickType_t now);
    AgentQSuiZkLoginProposalTransitionResult (*return_sui_zklogin_review_from_pin)(
        TickType_t now);
    AgentQSuiZkLoginProposalTransitionResult (*return_sui_zklogin_pin_entry_from_pin)();
    AgentQSuiZkLoginProposalTerminalResult (*record_sui_zklogin_ui_error_from_pin)();
    AgentQSuiZkLoginProposalTerminalResult (*record_sui_zklogin_timed_out_from_pin)();
    AgentQSuiZkLoginProposalTerminalResult (*record_sui_zklogin_rejected_from_pin)();
    AgentQSuiZkLoginProposalTerminalResult (*record_sui_zklogin_consistency_error_from_pin)();
    AgentQSuiZkLoginProposalTerminalResult (*commit_sui_zklogin_from_pin)();
    void (*finish_sui_zklogin_proposal_terminal)(
        const char* request_id,
        AgentQSuiZkLoginProposalTerminalResult result);
    void (*finish_sui_zklogin_proposal_error_terminal)(
        const char* request_id,
        const char* error_code,
        const char* error_message,
        const char* display_message);
    bool (*show_sui_zklogin_review)();
};

struct AgentQLocalPinAuthUserSigningOps {
    bool (*show_user_signing_review)();
    AgentQUserSigningConfirmationResult (*cancel_user_signing_for_pin_loss)();
    AgentQUserSigningConfirmationResult (*record_user_signing_timeout_from_pin)(
        TickType_t now);
    AgentQUserSigningConfirmationResult (*return_user_signing_review_from_pin)(
        TickType_t now,
        AgentQTimeoutWindow review_window);
    void (*cancel_user_signing_for_ui_loss)();
    AgentQUserSigningConfirmationResult (*complete_user_signing_pin_verify_from_pin)(
        const AgentQLocalAuthWorkerResult& worker_result,
        TickType_t now,
        TickType_t lockout_until);
    bool (*user_signing_terminal_pending_from_pin)();
    void (*execute_user_signing_from_pin)(const char* request_id);
    void (*finish_user_signing_terminal)(const char* request_id);
    void (*finish_user_signing_error_terminal)(
        const char* request_id,
        const char* error_code,
        const char* error_message,
        const char* display_message);
};

struct AgentQLocalPinAuthUiFlowOps {
    AgentQLocalPinAuthTimingOps timing;
    AgentQLocalPinAuthDisplayOps display;
    AgentQLocalPinAuthMaterialSettingsOps material_settings;
    AgentQLocalPinAuthRequestOps request;
    AgentQLocalPinAuthConnectOps connect;
    AgentQLocalPinAuthPolicyUpdateOps policy_update;
    AgentQLocalPinAuthSuiZkLoginOps sui_zklogin;
    AgentQLocalPinAuthUserSigningOps user_signing;
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
void local_pin_auth_ui_start_settings_sui_accept_gas_sponsor(
    const AgentQLocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_start_settings_sui_zklogin_clear(
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
