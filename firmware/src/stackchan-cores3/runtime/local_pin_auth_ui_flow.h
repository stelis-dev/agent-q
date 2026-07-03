#pragma once

#include <stddef.h>
#include <stdint.h>

#include "avatar_overlay_drawing.h"
#include "drawing_surface.h"
#include "human_approval_settings.h"
#include "local_auth_worker.h"
#include "local_pin_auth.h"
#include "persistent_material.h"
#include "policy_update_flow.h"
#include "signing_mode.h"
#include "sui_account_settings.h"
#include "sui_zklogin_proposal_flow.h"
#include "user_signing_confirmation.h"
#include "freertos/FreeRTOS.h"

namespace signing {

enum class LocalPinAuthPolicyUpdateUnavailableReason {
    material_unavailable,
    auth_unavailable,
};

enum class LocalPinAuthSuiZkLoginPinBeginResult {
    started,
    unavailable,
    pin_unavailable,
};

enum class LocalPinAuthConnectPinBeginResult {
    started,
    unavailable,
    pin_unavailable,
};

struct LocalPinAuthTimingOps {
    TickType_t (*now)();
    uint64_t (*wall_clock_ms)();
    uint32_t connect_approval_ms;
    uint32_t provisioning_approval_ms;
    uint32_t local_pin_input_window_ms;
    uint32_t local_processing_render_delay_ms;
    uint32_t local_processing_display_ms;
    uint32_t local_auth_worker_max_ms;
    uint32_t storage_maintenance_entry_ms;
};

struct LocalPinAuthDisplayOps {
    bool (*clear_panel_if_kind)(UiPanelKind kind, SensitiveUiClearPolicy policy);
    bool (*local_pin_panel_visible)();
    bool (*draw_local_pin_auth_panel)(const char* notice);
    bool (*draw_processing_overlay_on_current_panel)(UiPanelKind kind);
    void (*show_message)(const char* message, MessageKind kind);
    void (*log_write_failure)(const char* response_type, const char* id);
    void (*log_warn)(const char* message);
};

struct LocalPinAuthMaterialSettingsOps {
    bool (*provisioned_material_ready)();
    void (*record_material_failure)(PersistentMaterialRuntimeFailure failure);
    bool (*human_approval_requires_pin)();
    bool (*read_human_approval_input_mode)(HumanApprovalInputMode* output);
    bool (*read_signing_authorization_mode)(AuthorizationMode* output);
    bool (*read_sui_account_settings)(SuiAccountSettings* output);
    LocalPinAuthSettingsCompletionResult (*complete_policy_reset_setting)();
    bool (*sui_zklogin_proof_clear_available)();
    LocalPinAuthSettingsCompletionResult (*complete_sui_zklogin_clear_setting)();
    bool (*begin_settings_pin_auth_handoff)(const char* stale_log_message);
    void (*restore_settings_menu)(
        const char* display_failure_wipe_reason,
        const char* display_failure_message,
        MessageKind display_failure_kind);
    void (*restore_sui_settings)(
        const char* display_failure_wipe_reason,
        const char* display_failure_message,
        MessageKind display_failure_kind);
};

struct LocalPinAuthRequestOps {
    bool (*request_id_for_pin)(
        LocalPinAuthPurpose purpose,
        char* output,
        size_t output_size);
};

struct LocalPinAuthConnectOps {
    LocalPinAuthConnectPinBeginResult (*begin_connect_pin_auth)(
        const char* request_id,
        TickType_t now,
        TimeoutWindow request_window);
    void (*write_connect_rejected_from_pin)(
        const char* request_id,
        LocalPinAuthConnectRejectReason reason);
    void (*finish_connect_rejection_cleanup)(bool clear_protocol_pin);
    bool (*return_connect_review_from_pin)(TickType_t now, TimeoutWindow window);
    void (*show_connect_review)();
    LocalPinAuthConnectSessionResult (*replace_connect_session_from_pin)(
        const char* request_id);
    void (*finish_connect_session_error)(const char* request_id);
    void (*finish_connect_approved)(const char* request_id);
};

struct LocalPinAuthPolicyUpdateOps {
    bool (*show_policy_update_review)();
    bool (*require_pending_policy_update_session)(const char* request_id);
    PolicyUpdateFlowTransitionResult (*return_policy_update_review_from_pin)(
        TickType_t now,
        TimeoutWindow window);
    PolicyUpdateFlowTransitionResult (*return_policy_update_pin_entry_from_pin)();
    PolicyUpdateFlowTerminalResult (*record_policy_update_ui_error_from_pin)();
    PolicyUpdateFlowTerminalResult (*record_policy_update_timed_out_from_pin)(
        uint64_t uptime_ms);
    PolicyUpdateFlowTerminalResult (*commit_policy_update_from_pin)(
        uint64_t uptime_ms);
    void (*finish_policy_update_unavailable_from_pin)(
        const char* request_id,
        LocalPinAuthPolicyUpdateUnavailableReason reason);
    void (*finish_policy_update_terminal)(
        const char* request_id,
        PolicyUpdateFlowTerminalResult result);
    void (*finish_policy_update_error_terminal)(
        const char* request_id,
        const char* error_code,
        const char* error_message,
        const char* display_message);
};

struct LocalPinAuthSuiZkLoginOps {
    bool (*require_pending_sui_zklogin_proposal_session)(const char* request_id);
    LocalPinAuthSuiZkLoginPinBeginResult (*begin_sui_zklogin_proposal_pin_from_review)(
        const char* request_id,
        TickType_t now);
    SuiZkLoginProposalTransitionResult (*return_sui_zklogin_review_from_pin)(
        TickType_t now);
    SuiZkLoginProposalTransitionResult (*return_sui_zklogin_pin_entry_from_pin)();
    SuiZkLoginProposalTerminalResult (*record_sui_zklogin_ui_error_from_pin)();
    SuiZkLoginProposalTerminalResult (*record_sui_zklogin_timed_out_from_pin)();
    SuiZkLoginProposalTerminalResult (*record_sui_zklogin_rejected_from_pin)();
    SuiZkLoginProposalTerminalResult (*record_sui_zklogin_consistency_error_from_pin)();
    SuiZkLoginProposalTerminalResult (*commit_sui_zklogin_from_pin)();
    void (*finish_sui_zklogin_proposal_terminal)(
        const char* request_id,
        SuiZkLoginProposalTerminalResult result);
    void (*finish_sui_zklogin_proposal_error_terminal)(
        const char* request_id,
        const char* error_code,
        const char* error_message,
        const char* display_message);
    bool (*show_sui_zklogin_review)();
};

struct LocalPinAuthUserSigningOps {
    bool (*show_user_signing_review)();
    UserSigningConfirmationResult (*cancel_user_signing_for_pin_loss)();
    UserSigningConfirmationResult (*record_user_signing_timeout_from_pin)(
        TickType_t now);
    UserSigningConfirmationResult (*return_user_signing_review_from_pin)(
        TickType_t now,
        TimeoutWindow review_window);
    void (*cancel_user_signing_for_ui_loss)();
    UserSigningConfirmationResult (*complete_user_signing_pin_verify_from_pin)(
        const LocalAuthWorkerResult& worker_result,
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

struct LocalPinAuthUiFlowOps {
    LocalPinAuthTimingOps timing;
    LocalPinAuthDisplayOps display;
    LocalPinAuthMaterialSettingsOps material_settings;
    LocalPinAuthRequestOps request;
    LocalPinAuthConnectOps connect;
    LocalPinAuthPolicyUpdateOps policy_update;
    LocalPinAuthSuiZkLoginOps sui_zklogin;
    LocalPinAuthUserSigningOps user_signing;
};

bool local_pin_auth_ui_panel_matches_stage(UiPanelKind kind);
bool local_pin_auth_ui_accepts_keypad_input();
bool local_pin_auth_ui_begin_connect(
    const char* request_id,
    const LocalPinAuthUiFlowOps& ops);
bool local_pin_auth_ui_begin_sui_zklogin_proposal(
    const char* request_id,
    const LocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_start_settings_human_approval_input(
    const LocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_start_settings_signing_mode(
    const LocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_start_settings_policy_reset(
    const LocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_start_settings_change_pin(
    const LocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_start_settings_sui_accept_gas_sponsor(
    const LocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_start_settings_sui_zklogin_clear(
    const LocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_cancel(
    const char* message,
    const LocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_handle_digit(
    char digit,
    const LocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_handle_clear(const LocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_handle_backspace(const LocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_handle_submit(const LocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_commit_setting_if_ready(
    const LocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_handle_verify_worker_result(
    const LocalAuthWorkerResult& worker_result,
    const LocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_handle_prepare_worker_result(
    const LocalAuthWorkerResult& worker_result,
    const LocalPinAuthUiFlowOps& ops);
void local_pin_auth_ui_clear_if_needed(const LocalPinAuthUiFlowOps& ops);

}  // namespace signing
