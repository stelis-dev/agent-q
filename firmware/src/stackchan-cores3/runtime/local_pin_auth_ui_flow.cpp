#include "local_pin_auth_ui_flow.h"

#include <stdio.h>
#include <string.h>

#include "identification_display.h"
#include "protocol/protocol_constants.h"
#include "storage_maintenance.h"
#include "modal_transition.h"
#include "request_backed_local_pin_context.h"

namespace signing {
namespace {

constexpr size_t kMaxRequestIdSize = kRequestIdSize;

TickType_t now_or_zero(const LocalPinAuthUiFlowOps& ops)
{
    return ops.timing.now != nullptr ? ops.timing.now() : 0;
}

uint64_t wall_clock_ms_or_zero(const LocalPinAuthUiFlowOps& ops)
{
    return ops.timing.wall_clock_ms != nullptr ? ops.timing.wall_clock_ms() : 0;
}

TimeoutWindow window_from_now_ms(
    const LocalPinAuthUiFlowOps& ops,
    uint32_t duration_ms)
{
    const TickType_t now = now_or_zero(ops);
    return timeout_window_from_deadline(now, now + pdMS_TO_TICKS(duration_ms));
}

bool provisioned_material_ready(const LocalPinAuthUiFlowOps& ops)
{
    return ops.material_settings.provisioned_material_ready != nullptr &&
           ops.material_settings.provisioned_material_ready();
}

ModalTransitionOps modal_transition_ops(const LocalPinAuthUiFlowOps& ops)
{
    return ModalTransitionOps{
        ops.display.clear_panel_if_kind,
        ops.display.draw_processing_overlay_on_current_panel,
        ops.display.log_warn,
    };
}

bool draw_local_pin_panel(
    const LocalPinAuthUiFlowOps& ops,
    const char* notice = nullptr)
{
    return ops.display.draw_local_pin_auth_panel != nullptr &&
           ops.display.draw_local_pin_auth_panel(notice);
}

struct LocalPinPanelDrawContext {
    const LocalPinAuthUiFlowOps* ops = nullptr;
    const char* notice = nullptr;
};

bool draw_local_pin_panel_for_transition(void* context)
{
    const auto* draw_context = static_cast<const LocalPinPanelDrawContext*>(context);
    return draw_context != nullptr &&
           draw_context->ops != nullptr &&
           draw_local_pin_panel(*draw_context->ops, draw_context->notice);
}

bool draw_processing_or_local_pin_panel(const LocalPinAuthUiFlowOps& ops)
{
    LocalPinPanelDrawContext context{&ops, nullptr};
    return modal_transition_show_processing_or_redraw_panel(
        modal_transition_ops(ops),
        UiPanelKind::local_pin_auth,
        draw_local_pin_panel_for_transition,
        &context);
}

void show_message(
    const LocalPinAuthUiFlowOps& ops,
    const char* message,
    MessageKind kind)
{
    if (ops.display.show_message != nullptr) {
        ops.display.show_message(message, kind);
    }
}

void record_material_failure(
    const LocalPinAuthUiFlowOps& ops,
    PersistentMaterialRuntimeFailure failure)
{
    if (ops.material_settings.record_material_failure != nullptr) {
        ops.material_settings.record_material_failure(failure);
    }
}

void log_warn(const LocalPinAuthUiFlowOps& ops, const char* message)
{
    if (ops.display.log_warn != nullptr) {
        ops.display.log_warn(message);
    }
}

void write_connect_rejected_from_pin(
    const LocalPinAuthUiFlowOps& ops,
    const char* request_id,
    LocalPinAuthConnectRejectReason reason)
{
    if (ops.connect.write_connect_rejected_from_pin != nullptr) {
        ops.connect.write_connect_rejected_from_pin(request_id, reason);
    }
}

void finish_connect_rejection_cleanup(
    const LocalPinAuthUiFlowOps& ops,
    bool clear_protocol_pin)
{
    if (ops.connect.finish_connect_rejection_cleanup != nullptr) {
        ops.connect.finish_connect_rejection_cleanup(clear_protocol_pin);
    }
}

bool return_connect_review_from_pin(
    const LocalPinAuthUiFlowOps& ops,
    TickType_t now,
    TimeoutWindow window)
{
    return ops.connect.return_connect_review_from_pin != nullptr &&
           ops.connect.return_connect_review_from_pin(now, window);
}

LocalPinAuthConnectSessionResult replace_connect_session_from_pin(
    const LocalPinAuthUiFlowOps& ops,
    const char* request_id)
{
    return ops.connect.replace_connect_session_from_pin != nullptr
               ? ops.connect.replace_connect_session_from_pin(request_id)
               : LocalPinAuthConnectSessionResult::session_unavailable;
}

void finish_connect_session_error(
    const LocalPinAuthUiFlowOps& ops,
    const char* request_id)
{
    if (ops.connect.finish_connect_session_error != nullptr) {
        ops.connect.finish_connect_session_error(request_id);
    }
}

void finish_connect_approved(
    const LocalPinAuthUiFlowOps& ops,
    const char* request_id)
{
    if (ops.connect.finish_connect_approved != nullptr) {
        ops.connect.finish_connect_approved(request_id);
    }
}

void clear_local_pin_auth_scratch(
    const LocalPinAuthUiFlowOps& ops,
    const char* reason)
{
    const bool had_pin_auth = local_pin_auth_flow_active();
    const bool cleared = local_pin_auth_clear_flow();
    if (had_pin_auth && cleared) {
        log_warn(ops, reason != nullptr ? reason : "local PIN authorization scratch wiped");
    }
}

void finish_policy_update_terminal(
    const LocalPinAuthUiFlowOps& ops,
    const char* request_id,
    PolicyUpdateFlowTerminalResult result)
{
    if (ops.policy_update.finish_policy_update_terminal != nullptr) {
        ops.policy_update.finish_policy_update_terminal(request_id, result);
    }
}

void finish_policy_update_error_terminal(
    const LocalPinAuthUiFlowOps& ops,
    const char* request_id,
    const char* error_code,
    const char* error_message,
    const char* display_message)
{
    if (ops.policy_update.finish_policy_update_error_terminal != nullptr) {
        ops.policy_update.finish_policy_update_error_terminal(
            request_id,
            error_code,
            error_message,
            display_message);
    }
}

PolicyUpdateFlowTransitionResult return_policy_update_review_from_pin(
    const LocalPinAuthUiFlowOps& ops,
    TickType_t now,
    TimeoutWindow window)
{
    return ops.policy_update.return_policy_update_review_from_pin != nullptr
               ? ops.policy_update.return_policy_update_review_from_pin(now, window)
               : PolicyUpdateFlowTransitionResult::invalid_argument;
}

PolicyUpdateFlowTransitionResult return_policy_update_pin_entry_from_pin(
    const LocalPinAuthUiFlowOps& ops)
{
    return ops.policy_update.return_policy_update_pin_entry_from_pin != nullptr
               ? ops.policy_update.return_policy_update_pin_entry_from_pin()
               : PolicyUpdateFlowTransitionResult::invalid_argument;
}

PolicyUpdateFlowTerminalResult record_policy_update_ui_error_from_pin(
    const LocalPinAuthUiFlowOps& ops)
{
    return ops.policy_update.record_policy_update_ui_error_from_pin != nullptr
               ? ops.policy_update.record_policy_update_ui_error_from_pin()
               : PolicyUpdateFlowTerminalResult::ui_error;
}

PolicyUpdateFlowTerminalResult record_policy_update_timed_out_from_pin(
    const LocalPinAuthUiFlowOps& ops)
{
    return ops.policy_update.record_policy_update_timed_out_from_pin != nullptr
               ? ops.policy_update.record_policy_update_timed_out_from_pin(wall_clock_ms_or_zero(ops))
               : PolicyUpdateFlowTerminalResult::timed_out;
}

PolicyUpdateFlowTerminalResult commit_policy_update_from_pin(
    const LocalPinAuthUiFlowOps& ops)
{
    return ops.policy_update.commit_policy_update_from_pin != nullptr
               ? ops.policy_update.commit_policy_update_from_pin(wall_clock_ms_or_zero(ops))
               : PolicyUpdateFlowTerminalResult::invalid_state;
}

bool request_id_for_pin(
    const LocalPinAuthUiFlowOps& ops,
    LocalPinAuthPurpose purpose,
    char* output,
    size_t output_size)
{
    if (output != nullptr && output_size > 0) {
        output[0] = '\0';
    }
    return ops.request.request_id_for_pin != nullptr &&
           ops.request.request_id_for_pin(purpose, output, output_size);
}

void finish_policy_update_unavailable_from_pin(
    const LocalPinAuthUiFlowOps& ops,
    const char* request_id,
    LocalPinAuthPolicyUpdateUnavailableReason reason)
{
    if (ops.policy_update.finish_policy_update_unavailable_from_pin != nullptr) {
        ops.policy_update.finish_policy_update_unavailable_from_pin(request_id, reason);
    }
}

void finish_user_signing_terminal(
    const LocalPinAuthUiFlowOps& ops,
    const char* request_id)
{
    if (ops.user_signing.finish_user_signing_terminal != nullptr) {
        ops.user_signing.finish_user_signing_terminal(request_id);
    }
}

void finish_user_signing_error_terminal(
    const LocalPinAuthUiFlowOps& ops,
    const char* request_id,
    const char* error_code,
    const char* error_message,
    const char* display_message)
{
    if (ops.user_signing.finish_user_signing_error_terminal != nullptr) {
        ops.user_signing.finish_user_signing_error_terminal(
            request_id,
            error_code,
            error_message,
            display_message);
    }
}

UserSigningConfirmationResult cancel_user_signing_for_pin_loss(
    const LocalPinAuthUiFlowOps& ops)
{
    return ops.user_signing.cancel_user_signing_for_pin_loss != nullptr
               ? ops.user_signing.cancel_user_signing_for_pin_loss()
               : UserSigningConfirmationResult::inactive;
}

UserSigningConfirmationResult record_user_signing_timeout_from_pin(
    const LocalPinAuthUiFlowOps& ops,
    TickType_t now)
{
    return ops.user_signing.record_user_signing_timeout_from_pin != nullptr
               ? ops.user_signing.record_user_signing_timeout_from_pin(now)
               : UserSigningConfirmationResult::invalid_argument;
}

UserSigningConfirmationResult return_user_signing_review_from_pin(
    const LocalPinAuthUiFlowOps& ops,
    TickType_t now,
    TimeoutWindow review_window)
{
    return ops.user_signing.return_user_signing_review_from_pin != nullptr
               ? ops.user_signing.return_user_signing_review_from_pin(now, review_window)
               : UserSigningConfirmationResult::invalid_argument;
}

void cancel_user_signing_for_ui_loss(const LocalPinAuthUiFlowOps& ops)
{
    if (ops.user_signing.cancel_user_signing_for_ui_loss != nullptr) {
        ops.user_signing.cancel_user_signing_for_ui_loss();
    }
}

UserSigningConfirmationResult complete_user_signing_pin_verify_from_pin(
    const LocalPinAuthUiFlowOps& ops,
    const LocalAuthWorkerResult& worker_result,
    TickType_t now,
    TickType_t lockout_until,
    bool authorization_available)
{
    return ops.user_signing.complete_user_signing_pin_verify_from_pin != nullptr
               ? ops.user_signing.complete_user_signing_pin_verify_from_pin(
                   worker_result,
                   now,
                   lockout_until,
                   authorization_available)
               : UserSigningConfirmationResult::invalid_argument;
}

bool user_signing_terminal_pending_from_pin(const LocalPinAuthUiFlowOps& ops)
{
    return ops.user_signing.user_signing_terminal_pending_from_pin != nullptr &&
           ops.user_signing.user_signing_terminal_pending_from_pin();
}

SuiZkLoginProposalTransitionResult return_sui_zklogin_review_from_pin(
    const LocalPinAuthUiFlowOps& ops,
    TickType_t now)
{
    return ops.sui_zklogin.return_sui_zklogin_review_from_pin != nullptr
               ? ops.sui_zklogin.return_sui_zklogin_review_from_pin(now)
               : SuiZkLoginProposalTransitionResult::invalid_argument;
}

SuiZkLoginProposalTransitionResult return_sui_zklogin_pin_entry_from_pin(
    const LocalPinAuthUiFlowOps& ops)
{
    return ops.sui_zklogin.return_sui_zklogin_pin_entry_from_pin != nullptr
               ? ops.sui_zklogin.return_sui_zklogin_pin_entry_from_pin()
               : SuiZkLoginProposalTransitionResult::invalid_argument;
}

SuiZkLoginProposalTerminalResult record_sui_zklogin_ui_error_from_pin(
    const LocalPinAuthUiFlowOps& ops)
{
    return ops.sui_zklogin.record_sui_zklogin_ui_error_from_pin != nullptr
               ? ops.sui_zklogin.record_sui_zklogin_ui_error_from_pin()
               : SuiZkLoginProposalTerminalResult::ui_error;
}

SuiZkLoginProposalTerminalResult record_sui_zklogin_timed_out_from_pin(
    const LocalPinAuthUiFlowOps& ops)
{
    return ops.sui_zklogin.record_sui_zklogin_timed_out_from_pin != nullptr
               ? ops.sui_zklogin.record_sui_zklogin_timed_out_from_pin()
               : SuiZkLoginProposalTerminalResult::timed_out;
}

SuiZkLoginProposalTerminalResult record_sui_zklogin_rejected_from_pin(
    const LocalPinAuthUiFlowOps& ops)
{
    return ops.sui_zklogin.record_sui_zklogin_rejected_from_pin != nullptr
               ? ops.sui_zklogin.record_sui_zklogin_rejected_from_pin()
               : SuiZkLoginProposalTerminalResult::rejected;
}

SuiZkLoginProposalTerminalResult record_sui_zklogin_consistency_error_from_pin(
    const LocalPinAuthUiFlowOps& ops)
{
    return ops.sui_zklogin.record_sui_zklogin_consistency_error_from_pin != nullptr
               ? ops.sui_zklogin.record_sui_zklogin_consistency_error_from_pin()
               : SuiZkLoginProposalTerminalResult::consistency_error;
}

SuiZkLoginProposalTerminalResult commit_sui_zklogin_from_pin(
    const LocalPinAuthUiFlowOps& ops)
{
    return ops.sui_zklogin.commit_sui_zklogin_from_pin != nullptr
               ? ops.sui_zklogin.commit_sui_zklogin_from_pin()
               : SuiZkLoginProposalTerminalResult::invalid_state;
}

void finish_sui_zklogin_proposal_terminal(
    const LocalPinAuthUiFlowOps& ops,
    const char* request_id,
    SuiZkLoginProposalTerminalResult result)
{
    if (ops.sui_zklogin.finish_sui_zklogin_proposal_terminal != nullptr) {
        ops.sui_zklogin.finish_sui_zklogin_proposal_terminal(request_id, result);
    }
}

void finish_sui_zklogin_proposal_error_terminal(
    const LocalPinAuthUiFlowOps& ops,
    const char* request_id,
    const char* error_code,
    const char* error_message,
    const char* display_message)
{
    if (ops.sui_zklogin.finish_sui_zklogin_proposal_error_terminal != nullptr) {
        ops.sui_zklogin.finish_sui_zklogin_proposal_error_terminal(
            request_id,
            error_code,
            error_message,
            display_message);
    }
}

void complete_local_pin_processing_to_message(
    const LocalPinAuthUiFlowOps& ops,
    const char* message,
    MessageKind kind);
void complete_local_pin_to_policy_error_terminal(
    const LocalPinAuthUiFlowOps& ops,
    const char* request_id,
    const char* error_code,
    const char* error_message,
    const char* display_message);
void complete_local_pin_processing_to_policy_terminal(
    const LocalPinAuthUiFlowOps& ops,
    const char* request_id,
    PolicyUpdateFlowTerminalResult result);
void complete_local_pin_to_user_error_terminal(
    const LocalPinAuthUiFlowOps& ops,
    const char* request_id,
    const char* error_code,
    const char* error_message,
    const char* display_message);
void complete_local_pin_to_user_terminal(
    const LocalPinAuthUiFlowOps& ops,
    const char* request_id);
void complete_local_pin_processing_to_sui_zklogin_terminal(
    const LocalPinAuthUiFlowOps& ops,
    const char* request_id,
    SuiZkLoginProposalTerminalResult result);
void complete_local_pin_to_sui_zklogin_error_terminal(
    const LocalPinAuthUiFlowOps& ops,
    const char* request_id,
    const char* error_code,
    const char* error_message,
    const char* display_message);

TimeoutWindow local_pin_auth_next_input_window(
    LocalPinAuthPurpose purpose,
    TickType_t now,
    const LocalPinAuthUiFlowOps& ops)
{
    const TimeoutWindow next_input_window =
        timeout_window_from_deadline(
            now,
            now + pdMS_TO_TICKS(ops.timing.local_pin_input_window_ms));
    if (local_pin_auth_settings_purpose(purpose)) {
        return next_input_window;
    }
    if (!request_backed_local_pin_purpose(purpose)) {
        return kTimeoutWindowNone;
    }
    return request_backed_local_pin_cap_input_window(purpose, now, next_input_window);
}

bool resume_request_backed_pin_input_window(
    LocalPinAuthPurpose purpose,
    TickType_t now)
{
    return request_backed_local_pin_resume_input_window(purpose, now);
}

bool pause_request_backed_pin_input_window(
    LocalPinAuthPurpose purpose,
    TickType_t now)
{
    return request_backed_local_pin_pause_input_window(purpose, now);
}

bool request_backed_local_pin_input_deadline_reached(
    LocalPinAuthPurpose purpose,
    TickType_t now)
{
    return request_backed_local_pin_deadline_reached(purpose, now);
}

void handle_local_pin_auth_display_failure(
    const char* reason,
    bool clear_panel,
    const LocalPinAuthUiFlowOps& ops)
{
    const LocalPinAuthSnapshot snapshot =
        local_pin_auth_snapshot(now_or_zero(ops));
    char request_id[kMaxRequestIdSize] = {};
    if (snapshot.purpose == LocalPinAuthPurpose::policy_update) {
        request_id_for_pin(
            ops,
            LocalPinAuthPurpose::policy_update,
            request_id,
            sizeof(request_id));
        if (request_id[0] != '\0') {
            clear_local_pin_auth_scratch(ops, reason);
            if (clear_panel) {
                complete_local_pin_processing_to_policy_terminal(
                    ops,
                    request_id,
                    record_policy_update_ui_error_from_pin(ops));
                return;
            }
            finish_policy_update_terminal(
                ops,
                request_id,
                record_policy_update_ui_error_from_pin(ops));
            return;
        }
    }
    if (snapshot.purpose == LocalPinAuthPurpose::user_signing &&
        request_id_for_pin(
            ops,
            LocalPinAuthPurpose::user_signing,
            request_id,
            sizeof(request_id))) {
        cancel_user_signing_for_pin_loss(ops);
        clear_local_pin_auth_scratch(ops, reason);
        if (clear_panel) {
            complete_local_pin_to_user_error_terminal(
                ops,
                request_id,
                "ui_error",
                "Could not show signing PIN UI.",
                "Display error");
            return;
        }
        finish_user_signing_error_terminal(
            ops,
            request_id,
            "ui_error",
            "Could not show signing PIN UI.",
            "Display error");
        return;
    }
    if (snapshot.purpose == LocalPinAuthPurpose::sui_zklogin_proposal &&
        request_id_for_pin(
            ops,
            LocalPinAuthPurpose::sui_zklogin_proposal,
            request_id,
            sizeof(request_id))) {
        clear_local_pin_auth_scratch(ops, reason);
        if (clear_panel) {
            complete_local_pin_processing_to_sui_zklogin_terminal(
                ops,
                request_id,
                record_sui_zklogin_ui_error_from_pin(ops));
            return;
        }
        finish_sui_zklogin_proposal_terminal(
            ops,
            request_id,
            record_sui_zklogin_ui_error_from_pin(ops));
        return;
    }
    if (snapshot.purpose == LocalPinAuthPurpose::connect &&
        request_id_for_pin(
            ops,
            LocalPinAuthPurpose::connect,
            request_id,
            sizeof(request_id))) {
        clear_local_pin_auth_scratch(ops, reason);
        write_connect_rejected_from_pin(
            ops,
            request_id,
            LocalPinAuthConnectRejectReason::ui_error);
        finish_connect_rejection_cleanup(ops, true);
        if (clear_panel) {
            complete_local_pin_processing_to_message(
                ops,
                "Display error",
                MessageKind::error);
            return;
        }
        show_message(ops, "Display error", MessageKind::error);
        return;
    }
    clear_local_pin_auth_scratch(ops, reason);
    if (clear_panel) {
        complete_local_pin_processing_to_message(
            ops,
            "Display error",
            MessageKind::error);
        return;
    }
    show_message(ops, "Display error", MessageKind::error);
}

bool finish_request_backed_local_pin_input_timeout_if_reached(
    LocalPinAuthPurpose purpose,
    TickType_t now,
    const char* scratch_reason,
    const LocalPinAuthUiFlowOps& ops)
{
    if (!request_backed_local_pin_input_deadline_reached(purpose, now)) {
        return false;
    }

    char request_id[kMaxRequestIdSize] = {};
    request_id_for_pin(ops, purpose, request_id, sizeof(request_id));
    clear_local_pin_auth_scratch(ops, scratch_reason);
    switch (request_backed_local_pin_owner_for_purpose(purpose)) {
        case RequestBackedLocalPinOwner::protocol_pin_approval:
            if (purpose == LocalPinAuthPurpose::policy_update &&
                request_id[0] != '\0') {
                complete_local_pin_processing_to_policy_terminal(
                    ops,
                    request_id,
                    record_policy_update_timed_out_from_pin(ops));
                return true;
            }
            if (purpose == LocalPinAuthPurpose::sui_zklogin_proposal &&
                request_id[0] != '\0') {
                complete_local_pin_processing_to_sui_zklogin_terminal(
                    ops,
                    request_id,
                    record_sui_zklogin_timed_out_from_pin(ops));
                return true;
            }
            if (purpose == LocalPinAuthPurpose::connect &&
                request_id[0] != '\0') {
                write_connect_rejected_from_pin(
                    ops,
                    request_id,
                    LocalPinAuthConnectRejectReason::timeout);
                finish_connect_rejection_cleanup(ops, true);
                complete_local_pin_processing_to_message(
                    ops,
                    "Connection timed out",
                    MessageKind::timeout);
                return true;
            }
            break;
        case RequestBackedLocalPinOwner::user_signing:
            if (request_id[0] != '\0') {
                const UserSigningConfirmationResult result =
                    record_user_signing_timeout_from_pin(ops, now);
                if (result == UserSigningConfirmationResult::ok ||
                    user_signing_terminal_pending_from_pin(ops)) {
                    complete_local_pin_to_user_terminal(ops, request_id);
                } else {
                    complete_local_pin_to_user_error_terminal(
                        ops,
                        request_id,
                        "invalid_state",
                        "Signing request is unavailable.",
                        "Signing unavailable");
                }
                return true;
            }
            break;
        case RequestBackedLocalPinOwner::none:
        default:
            break;
    }
    complete_local_pin_processing_to_message(
        ops,
        "Auth timed out",
        MessageKind::timeout);
    return false;
}

bool start_settings_handoff(
    const char* stale_message,
    const LocalPinAuthUiFlowOps& ops)
{
    if (!local_pin_auth_settings_start_available()) {
        log_warn(ops, stale_message);
        return false;
    }
    return ops.material_settings.begin_settings_pin_auth_handoff != nullptr &&
           ops.material_settings.begin_settings_pin_auth_handoff(stale_message);
}

void show_settings_error(const LocalPinAuthUiFlowOps& ops)
{
    complete_local_pin_processing_to_message(
        ops,
        "Settings error",
        MessageKind::error);
}

bool restore_settings_menu_after_pin(
    const char* wipe_reason,
    const char* message,
    MessageKind kind,
    const LocalPinAuthUiFlowOps& ops)
{
    if (ops.material_settings.restore_settings_menu == nullptr) {
        return false;
    }
    ops.material_settings.restore_settings_menu(wipe_reason, message, kind);
    return true;
}

bool restore_sui_settings_after_pin(
    const char* wipe_reason,
    const char* message,
    MessageKind kind,
    const LocalPinAuthUiFlowOps& ops)
{
    if (ops.material_settings.restore_sui_settings == nullptr) {
        return false;
    }
    ops.material_settings.restore_sui_settings(wipe_reason, message, kind);
    return true;
}

struct RestoreSettingsContext {
    const LocalPinAuthUiFlowOps* ops = nullptr;
    const char* wipe_reason = nullptr;
    const char* message = nullptr;
    MessageKind kind = MessageKind::info;
};

bool restore_settings_menu_for_transition(void* context)
{
    const auto* restore_context = static_cast<const RestoreSettingsContext*>(context);
    if (restore_context == nullptr || restore_context->ops == nullptr) {
        return false;
    }
    return restore_settings_menu_after_pin(
        restore_context->wipe_reason,
        restore_context->message,
        restore_context->kind,
        *restore_context->ops);
}

bool restore_sui_settings_for_transition(void* context)
{
    const auto* restore_context = static_cast<const RestoreSettingsContext*>(context);
    if (restore_context == nullptr || restore_context->ops == nullptr) {
        return false;
    }
    return restore_sui_settings_after_pin(
        restore_context->wipe_reason,
        restore_context->message,
        restore_context->kind,
        *restore_context->ops);
}

void complete_local_pin_processing_to_settings(
    const LocalPinAuthUiFlowOps& ops,
    const char* wipe_reason,
    const char* message,
    MessageKind kind)
{
    RestoreSettingsContext context{&ops, wipe_reason, message, kind};
    modal_transition_complete_to_next_panel(
        modal_transition_ops(ops),
        UiPanelKind::local_pin_auth,
        restore_settings_menu_for_transition,
        &context);
}

void complete_local_pin_processing_to_sui_settings(
    const LocalPinAuthUiFlowOps& ops,
    const char* wipe_reason,
    const char* message,
    MessageKind kind)
{
    RestoreSettingsContext context{&ops, wipe_reason, message, kind};
    modal_transition_complete_to_next_panel(
        modal_transition_ops(ops),
        UiPanelKind::local_pin_auth,
        restore_sui_settings_for_transition,
        &context);
}

void complete_local_pin_settings_completion(
    const LocalPinAuthUiFlowOps& ops,
    LocalPinAuthSettingsCompletionResult result)
{
    switch (result) {
        case LocalPinAuthSettingsCompletionResult::not_ready:
            return;
        case LocalPinAuthSettingsCompletionResult::settings_saved:
            complete_local_pin_processing_to_settings(
                ops,
                "local settings display allocation failed after PIN commit",
                "Settings saved",
                MessageKind::success);
            return;
        case LocalPinAuthSettingsCompletionResult::settings_error:
            complete_local_pin_processing_to_message(
                ops,
                "Settings error",
                MessageKind::error);
            return;
        case LocalPinAuthSettingsCompletionResult::sui_settings_saved:
            complete_local_pin_processing_to_sui_settings(
                ops,
                "local Sui settings display allocation failed after PIN commit",
                "Settings saved",
                MessageKind::success);
            return;
        case LocalPinAuthSettingsCompletionResult::sui_settings_error:
            complete_local_pin_processing_to_sui_settings(
                ops,
                "local Sui settings display allocation failed after setting storage error",
                "Settings error",
                MessageKind::error);
            return;
        case LocalPinAuthSettingsCompletionResult::pin_changed:
            complete_local_pin_processing_to_settings(
                ops,
                "local settings display allocation failed after PIN commit",
                "PIN changed",
                MessageKind::success);
            return;
        case LocalPinAuthSettingsCompletionResult::pin_change_failed:
            complete_local_pin_processing_to_message(
                ops,
                "PIN change failed",
                MessageKind::error);
            return;
        case LocalPinAuthSettingsCompletionResult::auth_error:
            record_material_failure(
                ops,
                PersistentMaterialRuntimeFailure::pin_change_auth_unavailable);
            complete_local_pin_processing_to_message(
                ops,
                "Auth error",
                MessageKind::error);
            return;
        case LocalPinAuthSettingsCompletionResult::policy_reset:
            complete_local_pin_processing_to_settings(
                ops,
                "local settings display allocation failed after policy reset",
                "Policy reset",
                MessageKind::success);
            return;
        case LocalPinAuthSettingsCompletionResult::policy_reset_failed:
            complete_local_pin_processing_to_settings(
                ops,
                "local settings display allocation failed after policy reset",
                "Policy reset failed",
                MessageKind::error);
            return;
        case LocalPinAuthSettingsCompletionResult::sui_proof_cleared:
            complete_local_pin_processing_to_sui_settings(
                ops,
                "local settings display allocation failed after Sui clear",
                "Sui proof cleared",
                MessageKind::success);
            return;
        case LocalPinAuthSettingsCompletionResult::sui_clear_failed:
            complete_local_pin_processing_to_sui_settings(
                ops,
                "local settings display allocation failed after Sui clear",
                "Sui clear failed",
                MessageKind::error);
            return;
    }
}

struct ShowMessageContext {
    const LocalPinAuthUiFlowOps* ops = nullptr;
    const char* message = nullptr;
    MessageKind kind = MessageKind::info;
};

void show_message_for_transition(void* context)
{
    const auto* message_context = static_cast<const ShowMessageContext*>(context);
    if (message_context == nullptr || message_context->ops == nullptr) {
        return;
    }
    show_message(*message_context->ops, message_context->message, message_context->kind);
}

void complete_local_pin_processing_to_message(
    const LocalPinAuthUiFlowOps& ops,
    const char* message,
    MessageKind kind)
{
    ShowMessageContext context{&ops, message, kind};
    modal_transition_complete_processing_to_result(
        modal_transition_ops(ops),
        UiPanelKind::local_pin_auth,
        show_message_for_transition,
        &context);
}

struct PolicyUpdateErrorTerminalContext {
    const LocalPinAuthUiFlowOps* ops = nullptr;
    const char* request_id = nullptr;
    const char* error_code = nullptr;
    const char* error_message = nullptr;
    const char* display_message = nullptr;
};

void finish_policy_update_error_terminal_for_transition(void* context)
{
    const auto* terminal_context =
        static_cast<const PolicyUpdateErrorTerminalContext*>(context);
    if (terminal_context == nullptr || terminal_context->ops == nullptr) {
        return;
    }
    finish_policy_update_error_terminal(
        *terminal_context->ops,
        terminal_context->request_id,
        terminal_context->error_code,
        terminal_context->error_message,
        terminal_context->display_message);
}

void complete_local_pin_to_policy_error_terminal(
    const LocalPinAuthUiFlowOps& ops,
    const char* request_id,
    const char* error_code,
    const char* error_message,
    const char* display_message)
{
    PolicyUpdateErrorTerminalContext context{
        &ops,
        request_id,
        error_code,
        error_message,
        display_message};
    modal_transition_complete_to_result(
        modal_transition_ops(ops),
        UiPanelKind::local_pin_auth,
        finish_policy_update_error_terminal_for_transition,
        &context);
}

struct PolicyUpdateTerminalContext {
    const LocalPinAuthUiFlowOps* ops = nullptr;
    const char* request_id = nullptr;
    PolicyUpdateFlowTerminalResult result =
        PolicyUpdateFlowTerminalResult::invalid_state;
};

void finish_policy_update_terminal_for_transition(void* context)
{
    const auto* terminal_context = static_cast<const PolicyUpdateTerminalContext*>(context);
    if (terminal_context == nullptr || terminal_context->ops == nullptr) {
        return;
    }
    finish_policy_update_terminal(
        *terminal_context->ops,
        terminal_context->request_id,
        terminal_context->result);
}

void complete_local_pin_processing_to_policy_terminal(
    const LocalPinAuthUiFlowOps& ops,
    const char* request_id,
    PolicyUpdateFlowTerminalResult result)
{
    PolicyUpdateTerminalContext context{&ops, request_id, result};
    modal_transition_complete_processing_to_result(
        modal_transition_ops(ops),
        UiPanelKind::local_pin_auth,
        finish_policy_update_terminal_for_transition,
        &context);
}

struct UserDeviceRequestErrorTerminalContext {
    const LocalPinAuthUiFlowOps* ops = nullptr;
    const char* request_id = nullptr;
    const char* error_code = nullptr;
    const char* error_message = nullptr;
    const char* display_message = nullptr;
};

void finish_user_signing_error_terminal_for_transition(void* context)
{
    const auto* terminal_context =
        static_cast<const UserDeviceRequestErrorTerminalContext*>(context);
    if (terminal_context == nullptr || terminal_context->ops == nullptr) {
        return;
    }
    finish_user_signing_error_terminal(
        *terminal_context->ops,
        terminal_context->request_id,
        terminal_context->error_code,
        terminal_context->error_message,
        terminal_context->display_message);
}

void complete_local_pin_to_user_error_terminal(
    const LocalPinAuthUiFlowOps& ops,
    const char* request_id,
    const char* error_code,
    const char* error_message,
    const char* display_message)
{
    UserDeviceRequestErrorTerminalContext context{
        &ops,
        request_id,
        error_code,
        error_message,
        display_message};
    modal_transition_complete_to_result(
        modal_transition_ops(ops),
        UiPanelKind::local_pin_auth,
        finish_user_signing_error_terminal_for_transition,
        &context);
}

struct UserSigningTerminalContext {
    const LocalPinAuthUiFlowOps* ops = nullptr;
    const char* request_id = nullptr;
};

void finish_user_signing_terminal_for_transition(void* context)
{
    const auto* terminal_context = static_cast<const UserSigningTerminalContext*>(context);
    if (terminal_context == nullptr || terminal_context->ops == nullptr) {
        return;
    }
    finish_user_signing_terminal(*terminal_context->ops, terminal_context->request_id);
}

void complete_local_pin_to_user_terminal(
    const LocalPinAuthUiFlowOps& ops,
    const char* request_id)
{
    UserSigningTerminalContext context{&ops, request_id};
    modal_transition_complete_to_result(
        modal_transition_ops(ops),
        UiPanelKind::local_pin_auth,
        finish_user_signing_terminal_for_transition,
        &context);
}

struct SuiZkLoginProposalErrorTerminalContext {
    const LocalPinAuthUiFlowOps* ops = nullptr;
    const char* request_id = nullptr;
    const char* error_code = nullptr;
    const char* error_message = nullptr;
    const char* display_message = nullptr;
};

void finish_sui_zklogin_proposal_error_terminal_for_transition(void* context)
{
    const auto* terminal_context =
        static_cast<const SuiZkLoginProposalErrorTerminalContext*>(context);
    if (terminal_context == nullptr || terminal_context->ops == nullptr) {
        return;
    }
    finish_sui_zklogin_proposal_error_terminal(
        *terminal_context->ops,
        terminal_context->request_id,
        terminal_context->error_code,
        terminal_context->error_message,
        terminal_context->display_message);
}

void complete_local_pin_to_sui_zklogin_error_terminal(
    const LocalPinAuthUiFlowOps& ops,
    const char* request_id,
    const char* error_code,
    const char* error_message,
    const char* display_message)
{
    SuiZkLoginProposalErrorTerminalContext context{
        &ops,
        request_id,
        error_code,
        error_message,
        display_message};
    modal_transition_complete_to_result(
        modal_transition_ops(ops),
        UiPanelKind::local_pin_auth,
        finish_sui_zklogin_proposal_error_terminal_for_transition,
        &context);
}

struct SuiZkLoginProposalTerminalContext {
    const LocalPinAuthUiFlowOps* ops = nullptr;
    const char* request_id = nullptr;
    SuiZkLoginProposalTerminalResult result =
        SuiZkLoginProposalTerminalResult::invalid_state;
};

void finish_sui_zklogin_proposal_terminal_for_transition(void* context)
{
    const auto* terminal_context =
        static_cast<const SuiZkLoginProposalTerminalContext*>(context);
    if (terminal_context == nullptr || terminal_context->ops == nullptr) {
        return;
    }
    finish_sui_zklogin_proposal_terminal(
        *terminal_context->ops,
        terminal_context->request_id,
        terminal_context->result);
}

void complete_local_pin_processing_to_sui_zklogin_terminal(
    const LocalPinAuthUiFlowOps& ops,
    const char* request_id,
    SuiZkLoginProposalTerminalResult result)
{
    SuiZkLoginProposalTerminalContext context{&ops, request_id, result};
    modal_transition_complete_processing_to_result(
        modal_transition_ops(ops),
        UiPanelKind::local_pin_auth,
        finish_sui_zklogin_proposal_terminal_for_transition,
        &context);
}

struct DrawReviewPanelContext {
    const LocalPinAuthUiFlowOps* ops = nullptr;
    LocalPinAuthPurpose purpose = LocalPinAuthPurpose::none;
};

bool draw_review_panel_for_transition(void* context)
{
    const auto* draw_context = static_cast<const DrawReviewPanelContext*>(context);
    if (draw_context == nullptr || draw_context->ops == nullptr) {
        return false;
    }
    switch (draw_context->purpose) {
        case LocalPinAuthPurpose::policy_update:
            return draw_context->ops->policy_update.show_policy_update_review != nullptr &&
                   draw_context->ops->policy_update.show_policy_update_review();
        case LocalPinAuthPurpose::connect:
            if (draw_context->ops->connect.show_connect_review == nullptr) {
                return false;
            }
            draw_context->ops->connect.show_connect_review();
            return true;
        case LocalPinAuthPurpose::user_signing:
            return draw_context->ops->user_signing.show_user_signing_review != nullptr &&
                   draw_context->ops->user_signing.show_user_signing_review();
        case LocalPinAuthPurpose::sui_zklogin_proposal:
            return draw_context->ops->sui_zklogin.show_sui_zklogin_review != nullptr &&
                   draw_context->ops->sui_zklogin.show_sui_zklogin_review();
        default:
            return false;
    }
}

bool complete_local_pin_to_review_panel(
    const LocalPinAuthUiFlowOps& ops,
    LocalPinAuthPurpose purpose)
{
    DrawReviewPanelContext context{&ops, purpose};
    return modal_transition_complete_to_next_panel(
        modal_transition_ops(ops),
        UiPanelKind::local_pin_auth,
        draw_review_panel_for_transition,
        &context);
}

struct UserSigningWorkContext {
    const LocalPinAuthUiFlowOps* ops = nullptr;
    const char* request_id = nullptr;
};

void execute_user_signing_for_transition(void* context)
{
    const auto* work_context = static_cast<const UserSigningWorkContext*>(context);
    if (work_context == nullptr ||
        work_context->ops == nullptr ||
        work_context->ops->user_signing.execute_user_signing_from_pin == nullptr) {
        return;
    }
    work_context->ops->user_signing.execute_user_signing_from_pin(
        work_context->request_id);
}

void run_user_signing_then_clear_local_pin_panel(
    const LocalPinAuthUiFlowOps& ops,
    const char* request_id)
{
    UserSigningWorkContext context{&ops, request_id};
    modal_transition_run_work_then_clear_panel(
        modal_transition_ops(ops),
        UiPanelKind::local_pin_auth,
        execute_user_signing_for_transition,
        &context);
}

}  // namespace

bool local_pin_auth_ui_panel_matches_stage(UiPanelKind kind)
{
    return kind == UiPanelKind::local_pin_auth &&
           local_pin_auth_flow_active();
}

bool local_pin_auth_ui_accepts_keypad_input()
{
    return local_pin_auth_accepts_keypad_input();
}

bool local_pin_auth_ui_begin_connect(
    const char* request_id,
    const LocalPinAuthUiFlowOps& ops)
{
    identification_display_clear();
    const TickType_t now = now_or_zero(ops);
    const TimeoutWindow request_window =
        timeout_window_from_deadline(
            now,
            now + pdMS_TO_TICKS(ops.timing.connect_approval_ms));
    const LocalPinAuthConnectPinBeginResult begin_result =
        ops.connect.begin_connect_pin_auth != nullptr
            ? ops.connect.begin_connect_pin_auth(request_id, now, request_window)
            : LocalPinAuthConnectPinBeginResult::unavailable;
    switch (begin_result) {
        case LocalPinAuthConnectPinBeginResult::started:
            break;
        case LocalPinAuthConnectPinBeginResult::unavailable:
            write_connect_rejected_from_pin(
                ops,
                request_id,
                LocalPinAuthConnectRejectReason::invalid_state);
            finish_connect_rejection_cleanup(ops, false);
            show_message(ops, "Connect unavailable", MessageKind::error);
            return false;
        case LocalPinAuthConnectPinBeginResult::pin_unavailable:
            write_connect_rejected_from_pin(
                ops,
                request_id,
                LocalPinAuthConnectRejectReason::invalid_state);
            finish_connect_rejection_cleanup(ops, true);
            show_message(ops, "Connect unavailable", MessageKind::error);
            return false;
    }

    if (!draw_local_pin_panel(ops)) {
        write_connect_rejected_from_pin(
            ops,
            request_id,
            LocalPinAuthConnectRejectReason::ui_error);
        clear_local_pin_auth_scratch(ops, "connect PIN display allocation failed");
        finish_connect_rejection_cleanup(ops, true);
        show_message(ops, "Display error", MessageKind::error);
        return false;
    }
    return true;
}

bool local_pin_auth_ui_begin_sui_zklogin_proposal(
    const char* request_id,
    const LocalPinAuthUiFlowOps& ops)
{
    identification_display_clear();
    const TickType_t now = now_or_zero(ops);
    const LocalPinAuthSuiZkLoginPinBeginResult begin_result =
        ops.sui_zklogin.begin_sui_zklogin_proposal_pin_from_review != nullptr
            ? ops.sui_zklogin.begin_sui_zklogin_proposal_pin_from_review(request_id, now)
            : LocalPinAuthSuiZkLoginPinBeginResult::pin_unavailable;
    switch (begin_result) {
        case LocalPinAuthSuiZkLoginPinBeginResult::started:
            break;
        case LocalPinAuthSuiZkLoginPinBeginResult::unavailable:
            finish_sui_zklogin_proposal_error_terminal(
                ops,
                request_id,
                "invalid_state",
                "Sui zkLogin proposal is unavailable.",
                "zkLogin unavailable");
            return false;
        case LocalPinAuthSuiZkLoginPinBeginResult::pin_unavailable:
            finish_sui_zklogin_proposal_error_terminal(
                ops,
                request_id,
                "invalid_state",
                "Sui zkLogin proposal PIN is unavailable.",
                "zkLogin unavailable");
            return false;
    }

    if (!draw_local_pin_panel(ops, "Approve Sui zkLogin")) {
        clear_local_pin_auth_scratch(
            ops,
            "Sui zkLogin proposal PIN display allocation failed");
        finish_sui_zklogin_proposal_terminal(
            ops,
            request_id,
            record_sui_zklogin_ui_error_from_pin(ops));
        return false;
    }
    return true;
}

void local_pin_auth_ui_start_settings_human_approval_input(
    const LocalPinAuthUiFlowOps& ops)
{
    if (!start_settings_handoff(
            "Stale human approval input setting action ignored",
            ops)) {
        return;
    }

    HumanApprovalInputMode current_mode = HumanApprovalInputMode::pin;
    if (ops.material_settings.read_human_approval_input_mode == nullptr ||
        !ops.material_settings.read_human_approval_input_mode(&current_mode)) {
        show_settings_error(ops);
        return;
    }
    const HumanApprovalInputMode target_mode =
        local_pin_auth_target_human_approval_input_mode(current_mode);
    const TickType_t now = now_or_zero(ops);
    if (!local_pin_auth_begin_human_approval_input_setting(
            target_mode,
            now,
            timeout_window_from_deadline(
                now,
                now + pdMS_TO_TICKS(ops.timing.storage_maintenance_entry_ms)))) {
        show_message(ops, "Settings unavailable", MessageKind::error);
        return;
    }

    if (!draw_local_pin_panel(ops)) {
        clear_local_pin_auth_scratch(
            ops,
            "human approval input setting display allocation failed");
        show_message(ops, "Display error", MessageKind::error);
    }
}

bool local_pin_auth_ui_start_unlock(const LocalPinAuthUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    if (!local_pin_auth_begin_unlock(
            now,
            timeout_window_from_deadline(
                now,
                now + pdMS_TO_TICKS(ops.timing.storage_maintenance_entry_ms)))) {
        return false;
    }
    if (!draw_local_pin_panel(ops)) {
        clear_local_pin_auth_scratch(ops, "unlock display allocation failed");
        show_message(ops, "Display error", MessageKind::error);
        return false;
    }
    return true;
}

void local_pin_auth_ui_start_settings_signing_mode(
    const LocalPinAuthUiFlowOps& ops)
{
    if (!start_settings_handoff(
            "Stale settings signing mode action ignored",
            ops)) {
        return;
    }

    AuthorizationMode current_mode =
        AuthorizationMode::user;
    if (ops.material_settings.read_signing_authorization_mode == nullptr ||
        !ops.material_settings.read_signing_authorization_mode(&current_mode)) {
        show_settings_error(ops);
        return;
    }

    const AuthorizationMode target_mode =
        local_pin_auth_target_signing_authorization_mode(current_mode);
    const TickType_t now = now_or_zero(ops);
    if (!local_pin_auth_begin_signing_mode_setting(
            target_mode,
            now,
            timeout_window_from_deadline(
                now,
                now + pdMS_TO_TICKS(ops.timing.storage_maintenance_entry_ms)))) {
        show_message(ops, "Settings unavailable", MessageKind::error);
        return;
    }

    if (!draw_local_pin_panel(ops)) {
        clear_local_pin_auth_scratch(
            ops,
            "settings signing mode display allocation failed");
        show_message(ops, "Display error", MessageKind::error);
    }
}

void local_pin_auth_ui_start_settings_policy_reset(
    const LocalPinAuthUiFlowOps& ops)
{
    if (!start_settings_handoff(
            "Stale settings policy reset action ignored",
            ops)) {
        return;
    }

    const TickType_t now = now_or_zero(ops);
    if (!local_pin_auth_begin_policy_reset_setting(
            now,
            timeout_window_from_deadline(
                now,
                now + pdMS_TO_TICKS(ops.timing.storage_maintenance_entry_ms)))) {
        show_message(ops, "Policy reset unavailable", MessageKind::error);
        return;
    }

    if (!draw_local_pin_panel(ops)) {
        clear_local_pin_auth_scratch(
            ops,
            "settings policy reset display allocation failed");
        show_message(ops, "Display error", MessageKind::error);
    }
}

void local_pin_auth_ui_start_settings_change_pin(
    const LocalPinAuthUiFlowOps& ops)
{
    if (!start_settings_handoff(
            "Stale settings Change PIN action ignored",
            ops)) {
        return;
    }

    const TickType_t now = now_or_zero(ops);
    if (!local_pin_auth_begin_change_pin(
            now,
            timeout_window_from_deadline(
                now,
                now + pdMS_TO_TICKS(ops.timing.storage_maintenance_entry_ms)))) {
        show_message(ops, "Change PIN unavailable", MessageKind::error);
        return;
    }

    if (!draw_local_pin_panel(ops)) {
        clear_local_pin_auth_scratch(
            ops,
            "settings Change PIN display allocation failed");
        show_message(ops, "Display error", MessageKind::error);
    }
}

void local_pin_auth_ui_start_settings_sui_accept_gas_sponsor(
    const LocalPinAuthUiFlowOps& ops)
{
    if (!start_settings_handoff(
            "Stale Sui gas sponsor setting action ignored",
            ops)) {
        return;
    }

    SuiAccountSettings current_settings = kDefaultSuiAccountSettings;
    if (ops.material_settings.read_sui_account_settings == nullptr ||
        !ops.material_settings.read_sui_account_settings(&current_settings)) {
        show_settings_error(ops);
        return;
    }

    const SuiAccountSettings target_settings =
        local_pin_auth_target_sui_accept_gas_sponsor_settings(current_settings);
    const TickType_t now = now_or_zero(ops);
    if (!local_pin_auth_begin_sui_accept_gas_sponsor_setting(
            target_settings,
            now,
            timeout_window_from_deadline(
                now,
                now + pdMS_TO_TICKS(ops.timing.storage_maintenance_entry_ms)))) {
        show_message(ops, "Sui setting unavailable", MessageKind::error);
        return;
    }

    if (!draw_local_pin_panel(
            ops,
            target_settings.accept_gas_sponsor
                ? "Accept Sui gas sponsor"
                : "Reject Sui gas sponsor")) {
        clear_local_pin_auth_scratch(
            ops,
            "Sui gas sponsor setting display allocation failed");
        show_message(ops, "Display error", MessageKind::error);
    }
}

void local_pin_auth_ui_start_settings_sui_zklogin_clear(
    const LocalPinAuthUiFlowOps& ops)
{
    if (ops.material_settings.sui_zklogin_proof_clear_available == nullptr ||
        !ops.material_settings.sui_zklogin_proof_clear_available()) {
        show_message(ops, "No Sui proof", MessageKind::info);
        return;
    }
    if (!start_settings_handoff(
            "Stale Sui zkLogin clear action ignored",
            ops)) {
        return;
    }

    const TickType_t now = now_or_zero(ops);
    if (!local_pin_auth_begin_sui_zklogin_clear_setting(
            now,
            timeout_window_from_deadline(
                now,
                now + pdMS_TO_TICKS(ops.timing.storage_maintenance_entry_ms)))) {
        show_message(ops, "Sui clear unavailable", MessageKind::error);
        return;
    }

    if (!draw_local_pin_panel(ops, "Clear Sui zkLogin")) {
        clear_local_pin_auth_scratch(
            ops,
            "Sui zkLogin clear display allocation failed");
        show_message(ops, "Display error", MessageKind::error);
    }
}

void local_pin_auth_ui_cancel(
    const char* message,
    const LocalPinAuthUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const LocalPinAuthSnapshot snapshot = local_pin_auth_snapshot(now);
    if (!snapshot.flow_active || !snapshot.accepts_keypad_input) {
        log_warn(ops, "Stale local PIN authorization cancel ignored");
        return;
    }

    const LocalPinAuthPurpose purpose = snapshot.purpose;
    if (purpose == LocalPinAuthPurpose::unlock) {
        if (!draw_local_pin_panel(ops, "Device remains locked.")) {
            handle_local_pin_auth_display_failure(
                "unlock display allocation failed after cancel",
                false,
                ops);
        }
        return;
    }
    if (finish_request_backed_local_pin_input_timeout_if_reached(
            purpose,
            now,
            "request-backed local PIN cancel reached timeout",
            ops)) {
        return;
    }

    char request_id[kMaxRequestIdSize] = {};
    request_id_for_pin(ops, purpose, request_id, sizeof(request_id));

    if (purpose == LocalPinAuthPurpose::policy_update &&
        request_id[0] != '\0') {
        clear_local_pin_auth_scratch(ops, "local PIN authorization canceled");
        const PolicyUpdateFlowTransitionResult transition =
            return_policy_update_review_from_pin(
                ops,
                now,
                timeout_window_from_deadline(
                    now,
                    now + pdMS_TO_TICKS(ops.timing.provisioning_approval_ms)));
        if (transition != PolicyUpdateFlowTransitionResult::ok) {
            complete_local_pin_to_policy_error_terminal(
                ops,
                request_id,
                "invalid_state",
                "Policy update is unavailable.",
                "Policy unavailable");
            return;
        }
        if (!complete_local_pin_to_review_panel(ops, purpose)) {
            complete_local_pin_processing_to_policy_terminal(
                ops,
                request_id,
                record_policy_update_ui_error_from_pin(ops));
        }
        return;
    }
    if (purpose == LocalPinAuthPurpose::sui_zklogin_proposal &&
        request_id[0] != '\0') {
        clear_local_pin_auth_scratch(ops, "local PIN authorization canceled");
        const SuiZkLoginProposalTransitionResult transition =
            return_sui_zklogin_review_from_pin(ops, now);
        if (transition == SuiZkLoginProposalTransitionResult::timed_out) {
            complete_local_pin_processing_to_sui_zklogin_terminal(
                ops,
                request_id,
                record_sui_zklogin_timed_out_from_pin(ops));
            return;
        }
        if (transition != SuiZkLoginProposalTransitionResult::ok) {
            complete_local_pin_to_sui_zklogin_error_terminal(
                ops,
                request_id,
                "invalid_state",
                "Sui zkLogin proposal is unavailable.",
                "zkLogin unavailable");
            return;
        }
        if (!complete_local_pin_to_review_panel(ops, purpose)) {
            complete_local_pin_processing_to_sui_zklogin_terminal(
                ops,
                request_id,
                record_sui_zklogin_ui_error_from_pin(ops));
        }
        return;
    }
    if (purpose == LocalPinAuthPurpose::connect &&
        request_id[0] != '\0') {
        clear_local_pin_auth_scratch(ops, "local PIN authorization canceled");
        if (!return_connect_review_from_pin(
                ops,
                now,
                timeout_window_from_deadline(
                    now,
                    now + pdMS_TO_TICKS(ops.timing.connect_approval_ms)))) {
            complete_local_pin_processing_to_message(
                ops,
                "Connect unavailable",
                MessageKind::error);
            return;
        }
        if (!complete_local_pin_to_review_panel(ops, purpose)) {
            complete_local_pin_processing_to_message(
                ops,
                "Display error",
                MessageKind::error);
        }
        return;
    }
    if (purpose == LocalPinAuthPurpose::user_signing &&
        request_id[0] != '\0') {
        const UserSigningConfirmationResult result =
            return_user_signing_review_from_pin(
                ops,
                now,
                window_from_now_ms(ops, ops.timing.provisioning_approval_ms));
        if (result == UserSigningConfirmationResult::ok) {
            if (!complete_local_pin_to_review_panel(ops, purpose)) {
                cancel_user_signing_for_ui_loss(ops);
                complete_local_pin_to_user_error_terminal(
                    ops,
                    request_id,
                    "ui_error",
                    "Could not show signing review UI.",
                    "Display error");
            }
        } else {
            complete_local_pin_to_user_error_terminal(
                ops,
                request_id,
                "invalid_state",
                "Signing request is unavailable.",
                "Signing unavailable");
        }
        return;
    }
    if (local_pin_auth_settings_purpose(purpose)) {
        clear_local_pin_auth_scratch(ops, "local PIN authorization canceled");
        complete_local_pin_processing_to_settings(
            ops,
            "local settings display allocation failed after PIN cancel",
            "Display error",
            MessageKind::error);
        return;
    }

    clear_local_pin_auth_scratch(ops, "local PIN authorization canceled");
    complete_local_pin_processing_to_message(
        ops,
        message != nullptr && message[0] != '\0' ? message : "Settings canceled",
        MessageKind::rejected);
}

void local_pin_auth_ui_handle_digit(
    char digit,
    const LocalPinAuthUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const LocalPinAuthSnapshot snapshot = local_pin_auth_snapshot(now);
    if (snapshot.flow_active &&
        finish_request_backed_local_pin_input_timeout_if_reached(
            snapshot.purpose,
            now,
            "request-backed local PIN digit reached timeout",
            ops)) {
        return;
    }
    const LocalPinAuthInputResult result = local_pin_auth_add_digit(digit);
    if (result == LocalPinAuthInputResult::inactive ||
        result == LocalPinAuthInputResult::locked ||
        result == LocalPinAuthInputResult::invalid_digit) {
        return;
    }
    if (!draw_local_pin_panel(ops)) {
        handle_local_pin_auth_display_failure(
            "local PIN authorization display allocation failed",
            false,
            ops);
    }
}

void local_pin_auth_ui_handle_clear(const LocalPinAuthUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const LocalPinAuthSnapshot snapshot = local_pin_auth_snapshot(now);
    if (snapshot.flow_active &&
        finish_request_backed_local_pin_input_timeout_if_reached(
            snapshot.purpose,
            now,
            "request-backed local PIN clear reached timeout",
            ops)) {
        return;
    }
    if (!local_pin_auth_clear_pin()) {
        return;
    }
    if (!draw_local_pin_panel(ops)) {
        handle_local_pin_auth_display_failure(
            "local PIN authorization display allocation failed",
            false,
            ops);
    }
}

void local_pin_auth_ui_handle_backspace(const LocalPinAuthUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const LocalPinAuthSnapshot snapshot = local_pin_auth_snapshot(now);
    if (snapshot.flow_active &&
        finish_request_backed_local_pin_input_timeout_if_reached(
            snapshot.purpose,
            now,
            "request-backed local PIN backspace reached timeout",
            ops)) {
        return;
    }
    if (!local_pin_auth_backspace_pin()) {
        return;
    }
    if (!draw_local_pin_panel(ops)) {
        handle_local_pin_auth_display_failure(
            "local PIN authorization display allocation failed",
            false,
            ops);
    }
}

void local_pin_auth_ui_handle_submit(const LocalPinAuthUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const LocalPinAuthSnapshot snapshot = local_pin_auth_snapshot(now);
    if (snapshot.flow_active &&
        finish_request_backed_local_pin_input_timeout_if_reached(
            snapshot.purpose,
            now,
            "request-backed local PIN submit reached timeout",
            ops)) {
        return;
    }
    const TimeoutWindow next_input_window =
        local_pin_auth_next_input_window(snapshot.purpose, now, ops);
    const LocalPinAuthSubmitResult result =
        local_pin_auth_submit(
            now + pdMS_TO_TICKS(ops.timing.local_processing_render_delay_ms),
            now + pdMS_TO_TICKS(ops.timing.local_processing_display_ms),
            next_input_window,
            now + pdMS_TO_TICKS(ops.timing.local_auth_worker_max_ms));
    switch (result) {
        case LocalPinAuthSubmitResult::unavailable_stage:
            log_warn(ops, "Stale local PIN authorization submit ignored");
            return;
        case LocalPinAuthSubmitResult::locked:
            return;
        case LocalPinAuthSubmitResult::worker_unavailable:
            if (!draw_local_pin_panel(ops, "Auth worker busy. Try again.")) {
                handle_local_pin_auth_display_failure(
                    "local PIN worker unavailable display allocation failed",
                    true,
                    ops);
            }
            return;
        case LocalPinAuthSubmitResult::invalid_pin:
            if (!draw_local_pin_panel(ops, "Enter exactly 6 digits.")) {
                handle_local_pin_auth_display_failure(
                    "local PIN authorization display allocation failed",
                    false,
                    ops);
            }
            return;
        case LocalPinAuthSubmitResult::advanced_to_repeat_pin:
            if (!draw_local_pin_panel(ops)) {
                handle_local_pin_auth_display_failure(
                    "Change PIN repeat display allocation failed",
                    false,
                    ops);
            }
            return;
        case LocalPinAuthSubmitResult::mismatch_restart:
            if (!draw_local_pin_panel(ops, "PINs did not match.")) {
                handle_local_pin_auth_display_failure(
                    "Change PIN mismatch display allocation failed",
                    false,
                    ops);
            }
            return;
        case LocalPinAuthSubmitResult::started_pin_change_commit:
            if (!draw_processing_or_local_pin_panel(ops)) {
                handle_local_pin_auth_display_failure(
                    "Change PIN commit display allocation failed",
                    true,
                    ops);
            }
            return;
        case LocalPinAuthSubmitResult::started_verification:
            if (!pause_request_backed_pin_input_window(snapshot.purpose, now)) {
                handle_local_pin_auth_display_failure(
                    "local PIN authorization deadline pause failed",
                    true,
                    ops);
                return;
            }
            if (!draw_processing_or_local_pin_panel(ops)) {
                handle_local_pin_auth_display_failure(
                    "local PIN authorization verification display allocation failed",
                    true,
                    ops);
            }
            return;
    }
}

void local_pin_auth_ui_commit_setting_if_ready(
    const LocalPinAuthUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const LocalPinAuthPurpose purpose =
        local_pin_auth_snapshot(now).purpose;
    const LocalPinAuthCommitResult result = local_pin_auth_commit_if_ready(now);
    complete_local_pin_settings_completion(
        ops,
        local_pin_auth_settings_completion_for_commit_result(purpose, result));
}

void local_pin_auth_ui_handle_verify_worker_result(
    const LocalAuthWorkerResult& worker_result,
    const LocalPinAuthUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const LocalPinAuthSnapshot snapshot = local_pin_auth_snapshot(now);
    if (!snapshot.flow_active || snapshot.stage != LocalPinAuthStage::pin_verifying) {
        return;
    }

    const LocalPinAuthPurpose purpose = snapshot.purpose;
    if (purpose == LocalPinAuthPurpose::user_signing) {
        char request_id[kMaxRequestIdSize] = {};
        request_id_for_pin(ops, purpose, request_id, sizeof(request_id));
        const UserSigningConfirmationResult confirmation_result =
            complete_user_signing_pin_verify_from_pin(
                ops,
                worker_result,
                now,
                now + pdMS_TO_TICKS(kStorageMaintenancePinLockoutMs),
                provisioned_material_ready(ops));
        switch (confirmation_result) {
            case UserSigningConfirmationResult::not_ready:
                return;
            case UserSigningConfirmationResult::wrong_pin:
                if (!draw_local_pin_panel(ops, "Wrong PIN.")) {
                    handle_local_pin_auth_display_failure(
                        "user_signing PIN display allocation failed after wrong PIN",
                        false,
                        ops);
                }
                return;
            case UserSigningConfirmationResult::locked:
                if (!draw_local_pin_panel(ops, "Too many wrong PINs. Wait 30s.")) {
                    handle_local_pin_auth_display_failure(
                        "user_signing PIN lockout display allocation failed",
                        false,
                        ops);
                }
                return;
            case UserSigningConfirmationResult::auth_unavailable:
                record_material_failure(
                    ops,
                    PersistentMaterialRuntimeFailure::local_pin_auth_unavailable);
                complete_local_pin_to_user_error_terminal(
                    ops,
                    request_id,
                    "auth_unavailable",
                    "Local PIN authentication unavailable.",
                    "Auth error");
                return;
            case UserSigningConfirmationResult::history_error:
                complete_local_pin_to_user_error_terminal(
                    ops,
                    request_id,
                    "history_unavailable",
                    "Could not record signing confirmation.",
                    "History error");
                return;
            case UserSigningConfirmationResult::ok:
                break;
            case UserSigningConfirmationResult::deadline_expired:
            case UserSigningConfirmationResult::deadline_not_reached:
            case UserSigningConfirmationResult::invalid_session:
            case UserSigningConfirmationResult::inactive:
            case UserSigningConfirmationResult::wrong_stage:
            case UserSigningConfirmationResult::invalid_argument:
            case UserSigningConfirmationResult::invalid_deadline:
            case UserSigningConfirmationResult::session_still_active:
            case UserSigningConfirmationResult::local_pin_busy:
            case UserSigningConfirmationResult::local_pin_unavailable:
            case UserSigningConfirmationResult::stale_state:
            case UserSigningConfirmationResult::busy:
                if (user_signing_terminal_pending_from_pin(ops)) {
                    complete_local_pin_to_user_terminal(ops, request_id);
                    return;
                }
                complete_local_pin_to_user_error_terminal(
                    ops,
                    request_id,
                    confirmation_result == UserSigningConfirmationResult::invalid_session
                        ? "invalid_session"
                        : "invalid_state",
                    "Signing request is unavailable.",
                    "Signing unavailable");
                return;
        }

        run_user_signing_then_clear_local_pin_panel(ops, request_id);
        return;
    }
    const TimeoutWindow next_input_window =
        local_pin_auth_next_input_window(purpose, now, ops);
    const LocalPinAuthVerifyResult result =
        local_pin_auth_complete_verify_job(
            worker_result,
            next_input_window,
            now + pdMS_TO_TICKS(kStorageMaintenancePinLockoutMs),
            now + pdMS_TO_TICKS(ops.timing.local_processing_display_ms));
    if (result == LocalPinAuthVerifyResult::not_ready) {
        return;
    }

    if (purpose != LocalPinAuthPurpose::unlock &&
        !provisioned_material_ready(ops)) {
        char request_id[kMaxRequestIdSize] = {};
        request_id_for_pin(ops, purpose, request_id, sizeof(request_id));
        clear_local_pin_auth_scratch(ops, "local PIN authorization material state unavailable");
        if (purpose == LocalPinAuthPurpose::policy_update && request_id[0] != '\0') {
            finish_policy_update_unavailable_from_pin(
                ops,
                request_id,
                LocalPinAuthPolicyUpdateUnavailableReason::material_unavailable);
        }
        if (request_id[0] != '\0') {
            if (purpose == LocalPinAuthPurpose::policy_update) {
                complete_local_pin_processing_to_message(
                    ops,
                    "PIN unavailable",
                    MessageKind::error);
                return;
            }
            if (purpose == LocalPinAuthPurpose::sui_zklogin_proposal) {
                complete_local_pin_processing_to_sui_zklogin_terminal(
                    ops,
                    request_id,
                    record_sui_zklogin_consistency_error_from_pin(ops));
                return;
            }
            write_connect_rejected_from_pin(
                ops,
                request_id,
                LocalPinAuthConnectRejectReason::invalid_state);
            finish_connect_rejection_cleanup(ops, true);
        }
        complete_local_pin_processing_to_message(
            ops,
            "PIN unavailable",
            MessageKind::error);
        return;
    }

    if (request_backed_local_pin_input_deadline_reached(purpose, now)) {
        if (finish_request_backed_local_pin_input_timeout_if_reached(
                purpose,
                now,
                "protocol-backed local PIN authentication result reached timeout",
                ops)) {
            return;
        }
        complete_local_pin_processing_to_message(
            ops,
            "Auth timed out",
            MessageKind::timeout);
        return;
    }
    switch (result) {
        case LocalPinAuthVerifyResult::not_ready:
            return;
        case LocalPinAuthVerifyResult::unlocked:
            complete_local_pin_processing_to_message(
                ops,
                "Unlocked",
                MessageKind::success);
            return;
        case LocalPinAuthVerifyResult::auth_unavailable: {
            char request_id[kMaxRequestIdSize] = {};
            request_id_for_pin(ops, purpose, request_id, sizeof(request_id));
            record_material_failure(
                ops,
                PersistentMaterialRuntimeFailure::local_pin_auth_unavailable);
            clear_local_pin_auth_scratch(ops, "local PIN authentication unavailable");
            if (purpose == LocalPinAuthPurpose::policy_update &&
                request_id[0] != '\0') {
                finish_policy_update_unavailable_from_pin(
                    ops,
                    request_id,
                    LocalPinAuthPolicyUpdateUnavailableReason::auth_unavailable);
                complete_local_pin_processing_to_message(
                    ops,
                    "Auth error",
                    MessageKind::error);
                return;
            }
            if (purpose == LocalPinAuthPurpose::sui_zklogin_proposal &&
                request_id[0] != '\0') {
                complete_local_pin_processing_to_sui_zklogin_terminal(
                    ops,
                    request_id,
                    record_sui_zklogin_consistency_error_from_pin(ops));
                return;
            }
            if (request_id[0] != '\0') {
                write_connect_rejected_from_pin(
                    ops,
                    request_id,
                    LocalPinAuthConnectRejectReason::auth_unavailable);
                finish_connect_rejection_cleanup(ops, true);
            }
            complete_local_pin_processing_to_message(
                ops,
                "Auth error",
                MessageKind::error);
            return;
        }
        case LocalPinAuthVerifyResult::locked:
            if (purpose == LocalPinAuthPurpose::policy_update &&
                return_policy_update_pin_entry_from_pin(ops) !=
                    PolicyUpdateFlowTransitionResult::ok) {
                handle_local_pin_auth_display_failure(
                    "policy update lockout stage transition failed",
                    true,
                    ops);
                return;
            }
            if (purpose == LocalPinAuthPurpose::sui_zklogin_proposal &&
                return_sui_zklogin_pin_entry_from_pin(ops) !=
                    SuiZkLoginProposalTransitionResult::ok) {
                handle_local_pin_auth_display_failure(
                    "Sui zkLogin proposal lockout stage transition failed",
                    true,
                    ops);
                return;
            }
            if (!draw_local_pin_panel(ops, "Too many wrong PINs. Wait 30s.")) {
                handle_local_pin_auth_display_failure(
                    "local PIN authorization display allocation failed after wrong PIN",
                    false,
                    ops);
            }
            return;
        case LocalPinAuthVerifyResult::wrong_pin:
            if (purpose == LocalPinAuthPurpose::policy_update &&
                return_policy_update_pin_entry_from_pin(ops) !=
                    PolicyUpdateFlowTransitionResult::ok) {
                handle_local_pin_auth_display_failure(
                    "policy update wrong-PIN stage transition failed",
                    true,
                    ops);
                return;
            }
            if (purpose == LocalPinAuthPurpose::sui_zklogin_proposal &&
                return_sui_zklogin_pin_entry_from_pin(ops) !=
                    SuiZkLoginProposalTransitionResult::ok) {
                handle_local_pin_auth_display_failure(
                    "Sui zkLogin proposal wrong-PIN stage transition failed",
                    true,
                    ops);
                return;
            }
            if (request_backed_local_pin_purpose(purpose) &&
                !resume_request_backed_pin_input_window(purpose, now)) {
                if (finish_request_backed_local_pin_input_timeout_if_reached(
                        purpose,
                        now,
                        "request-backed local PIN wrong-PIN refresh reached timeout",
                        ops)) {
                    return;
                }
                handle_local_pin_auth_display_failure(
                    "request-backed local PIN wrong-PIN refresh failed",
                    true,
                    ops);
                return;
            }
            if (!draw_local_pin_panel(ops, "Wrong PIN.")) {
                handle_local_pin_auth_display_failure(
                    "local PIN authorization display allocation failed after wrong PIN",
                    false,
                    ops);
            }
            return;
        case LocalPinAuthVerifyResult::advanced_to_change_pin:
            if (!draw_local_pin_panel(ops)) {
                handle_local_pin_auth_display_failure(
                    "Change PIN new PIN display allocation failed",
                    false,
                    ops);
            }
            return;
        case LocalPinAuthVerifyResult::verified_connect: {
            char request_id[kMaxRequestIdSize] = {};
            request_id_for_pin(
                ops,
                LocalPinAuthPurpose::connect,
                request_id,
                sizeof(request_id));
            const LocalPinAuthConnectSessionResult session_result =
                replace_connect_session_from_pin(ops, request_id);
            if (session_result == LocalPinAuthConnectSessionResult::session_unavailable) {
                clear_local_pin_auth_scratch(ops, "connect PIN session creation failed");
                finish_connect_session_error(ops, request_id);
                complete_local_pin_processing_to_message(
                    ops,
                    "RNG error",
                    MessageKind::error);
                return;
            }
            clear_local_pin_auth_scratch(ops, "connect PIN approved");
            finish_connect_approved(ops, request_id);
            complete_local_pin_processing_to_message(
                ops,
                "Connected",
                MessageKind::success);
            return;
        }
        case LocalPinAuthVerifyResult::verified_settings_policy_reset: {
            const LocalPinAuthSettingsCompletionResult completion =
                ops.material_settings.complete_policy_reset_setting != nullptr
                    ? ops.material_settings.complete_policy_reset_setting()
                    : LocalPinAuthSettingsCompletionResult::policy_reset_failed;
            clear_local_pin_auth_scratch(
                ops,
                completion == LocalPinAuthSettingsCompletionResult::policy_reset
                    ? "settings policy reset committed"
                    : "settings policy reset failed");
            complete_local_pin_settings_completion(ops, completion);
            return;
        }
        case LocalPinAuthVerifyResult::verified_settings_sui_zklogin_clear: {
            const LocalPinAuthSettingsCompletionResult completion =
                ops.material_settings.complete_sui_zklogin_clear_setting != nullptr
                    ? ops.material_settings.complete_sui_zklogin_clear_setting()
                    : LocalPinAuthSettingsCompletionResult::sui_clear_failed;
            clear_local_pin_auth_scratch(
                ops,
                completion == LocalPinAuthSettingsCompletionResult::sui_proof_cleared
                    ? "Sui zkLogin proof cleared"
                    : "Sui zkLogin proof clear failed");
            complete_local_pin_settings_completion(ops, completion);
            return;
        }
        case LocalPinAuthVerifyResult::verified_policy_update: {
            char request_id[kMaxRequestIdSize] = {};
            request_id_for_pin(
                ops,
                LocalPinAuthPurpose::policy_update,
                request_id,
                sizeof(request_id));
            if (ops.policy_update.require_pending_policy_update_session == nullptr ||
                !ops.policy_update.require_pending_policy_update_session(request_id)) {
                clear_local_pin_auth_scratch(
                    ops,
                    "policy update PIN approved but session was unavailable");
                complete_local_pin_to_policy_error_terminal(
                    ops,
                    request_id,
                    "invalid_state",
                    "Policy update is unavailable.",
                    "Policy unavailable");
                return;
            }
            clear_local_pin_auth_scratch(ops, "policy update PIN approved");
            const PolicyUpdateFlowTerminalResult commit_result =
                commit_policy_update_from_pin(ops);
            complete_local_pin_processing_to_policy_terminal(
                ops,
                request_id,
                commit_result);
            return;
        }
        case LocalPinAuthVerifyResult::verified_sui_zklogin_proposal: {
            char request_id[kMaxRequestIdSize] = {};
            request_id_for_pin(
                ops,
                LocalPinAuthPurpose::sui_zklogin_proposal,
                request_id,
                sizeof(request_id));
            if (ops.sui_zklogin.require_pending_sui_zklogin_proposal_session == nullptr ||
                !ops.sui_zklogin.require_pending_sui_zklogin_proposal_session(request_id)) {
                clear_local_pin_auth_scratch(
                    ops,
                    "Sui zkLogin proposal PIN approved but session was unavailable");
                complete_local_pin_to_sui_zklogin_error_terminal(
                    ops,
                    request_id,
                    "invalid_state",
                    "Sui zkLogin proposal is unavailable.",
                    "zkLogin unavailable");
                return;
            }
            clear_local_pin_auth_scratch(ops, "Sui zkLogin proposal PIN approved");
            const SuiZkLoginProposalTerminalResult commit_result =
                commit_sui_zklogin_from_pin(ops);
            complete_local_pin_processing_to_sui_zklogin_terminal(
                ops,
                request_id,
                commit_result);
            return;
        }
        case LocalPinAuthVerifyResult::started_setting_commit:
            if (!draw_processing_or_local_pin_panel(ops)) {
                clear_local_pin_auth_scratch(ops, "settings PIN commit display allocation failed");
                complete_local_pin_processing_to_message(
                    ops,
                    "Display error",
                    MessageKind::error);
            }
            return;
    }
}

void local_pin_auth_ui_handle_pin_change_worker_result(
    const LocalAuthWorkerResult& worker_result,
    const LocalPinAuthUiFlowOps& ops)
{
    const LocalPinAuthCommitResult result =
        local_pin_auth_complete_pin_change_job(worker_result);
    complete_local_pin_settings_completion(
        ops,
        local_pin_auth_settings_completion_for_commit_result(
            LocalPinAuthPurpose::settings_change_pin,
            result));
}

bool local_pin_panel_visible(const LocalPinAuthUiFlowOps& ops)
{
    return ops.display.local_pin_panel_visible != nullptr && ops.display.local_pin_panel_visible();
}

void finish_local_pin_processing_deadline_failure(
    LocalPinAuthPurpose purpose,
    const char* request_id,
    const LocalPinAuthUiFlowOps& ops)
{
    if (purpose == LocalPinAuthPurpose::policy_update &&
        request_id[0] != '\0') {
        complete_local_pin_processing_to_policy_terminal(
            ops,
            request_id,
            record_policy_update_timed_out_from_pin(ops));
        return;
    }
    if (purpose == LocalPinAuthPurpose::sui_zklogin_proposal &&
        request_id[0] != '\0') {
        complete_local_pin_processing_to_sui_zklogin_terminal(
            ops,
            request_id,
            record_sui_zklogin_timed_out_from_pin(ops));
        return;
    }
    if (request_id[0] != '\0') {
        write_connect_rejected_from_pin(
            ops,
            request_id,
            LocalPinAuthConnectRejectReason::timeout);
        finish_connect_rejection_cleanup(ops, true);
        complete_local_pin_processing_to_message(
            ops,
            "Connection timed out",
            MessageKind::timeout);
        return;
    }
    complete_local_pin_processing_to_message(
        ops,
        "Auth timed out",
        MessageKind::timeout);
}

void finish_local_pin_authentication_unavailable(
    LocalPinAuthPurpose purpose,
    const char* request_id,
    const LocalPinAuthUiFlowOps& ops)
{
    record_material_failure(
        ops,
        PersistentMaterialRuntimeFailure::local_pin_auth_unavailable);
    if (purpose == LocalPinAuthPurpose::policy_update &&
        request_id[0] != '\0') {
        finish_policy_update_unavailable_from_pin(
            ops,
            request_id,
            LocalPinAuthPolicyUpdateUnavailableReason::auth_unavailable);
        complete_local_pin_processing_to_message(
            ops,
            "Auth error",
            MessageKind::error);
        return;
    }
    if (purpose == LocalPinAuthPurpose::sui_zklogin_proposal &&
        request_id[0] != '\0') {
        complete_local_pin_processing_to_sui_zklogin_terminal(
            ops,
            request_id,
            record_sui_zklogin_consistency_error_from_pin(ops));
        return;
    }
    if (request_id[0] != '\0') {
        write_connect_rejected_from_pin(
            ops,
            request_id,
            LocalPinAuthConnectRejectReason::auth_unavailable);
        finish_connect_rejection_cleanup(ops, true);
    }
    complete_local_pin_processing_to_message(
        ops,
        "Auth error",
        MessageKind::error);
}

void clear_user_signing_processing_if_needed(
    const LocalPinAuthSnapshot& snapshot,
    TickType_t now,
    const LocalPinAuthUiFlowOps& ops)
{
    char request_id[kMaxRequestIdSize] = {};
    request_id_for_pin(
        ops,
        snapshot.purpose,
        request_id,
        sizeof(request_id));
    if (finish_request_backed_local_pin_input_timeout_if_reached(
            snapshot.purpose,
            now,
            "user_signing local PIN authorization timed out",
            ops)) {
        return;
    }
    if (local_pin_auth_processing_deadline_expired(now)) {
        cancel_user_signing_for_pin_loss(ops);
        clear_local_pin_auth_scratch(ops, "user_signing local PIN authentication timed out");
        record_material_failure(
            ops,
            PersistentMaterialRuntimeFailure::local_pin_auth_unavailable);
        complete_local_pin_to_user_error_terminal(
            ops,
            request_id,
            "auth_unavailable",
            "Local PIN authentication unavailable.",
            "Auth error");
        return;
    }
    if (!local_pin_panel_visible(ops) && !draw_local_pin_panel(ops)) {
        handle_local_pin_auth_display_failure(
            "user_signing PIN authorization processing UI recovery failed",
            true,
            ops);
    }
}

void clear_processing_local_pin_if_needed(
    const LocalPinAuthSnapshot& snapshot,
    TickType_t now,
    const LocalPinAuthUiFlowOps& ops)
{
    if (snapshot.purpose == LocalPinAuthPurpose::user_signing) {
        clear_user_signing_processing_if_needed(snapshot, now, ops);
        return;
    }
    if (finish_request_backed_local_pin_input_timeout_if_reached(
            snapshot.purpose,
            now,
            "protocol-backed local PIN authorization timed out",
            ops)) {
        return;
    }
    if (request_backed_local_pin_input_deadline_reached(snapshot.purpose, now)) {
        complete_local_pin_processing_to_message(
            ops,
            "Auth timed out",
            MessageKind::timeout);
        return;
    }
    if (!local_pin_auth_fail_processing_if_expired(now)) {
        if (!local_pin_panel_visible(ops) && !draw_local_pin_panel(ops)) {
            handle_local_pin_auth_display_failure(
                "local PIN authorization processing UI recovery failed",
                true,
                ops);
        }
        return;
    }

    const LocalPinAuthPurpose purpose = snapshot.purpose;
    char request_id[kMaxRequestIdSize] = {};
    request_id_for_pin(ops, purpose, request_id, sizeof(request_id));
    if (snapshot.stage == LocalPinAuthStage::pin_verifying) {
        finish_local_pin_authentication_unavailable(purpose, request_id, ops);
        return;
    }
    finish_local_pin_processing_deadline_failure(purpose, request_id, ops);
}

void finish_local_pin_panel_recovery_failure(
    LocalPinAuthPurpose purpose,
    const char* request_id,
    const LocalPinAuthUiFlowOps& ops)
{
    if (purpose == LocalPinAuthPurpose::policy_update &&
        request_id[0] != '\0') {
        clear_local_pin_auth_scratch(ops, "policy update PIN UI recovery failed");
        finish_policy_update_terminal(
            ops,
            request_id,
            record_policy_update_ui_error_from_pin(ops));
        return;
    }
    if (purpose == LocalPinAuthPurpose::sui_zklogin_proposal &&
        request_id[0] != '\0') {
        clear_local_pin_auth_scratch(ops, "Sui zkLogin proposal PIN UI recovery failed");
        finish_sui_zklogin_proposal_terminal(
            ops,
            request_id,
            record_sui_zklogin_ui_error_from_pin(ops));
        return;
    }
    if (purpose == LocalPinAuthPurpose::connect &&
        request_id[0] != '\0') {
        write_connect_rejected_from_pin(
            ops,
            request_id,
            LocalPinAuthConnectRejectReason::ui_error);
        finish_connect_rejection_cleanup(ops, true);
    }
    clear_local_pin_auth_scratch(ops, "local PIN UI recovery failed");
    show_message(ops, "Display error", MessageKind::error);
}

void finish_local_pin_timeout_or_panel_loss(
    LocalPinAuthPurpose purpose,
    const char* request_id,
    bool expired,
    bool panel_active,
    const LocalPinAuthUiFlowOps& ops)
{
    clear_local_pin_auth_scratch(
        ops,
        expired ? "local PIN authorization timed out" : "local PIN authorization panel lost");

    if (request_id[0] != '\0') {
        if (purpose == LocalPinAuthPurpose::policy_update) {
            const PolicyUpdateFlowTerminalResult result =
                record_policy_update_timed_out_from_pin(ops);
            if (panel_active) {
                complete_local_pin_processing_to_policy_terminal(
                    ops,
                    request_id,
                    result);
            } else {
                finish_policy_update_terminal(ops, request_id, result);
            }
            return;
        }
        if (purpose == LocalPinAuthPurpose::sui_zklogin_proposal) {
            const SuiZkLoginProposalTerminalResult result =
                expired
                    ? record_sui_zklogin_timed_out_from_pin(ops)
                    : record_sui_zklogin_rejected_from_pin(ops);
            if (panel_active) {
                complete_local_pin_processing_to_sui_zklogin_terminal(
                    ops,
                    request_id,
                    result);
            } else {
                finish_sui_zklogin_proposal_terminal(ops, request_id, result);
            }
            return;
        }
        write_connect_rejected_from_pin(
            ops,
            request_id,
            expired ? LocalPinAuthConnectRejectReason::timeout
                    : LocalPinAuthConnectRejectReason::user_rejected);
        finish_connect_rejection_cleanup(ops, true);
        if (panel_active) {
            complete_local_pin_processing_to_message(
                ops,
                expired ? "Connection timed out" : "Connection canceled",
                expired ? MessageKind::timeout : MessageKind::info);
        } else {
            show_message(
                ops,
                expired ? "Connection timed out" : "Connection canceled",
                expired ? MessageKind::timeout : MessageKind::info);
        }
        return;
    }

    if (expired) {
        if (panel_active) {
            complete_local_pin_processing_to_message(
                ops,
                "Settings timed out",
                MessageKind::timeout);
        } else {
            show_message(ops, "Settings timed out", MessageKind::timeout);
        }
    }
}

bool clear_user_signing_input_if_needed(
    LocalPinAuthPurpose purpose,
    const char* request_id,
    TickType_t now,
    const LocalPinAuthUiFlowOps& ops)
{
    if (purpose != LocalPinAuthPurpose::user_signing ||
        request_id[0] == '\0') {
        return false;
    }
    if (finish_request_backed_local_pin_input_timeout_if_reached(
            purpose,
            now,
            "user_signing local PIN authorization timed out",
            ops)) {
        return true;
    }
    if (local_pin_auth_deadline_expired(now)) {
        clear_local_pin_auth_scratch(ops, "user_signing local PIN input timed out");
        const UserSigningConfirmationResult result =
            record_user_signing_timeout_from_pin(ops, now);
        if (result == UserSigningConfirmationResult::ok ||
            user_signing_terminal_pending_from_pin(ops)) {
            complete_local_pin_to_user_terminal(ops, request_id);
        } else {
            complete_local_pin_to_user_error_terminal(
                ops,
                request_id,
                "invalid_state",
                "Signing request is unavailable.",
                "Signing unavailable");
        }
        return true;
    }

    const LocalPinAuthLockoutReleaseResult lockout_release =
        local_pin_auth_release_lockout_if_elapsed(now);
    if (lockout_release == LocalPinAuthLockoutReleaseResult::failed) {
        handle_local_pin_auth_display_failure(
            "user_signing local PIN lockout release failed",
            true,
            ops);
        return true;
    }
    if (lockout_release == LocalPinAuthLockoutReleaseResult::released) {
        if (!resume_request_backed_pin_input_window(purpose, now)) {
            if (finish_request_backed_local_pin_input_timeout_if_reached(
                    purpose,
                    now,
                    "user_signing local PIN lockout release reached timeout",
                    ops)) {
                return true;
            }
            handle_local_pin_auth_display_failure(
                "user_signing local PIN lockout release refresh failed",
                true,
                ops);
            return true;
        }
        if (!draw_local_pin_panel(ops, "Try again.")) {
            handle_local_pin_auth_display_failure(
                "user_signing PIN authorization lockout display allocation failed",
                false,
                ops);
        }
        return true;
    }

    if (local_pin_panel_visible(ops)) {
        return true;
    }
    if (draw_local_pin_panel(ops)) {
        return true;
    }
    cancel_user_signing_for_pin_loss(ops);
    finish_user_signing_error_terminal(
        ops,
        request_id,
        "ui_error",
        "Could not restore signing PIN UI.",
        "Display error");
    return true;
}

void clear_waiting_local_pin_input_if_needed(
    const LocalPinAuthSnapshot& snapshot,
    TickType_t now,
    const LocalPinAuthUiFlowOps& ops)
{
    const LocalPinAuthPurpose purpose = snapshot.purpose;
    char request_id[kMaxRequestIdSize] = {};
    request_id_for_pin(ops, purpose, request_id, sizeof(request_id));
    if (clear_user_signing_input_if_needed(purpose, request_id, now, ops)) {
        return;
    }
    if (finish_request_backed_local_pin_input_timeout_if_reached(
            purpose,
            now,
            "protocol-backed local PIN authorization timed out",
            ops)) {
        return;
    }

    const LocalPinAuthLockoutReleaseResult lockout_release =
        local_pin_auth_release_lockout_if_elapsed(now);
    if (lockout_release == LocalPinAuthLockoutReleaseResult::failed) {
        handle_local_pin_auth_display_failure(
            "local PIN lockout release failed",
            true,
            ops);
        return;
    }
    if (lockout_release == LocalPinAuthLockoutReleaseResult::released) {
        if (request_backed_local_pin_purpose(purpose) &&
            !resume_request_backed_pin_input_window(purpose, now)) {
            if (finish_request_backed_local_pin_input_timeout_if_reached(
                    purpose,
                    now,
                    "protocol-backed local PIN lockout release reached timeout",
                    ops)) {
                return;
            }
            handle_local_pin_auth_display_failure(
                "protocol-backed local PIN lockout release refresh failed",
                true,
                ops);
            return;
        }
        if (!draw_local_pin_panel(ops, "Try again.")) {
            handle_local_pin_auth_display_failure(
                "local PIN authorization lockout display allocation failed",
                false,
                ops);
        }
        return;
    }

    const bool panel_active = local_pin_panel_visible(ops);
    const bool expired = local_pin_auth_deadline_expired(now);
    if (panel_active && !expired) {
        return;
    }

    if (!panel_active && !expired) {
        if (!draw_local_pin_panel(ops)) {
            finish_local_pin_panel_recovery_failure(purpose, request_id, ops);
        }
        return;
    }

    finish_local_pin_timeout_or_panel_loss(
        purpose,
        request_id,
        expired,
        panel_active,
        ops);
}

void local_pin_auth_ui_clear_if_needed(const LocalPinAuthUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const LocalPinAuthSnapshot snapshot = local_pin_auth_snapshot(now);
    if (!snapshot.flow_active) {
        return;
    }
    if (snapshot.processing) {
        clear_processing_local_pin_if_needed(snapshot, now, ops);
        return;
    }

    clear_waiting_local_pin_input_if_needed(snapshot, now, ops);
}

}  // namespace signing
