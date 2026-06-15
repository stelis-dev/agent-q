#include "agent_q_local_pin_auth_ui_flow.h"

#include <stdio.h>
#include <string.h>

#include "agent_q_connect_approval.h"
#include "agent_q_identification_display.h"
#include "agent_q_protocol_constants.h"
#include "agent_q_protocol_pin_approval.h"
#include "agent_q_local_reset.h"
#include "agent_q_modal_transition.h"
#include "agent_q_request_backed_local_pin_context.h"
#include "agent_q_user_signing_confirmation.h"
#include "agent_q_user_signing_flow.h"

namespace agent_q {
namespace {

constexpr size_t kMaxRequestIdSize = kAgentQRequestIdSize;

TickType_t now_or_zero(const AgentQLocalPinAuthUiFlowOps& ops)
{
    return ops.now != nullptr ? ops.now() : 0;
}

uint64_t wall_clock_ms_or_zero(const AgentQLocalPinAuthUiFlowOps& ops)
{
    return ops.wall_clock_ms != nullptr ? ops.wall_clock_ms() : 0;
}

AgentQTimeoutWindow window_from_now_ms(
    const AgentQLocalPinAuthUiFlowOps& ops,
    uint32_t duration_ms)
{
    const TickType_t now = now_or_zero(ops);
    return timeout_window_from_deadline(now, now + pdMS_TO_TICKS(duration_ms));
}

bool provisioned_material_ready(const AgentQLocalPinAuthUiFlowOps& ops)
{
    return ops.provisioned_material_ready != nullptr &&
           ops.provisioned_material_ready();
}

AgentQModalTransitionOps modal_transition_ops(const AgentQLocalPinAuthUiFlowOps& ops)
{
    return AgentQModalTransitionOps{
        ops.clear_panel_if_kind,
        ops.draw_processing_overlay_on_current_panel,
        ops.log_warn,
    };
}

bool draw_local_pin_panel(
    const AgentQLocalPinAuthUiFlowOps& ops,
    const char* notice = nullptr)
{
    return ops.draw_local_pin_auth_panel != nullptr &&
           ops.draw_local_pin_auth_panel(notice);
}

struct LocalPinPanelDrawContext {
    const AgentQLocalPinAuthUiFlowOps* ops = nullptr;
    const char* notice = nullptr;
};

bool draw_local_pin_panel_for_transition(void* context)
{
    const auto* draw_context = static_cast<const LocalPinPanelDrawContext*>(context);
    return draw_context != nullptr &&
           draw_context->ops != nullptr &&
           draw_local_pin_panel(*draw_context->ops, draw_context->notice);
}

bool draw_processing_or_local_pin_panel(const AgentQLocalPinAuthUiFlowOps& ops)
{
    LocalPinPanelDrawContext context{&ops, nullptr};
    return modal_transition_show_processing_or_redraw_panel(
        modal_transition_ops(ops),
        AgentQUiPanelKind::local_pin_auth,
        draw_local_pin_panel_for_transition,
        &context);
}

void show_message(
    const AgentQLocalPinAuthUiFlowOps& ops,
    const char* message,
    AgentQMessageKind kind)
{
    if (ops.show_message != nullptr) {
        ops.show_message(message, kind);
    }
}

void record_material_failure(
    const AgentQLocalPinAuthUiFlowOps& ops,
    AgentQPersistentMaterialRuntimeFailure failure)
{
    if (ops.record_material_failure != nullptr) {
        ops.record_material_failure(failure);
    }
}

void log_warn(const AgentQLocalPinAuthUiFlowOps& ops, const char* message)
{
    if (ops.log_warn != nullptr) {
        ops.log_warn(message);
    }
}

void wipe_local_pin_auth_scratch(
    const AgentQLocalPinAuthUiFlowOps& ops,
    const char* reason)
{
    const bool had_pin_auth = local_pin_auth_flow_active();
    local_pin_auth_clear_flow();
    if (had_pin_auth) {
        log_warn(ops, reason != nullptr ? reason : "local PIN authorization scratch wiped");
    }
}

void finish_policy_update_terminal(
    const AgentQLocalPinAuthUiFlowOps& ops,
    const char* request_id,
    AgentQPolicyUpdateFlowTerminalResult result)
{
    if (ops.finish_policy_update_terminal != nullptr) {
        ops.finish_policy_update_terminal(request_id, result);
    }
}

void finish_policy_update_error_terminal(
    const AgentQLocalPinAuthUiFlowOps& ops,
    const char* request_id,
    const char* error_code,
    const char* error_message,
    const char* display_message)
{
    if (ops.finish_policy_update_error_terminal != nullptr) {
        ops.finish_policy_update_error_terminal(
            request_id,
            error_code,
            error_message,
            display_message);
    }
}

void finish_user_signing_terminal(
    const AgentQLocalPinAuthUiFlowOps& ops,
    const char* request_id)
{
    if (ops.finish_user_signing_terminal != nullptr) {
        ops.finish_user_signing_terminal(request_id);
    }
}

void finish_user_signing_error_terminal(
    const AgentQLocalPinAuthUiFlowOps& ops,
    const char* request_id,
    const char* error_code,
    const char* error_message,
    const char* display_message)
{
    if (ops.finish_user_signing_error_terminal != nullptr) {
        ops.finish_user_signing_error_terminal(
            request_id,
            error_code,
            error_message,
            display_message);
    }
}

void complete_local_pin_processing_to_message(
    const AgentQLocalPinAuthUiFlowOps& ops,
    const char* message,
    AgentQMessageKind kind);
void complete_local_pin_to_policy_error_terminal(
    const AgentQLocalPinAuthUiFlowOps& ops,
    const char* request_id,
    const char* error_code,
    const char* error_message,
    const char* display_message);
void complete_local_pin_processing_to_policy_terminal(
    const AgentQLocalPinAuthUiFlowOps& ops,
    const char* request_id,
    AgentQPolicyUpdateFlowTerminalResult result);
void complete_local_pin_to_user_error_terminal(
    const AgentQLocalPinAuthUiFlowOps& ops,
    const char* request_id,
    const char* error_code,
    const char* error_message,
    const char* display_message);
void complete_local_pin_to_user_terminal(
    const AgentQLocalPinAuthUiFlowOps& ops,
    const char* request_id);

bool pending_request_id_for_local_pin_purpose(
    AgentQLocalPinAuthPurpose purpose,
    char* output,
    size_t output_size)
{
    return request_backed_local_pin_request_id(purpose, output, output_size);
}

AgentQTimeoutWindow local_pin_auth_next_input_window(
    AgentQLocalPinAuthPurpose purpose,
    TickType_t now,
    const AgentQLocalPinAuthUiFlowOps& ops)
{
    const AgentQTimeoutWindow next_input_window =
        timeout_window_from_deadline(
            now,
            now + pdMS_TO_TICKS(ops.local_pin_input_window_ms));
    if (purpose == AgentQLocalPinAuthPurpose::settings_human_approval_input ||
        purpose == AgentQLocalPinAuthPurpose::settings_signing_mode ||
        purpose == AgentQLocalPinAuthPurpose::settings_policy_reset ||
        purpose == AgentQLocalPinAuthPurpose::settings_change_pin) {
        return next_input_window;
    }
    if (!request_backed_local_pin_purpose(purpose)) {
        return kAgentQTimeoutWindowNone;
    }
    return request_backed_local_pin_cap_input_window(purpose, now, next_input_window);
}

bool resume_request_backed_pin_input_window(
    AgentQLocalPinAuthPurpose purpose,
    TickType_t now)
{
    return request_backed_local_pin_resume_input_window(purpose, now);
}

bool pause_request_backed_pin_input_window(
    AgentQLocalPinAuthPurpose purpose,
    TickType_t now)
{
    return request_backed_local_pin_pause_input_window(purpose, now);
}

bool request_backed_local_pin_input_deadline_reached(
    AgentQLocalPinAuthPurpose purpose,
    TickType_t now)
{
    return request_backed_local_pin_deadline_reached(purpose, now);
}

void write_policy_consistency_error(
    const AgentQLocalPinAuthUiFlowOps& ops,
    const char* request_id)
{
    const bool written =
        ops.write_policy_propose_result_with_current_policy != nullptr &&
        ops.write_policy_propose_result_with_current_policy(
            request_id,
            "consistency_error",
            "consistency_error");
    if (!written && ops.log_write_failure != nullptr) {
        ops.log_write_failure("policy_propose_result", request_id);
    }
}

void handle_local_pin_auth_display_failure(
    const char* reason,
    bool clear_panel,
    const AgentQLocalPinAuthUiFlowOps& ops)
{
    const AgentQLocalPinAuthSnapshot snapshot =
        local_pin_auth_snapshot(now_or_zero(ops));
    char request_id[kMaxRequestIdSize] = {};
    if (snapshot.purpose == AgentQLocalPinAuthPurpose::policy_update) {
        const bool protocol_request_found =
            protocol_pin_approval_request_id_for_local_pin_purpose(
                AgentQLocalPinAuthPurpose::policy_update,
                request_id,
                sizeof(request_id));
        if (!protocol_request_found) {
            const AgentQPolicyUpdateFlowSnapshot policy_snapshot =
                policy_update_flow_snapshot();
            if (policy_snapshot.active &&
                policy_snapshot.request_id != nullptr &&
                policy_snapshot.request_id[0] != '\0') {
                strlcpy(request_id, policy_snapshot.request_id, sizeof(request_id));
            }
        }
        if (request_id[0] != '\0') {
            wipe_local_pin_auth_scratch(ops, reason);
            if (clear_panel) {
                complete_local_pin_processing_to_policy_terminal(
                    ops,
                    request_id,
                    policy_update_flow_record_ui_error());
                return;
            }
            finish_policy_update_terminal(
                ops,
                request_id,
                policy_update_flow_record_ui_error());
            return;
        }
    }
    if (snapshot.purpose == AgentQLocalPinAuthPurpose::user_signing &&
        pending_request_id_for_local_pin_purpose(
            AgentQLocalPinAuthPurpose::user_signing,
            request_id,
            sizeof(request_id))) {
        user_signing_confirmation_cancel_for_pin_loss();
        wipe_local_pin_auth_scratch(ops, reason);
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
    if (snapshot.purpose == AgentQLocalPinAuthPurpose::connect &&
        protocol_pin_approval_request_id_for_local_pin_purpose(
            AgentQLocalPinAuthPurpose::connect,
            request_id,
            sizeof(request_id))) {
        wipe_local_pin_auth_scratch(ops, reason);
        if (ops.write_connect_rejected != nullptr) {
            ops.write_connect_rejected(
                request_id,
                "ui_error",
                "Could not show local PIN UI.");
        }
        if (ops.clear_connect_approval != nullptr) {
            ops.clear_connect_approval();
        }
        protocol_pin_approval_clear();
        if (clear_panel) {
            complete_local_pin_processing_to_message(
                ops,
                "Display error",
                AgentQMessageKind::error);
            return;
        }
        show_message(ops, "Display error", AgentQMessageKind::error);
        return;
    }
    wipe_local_pin_auth_scratch(ops, reason);
    if (clear_panel) {
        complete_local_pin_processing_to_message(
            ops,
            "Display error",
            AgentQMessageKind::error);
        return;
    }
    show_message(ops, "Display error", AgentQMessageKind::error);
}

bool finish_request_backed_local_pin_input_timeout_if_reached(
    AgentQLocalPinAuthPurpose purpose,
    TickType_t now,
    const char* scratch_reason,
    const AgentQLocalPinAuthUiFlowOps& ops)
{
    if (!request_backed_local_pin_input_deadline_reached(purpose, now)) {
        return false;
    }

    char request_id[kMaxRequestIdSize] = {};
    pending_request_id_for_local_pin_purpose(purpose, request_id, sizeof(request_id));
    wipe_local_pin_auth_scratch(ops, scratch_reason);
    switch (request_backed_local_pin_owner_for_purpose(purpose)) {
        case AgentQRequestBackedLocalPinOwner::protocol_pin_approval:
            if (purpose == AgentQLocalPinAuthPurpose::policy_update &&
                request_id[0] != '\0') {
                complete_local_pin_processing_to_policy_terminal(
                    ops,
                    request_id,
                    policy_update_flow_record_timed_out(wall_clock_ms_or_zero(ops)));
                return true;
            }
            if (purpose == AgentQLocalPinAuthPurpose::connect &&
                request_id[0] != '\0') {
                if (ops.write_connect_rejected != nullptr) {
                    ops.write_connect_rejected(
                        request_id,
                        "timeout",
                        "Connection PIN timed out.");
                }
                if (ops.clear_connect_approval != nullptr) {
                    ops.clear_connect_approval();
                }
                protocol_pin_approval_clear();
                complete_local_pin_processing_to_message(
                    ops,
                    "Connection timed out",
                    AgentQMessageKind::timeout);
                return true;
            }
            break;
        case AgentQRequestBackedLocalPinOwner::user_signing:
            if (request_id[0] != '\0') {
                const AgentQUserSigningConfirmationResult result =
                    user_signing_confirmation_record_timeout(now);
                if (result == AgentQUserSigningConfirmationResult::ok ||
                    user_signing_flow_terminal_pending()) {
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
        case AgentQRequestBackedLocalPinOwner::none:
        default:
            break;
    }
    complete_local_pin_processing_to_message(
        ops,
        "Auth timed out",
        AgentQMessageKind::timeout);
    return false;
}

bool start_settings_handoff(
    const char* stale_message,
    const AgentQLocalPinAuthUiFlowOps& ops)
{
    if (local_pin_auth_flow_active()) {
        log_warn(ops, stale_message);
        return false;
    }
    return ops.begin_settings_pin_auth_handoff != nullptr &&
           ops.begin_settings_pin_auth_handoff(stale_message);
}

void show_settings_error(const AgentQLocalPinAuthUiFlowOps& ops)
{
    complete_local_pin_processing_to_message(
        ops,
        "Settings error",
        AgentQMessageKind::error);
}

bool restore_settings_menu_after_pin(
    const char* wipe_reason,
    const char* message,
    AgentQMessageKind kind,
    const AgentQLocalPinAuthUiFlowOps& ops)
{
    if (ops.restore_settings_menu == nullptr) {
        return false;
    }
    ops.restore_settings_menu(wipe_reason, message, kind);
    return true;
}

struct RestoreSettingsContext {
    const AgentQLocalPinAuthUiFlowOps* ops = nullptr;
    const char* wipe_reason = nullptr;
    const char* message = nullptr;
    AgentQMessageKind kind = AgentQMessageKind::info;
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

void complete_local_pin_processing_to_settings(
    const AgentQLocalPinAuthUiFlowOps& ops,
    const char* wipe_reason,
    const char* message,
    AgentQMessageKind kind)
{
    RestoreSettingsContext context{&ops, wipe_reason, message, kind};
    modal_transition_complete_to_next_panel(
        modal_transition_ops(ops),
        AgentQUiPanelKind::local_pin_auth,
        restore_settings_menu_for_transition,
        &context);
}

struct ShowMessageContext {
    const AgentQLocalPinAuthUiFlowOps* ops = nullptr;
    const char* message = nullptr;
    AgentQMessageKind kind = AgentQMessageKind::info;
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
    const AgentQLocalPinAuthUiFlowOps& ops,
    const char* message,
    AgentQMessageKind kind)
{
    ShowMessageContext context{&ops, message, kind};
    modal_transition_complete_processing_to_result(
        modal_transition_ops(ops),
        AgentQUiPanelKind::local_pin_auth,
        show_message_for_transition,
        &context);
}

struct PolicyUpdateErrorTerminalContext {
    const AgentQLocalPinAuthUiFlowOps* ops = nullptr;
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
    const AgentQLocalPinAuthUiFlowOps& ops,
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
        AgentQUiPanelKind::local_pin_auth,
        finish_policy_update_error_terminal_for_transition,
        &context);
}

struct PolicyUpdateTerminalContext {
    const AgentQLocalPinAuthUiFlowOps* ops = nullptr;
    const char* request_id = nullptr;
    AgentQPolicyUpdateFlowTerminalResult result =
        AgentQPolicyUpdateFlowTerminalResult::invalid_state;
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
    const AgentQLocalPinAuthUiFlowOps& ops,
    const char* request_id,
    AgentQPolicyUpdateFlowTerminalResult result)
{
    PolicyUpdateTerminalContext context{&ops, request_id, result};
    modal_transition_complete_processing_to_result(
        modal_transition_ops(ops),
        AgentQUiPanelKind::local_pin_auth,
        finish_policy_update_terminal_for_transition,
        &context);
}

struct UserSigningErrorTerminalContext {
    const AgentQLocalPinAuthUiFlowOps* ops = nullptr;
    const char* request_id = nullptr;
    const char* error_code = nullptr;
    const char* error_message = nullptr;
    const char* display_message = nullptr;
};

void finish_user_signing_error_terminal_for_transition(void* context)
{
    const auto* terminal_context =
        static_cast<const UserSigningErrorTerminalContext*>(context);
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
    const AgentQLocalPinAuthUiFlowOps& ops,
    const char* request_id,
    const char* error_code,
    const char* error_message,
    const char* display_message)
{
    UserSigningErrorTerminalContext context{
        &ops,
        request_id,
        error_code,
        error_message,
        display_message};
    modal_transition_complete_to_result(
        modal_transition_ops(ops),
        AgentQUiPanelKind::local_pin_auth,
        finish_user_signing_error_terminal_for_transition,
        &context);
}

struct UserSigningTerminalContext {
    const AgentQLocalPinAuthUiFlowOps* ops = nullptr;
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
    const AgentQLocalPinAuthUiFlowOps& ops,
    const char* request_id)
{
    UserSigningTerminalContext context{&ops, request_id};
    modal_transition_complete_to_result(
        modal_transition_ops(ops),
        AgentQUiPanelKind::local_pin_auth,
        finish_user_signing_terminal_for_transition,
        &context);
}

struct DrawReviewPanelContext {
    const AgentQLocalPinAuthUiFlowOps* ops = nullptr;
    AgentQLocalPinAuthPurpose purpose = AgentQLocalPinAuthPurpose::none;
};

bool draw_review_panel_for_transition(void* context)
{
    const auto* draw_context = static_cast<const DrawReviewPanelContext*>(context);
    if (draw_context == nullptr || draw_context->ops == nullptr) {
        return false;
    }
    switch (draw_context->purpose) {
        case AgentQLocalPinAuthPurpose::policy_update:
            return draw_context->ops->show_policy_update_review != nullptr &&
                   draw_context->ops->show_policy_update_review();
        case AgentQLocalPinAuthPurpose::connect:
            if (draw_context->ops->show_connect_review == nullptr) {
                return false;
            }
            draw_context->ops->show_connect_review();
            return true;
        case AgentQLocalPinAuthPurpose::user_signing:
            return draw_context->ops->show_user_signing_review != nullptr &&
                   draw_context->ops->show_user_signing_review();
        default:
            return false;
    }
}

bool complete_local_pin_to_review_panel(
    const AgentQLocalPinAuthUiFlowOps& ops,
    AgentQLocalPinAuthPurpose purpose)
{
    DrawReviewPanelContext context{&ops, purpose};
    return modal_transition_complete_to_next_panel(
        modal_transition_ops(ops),
        AgentQUiPanelKind::local_pin_auth,
        draw_review_panel_for_transition,
        &context);
}

struct UserSigningWorkContext {
    const AgentQLocalPinAuthUiFlowOps* ops = nullptr;
    const char* request_id = nullptr;
};

void execute_user_signing_for_transition(void* context)
{
    const auto* work_context = static_cast<const UserSigningWorkContext*>(context);
    if (work_context == nullptr ||
        work_context->ops == nullptr ||
        work_context->ops->execute_user_signing_critical_section_and_finish == nullptr) {
        return;
    }
    work_context->ops->execute_user_signing_critical_section_and_finish(
        work_context->request_id);
}

void run_user_signing_then_clear_local_pin_panel(
    const AgentQLocalPinAuthUiFlowOps& ops,
    const char* request_id)
{
    UserSigningWorkContext context{&ops, request_id};
    modal_transition_run_work_then_clear_panel(
        modal_transition_ops(ops),
        AgentQUiPanelKind::local_pin_auth,
        execute_user_signing_for_transition,
        &context);
}

}  // namespace

bool local_pin_auth_ui_panel_matches_stage(AgentQUiPanelKind kind)
{
    return kind == AgentQUiPanelKind::local_pin_auth &&
           local_pin_auth_flow_active();
}

bool local_pin_auth_ui_accepts_keypad_input()
{
    return local_pin_auth_accepts_keypad_input();
}

bool local_pin_auth_ui_begin_connect(
    const char* request_id,
    const AgentQLocalPinAuthUiFlowOps& ops)
{
    identification_display_clear();
    const TickType_t now = now_or_zero(ops);
    const AgentQTimeoutWindow request_window =
        timeout_window_from_deadline(
            now,
            now + pdMS_TO_TICKS(ops.connect_approval_ms));
    if (!protocol_pin_approval_begin_connect(request_id, now, request_window)) {
        if (ops.write_connect_rejected != nullptr) {
            ops.write_connect_rejected(
                request_id,
                "invalid_state",
                "Connect is unavailable.");
        }
        if (ops.clear_connect_approval != nullptr) {
            ops.clear_connect_approval();
        }
        show_message(ops, "Connect unavailable", AgentQMessageKind::error);
        return false;
    }
    if (!local_pin_auth_begin_connect(now, request_window)) {
        if (ops.write_connect_rejected != nullptr) {
            ops.write_connect_rejected(
                request_id,
                "invalid_state",
                "Connect PIN is unavailable.");
        }
        if (ops.clear_connect_approval != nullptr) {
            ops.clear_connect_approval();
        }
        protocol_pin_approval_clear();
        show_message(ops, "Connect unavailable", AgentQMessageKind::error);
        return false;
    }

    if (!draw_local_pin_panel(ops)) {
        if (ops.write_connect_rejected != nullptr) {
            ops.write_connect_rejected(
                request_id,
                "ui_error",
                "Could not show local PIN UI.");
        }
        wipe_local_pin_auth_scratch(ops, "connect PIN display allocation failed");
        if (ops.clear_connect_approval != nullptr) {
            ops.clear_connect_approval();
        }
        protocol_pin_approval_clear();
        show_message(ops, "Display error", AgentQMessageKind::error);
        return false;
    }
    return true;
}

void local_pin_auth_ui_start_settings_human_approval_input(
    const AgentQLocalPinAuthUiFlowOps& ops)
{
    if (!start_settings_handoff(
            "Stale human approval input setting action ignored",
            ops)) {
        return;
    }

    AgentQHumanApprovalInputMode current_mode = AgentQHumanApprovalInputMode::pin;
    if (ops.read_human_approval_input_mode == nullptr ||
        !ops.read_human_approval_input_mode(&current_mode)) {
        show_settings_error(ops);
        return;
    }
    const AgentQHumanApprovalInputMode target_mode =
        current_mode == AgentQHumanApprovalInputMode::pin
            ? AgentQHumanApprovalInputMode::confirm
            : AgentQHumanApprovalInputMode::pin;
    const TickType_t now = now_or_zero(ops);
    if (!local_pin_auth_begin_human_approval_input_setting(
            target_mode,
            now,
            timeout_window_from_deadline(
                now,
                now + pdMS_TO_TICKS(ops.local_reset_entry_ms)))) {
        show_message(ops, "Settings unavailable", AgentQMessageKind::error);
        return;
    }

    if (!draw_local_pin_panel(ops)) {
        wipe_local_pin_auth_scratch(
            ops,
            "human approval input setting display allocation failed");
        show_message(ops, "Display error", AgentQMessageKind::error);
    }
}

void local_pin_auth_ui_start_settings_signing_mode(
    const AgentQLocalPinAuthUiFlowOps& ops)
{
    if (!start_settings_handoff(
            "Stale settings signing mode action ignored",
            ops)) {
        return;
    }

    AgentQSigningAuthorizationMode current_mode =
        AgentQSigningAuthorizationMode::user;
    if (ops.read_signing_authorization_mode == nullptr ||
        !ops.read_signing_authorization_mode(&current_mode)) {
        show_settings_error(ops);
        return;
    }

    const AgentQSigningAuthorizationMode target_mode =
        current_mode == AgentQSigningAuthorizationMode::policy
            ? AgentQSigningAuthorizationMode::user
            : AgentQSigningAuthorizationMode::policy;
    const TickType_t now = now_or_zero(ops);
    if (!local_pin_auth_begin_signing_mode_setting(
            target_mode,
            now,
            timeout_window_from_deadline(
                now,
                now + pdMS_TO_TICKS(ops.local_reset_entry_ms)))) {
        show_message(ops, "Settings unavailable", AgentQMessageKind::error);
        return;
    }

    if (!draw_local_pin_panel(ops)) {
        wipe_local_pin_auth_scratch(
            ops,
            "settings signing mode display allocation failed");
        show_message(ops, "Display error", AgentQMessageKind::error);
    }
}

void local_pin_auth_ui_start_settings_policy_reset(
    const AgentQLocalPinAuthUiFlowOps& ops)
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
                now + pdMS_TO_TICKS(ops.local_reset_entry_ms)))) {
        show_message(ops, "Policy reset unavailable", AgentQMessageKind::error);
        return;
    }

    if (!draw_local_pin_panel(ops)) {
        wipe_local_pin_auth_scratch(
            ops,
            "settings policy reset display allocation failed");
        show_message(ops, "Display error", AgentQMessageKind::error);
    }
}

void local_pin_auth_ui_start_settings_change_pin(
    const AgentQLocalPinAuthUiFlowOps& ops)
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
                now + pdMS_TO_TICKS(ops.local_reset_entry_ms)))) {
        show_message(ops, "Change PIN unavailable", AgentQMessageKind::error);
        return;
    }

    if (!draw_local_pin_panel(ops)) {
        wipe_local_pin_auth_scratch(
            ops,
            "settings Change PIN display allocation failed");
        show_message(ops, "Display error", AgentQMessageKind::error);
    }
}

void local_pin_auth_ui_cancel(
    const char* message,
    const AgentQLocalPinAuthUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const AgentQLocalPinAuthSnapshot snapshot = local_pin_auth_snapshot(now);
    if (!snapshot.flow_active || !snapshot.accepts_keypad_input) {
        log_warn(ops, "Stale local PIN authorization cancel ignored");
        return;
    }

    const AgentQLocalPinAuthPurpose purpose = snapshot.purpose;
    if (finish_request_backed_local_pin_input_timeout_if_reached(
            purpose,
            now,
            "request-backed local PIN cancel reached timeout",
            ops)) {
        return;
    }

    char request_id[kMaxRequestIdSize] = {};
    pending_request_id_for_local_pin_purpose(purpose, request_id, sizeof(request_id));

    if (purpose == AgentQLocalPinAuthPurpose::policy_update &&
        request_id[0] != '\0') {
        wipe_local_pin_auth_scratch(ops, "local PIN authorization canceled");
        protocol_pin_approval_clear();
        const AgentQPolicyUpdateFlowTransitionResult transition =
            policy_update_flow_return_to_review(
                now,
                timeout_window_from_deadline(
                    now,
                    now + pdMS_TO_TICKS(ops.provisioning_approval_ms)));
        if (transition != AgentQPolicyUpdateFlowTransitionResult::ok) {
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
                policy_update_flow_record_ui_error());
        }
        return;
    }
    if (purpose == AgentQLocalPinAuthPurpose::connect &&
        request_id[0] != '\0') {
        wipe_local_pin_auth_scratch(ops, "local PIN authorization canceled");
        protocol_pin_approval_clear();
        if (ops.connect_approval_return_to_review == nullptr ||
            !ops.connect_approval_return_to_review(
                now,
                timeout_window_from_deadline(
                    now,
                    now + pdMS_TO_TICKS(ops.connect_approval_ms)))) {
            if (ops.write_connect_rejected != nullptr) {
                ops.write_connect_rejected(
                    request_id,
                    "invalid_state",
                    "Connect is unavailable.");
            }
            if (ops.clear_connect_approval != nullptr) {
                ops.clear_connect_approval();
            }
            complete_local_pin_processing_to_message(
                ops,
                "Connect unavailable",
                AgentQMessageKind::error);
            return;
        }
        if (!complete_local_pin_to_review_panel(ops, purpose)) {
            complete_local_pin_processing_to_message(
                ops,
                "Display error",
                AgentQMessageKind::error);
        }
        return;
    }
    if (purpose == AgentQLocalPinAuthPurpose::user_signing &&
        request_id[0] != '\0') {
        const AgentQUserSigningConfirmationResult result =
            user_signing_confirmation_return_to_review_from_pin(
                now,
                window_from_now_ms(ops, ops.provisioning_approval_ms));
        if (result == AgentQUserSigningConfirmationResult::ok) {
            if (!complete_local_pin_to_review_panel(ops, purpose)) {
                user_signing_flow_cancel_for_ui_loss();
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
    if (purpose == AgentQLocalPinAuthPurpose::settings_human_approval_input ||
        purpose == AgentQLocalPinAuthPurpose::settings_signing_mode ||
        purpose == AgentQLocalPinAuthPurpose::settings_policy_reset ||
        purpose == AgentQLocalPinAuthPurpose::settings_change_pin) {
        wipe_local_pin_auth_scratch(ops, "local PIN authorization canceled");
        complete_local_pin_processing_to_settings(
            ops,
            "local settings display allocation failed after PIN cancel",
            "Display error",
            AgentQMessageKind::error);
        return;
    }

    wipe_local_pin_auth_scratch(ops, "local PIN authorization canceled");
    complete_local_pin_processing_to_message(
        ops,
        message != nullptr && message[0] != '\0' ? message : "Settings canceled",
        AgentQMessageKind::rejected);
}

void local_pin_auth_ui_handle_digit(
    char digit,
    const AgentQLocalPinAuthUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const AgentQLocalPinAuthSnapshot snapshot = local_pin_auth_snapshot(now);
    if (snapshot.flow_active &&
        finish_request_backed_local_pin_input_timeout_if_reached(
            snapshot.purpose,
            now,
            "request-backed local PIN digit reached timeout",
            ops)) {
        return;
    }
    const AgentQLocalPinAuthInputResult result = local_pin_auth_add_digit(digit);
    if (result == AgentQLocalPinAuthInputResult::inactive ||
        result == AgentQLocalPinAuthInputResult::locked ||
        result == AgentQLocalPinAuthInputResult::invalid_digit) {
        return;
    }
    if (!draw_local_pin_panel(ops)) {
        handle_local_pin_auth_display_failure(
            "local PIN authorization display allocation failed",
            false,
            ops);
    }
}

void local_pin_auth_ui_handle_clear(const AgentQLocalPinAuthUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const AgentQLocalPinAuthSnapshot snapshot = local_pin_auth_snapshot(now);
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

void local_pin_auth_ui_handle_backspace(const AgentQLocalPinAuthUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const AgentQLocalPinAuthSnapshot snapshot = local_pin_auth_snapshot(now);
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

void local_pin_auth_ui_handle_submit(const AgentQLocalPinAuthUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const AgentQLocalPinAuthSnapshot snapshot = local_pin_auth_snapshot(now);
    if (snapshot.flow_active &&
        finish_request_backed_local_pin_input_timeout_if_reached(
            snapshot.purpose,
            now,
            "request-backed local PIN submit reached timeout",
            ops)) {
        return;
    }
    const AgentQTimeoutWindow next_input_window =
        local_pin_auth_next_input_window(snapshot.purpose, now, ops);
    const AgentQLocalPinAuthSubmitResult result =
        local_pin_auth_submit(
            now + pdMS_TO_TICKS(ops.local_processing_render_delay_ms),
            now + pdMS_TO_TICKS(ops.local_processing_display_ms),
            next_input_window,
            now + pdMS_TO_TICKS(ops.local_auth_worker_max_ms));
    switch (result) {
        case AgentQLocalPinAuthSubmitResult::unavailable_stage:
            log_warn(ops, "Stale local PIN authorization submit ignored");
            return;
        case AgentQLocalPinAuthSubmitResult::locked:
            return;
        case AgentQLocalPinAuthSubmitResult::worker_unavailable:
            if (!draw_local_pin_panel(ops, "Auth worker busy. Try again.")) {
                handle_local_pin_auth_display_failure(
                    "local PIN worker unavailable display allocation failed",
                    true,
                    ops);
            }
            return;
        case AgentQLocalPinAuthSubmitResult::invalid_pin:
            if (!draw_local_pin_panel(ops, "Enter exactly 6 digits.")) {
                handle_local_pin_auth_display_failure(
                    "local PIN authorization display allocation failed",
                    false,
                    ops);
            }
            return;
        case AgentQLocalPinAuthSubmitResult::advanced_to_repeat_pin:
            if (!draw_local_pin_panel(ops)) {
                handle_local_pin_auth_display_failure(
                    "Change PIN repeat display allocation failed",
                    false,
                    ops);
            }
            return;
        case AgentQLocalPinAuthSubmitResult::mismatch_restart:
            if (!draw_local_pin_panel(ops, "PINs did not match.")) {
                handle_local_pin_auth_display_failure(
                    "Change PIN mismatch display allocation failed",
                    false,
                    ops);
            }
            return;
        case AgentQLocalPinAuthSubmitResult::started_pin_change_commit:
            if (!draw_processing_or_local_pin_panel(ops)) {
                handle_local_pin_auth_display_failure(
                    "Change PIN commit display allocation failed",
                    true,
                    ops);
            }
            return;
        case AgentQLocalPinAuthSubmitResult::started_verification:
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
    const AgentQLocalPinAuthUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const AgentQLocalPinAuthCommitResult result = local_pin_auth_commit_if_ready(now);
    if (result == AgentQLocalPinAuthCommitResult::not_ready) {
        return;
    }
    if (result == AgentQLocalPinAuthCommitResult::pin_change_auth_unavailable) {
        record_material_failure(
            ops,
            AgentQPersistentMaterialRuntimeFailure::pin_change_auth_unavailable);
        complete_local_pin_processing_to_message(
            ops,
            "Auth error",
            AgentQMessageKind::error);
        return;
    }
    if (result == AgentQLocalPinAuthCommitResult::pin_change_storage_error) {
        complete_local_pin_processing_to_message(
            ops,
            "PIN change failed",
            AgentQMessageKind::error);
        return;
    }
    if (result == AgentQLocalPinAuthCommitResult::storage_error) {
        complete_local_pin_processing_to_message(
            ops,
            "Settings error",
            AgentQMessageKind::error);
        return;
    }

    complete_local_pin_processing_to_settings(
        ops,
        "local settings display allocation failed after PIN commit",
        result == AgentQLocalPinAuthCommitResult::pin_changed
            ? "PIN changed"
            : "Settings saved",
        AgentQMessageKind::success);
}

void local_pin_auth_ui_handle_verify_worker_result(
    const AgentQLocalAuthWorkerResult& worker_result,
    const AgentQLocalPinAuthUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const AgentQLocalPinAuthSnapshot snapshot = local_pin_auth_snapshot(now);
    if (!snapshot.flow_active || snapshot.stage != AgentQLocalPinAuthStage::pin_verifying) {
        return;
    }

    const AgentQLocalPinAuthPurpose purpose = snapshot.purpose;
    if (purpose == AgentQLocalPinAuthPurpose::user_signing) {
        char request_id[kMaxRequestIdSize] = {};
        pending_request_id_for_local_pin_purpose(purpose, request_id, sizeof(request_id));
        if (!provisioned_material_ready(ops)) {
            user_signing_confirmation_cancel_for_pin_loss();
            wipe_local_pin_auth_scratch(ops, "user_signing material state unavailable");
            complete_local_pin_to_user_error_terminal(
                ops,
                request_id,
                "invalid_state",
                "Signing request is unavailable.",
                "Signing unavailable");
            return;
        }

        const AgentQUserSigningConfirmationResult confirmation_result =
            user_signing_confirmation_complete_pin_verify_job_and_write_history(
                worker_result,
                now,
                now + pdMS_TO_TICKS(kAgentQLocalResetPinLockoutMs),
                ops.write_user_signing_confirmation_history,
                nullptr);
        switch (confirmation_result) {
            case AgentQUserSigningConfirmationResult::not_ready:
                return;
            case AgentQUserSigningConfirmationResult::wrong_pin:
                if (!draw_local_pin_panel(ops, "Wrong PIN.")) {
                    handle_local_pin_auth_display_failure(
                        "user_signing PIN display allocation failed after wrong PIN",
                        false,
                        ops);
                }
                return;
            case AgentQUserSigningConfirmationResult::locked:
                if (!draw_local_pin_panel(ops, "Too many wrong PINs. Wait 30s.")) {
                    handle_local_pin_auth_display_failure(
                        "user_signing PIN lockout display allocation failed",
                        false,
                        ops);
                }
                return;
            case AgentQUserSigningConfirmationResult::auth_unavailable:
                record_material_failure(
                    ops,
                    AgentQPersistentMaterialRuntimeFailure::local_pin_auth_unavailable);
                complete_local_pin_to_user_error_terminal(
                    ops,
                    request_id,
                    "auth_unavailable",
                    "Local PIN verifier unavailable.",
                    "Auth error");
                return;
            case AgentQUserSigningConfirmationResult::history_error:
                complete_local_pin_to_user_error_terminal(
                    ops,
                    request_id,
                    "history_error",
                    "Could not record signing confirmation.",
                    "History error");
                return;
            case AgentQUserSigningConfirmationResult::ok:
                break;
            case AgentQUserSigningConfirmationResult::deadline_expired:
            case AgentQUserSigningConfirmationResult::deadline_not_reached:
            case AgentQUserSigningConfirmationResult::invalid_session:
            case AgentQUserSigningConfirmationResult::inactive:
            case AgentQUserSigningConfirmationResult::wrong_stage:
            case AgentQUserSigningConfirmationResult::invalid_argument:
            case AgentQUserSigningConfirmationResult::invalid_deadline:
            case AgentQUserSigningConfirmationResult::session_still_active:
            case AgentQUserSigningConfirmationResult::local_pin_busy:
            case AgentQUserSigningConfirmationResult::local_pin_unavailable:
            case AgentQUserSigningConfirmationResult::stale_state:
            case AgentQUserSigningConfirmationResult::busy:
                if (user_signing_flow_terminal_pending()) {
                    complete_local_pin_to_user_terminal(ops, request_id);
                    return;
                }
                complete_local_pin_to_user_error_terminal(
                    ops,
                    request_id,
                    confirmation_result == AgentQUserSigningConfirmationResult::invalid_session
                        ? "invalid_session"
                        : "invalid_state",
                    "Signing request is unavailable.",
                    "Signing unavailable");
                return;
        }

        run_user_signing_then_clear_local_pin_panel(ops, request_id);
        return;
    }
    if (!provisioned_material_ready(ops)) {
        char request_id[kMaxRequestIdSize] = {};
        pending_request_id_for_local_pin_purpose(purpose, request_id, sizeof(request_id));
        wipe_local_pin_auth_scratch(ops, "local PIN authorization material state unavailable");
        if (purpose == AgentQLocalPinAuthPurpose::policy_update && request_id[0] != '\0') {
            if (ops.write_error != nullptr) {
                ops.write_error(
                    request_id,
                    "invalid_state",
                    "Policy update is unavailable.");
            }
            policy_update_flow_clear();
            protocol_pin_approval_clear();
        }
        if (request_id[0] != '\0') {
            if (purpose == AgentQLocalPinAuthPurpose::policy_update) {
                complete_local_pin_processing_to_message(
                    ops,
                    "PIN unavailable",
                    AgentQMessageKind::error);
                return;
            }
            if (ops.write_connect_rejected != nullptr) {
                ops.write_connect_rejected(
                    request_id,
                    "invalid_state",
                    "Connect is unavailable.");
            }
            if (ops.clear_connect_approval != nullptr) {
                ops.clear_connect_approval();
            }
            protocol_pin_approval_clear();
        }
        complete_local_pin_processing_to_message(
            ops,
            "PIN unavailable",
            AgentQMessageKind::error);
        return;
    }

    if (finish_request_backed_local_pin_input_timeout_if_reached(
            purpose,
            now,
            "protocol-backed local PIN verifier result reached timeout",
            ops)) {
        return;
    }

    const AgentQTimeoutWindow next_input_window =
        local_pin_auth_next_input_window(purpose, now, ops);
    const AgentQLocalPinAuthVerifyResult result =
        local_pin_auth_complete_verify_job(
            worker_result,
            next_input_window,
            now + pdMS_TO_TICKS(kAgentQLocalResetPinLockoutMs),
            now + pdMS_TO_TICKS(ops.local_processing_display_ms));
    if ((result == AgentQLocalPinAuthVerifyResult::locked ||
         result == AgentQLocalPinAuthVerifyResult::wrong_pin ||
         result == AgentQLocalPinAuthVerifyResult::verified_connect ||
         result == AgentQLocalPinAuthVerifyResult::verified_settings_policy_reset ||
         result == AgentQLocalPinAuthVerifyResult::verified_policy_update) &&
        request_backed_local_pin_input_deadline_reached(purpose, now)) {
        if (finish_request_backed_local_pin_input_timeout_if_reached(
                purpose,
                now,
                "protocol-backed local PIN authorization timed out",
                ops)) {
            return;
        }
        complete_local_pin_processing_to_message(
            ops,
            "Auth timed out",
            AgentQMessageKind::timeout);
        return;
    }
    switch (result) {
        case AgentQLocalPinAuthVerifyResult::not_ready:
            return;
        case AgentQLocalPinAuthVerifyResult::auth_unavailable: {
            char request_id[kMaxRequestIdSize] = {};
            pending_request_id_for_local_pin_purpose(purpose, request_id, sizeof(request_id));
            record_material_failure(
                ops,
                AgentQPersistentMaterialRuntimeFailure::local_pin_auth_unavailable);
            wipe_local_pin_auth_scratch(ops, "local PIN authorization verifier unavailable");
            if (purpose == AgentQLocalPinAuthPurpose::policy_update &&
                request_id[0] != '\0') {
                write_policy_consistency_error(ops, request_id);
                policy_update_flow_clear();
                protocol_pin_approval_clear();
                complete_local_pin_processing_to_message(
                    ops,
                    "Auth error",
                    AgentQMessageKind::error);
                return;
            }
            if (request_id[0] != '\0') {
                if (ops.write_connect_rejected != nullptr) {
                    ops.write_connect_rejected(
                        request_id,
                        "auth_unavailable",
                        "Local PIN verifier unavailable.");
                }
                if (ops.clear_connect_approval != nullptr) {
                    ops.clear_connect_approval();
                }
                protocol_pin_approval_clear();
            }
            complete_local_pin_processing_to_message(
                ops,
                "Auth error",
                AgentQMessageKind::error);
            return;
        }
        case AgentQLocalPinAuthVerifyResult::locked:
            if (purpose == AgentQLocalPinAuthPurpose::policy_update &&
                policy_update_flow_return_to_pin_entry() !=
                    AgentQPolicyUpdateFlowTransitionResult::ok) {
                handle_local_pin_auth_display_failure(
                    "policy update lockout stage transition failed",
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
        case AgentQLocalPinAuthVerifyResult::wrong_pin:
            if (purpose == AgentQLocalPinAuthPurpose::policy_update &&
                policy_update_flow_return_to_pin_entry() !=
                    AgentQPolicyUpdateFlowTransitionResult::ok) {
                handle_local_pin_auth_display_failure(
                    "policy update wrong-PIN stage transition failed",
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
        case AgentQLocalPinAuthVerifyResult::advanced_to_change_pin:
            if (!draw_local_pin_panel(ops)) {
                handle_local_pin_auth_display_failure(
                    "Change PIN new PIN display allocation failed",
                    false,
                    ops);
            }
            return;
        case AgentQLocalPinAuthVerifyResult::verified_connect: {
            char request_id[kMaxRequestIdSize] = {};
            pending_request_id_for_local_pin_purpose(
                AgentQLocalPinAuthPurpose::connect,
                request_id,
                sizeof(request_id));
            if (ops.replace_active_session == nullptr ||
                !ops.replace_active_session()) {
                if (request_id[0] != '\0' && ops.write_error != nullptr) {
                    ops.write_error(request_id, "rng_error", "Could not create session id.");
                }
                if (ops.log_connect_session_creation_failed != nullptr) {
                    ops.log_connect_session_creation_failed(request_id);
                }
                wipe_local_pin_auth_scratch(ops, "connect PIN session creation failed");
                if (ops.clear_connect_approval != nullptr) {
                    ops.clear_connect_approval();
                }
                protocol_pin_approval_clear();
                complete_local_pin_processing_to_message(
                    ops,
                    "RNG error",
                    AgentQMessageKind::error);
                return;
            }
            wipe_local_pin_auth_scratch(ops, "connect PIN approved");
            if (ops.clear_connect_approval != nullptr) {
                ops.clear_connect_approval();
            }
            if (request_id[0] != '\0') {
                const bool written =
                    ops.write_connect_approved != nullptr &&
                    ops.write_connect_approved(request_id);
                if (!written && ops.log_write_failure != nullptr) {
                    ops.log_write_failure("connect_result", request_id);
                }
            }
            protocol_pin_approval_clear();
            if (ops.log_connect_pin_approved != nullptr) {
                ops.log_connect_pin_approved(request_id);
            }
            complete_local_pin_processing_to_message(
                ops,
                "Connected",
                AgentQMessageKind::success);
            return;
        }
        case AgentQLocalPinAuthVerifyResult::verified_settings_policy_reset: {
            const bool stored = ops.store_default_policy != nullptr &&
                                ops.store_default_policy();
            wipe_local_pin_auth_scratch(
                ops,
                stored ? "settings policy reset committed" : "settings policy reset failed");
            complete_local_pin_processing_to_settings(
                ops,
                "local settings display allocation failed after policy reset",
                stored ? "Policy reset" : "Policy reset failed",
                stored ? AgentQMessageKind::success : AgentQMessageKind::error);
            return;
        }
        case AgentQLocalPinAuthVerifyResult::verified_policy_update: {
            char request_id[kMaxRequestIdSize] = {};
            pending_request_id_for_local_pin_purpose(
                AgentQLocalPinAuthPurpose::policy_update,
                request_id,
                sizeof(request_id));
            if (ops.require_pending_policy_update_session == nullptr ||
                !ops.require_pending_policy_update_session(request_id)) {
                wipe_local_pin_auth_scratch(
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
            wipe_local_pin_auth_scratch(ops, "policy update PIN approved");
            const AgentQPolicyUpdateFlowTerminalResult commit_result =
                policy_update_flow_commit(wall_clock_ms_or_zero(ops));
            complete_local_pin_processing_to_policy_terminal(
                ops,
                request_id,
                commit_result);
            return;
        }
        case AgentQLocalPinAuthVerifyResult::started_setting_commit:
            if (!draw_processing_or_local_pin_panel(ops)) {
                wipe_local_pin_auth_scratch(ops, "settings PIN commit display allocation failed");
                complete_local_pin_processing_to_message(
                    ops,
                    "Display error",
                    AgentQMessageKind::error);
            }
            return;
    }
}

void local_pin_auth_ui_handle_prepare_worker_result(
    const AgentQLocalAuthWorkerResult& worker_result,
    const AgentQLocalPinAuthUiFlowOps& ops)
{
    const AgentQLocalPinAuthCommitResult result =
        local_pin_auth_complete_pin_change_job(worker_result);
    if (result == AgentQLocalPinAuthCommitResult::not_ready) {
        return;
    }
    if (result == AgentQLocalPinAuthCommitResult::pin_change_auth_unavailable) {
        record_material_failure(
            ops,
            AgentQPersistentMaterialRuntimeFailure::pin_change_auth_unavailable);
        complete_local_pin_processing_to_message(
            ops,
            "Auth error",
            AgentQMessageKind::error);
        return;
    }
    if (result == AgentQLocalPinAuthCommitResult::pin_change_storage_error) {
        complete_local_pin_processing_to_message(
            ops,
            "PIN change failed",
            AgentQMessageKind::error);
        return;
    }

    complete_local_pin_processing_to_settings(
        ops,
        "local settings display allocation failed after PIN commit",
        "PIN changed",
        AgentQMessageKind::success);
}

void local_pin_auth_ui_clear_if_needed(const AgentQLocalPinAuthUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const AgentQLocalPinAuthSnapshot snapshot = local_pin_auth_snapshot(now);
    if (!snapshot.flow_active) {
        return;
    }
    if (snapshot.processing) {
        if (snapshot.purpose == AgentQLocalPinAuthPurpose::user_signing) {
            char request_id[kMaxRequestIdSize] = {};
            pending_request_id_for_local_pin_purpose(
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
                user_signing_confirmation_cancel_for_pin_loss();
                wipe_local_pin_auth_scratch(ops, "user_signing local PIN verifier timed out");
                record_material_failure(
                    ops,
                    AgentQPersistentMaterialRuntimeFailure::local_pin_auth_unavailable);
                complete_local_pin_to_user_error_terminal(
                    ops,
                    request_id,
                    "auth_unavailable",
                    "Local PIN verifier unavailable.",
                    "Auth error");
                return;
            }
            const bool panel_active =
                ops.local_pin_panel_visible != nullptr && ops.local_pin_panel_visible();
            if (!panel_active && !draw_local_pin_panel(ops)) {
                handle_local_pin_auth_display_failure(
                    "user_signing PIN authorization processing UI recovery failed",
                    true,
                    ops);
            }
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
                AgentQMessageKind::timeout);
            return;
        }
        if (!local_pin_auth_fail_processing_if_expired(now)) {
            const bool panel_active =
                ops.local_pin_panel_visible != nullptr && ops.local_pin_panel_visible();
            if (!panel_active && !draw_local_pin_panel(ops)) {
                handle_local_pin_auth_display_failure(
                    "local PIN authorization processing UI recovery failed",
                    true,
                    ops);
            }
            return;
        }

        const AgentQLocalPinAuthPurpose purpose = snapshot.purpose;
        char request_id[kMaxRequestIdSize] = {};
        pending_request_id_for_local_pin_purpose(purpose, request_id, sizeof(request_id));
        if (snapshot.stage == AgentQLocalPinAuthStage::pin_verifying) {
            record_material_failure(
                ops,
                AgentQPersistentMaterialRuntimeFailure::local_pin_auth_unavailable);
            if (purpose == AgentQLocalPinAuthPurpose::policy_update &&
                request_id[0] != '\0') {
                write_policy_consistency_error(ops, request_id);
                policy_update_flow_clear();
                protocol_pin_approval_clear();
                complete_local_pin_processing_to_message(
                    ops,
                    "Auth error",
                    AgentQMessageKind::error);
                return;
            }
            if (request_id[0] != '\0') {
                if (ops.write_connect_rejected != nullptr) {
                    ops.write_connect_rejected(
                        request_id,
                        "auth_unavailable",
                        "Local PIN verifier unavailable.");
                }
                if (ops.clear_connect_approval != nullptr) {
                    ops.clear_connect_approval();
                }
                protocol_pin_approval_clear();
            }
            complete_local_pin_processing_to_message(
                ops,
                "Auth error",
                AgentQMessageKind::error);
            return;
        }
        if (purpose == AgentQLocalPinAuthPurpose::policy_update &&
            request_id[0] != '\0') {
            complete_local_pin_processing_to_policy_terminal(
                ops,
                request_id,
                policy_update_flow_record_timed_out(wall_clock_ms_or_zero(ops)));
            return;
        }
        if (request_id[0] != '\0') {
            if (ops.write_connect_rejected != nullptr) {
                ops.write_connect_rejected(
                    request_id,
                    "timeout",
                    "Connection PIN timed out.");
            }
            if (ops.clear_connect_approval != nullptr) {
                ops.clear_connect_approval();
            }
            protocol_pin_approval_clear();
            complete_local_pin_processing_to_message(
                ops,
                "Connection timed out",
                AgentQMessageKind::timeout);
            return;
        }
        complete_local_pin_processing_to_message(
            ops,
            "Auth timed out",
            AgentQMessageKind::timeout);
        return;
    }

    const AgentQLocalPinAuthPurpose purpose = snapshot.purpose;
    char request_id[kMaxRequestIdSize] = {};
    pending_request_id_for_local_pin_purpose(purpose, request_id, sizeof(request_id));
    if (purpose == AgentQLocalPinAuthPurpose::user_signing && request_id[0] != '\0') {
        if (finish_request_backed_local_pin_input_timeout_if_reached(
                purpose,
                now,
                "user_signing local PIN authorization timed out",
                ops)) {
            return;
        }
        if (local_pin_auth_deadline_expired(now)) {
            wipe_local_pin_auth_scratch(ops, "user_signing local PIN input timed out");
            const AgentQUserSigningConfirmationResult result =
                user_signing_confirmation_record_timeout(now);
            if (result == AgentQUserSigningConfirmationResult::ok ||
                user_signing_flow_terminal_pending()) {
                complete_local_pin_to_user_terminal(ops, request_id);
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

        const AgentQLocalPinAuthLockoutReleaseResult lockout_release =
            local_pin_auth_release_lockout_if_elapsed(now);
        if (lockout_release == AgentQLocalPinAuthLockoutReleaseResult::failed) {
            handle_local_pin_auth_display_failure(
                "user_signing local PIN lockout release failed",
                true,
                ops);
            return;
        }
        if (lockout_release == AgentQLocalPinAuthLockoutReleaseResult::released) {
            if (!resume_request_backed_pin_input_window(purpose, now)) {
                if (finish_request_backed_local_pin_input_timeout_if_reached(
                        purpose,
                        now,
                        "user_signing local PIN lockout release reached timeout",
                        ops)) {
                    return;
                }
                handle_local_pin_auth_display_failure(
                    "user_signing local PIN lockout release refresh failed",
                    true,
                    ops);
                return;
            }
            if (!draw_local_pin_panel(ops, "Try again.")) {
                handle_local_pin_auth_display_failure(
                    "user_signing PIN authorization lockout display allocation failed",
                    false,
                    ops);
            }
            return;
        }

        const bool panel_active =
            ops.local_pin_panel_visible != nullptr && ops.local_pin_panel_visible();
        if (panel_active) {
            return;
        }
        if (draw_local_pin_panel(ops)) {
            return;
        }
        user_signing_confirmation_cancel_for_pin_loss();
        finish_user_signing_error_terminal(
            ops,
            request_id,
            "ui_error",
            "Could not restore signing PIN UI.",
            "Display error");
        return;
    }
    if (finish_request_backed_local_pin_input_timeout_if_reached(
            purpose,
            now,
            "protocol-backed local PIN authorization timed out",
            ops)) {
        return;
    }

    const AgentQLocalPinAuthLockoutReleaseResult lockout_release =
        local_pin_auth_release_lockout_if_elapsed(now);
    if (lockout_release == AgentQLocalPinAuthLockoutReleaseResult::failed) {
        handle_local_pin_auth_display_failure(
            "local PIN lockout release failed",
            true,
            ops);
        return;
    }
    if (lockout_release == AgentQLocalPinAuthLockoutReleaseResult::released) {
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

    const bool panel_active =
        ops.local_pin_panel_visible != nullptr && ops.local_pin_panel_visible();
    const bool expired = local_pin_auth_deadline_expired(now);
    if (panel_active && !expired) {
        return;
    }

    if (!panel_active && !expired) {
        if (!draw_local_pin_panel(ops)) {
            if (purpose == AgentQLocalPinAuthPurpose::policy_update &&
                request_id[0] != '\0') {
                wipe_local_pin_auth_scratch(ops, "policy update PIN UI recovery failed");
                finish_policy_update_terminal(
                    ops,
                    request_id,
                    policy_update_flow_record_ui_error());
                return;
            }
            if (purpose == AgentQLocalPinAuthPurpose::connect &&
                request_id[0] != '\0') {
                if (ops.write_connect_rejected != nullptr) {
                    ops.write_connect_rejected(
                        request_id,
                        "ui_error",
                        "Could not restore local PIN UI.");
                }
                if (ops.clear_connect_approval != nullptr) {
                    ops.clear_connect_approval();
                }
                protocol_pin_approval_clear();
            }
            wipe_local_pin_auth_scratch(ops, "local PIN UI recovery failed");
            show_message(ops, "Display error", AgentQMessageKind::error);
        }
        return;
    }

    wipe_local_pin_auth_scratch(
        ops,
        expired ? "local PIN authorization timed out" : "local PIN authorization panel lost");

    if (request_id[0] != '\0') {
        if (purpose == AgentQLocalPinAuthPurpose::policy_update) {
            const AgentQPolicyUpdateFlowTerminalResult result =
                policy_update_flow_record_timed_out(wall_clock_ms_or_zero(ops));
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
        if (ops.write_connect_rejected != nullptr) {
            ops.write_connect_rejected(
                request_id,
                expired ? "timeout" : "rejected",
                expired ? "Connection PIN timed out." : "Connection PIN UI closed.");
        }
        if (ops.clear_connect_approval != nullptr) {
            ops.clear_connect_approval();
        }
        protocol_pin_approval_clear();
        if (panel_active) {
            complete_local_pin_processing_to_message(
                ops,
                expired ? "Connection timed out" : "Connection canceled",
                expired ? AgentQMessageKind::timeout : AgentQMessageKind::info);
        } else {
            show_message(
                ops,
                expired ? "Connection timed out" : "Connection canceled",
                expired ? AgentQMessageKind::timeout : AgentQMessageKind::info);
        }
        return;
    }

    if (expired) {
        if (panel_active) {
            complete_local_pin_processing_to_message(
                ops,
                "Settings timed out",
                AgentQMessageKind::timeout);
        } else {
            show_message(ops, "Settings timed out", AgentQMessageKind::timeout);
        }
    }
}

}  // namespace agent_q
