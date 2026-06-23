#include "agent_q_user_signing_review_ui_flow.h"

#include "agent_q_modal_transition.h"
#include "agent_q_timeout_window.h"

#include <string.h>

namespace agent_q {
namespace {

AgentQUserSigningFlowSnapshot g_review_snapshot_scratch;

TickType_t now_or_zero(const AgentQUserSigningReviewUiFlowOps& ops)
{
    return ops.now != nullptr ? ops.now() : 0;
}

const AgentQUserSigningFlowSnapshot* snapshot_or_null(
    const AgentQUserSigningReviewUiFlowOps& ops)
{
    if (ops.snapshot == nullptr) {
        return nullptr;
    }
    memset(&g_review_snapshot_scratch, 0, sizeof(g_review_snapshot_scratch));
    if (!ops.snapshot(&g_review_snapshot_scratch)) {
        memset(&g_review_snapshot_scratch, 0, sizeof(g_review_snapshot_scratch));
        return nullptr;
    }
    return &g_review_snapshot_scratch;
}

AgentQUserSigningFlowCoreSnapshot core_snapshot_or_inactive(
    const AgentQUserSigningReviewUiFlowOps& ops)
{
    if (ops.core_snapshot == nullptr) {
        return {};
    }
    return ops.core_snapshot();
}

AgentQUserSigningReviewTimerState review_timer_state_or_unavailable(
    const AgentQUserSigningReviewUiFlowOps& ops,
    TickType_t now)
{
    if (ops.review_timer_state == nullptr) {
        return {};
    }
    return ops.review_timer_state(now);
}

bool reviewing(const AgentQUserSigningFlowCoreSnapshot& snapshot)
{
    return snapshot.active &&
           snapshot.stage == AgentQUserSigningStage::reviewing;
}

void log_warn(const AgentQUserSigningReviewUiFlowOps& ops, const char* message)
{
    if (ops.log_warn != nullptr) {
        ops.log_warn(message);
    }
}

AgentQModalTransitionOps modal_transition_ops(const AgentQUserSigningReviewUiFlowOps& ops)
{
    return AgentQModalTransitionOps{
        ops.clear_panel_if_kind,
        nullptr,
        ops.log_warn,
    };
}

AgentQTimeoutWindow window_from_now_ms(
    const AgentQUserSigningReviewUiFlowOps& ops,
    uint32_t duration_ms)
{
    const TickType_t now = now_or_zero(ops);
    return timeout_window_from_deadline(now, now + pdMS_TO_TICKS(duration_ms));
}

void finish_terminal(
    const AgentQUserSigningReviewUiFlowOps& ops,
    const char* request_id)
{
    if (ops.finish_terminal != nullptr) {
        ops.finish_terminal(request_id);
    }
}

void finish_error_terminal(
    const AgentQUserSigningReviewUiFlowOps& ops,
    const char* request_id,
    const char* error_code,
    const char* error_message,
    const char* display_message)
{
    if (ops.finish_error_terminal != nullptr) {
        ops.finish_error_terminal(
            request_id,
            error_code,
            error_message,
            display_message);
    }
}

bool terminal_pending(const AgentQUserSigningReviewUiFlowOps& ops)
{
    return ops.terminal_pending != nullptr && ops.terminal_pending();
}

bool review_panel_active(const AgentQUserSigningReviewUiFlowOps& ops)
{
    return ops.review_panel_active != nullptr && ops.review_panel_active();
}

struct UserSigningWorkContext {
    const AgentQUserSigningReviewUiFlowOps* ops = nullptr;
    const char* request_id = nullptr;
};

void execute_user_signing_for_transition(void* context)
{
    const auto* work_context = static_cast<const UserSigningWorkContext*>(context);
    if (work_context == nullptr ||
        work_context->ops == nullptr ||
        work_context->ops->execute_critical_section_and_finish == nullptr) {
        return;
    }
    work_context->ops->execute_critical_section_and_finish(work_context->request_id);
}

void run_user_signing_then_clear_review_panel(
    const AgentQUserSigningReviewUiFlowOps& ops,
    const char* request_id)
{
    UserSigningWorkContext context{&ops, request_id};
    modal_transition_run_work_then_clear_panel(
        modal_transition_ops(ops),
        AgentQUiPanelKind::user_signing_review,
        execute_user_signing_for_transition,
        &context);
}

struct DrawLocalPinContext {
    const AgentQUserSigningReviewUiFlowOps* ops = nullptr;
};

struct UserSigningTerminalContext {
    const AgentQUserSigningReviewUiFlowOps* ops = nullptr;
    const char* request_id = nullptr;
};

bool draw_local_pin_for_transition(void* context)
{
    const auto* draw_context = static_cast<const DrawLocalPinContext*>(context);
    return draw_context != nullptr &&
           draw_context->ops != nullptr &&
           draw_context->ops->draw_local_pin_auth_panel != nullptr &&
           draw_context->ops->draw_local_pin_auth_panel();
}

void finish_user_signing_terminal_for_transition(void* context)
{
    const auto* terminal_context = static_cast<const UserSigningTerminalContext*>(context);
    if (terminal_context == nullptr || terminal_context->ops == nullptr) {
        return;
    }
    finish_terminal(*terminal_context->ops, terminal_context->request_id);
}

void complete_review_to_terminal(
    const AgentQUserSigningReviewUiFlowOps& ops,
    const char* request_id)
{
    UserSigningTerminalContext context{&ops, request_id};
    modal_transition_complete_to_result(
        modal_transition_ops(ops),
        AgentQUiPanelKind::user_signing_review,
        finish_user_signing_terminal_for_transition,
        &context);
}

bool stale_scroll_result(AgentQUserSigningTransitionResult result)
{
    return result == AgentQUserSigningTransitionResult::inactive ||
           result == AgentQUserSigningTransitionResult::wrong_stage;
}

void handle_scroll_result(
    const AgentQUserSigningReviewUiFlowOps& ops,
    const char* request_id,
    AgentQUserSigningTransitionResult result,
    const char* stale_message)
{
    if (result == AgentQUserSigningTransitionResult::ok) {
        const TickType_t now = now_or_zero(ops);
        const AgentQUserSigningReviewTimerState timer =
            review_timer_state_or_unavailable(ops, now);
        if (ops.draw_review_timer != nullptr && !ops.draw_review_timer(timer)) {
            finish_error_terminal(
                ops,
                request_id,
                "ui_error",
                "Could not update signing review timer UI.",
                "Display error");
        }
        return;
    }
    if (stale_scroll_result(result)) {
        log_warn(ops, stale_message);
        return;
    }
    if (result == AgentQUserSigningTransitionResult::deadline_expired ||
        terminal_pending(ops)) {
        complete_review_to_terminal(ops, request_id);
        return;
    }
    finish_error_terminal(
        ops,
        request_id,
        "invalid_state",
        "Signing request is unavailable.",
        "Signing unavailable");
}

}  // namespace

bool user_signing_review_ui_show(const AgentQUserSigningReviewUiFlowOps& ops)
{
    const AgentQUserSigningFlowSnapshot* current = snapshot_or_null(ops);
    const TickType_t now = now_or_zero(ops);
    AgentQUserSigningReviewViewModel model = {};
    if (current == nullptr ||
        ops.build_review_model == nullptr ||
        ops.build_review_model(*current, &model) !=
            AgentQUserSigningReviewBuildResult::ok) {
        memset(&g_review_snapshot_scratch, 0, sizeof(g_review_snapshot_scratch));
        return false;
    }
    const AgentQUserSigningReviewTimerState timer =
        review_timer_state_or_unavailable(ops, now);
    const bool drawn = ops.draw_review_panel != nullptr &&
                       ops.draw_review_panel(model, timer);
    memset(&g_review_snapshot_scratch, 0, sizeof(g_review_snapshot_scratch));
    return drawn;
}

void user_signing_review_ui_accept(const AgentQUserSigningReviewUiFlowOps& ops)
{
    const AgentQUserSigningFlowCoreSnapshot current = core_snapshot_or_inactive(ops);
    if (!reviewing(current)) {
        log_warn(ops, "Stale user_signing review accept ignored");
        return;
    }

    const TickType_t now = now_or_zero(ops);
    const bool requires_pin =
        ops.human_approval_requires_pin != nullptr &&
        ops.human_approval_requires_pin();
    if (!requires_pin) {
        const AgentQUserSigningTransitionResult result =
            ops.record_physical_confirmed_and_write_confirmation_history != nullptr
                ? ops.record_physical_confirmed_and_write_confirmation_history(
                    now,
                    ops.write_confirmation_history,
                    nullptr)
                : AgentQUserSigningTransitionResult::invalid_argument;
        if (result == AgentQUserSigningTransitionResult::ok) {
            run_user_signing_then_clear_review_panel(ops, current.request_id);
            return;
        }
        if (terminal_pending(ops)) {
            finish_terminal(ops, current.request_id);
            return;
        }
        finish_error_terminal(
            ops,
            current.request_id,
            result == AgentQUserSigningTransitionResult::history_error
                ? "history_error"
                : "invalid_state",
            "Signing request is unavailable.",
            "Signing unavailable");
        return;
    }

    const AgentQTimeoutWindow pin_input_window =
        window_from_now_ms(ops, ops.pin_input_window_ms);
    const AgentQUserSigningConfirmationResult result =
        ops.accept_review_and_begin_pin != nullptr
            ? ops.accept_review_and_begin_pin(now, pin_input_window)
            : AgentQUserSigningConfirmationResult::invalid_argument;
    if (result != AgentQUserSigningConfirmationResult::ok) {
        if (terminal_pending(ops)) {
            finish_terminal(ops, current.request_id);
            return;
        }
        finish_error_terminal(
            ops,
            current.request_id,
            result == AgentQUserSigningConfirmationResult::local_pin_busy
                ? "busy"
                : "invalid_state",
            "Signing request is unavailable.",
            "Signing unavailable");
        return;
    }

    DrawLocalPinContext draw_context{&ops};
    if (!modal_transition_complete_to_next_panel(
            modal_transition_ops(ops),
            AgentQUiPanelKind::user_signing_review,
            draw_local_pin_for_transition,
            &draw_context)) {
        if (ops.cancel_for_pin_loss != nullptr) {
            ops.cancel_for_pin_loss();
        }
        if (ops.clear_panel_if_kind != nullptr) {
            ops.clear_panel_if_kind(
                AgentQUiPanelKind::local_pin_auth,
                SensitiveUiClearPolicy::preserve);
        }
        finish_error_terminal(
            ops,
            current.request_id,
            "ui_error",
            "Could not show signing PIN UI.",
            "Display error");
    }
}

void user_signing_review_ui_reject(const AgentQUserSigningReviewUiFlowOps& ops)
{
    const AgentQUserSigningFlowCoreSnapshot current = core_snapshot_or_inactive(ops);
    if (!reviewing(current)) {
        log_warn(ops, "Stale user_signing review reject ignored");
        return;
    }

    const AgentQUserSigningConfirmationResult result =
        ops.record_device_rejected != nullptr
            ? ops.record_device_rejected()
            : AgentQUserSigningConfirmationResult::invalid_argument;
    if (result != AgentQUserSigningConfirmationResult::ok) {
        finish_error_terminal(
            ops,
            current.request_id,
            "invalid_state",
            "Signing request is unavailable.",
            "Signing unavailable");
        return;
    }
    complete_review_to_terminal(ops, current.request_id);
}

void user_signing_review_ui_scroll_started(const AgentQUserSigningReviewUiFlowOps& ops)
{
    const AgentQUserSigningFlowCoreSnapshot current = core_snapshot_or_inactive(ops);
    if (!reviewing(current) || !review_panel_active(ops)) {
        log_warn(ops, "Stale user_signing review scroll start ignored");
        return;
    }

    const TickType_t now = now_or_zero(ops);
    const AgentQUserSigningTransitionResult result =
        ops.pause_review_deadline != nullptr
            ? ops.pause_review_deadline(now)
            : AgentQUserSigningTransitionResult::invalid_argument;
    handle_scroll_result(
        ops,
        current.request_id,
        result,
        "Stale user_signing review scroll start ignored");
}

void user_signing_review_ui_scroll_finished(const AgentQUserSigningReviewUiFlowOps& ops)
{
    const AgentQUserSigningFlowCoreSnapshot current = core_snapshot_or_inactive(ops);
    if (!reviewing(current) || !review_panel_active(ops)) {
        log_warn(ops, "Stale user_signing review scroll finish ignored");
        return;
    }

    const TickType_t now = now_or_zero(ops);
    const AgentQUserSigningTransitionResult result =
        ops.resume_review_deadline != nullptr
            ? ops.resume_review_deadline(now)
            : AgentQUserSigningTransitionResult::invalid_argument;
    handle_scroll_result(
        ops,
        current.request_id,
        result,
        "Stale user_signing review scroll finish ignored");
}

void user_signing_review_ui_clear_if_needed(const AgentQUserSigningReviewUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const AgentQUserSigningFlowCoreSnapshot current = core_snapshot_or_inactive(ops);
    if (!reviewing(current)) {
        return;
    }

    const bool panel_active = review_panel_active(ops);
    const AgentQUserSigningReviewTimerState timer_before_timeout =
        review_timer_state_or_unavailable(ops, now);
    const AgentQUserSigningTransitionResult timeout_result =
        ops.record_timeout != nullptr
            ? ops.record_timeout(now)
            : AgentQUserSigningTransitionResult::invalid_argument;
    if (timeout_result == AgentQUserSigningTransitionResult::deadline_not_reached) {
        if (panel_active) {
            const AgentQUserSigningReviewTimerState timer_after_timeout =
                review_timer_state_or_unavailable(ops, now);
            if (timer_before_timeout.paused &&
                !timer_after_timeout.paused &&
                ops.draw_review_timer != nullptr &&
                !ops.draw_review_timer(timer_after_timeout)) {
                finish_error_terminal(
                    ops,
                    current.request_id,
                    "ui_error",
                    "Could not update signing review timer UI.",
                    "Display error");
            }
            return;
        }
        if (!user_signing_review_ui_show(ops)) {
            if (ops.clear_flow != nullptr) {
                ops.clear_flow();
            }
            if (ops.write_error != nullptr) {
                ops.write_error(
                    current.request_id,
                    "ui_error",
                    "Could not restore signing review UI.");
            }
            if (ops.show_display_error != nullptr) {
                ops.show_display_error();
            }
        }
        return;
    }
    if (timeout_result == AgentQUserSigningTransitionResult::ok ||
        terminal_pending(ops)) {
        complete_review_to_terminal(ops, current.request_id);
        return;
    }

    log_warn(ops, "Signature review timeout check returned unexpected result");
}

}  // namespace agent_q
