#include "agent_q_user_signing_review_ui_flow.h"

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

bool clear_review_panel(const AgentQUserSigningReviewUiFlowOps& ops)
{
    return ops.clear_panel_if_kind != nullptr &&
           ops.clear_panel_if_kind(
               AgentQUiPanelKind::user_signing_review,
               SensitiveUiClearPolicy::preserve);
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

}  // namespace

bool user_signing_review_ui_show(const AgentQUserSigningReviewUiFlowOps& ops)
{
    const AgentQUserSigningFlowSnapshot* current = snapshot_or_null(ops);
    AgentQUserSigningReviewViewModel model = {};
    if (current == nullptr ||
        ops.build_review_model == nullptr ||
        ops.build_review_model(*current, &model) !=
            AgentQUserSigningReviewBuildResult::ok) {
        memset(&g_review_snapshot_scratch, 0, sizeof(g_review_snapshot_scratch));
        return false;
    }
    const bool drawn = ops.draw_review_panel != nullptr &&
                       ops.draw_review_panel(model, current->request_window);
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
        clear_review_panel(ops);
        if (result == AgentQUserSigningTransitionResult::ok) {
            if (ops.execute_critical_section_and_finish != nullptr) {
                ops.execute_critical_section_and_finish(current.request_id);
            }
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

    clear_review_panel(ops);
    if (ops.draw_local_pin_auth_panel == nullptr ||
        !ops.draw_local_pin_auth_panel()) {
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

    clear_review_panel(ops);
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
    finish_terminal(ops, current.request_id);
}

void user_signing_review_ui_clear_if_needed(const AgentQUserSigningReviewUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const AgentQUserSigningFlowCoreSnapshot current = core_snapshot_or_inactive(ops);
    if (!reviewing(current)) {
        return;
    }

    const bool panel_active =
        ops.review_panel_active != nullptr && ops.review_panel_active();
    const AgentQUserSigningTransitionResult timeout_result =
        ops.record_timeout != nullptr
            ? ops.record_timeout(now)
            : AgentQUserSigningTransitionResult::invalid_argument;
    if (timeout_result == AgentQUserSigningTransitionResult::deadline_not_reached) {
        if (panel_active) {
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
        clear_review_panel(ops);
        finish_terminal(ops, current.request_id);
        return;
    }

    log_warn(ops, "Signature review timeout check returned unexpected result");
}

}  // namespace agent_q
