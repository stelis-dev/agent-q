#include "policy_update_review_ui_flow.h"

#include "modal_transition.h"
#include "transport/timeout_window.h"

namespace signing {
namespace {

TickType_t now_or_zero(const PolicyUpdateReviewUiFlowOps& ops)
{
    return ops.now != nullptr ? ops.now() : 0;
}

uint64_t wall_clock_ms_or_zero(const PolicyUpdateReviewUiFlowOps& ops)
{
    return ops.wall_clock_ms != nullptr ? ops.wall_clock_ms() : 0;
}

PolicyUpdateFlowSnapshot snapshot_or_inactive(
    const PolicyUpdateReviewUiFlowOps& ops)
{
    if (ops.snapshot == nullptr) {
        return {};
    }
    return ops.snapshot();
}

bool reviewing(const PolicyUpdateFlowSnapshot& snapshot)
{
    return snapshot.active &&
           snapshot.stage == PolicyUpdateFlowStage::reviewing;
}

void log_warn(const PolicyUpdateReviewUiFlowOps& ops, const char* message)
{
    if (ops.log_warn != nullptr) {
        ops.log_warn(message);
    }
}

ModalTransitionOps modal_transition_ops(
    const PolicyUpdateReviewUiFlowOps& ops)
{
    return ModalTransitionOps{
        ops.clear_panel_if_kind,
        nullptr,
        ops.log_warn,
    };
}

void finish_terminal(
    const PolicyUpdateReviewUiFlowOps& ops,
    const char* request_id,
    PolicyUpdateFlowTerminalResult result)
{
    if (ops.finish_terminal != nullptr) {
        ops.finish_terminal(request_id, result);
    }
}

void finish_error_terminal(
    const PolicyUpdateReviewUiFlowOps& ops,
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

PolicyUpdateFlowTerminalResult record_timed_out(
    const PolicyUpdateReviewUiFlowOps& ops)
{
    if (ops.record_timed_out == nullptr) {
        return PolicyUpdateFlowTerminalResult::invalid_state;
    }
    return ops.record_timed_out(wall_clock_ms_or_zero(ops));
}

struct DrawLocalPinContext {
    const PolicyUpdateReviewUiFlowOps* ops = nullptr;
};

struct PolicyUpdateTerminalContext {
    const PolicyUpdateReviewUiFlowOps* ops = nullptr;
    const char* request_id = nullptr;
    PolicyUpdateFlowTerminalResult result =
        PolicyUpdateFlowTerminalResult::invalid_state;
};

bool draw_local_pin_for_transition(void* context)
{
    const auto* draw_context = static_cast<const DrawLocalPinContext*>(context);
    return draw_context != nullptr &&
           draw_context->ops != nullptr &&
           draw_context->ops->draw_local_pin_auth_panel != nullptr &&
           draw_context->ops->draw_local_pin_auth_panel();
}

void finish_policy_update_terminal_for_transition(void* context)
{
    const auto* terminal_context = static_cast<const PolicyUpdateTerminalContext*>(context);
    if (terminal_context == nullptr || terminal_context->ops == nullptr) {
        return;
    }
    finish_terminal(
        *terminal_context->ops,
        terminal_context->request_id,
        terminal_context->result);
}

void complete_review_to_terminal(
    const PolicyUpdateReviewUiFlowOps& ops,
    const char* request_id,
    PolicyUpdateFlowTerminalResult result)
{
    PolicyUpdateTerminalContext context{&ops, request_id, result};
    modal_transition_complete_to_result(
        modal_transition_ops(ops),
        UiPanelKind::policy_update_review,
        finish_policy_update_terminal_for_transition,
        &context);
}

}  // namespace

bool policy_update_review_ui_show(const PolicyUpdateReviewUiFlowOps& ops)
{
    const PolicyUpdateFlowSnapshot current = snapshot_or_inactive(ops);
    if (!reviewing(current)) {
        return false;
    }
    const PolicyUpdateReviewViewModel model{
        current.policy_hash,
        current.blockchain_count,
        current.network_count,
        current.policy_count,
        current.condition_count,
        current.default_action,
        current.highest_action,
        current.scope_summary,
        current.review_summary,
    };
    return ops.draw_review_panel != nullptr &&
           ops.draw_review_panel(model, current.review_window);
}

void policy_update_review_ui_continue(const PolicyUpdateReviewUiFlowOps& ops)
{
    const PolicyUpdateFlowSnapshot current = snapshot_or_inactive(ops);
    if (!reviewing(current)) {
        log_warn(ops, "Stale policy update review continue ignored");
        return;
    }

    if (ops.identification_display_clear != nullptr) {
        ops.identification_display_clear();
    }
    const TickType_t started_at = now_or_zero(ops);
    const TimeoutWindow request_window =
        timeout_window_from_deadline(
            started_at,
            started_at + pdMS_TO_TICKS(ops.review_pin_window_ms));
    const PolicyUpdateReviewPinBeginResult begin_result =
        ops.begin_pin_from_review != nullptr
            ? ops.begin_pin_from_review(
                  current,
                  started_at,
                  request_window,
                  wall_clock_ms_or_zero(ops))
            : PolicyUpdateReviewPinBeginResult{
                  PolicyUpdateReviewPinBeginStatus::pin_unavailable,
                  PolicyUpdateFlowTerminalResult::invalid_state};
    switch (begin_result.status) {
        case PolicyUpdateReviewPinBeginStatus::started:
            break;
        case PolicyUpdateReviewPinBeginStatus::timed_out:
            complete_review_to_terminal(
                ops,
                current.request_id,
                begin_result.terminal_result);
            return;
        case PolicyUpdateReviewPinBeginStatus::unavailable:
            finish_error_terminal(
                ops,
                current.request_id,
                "invalid_state",
                "Policy update is unavailable.",
                "Policy unavailable");
            return;
        case PolicyUpdateReviewPinBeginStatus::pin_unavailable:
            finish_error_terminal(
                ops,
                current.request_id,
                "invalid_state",
                "Policy update PIN is unavailable.",
                "Policy unavailable");
            return;
    }

    DrawLocalPinContext draw_context{&ops};
    if (!modal_transition_complete_to_next_panel(
            modal_transition_ops(ops),
            UiPanelKind::policy_update_review,
            draw_local_pin_for_transition,
            &draw_context)) {
        if (ops.clear_local_pin_auth_scratch != nullptr) {
            ops.clear_local_pin_auth_scratch("policy update PIN display allocation failed");
        }
        if (ops.clear_panel_if_kind != nullptr) {
            ops.clear_panel_if_kind(
                UiPanelKind::local_pin_auth,
                SensitiveUiClearPolicy::preserve);
        }
        const PolicyUpdateFlowTerminalResult result =
            ops.record_ui_error != nullptr
                ? ops.record_ui_error()
                : PolicyUpdateFlowTerminalResult::ui_error;
        finish_terminal(ops, current.request_id, result);
    }
}

void policy_update_review_ui_reject(const PolicyUpdateReviewUiFlowOps& ops)
{
    const PolicyUpdateFlowSnapshot current = snapshot_or_inactive(ops);
    if (!reviewing(current)) {
        log_warn(ops, "Stale policy update review reject ignored");
        return;
    }
    const TickType_t now = now_or_zero(ops);
    if (ops.review_deadline_reached != nullptr &&
        ops.review_deadline_reached(now)) {
        complete_review_to_terminal(ops, current.request_id, record_timed_out(ops));
        return;
    }
    const PolicyUpdateFlowTerminalResult result =
        ops.record_rejected != nullptr
            ? ops.record_rejected(wall_clock_ms_or_zero(ops))
            : PolicyUpdateFlowTerminalResult::rejected;
    complete_review_to_terminal(ops, current.request_id, result);
}

void policy_update_review_ui_clear_if_needed(const PolicyUpdateReviewUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const PolicyUpdateFlowSnapshot current = snapshot_or_inactive(ops);
    if (!reviewing(current)) {
        return;
    }

    const bool panel_active =
        ops.review_panel_active != nullptr && ops.review_panel_active();
    if (ops.review_deadline_reached == nullptr ||
        !ops.review_deadline_reached(now)) {
        if (panel_active) {
            return;
        }
        if (!policy_update_review_ui_show(ops)) {
            const PolicyUpdateFlowTerminalResult result =
                ops.record_ui_error != nullptr
                    ? ops.record_ui_error()
                    : PolicyUpdateFlowTerminalResult::ui_error;
            finish_terminal(ops, current.request_id, result);
        }
        return;
    }

    complete_review_to_terminal(ops, current.request_id, record_timed_out(ops));
}

}  // namespace signing
