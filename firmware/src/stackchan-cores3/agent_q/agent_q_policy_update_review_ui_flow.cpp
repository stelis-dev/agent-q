#include "agent_q_policy_update_review_ui_flow.h"

#include "agent_q_modal_transition.h"
#include "agent_q_timeout_window.h"

namespace agent_q {
namespace {

TickType_t now_or_zero(const AgentQPolicyUpdateReviewUiFlowOps& ops)
{
    return ops.now != nullptr ? ops.now() : 0;
}

uint64_t wall_clock_ms_or_zero(const AgentQPolicyUpdateReviewUiFlowOps& ops)
{
    return ops.wall_clock_ms != nullptr ? ops.wall_clock_ms() : 0;
}

AgentQPolicyUpdateFlowSnapshot snapshot_or_inactive(
    const AgentQPolicyUpdateReviewUiFlowOps& ops)
{
    if (ops.snapshot == nullptr) {
        return {};
    }
    return ops.snapshot();
}

bool reviewing(const AgentQPolicyUpdateFlowSnapshot& snapshot)
{
    return snapshot.active &&
           snapshot.stage == AgentQPolicyUpdateFlowStage::reviewing;
}

void log_warn(const AgentQPolicyUpdateReviewUiFlowOps& ops, const char* message)
{
    if (ops.log_warn != nullptr) {
        ops.log_warn(message);
    }
}

AgentQModalTransitionOps modal_transition_ops(
    const AgentQPolicyUpdateReviewUiFlowOps& ops)
{
    return AgentQModalTransitionOps{
        ops.clear_panel_if_kind,
        nullptr,
        ops.log_warn,
    };
}

void finish_terminal(
    const AgentQPolicyUpdateReviewUiFlowOps& ops,
    const char* request_id,
    AgentQPolicyUpdateFlowTerminalResult result)
{
    if (ops.finish_terminal != nullptr) {
        ops.finish_terminal(request_id, result);
    }
}

void finish_error_terminal(
    const AgentQPolicyUpdateReviewUiFlowOps& ops,
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

AgentQPolicyUpdateFlowTerminalResult record_timed_out(
    const AgentQPolicyUpdateReviewUiFlowOps& ops)
{
    if (ops.record_timed_out == nullptr) {
        return AgentQPolicyUpdateFlowTerminalResult::invalid_state;
    }
    return ops.record_timed_out(wall_clock_ms_or_zero(ops));
}

struct DrawLocalPinContext {
    const AgentQPolicyUpdateReviewUiFlowOps* ops = nullptr;
};

struct PolicyUpdateTerminalContext {
    const AgentQPolicyUpdateReviewUiFlowOps* ops = nullptr;
    const char* request_id = nullptr;
    AgentQPolicyUpdateFlowTerminalResult result =
        AgentQPolicyUpdateFlowTerminalResult::invalid_state;
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
    const AgentQPolicyUpdateReviewUiFlowOps& ops,
    const char* request_id,
    AgentQPolicyUpdateFlowTerminalResult result)
{
    PolicyUpdateTerminalContext context{&ops, request_id, result};
    modal_transition_complete_to_result(
        modal_transition_ops(ops),
        AgentQUiPanelKind::policy_update_review,
        finish_policy_update_terminal_for_transition,
        &context);
}

}  // namespace

bool policy_update_review_ui_show(const AgentQPolicyUpdateReviewUiFlowOps& ops)
{
    const AgentQPolicyUpdateFlowSnapshot current = snapshot_or_inactive(ops);
    if (!reviewing(current)) {
        return false;
    }
    const AgentQPolicyUpdateReviewViewModel model{
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

void policy_update_review_ui_continue(const AgentQPolicyUpdateReviewUiFlowOps& ops)
{
    const AgentQPolicyUpdateFlowSnapshot current = snapshot_or_inactive(ops);
    if (!reviewing(current)) {
        log_warn(ops, "Stale policy update review continue ignored");
        return;
    }

    if (ops.identification_display_clear != nullptr) {
        ops.identification_display_clear();
    }
    const TickType_t started_at = now_or_zero(ops);
    const AgentQTimeoutWindow request_window =
        timeout_window_from_deadline(
            started_at,
            started_at + pdMS_TO_TICKS(ops.review_pin_window_ms));
    const AgentQPolicyUpdateReviewPinBeginResult begin_result =
        ops.begin_pin_from_review != nullptr
            ? ops.begin_pin_from_review(
                  current,
                  started_at,
                  request_window,
                  wall_clock_ms_or_zero(ops))
            : AgentQPolicyUpdateReviewPinBeginResult{
                  AgentQPolicyUpdateReviewPinBeginStatus::pin_unavailable,
                  AgentQPolicyUpdateFlowTerminalResult::invalid_state};
    switch (begin_result.status) {
        case AgentQPolicyUpdateReviewPinBeginStatus::started:
            break;
        case AgentQPolicyUpdateReviewPinBeginStatus::timed_out:
            complete_review_to_terminal(
                ops,
                current.request_id,
                begin_result.terminal_result);
            return;
        case AgentQPolicyUpdateReviewPinBeginStatus::unavailable:
            finish_error_terminal(
                ops,
                current.request_id,
                "invalid_state",
                "Policy update is unavailable.",
                "Policy unavailable");
            return;
        case AgentQPolicyUpdateReviewPinBeginStatus::pin_unavailable:
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
            AgentQUiPanelKind::policy_update_review,
            draw_local_pin_for_transition,
            &draw_context)) {
        if (ops.wipe_local_pin_auth_scratch != nullptr) {
            ops.wipe_local_pin_auth_scratch("policy update PIN display allocation failed");
        }
        if (ops.clear_panel_if_kind != nullptr) {
            ops.clear_panel_if_kind(
                AgentQUiPanelKind::local_pin_auth,
                SensitiveUiClearPolicy::preserve);
        }
        const AgentQPolicyUpdateFlowTerminalResult result =
            ops.record_ui_error != nullptr
                ? ops.record_ui_error()
                : AgentQPolicyUpdateFlowTerminalResult::ui_error;
        finish_terminal(ops, current.request_id, result);
    }
}

void policy_update_review_ui_reject(const AgentQPolicyUpdateReviewUiFlowOps& ops)
{
    const AgentQPolicyUpdateFlowSnapshot current = snapshot_or_inactive(ops);
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
    const AgentQPolicyUpdateFlowTerminalResult result =
        ops.record_rejected != nullptr
            ? ops.record_rejected(wall_clock_ms_or_zero(ops))
            : AgentQPolicyUpdateFlowTerminalResult::rejected;
    complete_review_to_terminal(ops, current.request_id, result);
}

void policy_update_review_ui_clear_if_needed(const AgentQPolicyUpdateReviewUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const AgentQPolicyUpdateFlowSnapshot current = snapshot_or_inactive(ops);
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
            const AgentQPolicyUpdateFlowTerminalResult result =
                ops.record_ui_error != nullptr
                    ? ops.record_ui_error()
                    : AgentQPolicyUpdateFlowTerminalResult::ui_error;
            finish_terminal(ops, current.request_id, result);
        }
        return;
    }

    complete_review_to_terminal(ops, current.request_id, record_timed_out(ops));
}

}  // namespace agent_q
