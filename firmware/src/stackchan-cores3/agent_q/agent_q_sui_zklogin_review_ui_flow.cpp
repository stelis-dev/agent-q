#include "agent_q_sui_zklogin_review_ui_flow.h"

#include "agent_q_modal_transition.h"

namespace agent_q {
namespace {

constexpr const char* kSuiZkLoginReviewSummary =
    "Sui account will switch to zkLogin. Native direct signing stays off while zkLogin is active.";

TickType_t now_or_zero(const AgentQSuiZkLoginReviewUiFlowOps& ops)
{
    return ops.now != nullptr ? ops.now() : 0;
}

AgentQSuiZkLoginProposalSnapshot snapshot_or_inactive(
    const AgentQSuiZkLoginReviewUiFlowOps& ops)
{
    if (ops.snapshot == nullptr) {
        return {};
    }
    return ops.snapshot();
}

bool reviewing(const AgentQSuiZkLoginProposalSnapshot& snapshot)
{
    return snapshot.active &&
           snapshot.stage == AgentQSuiZkLoginProposalStage::reviewing;
}

void log_warn(const AgentQSuiZkLoginReviewUiFlowOps& ops, const char* message)
{
    if (ops.log_warn != nullptr) {
        ops.log_warn(message);
    }
}

AgentQModalTransitionOps modal_transition_ops(
    const AgentQSuiZkLoginReviewUiFlowOps& ops)
{
    return AgentQModalTransitionOps{
        ops.clear_panel_if_kind,
        nullptr,
        ops.log_warn,
    };
}

void finish_terminal(
    const AgentQSuiZkLoginReviewUiFlowOps& ops,
    const char* request_id,
    AgentQSuiZkLoginProposalTerminalResult result)
{
    if (ops.finish_terminal != nullptr) {
        ops.finish_terminal(request_id, result);
    }
}

void finish_error_terminal(
    const AgentQSuiZkLoginReviewUiFlowOps& ops,
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

AgentQSuiZkLoginProposalTerminalResult record_timed_out(
    const AgentQSuiZkLoginReviewUiFlowOps& ops)
{
    if (ops.record_timed_out == nullptr) {
        return AgentQSuiZkLoginProposalTerminalResult::invalid_state;
    }
    return ops.record_timed_out();
}

struct DrawLocalPinContext {
    const AgentQSuiZkLoginReviewUiFlowOps* ops = nullptr;
};

struct SuiZkLoginTerminalContext {
    const AgentQSuiZkLoginReviewUiFlowOps* ops = nullptr;
    const char* request_id = nullptr;
    AgentQSuiZkLoginProposalTerminalResult result =
        AgentQSuiZkLoginProposalTerminalResult::invalid_state;
};

bool draw_local_pin_for_transition(void* context)
{
    const auto* draw_context = static_cast<const DrawLocalPinContext*>(context);
    return draw_context != nullptr &&
           draw_context->ops != nullptr &&
           draw_context->ops->draw_local_pin_auth_panel != nullptr &&
           draw_context->ops->draw_local_pin_auth_panel("Approve Sui zkLogin");
}

void finish_sui_zklogin_terminal_for_transition(void* context)
{
    const auto* terminal_context = static_cast<const SuiZkLoginTerminalContext*>(context);
    if (terminal_context == nullptr || terminal_context->ops == nullptr) {
        return;
    }
    finish_terminal(
        *terminal_context->ops,
        terminal_context->request_id,
        terminal_context->result);
}

void complete_review_to_terminal(
    const AgentQSuiZkLoginReviewUiFlowOps& ops,
    const char* request_id,
    AgentQSuiZkLoginProposalTerminalResult result)
{
    SuiZkLoginTerminalContext context{&ops, request_id, result};
    modal_transition_complete_to_result(
        modal_transition_ops(ops),
        AgentQUiPanelKind::sui_zklogin_review,
        finish_sui_zklogin_terminal_for_transition,
        &context);
}

}  // namespace

bool sui_zklogin_review_ui_show(const AgentQSuiZkLoginReviewUiFlowOps& ops)
{
    const AgentQSuiZkLoginProposalSnapshot current = snapshot_or_inactive(ops);
    if (!reviewing(current)) {
        return false;
    }
    const AgentQSuiZkLoginReviewViewModel model{
        current.network,
        current.address,
        current.issuer,
        current.max_epoch,
        current.proof_hash,
        kSuiZkLoginReviewSummary,
    };
    return ops.draw_review_panel != nullptr &&
           ops.draw_review_panel(model, current.request_window);
}

void sui_zklogin_review_ui_continue(const AgentQSuiZkLoginReviewUiFlowOps& ops)
{
    const AgentQSuiZkLoginProposalSnapshot current = snapshot_or_inactive(ops);
    if (!reviewing(current)) {
        log_warn(ops, "Stale Sui zkLogin review continue ignored");
        return;
    }

    if (ops.identification_display_clear != nullptr) {
        ops.identification_display_clear();
    }
    const TickType_t started_at = now_or_zero(ops);
    const AgentQSuiZkLoginReviewPinBeginResult begin_result =
        ops.begin_pin_from_review != nullptr
            ? ops.begin_pin_from_review(current, started_at)
            : AgentQSuiZkLoginReviewPinBeginResult{
                  AgentQSuiZkLoginReviewPinBeginStatus::pin_unavailable,
                  AgentQSuiZkLoginProposalTerminalResult::invalid_state};
    switch (begin_result.status) {
        case AgentQSuiZkLoginReviewPinBeginStatus::started:
            break;
        case AgentQSuiZkLoginReviewPinBeginStatus::timed_out:
            complete_review_to_terminal(
                ops,
                current.request_id,
                begin_result.terminal_result);
            return;
        case AgentQSuiZkLoginReviewPinBeginStatus::unavailable:
            finish_error_terminal(
                ops,
                current.request_id,
                "invalid_state",
                "Sui zkLogin proposal is unavailable.",
                "zkLogin unavailable");
            return;
        case AgentQSuiZkLoginReviewPinBeginStatus::pin_unavailable:
            finish_error_terminal(
                ops,
                current.request_id,
                "invalid_state",
                "Sui zkLogin proposal PIN is unavailable.",
                "zkLogin unavailable");
            return;
    }

    DrawLocalPinContext draw_context{&ops};
    if (!modal_transition_complete_to_next_panel(
            modal_transition_ops(ops),
            AgentQUiPanelKind::sui_zklogin_review,
            draw_local_pin_for_transition,
            &draw_context)) {
        if (ops.wipe_local_pin_auth_scratch != nullptr) {
            ops.wipe_local_pin_auth_scratch(
                "Sui zkLogin proposal PIN display allocation failed");
        }
        if (ops.clear_panel_if_kind != nullptr) {
            ops.clear_panel_if_kind(
                AgentQUiPanelKind::local_pin_auth,
                SensitiveUiClearPolicy::preserve);
        }
        const AgentQSuiZkLoginProposalTerminalResult result =
            ops.record_ui_error != nullptr
                ? ops.record_ui_error()
                : AgentQSuiZkLoginProposalTerminalResult::ui_error;
        finish_terminal(ops, current.request_id, result);
    }
}

void sui_zklogin_review_ui_reject(const AgentQSuiZkLoginReviewUiFlowOps& ops)
{
    const AgentQSuiZkLoginProposalSnapshot current = snapshot_or_inactive(ops);
    if (!reviewing(current)) {
        log_warn(ops, "Stale Sui zkLogin review reject ignored");
        return;
    }
    const TickType_t now = now_or_zero(ops);
    if (ops.review_deadline_reached != nullptr &&
        ops.review_deadline_reached(now)) {
        complete_review_to_terminal(ops, current.request_id, record_timed_out(ops));
        return;
    }
    const AgentQSuiZkLoginProposalTerminalResult result =
        ops.record_rejected != nullptr
            ? ops.record_rejected()
            : AgentQSuiZkLoginProposalTerminalResult::rejected;
    complete_review_to_terminal(ops, current.request_id, result);
}

void sui_zklogin_review_ui_clear_if_needed(const AgentQSuiZkLoginReviewUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const AgentQSuiZkLoginProposalSnapshot current = snapshot_or_inactive(ops);
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
        if (!sui_zklogin_review_ui_show(ops)) {
            const AgentQSuiZkLoginProposalTerminalResult result =
                ops.record_ui_error != nullptr
                    ? ops.record_ui_error()
                    : AgentQSuiZkLoginProposalTerminalResult::ui_error;
            finish_terminal(ops, current.request_id, result);
        }
        return;
    }

    complete_review_to_terminal(ops, current.request_id, record_timed_out(ops));
}

}  // namespace agent_q
