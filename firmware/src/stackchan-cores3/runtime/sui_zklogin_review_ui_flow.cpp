#include "sui_zklogin_review_ui_flow.h"

#include "modal_transition.h"

namespace signing {
namespace {

constexpr const char* kSuiZkLoginReviewSummary =
    "Sui account will switch to zkLogin. Native direct signing stays off while zkLogin is active.";

TickType_t now_or_zero(const SuiZkLoginReviewUiFlowOps& ops)
{
    return ops.now != nullptr ? ops.now() : 0;
}

SuiZkLoginProposalSnapshot snapshot_or_inactive(
    const SuiZkLoginReviewUiFlowOps& ops)
{
    if (ops.snapshot == nullptr) {
        return {};
    }
    return ops.snapshot();
}

bool reviewing(const SuiZkLoginProposalSnapshot& snapshot)
{
    return snapshot.active &&
           snapshot.stage == SuiZkLoginProposalStage::reviewing;
}

void log_warn(const SuiZkLoginReviewUiFlowOps& ops, const char* message)
{
    if (ops.log_warn != nullptr) {
        ops.log_warn(message);
    }
}

ModalTransitionOps modal_transition_ops(
    const SuiZkLoginReviewUiFlowOps& ops)
{
    return ModalTransitionOps{
        ops.clear_panel_if_kind,
        nullptr,
        ops.log_warn,
    };
}

void finish_terminal(
    const SuiZkLoginReviewUiFlowOps& ops,
    const char* request_id,
    SuiZkLoginProposalTerminalResult result)
{
    if (ops.finish_terminal != nullptr) {
        ops.finish_terminal(request_id, result);
    }
}

void finish_error_terminal(
    const SuiZkLoginReviewUiFlowOps& ops,
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

SuiZkLoginProposalTerminalResult record_timed_out(
    const SuiZkLoginReviewUiFlowOps& ops)
{
    if (ops.record_timed_out == nullptr) {
        return SuiZkLoginProposalTerminalResult::invalid_state;
    }
    return ops.record_timed_out();
}

struct DrawLocalPinContext {
    const SuiZkLoginReviewUiFlowOps* ops = nullptr;
};

struct SuiZkLoginTerminalContext {
    const SuiZkLoginReviewUiFlowOps* ops = nullptr;
    const char* request_id = nullptr;
    SuiZkLoginProposalTerminalResult result =
        SuiZkLoginProposalTerminalResult::invalid_state;
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
    const SuiZkLoginReviewUiFlowOps& ops,
    const char* request_id,
    SuiZkLoginProposalTerminalResult result)
{
    SuiZkLoginTerminalContext context{&ops, request_id, result};
    modal_transition_complete_to_result(
        modal_transition_ops(ops),
        UiPanelKind::sui_zklogin_review,
        finish_sui_zklogin_terminal_for_transition,
        &context);
}

}  // namespace

bool sui_zklogin_review_ui_show(const SuiZkLoginReviewUiFlowOps& ops)
{
    const SuiZkLoginProposalSnapshot current = snapshot_or_inactive(ops);
    if (!reviewing(current)) {
        return false;
    }
    const SuiZkLoginReviewViewModel model{
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

void sui_zklogin_review_ui_continue(const SuiZkLoginReviewUiFlowOps& ops)
{
    const SuiZkLoginProposalSnapshot current = snapshot_or_inactive(ops);
    if (!reviewing(current)) {
        log_warn(ops, "Stale Sui zkLogin review continue ignored");
        return;
    }

    if (ops.identification_display_clear != nullptr) {
        ops.identification_display_clear();
    }
    const TickType_t started_at = now_or_zero(ops);
    const SuiZkLoginReviewPinBeginResult begin_result =
        ops.begin_pin_from_review != nullptr
            ? ops.begin_pin_from_review(current, started_at)
            : SuiZkLoginReviewPinBeginResult{
                  SuiZkLoginReviewPinBeginStatus::pin_unavailable,
                  SuiZkLoginProposalTerminalResult::invalid_state};
    switch (begin_result.status) {
        case SuiZkLoginReviewPinBeginStatus::started:
            break;
        case SuiZkLoginReviewPinBeginStatus::timed_out:
            complete_review_to_terminal(
                ops,
                current.request_id,
                begin_result.terminal_result);
            return;
        case SuiZkLoginReviewPinBeginStatus::unavailable:
            finish_error_terminal(
                ops,
                current.request_id,
                "invalid_state",
                "Sui zkLogin proposal is unavailable.",
                "zkLogin unavailable");
            return;
        case SuiZkLoginReviewPinBeginStatus::pin_unavailable:
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
            UiPanelKind::sui_zklogin_review,
            draw_local_pin_for_transition,
            &draw_context)) {
        if (ops.wipe_local_pin_auth_scratch != nullptr) {
            ops.wipe_local_pin_auth_scratch(
                "Sui zkLogin proposal PIN display allocation failed");
        }
        if (ops.clear_panel_if_kind != nullptr) {
            ops.clear_panel_if_kind(
                UiPanelKind::local_pin_auth,
                SensitiveUiClearPolicy::preserve);
        }
        const SuiZkLoginProposalTerminalResult result =
            ops.record_ui_error != nullptr
                ? ops.record_ui_error()
                : SuiZkLoginProposalTerminalResult::ui_error;
        finish_terminal(ops, current.request_id, result);
    }
}

void sui_zklogin_review_ui_reject(const SuiZkLoginReviewUiFlowOps& ops)
{
    const SuiZkLoginProposalSnapshot current = snapshot_or_inactive(ops);
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
    const SuiZkLoginProposalTerminalResult result =
        ops.record_rejected != nullptr
            ? ops.record_rejected()
            : SuiZkLoginProposalTerminalResult::rejected;
    complete_review_to_terminal(ops, current.request_id, result);
}

void sui_zklogin_review_ui_clear_if_needed(const SuiZkLoginReviewUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const SuiZkLoginProposalSnapshot current = snapshot_or_inactive(ops);
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
            const SuiZkLoginProposalTerminalResult result =
                ops.record_ui_error != nullptr
                    ? ops.record_ui_error()
                    : SuiZkLoginProposalTerminalResult::ui_error;
            finish_terminal(ops, current.request_id, result);
        }
        return;
    }

    complete_review_to_terminal(ops, current.request_id, record_timed_out(ops));
}

}  // namespace signing
