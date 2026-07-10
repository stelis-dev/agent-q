#include "user_signing_review_ui_flow.h"

#include "modal_transition.h"
#include "transport/timeout_window.h"

#include "esp_attr.h"

#include <string.h>

namespace signing {
namespace {

EXT_RAM_BSS_ATTR UserSigningFlowSnapshot g_review_snapshot_scratch;

TickType_t now_or_zero(const UserSigningReviewUiFlowOps& ops)
{
    return ops.now != nullptr ? ops.now() : 0;
}

const UserSigningFlowSnapshot* snapshot_or_null(
    const UserSigningReviewUiFlowOps& ops)
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

UserSigningFlowCoreSnapshot core_snapshot_or_inactive(
    const UserSigningReviewUiFlowOps& ops)
{
    if (ops.core_snapshot == nullptr) {
        return {};
    }
    return ops.core_snapshot();
}

UserSigningReviewTimerState review_timer_state_or_unavailable(
    const UserSigningReviewUiFlowOps& ops,
    TickType_t now)
{
    if (ops.review_timer_state == nullptr) {
        return {};
    }
    return ops.review_timer_state(now);
}

bool reviewing(const UserSigningFlowCoreSnapshot& snapshot)
{
    return snapshot.active &&
           snapshot.stage == UserSigningStage::reviewing;
}

void log_warn(const UserSigningReviewUiFlowOps& ops, const char* message)
{
    if (ops.log_warn != nullptr) {
        ops.log_warn(message);
    }
}

ModalTransitionOps modal_transition_ops(const UserSigningReviewUiFlowOps& ops)
{
    return ModalTransitionOps{
        ops.clear_panel_if_kind,
        nullptr,
        ops.log_warn,
    };
}

TimeoutWindow window_from_now_ms(
    const UserSigningReviewUiFlowOps& ops,
    uint32_t duration_ms)
{
    const TickType_t now = now_or_zero(ops);
    return timeout_window_from_deadline(now, now + pdMS_TO_TICKS(duration_ms));
}

void finish_terminal(
    const UserSigningReviewUiFlowOps& ops,
    const char* request_id)
{
    if (ops.finish_terminal != nullptr) {
        ops.finish_terminal(request_id);
    }
}

void finish_error_terminal(
    const UserSigningReviewUiFlowOps& ops,
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

bool terminal_pending(const UserSigningReviewUiFlowOps& ops)
{
    return ops.terminal_pending != nullptr && ops.terminal_pending();
}

bool review_panel_active(const UserSigningReviewUiFlowOps& ops)
{
    return ops.review_panel_active != nullptr && ops.review_panel_active();
}

struct UserSigningWorkContext {
    const UserSigningReviewUiFlowOps* ops = nullptr;
    const char* request_id = nullptr;
};

void execute_user_signing_for_transition(void* context)
{
    const auto* work_context = static_cast<const UserSigningWorkContext*>(context);
    if (work_context == nullptr ||
        work_context->ops == nullptr ||
        work_context->ops->execute_user_signing_from_review == nullptr) {
        return;
    }
    work_context->ops->execute_user_signing_from_review(work_context->request_id);
}

void run_user_signing_then_clear_review_panel(
    const UserSigningReviewUiFlowOps& ops,
    const char* request_id)
{
    UserSigningWorkContext context{&ops, request_id};
    modal_transition_run_work_then_clear_panel(
        modal_transition_ops(ops),
        UiPanelKind::user_signing_review,
        execute_user_signing_for_transition,
        &context);
}

struct DrawLocalPinContext {
    const UserSigningReviewUiFlowOps* ops = nullptr;
};

struct UserSigningTerminalContext {
    const UserSigningReviewUiFlowOps* ops = nullptr;
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
    const UserSigningReviewUiFlowOps& ops,
    const char* request_id)
{
    UserSigningTerminalContext context{&ops, request_id};
    modal_transition_complete_to_result(
        modal_transition_ops(ops),
        UiPanelKind::user_signing_review,
        finish_user_signing_terminal_for_transition,
        &context);
}

bool stale_scroll_result(UserSigningTransitionResult result)
{
    return result == UserSigningTransitionResult::inactive ||
           result == UserSigningTransitionResult::wrong_stage;
}

void handle_scroll_result(
    const UserSigningReviewUiFlowOps& ops,
    const char* request_id,
    UserSigningTransitionResult result,
    const char* stale_message)
{
    if (result == UserSigningTransitionResult::ok) {
        const TickType_t now = now_or_zero(ops);
        const UserSigningReviewTimerState timer =
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
    if (result == UserSigningTransitionResult::deadline_expired ||
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

bool user_signing_review_ui_show(const UserSigningReviewUiFlowOps& ops)
{
    const UserSigningFlowSnapshot* current = snapshot_or_null(ops);
    const TickType_t now = now_or_zero(ops);
    UserSigningReviewViewModel model = {};
    if (current == nullptr ||
        ops.build_review_model == nullptr ||
        ops.build_review_model(*current, &model) !=
            UserSigningReviewBuildResult::ok) {
        memset(&g_review_snapshot_scratch, 0, sizeof(g_review_snapshot_scratch));
        return false;
    }
    const UserSigningReviewTimerState timer =
        review_timer_state_or_unavailable(ops, now);
    const bool drawn = ops.draw_review_panel != nullptr &&
                       ops.draw_review_panel(model, timer);
    memset(&g_review_snapshot_scratch, 0, sizeof(g_review_snapshot_scratch));
    return drawn;
}

void user_signing_review_ui_accept(const UserSigningReviewUiFlowOps& ops)
{
    const UserSigningFlowCoreSnapshot current = core_snapshot_or_inactive(ops);
    if (!reviewing(current)) {
        log_warn(ops, "Stale user_signing review accept ignored");
        return;
    }

    const TickType_t now = now_or_zero(ops);
    const bool requires_pin =
        ops.human_approval_requires_pin != nullptr &&
        ops.human_approval_requires_pin();
    if (!requires_pin) {
        const UserSigningReviewAcceptResult result =
            ops.accept_review_without_pin != nullptr
                ? ops.accept_review_without_pin(now)
                : UserSigningReviewAcceptResult::unavailable;
        switch (result) {
            case UserSigningReviewAcceptResult::execute:
                run_user_signing_then_clear_review_panel(ops, current.request_id);
                return;
            case UserSigningReviewAcceptResult::finish_terminal:
                finish_terminal(ops, current.request_id);
                return;
            case UserSigningReviewAcceptResult::history_error:
                finish_error_terminal(
                    ops,
                    current.request_id,
                    "history_unavailable",
                    "Signing request is unavailable.",
                    "Signing unavailable");
                return;
            case UserSigningReviewAcceptResult::unavailable:
                finish_error_terminal(
                    ops,
                    current.request_id,
                    "invalid_state",
                    "Signing request is unavailable.",
                    "Signing unavailable");
                return;
        }
        return;
    }

    const TimeoutWindow pin_input_window =
        window_from_now_ms(ops, ops.pin_input_window_ms);
    const UserSigningReviewPinBeginResult result =
        ops.begin_pin_from_review != nullptr
            ? ops.begin_pin_from_review(now, pin_input_window)
            : UserSigningReviewPinBeginResult::unavailable;
    if (result != UserSigningReviewPinBeginResult::started) {
        if (result == UserSigningReviewPinBeginResult::finish_terminal) {
            finish_terminal(ops, current.request_id);
            return;
        }
        finish_error_terminal(
            ops,
            current.request_id,
            result == UserSigningReviewPinBeginResult::busy
                ? "busy"
                : "invalid_state",
            "Signing request is unavailable.",
            "Signing unavailable");
        return;
    }

    DrawLocalPinContext draw_context{&ops};
    if (!modal_transition_complete_to_next_panel(
            modal_transition_ops(ops),
            UiPanelKind::user_signing_review,
            draw_local_pin_for_transition,
            &draw_context)) {
        if (ops.cancel_for_pin_loss != nullptr) {
            ops.cancel_for_pin_loss();
        }
        if (ops.clear_panel_if_kind != nullptr) {
            ops.clear_panel_if_kind(
                UiPanelKind::local_pin_auth,
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

void user_signing_review_ui_reject(const UserSigningReviewUiFlowOps& ops)
{
    const UserSigningFlowCoreSnapshot current = core_snapshot_or_inactive(ops);
    if (!reviewing(current)) {
        log_warn(ops, "Stale user_signing review reject ignored");
        return;
    }

    const UserSigningReviewRejectResult result =
        ops.reject_review != nullptr
            ? ops.reject_review()
            : UserSigningReviewRejectResult::unavailable;
    if (result != UserSigningReviewRejectResult::finish_terminal) {
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

void user_signing_review_ui_scroll_started(const UserSigningReviewUiFlowOps& ops)
{
    const UserSigningFlowCoreSnapshot current = core_snapshot_or_inactive(ops);
    if (!reviewing(current) || !review_panel_active(ops)) {
        log_warn(ops, "Stale user_signing review scroll start ignored");
        return;
    }

    const TickType_t now = now_or_zero(ops);
    const UserSigningTransitionResult result =
        ops.pause_review_deadline != nullptr
            ? ops.pause_review_deadline(now)
            : UserSigningTransitionResult::invalid_argument;
    handle_scroll_result(
        ops,
        current.request_id,
        result,
        "Stale user_signing review scroll start ignored");
}

void user_signing_review_ui_scroll_finished(const UserSigningReviewUiFlowOps& ops)
{
    const UserSigningFlowCoreSnapshot current = core_snapshot_or_inactive(ops);
    if (!reviewing(current) || !review_panel_active(ops)) {
        log_warn(ops, "Stale user_signing review scroll finish ignored");
        return;
    }

    const TickType_t now = now_or_zero(ops);
    const UserSigningTransitionResult result =
        ops.resume_review_deadline != nullptr
            ? ops.resume_review_deadline(now)
            : UserSigningTransitionResult::invalid_argument;
    handle_scroll_result(
        ops,
        current.request_id,
        result,
        "Stale user_signing review scroll finish ignored");
}

void user_signing_review_ui_clear_if_needed(const UserSigningReviewUiFlowOps& ops)
{
    const TickType_t now = now_or_zero(ops);
    const UserSigningFlowCoreSnapshot current = core_snapshot_or_inactive(ops);
    if (!reviewing(current)) {
        return;
    }

    const bool panel_active = review_panel_active(ops);
    const UserSigningReviewTimerState timer_before_timeout =
        review_timer_state_or_unavailable(ops, now);
    const UserSigningTransitionResult timeout_result =
        ops.record_timeout != nullptr
            ? ops.record_timeout(now)
            : UserSigningTransitionResult::invalid_argument;
    if (timeout_result == UserSigningTransitionResult::deadline_not_reached) {
        if (panel_active) {
            const UserSigningReviewTimerState timer_after_timeout =
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
                    current.method,
                    "ui_error");
            }
            if (ops.show_display_error != nullptr) {
                ops.show_display_error();
            }
        }
        return;
    }
    if (timeout_result == UserSigningTransitionResult::ok ||
        terminal_pending(ops)) {
        complete_review_to_terminal(ops, current.request_id);
        return;
    }

    log_warn(ops, "Signature review timeout check returned unexpected result");
}

}  // namespace signing
