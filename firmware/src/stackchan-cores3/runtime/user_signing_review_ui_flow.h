#pragma once

#include <stdint.h>

#include "avatar_overlay_drawing.h"
#include "drawing_surface.h"
#include "transport/timeout_window.h"
#include "signing/user_signing_flow.h"
#include "user_signing_review_view_model.h"
#include "freertos/FreeRTOS.h"

namespace signing {

enum class UserSigningReviewAcceptResult {
    execute,
    finish_terminal,
    history_error,
    unavailable,
};

enum class UserSigningReviewPinBeginResult {
    started,
    finish_terminal,
    busy,
    unavailable,
};

enum class UserSigningReviewRejectResult {
    finish_terminal,
    unavailable,
};

struct UserSigningReviewUiFlowOps {
    TickType_t (*now)();
    UserSigningFlowCoreSnapshot (*core_snapshot)();
    UserSigningReviewTimerState (*review_timer_state)(TickType_t now);
    bool (*snapshot)(UserSigningFlowSnapshot* output);
    UserSigningReviewBuildResult (*build_review_model)(
        const UserSigningFlowSnapshot& snapshot,
        UserSigningReviewViewModel* output);
    bool (*draw_review_panel)(
        const UserSigningReviewViewModel& model,
        UserSigningReviewTimerState timer);
    bool (*draw_review_timer)(UserSigningReviewTimerState timer);
    bool (*clear_panel_if_kind)(UiPanelKind kind, SensitiveUiClearPolicy policy);
    bool (*review_panel_active)();
    bool (*human_approval_requires_pin)();
    UserSigningReviewAcceptResult (*accept_review_without_pin)(TickType_t now);
    UserSigningReviewPinBeginResult (*begin_pin_from_review)(
        TickType_t now,
        TimeoutWindow pin_input_window);
    UserSigningReviewRejectResult (*reject_review)();
    UserSigningTransitionResult (*record_timeout)(TickType_t now);
    UserSigningTransitionResult (*pause_review_deadline)(TickType_t now);
    UserSigningTransitionResult (*resume_review_deadline)(TickType_t now);
    UserSigningTransitionResult (*clear_flow)();
    bool (*terminal_pending)();
    void (*cancel_for_pin_loss)();
    bool (*draw_local_pin_auth_panel)();
    bool (*write_error)(const char* id, const char* code);
    void (*show_display_error)();
    void (*execute_user_signing_from_review)(const char* request_id);
    void (*finish_terminal)(const char* request_id);
    void (*finish_error_terminal)(
        const char* request_id,
        const char* error_code,
        const char* error_message,
        const char* display_message);
    void (*log_warn)(const char* message);
    uint32_t pin_input_window_ms;
};

bool user_signing_review_ui_show(const UserSigningReviewUiFlowOps& ops);
void user_signing_review_ui_accept(const UserSigningReviewUiFlowOps& ops);
void user_signing_review_ui_reject(const UserSigningReviewUiFlowOps& ops);
void user_signing_review_ui_scroll_started(const UserSigningReviewUiFlowOps& ops);
void user_signing_review_ui_scroll_finished(const UserSigningReviewUiFlowOps& ops);
void user_signing_review_ui_clear_if_needed(const UserSigningReviewUiFlowOps& ops);

}  // namespace signing
