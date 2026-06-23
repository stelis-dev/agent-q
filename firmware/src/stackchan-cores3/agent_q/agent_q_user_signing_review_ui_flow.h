#pragma once

#include <stdint.h>

#include "agent_q_avatar_overlay_drawing.h"
#include "agent_q_drawing_surface.h"
#include "agent_q_timeout_window.h"
#include "agent_q_user_signing_confirmation.h"
#include "agent_q_user_signing_flow.h"
#include "agent_q_user_signing_review_view_model.h"
#include "freertos/FreeRTOS.h"

namespace agent_q {

struct AgentQUserSigningReviewUiFlowOps {
    TickType_t (*now)();
    AgentQUserSigningFlowCoreSnapshot (*core_snapshot)();
    AgentQUserSigningReviewTimerState (*review_timer_state)(TickType_t now);
    bool (*snapshot)(AgentQUserSigningFlowSnapshot* output);
    AgentQUserSigningReviewBuildResult (*build_review_model)(
        const AgentQUserSigningFlowSnapshot& snapshot,
        AgentQUserSigningReviewViewModel* output);
    bool (*draw_review_panel)(
        const AgentQUserSigningReviewViewModel& model,
        AgentQUserSigningReviewTimerState timer);
    bool (*draw_review_timer)(AgentQUserSigningReviewTimerState timer);
    bool (*clear_panel_if_kind)(AgentQUiPanelKind kind, SensitiveUiClearPolicy policy);
    bool (*review_panel_active)();
    bool (*human_approval_requires_pin)();
    AgentQUserSigningTransitionResult
        (*record_physical_confirmed_and_write_confirmation_history)(
            TickType_t now,
            AgentQUserSigningHistoryWriteFn write_fn,
            void* context);
    AgentQUserSigningConfirmationResult (*accept_review_and_begin_pin)(
        TickType_t now,
        AgentQTimeoutWindow pin_input_window);
    AgentQUserSigningConfirmationResult (*record_device_rejected)();
    AgentQUserSigningTransitionResult (*record_timeout)(TickType_t now);
    AgentQUserSigningTransitionResult (*pause_review_deadline)(TickType_t now);
    AgentQUserSigningTransitionResult (*resume_review_deadline)(TickType_t now);
    AgentQUserSigningTransitionResult (*clear_flow)();
    bool (*terminal_pending)();
    void (*cancel_for_pin_loss)();
    bool (*draw_local_pin_auth_panel)();
    bool (*write_error)(const char* id, const char* code, const char* message);
    void (*show_display_error)();
    AgentQUserSigningHistoryWriteFn write_confirmation_history;
    void (*execute_critical_section_and_finish)(const char* request_id);
    void (*finish_terminal)(const char* request_id);
    void (*finish_error_terminal)(
        const char* request_id,
        const char* error_code,
        const char* error_message,
        const char* display_message);
    void (*log_warn)(const char* message);
    uint32_t pin_input_window_ms;
};

bool user_signing_review_ui_show(const AgentQUserSigningReviewUiFlowOps& ops);
void user_signing_review_ui_accept(const AgentQUserSigningReviewUiFlowOps& ops);
void user_signing_review_ui_reject(const AgentQUserSigningReviewUiFlowOps& ops);
void user_signing_review_ui_scroll_started(const AgentQUserSigningReviewUiFlowOps& ops);
void user_signing_review_ui_scroll_finished(const AgentQUserSigningReviewUiFlowOps& ops);
void user_signing_review_ui_clear_if_needed(const AgentQUserSigningReviewUiFlowOps& ops);

}  // namespace agent_q
