#pragma once

#include <stdint.h>

#include "drawing_surface.h"
#include "local_pin_auth.h"
#include "modal_drawing.h"
#include "policy_update_flow.h"
#include "timeout_window.h"
#include "freertos/FreeRTOS.h"

namespace signing {

enum class PolicyUpdateReviewPinBeginStatus {
    started,
    timed_out,
    unavailable,
    pin_unavailable,
};

struct PolicyUpdateReviewPinBeginResult {
    PolicyUpdateReviewPinBeginStatus status;
    PolicyUpdateFlowTerminalResult terminal_result;
};

struct PolicyUpdateReviewUiFlowOps {
    TickType_t (*now)();
    uint64_t (*wall_clock_ms)();
    PolicyUpdateFlowSnapshot (*snapshot)();
    bool (*draw_review_panel)(
        const PolicyUpdateReviewViewModel& model,
        TimeoutWindow window);
    bool (*clear_panel_if_kind)(UiPanelKind kind, SensitiveUiClearPolicy policy);
    bool (*review_panel_active)();
    void (*identification_display_clear)();
    PolicyUpdateReviewPinBeginResult (*begin_pin_from_review)(
        const PolicyUpdateFlowSnapshot& current,
        TickType_t now,
        TimeoutWindow window,
        uint64_t uptime_ms);
    bool (*draw_local_pin_auth_panel)();
    void (*clear_local_pin_auth_scratch)(const char* reason);
    bool (*review_deadline_reached)(TickType_t now);
    PolicyUpdateFlowTerminalResult (*record_timed_out)(uint64_t uptime_ms);
    PolicyUpdateFlowTerminalResult (*record_rejected)(uint64_t uptime_ms);
    PolicyUpdateFlowTerminalResult (*record_ui_error)();
    void (*finish_terminal)(
        const char* request_id,
        PolicyUpdateFlowTerminalResult result);
    void (*finish_error_terminal)(
        const char* request_id,
        const char* error_code,
        const char* error_message,
        const char* display_message);
    void (*log_warn)(const char* message);
    uint32_t review_pin_window_ms;
};

bool policy_update_review_ui_show(const PolicyUpdateReviewUiFlowOps& ops);
void policy_update_review_ui_continue(const PolicyUpdateReviewUiFlowOps& ops);
void policy_update_review_ui_reject(const PolicyUpdateReviewUiFlowOps& ops);
void policy_update_review_ui_clear_if_needed(const PolicyUpdateReviewUiFlowOps& ops);

}  // namespace signing
