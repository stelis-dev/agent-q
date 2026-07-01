#pragma once

#include <stdint.h>

#include "agent_q_drawing_surface.h"
#include "agent_q_local_pin_auth.h"
#include "agent_q_modal_drawing.h"
#include "agent_q_policy_update_flow.h"
#include "agent_q_timeout_window.h"
#include "freertos/FreeRTOS.h"

namespace agent_q {

enum class AgentQPolicyUpdateReviewPinBeginStatus {
    started,
    timed_out,
    unavailable,
    pin_unavailable,
};

struct AgentQPolicyUpdateReviewPinBeginResult {
    AgentQPolicyUpdateReviewPinBeginStatus status;
    AgentQPolicyUpdateFlowTerminalResult terminal_result;
};

struct AgentQPolicyUpdateReviewUiFlowOps {
    TickType_t (*now)();
    uint64_t (*wall_clock_ms)();
    AgentQPolicyUpdateFlowSnapshot (*snapshot)();
    bool (*draw_review_panel)(
        const AgentQPolicyUpdateReviewViewModel& model,
        AgentQTimeoutWindow window);
    bool (*clear_panel_if_kind)(AgentQUiPanelKind kind, SensitiveUiClearPolicy policy);
    bool (*review_panel_active)();
    void (*identification_display_clear)();
    AgentQPolicyUpdateReviewPinBeginResult (*begin_pin_from_review)(
        const AgentQPolicyUpdateFlowSnapshot& current,
        TickType_t now,
        AgentQTimeoutWindow window,
        uint64_t uptime_ms);
    bool (*draw_local_pin_auth_panel)();
    void (*wipe_local_pin_auth_scratch)(const char* reason);
    bool (*review_deadline_reached)(TickType_t now);
    AgentQPolicyUpdateFlowTerminalResult (*record_timed_out)(uint64_t uptime_ms);
    AgentQPolicyUpdateFlowTerminalResult (*record_rejected)(uint64_t uptime_ms);
    AgentQPolicyUpdateFlowTerminalResult (*record_ui_error)();
    void (*finish_terminal)(
        const char* request_id,
        AgentQPolicyUpdateFlowTerminalResult result);
    void (*finish_error_terminal)(
        const char* request_id,
        const char* error_code,
        const char* error_message,
        const char* display_message);
    void (*log_warn)(const char* message);
    uint32_t review_pin_window_ms;
};

bool policy_update_review_ui_show(const AgentQPolicyUpdateReviewUiFlowOps& ops);
void policy_update_review_ui_continue(const AgentQPolicyUpdateReviewUiFlowOps& ops);
void policy_update_review_ui_reject(const AgentQPolicyUpdateReviewUiFlowOps& ops);
void policy_update_review_ui_clear_if_needed(const AgentQPolicyUpdateReviewUiFlowOps& ops);

}  // namespace agent_q
