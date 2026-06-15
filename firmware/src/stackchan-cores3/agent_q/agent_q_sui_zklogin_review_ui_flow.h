#pragma once

#include "agent_q_drawing_surface.h"
#include "agent_q_local_pin_auth.h"
#include "agent_q_modal_drawing.h"
#include "agent_q_sui_zklogin_proposal_flow.h"
#include "agent_q_timeout_window.h"
#include "freertos/FreeRTOS.h"

namespace agent_q {

struct AgentQSuiZkLoginReviewUiFlowOps {
    TickType_t (*now)();
    AgentQSuiZkLoginProposalSnapshot (*snapshot)();
    bool (*draw_review_panel)(
        const AgentQSuiZkLoginReviewViewModel& model,
        AgentQTimeoutWindow window);
    bool (*clear_panel_if_kind)(AgentQUiPanelKind kind, SensitiveUiClearPolicy policy);
    bool (*review_panel_active)();
    void (*identification_display_clear)();
    AgentQSuiZkLoginProposalTransitionResult (*continue_to_pin)(TickType_t now);
    bool (*protocol_pin_begin_sui_zklogin_proposal)(
        const char* request_id,
        const char* session_id,
        TickType_t now,
        AgentQTimeoutWindow window);
    void (*protocol_pin_clear)();
    bool (*local_pin_begin_sui_zklogin_proposal)(
        TickType_t now,
        AgentQTimeoutWindow window);
    bool (*draw_local_pin_auth_panel)(const char* notice);
    void (*wipe_local_pin_auth_scratch)(const char* reason);
    bool (*review_deadline_reached)(TickType_t now);
    AgentQSuiZkLoginProposalTerminalResult (*record_timed_out)();
    AgentQSuiZkLoginProposalTerminalResult (*record_rejected)();
    AgentQSuiZkLoginProposalTerminalResult (*record_ui_error)();
    void (*finish_terminal)(
        const char* request_id,
        AgentQSuiZkLoginProposalTerminalResult result);
    void (*finish_error_terminal)(
        const char* request_id,
        const char* error_code,
        const char* error_message,
        const char* display_message);
    void (*log_warn)(const char* message);
};

bool sui_zklogin_review_ui_show(const AgentQSuiZkLoginReviewUiFlowOps& ops);
void sui_zklogin_review_ui_continue(const AgentQSuiZkLoginReviewUiFlowOps& ops);
void sui_zklogin_review_ui_reject(const AgentQSuiZkLoginReviewUiFlowOps& ops);
void sui_zklogin_review_ui_clear_if_needed(const AgentQSuiZkLoginReviewUiFlowOps& ops);

}  // namespace agent_q
