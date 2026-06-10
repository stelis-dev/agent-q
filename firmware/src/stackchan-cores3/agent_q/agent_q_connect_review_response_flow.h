#pragma once

#include "agent_q_connect_approval.h"
#include "agent_q_avatar_overlay_drawing.h"
#include "freertos/FreeRTOS.h"

namespace agent_q {

struct AgentQConnectReviewResponseFlowOps {
    TickType_t (*now)();
    bool (*local_pin_flow_active)();
    void (*reset_connect_choices)();
    bool (*receive_connect_choice)(AgentQConnectApprovalChoice* choice);
    bool (*awaiting_choice)();
    bool (*human_approval_requires_pin)();
    bool (*begin_pin_auth_from_review)(TickType_t now);
    bool (*choose)(AgentQConnectApprovalChoice choice, TickType_t now);
    AgentQConnectApprovalSnapshot (*snapshot)();
    bool (*deadline_reached)(TickType_t now);
    bool (*request_id)(char* output, size_t output_size);
    void (*clear_approval)();
    bool (*replace_active_session)();
    bool (*write_error)(const char* id, const char* code, const char* message);
    bool (*write_approved)(const char* id);
    bool (*write_rejected)(const char* id, const char* code, const char* message);
    void (*log_info)(const char* message, const char* id);
    void (*log_error)(const char* message, const char* id);
    void (*log_write_failure)(const char* response_type, const char* id);
    void (*log_review_recovered)(const char* id);
    void (*show_result_and_clear_review)(const char* message, AgentQMessageKind kind);
    bool (*review_panel_visible)();
    void (*show_review)();
};

void connect_review_response_flow_run(
    const AgentQConnectReviewResponseFlowOps& ops);

}  // namespace agent_q
