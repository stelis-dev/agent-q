#pragma once

#include "transport/connect_approval.h"

namespace signing {

enum class ConnectReviewTerminalUiKind {
    success,
    rejected,
    timeout,
    error,
};

struct ConnectReviewResponseFlowOps {
    TimeoutTick (*now)();
    bool (*local_pin_flow_active)();
    void (*reset_connect_choices)();
    bool (*receive_connect_choice)(ConnectApprovalChoice* choice);
    bool (*awaiting_choice)();
    bool (*human_approval_requires_pin)();
    bool (*begin_pin_auth_from_review)(TimeoutTick now);
    bool (*choose)(ConnectApprovalChoice choice, TimeoutTick now);
    ConnectApprovalSnapshot (*snapshot)();
    bool (*deadline_reached)(TimeoutTick now);
    bool (*request_id)(char* output, size_t output_size);
    void (*clear_approval)();
    bool (*replace_active_session)();
    bool (*write_error)(const char* id, const char* code);
    bool (*write_approved)(const char* id);
    bool (*write_rejected)(const char* id, const char* code);
    void (*log_info)(const char* message, const char* id);
    void (*log_error)(const char* message, const char* id);
    void (*log_write_failure)(const char* response_type, const char* id);
    void (*log_review_recovered)(const char* id);
    void (*show_result_and_clear_review)(const char* message, ConnectReviewTerminalUiKind kind);
    bool (*review_panel_visible)();
    void (*show_review)();
};

void connect_review_response_flow_run(
    const ConnectReviewResponseFlowOps& ops);

}  // namespace signing
