#pragma once

#include <ArduinoJson.h>

#include "policy/policy_update_flow.h"
#include "protocol/operation_type.h"
#include "protocol/response_writer.h"
#include "transport/timeout_window.h"

namespace signing {

struct PolicyHandlerOps {
    bool (*material_ready)();
    bool (*write_policy_get_busy)(
        const char* id,
        const ResponseWriter& writer);
    bool (*write_policy_get_admission_error)(
        const char* id,
        OperationType operation,
        const ResponseWriter& writer);
    bool (*write_policy_propose_busy)(
        const char* id,
        const ResponseWriter& writer);
    bool (*require_active_matching_session)(
        const char* id,
        const char* session_id,
        const ResponseWriter& writer);
    void (*record_active_policy_unavailable)();
    TimeoutTick (*current_tick)();
    TimeoutWindow (*make_review_window)(TimeoutTick now);
    PolicyUpdateFlowBeginResult (*begin_policy_update)(
        JsonVariantConst policy,
        const char* request_id,
        const char* session_id,
        TickType_t now,
        TimeoutWindow review_window);
    const char* (*begin_result_reason)(PolicyUpdateFlowBeginResult result);
    bool (*show_policy_update_review)();
    PolicyUpdateFlowTerminalResult (*record_ui_error)();
    void (*finish_policy_update_terminal)(const char* id, PolicyUpdateFlowTerminalResult result);
    void (*record_review_waiting)(const char* id);
};

bool policy_propose_outcome_write(
    const char* id,
    const char* status,
    const char* reason_code,
    const PolicyUpdateFlowSnapshot* policy,
    const ResponseWriter& writer);

void handle_protocol_policy_get_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const PolicyHandlerOps& ops);

void handle_protocol_policy_propose_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const PolicyHandlerOps& ops);

}  // namespace signing
