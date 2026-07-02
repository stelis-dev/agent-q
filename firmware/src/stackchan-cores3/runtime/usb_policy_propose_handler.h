#pragma once

#include <ArduinoJson.h>

#include "policy_update_flow.h"
#include "timeout_window.h"
#include "usb_operation_response_writer.h"

namespace signing {

struct UsbPolicyProposeHandlerOps {
    bool (*material_ready)();
    bool (*write_policy_propose_busy)(
        const char* id,
        const UsbOperationResponseWriter& writer);
    bool (*require_active_matching_session)(
        const char* id,
        const char* session_id,
        const UsbOperationResponseWriter& writer);
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

void handle_usb_policy_propose_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbPolicyProposeHandlerOps& ops);

}  // namespace signing
