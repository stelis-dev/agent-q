#pragma once

#include <ArduinoJson.h>

#include "agent_q_usb_operation_type.h"
#include "agent_q_usb_operation_response_writer.h"

namespace agent_q {

struct AgentQUsbDisconnectHandlerOps {
    bool (*require_active_matching_session)(
        const char* id,
        const char* session_id,
        const AgentQUsbOperationResponseWriter& writer);
    bool (*disconnect_pending_policy_update_for_session)(const char* id, const char* session_id);
    bool (*disconnect_pending_sui_zklogin_proposal_for_session)(const char* id, const char* session_id);
    bool (*disconnect_pending_user_signing_for_session)(const char* id, const char* session_id);
    bool (*write_busy_if_pending_or_local_flow_active)(
        const char* id,
        const AgentQUsbOperationResponseWriter& writer);
    bool (*write_payload_delivery_disconnect_admission_error)(
        const char* id,
        AgentQUsbOperationType operation,
        const AgentQUsbOperationResponseWriter& writer);
    void (*clear_active_session)();
};

void handle_usb_disconnect_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbDisconnectHandlerOps& ops);

}  // namespace agent_q
