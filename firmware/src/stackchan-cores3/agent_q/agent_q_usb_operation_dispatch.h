#pragma once

#include <ArduinoJson.h>

#include "agent_q_usb_operation_response_writer.h"
#include "agent_q_usb_operation_type.h"

namespace agent_q {

using AgentQUsbOperationHandler =
    void (*)(const char* id, JsonDocument& request, const AgentQUsbOperationResponseWriter& writer);

struct AgentQUsbOperationHandlers {
    AgentQUsbOperationHandler get_status = nullptr;
    AgentQUsbOperationHandler identify_device = nullptr;
    AgentQUsbOperationHandler connect = nullptr;
    AgentQUsbOperationHandler sign_transaction = nullptr;
    AgentQUsbOperationHandler sign_personal_message = nullptr;
    AgentQUsbOperationHandler get_result = nullptr;
    AgentQUsbOperationHandler ack_result = nullptr;
    AgentQUsbOperationHandler disconnect = nullptr;
    AgentQUsbOperationHandler get_capabilities = nullptr;
    AgentQUsbOperationHandler get_accounts = nullptr;
    AgentQUsbOperationHandler policy_get = nullptr;
    AgentQUsbOperationHandler get_approval_history = nullptr;
    AgentQUsbOperationHandler policy_propose = nullptr;
    AgentQUsbOperationHandler payload_upload_begin = nullptr;
    AgentQUsbOperationHandler payload_upload_chunk = nullptr;
    AgentQUsbOperationHandler payload_upload_finish = nullptr;
    AgentQUsbOperationHandler payload_upload_abort = nullptr;
};

bool dispatch_usb_operation(
    const char* id,
    AgentQUsbOperationType operation_type,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& response_writer,
    const AgentQUsbOperationHandlers& handlers);

}  // namespace agent_q
