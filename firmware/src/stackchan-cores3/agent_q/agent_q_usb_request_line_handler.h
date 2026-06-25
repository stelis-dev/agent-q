#pragma once

#include <ArduinoJson.h>

#include "agent_q_timeout_window.h"
#include "agent_q_usb_request_envelope.h"
#include "agent_q_usb_operation_dispatch.h"
#include "agent_q_usb_operation_response_writer.h"

namespace agent_q {

using AgentQUsbPayloadRefResolver = bool (*)(
    JsonDocument& request,
    JsonDocument& resolved_payload,
    AgentQTimeoutTick now_tick,
    const AgentQUsbRequestEnvelope& envelope,
    const AgentQUsbOperationResponseWriter& writer);

void handle_usb_request_line(
    const char* line,
    AgentQTimeoutTick now_tick,
    const AgentQUsbOperationResponseWriter& response_writer,
    const AgentQUsbOperationHandlers& handlers,
    AgentQUsbPayloadRefResolver resolve_payload_ref = nullptr);

}  // namespace agent_q
