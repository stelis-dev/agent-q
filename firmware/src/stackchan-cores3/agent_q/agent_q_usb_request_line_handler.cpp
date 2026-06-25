#include "agent_q_usb_request_line_handler.h"

#include <ArduinoJson.h>

#include "agent_q_usb_request_envelope.h"

namespace agent_q {

void handle_usb_request_line(
    const char* line,
    AgentQTimeoutTick now_tick,
    const AgentQUsbOperationResponseWriter& response_writer,
    const AgentQUsbOperationHandlers& handlers,
    AgentQUsbPayloadRefResolver resolve_payload_ref)
{
    JsonDocument request;
    JsonDocument resolved_payload;
    AgentQUsbRequestEnvelope envelope = {};
    const AgentQUsbRequestEnvelopeParseStatus envelope_status =
        parse_usb_request_envelope(line, request, &envelope);
    const AgentQUsbOperationResponseWriter method_writer =
        response_writer.for_method(envelope.method);
    if (envelope_status != AgentQUsbRequestEnvelopeParseStatus::ok) {
        if (method_writer.can_write_error()) {
            method_writer.write_error(
                envelope.id,
                usb_request_envelope_error_code(envelope_status));
        }
        return;
    }

    if (resolve_payload_ref != nullptr &&
        !resolve_payload_ref(
            request,
            resolved_payload,
            now_tick,
            envelope,
            method_writer)) {
        return;
    }

    dispatch_usb_operation(
        envelope.id,
        envelope.operation_type,
        request,
        method_writer,
        handlers);
}

}  // namespace agent_q
