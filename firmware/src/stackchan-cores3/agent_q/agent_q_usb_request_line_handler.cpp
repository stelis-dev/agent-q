#include "agent_q_usb_request_line_handler.h"

#include <ArduinoJson.h>

#include "agent_q_usb_request_envelope.h"

namespace agent_q {

void handle_usb_request_line(
    const char* line,
    const AgentQUsbOperationResponseWriter& response_writer,
    const AgentQUsbOperationHandlers& handlers)
{
    JsonDocument request;
    AgentQUsbRequestEnvelope envelope = {};
    const AgentQUsbRequestEnvelopeParseStatus envelope_status =
        parse_usb_request_envelope(line, request, &envelope);
    if (envelope_status != AgentQUsbRequestEnvelopeParseStatus::ok) {
        if (response_writer.write_error != nullptr) {
            response_writer.write_error(
                envelope.id,
                usb_request_envelope_error_code(envelope_status),
                usb_request_envelope_error_message(envelope_status));
        }
        return;
    }

    dispatch_usb_operation(
        envelope.id,
        envelope.operation_type,
        request,
        response_writer,
        handlers);
}

}  // namespace agent_q
