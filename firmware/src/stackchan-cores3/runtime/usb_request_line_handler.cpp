#include "usb_request_line_handler.h"

#include <ArduinoJson.h>

#include "usb_request_envelope.h"

namespace signing {

void handle_usb_request_line(
    const char* line,
    TimeoutTick now_tick,
    const UsbOperationResponseWriter& response_writer,
    const UsbOperationHandlers& handlers,
    UsbPayloadRefResolver resolve_payload_ref)
{
    JsonDocument request;
    JsonDocument resolved_payload;
    UsbRequestEnvelope envelope = {};
    const UsbRequestEnvelopeParseStatus envelope_status =
        parse_usb_request_envelope(line, request, &envelope);
    const UsbOperationResponseWriter method_writer =
        response_writer.for_method(envelope.method);
    if (envelope_status != UsbRequestEnvelopeParseStatus::ok) {
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

}  // namespace signing
