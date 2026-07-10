#include "protocol/request_line_handler.h"

#include <ArduinoJson.h>

#include "protocol/request_envelope.h"

namespace signing {

void handle_protocol_request_line(
    const char* line,
    TimeoutTick now_tick,
    const ProtocolTransportRoute& route,
    const OperationHandlers& handlers,
    PayloadRefResolver resolve_payload_ref)
{
    if (!route.bound()) {
        return;
    }
    JsonDocument request;
    JsonDocument resolved_payload;
    RequestEnvelope envelope = {};
    const RequestEnvelopeParseStatus envelope_status =
        parse_request_envelope(line, request, &envelope);
    const ResponseWriter method_writer =
        route.response_writer().for_method(envelope.method);
    if (envelope_status != RequestEnvelopeParseStatus::ok) {
        if (method_writer.can_write_error()) {
            method_writer.write_error(
                envelope.id,
                request_envelope_error_code(envelope_status));
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

    dispatch_operation(
        envelope.id,
        envelope.operation_type,
        request,
        method_writer,
        handlers);
}

}  // namespace signing
