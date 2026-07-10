#pragma once

#include <ArduinoJson.h>

#include "transport/timeout_window.h"
#include "protocol/request_envelope.h"
#include "protocol/operation_dispatch.h"
#include "protocol/protocol_transport.h"

namespace signing {

using PayloadRefResolver = bool (*)(
    JsonDocument& request,
    JsonDocument& resolved_payload,
    TimeoutTick now_tick,
    const RequestEnvelope& envelope,
    const ResponseWriter& writer);

void handle_protocol_request_line(
    const char* line,
    TimeoutTick now_tick,
    const ProtocolTransportRoute& route,
    const OperationHandlers& handlers,
    PayloadRefResolver resolve_payload_ref = nullptr);

}  // namespace signing
