#pragma once

#include <ArduinoJson.h>

#include "protocol/operation_type.h"
#include "protocol/response_writer.h"

namespace signing {

struct RetainedResponseHandlerOps {
    bool (*material_ready)();
    bool (*write_payload_delivery_retained_response_admission_error)(
        const char* id,
        OperationType operation,
        const ResponseWriter& writer);
    bool (*require_active_matching_session)(
        const char* id,
        const char* session_id,
        const ResponseWriter& writer);
};

void handle_protocol_get_result_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const RetainedResponseHandlerOps& ops);

void handle_protocol_ack_result_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const RetainedResponseHandlerOps& ops);

}  // namespace signing
