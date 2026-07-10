#pragma once

#include <stddef.h>

#include <ArduinoJson.h>

#include "protocol/response_writer.h"
#include "protocol/operation_type.h"

namespace signing {

enum class SessionIdMode {
    optional_default_empty,
    required,
};

struct ActiveSessionRequestGuardOps {
    bool (*material_ready)();
    bool (*write_busy_if_pending_or_local_flow_active)(
        const char* id,
        const ResponseWriter& writer);
    bool (*write_admission_error)(
        const char* id,
        OperationType operation,
        const ResponseWriter& writer);
    bool (*require_active_matching_session)(
        const char* id,
        const char* session_id,
        const ResponseWriter& writer);
};

bool guard_active_session_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    OperationType operation,
    const ActiveSessionRequestGuardOps& ops,
    SessionIdMode session_id_mode,
    const char* const* allowed_request_fields,
    size_t allowed_request_field_count,
    const char** session_id);

}  // namespace signing
