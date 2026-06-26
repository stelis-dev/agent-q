#pragma once

#include <stddef.h>

#include <ArduinoJson.h>

#include "agent_q_usb_operation_response_writer.h"
#include "agent_q_usb_operation_type.h"

namespace agent_q {

enum class AgentQUsbSessionIdMode {
    optional_default_empty,
    required,
};

struct AgentQUsbActiveSessionRequestGuardOps {
    bool (*material_ready)();
    bool (*write_busy_if_pending_or_local_flow_active)(
        const char* id,
        const AgentQUsbOperationResponseWriter& writer);
    bool (*write_admission_error)(
        const char* id,
        AgentQUsbOperationType operation,
        const AgentQUsbOperationResponseWriter& writer);
    bool (*require_active_matching_session)(
        const char* id,
        const char* session_id,
        const AgentQUsbOperationResponseWriter& writer);
};

bool guard_usb_active_session_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    AgentQUsbOperationType operation,
    const AgentQUsbActiveSessionRequestGuardOps& ops,
    AgentQUsbSessionIdMode session_id_mode,
    const char* const* allowed_request_fields,
    size_t allowed_request_field_count,
    const char** session_id);

}  // namespace agent_q
