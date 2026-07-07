#pragma once

#include <stddef.h>

#include <ArduinoJson.h>

#include "protocol/usb_operation_response_writer.h"
#include "protocol/usb_operation_type.h"

namespace signing {

enum class UsbSessionIdMode {
    optional_default_empty,
    required,
};

struct UsbActiveSessionRequestGuardOps {
    bool (*material_ready)();
    bool (*write_busy_if_pending_or_local_flow_active)(
        const char* id,
        const UsbOperationResponseWriter& writer);
    bool (*write_admission_error)(
        const char* id,
        UsbOperationType operation,
        const UsbOperationResponseWriter& writer);
    bool (*require_active_matching_session)(
        const char* id,
        const char* session_id,
        const UsbOperationResponseWriter& writer);
};

bool guard_usb_active_session_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    UsbOperationType operation,
    const UsbActiveSessionRequestGuardOps& ops,
    UsbSessionIdMode session_id_mode,
    const char* const* allowed_request_fields,
    size_t allowed_request_field_count,
    const char** session_id);

}  // namespace signing
