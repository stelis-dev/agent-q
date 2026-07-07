#pragma once

#include <stddef.h>
#include <stdint.h>

#include <ArduinoJson.h>

#include "protocol/approval_history.h"
#include "usb_operation_type.h"
#include "protocol/usb_operation_response_writer.h"

namespace signing {

struct UsbApprovalHistoryHandlerOps {
    bool (*material_ready)();
    bool (*write_busy_if_pending_or_local_flow_active)(
        const char* id,
        const UsbOperationResponseWriter& writer);
    bool (*write_payload_delivery_safe_read_admission_error)(
        const char* id,
        UsbOperationType operation,
        const UsbOperationResponseWriter& writer);
    bool (*require_active_matching_session)(
        const char* id,
        const char* session_id,
        const UsbOperationResponseWriter& writer);
    ApprovalHistoryReadResult (*read_approval_history_page)(
        uint64_t before_sequence,
        size_t limit,
        ApprovalHistoryPage* output);
};

void handle_usb_get_approval_history_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbApprovalHistoryHandlerOps& ops);

}  // namespace signing
