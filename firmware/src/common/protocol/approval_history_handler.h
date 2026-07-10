#pragma once

#include <stddef.h>
#include <stdint.h>

#include <ArduinoJson.h>

#include "protocol/approval_history.h"
#include "protocol/operation_type.h"
#include "protocol/response_writer.h"

namespace signing {

struct ApprovalHistoryHandlerOps {
    bool (*material_ready)();
    bool (*write_busy_if_pending_or_local_flow_active)(
        const char* id,
        const ResponseWriter& writer);
    bool (*write_payload_delivery_safe_read_admission_error)(
        const char* id,
        OperationType operation,
        const ResponseWriter& writer);
    bool (*require_active_matching_session)(
        const char* id,
        const char* session_id,
        const ResponseWriter& writer);
    ApprovalHistoryReadResult (*read_approval_history_page)(
        uint64_t before_sequence,
        size_t limit,
        ApprovalHistoryPage* output);
};

void handle_protocol_get_approval_history_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const ApprovalHistoryHandlerOps& ops);

}  // namespace signing
