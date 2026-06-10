#pragma once

#include <stddef.h>
#include <stdint.h>

#include <ArduinoJson.h>

#include "agent_q_approval_history.h"
#include "agent_q_usb_operation_response_writer.h"

namespace agent_q {

struct AgentQUsbApprovalHistoryHandlerOps {
    bool (*material_ready)();
    bool (*write_busy_if_pending_or_local_flow_active)(const char* id);
    bool (*require_active_matching_session)(const char* id, const char* session_id);
    AgentQApprovalHistoryReadResult (*read_approval_history_page)(
        uint64_t before_sequence,
        size_t limit,
        AgentQApprovalHistoryPage* output);
};

void handle_usb_get_approval_history_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbApprovalHistoryHandlerOps& ops);

}  // namespace agent_q
