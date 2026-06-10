#pragma once

#include "agent_q_usb_operation_dispatch.h"
#include "agent_q_usb_operation_response_writer.h"

namespace agent_q {

void handle_usb_request_line(
    const char* line,
    const AgentQUsbOperationResponseWriter& response_writer,
    const AgentQUsbOperationHandlers& handlers);

}  // namespace agent_q
