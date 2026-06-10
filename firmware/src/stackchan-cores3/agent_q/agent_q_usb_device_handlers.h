#pragma once

#include <stdint.h>

#include <ArduinoJson.h>

#include "agent_q_usb_operation_response_writer.h"
#include "agent_q_usb_response_writer.h"

namespace agent_q {

struct AgentQUsbGetStatusHandlerOps {
    bool (*refresh_persistent_material_consistency)();
    AgentQUsbDeviceResponseInfo (*device_response_info)();
};

struct AgentQUsbIdentifyDeviceHandlerOps {
    bool (*write_busy_if_pending_or_local_flow_active)(const char* id);
    bool (*is_safe_identification_code)(const char* value);
    void (*show_identification_code)(const char* code, uint32_t duration_ms);
    AgentQUsbDeviceResponseInfo (*device_response_info)();
    uint32_t identify_display_ms = 0;
};

void handle_usb_get_status_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbGetStatusHandlerOps& ops);

void handle_usb_identify_device_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbIdentifyDeviceHandlerOps& ops);

}  // namespace agent_q
