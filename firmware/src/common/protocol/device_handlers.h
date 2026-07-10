#pragma once

#include <stdint.h>

#include <ArduinoJson.h>

#include "protocol/device_response.h"
#include "protocol/operation_type.h"
#include "protocol/response_writer.h"

namespace signing {

struct DeviceStatusInfo {
    DeviceResponseDeviceFields device;
    const char* provisioning_state;
};

struct GetStatusHandlerOps {
    bool (*refresh_persistent_material_consistency)();
    bool (*write_payload_delivery_safe_read_admission_error)(
        const char* id,
        OperationType operation,
        const ResponseWriter& writer);
    DeviceStatusInfo (*device_status_info)();
};

struct IdentifyDeviceHandlerOps {
    bool (*write_identify_device_admission_error)(
        const char* id,
        const ResponseWriter& writer);
    bool (*is_safe_identification_code)(const char* value);
    void (*show_identification_code)(const char* code, uint32_t duration_ms);
    DeviceStatusInfo (*device_status_info)();
    uint32_t identify_display_ms = 0;
};

void handle_protocol_get_status_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const GetStatusHandlerOps& ops);

void handle_protocol_identify_device_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const IdentifyDeviceHandlerOps& ops);

}  // namespace signing
