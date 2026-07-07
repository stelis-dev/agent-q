#pragma once

#include <stdint.h>

#include <ArduinoJson.h>

#include "protocol/device_response.h"
#include "protocol/usb_operation_type.h"
#include "protocol/usb_operation_response_writer.h"
#include "usb_response_writer.h"

namespace signing {

struct UsbDeviceStatusInfo {
    DeviceResponseDeviceFields device;
    const char* provisioning_state;
};

struct UsbGetStatusHandlerOps {
    bool (*refresh_persistent_material_consistency)();
    bool (*write_payload_delivery_safe_read_admission_error)(
        const char* id,
        UsbOperationType operation,
        const UsbOperationResponseWriter& writer);
    UsbDeviceStatusInfo (*device_status_info)();
};

struct UsbIdentifyDeviceHandlerOps {
    bool (*write_identify_device_admission_error)(
        const char* id,
        const UsbOperationResponseWriter& writer);
    bool (*is_safe_identification_code)(const char* value);
    void (*show_identification_code)(const char* code, uint32_t duration_ms);
    UsbDeviceStatusInfo (*device_status_info)();
    uint32_t identify_display_ms = 0;
};

void handle_usb_get_status_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbGetStatusHandlerOps& ops);

void handle_usb_identify_device_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbIdentifyDeviceHandlerOps& ops);

}  // namespace signing
