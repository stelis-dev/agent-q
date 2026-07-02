#pragma once

#include <ArduinoJson.h>

namespace signing {

struct DeviceResponseDeviceFields {
    const char* device_id;
    const char* device_state;
    const char* firmware_name;
    const char* hardware;
    const char* firmware_version;
};

void device_response_write_device_fields(JsonObject device, const DeviceResponseDeviceFields& info);
bool device_response_prepare_success_result(
    JsonDocument& response,
    const char* id,
    const char* method,
    JsonObjectConst result);
bool device_response_prepare_method_error(
    JsonDocument& response,
    const char* id,
    const char* method,
    const char* code);

}  // namespace signing
