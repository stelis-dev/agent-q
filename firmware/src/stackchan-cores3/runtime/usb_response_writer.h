#pragma once

#include <ArduinoJson.h>
#include <stddef.h>
#include <stdint.h>

#include "protocol/device_response.h"

namespace signing {

constexpr size_t kUsbResponseLineMaxBytes = 64 * 1024;

bool usb_response_write_json(JsonDocument& response);
bool usb_response_write_success_result(const char* id, const char* method, JsonObjectConst result);
bool usb_response_write_error(const char* id, const char* code);
bool usb_response_write_method_error(
    const char* id,
    const char* method,
    const char* code);
void usb_response_log_write_failure(const char* response_type, const char* id);
bool usb_response_write_ack_result(const char* id);
bool usb_response_write_connect_approved(
    const char* id,
    const char* session_id,
    uint32_t session_ttl_ms,
    const DeviceResponseDeviceFields& info);
bool usb_response_write_connect_rejected(
    const char* id,
    const char* error_code);
bool usb_response_write_disconnect_success(const char* id);

}  // namespace signing
