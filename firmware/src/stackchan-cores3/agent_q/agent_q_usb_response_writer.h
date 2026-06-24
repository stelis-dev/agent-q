#pragma once

#include <ArduinoJson.h>
#include <stddef.h>
#include <stdint.h>

namespace agent_q {

constexpr size_t kAgentQUsbResponseLineMaxBytes = 64 * 1024;

struct AgentQUsbDeviceResponseInfo {
    const char* device_id;
    const char* device_state;
    const char* firmware_name;
    const char* hardware;
    const char* firmware_version;
    const char* provisioning_state;
};

void usb_response_write_device_fields(
    JsonObject device,
    const AgentQUsbDeviceResponseInfo& info);
bool usb_response_write_json(JsonDocument& response);
bool usb_response_prepare_success_result(
    JsonDocument& response,
    const char* id,
    const char* method,
    JsonObjectConst result);
bool usb_response_write_success_result(const char* id, const char* method, JsonObjectConst result);
bool usb_response_write_error(const char* id, const char* code);
bool usb_response_prepare_method_error(
    JsonDocument& response,
    const char* id,
    const char* method,
    const char* code);
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
    const AgentQUsbDeviceResponseInfo& info);
bool usb_response_write_connect_rejected(
    const char* id,
    const char* error_code);
bool usb_response_write_disconnect_result(const char* id);

}  // namespace agent_q
