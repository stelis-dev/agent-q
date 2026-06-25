#include "agent_q_usb_response_writer.h"

#include <stddef.h>
#include <stdint.h>

#include "agent_q_device_contract.h"
#include "agent_q_protocol_constants.h"

#include "driver/usb_serial_jtag.h"
#include "esp_err.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

namespace agent_q {
namespace {

constexpr const char* kTag = "UsbResponseWriter";
constexpr size_t kUsbSerialWriteChunkBytes = 512;
constexpr uint32_t kUsbSerialWriteChunkTimeoutMs = 100;
constexpr uint32_t kUsbSerialTxDoneTimeoutMs = 100;
// Right after the device wakes from idle, the host USB link may be mid-resume
// (selective-suspend) and not yet draining, so the first response write times out
// and the response is dropped while a subsequent log line still gets through.
// Retry the whole response a few times to survive that resume window.
constexpr uint32_t kUsbResponseWriteAttempts = 6;
constexpr uint32_t kUsbResponseWriteRetryDelayMs = 150;

bool write_usb_serial_bytes(const char* data, size_t length)
{
    if (data == nullptr || length == 0) {
        return false;
    }

    size_t offset = 0;
    while (offset < length) {
        const size_t remaining = length - offset;
        const size_t chunk =
            remaining > kUsbSerialWriteChunkBytes ? kUsbSerialWriteChunkBytes : remaining;
        const int written = usb_serial_jtag_write_bytes(
            data + offset,
            chunk,
            pdMS_TO_TICKS(kUsbSerialWriteChunkTimeoutMs));
        if (written <= 0 || static_cast<size_t>(written) > chunk) {
            ESP_LOGW(kTag, "USB JSON write failed: requested=%u written=%d",
                     static_cast<unsigned>(chunk),
                     written);
            return false;
        }
        offset += static_cast<size_t>(written);
        if (usb_serial_jtag_wait_tx_done(pdMS_TO_TICKS(kUsbSerialTxDoneTimeoutMs)) != ESP_OK) {
            ESP_LOGW(kTag, "USB JSON write flush timed out");
            return false;
        }
    }
    return true;
}

class UsbSerialJsonWriter {
public:
    size_t write(uint8_t value)
    {
        return write(&value, 1);
    }

    size_t write(const uint8_t* data, size_t length)
    {
        if (failed_ || data == nullptr || length == 0) {
            return 0;
        }
        if (!write_usb_serial_bytes(reinterpret_cast<const char*>(data), length)) {
            failed_ = true;
            return 0;
        }
        return length;
    }

    bool failed() const
    {
        return failed_;
    }

private:
    bool failed_ = false;
};

}  // namespace

void usb_response_write_device_fields(
    JsonObject device,
    const AgentQUsbDeviceResponseInfo& info)
{
    device["deviceId"] = info.device_id;
    device["state"] = info.device_state;
    device["firmwareName"] = info.firmware_name;
    device["hardware"] = info.hardware;
    device["firmwareVersion"] = info.firmware_version;
}

bool usb_response_write_json(JsonDocument& response)
{
    if (response.overflowed()) {
        ESP_LOGW(kTag, "USB JSON response document overflowed");
        return false;
    }
    const size_t measured = measureJson(response);
    if (measured == 0 || measured > kAgentQUsbResponseLineMaxBytes) {
        ESP_LOGW(kTag, "USB JSON response too large: bytes=%u",
                 static_cast<unsigned>(measured));
        return false;
    }
    for (uint32_t attempt = 0; attempt < kUsbResponseWriteAttempts; ++attempt) {
        if (attempt > 0) {
            vTaskDelay(pdMS_TO_TICKS(kUsbResponseWriteRetryDelayMs));
        }
        // A leading newline isolates any partial bytes left by a failed earlier
        // attempt: the host parser sees those as an incomplete non-JSON line and
        // discards them, then parses the freshly re-serialized response line.
        if (!write_usb_serial_bytes("\n", 1)) {
            continue;
        }
        UsbSerialJsonWriter writer;
        const size_t len = serializeJson(response, writer);
        if (writer.failed() || len != measured) {
            continue;
        }
        if (!write_usb_serial_bytes("\n", 1)) {
            continue;
        }
        if (attempt > 0) {
            ESP_LOGW(kTag, "USB JSON response delivered on attempt %u",
                     static_cast<unsigned>(attempt + 1));
        }
        return true;
    }
    ESP_LOGW(kTag, "USB JSON response write failed after %u attempts",
             static_cast<unsigned>(kUsbResponseWriteAttempts));
    return false;
}

bool usb_response_prepare_success_result(
    JsonDocument& response,
    const char* id,
    const char* method,
    JsonObjectConst result)
{
    if (method == nullptr || method[0] == '\0' || result.isNull()) {
        return false;
    }
    response.clear();
    response["id"] = id;
    response["version"] = kAgentQProtocolVersion;
    response["success"] = true;
    response["method"] = method;
    response["result"].set(result);
    return true;
}

bool usb_response_write_success_result(const char* id, const char* method, JsonObjectConst result)
{
    JsonDocument response;
    if (!usb_response_prepare_success_result(response, id, method, result)) {
        return false;
    }
    return usb_response_write_json(response);
}

bool usb_response_prepare_method_error(
    JsonDocument& response,
    const char* id,
    const char* method,
    const char* code)
{
    const AgentQDeviceErrorRow* error = device_error_row(code);
    if (error == nullptr) {
        error = device_error_row("unknown_error");
    }
    if (error == nullptr) {
        return false;
    }
    response.clear();
    if (id != nullptr && id[0] != '\0') {
        response["id"] = id;
    }
    response["version"] = kAgentQProtocolVersion;
    response["success"] = false;
    if (method != nullptr && method[0] != '\0') {
        response["method"] = method;
    }
    response["error"]["code"] = error->code;
    response["error"]["message"] = error->message;
    response["error"]["retryable"] = error->retryable;
    return true;
}

bool usb_response_write_method_error(
    const char* id,
    const char* method,
    const char* code)
{
    JsonDocument response;
    if (!usb_response_prepare_method_error(response, id, method, code)) {
        return false;
    }
    return usb_response_write_json(response);
}

bool usb_response_write_error(const char* id, const char* code)
{
    return usb_response_write_method_error(id, nullptr, code);
}

void usb_response_log_write_failure(const char* response_type, const char* id)
{
    ESP_LOGW(kTag,
             "USB response write failed: type=%s id=%s",
             response_type != nullptr ? response_type : "",
             id != nullptr ? id : "");
}

bool usb_response_write_ack_result(const char* id)
{
    JsonDocument result;
    return usb_response_write_success_result(id, "ack_result", result.as<JsonObjectConst>());
}

bool usb_response_write_connect_approved(
    const char* id,
    const char* session_id,
    uint32_t session_ttl_ms,
    const AgentQUsbDeviceResponseInfo& info)
{
    JsonDocument result;
    result["sessionId"] = session_id;
    result["sessionTtlMs"] = session_ttl_ms;
    usb_response_write_device_fields(result["device"].to<JsonObject>(), info);
    return usb_response_write_success_result(id, "connect", result.as<JsonObjectConst>());
}

bool usb_response_write_connect_rejected(
    const char* id,
    const char* error_code)
{
    return usb_response_write_error(id, error_code);
}

bool usb_response_write_disconnect_success(const char* id)
{
    JsonDocument result;
    return usb_response_write_success_result(id, "disconnect", result.as<JsonObjectConst>());
}

}  // namespace agent_q
