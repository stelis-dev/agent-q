#include "usb_response_writer.h"

#include <stddef.h>
#include <stdint.h>

#include "protocol/protocol_constants.h"
#include "protocol/usb_json_response.h"

#include "driver/usb_serial_jtag.h"
#include "esp_err.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

namespace signing {
namespace {

constexpr const char* kTag = "UsbResponseWriter";
constexpr size_t kUsbSerialWriteChunkBytes = 512;
constexpr uint32_t kUsbSerialWriteChunkTimeoutMs = 100;
constexpr uint32_t kUsbSerialTxDoneTimeoutMs = 100;

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

bool write_usb_serial_response_bytes(const char* data, size_t length, void*)
{
    return write_usb_serial_bytes(data, length);
}

void delay_usb_response_ms(uint32_t duration_ms, void*)
{
    vTaskDelay(pdMS_TO_TICKS(duration_ms));
}

const UsbJsonResponseWriteOps& usb_json_response_write_ops()
{
    static const UsbJsonResponseWriteOps ops{
        write_usb_serial_response_bytes,
        delay_usb_response_ms,
        nullptr,
    };
    return ops;
}

}  // namespace

bool usb_response_write_json(JsonDocument& response)
{
    if (response.overflowed()) {
        ESP_LOGW(kTag, "USB JSON response document overflowed");
        return false;
    }
    const size_t measured = measureJson(response);
    if (measured == 0 || measured > kUsbResponseLineMaxBytes) {
        ESP_LOGW(kTag, "USB JSON response too large: bytes=%u",
                 static_cast<unsigned>(measured));
        return false;
    }
    const bool ok = usb_json_response_write(response, usb_json_response_write_ops());
    if (!ok) {
        ESP_LOGW(kTag, "USB JSON response write failed");
    }
    return ok;
}

const UsbJsonResponseWriteOps& usb_response_json_write_ops()
{
    return usb_json_response_write_ops();
}

bool usb_response_write_success_result(const char* id, const char* method, JsonObjectConst result)
{
    JsonDocument response;
    if (!device_response_prepare_success_result(response, id, method, result)) {
        return false;
    }
    return usb_response_write_json(response);
}

bool usb_response_write_transport_success_result(const char* id, JsonObjectConst result)
{
    JsonDocument response;
    if (!device_response_prepare_transport_success_result(response, id, result)) {
        return false;
    }
    return usb_response_write_json(response);
}

bool usb_response_write_method_error(
    const char* id,
    const char* method,
    const char* code)
{
    JsonDocument response;
    if (!device_response_prepare_method_error(response, id, method, code)) {
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

bool usb_response_write_empty_success_result(const char* id, const char* method)
{
    JsonDocument result;
    JsonObject object = result.to<JsonObject>();
    return usb_response_write_success_result(id, method, object);
}

bool usb_response_write_ack_result(const char* id)
{
    return usb_response_write_empty_success_result(id, "ack_result");
}

bool usb_response_write_connect_approved(
    const char* id,
    const char* session_id,
    uint32_t session_ttl_ms,
    const DeviceResponseDeviceFields& info)
{
    JsonDocument result;
    result["sessionId"] = session_id;
    result["sessionTtlMs"] = session_ttl_ms;
    device_response_write_device_fields(result["device"].to<JsonObject>(), info);
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
    return usb_response_write_empty_success_result(id, "disconnect");
}

}  // namespace signing
