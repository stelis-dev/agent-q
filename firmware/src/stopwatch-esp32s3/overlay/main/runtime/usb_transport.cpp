#include "usb_transport.h"

#include <ArduinoJson.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "freertos/FreeRTOS.h"
#include "protocol/device_contract.h"
#include "protocol/device_response.h"
#include "protocol/json_input.h"
#include "protocol/protocol_constants.h"
#include "protocol/request_id.h"
#include "protocol/request_line.h"

namespace stopwatch_target {
namespace {

constexpr const char* kTag = "StopWatchUSB";
constexpr size_t kLineBufferBytes = signing::kRequestLineMaxBytes + 1;
constexpr size_t kReadChunkBytes = 512;
constexpr size_t kWriteChunkBytes = 512;
constexpr uint32_t kWriteTimeoutMs = 100;
constexpr const char* kFirmwareName = "Agent-Q Firmware";
constexpr const char* kHardwareId = "stopwatch-esp32s3";
constexpr const char* kFirmwareVersion = "0.0.0";
constexpr const char* kFallbackDeviceId = "stopwatch-esp32s3-unavailable";

char g_line_buffer[kLineBufferBytes];
size_t g_line_size = 0;
bool g_discarding_line = false;
UsbStatus g_status = {};
char g_device_id[40] = {};
UsbRuntimeState g_runtime_state{LocalAuthProjectionStatus::missing, false, false};

void copy_status_text(char* output, size_t output_size, const char* value)
{
    if (output == nullptr || output_size == 0) {
        return;
    }
    output[0] = '\0';
    if (value == nullptr) {
        return;
    }
    strlcpy(output, value, output_size);
}

void format_device_id()
{
    if (g_device_id[0] != '\0') {
        return;
    }

    uint8_t mac[6] = {};
    const esp_err_t result = esp_efuse_mac_get_default(mac);
    if (result != ESP_OK) {
        ESP_LOGW(kTag, "Device id MAC read failed: %s", esp_err_to_name(result));
        strlcpy(g_device_id, kFallbackDeviceId, sizeof(g_device_id));
        return;
    }
    snprintf(
        g_device_id,
        sizeof(g_device_id),
        "%s-%02x%02x%02x%02x%02x%02x",
        kHardwareId,
        static_cast<unsigned>(mac[0]),
        static_cast<unsigned>(mac[1]),
        static_cast<unsigned>(mac[2]),
        static_cast<unsigned>(mac[3]),
        static_cast<unsigned>(mac[4]),
        static_cast<unsigned>(mac[5]));
}

const char* device_state()
{
    return stopwatch_device_state(StateProjectionInput{
        g_runtime_state.auth_status,
        g_runtime_state.locally_unlocked,
        g_runtime_state.ui_busy,
    });
}

const char* provisioning_state()
{
    return stopwatch_provisioning_state(g_runtime_state.auth_status);
}

bool write_usb_bytes(const char* data, size_t length)
{
    if (data == nullptr || length == 0) {
        return false;
    }
    size_t offset = 0;
    while (offset < length) {
        const size_t remaining = length - offset;
        const size_t chunk = remaining > kWriteChunkBytes ? kWriteChunkBytes : remaining;
        const int written = usb_serial_jtag_write_bytes(
            data + offset,
            chunk,
            pdMS_TO_TICKS(kWriteTimeoutMs));
        if (written <= 0 || static_cast<size_t>(written) > chunk) {
            ESP_LOGW(kTag, "USB write failed: requested=%u written=%d",
                     static_cast<unsigned>(chunk),
                     written);
            return false;
        }
        offset += static_cast<size_t>(written);
    }
    return usb_serial_jtag_wait_tx_done(pdMS_TO_TICKS(kWriteTimeoutMs)) == ESP_OK;
}

bool write_json_response(JsonDocument& response, size_t output_size)
{
    char output[1024];
    if (output_size > sizeof(output)) {
        return false;
    }
    const size_t length = serializeJson(response, output, output_size);
    if (length == 0 || length >= output_size) {
        copy_status_text(g_status.last_error, sizeof(g_status.last_error), "internal_output_error");
        return false;
    }
    return write_usb_bytes("\n", 1) &&
           write_usb_bytes(output, length) &&
           write_usb_bytes("\n", 1);
}

bool write_error_response(const char* id, const char* method, const char* code)
{
    JsonDocument response;
    if (!signing::device_response_prepare_method_error(response, id, method, code)) {
        return false;
    }
    return write_json_response(response, 768);
}

bool write_status_response(const char* id)
{
    format_device_id();

    const signing::DeviceResponseDeviceFields info{
        g_device_id,
        device_state(),
        kFirmwareName,
        kHardwareId,
        kFirmwareVersion,
    };
    JsonDocument result;
    signing::device_response_write_device_fields(result["device"].to<JsonObject>(), info);
    result["provisioning"]["state"] = provisioning_state();

    JsonDocument response;
    if (!signing::device_response_prepare_success_result(
            response,
            id,
            "get_status",
            result.as<JsonObjectConst>())) {
        return false;
    }
    return write_json_response(response, 1024);
}

void record_success(const char* id, const char* method)
{
    copy_status_text(g_status.last_id, sizeof(g_status.last_id), id);
    copy_status_text(g_status.last_method, sizeof(g_status.last_method), method);
    copy_status_text(g_status.last_error, sizeof(g_status.last_error), "none");
}

void record_error(const char* id, const char* method, const char* code)
{
    copy_status_text(g_status.last_id, sizeof(g_status.last_id), id);
    copy_status_text(g_status.last_method, sizeof(g_status.last_method), method);
    copy_status_text(g_status.last_error, sizeof(g_status.last_error), code);
}

bool reject_line(const char* id, const char* method, const char* code)
{
    record_error(id, method, code);
    if (method != nullptr && strcmp(method, "connect") == 0) {
        ++g_status.rejected_connects;
    }
    if (!write_error_response(id, method, code)) {
        record_error(id, method, "internal_output_error");
        return false;
    }
    return true;
}

void handle_request_line(const char* line)
{
    ++g_status.received_lines;

    JsonDocument request;
    if (!signing::json_line_is_single_object(line)) {
        ++g_status.invalid_lines;
        reject_line(nullptr, nullptr, "invalid_request");
        return;
    }

    const DeserializationError parse_error =
        deserializeJson(request, line, DeserializationOption::NestingLimit(signing::kRequestJsonNestingLimit));
    if (parse_error) {
        ++g_status.invalid_lines;
        reject_line(nullptr, nullptr, "invalid_request");
        return;
    }

    const char* id = nullptr;
    const char* method_text = nullptr;
    const bool has_id = signing::json_value_c_string(request["id"], &id);
    if (!has_id || !signing::request_id_format_valid(id)) {
        ++g_status.invalid_lines;
        reject_line(nullptr, nullptr, "invalid_request");
        return;
    }

    const bool has_method_text = signing::json_value_c_string(request["method"], &method_text);
    const char* method = has_method_text && signing::device_method_row(method_text) != nullptr ? method_text : nullptr;
    if (!has_method_text || !request["version"].is<int>()) {
        ++g_status.invalid_lines;
        reject_line(id, method, "invalid_request");
        return;
    }

    if (request["version"].as<int>() != signing::kProtocolVersion) {
        reject_line(id, method, "unsupported_version");
        return;
    }

    if (method == nullptr) {
        reject_line(id, nullptr, "unsupported_method");
        return;
    }

    if (strcmp(method, "get_status") == 0) {
        const char* const allowed_status_fields[] = {"id", "version", "method"};
        if (!signing::json_object_fields_supported(request.as<JsonObjectConst>(), allowed_status_fields, 3)) {
            reject_line(id, method, "invalid_params");
            return;
        }
        if (write_status_response(id)) {
            ++g_status.status_responses;
            record_success(id, method);
        } else {
            record_error(id, method, "internal_output_error");
        }
        return;
    }

    reject_line(id, method, "invalid_state");
}

void feed_byte(char value)
{
    switch (signing::request_line_feed(
        value,
        g_line_buffer,
        sizeof(g_line_buffer),
        &g_line_size,
        &g_discarding_line)) {
        case signing::RequestLineFeedResult::line_ready:
            handle_request_line(g_line_buffer);
            break;
        case signing::RequestLineFeedResult::rejected_nul:
        case signing::RequestLineFeedResult::rejected_too_long:
            ++g_status.invalid_lines;
            reject_line(nullptr, nullptr, "invalid_request");
            break;
        case signing::RequestLineFeedResult::none:
            break;
    }
}

}  // namespace

bool usb_transport_init()
{
    format_device_id();
    if (!usb_serial_jtag_is_driver_installed()) {
        usb_serial_jtag_driver_config_t config = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
        config.tx_buffer_size = 1024;
        config.rx_buffer_size = signing::kRequestLineMaxBytes + kReadChunkBytes;
        const esp_err_t result = usb_serial_jtag_driver_install(&config);
        if (result != ESP_OK) {
            ESP_LOGE(kTag, "USB serial driver install failed: %s", esp_err_to_name(result));
            g_status.ready = false;
            return false;
        }
    }
    usb_serial_jtag_vfs_use_driver();
    g_status.ready = true;
    return true;
}

void usb_transport_poll()
{
    if (!g_status.ready) {
        return;
    }
    g_status.connected = usb_serial_jtag_is_connected();
    if (!g_status.connected) {
        return;
    }

    uint8_t buffer[kReadChunkBytes];
    const int read_count = usb_serial_jtag_read_bytes(buffer, sizeof(buffer), 0);
    if (read_count <= 0) {
        return;
    }
    for (int i = 0; i < read_count; ++i) {
        feed_byte(static_cast<char>(buffer[i]));
    }
}

UsbStatus usb_transport_status()
{
    g_status.connected = g_status.ready && usb_serial_jtag_is_connected();
    return g_status;
}

void usb_transport_set_runtime_state(UsbRuntimeState state)
{
    g_runtime_state = state;
}

}  // namespace stopwatch_target
