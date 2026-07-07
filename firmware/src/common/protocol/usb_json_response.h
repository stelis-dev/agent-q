#pragma once

#include <ArduinoJson.h>
#include <stddef.h>
#include <stdint.h>

namespace signing {

constexpr size_t kUsbJsonResponseLineMaxBytes = 64 * 1024;
constexpr uint32_t kUsbJsonResponseWriteAttempts = 6;
constexpr uint32_t kUsbJsonResponseRetryDelayMs = 150;

struct UsbJsonResponseWriteOps {
    bool (*write_bytes)(const char* data, size_t length, void* context) = nullptr;
    void (*delay_ms)(uint32_t duration_ms, void* context) = nullptr;
    void* context = nullptr;
};

bool usb_json_response_write(JsonDocument& response, const UsbJsonResponseWriteOps& ops);
bool usb_json_response_write_line_bytes(
    const char* response,
    size_t response_len,
    const UsbJsonResponseWriteOps& ops);

}  // namespace signing
