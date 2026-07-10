#pragma once

#include <ArduinoJson.h>
#include <stddef.h>
#include <stdint.h>

namespace signing {

constexpr size_t kJsonResponseLineMaxBytes = 64 * 1024;
constexpr uint32_t kJsonResponseWriteAttempts = 6;
constexpr uint32_t kJsonResponseRetryDelayMs = 150;

struct JsonResponseWriteOps {
    bool (*write_bytes)(const char* data, size_t length, void* context) = nullptr;
    void (*delay_ms)(uint32_t duration_ms, void* context) = nullptr;
    void* context = nullptr;
};

bool json_response_write(JsonDocument& response, const JsonResponseWriteOps& ops);
bool json_response_write_line_bytes(
    const char* response,
    size_t response_len,
    const JsonResponseWriteOps& ops);

}  // namespace signing
