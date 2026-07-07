#include "protocol/usb_json_response.h"

#include <stdlib.h>
#include <string.h>

namespace signing {
namespace {

bool write_with_retries(const char* response, size_t response_len, const UsbJsonResponseWriteOps& ops)
{
    if (ops.write_bytes == nullptr ||
        response == nullptr ||
        response_len == 0 ||
        response_len > kUsbJsonResponseLineMaxBytes) {
        return false;
    }
    for (uint32_t attempt = 0; attempt < kUsbJsonResponseWriteAttempts; ++attempt) {
        if (attempt > 0 && ops.delay_ms != nullptr) {
            ops.delay_ms(kUsbJsonResponseRetryDelayMs, ops.context);
        }
        if (ops.write_bytes("\n", 1, ops.context) &&
            ops.write_bytes(response, response_len, ops.context) &&
            ops.write_bytes("\n", 1, ops.context)) {
            return true;
        }
    }
    return false;
}

}  // namespace

bool usb_json_response_write_line_bytes(
    const char* response,
    size_t response_len,
    const UsbJsonResponseWriteOps& ops)
{
    return write_with_retries(response, response_len, ops);
}

bool usb_json_response_write(JsonDocument& response, const UsbJsonResponseWriteOps& ops)
{
    if (response.overflowed()) {
        return false;
    }
    const size_t measured = measureJson(response);
    if (measured == 0 || measured > kUsbJsonResponseLineMaxBytes) {
        return false;
    }
    char* serialized = static_cast<char*>(malloc(measured + 1));
    if (serialized == nullptr) {
        return false;
    }
    const size_t written = serializeJson(response, serialized, measured + 1);
    const bool ok = written == measured && write_with_retries(serialized, written, ops);
    memset(serialized, 0, measured + 1);
    free(serialized);
    return ok;
}

}  // namespace signing
