#include "agent_q_usb_response_writer.h"

#include <stddef.h>
#include <stdint.h>

#include "driver/usb_serial_jtag.h"
#include "esp_err.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"

namespace agent_q {
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
    UsbSerialJsonWriter writer;
    const size_t len = serializeJson(response, writer);
    if (writer.failed() || len != measured) {
        ESP_LOGW(kTag, "USB JSON response serialization mismatch: measured=%u serialized=%u",
                 static_cast<unsigned>(measured),
                 static_cast<unsigned>(len));
        return false;
    }
    return write_usb_serial_bytes("\n", 1);
}

}  // namespace agent_q
