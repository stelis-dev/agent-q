#include "usb_request_line.h"

namespace signing {

UsbLineFeedResult usb_request_line_feed(
    char c,
    char* buffer,
    size_t capacity,
    size_t* size,
    bool* discarding)
{
    if (buffer == nullptr || size == nullptr || discarding == nullptr || capacity == 0) {
        return UsbLineFeedResult::none;
    }
    if (c == '\r') {
        return UsbLineFeedResult::none;
    }
    if (c == '\n') {
        if (*discarding) {
            *discarding = false;
            *size = 0;
            return UsbLineFeedResult::none;
        }
        buffer[*size] = '\0';
        const bool has_line = *size > 0;
        *size = 0;
        return has_line ? UsbLineFeedResult::line_ready : UsbLineFeedResult::none;
    }
    if (*discarding) {
        return UsbLineFeedResult::none;
    }
    if (c == '\0') {
        *size = 0;
        *discarding = true;
        return UsbLineFeedResult::rejected_nul;
    }
    if (*size + 1 >= capacity) {
        *size = 0;
        *discarding = true;
        return UsbLineFeedResult::rejected_too_long;
    }
    buffer[(*size)++] = c;
    return UsbLineFeedResult::none;
}

}  // namespace signing
