#include "usb_line_receiver.h"

#include <stdint.h>

#include "protocol/request_line.h"
#include "driver/usb_serial_jtag.h"

namespace signing {
namespace {

constexpr size_t kLineBufferSize = kRequestLineMaxBytes + 1;
// Drain bounded chunks per poll. The line buffer remains the framing bound.
constexpr size_t kReadBufferSize = 512;

char g_line_buffer[kLineBufferSize];
size_t g_line_size = 0;
bool g_discarding_invalid_line = false;

void report_line_error(
    UsbRequestLineErrorHandler write_error,
    const char* code)
{
    if (write_error != nullptr) {
        write_error(code);
    }
}

}  // namespace

void usb_line_receiver_reset()
{
    g_line_size = 0;
    g_discarding_invalid_line = false;
    g_line_buffer[0] = '\0';
}

void usb_line_receiver_poll(
    UsbRequestLineHandler handle_line,
    UsbRequestLineErrorHandler write_error)
{
    uint8_t buffer[kReadBufferSize];
    const int read_count = usb_serial_jtag_read_bytes(buffer, sizeof(buffer), 0);
    if (read_count <= 0) {
        return;
    }

    for (int index = 0; index < read_count; ++index) {
        switch (request_line_feed(
            static_cast<char>(buffer[index]),
            g_line_buffer,
            sizeof(g_line_buffer),
            &g_line_size,
            &g_discarding_invalid_line)) {
            case RequestLineFeedResult::line_ready:
                if (handle_line != nullptr) {
                    handle_line(g_line_buffer);
                }
                break;
            case RequestLineFeedResult::rejected_nul:
                report_line_error(
                    write_error,
                    "invalid_request");
                break;
            case RequestLineFeedResult::rejected_too_long:
                report_line_error(
                    write_error,
                    "invalid_request");
                break;
            case RequestLineFeedResult::none:
                break;
        }
    }
}

}  // namespace signing
