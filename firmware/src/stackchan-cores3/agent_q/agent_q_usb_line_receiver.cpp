#include "agent_q_usb_line_receiver.h"

#include <stdint.h>

#include "agent_q_usb_request_line.h"
#include "driver/usb_serial_jtag.h"

namespace agent_q {
namespace {

constexpr size_t kLineBufferSize = kAgentQUsbRequestLineMaxBytes + 1;
// Drain enough bytes per poll that a host-written 4096-byte JSONL frame does not
// depend on host-side pacing. The line buffer remains the framing bound.
constexpr size_t kReadBufferSize = 512;

char g_line_buffer[kLineBufferSize];
size_t g_line_size = 0;
bool g_discarding_invalid_line = false;

void report_line_error(
    AgentQUsbRequestLineErrorHandler write_error,
    const char* code,
    const char* message)
{
    if (write_error != nullptr) {
        write_error(code, message);
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
    AgentQUsbRequestLineHandler handle_line,
    AgentQUsbRequestLineErrorHandler write_error)
{
    uint8_t buffer[kReadBufferSize];
    const int read_count = usb_serial_jtag_read_bytes(buffer, sizeof(buffer), 0);
    if (read_count <= 0) {
        return;
    }

    for (int index = 0; index < read_count; ++index) {
        switch (usb_request_line_feed(
            static_cast<char>(buffer[index]),
            g_line_buffer,
            sizeof(g_line_buffer),
            &g_line_size,
            &g_discarding_invalid_line)) {
            case AgentQUsbLineFeedResult::line_ready:
                if (handle_line != nullptr) {
                    handle_line(g_line_buffer);
                }
                break;
            case AgentQUsbLineFeedResult::rejected_nul:
                report_line_error(
                    write_error,
                    "invalid_json",
                    "JSON line contains a NUL byte.");
                break;
            case AgentQUsbLineFeedResult::rejected_too_long:
                report_line_error(
                    write_error,
                    "invalid_json",
                    "JSON line is too long.");
                break;
            case AgentQUsbLineFeedResult::none:
                break;
        }
    }
}

}  // namespace agent_q
