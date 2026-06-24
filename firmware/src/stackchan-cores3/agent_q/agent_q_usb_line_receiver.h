#pragma once

#include <stddef.h>

namespace agent_q {

constexpr size_t kAgentQUsbRequestLineMaxBytes = 16 * 1024;

using AgentQUsbRequestLineHandler = void (*)(const char* line);
using AgentQUsbRequestLineErrorHandler = void (*)(const char* code);

void usb_line_receiver_reset();
void usb_line_receiver_poll(
    AgentQUsbRequestLineHandler handle_line,
    AgentQUsbRequestLineErrorHandler write_error);

}  // namespace agent_q
