#include "agent_q_usb_request_line.h"

namespace agent_q {

AgentQUsbLineFeedResult usb_request_line_feed(
    char c,
    char* buffer,
    size_t capacity,
    size_t* size,
    bool* discarding)
{
    if (buffer == nullptr || size == nullptr || discarding == nullptr || capacity == 0) {
        return AgentQUsbLineFeedResult::none;
    }
    if (c == '\r') {
        return AgentQUsbLineFeedResult::none;
    }
    if (c == '\n') {
        if (*discarding) {
            *discarding = false;
            *size = 0;
            return AgentQUsbLineFeedResult::none;
        }
        buffer[*size] = '\0';
        const bool has_line = *size > 0;
        *size = 0;
        return has_line ? AgentQUsbLineFeedResult::line_ready : AgentQUsbLineFeedResult::none;
    }
    if (*discarding) {
        return AgentQUsbLineFeedResult::none;
    }
    if (c == '\0') {
        *size = 0;
        *discarding = true;
        return AgentQUsbLineFeedResult::rejected_nul;
    }
    if (*size + 1 >= capacity) {
        *size = 0;
        *discarding = true;
        return AgentQUsbLineFeedResult::rejected_too_long;
    }
    buffer[(*size)++] = c;
    return AgentQUsbLineFeedResult::none;
}

}  // namespace agent_q
