#include "request_line.h"

namespace signing {

RequestLineFeedResult request_line_feed(
    char c,
    char* buffer,
    size_t capacity,
    size_t* size,
    bool* discarding)
{
    if (buffer == nullptr || size == nullptr || discarding == nullptr || capacity == 0) {
        return RequestLineFeedResult::none;
    }
    if (c == '\r') {
        return RequestLineFeedResult::none;
    }
    if (c == '\n') {
        if (*discarding) {
            *discarding = false;
            *size = 0;
            return RequestLineFeedResult::none;
        }
        buffer[*size] = '\0';
        const bool has_line = *size > 0;
        *size = 0;
        return has_line ? RequestLineFeedResult::line_ready : RequestLineFeedResult::none;
    }
    if (*discarding) {
        return RequestLineFeedResult::none;
    }
    if (c == '\0') {
        *size = 0;
        *discarding = true;
        return RequestLineFeedResult::rejected_nul;
    }
    if (*size + 1 >= capacity) {
        *size = 0;
        *discarding = true;
        return RequestLineFeedResult::rejected_too_long;
    }
    buffer[(*size)++] = c;
    return RequestLineFeedResult::none;
}

}  // namespace signing
