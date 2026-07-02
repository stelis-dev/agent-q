#include "request_id.h"

namespace signing {

bool request_id_format_valid(const char* value)
{
    if (value == nullptr || value[0] == '\0') {
        return false;
    }

    size_t length = 0;
    for (const char* cursor = value; *cursor != '\0'; ++cursor) {
        if (++length >= kRequestIdSize) {
            return false;
        }
        const char c = *cursor;
        const bool ok = (c >= 'a' && c <= 'z') ||
                        (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') ||
                        c == '_' ||
                        c == '-' ||
                        c == '.';
        if (!ok) {
            return false;
        }
    }
    return true;
}

}  // namespace signing
