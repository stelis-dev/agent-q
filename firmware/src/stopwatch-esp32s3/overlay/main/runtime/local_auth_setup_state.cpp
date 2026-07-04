#include "local_auth_setup_state.h"

#include <string.h>

namespace stopwatch_target {

LocalAuthSetupState::~LocalAuthSetupState()
{
    clear();
}

bool LocalAuthSetupState::set_first_entry(const char* code, size_t length)
{
    clear();
    if (!local_auth_code_shape_valid(code, length)) {
        return false;
    }
    memcpy(code_, code, length + 1);
    length_ = length;
    return true;
}

bool LocalAuthSetupState::matches(const char* code, size_t length) const
{
    if (!local_auth_code_shape_valid(code, length) || length != length_) {
        return false;
    }
    return memcmp(code_, code, length) == 0;
}

void LocalAuthSetupState::clear()
{
    wipe_sensitive_buffer(code_, sizeof(code_));
    length_ = 0;
}

#ifdef STOPWATCH_LOCAL_AUTH_HOST_TEST
bool LocalAuthSetupState::contains_for_test(const char* text) const
{
    if (text == nullptr) {
        return false;
    }
    const size_t text_size = strlen(text);
    if (text_size == 0 || text_size > sizeof(code_)) {
        return false;
    }
    for (size_t offset = 0; offset + text_size <= sizeof(code_); ++offset) {
        if (memcmp(code_ + offset, text, text_size) == 0) {
            return true;
        }
    }
    return false;
}
#endif

}  // namespace stopwatch_target
