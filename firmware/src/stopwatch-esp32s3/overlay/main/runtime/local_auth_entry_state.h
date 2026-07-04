#pragma once

#include <stddef.h>
#include <stdint.h>

#include "local_auth.h"

namespace stopwatch_target {

class LocalAuthEntryState {
public:
    void clear();
    bool append(char digit, uint32_t now_ms);
    bool delete_last(uint32_t now_ms);
    bool timed_out(uint32_t now_ms) const;

    size_t length() const { return length_; }
    const char* code() const { return code_; }
    char digit_at(size_t index) const;
    bool digit_visible(size_t index, uint32_t now_ms) const;

private:
    char code_[kLocalAuthInputBufferSize] = {};
    size_t length_ = 0;
    uint32_t last_activity_ms_ = 0;
    uint32_t digit_visible_until_ms_[kLocalAuthMaxDigits] = {};
};

}  // namespace stopwatch_target
