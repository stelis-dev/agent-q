#include "local_auth_entry_state.h"

#include <string.h>

#include "sensitive_memory.h"

namespace stopwatch_target {
namespace {

constexpr uint32_t kCapturedDigitVisibleMs = 850;

bool elapsed_at_least(uint32_t now_ms, uint32_t since_ms, uint32_t duration_ms)
{
    return static_cast<int32_t>(now_ms - since_ms) >= static_cast<int32_t>(duration_ms);
}

}  // namespace

void LocalAuthEntryState::clear()
{
    wipe_sensitive_buffer(code_, sizeof(code_));
    length_ = 0;
    last_activity_ms_ = 0;
    memset(digit_visible_until_ms_, 0, sizeof(digit_visible_until_ms_));
}

bool LocalAuthEntryState::append(char digit, uint32_t now_ms)
{
    if (length_ >= kLocalAuthMaxDigits || digit < '0' || digit > '9') {
        return false;
    }
    code_[length_++] = digit;
    code_[length_] = '\0';
    digit_visible_until_ms_[length_ - 1] = now_ms + kCapturedDigitVisibleMs;
    last_activity_ms_ = now_ms;
    return true;
}

bool LocalAuthEntryState::delete_last(uint32_t now_ms)
{
    if (length_ == 0) {
        return false;
    }
    code_[--length_] = '\0';
    digit_visible_until_ms_[length_] = 0;
    last_activity_ms_ = now_ms;
    return true;
}

bool LocalAuthEntryState::timed_out(uint32_t now_ms) const
{
    if (last_activity_ms_ == 0) {
        return false;
    }
    return elapsed_at_least(now_ms, last_activity_ms_, kLocalAuthInputTimeoutMs);
}

char LocalAuthEntryState::digit_at(size_t index) const
{
    if (index >= length_) {
        return '\0';
    }
    return code_[index];
}

bool LocalAuthEntryState::digit_visible(size_t index, uint32_t now_ms) const
{
    if (index >= length_) {
        return false;
    }
    return static_cast<int32_t>(digit_visible_until_ms_[index] - now_ms) > 0;
}

}  // namespace stopwatch_target
