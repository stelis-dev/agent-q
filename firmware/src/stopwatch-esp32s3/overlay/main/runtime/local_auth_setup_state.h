#pragma once

#include <stddef.h>

#include "local_auth.h"

namespace stopwatch_target {

class LocalAuthSetupState {
public:
    ~LocalAuthSetupState();

    bool set_first_entry(const char* code, size_t length);
    bool matches(const char* code, size_t length) const;
    void clear();

    size_t length() const { return length_; }

#ifdef STOPWATCH_LOCAL_AUTH_HOST_TEST
    bool contains_for_test(const char* text) const;
#endif

private:
    char code_[kLocalAuthInputBufferSize] = {};
    size_t length_ = 0;
};

}  // namespace stopwatch_target
