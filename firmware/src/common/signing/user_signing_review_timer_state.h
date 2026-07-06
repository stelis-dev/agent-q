#pragma once

#include "transport/timeout_window.h"

namespace signing {

struct UserSigningReviewTimerState {
    bool available;
    bool paused;
    TimeoutWindow display_window;
    TimeoutTick display_tick;
};

}  // namespace signing
