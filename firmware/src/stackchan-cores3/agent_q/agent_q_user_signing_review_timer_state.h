#pragma once

#include "agent_q_timeout_window.h"

namespace agent_q {

struct AgentQUserSigningReviewTimerState {
    bool available;
    bool paused;
    AgentQTimeoutWindow display_window;
    AgentQTimeoutTick display_tick;
};

}  // namespace agent_q
