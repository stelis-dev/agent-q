#pragma once

#include <stdint.h>

namespace agent_q {

enum class AgentQMotionPostureState {
    awake,
    rest,
};

enum class AgentQMotionFeedbackState {
    head_lift,
};

void set_motion_posture(AgentQMotionPostureState state);
uint32_t motion_rest_posture_settle_ms();
void play_motion_feedback(AgentQMotionFeedbackState state);

}  // namespace agent_q
