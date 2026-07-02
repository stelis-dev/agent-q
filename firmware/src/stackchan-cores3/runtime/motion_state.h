#pragma once

#include <stdint.h>

namespace signing {

enum class MotionPostureState {
    awake,
    rest,
};

enum class MotionFeedbackState {
    head_lift,
};

void set_motion_posture(MotionPostureState state);
uint32_t motion_rest_posture_settle_ms();
void play_motion_feedback(MotionFeedbackState state);

}  // namespace signing
