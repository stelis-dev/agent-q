#include "agent_q_motion_state.h"

#include <atomic>
#include <memory>

#include "stackchan/stackchan.h"

namespace agent_q {
namespace {

constexpr int kAwakeYawAngle = 0;
constexpr int kAwakePitchAngle = 540;
constexpr int kRestYawAngle = 0;
constexpr int kRestPitchAngle = 0;
constexpr int kAwakePostureMoveSpeed = 280;
constexpr int kRestPostureMoveSpeed = 160;
constexpr uint32_t kRestPostureSettleMs = 700;
constexpr uint32_t kHeadLiftMs = 900;
constexpr int kHeadLiftPitchDelta = 160;
constexpr int kHeadLiftSpeed = 280;

std::atomic<int> g_posture_state{static_cast<int>(AgentQMotionPostureState::awake)};

int clamp_int(int value, int min_value, int max_value)
{
    if (value < min_value) {
        return min_value;
    }
    if (value > max_value) {
        return max_value;
    }
    return value;
}

AgentQMotionPostureState current_posture_state()
{
    return static_cast<AgentQMotionPostureState>(g_posture_state.load(std::memory_order_relaxed));
}

void move_to_posture(AgentQMotionPostureState state)
{
    if (state == AgentQMotionPostureState::rest) {
        GetStackChan().motion().moveWithSpeed(kRestYawAngle, kRestPitchAngle, kRestPostureMoveSpeed);
    } else {
        GetStackChan().motion().moveWithSpeed(kAwakeYawAngle, kAwakePitchAngle, kAwakePostureMoveSpeed);
    }
    g_posture_state.store(static_cast<int>(state), std::memory_order_relaxed);
}

class HeadLiftModifier : public stackchan::TimedEventModifier {
public:
    HeadLiftModifier() : stackchan::TimedEventModifier(kHeadLiftMs)
    {
    }

    void _on_start(stackchan::Modifiable& stackchan) override
    {
        auto& motion = stackchan.motion();
        if (motion.isModifyLocked() || motion.isMoving()) {
            return;
        }

        const auto current = motion.getCurrentAngles();
        previous_yaw_ = current.x;
        previous_pitch_ = current.y;
        active_ = true;

        motion.setModifyLock(true);
        const int target_pitch = clamp_int(previous_pitch_ + kHeadLiftPitchDelta, 0, 540);
        motion.moveWithSpeed(previous_yaw_, target_pitch, kHeadLiftSpeed);
    }

    void _on_end(stackchan::Modifiable& stackchan) override
    {
        if (!active_) {
            return;
        }

        auto& motion = stackchan.motion();
        if (current_posture_state() == AgentQMotionPostureState::rest) {
            move_to_posture(AgentQMotionPostureState::rest);
        } else {
            motion.moveWithSpeed(previous_yaw_, previous_pitch_, kHeadLiftSpeed);
        }
        motion.setModifyLock(false);
        active_ = false;
    }

private:
    bool active_ = false;
    int previous_yaw_ = 0;
    int previous_pitch_ = 0;
};

}  // namespace

void set_motion_posture(AgentQMotionPostureState state)
{
    move_to_posture(state);
}

uint32_t motion_rest_posture_settle_ms()
{
    return kRestPostureSettleMs;
}

void play_motion_feedback(AgentQMotionFeedbackState state)
{
    switch (state) {
        case AgentQMotionFeedbackState::head_lift:
            GetStackChan().addModifier(std::make_unique<HeadLiftModifier>());
            break;
    }
}

}  // namespace agent_q
