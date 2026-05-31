#include "agent_q_pin_attempt.h"

namespace agent_q {
namespace {

bool tick_reached(TickType_t deadline, TickType_t now)
{
    return deadline != 0 && static_cast<int32_t>(now - deadline) >= 0;
}

}  // namespace

bool pin_attempt_locked_at(const AgentQPinAttemptState& state, TickType_t now)
{
    return state.lockout_until != 0 && !tick_reached(state.lockout_until, now);
}

bool pin_attempt_release_if_elapsed(AgentQPinAttemptState* state, TickType_t now)
{
    if (state == nullptr ||
        state->lockout_until == 0 ||
        !tick_reached(state->lockout_until, now)) {
        return false;
    }

    pin_attempt_clear(state);
    return true;
}

bool pin_attempt_record_failure(AgentQPinAttemptState* state, TickType_t lockout_until)
{
    if (state == nullptr) {
        return false;
    }
    if (state->wrong_pin_attempts < UINT8_MAX) {
        ++state->wrong_pin_attempts;
    }
    if (state->wrong_pin_attempts >= kAgentQMaxWrongPinAttempts) {
        state->lockout_until = lockout_until;
        return true;
    }
    return false;
}

void pin_attempt_clear(AgentQPinAttemptState* state)
{
    if (state == nullptr) {
        return;
    }
    state->lockout_until = 0;
    state->wrong_pin_attempts = 0;
}

}  // namespace agent_q
