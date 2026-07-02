#include "pin_attempt.h"

namespace signing {
namespace {

struct PinAttemptState {
    TickType_t lockout_until = 0;
    uint8_t wrong_pin_attempts = 0;
};

PinAttemptState g_pin_attempt;

bool tick_reached(TickType_t deadline, TickType_t now)
{
    return deadline != 0 && static_cast<int32_t>(now - deadline) >= 0;
}

}  // namespace

bool pin_attempt_locked_at(TickType_t now)
{
    return g_pin_attempt.lockout_until != 0 && !tick_reached(g_pin_attempt.lockout_until, now);
}

bool pin_attempt_lockout_elapsed_at(TickType_t now)
{
    return g_pin_attempt.lockout_until != 0 && tick_reached(g_pin_attempt.lockout_until, now);
}

bool pin_attempt_release_if_elapsed(TickType_t now)
{
    if (!pin_attempt_lockout_elapsed_at(now)) {
        return false;
    }

    pin_attempt_clear();
    return true;
}

bool pin_attempt_record_failure(TickType_t lockout_until)
{
    if (g_pin_attempt.wrong_pin_attempts < UINT8_MAX) {
        ++g_pin_attempt.wrong_pin_attempts;
    }
    if (g_pin_attempt.wrong_pin_attempts >= kMaxWrongPinAttempts) {
        g_pin_attempt.lockout_until = lockout_until;
        return true;
    }
    return false;
}

void pin_attempt_clear()
{
    g_pin_attempt.lockout_until = 0;
    g_pin_attempt.wrong_pin_attempts = 0;
}

}  // namespace signing
