#pragma once

#include <stdint.h>

#include "freertos/FreeRTOS.h"

namespace agent_q {

constexpr uint32_t kAgentQPinLockoutMs = 30000;
constexpr uint8_t kAgentQMaxWrongPinAttempts = 5;

struct AgentQPinAttemptState {
    TickType_t lockout_until = 0;
    uint8_t wrong_pin_attempts = 0;
};

bool pin_attempt_locked_at(const AgentQPinAttemptState& state, TickType_t now);
bool pin_attempt_release_if_elapsed(AgentQPinAttemptState* state, TickType_t now);
bool pin_attempt_record_failure(AgentQPinAttemptState* state, TickType_t lockout_until);
void pin_attempt_clear(AgentQPinAttemptState* state);

}  // namespace agent_q
