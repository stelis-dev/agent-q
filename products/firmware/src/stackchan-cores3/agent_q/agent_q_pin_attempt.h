#pragma once

#include <stdint.h>

#include "freertos/FreeRTOS.h"

namespace agent_q {

constexpr uint32_t kAgentQPinLockoutMs = 30000;
constexpr uint8_t kAgentQMaxWrongPinAttempts = 5;

bool pin_attempt_locked_at(TickType_t now);
bool pin_attempt_release_if_elapsed(TickType_t now);
bool pin_attempt_record_failure(TickType_t lockout_until);
void pin_attempt_clear();

}  // namespace agent_q
