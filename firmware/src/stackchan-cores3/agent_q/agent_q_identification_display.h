#pragma once

#include "freertos/FreeRTOS.h"

namespace agent_q {

struct AgentQIdentificationDisplaySnapshot {
    bool active;
    TickType_t deadline;
};

void identification_display_clear();
bool identification_display_active();
AgentQIdentificationDisplaySnapshot identification_display_snapshot();

void identification_display_begin(TickType_t deadline);
bool identification_display_deadline_reached(TickType_t now);

}  // namespace agent_q
