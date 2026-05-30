#pragma once

#include <stdint.h>

namespace agent_q {

void request_display_power_toggle();
void request_display_power_wake();
void prepare_display_power_awake_posture();
void prepare_display_power_rest_posture();
uint32_t display_power_rest_posture_delay_ms();
void update_display_power(uint32_t inactive_time_ms);

}  // namespace agent_q
