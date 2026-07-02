#pragma once

#include <stdint.h>

namespace signing {

void request_display_power_toggle();
void request_display_power_wake();
void update_display_power(uint32_t inactive_time_ms);

}  // namespace signing
