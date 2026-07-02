#pragma once

#include "freertos/FreeRTOS.h"

namespace signing {

struct IdentificationDisplaySnapshot {
    bool active;
    TickType_t deadline;
};

void identification_display_clear();
bool identification_display_active();
IdentificationDisplaySnapshot identification_display_snapshot();

void identification_display_begin(TickType_t deadline);
bool identification_display_deadline_reached(TickType_t now);

}  // namespace signing
