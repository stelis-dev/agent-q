#pragma once

#include "freertos/FreeRTOS.h"

namespace agent_q {

struct AgentQLocalSettingsTouchEntrySnapshot {
    bool active;
    TickType_t started_at;
};

void local_settings_touch_entry_clear();
bool local_settings_touch_entry_active();
AgentQLocalSettingsTouchEntrySnapshot local_settings_touch_entry_snapshot();

bool local_settings_touch_entry_update(
    bool inside_entry_area,
    TickType_t now,
    TickType_t hold_ticks);

}  // namespace agent_q
