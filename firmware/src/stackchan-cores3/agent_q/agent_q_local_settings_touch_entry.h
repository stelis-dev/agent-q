#pragma once

#include "freertos/FreeRTOS.h"

namespace agent_q {

enum class AgentQLocalSettingsTouchEntryTarget {
    none,
    device_settings,
    chain_settings,
};

struct AgentQLocalSettingsTouchEntrySnapshot {
    bool active;
    AgentQLocalSettingsTouchEntryTarget target;
    TickType_t started_at;
};

void local_settings_touch_entry_clear();
bool local_settings_touch_entry_active();
AgentQLocalSettingsTouchEntrySnapshot local_settings_touch_entry_snapshot();

bool local_settings_touch_entry_update(
    AgentQLocalSettingsTouchEntryTarget target,
    TickType_t now,
    TickType_t hold_ticks);

}  // namespace agent_q
