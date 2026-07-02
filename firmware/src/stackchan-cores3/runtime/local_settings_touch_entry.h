#pragma once

#include "freertos/FreeRTOS.h"

namespace signing {

enum class LocalSettingsTouchEntryTarget {
    none,
    device_settings,
    chain_settings,
};

struct LocalSettingsTouchEntrySnapshot {
    bool active;
    LocalSettingsTouchEntryTarget target;
    TickType_t started_at;
};

void local_settings_touch_entry_clear();
bool local_settings_touch_entry_active();
LocalSettingsTouchEntrySnapshot local_settings_touch_entry_snapshot();

bool local_settings_touch_entry_update(
    LocalSettingsTouchEntryTarget target,
    TickType_t now,
    TickType_t hold_ticks);

}  // namespace signing
