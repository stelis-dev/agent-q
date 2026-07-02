#include "local_settings_touch_entry.h"

#include <stdint.h>

namespace signing {
namespace {

struct LocalSettingsTouchEntryState {
    bool active = false;
    LocalSettingsTouchEntryTarget target = LocalSettingsTouchEntryTarget::none;
    TickType_t started_at = 0;

    void clear()
    {
        active = false;
        target = LocalSettingsTouchEntryTarget::none;
        started_at = 0;
    }
};

LocalSettingsTouchEntryState g_state;

bool elapsed_at_least(TickType_t now, TickType_t started_at, TickType_t hold_ticks)
{
    return static_cast<int32_t>(now - started_at) >=
           static_cast<int32_t>(hold_ticks);
}

}  // namespace

void local_settings_touch_entry_clear()
{
    g_state.clear();
}

bool local_settings_touch_entry_active()
{
    return g_state.active;
}

LocalSettingsTouchEntrySnapshot local_settings_touch_entry_snapshot()
{
    return LocalSettingsTouchEntrySnapshot{
        g_state.active,
        g_state.target,
        g_state.started_at,
    };
}

bool local_settings_touch_entry_update(
    LocalSettingsTouchEntryTarget target,
    TickType_t now,
    TickType_t hold_ticks)
{
    if (target == LocalSettingsTouchEntryTarget::none) {
        g_state.clear();
        return false;
    }

    if (!g_state.active || g_state.target != target) {
        g_state.active = true;
        g_state.target = target;
        g_state.started_at = now;
        return false;
    }

    if (!elapsed_at_least(now, g_state.started_at, hold_ticks)) {
        return false;
    }

    g_state.clear();
    return true;
}

}  // namespace signing
