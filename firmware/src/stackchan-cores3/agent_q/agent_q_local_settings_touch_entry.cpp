#include "agent_q_local_settings_touch_entry.h"

#include <stdint.h>

namespace agent_q {
namespace {

struct LocalSettingsTouchEntryState {
    bool active = false;
    AgentQLocalSettingsTouchEntryTarget target = AgentQLocalSettingsTouchEntryTarget::none;
    TickType_t started_at = 0;

    void clear()
    {
        active = false;
        target = AgentQLocalSettingsTouchEntryTarget::none;
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

AgentQLocalSettingsTouchEntrySnapshot local_settings_touch_entry_snapshot()
{
    return AgentQLocalSettingsTouchEntrySnapshot{
        g_state.active,
        g_state.target,
        g_state.started_at,
    };
}

bool local_settings_touch_entry_update(
    AgentQLocalSettingsTouchEntryTarget target,
    TickType_t now,
    TickType_t hold_ticks)
{
    if (target == AgentQLocalSettingsTouchEntryTarget::none) {
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

}  // namespace agent_q
