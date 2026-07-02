#include "identification_display.h"

#include <stdint.h>

namespace signing {
namespace {

struct IdentificationDisplayState {
    bool active = false;
    TickType_t deadline = 0;

    void clear()
    {
        active = false;
        deadline = 0;
    }
};

IdentificationDisplayState g_state;

bool tick_reached(TickType_t now, TickType_t deadline)
{
    return static_cast<int32_t>(now - deadline) >= 0;
}

}  // namespace

void identification_display_clear()
{
    g_state.clear();
}

bool identification_display_active()
{
    return g_state.active;
}

IdentificationDisplaySnapshot identification_display_snapshot()
{
    return IdentificationDisplaySnapshot{
        g_state.active,
        g_state.deadline,
    };
}

void identification_display_begin(TickType_t deadline)
{
    g_state.active = true;
    g_state.deadline = deadline;
}

bool identification_display_deadline_reached(TickType_t now)
{
    return g_state.active && tick_reached(now, g_state.deadline);
}

}  // namespace signing
