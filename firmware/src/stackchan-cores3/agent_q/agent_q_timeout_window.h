#pragma once

#include <stdint.h>

namespace agent_q {

using AgentQTimeoutTick = uint32_t;

struct AgentQTimeoutWindow {
    AgentQTimeoutTick started_at;
    AgentQTimeoutTick deadline;
};

struct AgentQPausedTimeoutWindow {
    AgentQTimeoutWindow window;
    AgentQTimeoutTick paused_at;
};

constexpr AgentQTimeoutWindow kAgentQTimeoutWindowNone = {0, 0};
constexpr AgentQPausedTimeoutWindow kAgentQPausedTimeoutWindowNone = {
    kAgentQTimeoutWindowNone,
    0,
};

inline AgentQTimeoutWindow timeout_window_from_deadline(
    AgentQTimeoutTick started_at,
    AgentQTimeoutTick deadline)
{
    return deadline == 0 || static_cast<int32_t>(started_at - deadline) >= 0
               ? kAgentQTimeoutWindowNone
               : AgentQTimeoutWindow{started_at, deadline};
}

inline bool timeout_window_tick_reached(AgentQTimeoutTick now, AgentQTimeoutTick deadline)
{
    return deadline != 0 && static_cast<int32_t>(now - deadline) >= 0;
}

inline bool timeout_window_active(const AgentQTimeoutWindow& window)
{
    return window.deadline != 0;
}

inline bool timeout_window_open_at(const AgentQTimeoutWindow& window, AgentQTimeoutTick now)
{
    return timeout_window_active(window) && !timeout_window_tick_reached(now, window.deadline);
}

inline bool timeout_window_valid(const AgentQTimeoutWindow& window)
{
    return timeout_window_open_at(window, window.started_at);
}

inline bool timeout_paused_window_valid(const AgentQPausedTimeoutWindow& paused_window)
{
    return timeout_window_valid(paused_window.window) &&
           static_cast<int32_t>(paused_window.paused_at - paused_window.window.started_at) >= 0 &&
           !timeout_window_tick_reached(paused_window.paused_at, paused_window.window.deadline);
}

inline bool timeout_window_reached(const AgentQTimeoutWindow& window, AgentQTimeoutTick now)
{
    return timeout_window_active(window) && timeout_window_tick_reached(now, window.deadline);
}

inline AgentQTimeoutTick timeout_window_remaining_ticks(
    const AgentQTimeoutWindow& window,
    AgentQTimeoutTick now)
{
    if (!timeout_window_open_at(window, now)) {
        return 0;
    }
    if (static_cast<int32_t>(now - window.started_at) <= 0) {
        return window.deadline - window.started_at;
    }
    return window.deadline - now;
}

inline AgentQPausedTimeoutWindow timeout_window_pause_at(
    const AgentQTimeoutWindow& window,
    AgentQTimeoutTick now)
{
    if (!timeout_window_open_at(window, now) ||
        static_cast<int32_t>(now - window.started_at) < 0) {
        return kAgentQPausedTimeoutWindowNone;
    }
    return AgentQPausedTimeoutWindow{window, now};
}

inline AgentQTimeoutWindow timeout_window_resume_at(
    const AgentQPausedTimeoutWindow& paused_window,
    AgentQTimeoutTick now)
{
    if (!timeout_paused_window_valid(paused_window) ||
        static_cast<int32_t>(now - paused_window.paused_at) < 0) {
        return kAgentQTimeoutWindowNone;
    }
    const AgentQTimeoutTick elapsed_ticks =
        paused_window.paused_at - paused_window.window.started_at;
    const AgentQTimeoutTick remaining_ticks =
        paused_window.window.deadline - paused_window.paused_at;
    return timeout_window_from_deadline(
        now - elapsed_ticks,
        now + remaining_ticks);
}

inline AgentQTimeoutTick timeout_window_cap_deadline(
    const AgentQTimeoutWindow& cap,
    AgentQTimeoutTick deadline)
{
    if (!timeout_window_active(cap)) {
        return deadline;
    }
    if (deadline == 0 || timeout_window_tick_reached(deadline, cap.deadline)) {
        return cap.deadline;
    }
    return deadline;
}

inline int32_t timeout_window_fill_width(
    const AgentQTimeoutWindow& window,
    AgentQTimeoutTick now,
    int32_t full_width)
{
    if (full_width <= 0 || !timeout_window_active(window)) {
        return 0;
    }
    if (timeout_window_reached(window, now)) {
        return 0;
    }
    if (!timeout_window_valid(window)) {
        return 0;
    }
    if (static_cast<int32_t>(now - window.started_at) <= 0) {
        return full_width;
    }

    const AgentQTimeoutTick total_ticks = window.deadline - window.started_at;
    const AgentQTimeoutTick remaining_ticks = window.deadline - now;
    int32_t width = static_cast<int32_t>(
        (static_cast<uint64_t>(remaining_ticks) * static_cast<uint64_t>(full_width) +
         static_cast<uint64_t>(total_ticks) - 1) /
        static_cast<uint64_t>(total_ticks));
    if (width < 0) {
        return 0;
    }
    if (width > full_width) {
        return full_width;
    }
    return width;
}

}  // namespace agent_q
