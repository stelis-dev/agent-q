#pragma once

#include <stdint.h>

namespace signing {

using TimeoutTick = uint32_t;

struct TimeoutWindow {
    TimeoutTick started_at;
    TimeoutTick deadline;
};

struct PausedTimeoutWindow {
    TimeoutWindow window;
    TimeoutTick paused_at;
};

constexpr TimeoutWindow kTimeoutWindowNone = {0, 0};
constexpr PausedTimeoutWindow kPausedTimeoutWindowNone = {
    kTimeoutWindowNone,
    0,
};

inline TimeoutWindow timeout_window_from_deadline(
    TimeoutTick started_at,
    TimeoutTick deadline)
{
    return deadline == 0 || static_cast<int32_t>(started_at - deadline) >= 0
               ? kTimeoutWindowNone
               : TimeoutWindow{started_at, deadline};
}

inline bool timeout_window_tick_reached(TimeoutTick now, TimeoutTick deadline)
{
    return deadline != 0 && static_cast<int32_t>(now - deadline) >= 0;
}

inline bool timeout_window_active(const TimeoutWindow& window)
{
    return window.deadline != 0;
}

inline bool timeout_window_open_at(const TimeoutWindow& window, TimeoutTick now)
{
    return timeout_window_active(window) && !timeout_window_tick_reached(now, window.deadline);
}

inline bool timeout_window_valid(const TimeoutWindow& window)
{
    return timeout_window_open_at(window, window.started_at);
}

inline bool timeout_window_valid_and_open_at(
    const TimeoutWindow& window,
    TimeoutTick now)
{
    return timeout_window_valid(window) &&
           static_cast<int32_t>(now - window.started_at) >= 0 &&
           timeout_window_open_at(window, now);
}

inline bool timeout_paused_window_valid(const PausedTimeoutWindow& paused_window)
{
    return timeout_window_valid(paused_window.window) &&
           static_cast<int32_t>(paused_window.paused_at - paused_window.window.started_at) >= 0 &&
           !timeout_window_tick_reached(paused_window.paused_at, paused_window.window.deadline);
}

inline bool timeout_window_reached(const TimeoutWindow& window, TimeoutTick now)
{
    return timeout_window_active(window) && timeout_window_tick_reached(now, window.deadline);
}

inline TimeoutTick timeout_window_remaining_ticks(
    const TimeoutWindow& window,
    TimeoutTick now)
{
    if (!timeout_window_open_at(window, now)) {
        return 0;
    }
    if (static_cast<int32_t>(now - window.started_at) <= 0) {
        return window.deadline - window.started_at;
    }
    return window.deadline - now;
}

inline PausedTimeoutWindow timeout_window_pause_at(
    const TimeoutWindow& window,
    TimeoutTick now)
{
    if (!timeout_window_open_at(window, now) ||
        static_cast<int32_t>(now - window.started_at) < 0) {
        return kPausedTimeoutWindowNone;
    }
    return PausedTimeoutWindow{window, now};
}

inline TimeoutWindow timeout_window_resume_at(
    const PausedTimeoutWindow& paused_window,
    TimeoutTick now)
{
    if (!timeout_paused_window_valid(paused_window) ||
        static_cast<int32_t>(now - paused_window.paused_at) < 0) {
        return kTimeoutWindowNone;
    }
    const TimeoutTick elapsed_ticks =
        paused_window.paused_at - paused_window.window.started_at;
    const TimeoutTick remaining_ticks =
        paused_window.window.deadline - paused_window.paused_at;
    return timeout_window_from_deadline(
        now - elapsed_ticks,
        now + remaining_ticks);
}

inline TimeoutTick timeout_window_cap_deadline(
    const TimeoutWindow& cap,
    TimeoutTick deadline)
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
    const TimeoutWindow& window,
    TimeoutTick now,
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

    const TimeoutTick total_ticks = window.deadline - window.started_at;
    const TimeoutTick remaining_ticks = window.deadline - now;
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

}  // namespace signing
