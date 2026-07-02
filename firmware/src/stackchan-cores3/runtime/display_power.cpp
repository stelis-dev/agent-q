#include "display_power.h"

#include <atomic>

#include "motion_state.h"
#include "esp_log.h"
#include "hal/hal.h"
#include "lvgl.h"

namespace signing {
namespace {

constexpr const char* kTag = "DisplayPower";
constexpr uint32_t kMillisPerMinute = 60 * 1000;
constexpr uint32_t kScreenSleepTimeoutMs = 3 * kMillisPerMinute;
// Single source of truth for device display brightness. Pinned to 50 (StackChan default
// is 75) for lower heat / longer panel life: applied once at boot and restored on wake.
// This overrides Settings, so app/Settings brightness changes do not persist
// across reboot; change device brightness by editing this one constant.
constexpr uint8_t kDisplayBrightness = 50;

std::atomic<bool> g_toggle_requested{false};
std::atomic<bool> g_wake_requested{false};

bool g_screen_sleeping = false;
bool g_manual_screen_off = false;
uint32_t g_last_inactive_time_ms = 0;
uint8_t g_saved_brightness = 0;
bool g_brightness_applied = false;

void sleep_now(bool manual)
{
    if (g_screen_sleeping) {
        g_manual_screen_off = g_manual_screen_off || manual;
        return;
    }

    set_motion_posture(MotionPostureState::rest);
    g_saved_brightness = GetHAL().getBackLightBrightness();
    GetHAL().setBackLightBrightness(0, false);
    g_screen_sleeping = true;
    g_manual_screen_off = manual;
    ESP_LOGI(kTag, "Screen off");
}

void wake_now()
{
    if (!g_screen_sleeping) {
        return;
    }

    const uint8_t brightness = g_saved_brightness > 0 ? g_saved_brightness : kDisplayBrightness;
    GetHAL().setBackLightBrightness(brightness, false);
    set_motion_posture(MotionPostureState::awake);
    g_screen_sleeping = false;
    g_manual_screen_off = false;
    ESP_LOGI(kTag, "Screen on");
}

}  // namespace

void request_display_power_toggle()
{
    g_toggle_requested.store(true, std::memory_order_relaxed);
}

void request_display_power_wake()
{
    g_wake_requested.store(true, std::memory_order_relaxed);
}

void update_display_power(uint32_t inactive_time_ms)
{
    if (!g_brightness_applied) {
        // Board boots at the StackChan default (~75). Agent-Q runs the backlight
        // lower (cooler / longer panel life; plenty on the light theme). permanent=true
        // so the saved setting, RestoreBrightness, and sleep/wake all settle here.
        GetHAL().setBackLightBrightness(kDisplayBrightness, true);
        g_brightness_applied = true;
    }

    if (g_toggle_requested.exchange(false, std::memory_order_relaxed)) {
        if (g_screen_sleeping) {
            lv_display_trigger_activity(nullptr);
            wake_now();
        } else {
            sleep_now(true);
        }
        g_last_inactive_time_ms = inactive_time_ms;
        return;
    }

    if (g_wake_requested.exchange(false, std::memory_order_relaxed)) {
        lv_display_trigger_activity(nullptr);
        wake_now();
        g_last_inactive_time_ms = inactive_time_ms;
        return;
    }

    if (g_screen_sleeping && g_manual_screen_off) {
        if (inactive_time_ms < g_last_inactive_time_ms) {
            wake_now();
        }
        g_last_inactive_time_ms = inactive_time_ms;
        return;
    }

    if (inactive_time_ms >= kScreenSleepTimeoutMs) {
        sleep_now(false);
    } else {
        wake_now();
    }
    g_last_inactive_time_ms = inactive_time_ms;
}

}  // namespace signing
