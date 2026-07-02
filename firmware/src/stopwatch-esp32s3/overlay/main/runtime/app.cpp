#include "app.h"

#include <stdio.h>

#include <hal/hal.h>
#include <mooncake_log.h>
#include <smooth_lvgl.hpp>

namespace stopwatch_target {
namespace {

constexpr const char* kAppName = "Device";
constexpr uint32_t kUiRefreshMs = 250;

void set_label_text(lv_obj_t* label, const char* text)
{
    if (label != nullptr) {
        lv_label_set_text(label, text != nullptr ? text : "");
    }
}

lv_obj_t* make_label(lv_obj_t* parent, const lv_font_t* font, lv_color_t color, lv_align_t align, int x, int y)
{
    lv_obj_t* label = lv_label_create(parent);
    lv_obj_set_style_text_font(label, font, LV_PART_MAIN);
    lv_obj_set_style_text_color(label, color, LV_PART_MAIN);
    lv_obj_set_width(label, 360);
    lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
    lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
    lv_obj_align(label, align, x, y);
    return label;
}

lv_obj_t* make_action_button(lv_obj_t* parent, const char* text, lv_align_t align, int x, int y)
{
    lv_obj_t* button = lv_button_create(parent);
    lv_obj_set_size(button, 128, 58);
    lv_obj_align(button, align, x, y);
    lv_obj_set_style_radius(button, 28, LV_PART_MAIN);
    lv_obj_set_style_bg_color(button, lv_color_hex(0x24415F), LV_PART_MAIN);
    lv_obj_set_style_border_width(button, 0, LV_PART_MAIN);

    lv_obj_t* label = lv_label_create(button);
    lv_obj_set_style_text_font(label, &lv_font_montserrat_18, LV_PART_MAIN);
    lv_obj_set_style_text_color(label, lv_color_hex(0xFFFFFF), LV_PART_MAIN);
    lv_label_set_text(label, text);
    lv_obj_center(label);
    return button;
}

}  // namespace

RuntimeApp::RuntimeApp()
{
    setAppInfo().name = kAppName;
}

void RuntimeApp::onCreate()
{
    mclog::tagInfo(kAppName, "on create");
    open();
}

void RuntimeApp::onOpen()
{
    mclog::tagInfo(kAppName, "on open");
    key_manager_ = std::make_unique<input::KeyManager>();
    usb_transport_init();
    display_on_ = true;
    button_feedback_suppressed_ = false;
    saved_button_config_ = GetHAL().getButtonConfig();
    display_restore_brightness_ = GetHAL().getBackLightBrightness(false);
    if (display_restore_brightness_ <= 0) {
        display_restore_brightness_ = 80;
    }
    GetHAL().setBackLightBrightness(display_restore_brightness_, false);
    sync_power_button_policy();

    LvglLockGuard lock;
    create_ui();
    update_ui(true);
}

void RuntimeApp::onRunning()
{
    usb_transport_poll();

    if (key_manager_) {
        const input::KeyEvent key_event = key_manager_->update();
        sync_power_button_policy();
        handle_power_button();
        handle_key_event(key_event);
    }

    const UsbStatus status = usb_transport_status();
    if (status.rejected_connects != last_seen_rejected_connects_) {
        last_seen_rejected_connects_ = status.rejected_connects;
        record_input("USB connect rejected", 45, 80, false);
    }

    const uint32_t now = GetHAL().millis();
    if (display_on_ && now - last_update_ms_ >= kUiRefreshMs) {
        LvglLockGuard lock;
        update_ui(false);
    }
}

void RuntimeApp::onClose()
{
    mclog::tagInfo(kAppName, "on close");
    set_button_feedback_suppressed(false);
    key_manager_.reset();

    LvglLockGuard lock;
    destroy_ui();
}

void RuntimeApp::create_ui()
{
    destroy_ui();

    lv_obj_t* screen = lv_screen_active();
    lv_obj_remove_flag(screen, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_style_bg_color(screen, lv_color_black(), LV_PART_MAIN);

    root_ = lv_obj_create(screen);
    lv_obj_set_size(root_, 466, 466);
    lv_obj_align(root_, LV_ALIGN_CENTER, 0, 0);
    lv_obj_set_style_bg_color(root_, lv_color_black(), LV_PART_MAIN);
    lv_obj_set_style_border_width(root_, 0, LV_PART_MAIN);
    lv_obj_set_style_radius(root_, 233, LV_PART_MAIN);
    lv_obj_set_style_pad_all(root_, 0, LV_PART_MAIN);
    lv_obj_clear_flag(root_, LV_OBJ_FLAG_SCROLLABLE);

    title_label_ = make_label(root_, &lv_font_montserrat_28, lv_color_hex(0xFFFFFF), LV_ALIGN_TOP_MID, 0, 38);
    set_label_text(title_label_, "Agent-Q");

    state_label_ = make_label(root_, &lv_font_montserrat_18, lv_color_hex(0x9CF1B6), LV_ALIGN_TOP_MID, 0, 82);
    set_label_text(state_label_, "StopWatch ESP32-S3");

    instruction_label_ = make_label(root_, &lv_font_montserrat_16, lv_color_hex(0xC8D3DA), LV_ALIGN_TOP_MID, 0, 132);
    set_label_text(instruction_label_, "Unprovisioned. Connect requests fail closed.");

    usb_label_ = make_label(root_, &lv_font_montserrat_16, lv_color_hex(0xD8F2FF), LV_ALIGN_TOP_MID, 0, 202);
    input_label_ = make_label(root_, &lv_font_montserrat_16, lv_color_hex(0xB3CDFF), LV_ALIGN_TOP_MID, 0, 252);
    power_label_ = make_label(root_, &lv_font_montserrat_14, lv_color_hex(0x96A3AB), LV_ALIGN_TOP_MID, 0, 302);

    left_button_ = make_action_button(root_, "Touch A", LV_ALIGN_BOTTOM_LEFT, 58, -50);
    right_button_ = make_action_button(root_, "Touch B", LV_ALIGN_BOTTOM_RIGHT, -58, -50);
    lv_obj_add_event_cb(left_button_, handle_touch_event, LV_EVENT_PRESSED, this);
    lv_obj_add_event_cb(right_button_, handle_touch_event, LV_EVENT_PRESSED, this);
}

void RuntimeApp::destroy_ui()
{
    if (root_ != nullptr) {
        lv_obj_delete(root_);
    }
    root_ = nullptr;
    title_label_ = nullptr;
    state_label_ = nullptr;
    instruction_label_ = nullptr;
    usb_label_ = nullptr;
    input_label_ = nullptr;
    power_label_ = nullptr;
    left_button_ = nullptr;
    right_button_ = nullptr;
}

void RuntimeApp::update_ui(bool force)
{
    if (!display_on_) {
        return;
    }

    const uint32_t now = GetHAL().millis();
    if (!force && now - last_update_ms_ < kUiRefreshMs) {
        return;
    }
    last_update_ms_ = now;

    const UsbStatus status = usb_transport_status();
    char usb_text[160];
    snprintf(
        usb_text,
        sizeof(usb_text),
        "USB %s  lines:%lu  status:%lu  connect rejects:%lu",
        status.connected ? "connected" : "waiting",
        static_cast<unsigned long>(status.received_lines),
        static_cast<unsigned long>(status.status_responses),
        static_cast<unsigned long>(status.rejected_connects));
    set_label_text(usb_label_, usb_text);

    char input_text[160];
    snprintf(
        input_text,
        sizeof(input_text),
        "Last input: %s  last error: %s",
        last_input_.c_str(),
        status.last_error[0] != '\0' ? status.last_error : "none");
    set_label_text(input_label_, input_text);

    const bool external_power_present = GetHAL().isExternalPowerPresent();
    const bool battery_charging       = GetHAL().isBatteryCharging();
    char power_text[128];
    snprintf(
        power_text,
        sizeof(power_text),
        "Battery %u%%  %s",
        static_cast<unsigned>(GetHAL().getBatteryLevel()),
        external_power_present ? (battery_charging ? "USB charging" : "USB power") : "battery");
    set_label_text(power_label_, power_text);
}

void RuntimeApp::handle_key_event(input::KeyEvent event)
{
    switch (event) {
        case input::KeyEvent::GoPrevious:
            record_input("KEYA", 35, 70, false);
            break;
        case input::KeyEvent::GoNext:
            record_input("KEYB", 35, 70, false);
            break;
        case input::KeyEvent::GoHome:
            record_input("KEYA+KEYB", 60, 90, false);
            break;
        case input::KeyEvent::None:
            break;
    }
}

void RuntimeApp::handle_power_button()
{
    switch (GetHAL().readPowerButtonEvent()) {
        case Hal::PowerButtonEvent::shortClick:
            if (usb_power_present_for_power_policy()) {
                set_display_on(!display_on_);
            }
            break;
        case Hal::PowerButtonEvent::none:
            break;
    }
}

void RuntimeApp::sync_power_button_policy()
{
    const bool external_power_present = GetHAL().isExternalPowerPresent();
    if (power_policy_synced_ && external_power_present_ == external_power_present) {
        return;
    }
    if (GetHAL().setPowerButtonSingleClickResetEnabled(!external_power_present)) {
        external_power_present_ = external_power_present;
        power_policy_synced_ = true;
    }
}

bool RuntimeApp::usb_power_present_for_power_policy() const
{
    return external_power_present_;
}

void RuntimeApp::set_display_on(bool display_on, bool feedback, bool lvgl_locked)
{
    if (display_on_ == display_on) {
        return;
    }

    if (display_on) {
        display_on_ = true;
        set_button_feedback_suppressed(false);
        const int brightness = display_restore_brightness_ > 0 ? display_restore_brightness_ : 80;
        GetHAL().setBackLightBrightness(brightness, false);
        last_input_ = "power screen on";
        if (feedback) {
            GetHAL().vibrate(35, 70);
        }
        if (lvgl_locked) {
            update_ui(true);
        } else {
            LvglLockGuard lock;
            update_ui(true);
        }
        return;
    }

    const int current_brightness = GetHAL().getBackLightBrightness(false);
    if (current_brightness > 0) {
        display_restore_brightness_ = current_brightness;
    }
    last_input_ = "power screen off";
    if (feedback) {
        GetHAL().vibrate(35, 70);
    }
    set_button_feedback_suppressed(true);
    GetHAL().setBackLightBrightness(0, false);
    display_on_ = false;
}

void RuntimeApp::set_button_feedback_suppressed(bool suppressed)
{
    if (button_feedback_suppressed_ == suppressed) {
        return;
    }

    if (suppressed) {
        saved_button_config_ = GetHAL().getButtonConfig();
        Hal::ButtonConfig disabled_config = saved_button_config_;
        disabled_config.sfxEnabled = false;
        disabled_config.vibrateEnabled = false;
        GetHAL().setButtonConfig(disabled_config, false);
        button_feedback_suppressed_ = true;
        return;
    }

    GetHAL().setButtonConfig(saved_button_config_, false);
    button_feedback_suppressed_ = false;
}

void RuntimeApp::record_input(
    const char* input_name,
    uint16_t vibration_ms,
    uint8_t strength,
    bool lvgl_locked)
{
    if (!display_on_) {
        set_display_on(true, false, lvgl_locked);
    }

    last_input_ = input_name != nullptr ? input_name : "unknown";
    GetHAL().vibrate(vibration_ms, strength);
    if (lvgl_locked) {
        update_ui(true);
    } else {
        LvglLockGuard lock;
        update_ui(true);
    }
}

void RuntimeApp::handle_touch_event(lv_event_t* event)
{
    auto* app = static_cast<RuntimeApp*>(lv_event_get_user_data(event));
    if (app == nullptr) {
        return;
    }
    const lv_obj_t* target = static_cast<lv_obj_t*>(lv_event_get_current_target(event));
    if (target == app->left_button_) {
        app->record_input("touch A", 35, 70, true);
    } else if (target == app->right_button_) {
        app->record_input("touch B", 35, 70, true);
    }
}

}  // namespace stopwatch_target
