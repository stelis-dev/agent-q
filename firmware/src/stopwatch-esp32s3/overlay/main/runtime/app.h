#pragma once

#include <apps/common/key_manager/key_manager.h>
#include <hal/hal.h>
#include <lvgl.h>
#include <mooncake.h>
#include <memory>
#include <string>

#include "usb_transport.h"

namespace stopwatch_target {

class RuntimeApp : public mooncake::AppAbility {
public:
    RuntimeApp();

    void onCreate() override;
    void onOpen() override;
    void onRunning() override;
    void onClose() override;

private:
    std::unique_ptr<input::KeyManager> key_manager_;
    lv_obj_t* root_ = nullptr;
    lv_obj_t* title_label_ = nullptr;
    lv_obj_t* state_label_ = nullptr;
    lv_obj_t* instruction_label_ = nullptr;
    lv_obj_t* usb_label_ = nullptr;
    lv_obj_t* input_label_ = nullptr;
    lv_obj_t* power_label_ = nullptr;
    lv_obj_t* left_button_ = nullptr;
    lv_obj_t* right_button_ = nullptr;
    uint32_t last_update_ms_ = 0;
    uint32_t last_seen_rejected_connects_ = 0;
    std::string last_input_ = "none";
    int display_restore_brightness_ = 80;
    bool display_on_ = true;
    bool button_feedback_suppressed_ = false;
    bool power_policy_synced_ = false;
    bool synced_external_power_present_ = false;
    Hal::ButtonConfig saved_button_config_ = {};

    void create_ui();
    void destroy_ui();
    void update_ui(bool force);
    void handle_key_event(input::KeyEvent event);
    void handle_power_button(bool external_power_present);
    void sync_power_button_policy(bool external_power_present);
    void set_display_on(bool display_on, bool feedback = true, bool lvgl_locked = false);
    void set_button_feedback_suppressed(bool suppressed);
    void record_input(const char* input_name, uint16_t vibration_ms, uint8_t strength, bool lvgl_locked);
    static void handle_touch_event(lv_event_t* event);
};

}  // namespace stopwatch_target
