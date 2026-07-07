#pragma once

#include <apps/common/key_manager/key_manager.h>
#include <hal/hal.h>
#include <lvgl.h>
#include <mooncake.h>
#include <memory>

#include "local_auth.h"
#include "local_auth_entry_state.h"
#include "local_auth_setup_state.h"
#include "device_reset.h"
#include "protocol/signing_mode.h"
#include "rotary_dial_scene.h"
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
    enum class ScreenMode {
        setup_enter,
        setup_confirm,
        unlock,
        idle,
        connect_review,
        proof_review,
        policy_review,
        signing_review,
        signing_mode_review,
        proof_auth,
        policy_auth,
        signing_mode_auth,
        device_reset_review,
        device_reset_auth,
        lockout,
        error,
    };

    std::unique_ptr<input::KeyManager> key_manager_;
    lv_obj_t* root_ = nullptr;
    lv_obj_t* input_slot_labels_[kLocalAuthMaxDigits] = {};
    lv_obj_t* prompt_label_ = nullptr;
    lv_obj_t* detail_label_ = nullptr;
    RotaryDialScene rotary_dial_;
    uint32_t last_update_ms_ = 0;
    uint32_t last_seen_rejected_connects_ = 0;
    ScreenMode screen_mode_ = ScreenMode::setup_enter;
    bool locally_unlocked_ = false;
    bool previous_external_power_present_ = false;
    LocalAuthEntryState auth_entry_;
    LocalAuthSetupState setup_state_;
    bool touch_down_ = false;
    int touch_last_x_ = 0;
    int touch_last_y_ = 0;
    int touch_digit_ = -1;
    bool dial_return_active_ = false;
    uint32_t dial_return_last_ms_ = 0;
    int display_restore_brightness_ = 50;
    bool display_on_ = true;
    bool button_feedback_suppressed_ = false;
    bool power_policy_synced_ = false;
    bool synced_external_power_present_ = false;
    signing::AuthorizationMode pending_signing_mode_ = signing::AuthorizationMode::user;
    Hal::ButtonConfig saved_button_config_ = {};

    void create_ui();
    void destroy_ui();
    void update_ui(bool force);
    void handle_key_event(input::KeyEvent event, uint32_t now_ms);
    void handle_touch_poll(uint32_t now_ms);
    void handle_power_button(bool external_power_present);
    void sync_power_button_policy(bool external_power_present);
    void set_display_on(bool display_on, bool feedback = true, bool lvgl_locked = false);
    void set_button_feedback_suppressed(bool suppressed);
    void record_feedback(uint16_t vibration_ms, uint8_t strength, bool lvgl_locked);
    void enter_mode(ScreenMode mode);
    void refresh_auth_mode();
    void refresh_auth_mode(const LocalAuthSnapshot& snapshot);
    void sync_usb_runtime_state();
    void sync_usb_runtime_state(const LocalAuthSnapshot& snapshot);
    void relock();
    void clear_entry();
    void clear_auth_scratch();
    void append_digit(char digit, uint32_t now_ms);
    void delete_digit(uint32_t now_ms);
    void submit_entry(uint32_t now_ms);
    bool complete_device_reset();
    bool auth_entry_mode() const;
    bool input_timed_out(uint32_t now) const;
    bool capture_touch_digit(int x, int y);
    void refresh_input_slot_layer();
    void update_input_slots();
    void update_prompt_label();
    void update_detail_label();
    void handle_touch_release(uint32_t now_ms);
    void start_dial_return();
    void animate_dial_return(uint32_t now);
};

}  // namespace stopwatch_target
