#pragma once

#include <apps/common/key_manager/key_manager.h>
#include <hal/hal.h>
#include <lvgl.h>
#include <mooncake.h>
#include <memory>

#include "local_auth.h"
#include "local_auth_entry_state.h"
#include "local_auth_setup_state.h"
#include "local_auth_worker.h"
#include "local_transport_pairing_scene.h"
#include "clock_scene.h"
#include "device_reset.h"
#include "protocol/signing_mode.h"
#include "rotary_dial_scene.h"
#include "protocol_runtime.h"

namespace stopwatch_target {

class RuntimeApp : public mooncake::AppAbility {
public:
    RuntimeApp();

    void onCreate() override;
    void onOpen() override;
    void onRunning() override;
    void onClose() override;

private:
    // Target interaction state. Protocol, approval, signing, and carrier
    // authority remain in their owning runtime modules; scenes only project it.
    enum class RuntimeState {
        setup_enter,
        setup_confirm,
        unlock,
        auth_processing,
        idle,
        local_transport_pairing,
        local_transport_result,
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

    enum class LocalTransportResult {
        none,
        ready,
        expired,
        display_error,
        unavailable,
        failed,
    };

    enum class LocalAuthPurpose {
        none,
        setup,
        unlock,
        proof_approval,
        policy_approval,
        signing_mode_change,
        device_reset,
    };

    std::unique_ptr<input::KeyManager> key_manager_;
    lv_obj_t* root_ = nullptr;
    lv_obj_t* input_slot_labels_[kLocalAuthMaxDigits] = {};
    lv_obj_t* prompt_label_ = nullptr;
    lv_obj_t* detail_label_ = nullptr;
    RotaryDialScene rotary_dial_;
    ClockScene clock_scene_;
    LocalTransportPairingScene local_transport_pairing_scene_;
    uint32_t last_update_ms_ = 0;
    uint32_t unlock_idle_started_ms_ = 0;
    bool unlock_watch_timer_armed_ = false;
    bool watch_visible_ = false;
    bool ignore_touch_until_release_ = false;
    uint32_t last_seen_rejected_connects_ = 0;
    uint32_t local_transport_result_deadline_ms_ = 0;
    bool local_transport_qr_rendered_ = false;
    bool local_transport_result_rendered_ = false;
    LocalTransportResult local_transport_result_ = LocalTransportResult::none;
    RuntimeState runtime_state_ = RuntimeState::setup_enter;
    bool locally_unlocked_ = false;
    uint32_t local_auth_job_id_ = 0;
    uint32_t local_auth_worker_deadline_ms_ = 0;
    LocalAuthPurpose local_auth_purpose_ = LocalAuthPurpose::none;
    bool local_auth_cancel_requested_ = false;
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
    bool handle_power_button(bool external_power_present);
    void sync_power_button_policy(bool external_power_present);
    void set_display_on(bool display_on, bool feedback = true, bool lvgl_locked = false);
    void set_button_feedback_suppressed(bool suppressed);
    void record_feedback(uint16_t vibration_ms, uint8_t strength, bool lvgl_locked);
    void transition_to(RuntimeState state);
    void reset_unlock_watch();
    void show_unlock_watch();
    bool unlock_watch_allowed() const;
    void refresh_auth_mode();
    void refresh_auth_mode(const LocalAuthSnapshot& snapshot);
    void maybe_enter_watch(uint32_t now_ms);
    void begin_local_transport_pairing(uint32_t now_ms);
    void sync_local_transport_state(uint32_t now_ms);
    void project_local_transport_scene();
    void set_local_transport_result(
        LocalTransportResult result,
        uint32_t now_ms,
        uint32_t duration_ms);
    void cancel_local_transport_carrier();
    void sync_protocol_runtime_state();
    void sync_protocol_runtime_state(const LocalAuthSnapshot& snapshot);
    bool start_local_auth_job(
        LocalAuthWorkerOperation operation,
        LocalAuthPurpose purpose,
        const char* pin,
        uint32_t now_ms);
    void poll_local_auth_worker(uint32_t now_ms);
    void finish_local_auth_worker_result(
        const LocalAuthWorkerResult& result,
        uint32_t now_ms);
    void clear_local_auth_job();
    void lock_local_auth();
    bool unlocked_material_valid();
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
