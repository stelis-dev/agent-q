#include "app.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#include <hal/hal.h>
#include <mooncake_log.h>
#include <smooth_lvgl.hpp>

#include "credential_preparation_state.h"
#include "payload_transfer_state.h"
#include "secure_random.h"
#include "session_state.h"
#include "sui_zklogin_credential_clear.h"
#include "sui_zklogin_credential_store.h"
#include "sui_zklogin_proposal_state.h"

namespace stopwatch_target {
namespace {

constexpr const char* kAppName = "Device";
constexpr uint32_t kUiRefreshMs = 250;
constexpr uint32_t kDialReturnFrameMs = 24;
constexpr float kDialReturnBaseStepDegrees = 30.0F;
constexpr float kDialReturnDistanceFactor = 0.13F;
constexpr float kDialReturnMaxStepDegrees = 42.0F;
constexpr uint16_t kDialReturnTickMs = 8;
constexpr uint8_t kDialReturnTickStrength = 25;
constexpr uint16_t kDialCaptureMs = 16;
constexpr uint8_t kDialCaptureStrength = 45;
constexpr int kDefaultBacklightBrightness = 50;
constexpr int kInputSlotCount = static_cast<int>(kLocalAuthMaxDigits);
constexpr int kPromptAuthY = -26;
constexpr int kPromptSceneY = 0;
constexpr int kPromptReviewY = -104;
constexpr int kDetailReviewY = -28;

void copy_middle_elided(
    const char* input,
    char* output,
    size_t output_size,
    size_t prefix_chars,
    size_t suffix_chars)
{
    if (output == nullptr || output_size == 0) {
        return;
    }
    output[0] = '\0';
    if (input == nullptr) {
        return;
    }
    const size_t length = strlen(input);
    if (length + 1 <= output_size ||
        prefix_chars + suffix_chars + 4 >= output_size ||
        length <= prefix_chars + suffix_chars + 3) {
        strlcpy(output, input, output_size);
        return;
    }
    memcpy(output, input, prefix_chars);
    memcpy(output + prefix_chars, "...", 3);
    memcpy(output + prefix_chars + 3, input + length - suffix_chars, suffix_chars);
    output[prefix_chars + 3 + suffix_chars] = '\0';
}

void copy_proof_hash_preview(const char* proof_hash, char* output, size_t output_size)
{
    if (output == nullptr || output_size == 0) {
        return;
    }
    output[0] = '\0';
    constexpr const char* kPrefix = "sha256:";
    constexpr size_t kPrefixLength = 7;
    if (proof_hash == nullptr ||
        strncmp(proof_hash, kPrefix, kPrefixLength) != 0) {
        strlcpy(output, proof_hash != nullptr ? proof_hash : "", output_size);
        return;
    }
    copy_middle_elided(proof_hash + kPrefixLength, output, output_size, 8, 6);
}

void set_label_text(lv_obj_t* label, const char* text)
{
    if (label != nullptr) {
        lv_label_set_text(label, text != nullptr ? text : "");
    }
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
    local_auth_init(GetHAL().millis());
    session_state_init();
    credential_preparation_state_init();
    payload_transfer_state_init();
    sui_zklogin_proposal_state_init();
    secure_random_init();
    usb_transport_init();
    display_on_ = true;
    locally_unlocked_ = false;
    button_feedback_suppressed_ = false;
    saved_button_config_ = GetHAL().getButtonConfig();
    display_restore_brightness_ = kDefaultBacklightBrightness;
    GetHAL().setBackLightBrightness(display_restore_brightness_, false);
    sync_power_button_policy(GetHAL().isExternalPowerPresent());
    previous_usb_connected_ = usb_transport_status().connected;

    const LocalAuthSnapshot snapshot = local_auth_snapshot(GetHAL().millis());
    if (snapshot.status == LocalAuthStoreStatus::missing) {
        screen_mode_ = ScreenMode::setup_enter;
    } else if (snapshot.status == LocalAuthStoreStatus::active && snapshot.locked) {
        screen_mode_ = ScreenMode::lockout;
    } else if (snapshot.status == LocalAuthStoreStatus::active) {
        screen_mode_ = ScreenMode::unlock;
    } else {
        screen_mode_ = ScreenMode::error;
    }
    sync_usb_runtime_state();

    LvglLockGuard lock;
    create_ui();
    update_ui(true);
}

void RuntimeApp::onRunning()
{
    sync_usb_runtime_state();

    const UsbStatus status = usb_transport_status();
    if (previous_usb_connected_ != status.connected) {
        relock();
        if (!display_on_) {
            set_display_on(true, false, false);
        }
    }
    previous_usb_connected_ = status.connected;

    const uint32_t now = GetHAL().millis();

    if (key_manager_) {
        const input::KeyEvent key_event = key_manager_->update();
        const bool external_power_present = GetHAL().isExternalPowerPresent();
        sync_power_button_policy(external_power_present);
        handle_power_button(external_power_present);
        handle_key_event(key_event, now);
    }

    handle_touch_poll(now);
    animate_dial_return(now);

    sync_usb_runtime_state();
    usb_transport_poll();
    if (usb_transport_identification_display().active && !display_on_) {
        set_display_on(true, false, false);
    }
    refresh_auth_mode();
    const UsbPendingRequest pending = usb_transport_pending_request();
    if (pending.kind == UsbPendingRequestKind::connect) {
        if (!display_on_) {
            set_display_on(true, false, false);
        }
        if (locally_unlocked_ && screen_mode_ == ScreenMode::idle) {
            enter_mode(ScreenMode::connect_review);
        }
    } else if (pending.kind == UsbPendingRequestKind::credential_propose) {
        if (!display_on_) {
            set_display_on(true, false, false);
        }
        if (locally_unlocked_ && screen_mode_ == ScreenMode::idle) {
            enter_mode(ScreenMode::proof_review);
        }
    } else if (screen_mode_ == ScreenMode::connect_review ||
               screen_mode_ == ScreenMode::proof_review ||
               screen_mode_ == ScreenMode::proof_auth) {
        enter_mode(locally_unlocked_ ? ScreenMode::idle : ScreenMode::unlock);
    }

    const uint32_t timeout_check_ms = GetHAL().millis();
    if (input_timed_out(timeout_check_ms)) {
        if (screen_mode_ == ScreenMode::setup_confirm) {
            setup_state_.clear();
            enter_mode(ScreenMode::setup_enter);
        }
        clear_entry();
    }

    const UsbStatus updated_status = usb_transport_status();
    if (updated_status.rejected_connects != last_seen_rejected_connects_) {
        last_seen_rejected_connects_ = updated_status.rejected_connects;
        record_feedback(45, 80, false);
    }

    sync_usb_runtime_state();
    if (display_on_ && now - last_update_ms_ >= kUiRefreshMs) {
        LvglLockGuard lock;
        update_ui(false);
    }
}

void RuntimeApp::onClose()
{
    mclog::tagInfo(kAppName, "on close");
    relock();
    usb_transport_clear_session_scoped_state();
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
    lv_obj_set_style_bg_color(root_, lv_color_hex(0x050607), LV_PART_MAIN);
    lv_obj_set_style_border_width(root_, 0, LV_PART_MAIN);
    lv_obj_set_style_radius(root_, 233, LV_PART_MAIN);
    lv_obj_set_style_pad_all(root_, 0, LV_PART_MAIN);
    lv_obj_clear_flag(root_, LV_OBJ_FLAG_SCROLLABLE);

    rotary_dial_.create(root_);

    constexpr int kSlotWidth = 32;
    constexpr int kSlotGap = 2;
    constexpr int kSlotY = 10;
    prompt_label_ = lv_label_create(root_);
    lv_obj_set_style_text_font(prompt_label_, &lv_font_montserrat_16, LV_PART_MAIN);
    lv_obj_set_style_text_color(prompt_label_, lv_color_hex(0xC9D2D8), LV_PART_MAIN);
    lv_obj_set_style_text_opa(prompt_label_, LV_OPA_80, LV_PART_MAIN);
    lv_obj_set_width(prompt_label_, 160);
    lv_obj_set_style_text_align(prompt_label_, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
    lv_label_set_long_mode(prompt_label_, LV_LABEL_LONG_CLIP);
    lv_obj_align(prompt_label_, LV_ALIGN_CENTER, 0, kPromptAuthY);

    detail_label_ = lv_label_create(root_);
    lv_obj_set_style_text_font(detail_label_, &lv_font_montserrat_14, LV_PART_MAIN);
    lv_obj_set_style_text_color(detail_label_, lv_color_hex(0xC9D2D8), LV_PART_MAIN);
    lv_obj_set_style_text_opa(detail_label_, LV_OPA_80, LV_PART_MAIN);
    lv_obj_set_width(detail_label_, 268);
    lv_obj_set_style_text_align(detail_label_, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
    lv_label_set_long_mode(detail_label_, LV_LABEL_LONG_WRAP);
    lv_obj_align(detail_label_, LV_ALIGN_CENTER, 0, kDetailReviewY);
    lv_obj_add_flag(detail_label_, LV_OBJ_FLAG_HIDDEN);

    const int slot_total_width = kInputSlotCount * kSlotWidth + (kInputSlotCount - 1) * kSlotGap;
    for (int index = 0; index < kInputSlotCount; ++index) {
        input_slot_labels_[index] = lv_label_create(root_);
        lv_obj_set_style_text_font(input_slot_labels_[index], &lv_font_montserrat_28, LV_PART_MAIN);
        lv_obj_set_style_text_color(input_slot_labels_[index], lv_color_hex(0xFFFFFF), LV_PART_MAIN);
        lv_obj_set_style_text_opa(input_slot_labels_[index], LV_OPA_90, LV_PART_MAIN);
        lv_obj_set_width(input_slot_labels_[index], kSlotWidth);
        lv_obj_set_style_text_align(input_slot_labels_[index], LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
        lv_label_set_long_mode(input_slot_labels_[index], LV_LABEL_LONG_CLIP);
        lv_obj_align(
            input_slot_labels_[index],
            LV_ALIGN_CENTER,
            -slot_total_width / 2 + index * (kSlotWidth + kSlotGap) + kSlotWidth / 2,
            kSlotY);
    }
    refresh_input_slot_layer();
}

void RuntimeApp::destroy_ui()
{
    if (root_ != nullptr) {
        lv_obj_delete(root_);
    }
    root_ = nullptr;
    for (lv_obj_t*& slot : input_slot_labels_) {
        slot = nullptr;
    }
    prompt_label_ = nullptr;
    detail_label_ = nullptr;
    rotary_dial_.destroy();
    dial_return_active_ = false;
    dial_return_last_ms_ = 0;
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

    update_input_slots();
    update_prompt_label();
    update_detail_label();
    rotary_dial_.set_visible(auth_entry_mode());
}

void RuntimeApp::handle_key_event(input::KeyEvent event, uint32_t now_ms)
{
    switch (event) {
        case input::KeyEvent::GoPrevious:
            if (!display_on_) {
                set_display_on(true, false, false);
                return;
            }
            if (screen_mode_ == ScreenMode::connect_review) {
                if (usb_transport_reject_pending_request("user_rejected")) {
                    enter_mode(ScreenMode::idle);
                    record_feedback(35, 70, false);
                } else {
                    record_feedback(60, 90, false);
                }
                return;
            }
            if (screen_mode_ == ScreenMode::proof_review) {
                if (usb_transport_reject_pending_request("user_rejected")) {
                    enter_mode(ScreenMode::idle);
                    record_feedback(35, 70, false);
                } else {
                    record_feedback(60, 90, false);
                }
                return;
            }
            if (screen_mode_ == ScreenMode::proof_clear_review) {
                enter_mode(ScreenMode::idle);
                record_feedback(25, 45, false);
                return;
            }
            if (screen_mode_ == ScreenMode::proof_clear_auth) {
                clear_entry();
                enter_mode(ScreenMode::proof_clear_review);
                record_feedback(25, 45, false);
                return;
            }
            if (auth_entry_mode()) {
                delete_digit(now_ms);
                return;
            }
            record_feedback(35, 70, false);
            break;
        case input::KeyEvent::GoNext:
            if (!display_on_) {
                set_display_on(true, false, false);
                return;
            }
            if (screen_mode_ == ScreenMode::connect_review) {
                if (usb_transport_approve_pending_request()) {
                    enter_mode(ScreenMode::idle);
                    record_feedback(45, 75, false);
                } else {
                    enter_mode(ScreenMode::idle);
                    record_feedback(80, 100, false);
                }
                return;
            }
            if (screen_mode_ == ScreenMode::proof_review) {
                usb_transport_poll();
                const UsbPendingRequest pending = usb_transport_pending_request();
                if (pending.kind != UsbPendingRequestKind::credential_propose) {
                    enter_mode(ScreenMode::idle);
                    record_feedback(45, 75, false);
                    return;
                }
                const SuiZkLoginProposalTransitionResult transition =
                    sui_zklogin_proposal_continue_to_auth(now_ms);
                if (transition == SuiZkLoginProposalTransitionResult::ok) {
                    clear_entry();
                    enter_mode(ScreenMode::proof_auth);
                    record_feedback(35, 65, false);
                } else {
                    record_feedback(80, 100, false);
                }
                return;
            }
            if (screen_mode_ == ScreenMode::proof_clear_review) {
                clear_entry();
                enter_mode(ScreenMode::proof_clear_auth);
                record_feedback(35, 65, false);
                return;
            }
            if (screen_mode_ == ScreenMode::idle && active_proof_clear_available()) {
                enter_mode(ScreenMode::proof_clear_review);
                record_feedback(25, 45, false);
                return;
            }
            submit_entry(now_ms);
            break;
        case input::KeyEvent::GoHome:
            if (!display_on_) {
                set_display_on(true, false, false);
                return;
            }
            record_feedback(60, 90, false);
            break;
        case input::KeyEvent::None:
            break;
    }
}

void RuntimeApp::handle_touch_poll(uint32_t now_ms)
{
    const Hal::TouchPoint point = GetHAL().getTouchPoint();
    const bool down = point.num > 0 && point.x >= 0 && point.y >= 0;
    if (!display_on_) {
        if (down) {
            set_display_on(true, false, false);
        }
        touch_down_ = down;
        touch_digit_ = -1;
        dial_return_active_ = false;
        return;
    }

    if (!auth_entry_mode()) {
        touch_down_ = down;
        touch_digit_ = -1;
        if (rotary_dial_.rotation_degrees() != 0.0F) {
            LvglLockGuard lock;
            rotary_dial_.reset();
        }
        return;
    }

    if (down && !touch_down_) {
        dial_return_active_ = false;
        if (rotary_dial_.rotation_degrees() != 0.0F) {
            LvglLockGuard lock;
            rotary_dial_.reset();
        }
        touch_down_ = true;
        touch_last_x_ = point.x;
        touch_last_y_ = point.y;
        touch_digit_ = -1;
        capture_touch_digit(point.x, point.y);
        {
            LvglLockGuard lock;
            update_input_slots();
        }
        return;
    }
    if (down && touch_down_) {
        if (touch_digit_ < 0) {
            capture_touch_digit(point.x, point.y);
            touch_last_x_ = point.x;
            touch_last_y_ = point.y;
            return;
        }
        if (touch_digit_ >= 0) {
            LvglLockGuard lock;
            rotary_dial_.advance_clockwise_from_touch(
                touch_last_x_,
                touch_last_y_,
                point.x,
                point.y,
                static_cast<char>(touch_digit_));
            refresh_input_slot_layer();
        }
        touch_last_x_ = point.x;
        touch_last_y_ = point.y;
        return;
    }
    if (!down && touch_down_) {
        handle_touch_release(now_ms);
        touch_down_ = false;
        touch_digit_ = -1;
        {
            LvglLockGuard lock;
            update_input_slots();
        }
    }
}

void RuntimeApp::handle_power_button(bool external_power_present)
{
    switch (GetHAL().readPowerButtonEvent()) {
        case Hal::PowerButtonEvent::shortClick:
            if (external_power_present) {
                set_display_on(!display_on_);
            }
            break;
        case Hal::PowerButtonEvent::none:
            break;
    }
}

void RuntimeApp::sync_power_button_policy(bool external_power_present)
{
    if (power_policy_synced_ && synced_external_power_present_ == external_power_present) {
        return;
    }
    if (GetHAL().setPowerButtonSingleClickResetEnabled(!external_power_present)) {
        synced_external_power_present_ = external_power_present;
        power_policy_synced_ = true;
    }
}

void RuntimeApp::set_display_on(bool display_on, bool feedback, bool lvgl_locked)
{
    if (display_on_ == display_on) {
        return;
    }

    if (display_on) {
        display_on_ = true;
        set_button_feedback_suppressed(false);
        const int brightness = display_restore_brightness_ > 0 ? display_restore_brightness_ : kDefaultBacklightBrightness;
        GetHAL().setBackLightBrightness(brightness, false);
        refresh_auth_mode();
        if (feedback) {
            GetHAL().vibrate(35, 70);
        }
        if (lvgl_locked) {
            rotary_dial_.reset();
            update_ui(true);
        } else {
            LvglLockGuard lock;
            rotary_dial_.reset();
            update_ui(true);
        }
        return;
    }

    relock();
    dial_return_active_ = false;
    if (lvgl_locked) {
        rotary_dial_.reset();
    } else {
        LvglLockGuard lock;
        rotary_dial_.reset();
    }
    const int current_brightness = GetHAL().getBackLightBrightness(false);
    if (current_brightness > 0) {
        display_restore_brightness_ = current_brightness;
    }
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

void RuntimeApp::record_feedback(
    uint16_t vibration_ms,
    uint8_t strength,
    bool lvgl_locked)
{
    if (!display_on_) {
        set_display_on(true, false, lvgl_locked);
    }

    GetHAL().vibrate(vibration_ms, strength);
    if (lvgl_locked) {
        update_ui(true);
    } else {
        LvglLockGuard lock;
        update_ui(true);
    }
}

void RuntimeApp::enter_mode(ScreenMode mode)
{
    if (screen_mode_ == mode) {
        return;
    }
    if (screen_mode_ == ScreenMode::setup_confirm && mode != ScreenMode::setup_confirm) {
        setup_state_.clear();
    }
    screen_mode_ = mode;
    last_update_ms_ = 0;
}

void RuntimeApp::refresh_auth_mode()
{
    const LocalAuthSnapshot snapshot = local_auth_snapshot(GetHAL().millis());
    if (snapshot.status == LocalAuthStoreStatus::missing) {
        locally_unlocked_ = false;
        if (screen_mode_ != ScreenMode::setup_enter && screen_mode_ != ScreenMode::setup_confirm) {
            enter_mode(ScreenMode::setup_enter);
        }
        return;
    }
    if (snapshot.status == LocalAuthStoreStatus::invalid ||
        snapshot.status == LocalAuthStoreStatus::storage_error) {
        locally_unlocked_ = false;
        enter_mode(ScreenMode::error);
        return;
    }
    if (snapshot.locked) {
        locally_unlocked_ = false;
        clear_entry();
        const UsbPendingRequest pending = usb_transport_pending_request();
        if (pending.kind != UsbPendingRequestKind::credential_propose) {
            usb_transport_reject_pending_request("auth_unavailable");
        }
        enter_mode(ScreenMode::lockout);
        return;
    }
    if (!locally_unlocked_) {
        if (screen_mode_ != ScreenMode::setup_enter && screen_mode_ != ScreenMode::setup_confirm) {
            enter_mode(ScreenMode::unlock);
        }
        return;
    }
    if (screen_mode_ == ScreenMode::unlock ||
        screen_mode_ == ScreenMode::lockout) {
        enter_mode(ScreenMode::idle);
    }
}

void RuntimeApp::sync_usb_runtime_state()
{
    const LocalAuthSnapshot snapshot = local_auth_snapshot(GetHAL().millis());
    LocalAuthProjectionStatus auth_status = LocalAuthProjectionStatus::missing;
    switch (snapshot.status) {
        case LocalAuthStoreStatus::active:
            auth_status = snapshot.locked ? LocalAuthProjectionStatus::locked : LocalAuthProjectionStatus::active;
            break;
        case LocalAuthStoreStatus::missing:
            auth_status = LocalAuthProjectionStatus::missing;
            break;
        case LocalAuthStoreStatus::invalid:
            auth_status = LocalAuthProjectionStatus::invalid;
            break;
        case LocalAuthStoreStatus::storage_error:
            auth_status = LocalAuthProjectionStatus::storage_error;
            break;
    }
    if (auth_status != LocalAuthProjectionStatus::active) {
        locally_unlocked_ = false;
    }
    const bool ui_busy = screen_mode_ == ScreenMode::connect_review ||
                         screen_mode_ == ScreenMode::proof_review ||
                         screen_mode_ == ScreenMode::proof_auth ||
                         screen_mode_ == ScreenMode::proof_clear_review ||
                         screen_mode_ == ScreenMode::proof_clear_auth;
    usb_transport_set_runtime_state(UsbRuntimeState{
        auth_status,
        locally_unlocked_,
        ui_busy,
    });
}

void RuntimeApp::relock()
{
    locally_unlocked_ = false;
    clear_auth_scratch();
    usb_transport_reject_pending_request("user_rejected");
    const LocalAuthSnapshot snapshot = local_auth_snapshot(GetHAL().millis());
    if (snapshot.status == LocalAuthStoreStatus::missing) {
        enter_mode(ScreenMode::setup_enter);
    } else if (snapshot.status == LocalAuthStoreStatus::active && snapshot.locked) {
        enter_mode(ScreenMode::lockout);
    } else if (snapshot.status == LocalAuthStoreStatus::active) {
        enter_mode(ScreenMode::unlock);
    } else {
        enter_mode(ScreenMode::error);
    }
}

void RuntimeApp::clear_entry()
{
    auth_entry_.clear();
}

void RuntimeApp::clear_auth_scratch()
{
    auth_entry_.clear();
    setup_state_.clear();
}

void RuntimeApp::append_digit(char digit, uint32_t now_ms)
{
    if (!auth_entry_mode()) {
        return;
    }
    if (auth_entry_.append(digit, now_ms)) {
        record_feedback(18, 45, false);
    }
}

void RuntimeApp::delete_digit(uint32_t now_ms)
{
    if (!auth_entry_mode()) {
        return;
    }
    if (auth_entry_.delete_last(now_ms)) {
        record_feedback(20, 45, false);
        return;
    }
    if (screen_mode_ == ScreenMode::setup_confirm) {
        setup_state_.clear();
        enter_mode(ScreenMode::setup_enter);
        record_feedback(25, 45, false);
    }
}

void RuntimeApp::submit_entry(uint32_t now_ms)
{
    if (screen_mode_ == ScreenMode::idle) {
        record_feedback(18, 35, false);
        return;
    }
    if (screen_mode_ == ScreenMode::lockout) {
        record_feedback(25, 45, false);
        return;
    }
    if (screen_mode_ == ScreenMode::error) {
        if (local_auth_clear()) {
            relock();
            enter_mode(ScreenMode::setup_enter);
            record_feedback(45, 75, false);
        } else {
            record_feedback(80, 100, false);
        }
        return;
    }
    if (!auth_entry_mode() ||
        auth_entry_.length() < kLocalAuthMinDigits ||
        auth_entry_.length() > kLocalAuthMaxDigits) {
        record_feedback(45, 90, false);
        return;
    }

    if (screen_mode_ == ScreenMode::setup_enter) {
        if (!setup_state_.set_first_entry(auth_entry_.code(), auth_entry_.length())) {
            clear_entry();
            enter_mode(ScreenMode::error);
            record_feedback(80, 100, false);
            return;
        }
        clear_entry();
        enter_mode(ScreenMode::setup_confirm);
        record_feedback(25, 55, false);
        return;
    }

    if (screen_mode_ == ScreenMode::setup_confirm) {
        const bool matches = setup_state_.matches(auth_entry_.code(), auth_entry_.length());
        setup_state_.clear();
        if (matches && local_auth_store_new_code(auth_entry_.code(), auth_entry_.length())) {
            clear_entry();
            locally_unlocked_ = true;
            enter_mode(ScreenMode::idle);
            record_feedback(45, 75, false);
            return;
        }
        clear_entry();
        enter_mode(matches ? ScreenMode::error : ScreenMode::setup_enter);
        record_feedback(65, 95, false);
        return;
    }

    if (screen_mode_ == ScreenMode::unlock) {
        const LocalAuthVerifyResult result = local_auth_verify_code(auth_entry_.code(), auth_entry_.length(), now_ms);
        clear_entry();
        switch (result) {
            case LocalAuthVerifyResult::verified:
                locally_unlocked_ = true;
                enter_mode(ScreenMode::idle);
                record_feedback(45, 75, false);
                return;
            case LocalAuthVerifyResult::rejected:
                locally_unlocked_ = false;
                enter_mode(ScreenMode::unlock);
                record_feedback(65, 95, false);
                return;
            case LocalAuthVerifyResult::locked:
                locally_unlocked_ = false;
                enter_mode(ScreenMode::lockout);
                record_feedback(80, 100, false);
                return;
            case LocalAuthVerifyResult::missing:
                locally_unlocked_ = false;
                enter_mode(ScreenMode::setup_enter);
                record_feedback(45, 75, false);
                return;
            case LocalAuthVerifyResult::invalid:
            case LocalAuthVerifyResult::storage_error:
                locally_unlocked_ = false;
                enter_mode(ScreenMode::error);
                record_feedback(80, 100, false);
                return;
        }
    }

    if (screen_mode_ == ScreenMode::proof_auth) {
        const LocalAuthVerifyResult result = local_auth_verify_code(auth_entry_.code(), auth_entry_.length(), now_ms);
        clear_entry();
        switch (result) {
            case LocalAuthVerifyResult::verified:
                if (usb_transport_approve_pending_request()) {
                    enter_mode(ScreenMode::idle);
                    record_feedback(45, 75, false);
                } else {
                    enter_mode(ScreenMode::idle);
                    record_feedback(80, 100, false);
                }
                return;
            case LocalAuthVerifyResult::rejected:
                enter_mode(ScreenMode::proof_auth);
                record_feedback(65, 95, false);
                return;
            case LocalAuthVerifyResult::locked:
                locally_unlocked_ = false;
                enter_mode(ScreenMode::lockout);
                record_feedback(80, 100, false);
                return;
            case LocalAuthVerifyResult::missing:
                locally_unlocked_ = false;
                usb_transport_reject_pending_request("auth_unavailable");
                enter_mode(ScreenMode::setup_enter);
                record_feedback(45, 75, false);
                return;
            case LocalAuthVerifyResult::invalid:
            case LocalAuthVerifyResult::storage_error:
                locally_unlocked_ = false;
                usb_transport_reject_pending_request("auth_unavailable");
                enter_mode(ScreenMode::error);
                record_feedback(80, 100, false);
                return;
        }
    }

    if (screen_mode_ == ScreenMode::proof_clear_auth) {
        const LocalAuthVerifyResult result = local_auth_verify_code(auth_entry_.code(), auth_entry_.length(), now_ms);
        clear_entry();
        switch (result) {
            case LocalAuthVerifyResult::verified:
                if (complete_active_proof_clear()) {
                    locally_unlocked_ = true;
                    enter_mode(ScreenMode::idle);
                    record_feedback(45, 75, false);
                } else {
                    enter_mode(ScreenMode::proof_clear_review);
                    record_feedback(80, 100, false);
                }
                return;
            case LocalAuthVerifyResult::rejected:
                enter_mode(ScreenMode::proof_clear_auth);
                record_feedback(65, 95, false);
                return;
            case LocalAuthVerifyResult::locked:
                locally_unlocked_ = false;
                enter_mode(ScreenMode::lockout);
                record_feedback(80, 100, false);
                return;
            case LocalAuthVerifyResult::missing:
                locally_unlocked_ = false;
                enter_mode(ScreenMode::setup_enter);
                record_feedback(45, 75, false);
                return;
            case LocalAuthVerifyResult::invalid:
            case LocalAuthVerifyResult::storage_error:
                locally_unlocked_ = false;
                enter_mode(ScreenMode::error);
                record_feedback(80, 100, false);
                return;
        }
    }
}

bool RuntimeApp::active_proof_clear_available() const
{
    return sui_zklogin_credential_status() == SuiZkLoginCredentialStatus::active;
}

bool RuntimeApp::complete_active_proof_clear()
{
    return sui_zklogin_clear_active_credential();
}

bool RuntimeApp::auth_entry_mode() const
{
    return screen_mode_ == ScreenMode::setup_enter ||
           screen_mode_ == ScreenMode::setup_confirm ||
           screen_mode_ == ScreenMode::unlock ||
           screen_mode_ == ScreenMode::proof_auth ||
           screen_mode_ == ScreenMode::proof_clear_auth;
}

bool RuntimeApp::input_timed_out(uint32_t now) const
{
    return auth_entry_mode() && auth_entry_.timed_out(now);
}

bool RuntimeApp::capture_touch_digit(int x, int y)
{
    if (touch_digit_ >= 0) {
        return false;
    }
    const int digit = rotary_dial_.digit_at_point(x, y);
    if (digit < 0) {
        return false;
    }
    touch_digit_ = digit;
    GetHAL().vibrate(kDialCaptureMs, kDialCaptureStrength);
    return true;
}

void RuntimeApp::refresh_input_slot_layer()
{
    if (prompt_label_ != nullptr) {
        lv_obj_move_foreground(prompt_label_);
        lv_obj_invalidate(prompt_label_);
    }
    if (detail_label_ != nullptr) {
        lv_obj_move_foreground(detail_label_);
        lv_obj_invalidate(detail_label_);
    }
    for (lv_obj_t* slot : input_slot_labels_) {
        if (slot == nullptr) {
            continue;
        }
        lv_obj_move_foreground(slot);
        lv_obj_invalidate(slot);
    }
}

void RuntimeApp::update_input_slots()
{
    const uint32_t now = GetHAL().millis();
    for (int index = 0; index < kInputSlotCount; ++index) {
        if (input_slot_labels_[index] == nullptr) {
            continue;
        }
        if (!auth_entry_mode()) {
            set_label_text(input_slot_labels_[index], "");
            lv_obj_add_flag(input_slot_labels_[index], LV_OBJ_FLAG_HIDDEN);
            continue;
        }
        lv_obj_remove_flag(input_slot_labels_[index], LV_OBJ_FLAG_HIDDEN);
        char text[2] = "_";
        lv_color_t color = lv_color_hex(0x7D8A95);
        lv_opa_t opacity = LV_OPA_50;
        if (static_cast<size_t>(index) < auth_entry_.length()) {
            color = lv_color_hex(0xFFFFFF);
            opacity = LV_OPA_90;
            const char digit = auth_entry_.digit_at(index);
            if (digit >= '0' && digit <= '9' && auth_entry_.digit_visible(index, now)) {
                text[0] = digit;
                color = lv_color_hex(0xB8E3FF);
            } else {
                text[0] = '*';
            }
        } else if (static_cast<size_t>(index) == auth_entry_.length() &&
                   auth_entry_.length() < kLocalAuthMaxDigits) {
            color = lv_color_hex(0xFFFFFF);
            opacity = LV_OPA_90;
        }
        lv_obj_set_style_text_color(input_slot_labels_[index], color, LV_PART_MAIN);
        lv_obj_set_style_text_opa(input_slot_labels_[index], opacity, LV_PART_MAIN);
        set_label_text(input_slot_labels_[index], text);
    }
    refresh_input_slot_layer();
}

void RuntimeApp::update_prompt_label()
{
    if (prompt_label_ == nullptr) {
        return;
    }

    const char* text = "";
    lv_color_t color = lv_color_hex(0xC9D2D8);
    const UsbIdentificationDisplay identification = usb_transport_identification_display();
    if (identification.active) {
        text = identification.code;
        color = lv_color_hex(0xB8E3FF);
        lv_obj_align(prompt_label_, LV_ALIGN_CENTER, 0, kPromptSceneY);
        lv_obj_set_style_text_color(prompt_label_, color, LV_PART_MAIN);
        set_label_text(prompt_label_, text);
        lv_obj_move_foreground(prompt_label_);
        lv_obj_invalidate(prompt_label_);
        return;
    }
    switch (screen_mode_) {
        case ScreenMode::setup_enter:
            text = "SET";
            break;
        case ScreenMode::setup_confirm:
            text = "AGAIN";
            break;
        case ScreenMode::unlock:
            text = "UNLOCK";
            break;
        case ScreenMode::idle:
            text = "IDLE";
            color = lv_color_hex(0x7D8A95);
            break;
        case ScreenMode::connect_review:
            text = "LINK?";
            color = lv_color_hex(0xB8E3FF);
            break;
        case ScreenMode::proof_review:
            text = "PROOF";
            color = lv_color_hex(0xB8E3FF);
            break;
        case ScreenMode::proof_auth:
            text = "CHECK";
            color = lv_color_hex(0xB8E3FF);
            break;
        case ScreenMode::proof_clear_review:
            text = "CLEAR?";
            color = lv_color_hex(0xFFCA7A);
            break;
        case ScreenMode::proof_clear_auth:
            text = "CHECK";
            color = lv_color_hex(0xFFCA7A);
            break;
        case ScreenMode::lockout:
            text = "WAIT";
            color = lv_color_hex(0xFFCA7A);
            break;
        case ScreenMode::error:
            text = "ERR";
            color = lv_color_hex(0xFF8A8A);
            break;
    }
    const bool review_mode = screen_mode_ == ScreenMode::connect_review ||
                             screen_mode_ == ScreenMode::proof_review ||
                             screen_mode_ == ScreenMode::proof_clear_review;
    lv_obj_align(
        prompt_label_,
        LV_ALIGN_CENTER,
        0,
        auth_entry_mode() ? kPromptAuthY : (review_mode ? kPromptReviewY : kPromptSceneY));
    lv_obj_set_style_text_color(prompt_label_, color, LV_PART_MAIN);
    set_label_text(prompt_label_, text);
    lv_obj_move_foreground(prompt_label_);
    lv_obj_invalidate(prompt_label_);
}

void RuntimeApp::update_detail_label()
{
    if (detail_label_ == nullptr) {
        return;
    }

    char text[320] = {};
    lv_color_t color = lv_color_hex(0xC9D2D8);
    if (screen_mode_ == ScreenMode::connect_review) {
        const UsbPendingRequest pending = usb_transport_pending_request();
        snprintf(
            text,
            sizeof(text),
            "Client\n%s\nA reject  B approve",
            pending.label[0] != '\0' ? pending.label : "USB host");
        color = lv_color_hex(0xB8E3FF);
    } else if (screen_mode_ == ScreenMode::proof_review) {
        const SuiZkLoginProposalSnapshot snapshot =
            sui_zklogin_proposal_state_snapshot();
        char address_preview[28] = {};
        char proof_preview[24] = {};
        copy_middle_elided(snapshot.address, address_preview, sizeof(address_preview), 8, 6);
        copy_proof_hash_preview(snapshot.proof_hash, proof_preview, sizeof(proof_preview));
        snprintf(
            text,
            sizeof(text),
            "%s\n%s\n%s\nEpoch %s\nProof %s\nA reject  B approve",
            snapshot.network != nullptr ? snapshot.network : "",
            snapshot.issuer != nullptr ? snapshot.issuer : "",
            address_preview,
            snapshot.max_epoch != nullptr ? snapshot.max_epoch : "",
            proof_preview);
        color = lv_color_hex(0xB8E3FF);
    } else if (screen_mode_ == ScreenMode::proof_clear_review) {
        snprintf(text, sizeof(text), "Clear zkLogin proof\nA cancel  B continue");
        color = lv_color_hex(0xFFCA7A);
    } else {
        lv_obj_add_flag(detail_label_, LV_OBJ_FLAG_HIDDEN);
        set_label_text(detail_label_, "");
        return;
    }

    lv_obj_remove_flag(detail_label_, LV_OBJ_FLAG_HIDDEN);
    lv_obj_set_style_text_color(detail_label_, color, LV_PART_MAIN);
    set_label_text(detail_label_, text);
    lv_obj_move_foreground(detail_label_);
    lv_obj_invalidate(detail_label_);
}

void RuntimeApp::handle_touch_release(uint32_t now_ms)
{
    if (touch_digit_ >= 0) {
        const char digit = static_cast<char>(touch_digit_);
        if (rotary_dial_.digit_reached_stop(digit)) {
            append_digit(digit, now_ms);
        } else {
            record_feedback(18, 35, false);
        }
        start_dial_return();
        return;
    }
}

void RuntimeApp::start_dial_return()
{
    dial_return_active_ = rotary_dial_.rotation_degrees() > 0.5F || rotary_dial_.rotation_degrees() < -0.5F;
    dial_return_last_ms_ = 0;
}

void RuntimeApp::animate_dial_return(uint32_t now)
{
    if (!dial_return_active_ || !display_on_) {
        return;
    }
    if (dial_return_last_ms_ != 0 && now - dial_return_last_ms_ < kDialReturnFrameMs) {
        return;
    }
    dial_return_last_ms_ = now;

    const float current = rotary_dial_.rotation_degrees();
    const float computed_step = kDialReturnBaseStepDegrees + fabsf(current) * kDialReturnDistanceFactor;
    const float step = computed_step < kDialReturnMaxStepDegrees ? computed_step : kDialReturnMaxStepDegrees;
    float next = 0.0F;
    if (current > step) {
        next = current - step;
    } else if (current < -step) {
        next = current + step;
    } else {
        dial_return_active_ = false;
    }

    LvglLockGuard lock;
    rotary_dial_.set_rotation_degrees(next, next == 0.0F);
    update_input_slots();
    if (next != 0.0F) {
        GetHAL().vibrate(kDialReturnTickMs, kDialReturnTickStrength);
    }
}

}  // namespace stopwatch_target
