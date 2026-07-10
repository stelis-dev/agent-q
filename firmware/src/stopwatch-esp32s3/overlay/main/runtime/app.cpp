#include "app.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#include <hal/hal.h>
#include <mooncake_log.h>
#include <smooth_lvgl.hpp>

#include "credential_preparation_state.h"
#include "device_reset.h"
#include "display_geometry.h"
#include "policy/policy_store.h"
#include "policy/policy_update_flow.h"
#include "policy/policy_update_marker.h"
#include "protocol/approval_history.h"
#include "protocol/signing_mode.h"
#include "secure_random.h"
#include "protocol/session_state.h"
#include "sui_zklogin_credential_store.h"
#include "sui_zklogin_proposal_state.h"
#include "transport/payload_delivery_store.h"

namespace stopwatch_target {
namespace {

constexpr const char* kAppName = "Device";
constexpr uint32_t kUiRefreshMs = 250;
constexpr uint32_t kUnlockWatchDelayMs = 60U * 1000U;
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

bool wipe_setup_settings()
{
    const bool policy_wiped = signing::wipe_policy();
    const bool signing_mode_wiped = signing::wipe_signing_authorization_mode();
    const bool history_wiped = signing::approval_history_wipe();
    const bool marker_cleared = signing::policy_update_marker_clear();
    return policy_wiped && signing_mode_wiped && history_wiped && marker_cleared;
}

bool store_new_auth_and_default_settings(const char* code, size_t length)
{
    if (code == nullptr ||
        length < kLocalAuthMinDigits ||
        length > kLocalAuthMaxDigits) {
        return false;
    }
    if (!signing::store_default_policy()) {
        return false;
    }
    if (!signing::store_signing_authorization_mode(signing::AuthorizationMode::user)) {
        wipe_setup_settings();
        usb_transport_invalidate_projected_state_cache();
        return false;
    }
    if (!signing::approval_history_wipe() ||
        !signing::policy_update_marker_clear()) {
        wipe_setup_settings();
        usb_transport_invalidate_projected_state_cache();
        return false;
    }
    if (!local_auth_store_new_code(code, length)) {
        local_auth_clear();
        wipe_setup_settings();
        usb_transport_invalidate_projected_state_cache();
        return false;
    }
    usb_transport_invalidate_projected_state_cache();
    return true;
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
    signing::session_init();
    credential_preparation_state_init();
    signing::payload_delivery_store_reset();
    sui_zklogin_proposal_state_init();
    secure_random_init();
    usb_transport_init();
    display_on_ = true;
    locally_unlocked_ = false;
    button_feedback_suppressed_ = false;
    saved_button_config_ = GetHAL().getButtonConfig();
    display_restore_brightness_ = kDefaultBacklightBrightness;
    GetHAL().setBackLightBrightness(display_restore_brightness_, false);
    const bool external_power_present = GetHAL().isExternalPowerPresent();
    sync_power_button_policy(external_power_present);
    previous_external_power_present_ = external_power_present;

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
    if (usb_transport_projected_device_state_is_error()) {
        screen_mode_ = ScreenMode::error;
    }

    LvglLockGuard lock;
    create_ui();
    update_ui(true);
}

void RuntimeApp::onRunning()
{
    const bool external_power_present = GetHAL().isExternalPowerPresent();
    if (previous_external_power_present_ != external_power_present) {
        relock();
        if (!display_on_) {
            set_display_on(true, false, false);
        }
    }
    previous_external_power_present_ = external_power_present;

    const uint32_t now = GetHAL().millis();

    if (key_manager_) {
        const input::KeyEvent key_event = key_manager_->update();
        sync_power_button_policy(external_power_present);
        const bool power_button_handled = handle_power_button(external_power_present);
        if (!power_button_handled) {
            handle_key_event(key_event, now);
        }
    }

    handle_touch_poll(now);
    animate_dial_return(now);

    const LocalAuthSnapshot snapshot = local_auth_snapshot(now);
    sync_usb_runtime_state(snapshot);
    usb_transport_poll();
    if (usb_transport_identification_display().active && !display_on_) {
        set_display_on(true, false, false);
    }
    refresh_auth_mode(snapshot);
    maybe_enter_watch(now);
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
    } else if (pending.kind == UsbPendingRequestKind::policy_propose) {
        if (!display_on_) {
            set_display_on(true, false, false);
        }
        if (locally_unlocked_ && screen_mode_ == ScreenMode::idle) {
            enter_mode(ScreenMode::policy_review);
        }
    } else if (pending.kind == UsbPendingRequestKind::sign_transaction ||
               pending.kind == UsbPendingRequestKind::sign_personal_message) {
        if (!display_on_) {
            set_display_on(true, false, false);
        }
        if (locally_unlocked_ && screen_mode_ == ScreenMode::idle) {
            enter_mode(ScreenMode::signing_review);
        }
    } else if (screen_mode_ == ScreenMode::connect_review ||
               screen_mode_ == ScreenMode::proof_review ||
               screen_mode_ == ScreenMode::signing_review ||
               screen_mode_ == ScreenMode::policy_review ||
               screen_mode_ == ScreenMode::proof_auth ||
               screen_mode_ == ScreenMode::policy_auth) {
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

    sync_usb_runtime_state(snapshot);
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
    lv_obj_set_size(root_, kDisplaySizePx, kDisplaySizePx);
    lv_obj_align(root_, LV_ALIGN_CENTER, 0, 0);
    lv_obj_set_style_bg_color(root_, lv_color_hex(0x050607), LV_PART_MAIN);
    lv_obj_set_style_border_width(root_, 0, LV_PART_MAIN);
    lv_obj_set_style_radius(root_, kDisplayCenterPx, LV_PART_MAIN);
    lv_obj_set_style_pad_all(root_, 0, LV_PART_MAIN);
    lv_obj_clear_flag(root_, LV_OBJ_FLAG_SCROLLABLE);

    rotary_dial_.create(root_);
    clock_scene_.create(root_);

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
    rotary_dial_.destroy();
    clock_scene_.destroy();
    if (root_ != nullptr) {
        lv_obj_delete(root_);
    }
    root_ = nullptr;
    for (lv_obj_t*& slot : input_slot_labels_) {
        slot = nullptr;
    }
    prompt_label_ = nullptr;
    detail_label_ = nullptr;
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
    rotary_dial_.set_visible(auth_entry_mode() && !watch_visible_);
    clock_scene_.set_visible(watch_visible_);
    clock_scene_.update(now);
}

void RuntimeApp::handle_key_event(input::KeyEvent event, uint32_t now_ms)
{
    if (event != input::KeyEvent::None &&
        display_on_ &&
        watch_visible_) {
        const bool touch_was_down = touch_down_;
        reset_unlock_watch();
        if (touch_was_down) {
            ignore_touch_until_release_ = true;
        }
        record_feedback(20, 45, false);
        return;
    }

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
            if (screen_mode_ == ScreenMode::policy_review) {
                if (usb_transport_reject_pending_request("user_rejected")) {
                    enter_mode(ScreenMode::idle);
                    record_feedback(35, 70, false);
                } else {
                    record_feedback(60, 90, false);
                }
                return;
            }
            if (screen_mode_ == ScreenMode::signing_mode_review) {
                enter_mode(ScreenMode::idle);
                record_feedback(25, 45, false);
                return;
            }
            if (screen_mode_ == ScreenMode::signing_review) {
                if (usb_transport_reject_pending_request("user_rejected")) {
                    enter_mode(ScreenMode::idle);
                    record_feedback(35, 70, false);
                } else {
                    record_feedback(60, 90, false);
                }
                return;
            }
            if (screen_mode_ == ScreenMode::device_reset_review) {
                enter_mode(ScreenMode::idle);
                record_feedback(25, 45, false);
                return;
            }
            if (screen_mode_ == ScreenMode::device_reset_auth) {
                clear_entry();
                enter_mode(ScreenMode::device_reset_review);
                record_feedback(25, 45, false);
                return;
            }
            if (screen_mode_ == ScreenMode::policy_auth) {
                clear_entry();
                enter_mode(ScreenMode::policy_review);
                record_feedback(25, 45, false);
                return;
            }
            if (screen_mode_ == ScreenMode::signing_mode_auth) {
                clear_entry();
                enter_mode(ScreenMode::signing_mode_review);
                record_feedback(25, 45, false);
                return;
            }
            if (screen_mode_ == ScreenMode::idle) {
                enter_mode(ScreenMode::signing_mode_review);
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
            if (screen_mode_ == ScreenMode::policy_review) {
                usb_transport_poll();
                const UsbPendingRequest pending = usb_transport_pending_request();
                if (pending.kind != UsbPendingRequestKind::policy_propose) {
                    enter_mode(ScreenMode::idle);
                    record_feedback(45, 75, false);
                    return;
                }
                const signing::PolicyUpdateFlowTransitionResult transition =
                    signing::policy_update_flow_continue_to_pin(now_ms);
                if (transition == signing::PolicyUpdateFlowTransitionResult::ok) {
                    clear_entry();
                    enter_mode(ScreenMode::policy_auth);
                    record_feedback(35, 65, false);
                } else {
                    record_feedback(80, 100, false);
                }
                return;
            }
            if (screen_mode_ == ScreenMode::signing_mode_review) {
                signing::AuthorizationMode current_mode = signing::AuthorizationMode::user;
                if (!signing::read_signing_authorization_mode(&current_mode)) {
                    record_feedback(80, 100, false);
                    return;
                }
                pending_signing_mode_ = current_mode == signing::AuthorizationMode::policy
                                            ? signing::AuthorizationMode::user
                                            : signing::AuthorizationMode::policy;
                clear_entry();
                enter_mode(ScreenMode::signing_mode_auth);
                record_feedback(35, 65, false);
                return;
            }
            if (screen_mode_ == ScreenMode::signing_review) {
                if (usb_transport_approve_pending_request()) {
                    enter_mode(ScreenMode::idle);
                    record_feedback(45, 75, false);
                } else {
                    enter_mode(ScreenMode::idle);
                    record_feedback(80, 100, false);
                }
                return;
            }
            if (screen_mode_ == ScreenMode::device_reset_review) {
                clear_entry();
                enter_mode(ScreenMode::device_reset_auth);
                record_feedback(35, 65, false);
                return;
            }
            if (screen_mode_ == ScreenMode::idle) {
                enter_mode(ScreenMode::device_reset_review);
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
        touch_down_ = down;
        touch_digit_ = -1;
        dial_return_active_ = false;
        return;
    }

    if (watch_visible_) {
        if (down) {
            ignore_touch_until_release_ = true;
        }
        touch_down_ = down;
        touch_digit_ = -1;
        dial_return_active_ = false;
        return;
    }

    if (ignore_touch_until_release_) {
        touch_down_ = down;
        touch_digit_ = -1;
        if (!down) {
            ignore_touch_until_release_ = false;
        }
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

bool RuntimeApp::handle_power_button(bool external_power_present)
{
    switch (GetHAL().readPowerButtonEvent()) {
        case Hal::PowerButtonEvent::shortClick:
            if (!external_power_present) {
                return false;
            }
            set_display_on(!display_on_);
            return true;
        case Hal::PowerButtonEvent::none:
            return false;
    }
    return false;
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
        ignore_touch_until_release_ = true;
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
    reset_unlock_watch();
    last_update_ms_ = 0;
}

void RuntimeApp::reset_unlock_watch()
{
    unlock_idle_started_ms_ = 0;
    unlock_watch_timer_armed_ = false;
    watch_visible_ = false;
    ignore_touch_until_release_ = false;
    last_update_ms_ = 0;
}

void RuntimeApp::show_unlock_watch()
{
    if (watch_visible_) {
        return;
    }
    watch_visible_ = true;
    unlock_watch_timer_armed_ = false;
    last_update_ms_ = 0;
}

bool RuntimeApp::unlock_watch_allowed() const
{
    const UsbPendingRequest pending = usb_transport_pending_request();
    const UsbIdentificationDisplay identification = usb_transport_identification_display();
    const bool request_prompt_active = pending.kind != UsbPendingRequestKind::none ||
                                       identification.active;
    return screen_mode_ == ScreenMode::unlock &&
           display_on_ &&
           !locally_unlocked_ &&
           auth_entry_.length() == 0 &&
           !dial_return_active_ &&
           !request_prompt_active;
}

void RuntimeApp::refresh_auth_mode()
{
    const LocalAuthSnapshot snapshot = local_auth_snapshot(GetHAL().millis());
    refresh_auth_mode(snapshot);
}

void RuntimeApp::refresh_auth_mode(const LocalAuthSnapshot& snapshot)
{
    sync_usb_runtime_state(snapshot);
    if (usb_transport_projected_device_state_is_error()) {
        locally_unlocked_ = false;
        enter_mode(ScreenMode::error);
        return;
    }
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
        if (screen_mode_ != ScreenMode::setup_enter &&
            screen_mode_ != ScreenMode::setup_confirm &&
            screen_mode_ != ScreenMode::unlock) {
            enter_mode(ScreenMode::unlock);
        }
        return;
    }
    if (screen_mode_ == ScreenMode::unlock ||
        screen_mode_ == ScreenMode::lockout) {
        enter_mode(ScreenMode::idle);
    }
}

void RuntimeApp::maybe_enter_watch(uint32_t now_ms)
{
    const bool state_allows_watch = unlock_watch_allowed();
    if (watch_visible_) {
        if (!state_allows_watch) {
            const bool touch_was_down = touch_down_;
            reset_unlock_watch();
            if (touch_was_down) {
                ignore_touch_until_release_ = true;
            }
        }
        return;
    }

    if (!state_allows_watch) {
        unlock_watch_timer_armed_ = false;
        unlock_idle_started_ms_ = 0;
        return;
    }
    if (!unlock_watch_timer_armed_) {
        unlock_idle_started_ms_ = now_ms;
        unlock_watch_timer_armed_ = true;
        return;
    }
    if (now_ms - unlock_idle_started_ms_ >= kUnlockWatchDelayMs) {
        show_unlock_watch();
    }
}

void RuntimeApp::sync_usb_runtime_state()
{
    const LocalAuthSnapshot snapshot = local_auth_snapshot(GetHAL().millis());
    sync_usb_runtime_state(snapshot);
}

void RuntimeApp::sync_usb_runtime_state(const LocalAuthSnapshot& snapshot)
{
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
                         screen_mode_ == ScreenMode::policy_review ||
                         screen_mode_ == ScreenMode::signing_review ||
                         screen_mode_ == ScreenMode::signing_mode_review ||
                         screen_mode_ == ScreenMode::proof_auth ||
                         screen_mode_ == ScreenMode::policy_auth ||
                         screen_mode_ == ScreenMode::signing_mode_auth ||
                         screen_mode_ == ScreenMode::device_reset_review ||
                         screen_mode_ == ScreenMode::device_reset_auth;
    usb_transport_set_runtime_state(UsbRuntimeState{
        auth_status,
        locally_unlocked_,
        ui_busy,
    });
}

void RuntimeApp::relock()
{
    locally_unlocked_ = false;
    reset_unlock_watch();
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
    pending_signing_mode_ = signing::AuthorizationMode::user;
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
        if (complete_device_reset()) {
            locally_unlocked_ = false;
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
        if (matches && store_new_auth_and_default_settings(auth_entry_.code(), auth_entry_.length())) {
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

    if (screen_mode_ == ScreenMode::policy_auth) {
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
                enter_mode(ScreenMode::policy_auth);
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

    if (screen_mode_ == ScreenMode::signing_mode_auth) {
        const LocalAuthVerifyResult result = local_auth_verify_code(auth_entry_.code(), auth_entry_.length(), now_ms);
        clear_entry();
        switch (result) {
            case LocalAuthVerifyResult::verified:
                if (signing::store_signing_authorization_mode(pending_signing_mode_)) {
                    usb_transport_invalidate_projected_state_cache();
                    locally_unlocked_ = true;
                    enter_mode(ScreenMode::idle);
                    record_feedback(45, 75, false);
                } else {
                    usb_transport_invalidate_projected_state_cache();
                    enter_mode(ScreenMode::signing_mode_review);
                    record_feedback(80, 100, false);
                }
                return;
            case LocalAuthVerifyResult::rejected:
                enter_mode(ScreenMode::signing_mode_auth);
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

    if (screen_mode_ == ScreenMode::device_reset_auth) {
        const LocalAuthVerifyResult result = local_auth_verify_code(auth_entry_.code(), auth_entry_.length(), now_ms);
        clear_entry();
        switch (result) {
            case LocalAuthVerifyResult::verified:
                if (complete_device_reset()) {
                    locally_unlocked_ = false;
                    enter_mode(ScreenMode::setup_enter);
                    record_feedback(45, 75, false);
                } else {
                    enter_mode(ScreenMode::device_reset_review);
                    record_feedback(80, 100, false);
                }
                return;
            case LocalAuthVerifyResult::rejected:
                enter_mode(ScreenMode::device_reset_auth);
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

bool RuntimeApp::complete_device_reset()
{
    clear_auth_scratch();
    const bool reset = device_reset_all();
    usb_transport_invalidate_projected_state_cache();
    return reset;
}

bool RuntimeApp::auth_entry_mode() const
{
    return screen_mode_ == ScreenMode::setup_enter ||
           screen_mode_ == ScreenMode::setup_confirm ||
           screen_mode_ == ScreenMode::unlock ||
           screen_mode_ == ScreenMode::proof_auth ||
           screen_mode_ == ScreenMode::policy_auth ||
           screen_mode_ == ScreenMode::signing_mode_auth ||
           screen_mode_ == ScreenMode::device_reset_auth;
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
        if (!auth_entry_mode() || watch_visible_) {
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

    if (watch_visible_) {
        lv_obj_add_flag(prompt_label_, LV_OBJ_FLAG_HIDDEN);
        set_label_text(prompt_label_, "");
        return;
    }

    const char* text = "";
    lv_color_t color = lv_color_hex(0xC9D2D8);
    const UsbIdentificationDisplay identification = usb_transport_identification_display();
    if (identification.active) {
        text = identification.code;
        color = lv_color_hex(0xB8E3FF);
        lv_obj_remove_flag(prompt_label_, LV_OBJ_FLAG_HIDDEN);
        lv_obj_align(prompt_label_, LV_ALIGN_CENTER, 0, kPromptSceneY);
        lv_obj_set_style_text_color(prompt_label_, color, LV_PART_MAIN);
        set_label_text(prompt_label_, text);
        lv_obj_move_foreground(prompt_label_);
        lv_obj_invalidate(prompt_label_);
        return;
    }
    const UsbSigningNotice signing_notice = usb_transport_signing_notice();
    if (screen_mode_ == ScreenMode::idle && signing_notice.active) {
        switch (signing_notice.kind) {
            case UsbSigningNoticeKind::rejected:
                text = "REJECT";
                color = lv_color_hex(0xFFCA7A);
                break;
            case UsbSigningNoticeKind::error:
                text = "ERROR";
                color = lv_color_hex(0xFF8A8A);
                break;
            case UsbSigningNoticeKind::success:
                text = "SIGNED";
                color = lv_color_hex(0x9BE7B5);
                break;
            case UsbSigningNoticeKind::info:
            default:
                text = "POLICY";
                color = lv_color_hex(0xB8E3FF);
                break;
        }
        lv_obj_remove_flag(prompt_label_, LV_OBJ_FLAG_HIDDEN);
        lv_obj_align(prompt_label_, LV_ALIGN_CENTER, 0, kPromptReviewY);
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
        case ScreenMode::signing_review:
            text = "SIGN?";
            color = lv_color_hex(0xB8E3FF);
            break;
        case ScreenMode::policy_review:
            text = "POLICY";
            color = lv_color_hex(0xB8E3FF);
            break;
        case ScreenMode::signing_mode_review:
            text = "MODE";
            color = lv_color_hex(0xB8E3FF);
            break;
        case ScreenMode::proof_auth:
        case ScreenMode::policy_auth:
        case ScreenMode::signing_mode_auth:
            text = "CHECK";
            color = lv_color_hex(0xB8E3FF);
            break;
        case ScreenMode::device_reset_review:
            text = "RESET?";
            color = lv_color_hex(0xFFCA7A);
            break;
        case ScreenMode::device_reset_auth:
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
                             screen_mode_ == ScreenMode::signing_review ||
                             screen_mode_ == ScreenMode::policy_review ||
                             screen_mode_ == ScreenMode::signing_mode_review ||
                             screen_mode_ == ScreenMode::device_reset_review;
    lv_obj_remove_flag(prompt_label_, LV_OBJ_FLAG_HIDDEN);
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

    if (watch_visible_) {
        set_label_text(detail_label_, "");
        lv_obj_add_flag(detail_label_, LV_OBJ_FLAG_HIDDEN);
        return;
    }

    char text[320] = {};
    lv_color_t color = lv_color_hex(0xC9D2D8);
    const UsbSigningNotice signing_notice = usb_transport_signing_notice();
    if (screen_mode_ == ScreenMode::idle && signing_notice.active) {
        snprintf(
            text,
            sizeof(text),
            "%s",
            signing_notice.message[0] != '\0' ? signing_notice.message : "Signing result");
        switch (signing_notice.kind) {
            case UsbSigningNoticeKind::rejected:
                color = lv_color_hex(0xFFCA7A);
                break;
            case UsbSigningNoticeKind::error:
                color = lv_color_hex(0xFF8A8A);
                break;
            case UsbSigningNoticeKind::success:
                color = lv_color_hex(0x9BE7B5);
                break;
            case UsbSigningNoticeKind::info:
            default:
                color = lv_color_hex(0xB8E3FF);
                break;
        }
    } else if (screen_mode_ == ScreenMode::connect_review) {
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
    } else if (screen_mode_ == ScreenMode::signing_review) {
        const UsbPendingRequest pending = usb_transport_pending_request();
        snprintf(
            text,
            sizeof(text),
            "%s\nA reject  B sign",
            pending.label[0] != '\0' ? pending.label : "Sui request");
        color = lv_color_hex(0xB8E3FF);
    } else if (screen_mode_ == ScreenMode::policy_review) {
        const signing::PolicyUpdateFlowSnapshot snapshot =
            signing::policy_update_flow_snapshot();
        char policy_preview[24] = {};
        copy_middle_elided(
            snapshot.policy_hash != nullptr ? snapshot.policy_hash : "",
            policy_preview,
            sizeof(policy_preview),
            10,
            6);
        snprintf(
            text,
            sizeof(text),
            "%s\n%s\n%s\n%s\nA reject  B approve",
            snapshot.scope_summary != nullptr && snapshot.scope_summary[0] != '\0'
                ? snapshot.scope_summary
                : "Policy update",
            snapshot.review_summary != nullptr && snapshot.review_summary[0] != '\0'
                ? snapshot.review_summary
                : "Review changes",
            snapshot.highest_action != nullptr && snapshot.highest_action[0] != '\0'
                ? snapshot.highest_action
                : "Action",
            policy_preview);
        color = lv_color_hex(0xB8E3FF);
    } else if (screen_mode_ == ScreenMode::signing_mode_review) {
        signing::AuthorizationMode current_mode = signing::AuthorizationMode::user;
        const bool mode_available = signing::read_signing_authorization_mode(&current_mode);
        const signing::AuthorizationMode next_mode =
            current_mode == signing::AuthorizationMode::policy
                ? signing::AuthorizationMode::user
                : signing::AuthorizationMode::policy;
        snprintf(
            text,
            sizeof(text),
            "%s\nCurrent %s\nB set %s\nA cancel",
            mode_available ? "Signing mode" : "Mode unavailable",
            signing::authorization_mode_name(current_mode),
            signing::authorization_mode_name(next_mode));
        color = lv_color_hex(0xB8E3FF);
    } else if (screen_mode_ == ScreenMode::device_reset_review) {
        snprintf(text, sizeof(text), "Reset device\nA cancel  B reset");
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
