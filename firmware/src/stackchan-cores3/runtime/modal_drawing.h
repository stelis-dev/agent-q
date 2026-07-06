#pragma once

#include <stddef.h>

#include "drawing_surface.h"
#include "human_approval_settings.h"
#include "transport/timeout_window.h"
#include "user_signing_review_view_model.h"
#include "signing/user_signing_review_timer_state.h"
#include "lvgl.h"

namespace signing {

struct ModalDrawingCallbacks {
    lv_event_cb_t on_connect_review_accept_clicked = nullptr;
    lv_event_cb_t on_connect_review_reject_clicked = nullptr;
    lv_event_cb_t on_setup_generate_clicked = nullptr;
    lv_event_cb_t on_setup_import_clicked = nullptr;
    lv_event_cb_t on_setup_cancel_clicked = nullptr;
    lv_event_cb_t on_settings_cancel_clicked = nullptr;
    lv_event_cb_t on_settings_human_approval_input_clicked = nullptr;
    lv_event_cb_t on_settings_signing_mode_clicked = nullptr;
    lv_event_cb_t on_settings_policy_reset_clicked = nullptr;
    lv_event_cb_t on_settings_change_pin_clicked = nullptr;
    lv_event_cb_t on_settings_wallet_erase_clicked = nullptr;
    lv_event_cb_t on_chain_settings_sui_clicked = nullptr;
    lv_event_cb_t on_sui_settings_back_clicked = nullptr;
    lv_event_cb_t on_sui_settings_gas_sponsor_clicked = nullptr;
    lv_event_cb_t on_sui_settings_clear_clicked = nullptr;
    lv_event_cb_t on_error_recovery_action_clicked = nullptr;
    lv_event_cb_t on_error_recovery_cancel_clicked = nullptr;
    lv_event_cb_t on_storage_action_cancel_clicked = nullptr;
    lv_event_cb_t on_backup_phrase_cancel_clicked = nullptr;
    lv_event_cb_t on_backup_phrase_confirm_clicked = nullptr;
    lv_event_cb_t on_pin_digit_clicked = nullptr;
    lv_event_cb_t on_pin_clear_clicked = nullptr;
    lv_event_cb_t on_pin_backspace_clicked = nullptr;
    lv_event_cb_t on_pin_submit_clicked = nullptr;
    lv_event_cb_t on_pin_cancel_clicked = nullptr;
    lv_event_cb_t on_import_slot_clicked = nullptr;
    lv_event_cb_t on_import_letter_clicked = nullptr;
    lv_event_cb_t on_import_candidate_clicked = nullptr;
    lv_event_cb_t on_import_clear_clicked = nullptr;
    lv_event_cb_t on_import_previous_clicked = nullptr;
    lv_event_cb_t on_import_next_clicked = nullptr;
    lv_event_cb_t on_import_cancel_clicked = nullptr;
    lv_event_cb_t on_policy_update_review_continue_clicked = nullptr;
    lv_event_cb_t on_policy_update_review_reject_clicked = nullptr;
    lv_event_cb_t on_sui_zklogin_review_continue_clicked = nullptr;
    lv_event_cb_t on_sui_zklogin_review_reject_clicked = nullptr;
    lv_event_cb_t on_user_signing_review_accept_clicked = nullptr;
    lv_event_cb_t on_user_signing_review_reject_clicked = nullptr;
    lv_event_cb_t on_user_signing_review_scroll_started = nullptr;
    lv_event_cb_t on_user_signing_review_scroll_finished = nullptr;
};

struct PolicyUpdateReviewViewModel {
    const char* policy_hash = nullptr;
    size_t blockchain_count = 0;
    size_t network_count = 0;
    size_t policy_count = 0;
    size_t condition_count = 0;
    const char* default_action = nullptr;
    const char* highest_action = nullptr;
    const char* scope_summary = nullptr;
    const char* review_summary = nullptr;
};

struct SuiZkLoginReviewViewModel {
    const char* network = nullptr;
    const char* address = nullptr;
    const char* issuer = nullptr;
    const char* max_epoch = nullptr;
    const char* proof_hash = nullptr;
    const char* effect_summary = nullptr;
};

struct SuiSettingsViewModel {
    const char* account_kind = nullptr;
    const char* address = nullptr;
    const char* proof_status = nullptr;
    const char* max_epoch = nullptr;
    const char* proof_hash = nullptr;
    const char* gas_sponsor_status = nullptr;
    bool gas_sponsor_toggle_available = false;
    bool clear_available = false;
};

void modal_drawing_set_callbacks(const ModalDrawingCallbacks& callbacks);

bool modal_draw_connect_review_panel(
    const char* client_name,
    HumanApprovalInputMode input_mode,
    TimeoutWindow timeout_window);
bool modal_draw_setup_choice_panel();
bool modal_draw_import_word_entry_panel(const char* notice = nullptr);
bool modal_draw_backup_phrase_display(const char* backup_phrase);
bool modal_draw_pin_setup_panel(const char* notice = nullptr);
bool modal_draw_settings_menu_panel();
bool modal_draw_chain_settings_menu_panel();
bool modal_draw_sui_settings_panel(const SuiSettingsViewModel& model);
bool modal_draw_error_recovery_panel(bool confirm);
bool modal_draw_action_pin_panel(const char* notice = nullptr);
bool modal_draw_local_pin_auth_panel(const char* notice = nullptr);
bool modal_draw_policy_update_review_panel(
    const PolicyUpdateReviewViewModel& model,
    TimeoutWindow timeout_window);
bool modal_draw_sui_zklogin_review_panel(
    const SuiZkLoginReviewViewModel& model,
    TimeoutWindow timeout_window);
bool modal_draw_user_signing_review_panel(
    const UserSigningReviewViewModel& model,
    UserSigningReviewTimerState timer);
bool modal_draw_user_signing_review_timer(UserSigningReviewTimerState timer);
bool modal_draw_processing_overlay_on_current_panel(UiPanelKind expected_kind);

}  // namespace signing
