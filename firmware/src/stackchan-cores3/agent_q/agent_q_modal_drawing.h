#pragma once

#include <stddef.h>

#include "agent_q_drawing_surface.h"
#include "agent_q_human_approval_settings.h"
#include "agent_q_timeout_window.h"
#include "agent_q_user_signing_review_view_model.h"
#include "lvgl.h"

namespace agent_q {

struct AgentQModalDrawingCallbacks {
    lv_event_cb_t on_connect_review_accept_clicked = nullptr;
    lv_event_cb_t on_connect_review_reject_clicked = nullptr;
    lv_event_cb_t on_setup_generate_clicked = nullptr;
    lv_event_cb_t on_setup_recover_clicked = nullptr;
    lv_event_cb_t on_setup_cancel_clicked = nullptr;
    lv_event_cb_t on_settings_cancel_clicked = nullptr;
    lv_event_cb_t on_settings_human_approval_input_clicked = nullptr;
    lv_event_cb_t on_settings_signing_mode_clicked = nullptr;
    lv_event_cb_t on_settings_change_pin_clicked = nullptr;
    lv_event_cb_t on_settings_reset_clicked = nullptr;
    lv_event_cb_t on_error_recovery_erase_clicked = nullptr;
    lv_event_cb_t on_error_recovery_cancel_clicked = nullptr;
    lv_event_cb_t on_reset_cancel_clicked = nullptr;
    lv_event_cb_t on_recovery_phrase_cancel_clicked = nullptr;
    lv_event_cb_t on_recovery_phrase_confirm_clicked = nullptr;
    lv_event_cb_t on_pin_digit_clicked = nullptr;
    lv_event_cb_t on_pin_clear_clicked = nullptr;
    lv_event_cb_t on_pin_backspace_clicked = nullptr;
    lv_event_cb_t on_pin_submit_clicked = nullptr;
    lv_event_cb_t on_pin_cancel_clicked = nullptr;
    lv_event_cb_t on_recover_slot_clicked = nullptr;
    lv_event_cb_t on_recover_letter_clicked = nullptr;
    lv_event_cb_t on_recover_candidate_clicked = nullptr;
    lv_event_cb_t on_recover_clear_clicked = nullptr;
    lv_event_cb_t on_recover_previous_clicked = nullptr;
    lv_event_cb_t on_recover_next_clicked = nullptr;
    lv_event_cb_t on_recover_cancel_clicked = nullptr;
    lv_event_cb_t on_policy_update_review_continue_clicked = nullptr;
    lv_event_cb_t on_policy_update_review_reject_clicked = nullptr;
    lv_event_cb_t on_user_signing_review_accept_clicked = nullptr;
    lv_event_cb_t on_user_signing_review_reject_clicked = nullptr;
};

struct AgentQPolicyUpdateReviewViewModel {
    const char* policy_hash = nullptr;
    size_t rule_count = 0;
    const char* default_action = nullptr;
    const char* highest_action = nullptr;
    const char* method_summary = nullptr;
    const char* review_summary = nullptr;
};

void modal_drawing_set_callbacks(const AgentQModalDrawingCallbacks& callbacks);

bool modal_draw_connect_review_panel(
    const char* gateway_name,
    AgentQHumanApprovalInputMode input_mode,
    AgentQTimeoutWindow timeout_window);
bool modal_draw_setup_choice_panel();
bool modal_draw_recover_word_entry_panel(const char* notice = nullptr);
bool modal_draw_recovery_phrase_display(const char* recovery_phrase);
bool modal_draw_pin_setup_panel(const char* notice = nullptr);
bool modal_draw_settings_menu_panel();
bool modal_draw_error_recovery_panel(bool confirm);
bool modal_draw_reset_pin_panel(const char* notice = nullptr);
bool modal_draw_local_pin_auth_panel(const char* notice = nullptr);
bool modal_draw_policy_update_review_panel(
    const AgentQPolicyUpdateReviewViewModel& model,
    AgentQTimeoutWindow timeout_window);
bool modal_draw_user_signing_review_panel(
    const AgentQUserSigningReviewViewModel& model,
    AgentQTimeoutWindow timeout_window);
bool modal_draw_processing_overlay_on_current_panel(AgentQUiPanelKind expected_kind);

}  // namespace agent_q
