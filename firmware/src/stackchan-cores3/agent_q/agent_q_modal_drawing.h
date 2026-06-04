#pragma once

#include "agent_q_drawing_surface.h"
#include "agent_q_signature_request_review_view_model.h"
#include "lvgl.h"

namespace agent_q {

struct AgentQModalDrawingCallbacks {
    lv_event_cb_t on_yes_clicked = nullptr;
    lv_event_cb_t on_no_clicked = nullptr;
    lv_event_cb_t on_setup_generate_clicked = nullptr;
    lv_event_cb_t on_setup_recover_clicked = nullptr;
    lv_event_cb_t on_setup_cancel_clicked = nullptr;
    lv_event_cb_t on_settings_cancel_clicked = nullptr;
    lv_event_cb_t on_settings_connect_pin_clicked = nullptr;
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
    lv_event_cb_t on_signature_review_accept_clicked = nullptr;
    lv_event_cb_t on_signature_review_reject_clicked = nullptr;
};

void modal_drawing_set_callbacks(const AgentQModalDrawingCallbacks& callbacks);

bool modal_draw_decision_panel();
bool modal_draw_setup_choice_panel();
bool modal_draw_recover_word_entry_panel(const char* notice = nullptr);
bool modal_draw_recovery_phrase_display(const char* recovery_phrase);
bool modal_draw_pin_setup_panel(const char* notice = nullptr);
bool modal_draw_settings_menu_panel();
bool modal_draw_error_recovery_panel(bool confirm);
bool modal_draw_reset_pin_panel(const char* notice = nullptr);
bool modal_draw_local_pin_auth_panel(const char* notice = nullptr);
bool modal_draw_signature_request_review_panel(
    const AgentQSignatureRequestReviewViewModel& model);
bool modal_draw_processing_overlay_on_current_panel(AgentQUiPanelKind expected_kind);

}  // namespace agent_q
