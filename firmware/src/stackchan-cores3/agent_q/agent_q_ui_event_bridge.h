#pragma once

#include <stdint.h>

#include "agent_q_connect_approval.h"
#include "agent_q_drawing_surface.h"
#include "lvgl.h"

namespace agent_q {

enum class AgentQUiEventKind {
    panel_deleted,
    setup_requested,
    setup_generate_requested,
    setup_import_requested,
    setup_cancel_requested,
    ui_surface_ready,
    settings_requested,
    chain_settings_requested,
    settings_cancel_requested,
    settings_human_approval_input_requested,
    settings_signing_mode_requested,
    settings_policy_reset_requested,
    settings_change_pin_requested,
    settings_reset_requested,
    sui_settings_back_requested,
    sui_settings_clear_requested,
    error_recovery_erase_requested,
    error_recovery_cancel_requested,
    reset_cancel_requested,
    backup_phrase_cancel_requested,
    backup_phrase_confirm_requested,
    pin_digit_requested,
    pin_clear_requested,
    pin_backspace_requested,
    pin_submit_requested,
    pin_cancel_requested,
    import_slot_requested,
    import_letter_requested,
    import_clear_requested,
    import_candidate_requested,
    import_previous_requested,
    import_next_requested,
    import_cancel_requested,
    policy_update_review_continue_requested,
    policy_update_review_reject_requested,
    sui_zklogin_review_continue_requested,
    sui_zklogin_review_reject_requested,
    user_signing_review_accept_requested,
    user_signing_review_reject_requested,
};

struct AgentQUiEvent {
    AgentQUiEventKind kind = AgentQUiEventKind::panel_deleted;
    AgentQUiPanelKind panel_kind = AgentQUiPanelKind::none;
    char digit = '\0';
    char letter = '\0';
    uint8_t slot = 0;
    uint16_t word_index = 0;
};

bool ui_event_bridge_init();
void ui_event_bridge_reset();
void ui_event_bridge_register_callbacks();

void ui_event_bridge_enqueue_surface_ready();
void ui_event_bridge_enqueue_settings_requested();
void ui_event_bridge_enqueue_chain_settings_requested();
lv_event_cb_t ui_event_bridge_setup_clicked_callback();

bool ui_event_bridge_receive(AgentQUiEvent* event);
bool ui_event_bridge_receive_connect_choice(AgentQConnectApprovalChoice* choice);
void ui_event_bridge_reset_connect_choices();

}  // namespace agent_q
