#pragma once

#include <stdint.h>

#include "transport/connect_approval.h"
#include "drawing_surface.h"
#include "lvgl.h"

namespace signing {

enum class UiEventKind {
    panel_deleted,
    setup_requested,
    setup_generate_requested,
    setup_import_requested,
    setup_cancel_requested,
    ui_surface_ready,
    settings_requested,
    chain_settings_requested,
    chain_settings_sui_requested,
    settings_cancel_requested,
    settings_human_approval_input_requested,
    settings_signing_mode_requested,
    settings_policy_reset_requested,
    settings_change_pin_requested,
    settings_wallet_erase_requested,
    settings_local_transport_pairing_requested,
    local_transport_pairing_cancel_requested,
    sui_settings_back_requested,
    sui_settings_gas_sponsor_requested,
    sui_settings_clear_requested,
    error_recovery_action_requested,
    error_recovery_cancel_requested,
    storage_action_cancel_requested,
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
    user_signing_review_scroll_started,
    user_signing_review_scroll_finished,
};

struct UiEvent {
    UiEventKind kind = UiEventKind::panel_deleted;
    UiPanelKind panel_kind = UiPanelKind::none;
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

bool ui_event_bridge_receive(UiEvent* event);
bool ui_event_bridge_receive_connect_choice(ConnectApprovalChoice* choice);
void ui_event_bridge_reset_connect_choices();

}  // namespace signing
