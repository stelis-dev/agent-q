#include "ui_event_bridge.h"

#include "bip39.h"
#include "modal_drawing.h"
#include "provisioning_flow.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "lvgl.h"

namespace signing {

namespace {

constexpr const char* kTag = "UiEventBridge";
constexpr UBaseType_t kQueueDepth = 4;

QueueHandle_t g_connect_review_choice_queue = nullptr;
QueueHandle_t g_ui_event_queue = nullptr;

void enqueue_connect_review_choice(ConnectApprovalChoice choice)
{
    if (choice == ConnectApprovalChoice::none || g_connect_review_choice_queue == nullptr) {
        return;
    }
    if (xQueueSend(g_connect_review_choice_queue, &choice, 0) != pdTRUE) {
        ESP_LOGW(kTag, "Pending choice queue is full");
    }
}

void enqueue_ui_event(UiEventKind kind, UiPanelKind panel_kind = UiPanelKind::none)
{
    if (g_ui_event_queue == nullptr) {
        return;
    }

    UiEvent event;
    event.kind = kind;
    event.panel_kind = panel_kind;
    if (xQueueSend(g_ui_event_queue, &event, 0) != pdTRUE) {
        ESP_LOGW(kTag, "UI event queue is full");
    }
}

void on_connect_review_accept_clicked(lv_event_t*)
{
    enqueue_connect_review_choice(ConnectApprovalChoice::approved);
}

void on_connect_review_reject_clicked(lv_event_t*)
{
    enqueue_connect_review_choice(ConnectApprovalChoice::rejected);
}

void on_user_signing_review_accept_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::user_signing_review_accept_requested);
}

void on_user_signing_review_reject_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::user_signing_review_reject_requested);
}

void on_user_signing_review_scroll_started(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::user_signing_review_scroll_started);
}

void on_user_signing_review_scroll_finished(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::user_signing_review_scroll_finished);
}

void on_policy_update_review_continue_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::policy_update_review_continue_requested);
}

void on_policy_update_review_reject_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::policy_update_review_reject_requested);
}

void on_sui_zklogin_review_continue_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::sui_zklogin_review_continue_requested);
}

void on_sui_zklogin_review_reject_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::sui_zklogin_review_reject_requested);
}

void on_setup_generate_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::setup_generate_requested);
}

void on_setup_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::setup_requested);
}

void on_setup_import_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::setup_import_requested);
}

void on_setup_cancel_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::setup_cancel_requested);
}

void on_settings_cancel_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::settings_cancel_requested);
}

void on_settings_wallet_erase_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::settings_wallet_erase_requested);
}

void on_settings_local_transport_pairing_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::settings_local_transport_pairing_requested);
}

void on_local_transport_pairing_cancel_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::local_transport_pairing_cancel_requested);
}

void on_settings_human_approval_input_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::settings_human_approval_input_requested);
}

void on_settings_signing_mode_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::settings_signing_mode_requested);
}

void on_settings_policy_reset_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::settings_policy_reset_requested);
}

void on_settings_change_pin_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::settings_change_pin_requested);
}

void on_chain_settings_sui_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::chain_settings_sui_requested);
}

void on_sui_settings_back_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::sui_settings_back_requested);
}

void on_sui_settings_gas_sponsor_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::sui_settings_gas_sponsor_requested);
}

void on_sui_settings_clear_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::sui_settings_clear_requested);
}

void on_error_recovery_action_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::error_recovery_action_requested);
}

void on_error_recovery_cancel_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::error_recovery_cancel_requested);
}

void on_storage_action_cancel_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::storage_action_cancel_requested);
}

void on_backup_phrase_cancel_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::backup_phrase_cancel_requested);
}

void on_backup_phrase_confirm_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::backup_phrase_confirm_requested);
}

void on_pin_digit_clicked(lv_event_t* event)
{
    const char* digit = static_cast<const char*>(lv_event_get_user_data(event));
    if (digit == nullptr || digit[0] < '0' || digit[0] > '9' || g_ui_event_queue == nullptr) {
        return;
    }

    UiEvent ui_event;
    ui_event.kind = UiEventKind::pin_digit_requested;
    ui_event.digit = digit[0];
    if (xQueueSend(g_ui_event_queue, &ui_event, 0) != pdTRUE) {
        ESP_LOGW(kTag, "UI event queue is full");
    }
}

void on_pin_clear_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::pin_clear_requested);
}

void on_pin_backspace_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::pin_backspace_requested);
}

void on_pin_submit_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::pin_submit_requested);
}

void on_pin_cancel_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::pin_cancel_requested);
}

void on_import_slot_clicked(lv_event_t* event)
{
    const uint8_t* slot = static_cast<const uint8_t*>(lv_event_get_user_data(event));
    if (slot == nullptr || *slot >= kProvisioningFlowImportWordsPerPage ||
        g_ui_event_queue == nullptr) {
        return;
    }

    UiEvent ui_event;
    ui_event.kind = UiEventKind::import_slot_requested;
    ui_event.slot = *slot;
    if (xQueueSend(g_ui_event_queue, &ui_event, 0) != pdTRUE) {
        ESP_LOGW(kTag, "UI event queue is full");
    }
}

void on_import_letter_clicked(lv_event_t* event)
{
    const char* letter = static_cast<const char*>(lv_event_get_user_data(event));
    if (letter == nullptr || letter[0] < 'a' || letter[0] > 'z' || g_ui_event_queue == nullptr) {
        return;
    }

    UiEvent ui_event;
    ui_event.kind = UiEventKind::import_letter_requested;
    ui_event.letter = letter[0];
    if (xQueueSend(g_ui_event_queue, &ui_event, 0) != pdTRUE) {
        ESP_LOGW(kTag, "UI event queue is full");
    }
}

void on_import_candidate_clicked(lv_event_t* event)
{
    const uint16_t* word_index = static_cast<const uint16_t*>(lv_event_get_user_data(event));
    if (word_index == nullptr || *word_index >= kBip39WordCount || g_ui_event_queue == nullptr) {
        return;
    }

    UiEvent ui_event;
    ui_event.kind = UiEventKind::import_candidate_requested;
    ui_event.word_index = *word_index;
    if (xQueueSend(g_ui_event_queue, &ui_event, 0) != pdTRUE) {
        ESP_LOGW(kTag, "UI event queue is full");
    }
}

void on_import_clear_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::import_clear_requested);
}

void on_import_previous_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::import_previous_requested);
}

void on_import_next_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::import_next_requested);
}

void on_import_cancel_clicked(lv_event_t*)
{
    enqueue_ui_event(UiEventKind::import_cancel_requested);
}

void on_panel_deleted(UiPanelKind deleted_kind)
{
    enqueue_ui_event(UiEventKind::panel_deleted, deleted_kind);
}

}  // namespace

bool ui_event_bridge_init()
{
    if (g_connect_review_choice_queue == nullptr) {
        g_connect_review_choice_queue = xQueueCreate(kQueueDepth, sizeof(ConnectApprovalChoice));
        if (g_connect_review_choice_queue == nullptr) {
            return false;
        }
    } else {
        xQueueReset(g_connect_review_choice_queue);
    }

    if (g_ui_event_queue == nullptr) {
        g_ui_event_queue = xQueueCreate(kQueueDepth, sizeof(UiEvent));
        if (g_ui_event_queue == nullptr) {
            return false;
        }
    } else {
        xQueueReset(g_ui_event_queue);
    }

    return true;
}

void ui_event_bridge_reset()
{
    ui_event_bridge_reset_connect_choices();
    if (g_ui_event_queue != nullptr) {
        xQueueReset(g_ui_event_queue);
    }
}

void ui_event_bridge_register_callbacks()
{
    drawing_surface_set_panel_deleted_callback(on_panel_deleted);

    ModalDrawingCallbacks modal_callbacks;
    modal_callbacks.on_connect_review_accept_clicked = on_connect_review_accept_clicked;
    modal_callbacks.on_connect_review_reject_clicked = on_connect_review_reject_clicked;
    modal_callbacks.on_setup_generate_clicked = on_setup_generate_clicked;
    modal_callbacks.on_setup_import_clicked = on_setup_import_clicked;
    modal_callbacks.on_setup_cancel_clicked = on_setup_cancel_clicked;
    modal_callbacks.on_settings_cancel_clicked = on_settings_cancel_clicked;
    modal_callbacks.on_settings_human_approval_input_clicked = on_settings_human_approval_input_clicked;
    modal_callbacks.on_settings_signing_mode_clicked = on_settings_signing_mode_clicked;
    modal_callbacks.on_settings_policy_reset_clicked = on_settings_policy_reset_clicked;
    modal_callbacks.on_settings_change_pin_clicked = on_settings_change_pin_clicked;
    modal_callbacks.on_settings_wallet_erase_clicked = on_settings_wallet_erase_clicked;
    modal_callbacks.on_settings_local_transport_pairing_clicked =
        on_settings_local_transport_pairing_clicked;
    modal_callbacks.on_local_transport_pairing_cancel_clicked =
        on_local_transport_pairing_cancel_clicked;
    modal_callbacks.on_chain_settings_sui_clicked = on_chain_settings_sui_clicked;
    modal_callbacks.on_sui_settings_back_clicked = on_sui_settings_back_clicked;
    modal_callbacks.on_sui_settings_gas_sponsor_clicked = on_sui_settings_gas_sponsor_clicked;
    modal_callbacks.on_sui_settings_clear_clicked = on_sui_settings_clear_clicked;
    modal_callbacks.on_error_recovery_action_clicked = on_error_recovery_action_clicked;
    modal_callbacks.on_error_recovery_cancel_clicked = on_error_recovery_cancel_clicked;
    modal_callbacks.on_storage_action_cancel_clicked = on_storage_action_cancel_clicked;
    modal_callbacks.on_backup_phrase_cancel_clicked = on_backup_phrase_cancel_clicked;
    modal_callbacks.on_backup_phrase_confirm_clicked = on_backup_phrase_confirm_clicked;
    modal_callbacks.on_pin_digit_clicked = on_pin_digit_clicked;
    modal_callbacks.on_pin_clear_clicked = on_pin_clear_clicked;
    modal_callbacks.on_pin_backspace_clicked = on_pin_backspace_clicked;
    modal_callbacks.on_pin_submit_clicked = on_pin_submit_clicked;
    modal_callbacks.on_pin_cancel_clicked = on_pin_cancel_clicked;
    modal_callbacks.on_import_slot_clicked = on_import_slot_clicked;
    modal_callbacks.on_import_letter_clicked = on_import_letter_clicked;
    modal_callbacks.on_import_candidate_clicked = on_import_candidate_clicked;
    modal_callbacks.on_import_clear_clicked = on_import_clear_clicked;
    modal_callbacks.on_import_previous_clicked = on_import_previous_clicked;
    modal_callbacks.on_import_next_clicked = on_import_next_clicked;
    modal_callbacks.on_import_cancel_clicked = on_import_cancel_clicked;
    modal_callbacks.on_policy_update_review_continue_clicked = on_policy_update_review_continue_clicked;
    modal_callbacks.on_policy_update_review_reject_clicked = on_policy_update_review_reject_clicked;
    modal_callbacks.on_sui_zklogin_review_continue_clicked = on_sui_zklogin_review_continue_clicked;
    modal_callbacks.on_sui_zklogin_review_reject_clicked = on_sui_zklogin_review_reject_clicked;
    modal_callbacks.on_user_signing_review_accept_clicked = on_user_signing_review_accept_clicked;
    modal_callbacks.on_user_signing_review_reject_clicked = on_user_signing_review_reject_clicked;
    modal_callbacks.on_user_signing_review_scroll_started = on_user_signing_review_scroll_started;
    modal_callbacks.on_user_signing_review_scroll_finished = on_user_signing_review_scroll_finished;
    modal_drawing_set_callbacks(modal_callbacks);
}

void ui_event_bridge_enqueue_surface_ready()
{
    enqueue_ui_event(UiEventKind::ui_surface_ready);
}

void ui_event_bridge_enqueue_settings_requested()
{
    enqueue_ui_event(UiEventKind::settings_requested);
}

void ui_event_bridge_enqueue_chain_settings_requested()
{
    enqueue_ui_event(UiEventKind::chain_settings_requested);
}

lv_event_cb_t ui_event_bridge_setup_clicked_callback()
{
    return on_setup_clicked;
}

bool ui_event_bridge_receive(UiEvent* event)
{
    return event != nullptr &&
           g_ui_event_queue != nullptr &&
           xQueueReceive(g_ui_event_queue, event, 0) == pdTRUE;
}

bool ui_event_bridge_receive_connect_choice(ConnectApprovalChoice* choice)
{
    return choice != nullptr &&
           g_connect_review_choice_queue != nullptr &&
           xQueueReceive(g_connect_review_choice_queue, choice, 0) == pdTRUE;
}

void ui_event_bridge_reset_connect_choices()
{
    if (g_connect_review_choice_queue != nullptr) {
        xQueueReset(g_connect_review_choice_queue);
    }
}

}  // namespace signing
