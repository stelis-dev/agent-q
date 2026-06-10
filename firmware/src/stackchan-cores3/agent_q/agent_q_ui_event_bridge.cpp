#include "agent_q_ui_event_bridge.h"

#include "agent_q_bip39.h"
#include "agent_q_modal_drawing.h"
#include "agent_q_provisioning_flow.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "lvgl.h"

namespace agent_q {

namespace {

constexpr const char* kTag = "AgentQUiEventBridge";
constexpr UBaseType_t kQueueDepth = 4;

QueueHandle_t g_connect_review_choice_queue = nullptr;
QueueHandle_t g_ui_event_queue = nullptr;

void enqueue_connect_review_choice(AgentQConnectApprovalChoice choice)
{
    if (choice == AgentQConnectApprovalChoice::none || g_connect_review_choice_queue == nullptr) {
        return;
    }
    if (xQueueSend(g_connect_review_choice_queue, &choice, 0) != pdTRUE) {
        ESP_LOGW(kTag, "Pending choice queue is full");
    }
}

void enqueue_ui_event(AgentQUiEventKind kind, AgentQUiPanelKind panel_kind = AgentQUiPanelKind::none)
{
    if (g_ui_event_queue == nullptr) {
        return;
    }

    AgentQUiEvent event;
    event.kind = kind;
    event.panel_kind = panel_kind;
    if (xQueueSend(g_ui_event_queue, &event, 0) != pdTRUE) {
        ESP_LOGW(kTag, "UI event queue is full");
    }
}

void on_connect_review_accept_clicked(lv_event_t*)
{
    enqueue_connect_review_choice(AgentQConnectApprovalChoice::approved);
}

void on_connect_review_reject_clicked(lv_event_t*)
{
    enqueue_connect_review_choice(AgentQConnectApprovalChoice::rejected);
}

void on_user_signing_review_accept_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::user_signing_review_accept_requested);
}

void on_user_signing_review_reject_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::user_signing_review_reject_requested);
}

void on_policy_update_review_continue_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::policy_update_review_continue_requested);
}

void on_policy_update_review_reject_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::policy_update_review_reject_requested);
}

void on_setup_generate_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::setup_generate_requested);
}

void on_setup_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::setup_requested);
}

void on_setup_import_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::setup_import_requested);
}

void on_setup_cancel_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::setup_cancel_requested);
}

void on_settings_cancel_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::settings_cancel_requested);
}

void on_settings_reset_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::settings_reset_requested);
}

void on_settings_human_approval_input_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::settings_human_approval_input_requested);
}

void on_settings_signing_mode_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::settings_signing_mode_requested);
}

void on_settings_change_pin_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::settings_change_pin_requested);
}

void on_error_recovery_erase_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::error_recovery_erase_requested);
}

void on_error_recovery_cancel_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::error_recovery_cancel_requested);
}

void on_reset_cancel_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::reset_cancel_requested);
}

void on_backup_phrase_cancel_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::backup_phrase_cancel_requested);
}

void on_backup_phrase_confirm_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::backup_phrase_confirm_requested);
}

void on_pin_digit_clicked(lv_event_t* event)
{
    const char* digit = static_cast<const char*>(lv_event_get_user_data(event));
    if (digit == nullptr || digit[0] < '0' || digit[0] > '9' || g_ui_event_queue == nullptr) {
        return;
    }

    AgentQUiEvent ui_event;
    ui_event.kind = AgentQUiEventKind::pin_digit_requested;
    ui_event.digit = digit[0];
    if (xQueueSend(g_ui_event_queue, &ui_event, 0) != pdTRUE) {
        ESP_LOGW(kTag, "UI event queue is full");
    }
}

void on_pin_clear_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::pin_clear_requested);
}

void on_pin_backspace_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::pin_backspace_requested);
}

void on_pin_submit_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::pin_submit_requested);
}

void on_pin_cancel_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::pin_cancel_requested);
}

void on_import_slot_clicked(lv_event_t* event)
{
    const uint8_t* slot = static_cast<const uint8_t*>(lv_event_get_user_data(event));
    if (slot == nullptr || *slot >= kProvisioningFlowImportWordsPerPage ||
        g_ui_event_queue == nullptr) {
        return;
    }

    AgentQUiEvent ui_event;
    ui_event.kind = AgentQUiEventKind::import_slot_requested;
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

    AgentQUiEvent ui_event;
    ui_event.kind = AgentQUiEventKind::import_letter_requested;
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

    AgentQUiEvent ui_event;
    ui_event.kind = AgentQUiEventKind::import_candidate_requested;
    ui_event.word_index = *word_index;
    if (xQueueSend(g_ui_event_queue, &ui_event, 0) != pdTRUE) {
        ESP_LOGW(kTag, "UI event queue is full");
    }
}

void on_import_clear_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::import_clear_requested);
}

void on_import_previous_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::import_previous_requested);
}

void on_import_next_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::import_next_requested);
}

void on_import_cancel_clicked(lv_event_t*)
{
    enqueue_ui_event(AgentQUiEventKind::import_cancel_requested);
}

void on_panel_deleted(AgentQUiPanelKind deleted_kind)
{
    enqueue_ui_event(AgentQUiEventKind::panel_deleted, deleted_kind);
}

}  // namespace

bool ui_event_bridge_init()
{
    if (g_connect_review_choice_queue == nullptr) {
        g_connect_review_choice_queue = xQueueCreate(kQueueDepth, sizeof(AgentQConnectApprovalChoice));
        if (g_connect_review_choice_queue == nullptr) {
            return false;
        }
    } else {
        xQueueReset(g_connect_review_choice_queue);
    }

    if (g_ui_event_queue == nullptr) {
        g_ui_event_queue = xQueueCreate(kQueueDepth, sizeof(AgentQUiEvent));
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

    AgentQModalDrawingCallbacks modal_callbacks;
    modal_callbacks.on_connect_review_accept_clicked = on_connect_review_accept_clicked;
    modal_callbacks.on_connect_review_reject_clicked = on_connect_review_reject_clicked;
    modal_callbacks.on_setup_generate_clicked = on_setup_generate_clicked;
    modal_callbacks.on_setup_import_clicked = on_setup_import_clicked;
    modal_callbacks.on_setup_cancel_clicked = on_setup_cancel_clicked;
    modal_callbacks.on_settings_cancel_clicked = on_settings_cancel_clicked;
    modal_callbacks.on_settings_human_approval_input_clicked = on_settings_human_approval_input_clicked;
    modal_callbacks.on_settings_signing_mode_clicked = on_settings_signing_mode_clicked;
    modal_callbacks.on_settings_change_pin_clicked = on_settings_change_pin_clicked;
    modal_callbacks.on_settings_reset_clicked = on_settings_reset_clicked;
    modal_callbacks.on_error_recovery_erase_clicked = on_error_recovery_erase_clicked;
    modal_callbacks.on_error_recovery_cancel_clicked = on_error_recovery_cancel_clicked;
    modal_callbacks.on_reset_cancel_clicked = on_reset_cancel_clicked;
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
    modal_callbacks.on_user_signing_review_accept_clicked = on_user_signing_review_accept_clicked;
    modal_callbacks.on_user_signing_review_reject_clicked = on_user_signing_review_reject_clicked;
    modal_drawing_set_callbacks(modal_callbacks);
}

void ui_event_bridge_enqueue_surface_ready()
{
    enqueue_ui_event(AgentQUiEventKind::ui_surface_ready);
}

void ui_event_bridge_enqueue_settings_requested()
{
    enqueue_ui_event(AgentQUiEventKind::settings_requested);
}

lv_event_cb_t ui_event_bridge_setup_clicked_callback()
{
    return on_setup_clicked;
}

bool ui_event_bridge_receive(AgentQUiEvent* event)
{
    return event != nullptr &&
           g_ui_event_queue != nullptr &&
           xQueueReceive(g_ui_event_queue, event, 0) == pdTRUE;
}

bool ui_event_bridge_receive_connect_choice(AgentQConnectApprovalChoice* choice)
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

}  // namespace agent_q
