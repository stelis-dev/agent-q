#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: firmware/tools/stackchan-cores3/test_ui_event_bridge.sh

Compiles the UI event bridge with small LVGL/FreeRTOS stubs and verifies that
registered callbacks enqueue the expected internal events. It does not require
hardware.
EOF
}

if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
AGENT_Q_DIR="${REPO_ROOT}/firmware/src/stackchan-cores3/agent_q"
COMMON_ROOT="${REPO_ROOT}/firmware/src/common/agent_q"
CXX_BIN="${CXX:-c++}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-q-ui-event-bridge.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/stubs/freertos"

cat >"${TMP_DIR}/stubs/lvgl.h" <<'H'
#pragma once
struct lv_event_t {
    void* user_data;
};
using lv_event_cb_t = void (*)(lv_event_t*);
struct lv_area_t {
    int x1;
    int y1;
    int x2;
    int y2;
};
struct lv_obj_t {};
inline void* lv_event_get_user_data(lv_event_t* event)
{
    return event != nullptr ? event->user_data : nullptr;
}
H

cat >"${TMP_DIR}/stubs/esp_log.h" <<'H'
#pragma once
#define ESP_LOGW(tag, fmt, ...) \
    do {                        \
        (void)(tag);            \
        (void)(fmt);            \
    } while (0)
H

cat >"${TMP_DIR}/stubs/agent_q_bip39.h" <<'H'
#pragma once
#include <stddef.h>
namespace agent_q {
constexpr size_t kBip39WordCount = 2048;
}
H

cat >"${TMP_DIR}/stubs/agent_q_provisioning_flow.h" <<'H'
#pragma once
#include <stddef.h>
namespace agent_q {
constexpr size_t kProvisioningFlowImportWordsPerPage = 3;
}
H

cat >"${TMP_DIR}/stubs/agent_q_modal_drawing.h" <<'H'
#pragma once

#include "agent_q_drawing_surface.h"
#include "lvgl.h"

namespace agent_q {

struct AgentQModalDrawingCallbacks {
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
    lv_event_cb_t on_settings_reset_clicked = nullptr;
    lv_event_cb_t on_error_recovery_erase_clicked = nullptr;
    lv_event_cb_t on_error_recovery_cancel_clicked = nullptr;
    lv_event_cb_t on_reset_cancel_clicked = nullptr;
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
};

void modal_drawing_set_callbacks(const AgentQModalDrawingCallbacks& callbacks);

}  // namespace agent_q
H

cat >"${TMP_DIR}/stubs/freertos/FreeRTOS.h" <<'H'
#pragma once
#include <stdint.h>
using TickType_t = uint32_t;
using UBaseType_t = unsigned int;
constexpr int pdTRUE = 1;
constexpr int pdFALSE = 0;
H

cat >"${TMP_DIR}/stubs/freertos/queue.h" <<'H'
#pragma once
#include <stddef.h>
#include <string.h>

#include <deque>
#include <vector>

#include "freertos/FreeRTOS.h"

struct FakeQueue {
    size_t item_size;
    std::deque<std::vector<unsigned char>> items;
};
using QueueHandle_t = FakeQueue*;

inline QueueHandle_t xQueueCreate(UBaseType_t, size_t item_size)
{
    return new FakeQueue{item_size, {}};
}

inline int xQueueSend(QueueHandle_t queue, const void* item, TickType_t)
{
    if (queue == nullptr || item == nullptr) {
        return pdFALSE;
    }
    std::vector<unsigned char> bytes(queue->item_size);
    memcpy(bytes.data(), item, queue->item_size);
    queue->items.push_back(bytes);
    return pdTRUE;
}

inline int xQueueReceive(QueueHandle_t queue, void* out, TickType_t)
{
    if (queue == nullptr || out == nullptr || queue->items.empty()) {
        return pdFALSE;
    }
    const std::vector<unsigned char>& bytes = queue->items.front();
    memcpy(out, bytes.data(), queue->item_size);
    queue->items.pop_front();
    return pdTRUE;
}

inline void xQueueReset(QueueHandle_t queue)
{
    if (queue != nullptr) {
        queue->items.clear();
    }
}
H

cat >"${TMP_DIR}/test.cpp" <<'CPP'
#include <assert.h>
#include <stdio.h>

#include "agent_q_ui_event_bridge.h"
#include "agent_q_modal_drawing.h"

namespace {

agent_q::AgentQModalDrawingCallbacks g_callbacks;
agent_q::AgentQUiPanelDeletedCallback g_panel_deleted_callback = nullptr;

agent_q::AgentQUiEvent receive_event()
{
    agent_q::AgentQUiEvent event;
    assert(agent_q::ui_event_bridge_receive(&event));
    return event;
}

void expect_no_event()
{
    agent_q::AgentQUiEvent event;
    assert(!agent_q::ui_event_bridge_receive(&event));
}

}  // namespace

namespace agent_q {

void modal_drawing_set_callbacks(const AgentQModalDrawingCallbacks& callbacks)
{
    g_callbacks = callbacks;
}

void drawing_surface_set_panel_deleted_callback(AgentQUiPanelDeletedCallback callback)
{
    g_panel_deleted_callback = callback;
}

}  // namespace agent_q

int main()
{
    assert(agent_q::ui_event_bridge_init());
    agent_q::ui_event_bridge_register_callbacks();

    assert(g_callbacks.on_setup_generate_clicked != nullptr);
    assert(g_callbacks.on_pin_digit_clicked != nullptr);
    assert(g_callbacks.on_import_slot_clicked != nullptr);
    assert(g_callbacks.on_connect_review_accept_clicked != nullptr);
    assert(g_callbacks.on_settings_policy_reset_clicked != nullptr);
    assert(g_callbacks.on_sui_zklogin_review_continue_clicked != nullptr);
    assert(g_callbacks.on_sui_zklogin_review_reject_clicked != nullptr);
    assert(g_panel_deleted_callback != nullptr);

    g_callbacks.on_setup_generate_clicked(nullptr);
    assert(receive_event().kind == agent_q::AgentQUiEventKind::setup_generate_requested);

    lv_event_t digit_event{};
    const char digit[] = "7";
    digit_event.user_data = const_cast<char*>(digit);
    g_callbacks.on_pin_digit_clicked(&digit_event);
    agent_q::AgentQUiEvent event = receive_event();
    assert(event.kind == agent_q::AgentQUiEventKind::pin_digit_requested);
    assert(event.digit == '7');

    const char invalid_digit[] = "x";
    digit_event.user_data = const_cast<char*>(invalid_digit);
    g_callbacks.on_pin_digit_clicked(&digit_event);
    expect_no_event();

    uint8_t slot = 2;
    lv_event_t slot_event{&slot};
    g_callbacks.on_import_slot_clicked(&slot_event);
    event = receive_event();
    assert(event.kind == agent_q::AgentQUiEventKind::import_slot_requested);
    assert(event.slot == 2);

    slot = 3;
    g_callbacks.on_import_slot_clicked(&slot_event);
    expect_no_event();

    uint16_t word_index = 2047;
    lv_event_t word_event{&word_index};
    g_callbacks.on_import_candidate_clicked(&word_event);
    event = receive_event();
    assert(event.kind == agent_q::AgentQUiEventKind::import_candidate_requested);
    assert(event.word_index == 2047);

    word_index = 2048;
    g_callbacks.on_import_candidate_clicked(&word_event);
    expect_no_event();

    g_panel_deleted_callback(agent_q::AgentQUiPanelKind::user_signing_review);
    event = receive_event();
    assert(event.kind == agent_q::AgentQUiEventKind::panel_deleted);
    assert(event.panel_kind == agent_q::AgentQUiPanelKind::user_signing_review);

    agent_q::ui_event_bridge_setup_clicked_callback()(nullptr);
    assert(receive_event().kind == agent_q::AgentQUiEventKind::setup_requested);

    g_callbacks.on_connect_review_accept_clicked(nullptr);
    agent_q::AgentQConnectApprovalChoice choice = agent_q::AgentQConnectApprovalChoice::none;
    assert(agent_q::ui_event_bridge_receive_connect_choice(&choice));
    assert(choice == agent_q::AgentQConnectApprovalChoice::approved);

    g_callbacks.on_connect_review_reject_clicked(nullptr);
    agent_q::ui_event_bridge_reset_connect_choices();
    assert(!agent_q::ui_event_bridge_receive_connect_choice(&choice));

    agent_q::ui_event_bridge_enqueue_surface_ready();
    assert(receive_event().kind == agent_q::AgentQUiEventKind::ui_surface_ready);

    agent_q::ui_event_bridge_enqueue_settings_requested();
    assert(receive_event().kind == agent_q::AgentQUiEventKind::settings_requested);

    g_callbacks.on_settings_policy_reset_clicked(nullptr);
    assert(receive_event().kind == agent_q::AgentQUiEventKind::settings_policy_reset_requested);

    g_callbacks.on_settings_reset_clicked(nullptr);
    assert(receive_event().kind == agent_q::AgentQUiEventKind::settings_reset_requested);

    g_callbacks.on_sui_zklogin_review_continue_clicked(nullptr);
    assert(receive_event().kind == agent_q::AgentQUiEventKind::sui_zklogin_review_continue_requested);

    g_callbacks.on_sui_zklogin_review_reject_clicked(nullptr);
    assert(receive_event().kind == agent_q::AgentQUiEventKind::sui_zklogin_review_reject_requested);

    printf("UI event bridge tests passed\n");
    return 0;
}
CPP

cp "${AGENT_Q_DIR}/agent_q_ui_event_bridge.cpp" "${TMP_DIR}/agent_q_ui_event_bridge.cpp"

"${CXX_BIN}" -std=c++17 -Wall -Wextra -Werror \
  -I"${TMP_DIR}/stubs" \
  -I"${AGENT_Q_DIR}" \
  -I"${COMMON_ROOT}" \
  "${TMP_DIR}/test.cpp" \
  "${TMP_DIR}/agent_q_ui_event_bridge.cpp" \
  -o "${TMP_DIR}/test"

"${TMP_DIR}/test"
