#pragma once

#include <stdint.h>

#include "avatar_overlay_drawing.h"
#include "freertos/FreeRTOS.h"
#include "lvgl.h"

namespace signing {

struct TransientUiFlowOps {
    TickType_t (*now)();
    bool (*provisioning_welcome_available)();
    void (*clear_request_ui_for_identification)();
    void (*identification_begin)(TickType_t deadline);
    bool (*identification_deadline_reached)(TickType_t now);
    void (*identification_clear)();
    UiMode (*overlay_mode)();
    void (*overlay_clear)();
    bool (*overlay_message_deadline_reached)(TickType_t now);
    bool (*show_message)(
        const char* message,
        MessageKind kind,
        UiMode mode,
        uint32_t duration_ms,
        lv_event_cb_t click_callback);
    lv_event_cb_t (*setup_clicked_callback)();
    void (*log_warn)(const char* message);
};

bool transient_ui_identification_code_safe(const char* value);
void transient_ui_show_provisioning_welcome_if_available(
    const TransientUiFlowOps& ops);
void transient_ui_show_identification_code(
    const char* code,
    uint32_t duration_ms,
    const TransientUiFlowOps& ops);
void transient_ui_clear_identification_if_needed(
    const TransientUiFlowOps& ops);
void transient_ui_clear_message_if_needed(
    const TransientUiFlowOps& ops);

}  // namespace signing
