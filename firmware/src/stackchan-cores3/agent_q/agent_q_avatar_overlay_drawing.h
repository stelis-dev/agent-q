#pragma once

#include <stdint.h>

#include "freertos/FreeRTOS.h"
#include "lvgl.h"

namespace agent_q {

enum class AgentQUiMode {
    none,
    decision,
    result,
    identification,
};

enum class AgentQMessageKind {
    info,
    approval,
    success,
    rejected,
    timeout,
    error,
    usb_connected,
    usb_disconnected,
};

void avatar_overlay_clear();
bool avatar_overlay_show_message(
    const char* message,
    AgentQMessageKind kind,
    AgentQUiMode mode,
    uint32_t duration_ms,
    lv_event_cb_t click_callback = nullptr);
AgentQUiMode avatar_overlay_mode();
bool avatar_overlay_message_deadline_reached(TickType_t now);

}  // namespace agent_q
