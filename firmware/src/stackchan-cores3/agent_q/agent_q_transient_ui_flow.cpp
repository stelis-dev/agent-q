#include "agent_q_transient_ui_flow.h"

#include <stdio.h>

namespace agent_q {

namespace {

bool show_overlay_message(
    const AgentQTransientUiFlowOps& ops,
    const char* message,
    AgentQMessageKind kind,
    AgentQUiMode mode,
    uint32_t duration_ms,
    lv_event_cb_t click_callback = nullptr)
{
    return ops.show_message != nullptr &&
           ops.show_message(message, kind, mode, duration_ms, click_callback);
}

void show_welcome_if_available(const AgentQTransientUiFlowOps& ops)
{
    if (ops.provisioning_welcome_available == nullptr ||
        !ops.provisioning_welcome_available()) {
        return;
    }
    const lv_event_cb_t callback =
        ops.setup_clicked_callback != nullptr ? ops.setup_clicked_callback() : nullptr;
    show_overlay_message(
        ops,
        "Set up Agent-Q",
        AgentQMessageKind::info,
        AgentQUiMode::identification,
        0,
        callback);
}

}  // namespace

bool transient_ui_identification_code_safe(const char* value)
{
    if (value == nullptr) {
        return false;
    }
    for (size_t index = 0; index < 4; ++index) {
        if (value[index] < '0' || value[index] > '9') {
            return false;
        }
    }
    return value[4] == '\0';
}

void transient_ui_show_provisioning_welcome_if_available(
    const AgentQTransientUiFlowOps& ops)
{
    show_welcome_if_available(ops);
}

void transient_ui_show_identification_code(
    const char* code,
    uint32_t duration_ms,
    const AgentQTransientUiFlowOps& ops)
{
    if (ops.clear_request_ui_for_identification != nullptr) {
        ops.clear_request_ui_for_identification();
    }

    const TickType_t now = ops.now != nullptr ? ops.now() : 0;
    if (ops.identification_begin != nullptr) {
        ops.identification_begin(now + pdMS_TO_TICKS(duration_ms));
    }

    char message[40];
    snprintf(message, sizeof(message), "Device code: %s", code != nullptr ? code : "");
    if (!show_overlay_message(
            ops,
            message,
            AgentQMessageKind::info,
            AgentQUiMode::identification,
            duration_ms)) {
        if (ops.log_warn != nullptr) {
            ops.log_warn("identify_device could not show Agent-Q speech bubble");
        }
    }
}

void transient_ui_clear_identification_if_needed(
    const AgentQTransientUiFlowOps& ops)
{
    const TickType_t now = ops.now != nullptr ? ops.now() : 0;
    if (ops.identification_deadline_reached == nullptr ||
        !ops.identification_deadline_reached(now)) {
        return;
    }

    const bool identification_visible =
        ops.overlay_mode != nullptr &&
        ops.overlay_mode() == AgentQUiMode::identification;
    if (ops.identification_clear != nullptr) {
        ops.identification_clear();
    }
    if (identification_visible && ops.overlay_clear != nullptr) {
        ops.overlay_clear();
        show_welcome_if_available(ops);
    }
}

void transient_ui_clear_message_if_needed(
    const AgentQTransientUiFlowOps& ops)
{
    const TickType_t now = ops.now != nullptr ? ops.now() : 0;
    if (ops.overlay_message_deadline_reached == nullptr ||
        !ops.overlay_message_deadline_reached(now)) {
        return;
    }
    if (ops.overlay_clear != nullptr) {
        ops.overlay_clear();
    }
    show_welcome_if_available(ops);
}

}  // namespace agent_q
