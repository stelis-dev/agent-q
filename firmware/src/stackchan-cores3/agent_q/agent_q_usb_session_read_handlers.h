#pragma once

#include <ArduinoJson.h>

#include "agent_q_signing_mode.h"
#include "agent_q_usb_operation_response_writer.h"

namespace agent_q {

enum class AgentQUsbPolicyResponseWriteResult {
    ok,
    active_policy_unavailable,
    response_write_failed,
};

struct AgentQUsbSessionReadHandlerOps {
    bool (*material_ready)();
    bool (*write_busy_if_pending_or_local_flow_active)(const char* id);
    bool (*require_active_matching_session)(const char* id, const char* session_id);
    bool (*read_signing_mode)(AgentQSigningAuthorizationMode* mode);
    bool (*write_accounts_response)(const char* id);
    AgentQUsbPolicyResponseWriteResult (*write_policy_response)(const char* id);
    void (*record_active_policy_unavailable)();
};

void handle_usb_get_capabilities_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbSessionReadHandlerOps& ops);

void handle_usb_get_accounts_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbSessionReadHandlerOps& ops);

void handle_usb_policy_get_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbSessionReadHandlerOps& ops);

}  // namespace agent_q
