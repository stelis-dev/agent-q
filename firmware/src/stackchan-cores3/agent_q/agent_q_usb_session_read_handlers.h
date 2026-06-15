#pragma once

#include <ArduinoJson.h>

#include "policy/agent_q_policy_document.h"
#include "agent_q_signing_mode.h"
#include "agent_q_sui_account_store.h"
#include "agent_q_usb_operation_type.h"
#include "agent_q_usb_operation_response_writer.h"

namespace agent_q {

struct AgentQUsbSessionReadHandlerOps {
    bool (*material_ready)();
    bool (*write_busy_if_pending_or_local_flow_active)(const char* id);
    bool (*write_payload_delivery_safe_read_admission_error)(
        const char* id,
        AgentQUsbOperationType operation);
    bool (*require_active_matching_session)(const char* id, const char* session_id);
    bool (*read_signing_mode)(AgentQSigningAuthorizationMode* mode);
    SuiAccountDerivationResult (*derive_sui_account)(
        uint8_t public_key_out[kSuiEd25519PublicKeyBytes],
        char* address_out,
        size_t address_out_size);
    void (*record_root_material_unreadable)();
    bool (*read_active_policy)(
        const char** schema,
        char* policy_id_out,
        size_t policy_id_out_size,
        const char** default_action,
        size_t* blockchain_count,
        size_t* network_count,
        size_t* policy_count,
        size_t* condition_count,
        const AgentQCurrentPolicyDocument** document);
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
