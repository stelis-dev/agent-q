#pragma once

#include <ArduinoJson.h>

#include "agent_q_sui_zklogin_proof_store.h"
#include "agent_q_sui_zklogin_proposal_flow.h"
#include "agent_q_timeout_window.h"
#include "agent_q_usb_operation_response_writer.h"
#include "agent_q_usb_operation_type.h"

namespace agent_q {

struct AgentQUsbSuiZkLoginCredentialHandlerOps {
    bool (*material_ready)();
    bool (*write_credential_prepare_admission_error)(
        const char* id,
        const AgentQUsbOperationResponseWriter& writer);
    bool (*write_credential_propose_admission_error)(
        const char* id,
        const AgentQUsbOperationResponseWriter& writer);
    bool (*write_payload_delivery_safe_read_admission_error)(
        const char* id,
        AgentQUsbOperationType operation,
        const AgentQUsbOperationResponseWriter& writer);
    bool (*require_active_matching_session)(
        const char* id,
        const char* session_id,
        const AgentQUsbOperationResponseWriter& writer);
    AgentQSuiActiveIdentity (*resolve_active_identity)();
    AgentQTimeoutTick (*current_tick)();
    AgentQTimeoutWindow (*make_proposal_window)(AgentQTimeoutTick now);
    AgentQSuiZkLoginProposalBeginResult (*begin_proposal)(
        JsonVariantConst params,
        const char* request_id,
        const char* session_id,
        TickType_t now,
        AgentQTimeoutWindow request_window);
    const char* (*begin_result_reason)(AgentQSuiZkLoginProposalBeginResult result);
    bool (*show_proposal_review)(const char* request_id);
};

void handle_usb_credential_prepare_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbSuiZkLoginCredentialHandlerOps& ops);

void handle_usb_credential_propose_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbSuiZkLoginCredentialHandlerOps& ops);

}  // namespace agent_q
