#pragma once

#include <ArduinoJson.h>

#include "sui_zklogin_proof_store.h"
#include "sui_zklogin_proposal_flow.h"
#include "transport/timeout_window.h"
#include "usb_operation_response_writer.h"
#include "usb_operation_type.h"

namespace signing {

struct UsbSuiZkLoginCredentialHandlerOps {
    bool (*material_ready)();
    bool (*write_credential_prepare_admission_error)(
        const char* id,
        const UsbOperationResponseWriter& writer);
    bool (*write_credential_propose_admission_error)(
        const char* id,
        const UsbOperationResponseWriter& writer);
    bool (*write_payload_delivery_safe_read_admission_error)(
        const char* id,
        UsbOperationType operation,
        const UsbOperationResponseWriter& writer);
    bool (*require_active_matching_session)(
        const char* id,
        const char* session_id,
        const UsbOperationResponseWriter& writer);
    SuiActiveIdentity (*resolve_active_identity)();
    TimeoutTick (*current_tick)();
    TimeoutWindow (*make_proposal_window)(TimeoutTick now);
    SuiZkLoginProposalBeginResult (*begin_proposal)(
        JsonVariantConst params,
        const char* request_id,
        const char* session_id,
        TickType_t now,
        TimeoutWindow request_window);
    const char* (*begin_result_reason)(SuiZkLoginProposalBeginResult result);
    bool (*show_proposal_review)(const char* request_id);
};

void handle_usb_credential_prepare_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbSuiZkLoginCredentialHandlerOps& ops);

void handle_usb_credential_propose_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbSuiZkLoginCredentialHandlerOps& ops);

}  // namespace signing
