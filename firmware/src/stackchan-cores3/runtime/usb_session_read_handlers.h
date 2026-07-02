#pragma once

#include <ArduinoJson.h>

#include "policy/document.h"
#include "signing_mode.h"
#include "sui_account_settings.h"
#include "sui_zklogin_proof_store.h"
#include "usb_operation_type.h"
#include "usb_operation_response_writer.h"

namespace signing {

struct UsbSessionReadHandlerOps {
    bool (*material_ready)();
    bool (*write_busy_if_pending_or_local_flow_active)(
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
    bool (*read_signing_mode)(AuthorizationMode* mode);
    bool (*read_sui_account_settings)(SuiAccountSettings* settings);
    bool (*sui_zklogin_credential_available)();
    SuiActiveIdentity (*resolve_active_sui_identity)();
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
        const CurrentPolicyDocument** document);
    void (*record_active_policy_unavailable)();
};

void handle_usb_get_capabilities_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbSessionReadHandlerOps& ops);

void handle_usb_get_accounts_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbSessionReadHandlerOps& ops);

void handle_usb_policy_get_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbSessionReadHandlerOps& ops);

}  // namespace signing
