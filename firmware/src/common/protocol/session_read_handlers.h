#pragma once

#include <ArduinoJson.h>

#include "sui/account_settings_types.h"
#include "sui/active_identity.h"
#include "protocol/signing_mode.h"
#include "protocol/operation_type.h"
#include "protocol/response_writer.h"

namespace signing {

struct SessionReadHandlerOps {
    bool (*material_ready)();
    bool (*write_busy_if_pending_or_local_flow_active)(
        const char* id,
        const ResponseWriter& writer);
    bool (*write_payload_delivery_safe_read_admission_error)(
        const char* id,
        OperationType operation,
        const ResponseWriter& writer);
    bool (*require_active_matching_session)(
        const char* id,
        const char* session_id,
        const ResponseWriter& writer);
    bool (*read_signing_mode)(AuthorizationMode* mode);
    bool (*read_sui_account_settings)(SuiAccountSettings* settings);
    bool (*sui_zklogin_credential_available)();
    SuiActiveIdentity (*resolve_active_sui_identity)();
    void (*record_root_material_unreadable)();
};

void handle_protocol_get_capabilities_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const SessionReadHandlerOps& ops);

void handle_protocol_get_accounts_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const SessionReadHandlerOps& ops);

}  // namespace signing
