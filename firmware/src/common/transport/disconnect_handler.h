#pragma once

#include <ArduinoJson.h>

#include "protocol/operation_type.h"
#include "protocol/response_writer.h"

namespace signing {

struct DisconnectHandlerOps {
    bool (*require_active_matching_session)(
        const char* id,
        const char* session_id,
        const ResponseWriter& writer);
    bool (*disconnect_pending_policy_update_for_session)(
        const char* id,
        const char* session_id,
        const ResponseWriter& writer);
    bool (*disconnect_pending_sui_zklogin_proposal_for_session)(
        const char* id,
        const char* session_id,
        const ResponseWriter& writer);
    bool (*disconnect_pending_user_signing_for_session)(
        const char* id,
        const char* session_id,
        const ResponseWriter& writer);
    bool (*write_busy_if_pending_or_local_flow_active)(
        const char* id,
        const ResponseWriter& writer);
    bool (*write_payload_delivery_disconnect_admission_error)(
        const char* id,
        OperationType operation,
        const ResponseWriter& writer);
    void (*clear_active_session)();
};

void handle_protocol_disconnect_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const DisconnectHandlerOps& ops);

}  // namespace signing
