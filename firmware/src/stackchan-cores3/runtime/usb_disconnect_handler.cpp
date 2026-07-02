#include "usb_disconnect_handler.h"

#include "protocol/json_input.h"
#include "usb_response_writer.h"

namespace signing {

void handle_usb_disconnect_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbDisconnectHandlerOps& ops)
{
    const char* session_id = nullptr;
    if (!json_optional_c_string(request["sessionId"], "", &session_id)) {
        writer.write_error(id, "invalid_session");
        return;
    }
    if (ops.require_active_matching_session == nullptr ||
        !ops.require_active_matching_session(id, session_id, writer)) {
        return;
    }

    const char* const allowed_request_fields[] = {"id", "version", "method", "sessionId"};
    if (!json_object_fields_supported(
            request.as<JsonVariantConst>(),
            allowed_request_fields,
            4)) {
        writer.write_error(id, "invalid_params");
        return;
    }
    if (ops.disconnect_pending_policy_update_for_session != nullptr &&
        ops.disconnect_pending_policy_update_for_session(id, session_id)) {
        return;
    }
    if (ops.disconnect_pending_sui_zklogin_proposal_for_session != nullptr &&
        ops.disconnect_pending_sui_zklogin_proposal_for_session(id, session_id)) {
        return;
    }
    if (ops.disconnect_pending_user_signing_for_session != nullptr &&
        ops.disconnect_pending_user_signing_for_session(id, session_id)) {
        return;
    }
    if (ops.write_busy_if_pending_or_local_flow_active != nullptr &&
        ops.write_busy_if_pending_or_local_flow_active(id, writer)) {
        return;
    }
    if (ops.write_payload_delivery_disconnect_admission_error != nullptr &&
        ops.write_payload_delivery_disconnect_admission_error(
            id,
            UsbOperationType::disconnect,
            writer)) {
        return;
    }
    if (ops.clear_active_session != nullptr) {
        ops.clear_active_session();
    }
    if (usb_response_write_disconnect_success(id)) {
        return;
    }
    writer.log_write_failure("disconnect", id);
}

}  // namespace signing
