#include "usb_retained_response_handlers.h"

#include "protocol/json_input.h"
#include "protocol/request_id.h"
#include "signing_response_store.h"
#include "usb_active_session_request_guard.h"
#include "usb_response_writer.h"

namespace signing {

namespace {

bool guard_retained_response_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbRetainedResponseHandlerOps& ops,
    UsbOperationType operation,
    const char** session_id)
{
    const char* const allowed_request_fields[] = {"id", "version", "method", "sessionId", "payload"};
    const UsbActiveSessionRequestGuardOps guard_ops = {
        ops.material_ready,
        nullptr,
        ops.write_payload_delivery_retained_response_admission_error,
        ops.require_active_matching_session,
    };
    return guard_usb_active_session_request(
        id,
        request,
        writer,
        operation,
        guard_ops,
        UsbSessionIdMode::optional_default_empty,
        allowed_request_fields,
        5,
        session_id);
}

bool retained_request_id_from_payload(JsonDocument& request, const char** retained_request_id)
{
    const char* const allowed_payload_fields[] = {"retainedRequestId"};
    JsonObjectConst payload = request["payload"].as<JsonObjectConst>();
    if (payload.isNull() ||
        !json_object_fields_supported(payload, allowed_payload_fields, 1) ||
        !json_value_c_string(payload["retainedRequestId"], retained_request_id) ||
        !request_id_format_valid(*retained_request_id)) {
        return false;
    }
    return true;
}

bool deliver_stored_response_by_id(
    const char* response_id,
    const char* session_id,
    const char* retained_request_id)
{
    static char stored_response[kResponseMaxSize];
    size_t stored_len = 0;
    if (!signing_response_find(
            session_id,
            retained_request_id,
            stored_response,
            sizeof(stored_response),
            &stored_len)) {
        return false;
    }
    JsonDocument response;
    if (deserializeJson(response, stored_response, stored_len)) {
        return false;
    }
    if (response["success"] == true) {
        JsonObjectConst result = response["result"].as<JsonObjectConst>();
        return !result.isNull() &&
               usb_response_write_success_result(response_id, "get_result", result);
    }
    if (response["success"] == false) {
        const char* code = nullptr;
        if (!json_value_c_string(response["error"]["code"], &code)) {
            return false;
        }
        return usb_response_write_method_error(response_id, "get_result", code);
    }
    return false;
}

}  // namespace

void handle_usb_get_result_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbRetainedResponseHandlerOps& ops)
{
    const char* session_id = nullptr;
    if (!guard_retained_response_request(
            id,
            request,
            writer,
            ops,
            UsbOperationType::get_result,
            &session_id)) {
        return;
    }
    const char* retained_request_id = nullptr;
    if (!retained_request_id_from_payload(request, &retained_request_id)) {
        writer.write_error(id, "invalid_params");
        return;
    }
    if (deliver_stored_response_by_id(id, session_id, retained_request_id)) {
        return;
    }
    writer.write_error(id, "unknown_request");
}

void handle_usb_ack_result_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbRetainedResponseHandlerOps& ops)
{
    const char* session_id = nullptr;
    if (!guard_retained_response_request(
            id,
            request,
            writer,
            ops,
            UsbOperationType::ack_result,
            &session_id)) {
        return;
    }
    const char* retained_request_id = nullptr;
    if (!retained_request_id_from_payload(request, &retained_request_id)) {
        writer.write_error(id, "invalid_params");
        return;
    }
    signing_response_ack(session_id, retained_request_id);
    if (!usb_response_write_ack_result(id)) {
        writer.log_write_failure("ack_result", id);
    }
}

}  // namespace signing
