#include "agent_q_usb_retained_result_handlers.h"

#include "agent_q_json_input.h"
#include "agent_q_request_id.h"
#include "agent_q_signing_result_store.h"
#include "agent_q_usb_response_writer.h"

namespace agent_q {

namespace {

bool retained_result_material_ready(const AgentQUsbRetainedResultHandlerOps& ops)
{
    return ops.material_ready != nullptr && ops.material_ready();
}

bool retained_result_session_valid(
    const AgentQUsbRetainedResultHandlerOps& ops,
    const char* id,
    const char* session_id,
    const AgentQUsbOperationResponseWriter& writer)
{
    return ops.require_active_matching_session != nullptr &&
           ops.require_active_matching_session(id, session_id, writer);
}

bool retained_result_request_fields_supported(JsonDocument& request)
{
    const char* const allowed_request_fields[] = {"id", "version", "method", "sessionId", "payload"};
    return agent_q_json_object_fields_supported(
        request.as<JsonVariantConst>(),
        allowed_request_fields,
        5);
}

bool retained_request_id_from_payload(JsonDocument& request, const char** retained_request_id)
{
    const char* const allowed_payload_fields[] = {"retainedRequestId"};
    JsonObjectConst payload = request["payload"].as<JsonObjectConst>();
    if (payload.isNull() ||
        !agent_q_json_object_fields_supported(payload, allowed_payload_fields, 1) ||
        !agent_q_json_value_c_string(payload["retainedRequestId"], retained_request_id) ||
        !request_id_format_valid(*retained_request_id)) {
        return false;
    }
    return true;
}

bool deliver_stored_result_by_id(
    const char* response_id,
    const char* session_id,
    const char* retained_request_id)
{
    static char stored_result[kSigningResultMaxSize];
    size_t stored_len = 0;
    if (!signing_result_find(
            session_id,
            retained_request_id,
            stored_result,
            sizeof(stored_result),
            &stored_len)) {
        return false;
    }
    JsonDocument response;
    if (deserializeJson(response, stored_result, stored_len)) {
        return false;
    }
    if (response["success"] == true) {
        JsonObjectConst result = response["result"].as<JsonObjectConst>();
        return !result.isNull() &&
               usb_response_write_success_result(response_id, "get_result", result);
    }
    if (response["success"] == false) {
        const char* code = nullptr;
        if (!agent_q_json_value_c_string(response["error"]["code"], &code)) {
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
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbRetainedResultHandlerOps& ops)
{
    if (!retained_result_material_ready(ops)) {
        writer.write_error(id, "invalid_state");
        return;
    }
    if (ops.write_payload_delivery_retained_result_admission_error != nullptr &&
        ops.write_payload_delivery_retained_result_admission_error(
            id,
            AgentQUsbOperationType::get_result,
            writer)) {
        return;
    }
    const char* session_id = nullptr;
    if (!agent_q_json_optional_c_string(request["sessionId"], "", &session_id)) {
        writer.write_error(id, "invalid_session");
        return;
    }
    if (!retained_result_session_valid(ops, id, session_id, writer)) {
        return;
    }
    if (!retained_result_request_fields_supported(request)) {
        writer.write_error(id, "invalid_params");
        return;
    }
    const char* retained_request_id = nullptr;
    if (!retained_request_id_from_payload(request, &retained_request_id)) {
        writer.write_error(id, "invalid_params");
        return;
    }
    if (deliver_stored_result_by_id(id, session_id, retained_request_id)) {
        return;
    }
    writer.write_error(id, "unknown_request");
}

void handle_usb_ack_result_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbRetainedResultHandlerOps& ops)
{
    if (!retained_result_material_ready(ops)) {
        writer.write_error(id, "invalid_state");
        return;
    }
    if (ops.write_payload_delivery_retained_result_admission_error != nullptr &&
        ops.write_payload_delivery_retained_result_admission_error(
            id,
            AgentQUsbOperationType::ack_result,
            writer)) {
        return;
    }
    const char* session_id = nullptr;
    if (!agent_q_json_optional_c_string(request["sessionId"], "", &session_id)) {
        writer.write_error(id, "invalid_session");
        return;
    }
    if (!retained_result_session_valid(ops, id, session_id, writer)) {
        return;
    }
    if (!retained_result_request_fields_supported(request)) {
        writer.write_error(id, "invalid_params");
        return;
    }
    const char* retained_request_id = nullptr;
    if (!retained_request_id_from_payload(request, &retained_request_id)) {
        writer.write_error(id, "invalid_params");
        return;
    }
    signing_result_ack(session_id, retained_request_id);
    if (!usb_response_write_ack_result(id)) {
        writer.log_write_failure("ack_result", id);
    }
}

}  // namespace agent_q
