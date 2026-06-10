#include "agent_q_usb_retained_result_handlers.h"

#include "agent_q_json_input.h"
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
    const char* session_id)
{
    return ops.require_active_matching_session != nullptr &&
           ops.require_active_matching_session(id, session_id);
}

bool retained_result_request_fields_supported(JsonDocument& request)
{
    const char* const allowed_request_fields[] = {"id", "version", "type", "sessionId"};
    return agent_q_json_object_fields_supported(
        request.as<JsonVariantConst>(),
        allowed_request_fields,
        4);
}

}  // namespace

void handle_usb_get_result_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbRetainedResultHandlerOps& ops)
{
    if (!retained_result_material_ready(ops)) {
        writer.write_error(id, "invalid_state", "get_result is available only after provisioning is complete.");
        return;
    }
    const char* session_id = nullptr;
    if (!agent_q_json_optional_c_string(request["sessionId"], "", &session_id)) {
        writer.write_error(id, "invalid_session", "Invalid session.");
        return;
    }
    if (!retained_result_session_valid(ops, id, session_id)) {
        return;
    }
    if (!retained_result_request_fields_supported(request)) {
        writer.write_error(id, "invalid_params", "get_result request contains unsupported fields.");
        return;
    }
    if (ops.deliver_stored_result != nullptr &&
        ops.deliver_stored_result(session_id, id)) {
        return;
    }
    writer.write_error(id, "unknown_request", "No buffered signing result for this request id.");
}

void handle_usb_ack_result_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbRetainedResultHandlerOps& ops)
{
    if (!retained_result_material_ready(ops)) {
        writer.write_error(id, "invalid_state", "ack_result is available only after provisioning is complete.");
        return;
    }
    const char* session_id = nullptr;
    if (!agent_q_json_optional_c_string(request["sessionId"], "", &session_id)) {
        writer.write_error(id, "invalid_session", "Invalid session.");
        return;
    }
    if (!retained_result_session_valid(ops, id, session_id)) {
        return;
    }
    if (!retained_result_request_fields_supported(request)) {
        writer.write_error(id, "invalid_params", "ack_result request contains unsupported fields.");
        return;
    }
    if (ops.ack_stored_result != nullptr) {
        ops.ack_stored_result(session_id, id);
    }
    if (!usb_response_write_ack_result(id)) {
        writer.log_write_failure("ack_result", id);
    }
}

}  // namespace agent_q
