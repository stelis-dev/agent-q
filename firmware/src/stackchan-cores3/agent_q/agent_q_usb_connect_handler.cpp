#include "agent_q_usb_connect_handler.h"

#include "agent_q_connect_approval.h"
#include "agent_q_json_input.h"
#include "agent_q_usb_response_writer.h"

namespace agent_q {

namespace {

bool is_printable_ascii_client_name(const char* value)
{
    if (value == nullptr || value[0] == '\0') {
        return false;
    }
    size_t length = 0;
    for (const char* cursor = value; *cursor != '\0'; ++cursor) {
        if (++length >= kAgentQConnectApprovalClientNameSize) {
            return false;
        }
        const unsigned char c = static_cast<unsigned char>(*cursor);
        if (c < 0x20 || c > 0x7E) {
            return false;
        }
    }
    return true;
}

}  // namespace

void handle_usb_connect_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbConnectHandlerOps& ops)
{
    if (ops.material_ready == nullptr || !ops.material_ready()) {
        writer.write_error(id, "invalid_state", "Connect is available only after provisioning is complete.");
        return;
    }
    if (ops.write_busy_if_pending_or_local_flow_active != nullptr &&
        ops.write_busy_if_pending_or_local_flow_active(id)) {
        return;
    }

    const char* const allowed_request_fields[] = {"id", "version", "type", "params"};
    if (!agent_q_json_object_fields_supported(
            request.as<JsonVariantConst>(),
            allowed_request_fields,
            4)) {
        writer.write_error(id, "invalid_params", "connect request contains unsupported fields.");
        return;
    }

    const char* const allowed_connect_params[] = {"clientName"};
    if (!agent_q_json_object_fields_supported(request["params"], allowed_connect_params, 1)) {
        writer.write_error(id, "invalid_params", "connect params contain unsupported fields.");
        return;
    }

    const char* client_name = nullptr;
    if (!agent_q_json_optional_c_string(request["params"]["clientName"], "", &client_name) ||
        !is_printable_ascii_client_name(client_name)) {
        writer.write_error(id, "invalid_client_name", "clientName must be 1-64 printable ASCII characters.");
        return;
    }

    if (ops.make_approval_window == nullptr ||
        ops.begin_connect_approval == nullptr ||
        ops.show_connect_unavailable == nullptr ||
        ops.reset_review_choice_queue == nullptr ||
        ops.show_connect_review == nullptr ||
        ops.record_review_waiting == nullptr) {
        writer.write_error(id, "protocol_error", "Connect handler is unavailable.");
        return;
    }

    const AgentQTimeoutWindow approval_window = ops.make_approval_window();
    if (!ops.begin_connect_approval(id, client_name, approval_window)) {
        usb_response_write_connect_rejected(id, "invalid_state", "Connect is unavailable.");
        ops.show_connect_unavailable();
        return;
    }
    ops.reset_review_choice_queue();
    ops.show_connect_review();
    ops.record_review_waiting(id, client_name);
}

}  // namespace agent_q
