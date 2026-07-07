#include "transport/usb_connect_handler.h"

#include "protocol/json_input.h"

namespace signing {

namespace {

bool is_printable_ascii_client_name(const char* value)
{
    if (value == nullptr || value[0] == '\0') {
        return false;
    }
    size_t length = 0;
    for (const char* cursor = value; *cursor != '\0'; ++cursor) {
        if (++length > kUsbConnectClientNameMaxBytes) {
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
    const UsbOperationResponseWriter& writer,
    const UsbConnectHandlerOps& ops)
{
    if (ops.material_ready == nullptr || !ops.material_ready()) {
        writer.write_error(id, "invalid_state");
        return;
    }
    if (ops.write_connect_admission_error != nullptr &&
        ops.write_connect_admission_error(id, writer)) {
        return;
    }

    const char* const allowed_request_fields[] = {"id", "version", "method", "payload"};
    if (!json_object_fields_supported(
            request.as<JsonVariantConst>(),
            allowed_request_fields,
            4)) {
        writer.write_error(id, "invalid_request");
        return;
    }

    const char* const allowed_connect_params[] = {"clientName"};
    if (!json_object_fields_supported(request["payload"], allowed_connect_params, 1)) {
        writer.write_error(id, "invalid_params");
        return;
    }

    const char* client_name = nullptr;
    if (!json_optional_c_string(request["payload"]["clientName"], "", &client_name) ||
        !is_printable_ascii_client_name(client_name)) {
        writer.write_error(id, "invalid_params");
        return;
    }

    if (ops.write_existing_session_connect_response != nullptr &&
        ops.write_existing_session_connect_response(id)) {
        return;
    }

    if (ops.current_tick == nullptr ||
        ops.make_approval_window == nullptr ||
        ops.begin_connect_approval == nullptr ||
        ops.show_connect_unavailable == nullptr ||
        ops.reset_review_choice_queue == nullptr ||
        ops.show_connect_review == nullptr ||
        ops.record_review_waiting == nullptr) {
        writer.write_error(id, "internal_output_error");
        return;
    }

    const TimeoutTick now = ops.current_tick();
    const TimeoutWindow approval_window = ops.make_approval_window(now);
    if (!ops.begin_connect_approval(id, client_name, now, approval_window)) {
        writer.write_error(id, "invalid_state");
        ops.show_connect_unavailable();
        return;
    }
    ops.reset_review_choice_queue();
    ops.show_connect_review();
    ops.record_review_waiting(id, client_name);
}

}  // namespace signing
