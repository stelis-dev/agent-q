#include "agent_q_usb_device_handlers.h"

#include "agent_q_json_input.h"
#include "agent_q_protocol_constants.h"
#include "agent_q_usb_response_writer.h"

namespace agent_q {

namespace {

bool write_status_response(const char* id, const AgentQUsbDeviceResponseInfo& info)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kAgentQProtocolVersion;
    response["type"] = "status";
    usb_response_write_device_fields(response["device"].to<JsonObject>(), info);
    response["provisioning"]["state"] = info.provisioning_state;
    return usb_response_write_json(response);
}

bool write_identify_device_result(
    const char* id,
    const char* code,
    const AgentQUsbDeviceResponseInfo& info)
{
    JsonDocument response;
    response["id"] = id;
    response["version"] = kAgentQProtocolVersion;
    response["type"] = "identify_device_result";
    response["status"] = "displayed";
    response["code"] = code;
    usb_response_write_device_fields(response["device"].to<JsonObject>(), info);
    return usb_response_write_json(response);
}

}  // namespace

void handle_usb_get_status_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbGetStatusHandlerOps& ops)
{
    const char* const allowed_request_fields[] = {"id", "version", "type"};
    if (!agent_q_json_object_fields_supported(
            request.as<JsonVariantConst>(),
            allowed_request_fields,
            3)) {
        writer.write_error(id, "invalid_params", "get_status request contains unsupported fields.");
        return;
    }
    if (ops.write_payload_delivery_safe_read_admission_error != nullptr &&
        ops.write_payload_delivery_safe_read_admission_error(
            id,
            AgentQUsbOperationType::get_status)) {
        return;
    }
    if (ops.refresh_persistent_material_consistency != nullptr) {
        (void)ops.refresh_persistent_material_consistency();
    }
    if (ops.device_response_info != nullptr &&
        write_status_response(id, ops.device_response_info())) {
        return;
    }
    {
        writer.log_write_failure("status", id);
    }
}

void handle_usb_identify_device_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbIdentifyDeviceHandlerOps& ops)
{
    if (ops.write_identify_device_admission_error != nullptr &&
        ops.write_identify_device_admission_error(id)) {
        return;
    }
    const char* const allowed_request_fields[] = {"id", "version", "type", "params"};
    if (!agent_q_json_object_fields_supported(
            request.as<JsonVariantConst>(),
            allowed_request_fields,
            4)) {
        writer.write_error(id, "invalid_params", "identify_device request contains unsupported fields.");
        return;
    }
    const char* const allowed_identify_params[] = {"code"};
    if (!agent_q_json_object_fields_supported(
            request["params"],
            allowed_identify_params,
            1)) {
        writer.write_error(id, "invalid_params", "identify_device params contain unsupported fields.");
        return;
    }

    const char* code = nullptr;
    if (!agent_q_json_optional_c_string(request["params"]["code"], "", &code)) {
        writer.write_error(id, "invalid_code", "Invalid identification code.");
        return;
    }
    if (ops.is_safe_identification_code == nullptr ||
        !ops.is_safe_identification_code(code)) {
        writer.write_error(id, "invalid_code", "Invalid identification code.");
        return;
    }

    if (ops.show_identification_code != nullptr) {
        ops.show_identification_code(code, ops.identify_display_ms);
    }
    if (ops.device_response_info != nullptr &&
        write_identify_device_result(id, code, ops.device_response_info())) {
        return;
    }
    writer.log_write_failure("identify_device_result", id);
}

}  // namespace agent_q
