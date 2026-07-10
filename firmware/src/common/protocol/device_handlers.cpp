#include "protocol/device_handlers.h"

#include "protocol/json_input.h"
#include "protocol/protocol_constants.h"

namespace signing {

namespace {

bool write_status_response(
    const char* id,
    const DeviceStatusInfo& info,
    const ResponseWriter& writer)
{
    JsonDocument result;
    device_response_write_device_fields(result["device"].to<JsonObject>(), info.device);
    result["provisioning"]["state"] = info.provisioning_state;
    return writer.write_success_result(id, "get_status", result.as<JsonObjectConst>());
}

bool write_identify_device_method_result(
    const char* id,
    const char* code,
    const DeviceStatusInfo& info,
    const ResponseWriter& writer)
{
    JsonDocument result;
    result["code"] = code;
    device_response_write_device_fields(result["device"].to<JsonObject>(), info.device);
    return writer.write_success_result(id, "identify_device", result.as<JsonObjectConst>());
}

}  // namespace

void handle_protocol_get_status_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const GetStatusHandlerOps& ops)
{
    const char* const allowed_request_fields[] = {"id", "version", "method"};
    if (!json_object_fields_supported(
            request.as<JsonVariantConst>(),
            allowed_request_fields,
            3)) {
        writer.write_error(id, "invalid_request");
        return;
    }
    if (ops.write_payload_delivery_safe_read_admission_error != nullptr &&
        ops.write_payload_delivery_safe_read_admission_error(
            id,
            OperationType::get_status,
            writer)) {
        return;
    }
    if (ops.refresh_persistent_material_consistency != nullptr) {
        (void)ops.refresh_persistent_material_consistency();
    }
    if (ops.device_status_info != nullptr) {
        if (write_status_response(id, ops.device_status_info(), writer)) {
            return;
        }
    }
    {
        writer.log_write_failure("get_status", id);
    }
}

void handle_protocol_identify_device_request(
    const char* id,
    JsonDocument& request,
    const ResponseWriter& writer,
    const IdentifyDeviceHandlerOps& ops)
{
    if (ops.write_identify_device_admission_error != nullptr &&
        ops.write_identify_device_admission_error(id, writer)) {
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
    const char* const allowed_identify_params[] = {"code"};
    if (!json_object_fields_supported(
            request["payload"],
            allowed_identify_params,
            1)) {
        writer.write_error(id, "invalid_params");
        return;
    }

    const char* code = nullptr;
    if (!json_optional_c_string(request["payload"]["code"], "", &code)) {
        writer.write_error(id, "invalid_params");
        return;
    }
    if (ops.is_safe_identification_code == nullptr ||
        !ops.is_safe_identification_code(code)) {
        writer.write_error(id, "invalid_params");
        return;
    }

    if (ops.show_identification_code != nullptr) {
        ops.show_identification_code(code, ops.identify_display_ms);
    }
    if (ops.device_status_info != nullptr) {
        if (write_identify_device_method_result(id, code, ops.device_status_info(), writer)) {
            return;
        }
    }
    writer.log_write_failure("identify_device", id);
}

}  // namespace signing
