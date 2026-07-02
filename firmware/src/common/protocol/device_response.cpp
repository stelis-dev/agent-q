#include "device_response.h"

#include "protocol/device_contract.h"
#include "protocol/protocol_constants.h"

namespace signing {

void device_response_write_device_fields(JsonObject device, const DeviceResponseDeviceFields& info)
{
    device["deviceId"] = info.device_id;
    device["state"] = info.device_state;
    device["firmwareName"] = info.firmware_name;
    device["hardware"] = info.hardware;
    device["firmwareVersion"] = info.firmware_version;
}

bool device_response_prepare_success_result(
    JsonDocument& response,
    const char* id,
    const char* method,
    JsonObjectConst result)
{
    if (method == nullptr || method[0] == '\0' || result.isNull()) {
        return false;
    }
    response.clear();
    response["id"] = id;
    response["version"] = kProtocolVersion;
    response["success"] = true;
    response["method"] = method;
    response["result"].set(result);
    return true;
}

bool device_response_prepare_method_error(
    JsonDocument& response,
    const char* id,
    const char* method,
    const char* code)
{
    const DeviceErrorRow* error = device_error_row(code);
    if (error == nullptr) {
        error = device_error_row("unknown_error");
    }
    if (error == nullptr) {
        return false;
    }
    response.clear();
    if (id != nullptr && id[0] != '\0') {
        response["id"] = id;
    }
    response["version"] = kProtocolVersion;
    response["success"] = false;
    if (method != nullptr && method[0] != '\0') {
        response["method"] = method;
    }
    response["error"]["code"] = error->code;
    response["error"]["message"] = error->message;
    response["error"]["retryable"] = error->retryable;
    return true;
}

}  // namespace signing
