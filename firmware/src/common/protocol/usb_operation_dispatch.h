#pragma once

#include <ArduinoJson.h>

#include "protocol/usb_operation_type.h"
#include "protocol/usb_operation_response_writer.h"

namespace signing {

using UsbOperationHandler =
    void (*)(const char* id, JsonDocument& request, const UsbOperationResponseWriter& writer);

struct UsbOperationHandlers {
    UsbOperationHandler get_status = nullptr;
    UsbOperationHandler identify_device = nullptr;
    UsbOperationHandler connect = nullptr;
    UsbOperationHandler sign_transaction = nullptr;
    UsbOperationHandler sign_personal_message = nullptr;
    UsbOperationHandler get_result = nullptr;
    UsbOperationHandler ack_result = nullptr;
    UsbOperationHandler disconnect = nullptr;
    UsbOperationHandler get_capabilities = nullptr;
    UsbOperationHandler get_accounts = nullptr;
    UsbOperationHandler policy_get = nullptr;
    UsbOperationHandler get_approval_history = nullptr;
    UsbOperationHandler policy_propose = nullptr;
    UsbOperationHandler credential_prepare = nullptr;
    UsbOperationHandler credential_propose = nullptr;
    UsbOperationHandler payload_transfer_begin = nullptr;
    UsbOperationHandler payload_transfer_chunk = nullptr;
    UsbOperationHandler payload_transfer_finish = nullptr;
    UsbOperationHandler payload_transfer_abort = nullptr;
};

bool dispatch_usb_operation(
    const char* id,
    UsbOperationType operation_type,
    JsonDocument& request,
    const UsbOperationResponseWriter& response_writer,
    const UsbOperationHandlers& handlers);

}  // namespace signing
