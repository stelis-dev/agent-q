#pragma once

#include <ArduinoJson.h>

#include "protocol/operation_type.h"
#include "protocol/response_writer.h"

namespace signing {

using OperationHandler =
    void (*)(const char* id, JsonDocument& request, const ResponseWriter& writer);

struct OperationHandlers {
    OperationHandler get_status = nullptr;
    OperationHandler identify_device = nullptr;
    OperationHandler connect = nullptr;
    OperationHandler sign_transaction = nullptr;
    OperationHandler sign_personal_message = nullptr;
    OperationHandler get_result = nullptr;
    OperationHandler ack_result = nullptr;
    OperationHandler disconnect = nullptr;
    OperationHandler get_capabilities = nullptr;
    OperationHandler get_accounts = nullptr;
    OperationHandler policy_get = nullptr;
    OperationHandler get_approval_history = nullptr;
    OperationHandler policy_propose = nullptr;
    OperationHandler credential_prepare = nullptr;
    OperationHandler credential_propose = nullptr;
    OperationHandler payload_transfer_begin = nullptr;
    OperationHandler payload_transfer_chunk = nullptr;
    OperationHandler payload_transfer_finish = nullptr;
    OperationHandler payload_transfer_abort = nullptr;
};

bool dispatch_operation(
    const char* id,
    OperationType operation_type,
    JsonDocument& request,
    const ResponseWriter& response_writer,
    const OperationHandlers& handlers);

}  // namespace signing
