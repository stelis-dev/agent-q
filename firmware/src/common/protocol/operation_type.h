#pragma once

namespace signing {

enum class OperationType {
    unsupported,
    get_status,
    identify_device,
    connect,
    sign_transaction,
    sign_personal_message,
    get_result,
    ack_result,
    disconnect,
    get_capabilities,
    get_accounts,
    policy_get,
    get_approval_history,
    policy_propose,
    credential_prepare,
    credential_propose,
    payload_transfer_begin,
    payload_transfer_chunk,
    payload_transfer_finish,
    payload_transfer_abort,
};

OperationType classify_operation_type(const char* type);
const char* operation_type_wire_name(OperationType operation);
bool operation_is_retained_response_read_cleanup(
    OperationType operation);

}  // namespace signing
