#pragma once

namespace agent_q {

enum class AgentQUsbOperationType {
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

AgentQUsbOperationType classify_usb_operation_type(const char* type);
const char* usb_operation_type_wire_name(AgentQUsbOperationType operation);
bool usb_operation_is_retained_result_read_cleanup(
    AgentQUsbOperationType operation);

}  // namespace agent_q
