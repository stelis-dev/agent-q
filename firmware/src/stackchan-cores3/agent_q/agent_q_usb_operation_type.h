#pragma once

#include <string.h>

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
};

inline AgentQUsbOperationType classify_usb_operation_type(const char* type)
{
    if (type == nullptr) {
        return AgentQUsbOperationType::unsupported;
    }
    if (strcmp(type, "get_status") == 0) {
        return AgentQUsbOperationType::get_status;
    }
    if (strcmp(type, "identify_device") == 0) {
        return AgentQUsbOperationType::identify_device;
    }
    if (strcmp(type, "connect") == 0) {
        return AgentQUsbOperationType::connect;
    }
    if (strcmp(type, "sign_transaction") == 0) {
        return AgentQUsbOperationType::sign_transaction;
    }
    if (strcmp(type, "sign_personal_message") == 0) {
        return AgentQUsbOperationType::sign_personal_message;
    }
    if (strcmp(type, "get_result") == 0) {
        return AgentQUsbOperationType::get_result;
    }
    if (strcmp(type, "ack_result") == 0) {
        return AgentQUsbOperationType::ack_result;
    }
    if (strcmp(type, "disconnect") == 0) {
        return AgentQUsbOperationType::disconnect;
    }
    if (strcmp(type, "get_capabilities") == 0) {
        return AgentQUsbOperationType::get_capabilities;
    }
    if (strcmp(type, "get_accounts") == 0) {
        return AgentQUsbOperationType::get_accounts;
    }
    if (strcmp(type, "policy_get") == 0) {
        return AgentQUsbOperationType::policy_get;
    }
    if (strcmp(type, "get_approval_history") == 0) {
        return AgentQUsbOperationType::get_approval_history;
    }
    if (strcmp(type, "policy_propose") == 0) {
        return AgentQUsbOperationType::policy_propose;
    }
    return AgentQUsbOperationType::unsupported;
}

}  // namespace agent_q
