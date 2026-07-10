#include "protocol/operation_type.h"

#include <stddef.h>
#include <string.h>

namespace signing {
namespace {

struct OperationTypeEntry {
    OperationType type;
    const char* wire_type;
};

constexpr OperationTypeEntry kOperationTypes[] = {
    {OperationType::get_status, "get_status"},
    {OperationType::identify_device, "identify_device"},
    {OperationType::connect, "connect"},
    {OperationType::sign_transaction, "sign_transaction"},
    {OperationType::sign_personal_message, "sign_personal_message"},
    {OperationType::get_result, "get_result"},
    {OperationType::ack_result, "ack_result"},
    {OperationType::disconnect, "disconnect"},
    {OperationType::get_capabilities, "get_capabilities"},
    {OperationType::get_accounts, "get_accounts"},
    {OperationType::policy_get, "policy_get"},
    {OperationType::get_approval_history, "get_approval_history"},
    {OperationType::policy_propose, "policy_propose"},
    {OperationType::credential_prepare, "credential_prepare"},
    {OperationType::credential_propose, "credential_propose"},
    {OperationType::payload_transfer_begin, "payload_transfer_begin"},
    {OperationType::payload_transfer_chunk, "payload_transfer_chunk"},
    {OperationType::payload_transfer_finish, "payload_transfer_finish"},
    {OperationType::payload_transfer_abort, "payload_transfer_abort"},
};

}  // namespace

OperationType classify_operation_type(const char* type)
{
    if (type == nullptr) {
        return OperationType::unsupported;
    }
    for (const OperationTypeEntry& entry : kOperationTypes) {
        if (strcmp(entry.wire_type, type) == 0) {
            return entry.type;
        }
    }
    return OperationType::unsupported;
}

const char* operation_type_wire_name(OperationType operation)
{
    for (const OperationTypeEntry& entry : kOperationTypes) {
        if (entry.type == operation) {
            return entry.wire_type;
        }
    }
    return nullptr;
}

bool operation_is_retained_response_read_cleanup(
    OperationType operation)
{
    return operation == OperationType::get_result ||
           operation == OperationType::ack_result;
}

}  // namespace signing
