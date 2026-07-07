#include "protocol/usb_operation_type.h"

#include <stddef.h>
#include <string.h>

namespace signing {
namespace {

struct UsbOperationTypeEntry {
    UsbOperationType type;
    const char* wire_type;
};

constexpr UsbOperationTypeEntry kUsbOperationTypes[] = {
    {UsbOperationType::get_status, "get_status"},
    {UsbOperationType::identify_device, "identify_device"},
    {UsbOperationType::connect, "connect"},
    {UsbOperationType::sign_transaction, "sign_transaction"},
    {UsbOperationType::sign_personal_message, "sign_personal_message"},
    {UsbOperationType::get_result, "get_result"},
    {UsbOperationType::ack_result, "ack_result"},
    {UsbOperationType::disconnect, "disconnect"},
    {UsbOperationType::get_capabilities, "get_capabilities"},
    {UsbOperationType::get_accounts, "get_accounts"},
    {UsbOperationType::policy_get, "policy_get"},
    {UsbOperationType::get_approval_history, "get_approval_history"},
    {UsbOperationType::policy_propose, "policy_propose"},
    {UsbOperationType::credential_prepare, "credential_prepare"},
    {UsbOperationType::credential_propose, "credential_propose"},
    {UsbOperationType::payload_transfer_begin, "payload_transfer_begin"},
    {UsbOperationType::payload_transfer_chunk, "payload_transfer_chunk"},
    {UsbOperationType::payload_transfer_finish, "payload_transfer_finish"},
    {UsbOperationType::payload_transfer_abort, "payload_transfer_abort"},
};

}  // namespace

UsbOperationType classify_usb_operation_type(const char* type)
{
    if (type == nullptr) {
        return UsbOperationType::unsupported;
    }
    for (const UsbOperationTypeEntry& entry : kUsbOperationTypes) {
        if (strcmp(entry.wire_type, type) == 0) {
            return entry.type;
        }
    }
    return UsbOperationType::unsupported;
}

const char* usb_operation_type_wire_name(UsbOperationType operation)
{
    for (const UsbOperationTypeEntry& entry : kUsbOperationTypes) {
        if (entry.type == operation) {
            return entry.wire_type;
        }
    }
    return nullptr;
}

bool usb_operation_is_retained_response_read_cleanup(
    UsbOperationType operation)
{
    return operation == UsbOperationType::get_result ||
           operation == UsbOperationType::ack_result;
}

}  // namespace signing
