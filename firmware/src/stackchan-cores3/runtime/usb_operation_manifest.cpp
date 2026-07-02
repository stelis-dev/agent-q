#include "usb_operation_manifest.h"

#include <stddef.h>
#include <string.h>

namespace signing {
namespace {

constexpr UsbOperationManifestEntry kUsbOperationManifest[] = {
    {
        UsbOperationType::get_status,
        "get_status",
        UsbOperationHandlerSlot::get_status,
        PayloadDeliveryOperationKind::safe_read,
        UsbOperationCompletionPolicy::immediate_response,
        UsbOperationReadSideEffectPolicy::persistent_material_consistency_refresh,
    },
    {
        UsbOperationType::identify_device,
        "identify_device",
        UsbOperationHandlerSlot::identify_device,
        PayloadDeliveryOperationKind::identify_device,
        UsbOperationCompletionPolicy::immediate_response,
        UsbOperationReadSideEffectPolicy::none,
    },
    {
        UsbOperationType::connect,
        "connect",
        UsbOperationHandlerSlot::connect,
        PayloadDeliveryOperationKind::connect,
        UsbOperationCompletionPolicy::connect_approval,
        UsbOperationReadSideEffectPolicy::none,
    },
    {
        UsbOperationType::sign_transaction,
        "sign_transaction",
        UsbOperationHandlerSlot::sign_transaction,
        PayloadDeliveryOperationKind::sign_transaction,
        UsbOperationCompletionPolicy::signing_retained_response,
        UsbOperationReadSideEffectPolicy::none,
    },
    {
        UsbOperationType::sign_personal_message,
        "sign_personal_message",
        UsbOperationHandlerSlot::sign_personal_message,
        PayloadDeliveryOperationKind::sign_personal_message,
        UsbOperationCompletionPolicy::signing_retained_response,
        UsbOperationReadSideEffectPolicy::none,
    },
    {
        UsbOperationType::get_result,
        "get_result",
        UsbOperationHandlerSlot::get_result,
        PayloadDeliveryOperationKind::retained_response_read_cleanup,
        UsbOperationCompletionPolicy::signing_retained_response_read,
        UsbOperationReadSideEffectPolicy::none,
    },
    {
        UsbOperationType::ack_result,
        "ack_result",
        UsbOperationHandlerSlot::ack_result,
        PayloadDeliveryOperationKind::retained_response_read_cleanup,
        UsbOperationCompletionPolicy::signing_retained_response_ack,
        UsbOperationReadSideEffectPolicy::none,
    },
    {
        UsbOperationType::disconnect,
        "disconnect",
        UsbOperationHandlerSlot::disconnect,
        PayloadDeliveryOperationKind::disconnect,
        UsbOperationCompletionPolicy::immediate_response,
        UsbOperationReadSideEffectPolicy::none,
    },
    {
        UsbOperationType::get_capabilities,
        "get_capabilities",
        UsbOperationHandlerSlot::get_capabilities,
        PayloadDeliveryOperationKind::safe_read,
        UsbOperationCompletionPolicy::immediate_response,
        UsbOperationReadSideEffectPolicy::none,
    },
    {
        UsbOperationType::get_accounts,
        "get_accounts",
        UsbOperationHandlerSlot::get_accounts,
        PayloadDeliveryOperationKind::safe_read,
        UsbOperationCompletionPolicy::immediate_response,
        UsbOperationReadSideEffectPolicy::none,
    },
    {
        UsbOperationType::policy_get,
        "policy_get",
        UsbOperationHandlerSlot::policy_get,
        PayloadDeliveryOperationKind::safe_read,
        UsbOperationCompletionPolicy::immediate_response,
        UsbOperationReadSideEffectPolicy::none,
    },
    {
        UsbOperationType::get_approval_history,
        "get_approval_history",
        UsbOperationHandlerSlot::get_approval_history,
        PayloadDeliveryOperationKind::safe_read,
        UsbOperationCompletionPolicy::immediate_response,
        UsbOperationReadSideEffectPolicy::none,
    },
    {
        UsbOperationType::policy_propose,
        "policy_propose",
        UsbOperationHandlerSlot::policy_propose,
        PayloadDeliveryOperationKind::policy_propose,
        UsbOperationCompletionPolicy::policy_update_history_marker,
        UsbOperationReadSideEffectPolicy::none,
    },
    {
        UsbOperationType::credential_prepare,
        "credential_prepare",
        UsbOperationHandlerSlot::credential_prepare,
        PayloadDeliveryOperationKind::safe_read,
        UsbOperationCompletionPolicy::immediate_response,
        UsbOperationReadSideEffectPolicy::none,
    },
    {
        UsbOperationType::credential_propose,
        "credential_propose",
        UsbOperationHandlerSlot::credential_propose,
        PayloadDeliveryOperationKind::credential_propose,
        UsbOperationCompletionPolicy::credential_proposal_outcome,
        UsbOperationReadSideEffectPolicy::none,
    },
    {
        UsbOperationType::payload_transfer_begin,
        "payload_transfer_begin",
        UsbOperationHandlerSlot::payload_transfer_begin,
        PayloadDeliveryOperationKind::payload_transfer_begin,
        UsbOperationCompletionPolicy::immediate_response,
        UsbOperationReadSideEffectPolicy::none,
    },
    {
        UsbOperationType::payload_transfer_chunk,
        "payload_transfer_chunk",
        UsbOperationHandlerSlot::payload_transfer_chunk,
        PayloadDeliveryOperationKind::payload_transfer_chunk,
        UsbOperationCompletionPolicy::immediate_response,
        UsbOperationReadSideEffectPolicy::none,
    },
    {
        UsbOperationType::payload_transfer_finish,
        "payload_transfer_finish",
        UsbOperationHandlerSlot::payload_transfer_finish,
        PayloadDeliveryOperationKind::payload_transfer_finish,
        UsbOperationCompletionPolicy::immediate_response,
        UsbOperationReadSideEffectPolicy::none,
    },
    {
        UsbOperationType::payload_transfer_abort,
        "payload_transfer_abort",
        UsbOperationHandlerSlot::payload_transfer_abort,
        PayloadDeliveryOperationKind::payload_transfer_abort,
        UsbOperationCompletionPolicy::immediate_response,
        UsbOperationReadSideEffectPolicy::none,
    },
};

}  // namespace

const UsbOperationManifestEntry* usb_operation_manifest_entry(
    UsbOperationType operation)
{
    for (const UsbOperationManifestEntry& entry : kUsbOperationManifest) {
        if (entry.type == operation) {
            return &entry;
        }
    }
    return nullptr;
}

const UsbOperationManifestEntry* usb_operation_manifest_entry_for_wire_type(
    const char* wire_type)
{
    if (wire_type == nullptr) {
        return nullptr;
    }
    for (const UsbOperationManifestEntry& entry : kUsbOperationManifest) {
        if (strcmp(entry.wire_type, wire_type) == 0) {
            return &entry;
        }
    }
    return nullptr;
}

UsbOperationType classify_usb_operation_type(const char* type)
{
    const UsbOperationManifestEntry* entry =
        usb_operation_manifest_entry_for_wire_type(type);
    return entry != nullptr ? entry->type : UsbOperationType::unsupported;
}

const char* usb_operation_type_wire_name(UsbOperationType operation)
{
    const UsbOperationManifestEntry* entry =
        usb_operation_manifest_entry(operation);
    return entry != nullptr ? entry->wire_type : nullptr;
}

bool usb_operation_is_retained_response_read_cleanup(
    UsbOperationType operation)
{
    const UsbOperationManifestEntry* entry =
        usb_operation_manifest_entry(operation);
    if (entry == nullptr) {
        return false;
    }
    return entry->completion_policy ==
               UsbOperationCompletionPolicy::signing_retained_response_read ||
           entry->completion_policy ==
               UsbOperationCompletionPolicy::signing_retained_response_ack;
}

}  // namespace signing
