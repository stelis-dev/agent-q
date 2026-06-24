#include "agent_q_usb_operation_manifest.h"

#include <stddef.h>
#include <string.h>

namespace agent_q {
namespace {

constexpr AgentQUsbOperationManifestEntry kUsbOperationManifest[] = {
    {
        AgentQUsbOperationType::get_status,
        "get_status",
        AgentQUsbOperationHandlerSlot::get_status,
        AgentQPayloadDeliveryOperationKind::safe_read,
        AgentQUsbOperationTerminalResultPolicy::immediate_response,
        AgentQUsbOperationReadSideEffectPolicy::persistent_material_consistency_refresh,
    },
    {
        AgentQUsbOperationType::identify_device,
        "identify_device",
        AgentQUsbOperationHandlerSlot::identify_device,
        AgentQPayloadDeliveryOperationKind::identify_device,
        AgentQUsbOperationTerminalResultPolicy::immediate_response,
        AgentQUsbOperationReadSideEffectPolicy::none,
    },
    {
        AgentQUsbOperationType::connect,
        "connect",
        AgentQUsbOperationHandlerSlot::connect,
        AgentQPayloadDeliveryOperationKind::connect,
        AgentQUsbOperationTerminalResultPolicy::connect_approval_result,
        AgentQUsbOperationReadSideEffectPolicy::none,
    },
    {
        AgentQUsbOperationType::sign_transaction,
        "sign_transaction",
        AgentQUsbOperationHandlerSlot::sign_transaction,
        AgentQPayloadDeliveryOperationKind::sign_transaction,
        AgentQUsbOperationTerminalResultPolicy::signing_retained_result,
        AgentQUsbOperationReadSideEffectPolicy::none,
    },
    {
        AgentQUsbOperationType::sign_personal_message,
        "sign_personal_message",
        AgentQUsbOperationHandlerSlot::sign_personal_message,
        AgentQPayloadDeliveryOperationKind::sign_personal_message,
        AgentQUsbOperationTerminalResultPolicy::signing_retained_result,
        AgentQUsbOperationReadSideEffectPolicy::none,
    },
    {
        AgentQUsbOperationType::get_result,
        "get_result",
        AgentQUsbOperationHandlerSlot::get_result,
        AgentQPayloadDeliveryOperationKind::retained_result_read_cleanup,
        AgentQUsbOperationTerminalResultPolicy::signing_retained_result_read,
        AgentQUsbOperationReadSideEffectPolicy::none,
    },
    {
        AgentQUsbOperationType::ack_result,
        "ack_result",
        AgentQUsbOperationHandlerSlot::ack_result,
        AgentQPayloadDeliveryOperationKind::retained_result_read_cleanup,
        AgentQUsbOperationTerminalResultPolicy::signing_retained_result_ack,
        AgentQUsbOperationReadSideEffectPolicy::none,
    },
    {
        AgentQUsbOperationType::disconnect,
        "disconnect",
        AgentQUsbOperationHandlerSlot::disconnect,
        AgentQPayloadDeliveryOperationKind::disconnect,
        AgentQUsbOperationTerminalResultPolicy::immediate_response,
        AgentQUsbOperationReadSideEffectPolicy::none,
    },
    {
        AgentQUsbOperationType::get_capabilities,
        "get_capabilities",
        AgentQUsbOperationHandlerSlot::get_capabilities,
        AgentQPayloadDeliveryOperationKind::safe_read,
        AgentQUsbOperationTerminalResultPolicy::immediate_response,
        AgentQUsbOperationReadSideEffectPolicy::none,
    },
    {
        AgentQUsbOperationType::get_accounts,
        "get_accounts",
        AgentQUsbOperationHandlerSlot::get_accounts,
        AgentQPayloadDeliveryOperationKind::safe_read,
        AgentQUsbOperationTerminalResultPolicy::immediate_response,
        AgentQUsbOperationReadSideEffectPolicy::none,
    },
    {
        AgentQUsbOperationType::policy_get,
        "policy_get",
        AgentQUsbOperationHandlerSlot::policy_get,
        AgentQPayloadDeliveryOperationKind::safe_read,
        AgentQUsbOperationTerminalResultPolicy::immediate_response,
        AgentQUsbOperationReadSideEffectPolicy::none,
    },
    {
        AgentQUsbOperationType::get_approval_history,
        "get_approval_history",
        AgentQUsbOperationHandlerSlot::get_approval_history,
        AgentQPayloadDeliveryOperationKind::safe_read,
        AgentQUsbOperationTerminalResultPolicy::immediate_response,
        AgentQUsbOperationReadSideEffectPolicy::none,
    },
    {
        AgentQUsbOperationType::policy_propose,
        "policy_propose",
        AgentQUsbOperationHandlerSlot::policy_propose,
        AgentQPayloadDeliveryOperationKind::policy_propose,
        AgentQUsbOperationTerminalResultPolicy::policy_update_result_history_marker,
        AgentQUsbOperationReadSideEffectPolicy::none,
    },
    {
        AgentQUsbOperationType::credential_prepare,
        "credential_prepare",
        AgentQUsbOperationHandlerSlot::credential_prepare,
        AgentQPayloadDeliveryOperationKind::safe_read,
        AgentQUsbOperationTerminalResultPolicy::immediate_response,
        AgentQUsbOperationReadSideEffectPolicy::none,
    },
    {
        AgentQUsbOperationType::credential_propose,
        "credential_propose",
        AgentQUsbOperationHandlerSlot::credential_propose,
        AgentQPayloadDeliveryOperationKind::credential_propose,
        AgentQUsbOperationTerminalResultPolicy::credential_propose_result,
        AgentQUsbOperationReadSideEffectPolicy::none,
    },
    {
        AgentQUsbOperationType::payload_transfer_begin,
        "payload_transfer_begin",
        AgentQUsbOperationHandlerSlot::payload_transfer_begin,
        AgentQPayloadDeliveryOperationKind::payload_transfer_begin,
        AgentQUsbOperationTerminalResultPolicy::immediate_response,
        AgentQUsbOperationReadSideEffectPolicy::none,
    },
    {
        AgentQUsbOperationType::payload_transfer_chunk,
        "payload_transfer_chunk",
        AgentQUsbOperationHandlerSlot::payload_transfer_chunk,
        AgentQPayloadDeliveryOperationKind::payload_transfer_chunk,
        AgentQUsbOperationTerminalResultPolicy::immediate_response,
        AgentQUsbOperationReadSideEffectPolicy::none,
    },
    {
        AgentQUsbOperationType::payload_transfer_finish,
        "payload_transfer_finish",
        AgentQUsbOperationHandlerSlot::payload_transfer_finish,
        AgentQPayloadDeliveryOperationKind::payload_transfer_finish,
        AgentQUsbOperationTerminalResultPolicy::immediate_response,
        AgentQUsbOperationReadSideEffectPolicy::none,
    },
    {
        AgentQUsbOperationType::payload_transfer_abort,
        "payload_transfer_abort",
        AgentQUsbOperationHandlerSlot::payload_transfer_abort,
        AgentQPayloadDeliveryOperationKind::payload_transfer_abort,
        AgentQUsbOperationTerminalResultPolicy::immediate_response,
        AgentQUsbOperationReadSideEffectPolicy::none,
    },
};

}  // namespace

const AgentQUsbOperationManifestEntry* usb_operation_manifest_entry(
    AgentQUsbOperationType operation)
{
    for (const AgentQUsbOperationManifestEntry& entry : kUsbOperationManifest) {
        if (entry.type == operation) {
            return &entry;
        }
    }
    return nullptr;
}

const AgentQUsbOperationManifestEntry* usb_operation_manifest_entry_for_wire_type(
    const char* wire_type)
{
    if (wire_type == nullptr) {
        return nullptr;
    }
    for (const AgentQUsbOperationManifestEntry& entry : kUsbOperationManifest) {
        if (strcmp(entry.wire_type, wire_type) == 0) {
            return &entry;
        }
    }
    return nullptr;
}

AgentQUsbOperationType classify_usb_operation_type(const char* type)
{
    const AgentQUsbOperationManifestEntry* entry =
        usb_operation_manifest_entry_for_wire_type(type);
    return entry != nullptr ? entry->type : AgentQUsbOperationType::unsupported;
}

const char* usb_operation_type_wire_name(AgentQUsbOperationType operation)
{
    const AgentQUsbOperationManifestEntry* entry =
        usb_operation_manifest_entry(operation);
    return entry != nullptr ? entry->wire_type : nullptr;
}

bool usb_operation_is_retained_result_read_cleanup(
    AgentQUsbOperationType operation)
{
    const AgentQUsbOperationManifestEntry* entry =
        usb_operation_manifest_entry(operation);
    if (entry == nullptr) {
        return false;
    }
    return entry->terminal_result_policy ==
               AgentQUsbOperationTerminalResultPolicy::signing_retained_result_read ||
           entry->terminal_result_policy ==
               AgentQUsbOperationTerminalResultPolicy::signing_retained_result_ack;
}

}  // namespace agent_q
