#include "protocol/operation_manifest.h"

#include <stddef.h>

namespace signing {
namespace {

constexpr OperationManifestEntry kOperationManifest[] = {
    {
        OperationType::get_status,
        OperationHandlerSlot::get_status,
        PayloadDeliveryOperationKind::safe_read,
        OperationCompletionPolicy::immediate_response,
        OperationReadSideEffectPolicy::persistent_material_consistency_refresh,
    },
    {
        OperationType::identify_device,
        OperationHandlerSlot::identify_device,
        PayloadDeliveryOperationKind::identify_device,
        OperationCompletionPolicy::immediate_response,
        OperationReadSideEffectPolicy::none,
    },
    {
        OperationType::connect,
        OperationHandlerSlot::connect,
        PayloadDeliveryOperationKind::connect,
        OperationCompletionPolicy::connect_approval,
        OperationReadSideEffectPolicy::none,
    },
    {
        OperationType::sign_transaction,
        OperationHandlerSlot::sign_transaction,
        PayloadDeliveryOperationKind::sign_transaction,
        OperationCompletionPolicy::signing_retained_response,
        OperationReadSideEffectPolicy::none,
    },
    {
        OperationType::sign_personal_message,
        OperationHandlerSlot::sign_personal_message,
        PayloadDeliveryOperationKind::sign_personal_message,
        OperationCompletionPolicy::signing_retained_response,
        OperationReadSideEffectPolicy::none,
    },
    {
        OperationType::get_result,
        OperationHandlerSlot::get_result,
        PayloadDeliveryOperationKind::retained_response_read_cleanup,
        OperationCompletionPolicy::signing_retained_response_read,
        OperationReadSideEffectPolicy::none,
    },
    {
        OperationType::ack_result,
        OperationHandlerSlot::ack_result,
        PayloadDeliveryOperationKind::retained_response_read_cleanup,
        OperationCompletionPolicy::signing_retained_response_ack,
        OperationReadSideEffectPolicy::none,
    },
    {
        OperationType::disconnect,
        OperationHandlerSlot::disconnect,
        PayloadDeliveryOperationKind::disconnect,
        OperationCompletionPolicy::immediate_response,
        OperationReadSideEffectPolicy::none,
    },
    {
        OperationType::get_capabilities,
        OperationHandlerSlot::get_capabilities,
        PayloadDeliveryOperationKind::safe_read,
        OperationCompletionPolicy::immediate_response,
        OperationReadSideEffectPolicy::none,
    },
    {
        OperationType::get_accounts,
        OperationHandlerSlot::get_accounts,
        PayloadDeliveryOperationKind::safe_read,
        OperationCompletionPolicy::immediate_response,
        OperationReadSideEffectPolicy::none,
    },
    {
        OperationType::policy_get,
        OperationHandlerSlot::policy_get,
        PayloadDeliveryOperationKind::safe_read,
        OperationCompletionPolicy::immediate_response,
        OperationReadSideEffectPolicy::none,
    },
    {
        OperationType::get_approval_history,
        OperationHandlerSlot::get_approval_history,
        PayloadDeliveryOperationKind::safe_read,
        OperationCompletionPolicy::immediate_response,
        OperationReadSideEffectPolicy::none,
    },
    {
        OperationType::policy_propose,
        OperationHandlerSlot::policy_propose,
        PayloadDeliveryOperationKind::policy_propose,
        OperationCompletionPolicy::policy_update_history_marker,
        OperationReadSideEffectPolicy::none,
    },
    {
        OperationType::credential_prepare,
        OperationHandlerSlot::credential_prepare,
        PayloadDeliveryOperationKind::safe_read,
        OperationCompletionPolicy::immediate_response,
        OperationReadSideEffectPolicy::none,
    },
    {
        OperationType::credential_propose,
        OperationHandlerSlot::credential_propose,
        PayloadDeliveryOperationKind::credential_propose,
        OperationCompletionPolicy::credential_proposal_outcome,
        OperationReadSideEffectPolicy::none,
    },
    {
        OperationType::payload_transfer_begin,
        OperationHandlerSlot::payload_transfer_begin,
        PayloadDeliveryOperationKind::payload_transfer_begin,
        OperationCompletionPolicy::immediate_response,
        OperationReadSideEffectPolicy::none,
    },
    {
        OperationType::payload_transfer_chunk,
        OperationHandlerSlot::payload_transfer_chunk,
        PayloadDeliveryOperationKind::payload_transfer_chunk,
        OperationCompletionPolicy::immediate_response,
        OperationReadSideEffectPolicy::none,
    },
    {
        OperationType::payload_transfer_finish,
        OperationHandlerSlot::payload_transfer_finish,
        PayloadDeliveryOperationKind::payload_transfer_finish,
        OperationCompletionPolicy::immediate_response,
        OperationReadSideEffectPolicy::none,
    },
    {
        OperationType::payload_transfer_abort,
        OperationHandlerSlot::payload_transfer_abort,
        PayloadDeliveryOperationKind::payload_transfer_abort,
        OperationCompletionPolicy::immediate_response,
        OperationReadSideEffectPolicy::none,
    },
};

}  // namespace

const OperationManifestEntry* operation_manifest_entry(
    OperationType operation)
{
    for (const OperationManifestEntry& entry : kOperationManifest) {
        if (entry.type == operation) {
            return &entry;
        }
    }
    return nullptr;
}

const OperationManifestEntry* operation_manifest_entry_for_wire_type(
    const char* wire_type)
{
    const OperationType operation = classify_operation_type(wire_type);
    if (operation == OperationType::unsupported) {
        return nullptr;
    }
    return operation_manifest_entry(operation);
}

}  // namespace signing
