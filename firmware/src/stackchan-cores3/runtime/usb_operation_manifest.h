#pragma once

#include "transport/payload_delivery_operation_kind.h"
#include "usb_operation_type.h"

namespace signing {

enum class UsbOperationHandlerSlot {
    none,
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

enum class UsbOperationCompletionPolicy {
    immediate_response,
    connect_approval,
    signing_retained_response,
    signing_retained_response_read,
    signing_retained_response_ack,
    policy_update_history_marker,
    credential_proposal_outcome,
};

enum class UsbOperationReadSideEffectPolicy {
    none,
    persistent_material_consistency_refresh,
};

struct UsbOperationManifestEntry {
    UsbOperationType type;
    const char* wire_type;
    UsbOperationHandlerSlot handler_slot;
    PayloadDeliveryOperationKind payload_delivery_operation;
    UsbOperationCompletionPolicy completion_policy;
    UsbOperationReadSideEffectPolicy read_side_effect_policy;
};

const UsbOperationManifestEntry* usb_operation_manifest_entry(
    UsbOperationType operation);
const UsbOperationManifestEntry* usb_operation_manifest_entry_for_wire_type(
    const char* wire_type);

}  // namespace signing
