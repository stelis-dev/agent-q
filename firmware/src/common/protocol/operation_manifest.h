#pragma once

#include "transport/payload_delivery_operation_kind.h"
#include "protocol/operation_type.h"

namespace signing {

enum class OperationHandlerSlot {
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

enum class OperationCompletionPolicy {
    immediate_response,
    connect_approval,
    signing_retained_response,
    signing_retained_response_read,
    signing_retained_response_ack,
    policy_update_history_marker,
    credential_proposal_outcome,
};

enum class OperationReadSideEffectPolicy {
    none,
    persistent_material_consistency_refresh,
};

struct OperationManifestEntry {
    OperationType type;
    OperationHandlerSlot handler_slot;
    PayloadDeliveryOperationKind payload_delivery_operation;
    OperationCompletionPolicy completion_policy;
    OperationReadSideEffectPolicy read_side_effect_policy;
};

const OperationManifestEntry* operation_manifest_entry(
    OperationType operation);
const OperationManifestEntry* operation_manifest_entry_for_wire_type(
    const char* wire_type);

}  // namespace signing
