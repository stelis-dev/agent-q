#pragma once

#include "agent_q_payload_delivery_operation_kind.h"
#include "agent_q_usb_operation_type.h"

namespace agent_q {

enum class AgentQUsbOperationHandlerSlot {
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

enum class AgentQUsbOperationTerminalResultPolicy {
    immediate_response,
    connect_approval_result,
    signing_retained_result,
    signing_retained_result_read,
    signing_retained_result_ack,
    policy_update_result_history_marker,
    credential_propose_result,
};

enum class AgentQUsbOperationReadSideEffectPolicy {
    none,
    persistent_material_consistency_refresh,
};

struct AgentQUsbOperationManifestEntry {
    AgentQUsbOperationType type;
    const char* wire_type;
    AgentQUsbOperationHandlerSlot handler_slot;
    AgentQPayloadDeliveryOperationKind payload_delivery_operation;
    AgentQUsbOperationTerminalResultPolicy terminal_result_policy;
    AgentQUsbOperationReadSideEffectPolicy read_side_effect_policy;
};

const AgentQUsbOperationManifestEntry* usb_operation_manifest_entry(
    AgentQUsbOperationType operation);
const AgentQUsbOperationManifestEntry* usb_operation_manifest_entry_for_wire_type(
    const char* wire_type);

}  // namespace agent_q
