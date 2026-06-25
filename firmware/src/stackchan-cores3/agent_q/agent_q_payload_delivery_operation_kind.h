#pragma once

namespace agent_q {

enum class AgentQPayloadDeliveryOperationKind {
    safe_read,
    retained_response_read_cleanup,
    payload_transfer_begin,
    payload_transfer_chunk,
    payload_transfer_finish,
    payload_transfer_abort,
    sign_transaction,
    sign_personal_message,
    policy_propose,
    credential_propose,
    connect,
    identify_device,
    disconnect,
};

}  // namespace agent_q
