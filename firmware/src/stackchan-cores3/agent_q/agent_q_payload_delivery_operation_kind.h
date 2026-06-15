#pragma once

namespace agent_q {

enum class AgentQPayloadDeliveryOperationKind {
    safe_read,
    retained_result_read_cleanup,
    payload_upload_begin,
    payload_upload_chunk,
    payload_upload_finish,
    payload_upload_abort,
    sign_transaction,
    sign_personal_message,
    policy_propose,
    connect,
    identify_device,
    disconnect,
};

}  // namespace agent_q
