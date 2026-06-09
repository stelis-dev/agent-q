#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_signing_result_store.h"

namespace agent_q {

enum class AgentQSigningRetryDeliveryStatus {
    not_found,
    match,
    request_id_conflict,
    lookup_error,
};

struct AgentQSigningRetryDeliveryResult {
    AgentQSigningRetryDeliveryStatus status;
    size_t stored_result_len;
    const char* error_code;
    const char* error_message;
};

AgentQSigningRetryDeliveryResult evaluate_signing_retry_delivery(
    const char* session_id,
    const char* request_id,
    const uint8_t* request_identity,
    size_t request_identity_size,
    char* stored_result,
    size_t stored_result_size);

}  // namespace agent_q
