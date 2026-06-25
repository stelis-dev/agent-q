#pragma once

#include <ArduinoJson.h>

#include "agent_q_signing_retry_delivery.h"

namespace agent_q {

enum class AgentQSigningRetryResponseResult {
    not_found,
    replayed_result,
    replay_write_failed,
    error_response,
    error_write_failed,
    invalid_stored_response,
};

using AgentQSigningRetryResponseWriter = bool (*)(JsonDocument& response, void* context);

AgentQSigningRetryResponseResult deliver_signing_retry_response(
    const char* request_id,
    const char* method,
    const AgentQSigningRetryDeliveryResult& retry,
    const char* stored_response,
    AgentQSigningRetryResponseWriter write_response,
    void* context);

}  // namespace agent_q
