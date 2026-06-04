#pragma once

#include <stddef.h>
#include <stdint.h>

#include <ArduinoJson.h>

#include "agent_q_method_limits.h"
#include "agent_q_session.h"
#include "agent_q_sign_by_user_limits.h"

namespace agent_q {

constexpr uint32_t kAgentQSignByUserApprovalWindowMs = 30000;
constexpr size_t kAgentQSignByUserTxBytesBase64Size =
    kAgentQSuiSignTransactionTxBytesMaxBase64Size + 1;

enum class AgentQSignByUserValidationResult {
    ok,
    invalid_request_shape,
    unsupported_version,
    unsupported_type,
    invalid_session,
    invalid_params_shape,
    unsupported_field,
    unsupported_method,
    invalid_network,
    invalid_tx_bytes,
};

struct AgentQSignByUserEnvelope {
    char request_id[kAgentQSignByUserIdSize];
};

struct AgentQSignByUserSessionRef {
    char session_id[kAgentQSessionIdSize];
};

struct AgentQSignByUserParams {
    char chain[kAgentQSignByUserChainSize];
    char method[kAgentQSignByUserMethodSize];
    char network[kAgentQSignByUserNetworkSize];
    char tx_bytes_base64[kAgentQSignByUserTxBytesBase64Size];
    size_t tx_bytes_decoded_size;
};

AgentQSignByUserValidationResult validate_sign_by_user_envelope(
    JsonDocument& request,
    AgentQSignByUserEnvelope* output);

AgentQSignByUserValidationResult validate_sign_by_user_session_format(
    JsonDocument& request,
    AgentQSignByUserSessionRef* output);

AgentQSignByUserValidationResult validate_sign_by_user_params(
    JsonDocument& request,
    AgentQSignByUserParams* output);

const char* sign_by_user_validation_result_name(
    AgentQSignByUserValidationResult result);

}  // namespace agent_q
