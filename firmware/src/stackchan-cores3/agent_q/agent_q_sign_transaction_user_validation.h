#pragma once

#include <stddef.h>
#include <stdint.h>

#include <ArduinoJson.h>

#include "agent_q_sign_transaction_limits.h"
#include "agent_q_session.h"
#include "agent_q_sign_transaction_user_limits.h"

namespace agent_q {

constexpr uint32_t kAgentQSignTransactionUserApprovalWindowMs = 30000;
constexpr size_t kAgentQSignTransactionUserTxBytesBase64Size =
    kAgentQSuiSignTransactionTxBytesMaxBase64Size + 1;

enum class AgentQSignTransactionUserValidationResult {
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

struct AgentQSignTransactionUserEnvelope {
    char request_id[kAgentQSignTransactionUserIdSize];
};

struct AgentQSignTransactionUserSessionRef {
    char session_id[kAgentQSessionIdSize];
};

struct AgentQSignTransactionUserParams {
    char chain[kAgentQSignTransactionUserChainSize];
    char method[kAgentQSignTransactionUserMethodSize];
    char network[kAgentQSignTransactionUserNetworkSize];
    char tx_bytes_base64[kAgentQSignTransactionUserTxBytesBase64Size];
    size_t tx_bytes_decoded_size;
};

AgentQSignTransactionUserValidationResult validate_sign_transaction_user_envelope(
    JsonDocument& request,
    AgentQSignTransactionUserEnvelope* output);

AgentQSignTransactionUserValidationResult validate_sign_transaction_user_session_format(
    JsonDocument& request,
    AgentQSignTransactionUserSessionRef* output);

AgentQSignTransactionUserValidationResult validate_sign_transaction_user_params(
    JsonDocument& request,
    AgentQSignTransactionUserParams* output);

const char* sign_transaction_user_validation_result_name(
    AgentQSignTransactionUserValidationResult result);

}  // namespace agent_q
