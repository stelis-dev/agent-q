#pragma once

#include <stddef.h>
#include <stdint.h>

#include <ArduinoJson.h>

#include "agent_q_method_limits.h"
#include "agent_q_session.h"
#include "agent_q_signature_request_limits.h"

namespace agent_q {

constexpr uint32_t kAgentQSignatureRequestApprovalTimeoutDefaultMs = 30000;
constexpr uint32_t kAgentQSignatureRequestApprovalTimeoutMaxMs = 60000;
constexpr size_t kAgentQSignatureRequestTxBytesBase64Size =
    kAgentQSuiSignTransactionTxBytesMaxBase64Size + 1;

enum class AgentQSignatureRequestValidationResult {
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
    invalid_timeout,
};

struct AgentQSignatureRequestEnvelope {
    char request_id[kAgentQSignatureRequestIdSize];
};

struct AgentQSignatureRequestSessionRef {
    char session_id[kAgentQSessionIdSize];
};

struct AgentQSignatureRequestParams {
    char chain[kAgentQSignatureRequestChainSize];
    char method[kAgentQSignatureRequestMethodSize];
    char network[kAgentQSignatureRequestNetworkSize];
    char tx_bytes_base64[kAgentQSignatureRequestTxBytesBase64Size];
    size_t tx_bytes_decoded_size;
    uint32_t approval_timeout_ms;
};

AgentQSignatureRequestValidationResult validate_signature_request_envelope(
    JsonDocument& request,
    AgentQSignatureRequestEnvelope* output);

AgentQSignatureRequestValidationResult validate_signature_request_session_format(
    JsonDocument& request,
    AgentQSignatureRequestSessionRef* output);

AgentQSignatureRequestValidationResult validate_signature_request_params(
    JsonDocument& request,
    AgentQSignatureRequestParams* output);

const char* signature_request_validation_result_name(
    AgentQSignatureRequestValidationResult result);

}  // namespace agent_q
