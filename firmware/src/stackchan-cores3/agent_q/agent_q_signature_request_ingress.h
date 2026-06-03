#pragma once

#include <ArduinoJson.h>

#include "agent_q_session.h"
#include "agent_q_signature_request_validation.h"

namespace agent_q {

enum class AgentQSignatureRequestIngressResult {
    ok,
    invalid_request_shape,
    unsupported_version,
    unsupported_type,
    invalid_state,
    busy,
    invalid_session,
    invalid_params_shape,
    unsupported_field,
    unsupported_method,
    invalid_network,
    invalid_tx_bytes,
    invalid_timeout,
};

using AgentQSignatureRequestSessionValidateFn =
    AgentQSessionValidationResult (*)(const char* session_id, void* context);

struct AgentQSignatureRequestIngressState {
    bool material_ready;
    bool busy;
    AgentQSignatureRequestSessionValidateFn validate_session;
    void* session_context;
};

struct AgentQSignatureRequestIngressOutput {
    AgentQSignatureRequestEnvelope envelope;
    AgentQSignatureRequestSessionRef session;
    AgentQSignatureRequestParams params;
};

AgentQSignatureRequestIngressResult evaluate_signature_request_ingress(
    JsonDocument& request,
    const AgentQSignatureRequestIngressState& state,
    AgentQSignatureRequestIngressOutput* output);

const char* signature_request_ingress_result_name(
    AgentQSignatureRequestIngressResult result);

}  // namespace agent_q
