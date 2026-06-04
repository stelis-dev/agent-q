#pragma once

#include <ArduinoJson.h>

#include "agent_q_session.h"
#include "agent_q_sign_by_user_validation.h"

namespace agent_q {

enum class AgentQSignByUserIngressResult {
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
};

using AgentQSignByUserSessionValidateFn =
    AgentQSessionValidationResult (*)(const char* session_id, void* context);

struct AgentQSignByUserIngressState {
    bool material_ready;
    bool busy;
    AgentQSignByUserSessionValidateFn validate_session;
    void* session_context;
};

struct AgentQSignByUserIngressOutput {
    AgentQSignByUserEnvelope envelope;
    AgentQSignByUserSessionRef session;
    AgentQSignByUserParams params;
};

AgentQSignByUserIngressResult evaluate_sign_by_user_ingress(
    JsonDocument& request,
    const AgentQSignByUserIngressState& state,
    AgentQSignByUserIngressOutput* output);

const char* sign_by_user_ingress_result_name(
    AgentQSignByUserIngressResult result);

}  // namespace agent_q
