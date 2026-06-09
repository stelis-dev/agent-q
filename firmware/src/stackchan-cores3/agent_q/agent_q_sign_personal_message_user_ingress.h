#pragma once

#include <ArduinoJson.h>

#include "agent_q_session.h"
#include "agent_q_sign_personal_message_user_validation.h"

namespace agent_q {

enum class AgentQSignPersonalMessageUserIngressResult {
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
    invalid_message,
};

using AgentQSignPersonalMessageUserSessionValidateFn =
    AgentQSessionValidationResult (*)(const char* session_id, void* context);

struct AgentQSignPersonalMessageUserIngressState {
    bool material_ready;
    bool busy;
    AgentQSignPersonalMessageUserSessionValidateFn validate_session;
    void* session_context;
};

struct AgentQSignPersonalMessageUserIngressOutput {
    AgentQSignPersonalMessageUserEnvelope envelope;
    AgentQSignPersonalMessageUserSessionRef session;
    AgentQSignPersonalMessageUserParams params;
};

AgentQSignPersonalMessageUserIngressResult
evaluate_sign_personal_message_user_ingress(
    JsonDocument& request,
    AgentQSupportedSignRoute route,
    const AgentQSignPersonalMessageUserIngressState& state,
    AgentQSignPersonalMessageUserIngressOutput* output);

const char* sign_personal_message_user_ingress_result_name(
    AgentQSignPersonalMessageUserIngressResult result);

}  // namespace agent_q
