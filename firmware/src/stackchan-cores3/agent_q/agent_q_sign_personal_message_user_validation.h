#pragma once

#include <stddef.h>
#include <stdint.h>

#include <ArduinoJson.h>

#include "agent_q_session.h"
#include "agent_q_sign_route.h"
#include "agent_q_user_signing_limits.h"

namespace agent_q {

enum class AgentQSignPersonalMessageUserValidationResult {
    ok,
    invalid_request_shape,
    unsupported_version,
    invalid_session,
    invalid_params_shape,
    unsupported_field,
    unsupported_method,
    invalid_network,
    invalid_message,
    message_too_large,
};

struct AgentQSignPersonalMessageUserEnvelope {
    char request_id[kAgentQUserSigningIdSize];
};

struct AgentQSignPersonalMessageUserSessionRef {
    char session_id[kAgentQSessionIdSize];
};

struct AgentQSignPersonalMessageUserParams {
    char network[kAgentQUserSigningNetworkSize];
    const char* message_base64;
    size_t message_decoded_size;
};

AgentQSignPersonalMessageUserValidationResult
validate_sign_personal_message_user_envelope(
    JsonDocument& request,
    AgentQSignPersonalMessageUserEnvelope* output);

AgentQSignPersonalMessageUserValidationResult
validate_sign_personal_message_user_session_format(
    JsonDocument& request,
    AgentQSignPersonalMessageUserSessionRef* output);

AgentQSignPersonalMessageUserValidationResult
validate_sign_personal_message_user_params(
    JsonDocument& request,
    AgentQSupportedSignRoute route,
    AgentQSignPersonalMessageUserParams* output);

const char* sign_personal_message_user_validation_result_name(
    AgentQSignPersonalMessageUserValidationResult result);

}  // namespace agent_q
