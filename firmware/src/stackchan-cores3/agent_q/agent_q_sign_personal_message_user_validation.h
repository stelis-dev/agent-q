#pragma once

#include <stddef.h>
#include <stdint.h>

#include <ArduinoJson.h>

#include "agent_q_sign_personal_message_limits.h"
#include "agent_q_session.h"
#include "agent_q_user_signing_limits.h"

namespace agent_q {

constexpr size_t kAgentQUserSigningPersonalMessageBase64Size =
    kAgentQSuiSignPersonalMessageMaxBase64Size + 1;

enum class AgentQSignPersonalMessageUserValidationResult {
    ok,
    invalid_request_shape,
    unsupported_version,
    unsupported_type,
    invalid_session,
    invalid_params_shape,
    unsupported_field,
    unsupported_method,
    invalid_network,
    invalid_message,
};

struct AgentQSignPersonalMessageUserEnvelope {
    char request_id[kAgentQUserSigningIdSize];
};

struct AgentQSignPersonalMessageUserSessionRef {
    char session_id[kAgentQSessionIdSize];
};

struct AgentQSignPersonalMessageUserParams {
    char chain[kAgentQUserSigningChainSize];
    char method[kAgentQUserSigningMethodSize];
    char network[kAgentQUserSigningNetworkSize];
    char message_base64[kAgentQUserSigningPersonalMessageBase64Size];
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
    AgentQSignPersonalMessageUserParams* output);

const char* sign_personal_message_user_validation_result_name(
    AgentQSignPersonalMessageUserValidationResult result);

}  // namespace agent_q
