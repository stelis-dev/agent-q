#pragma once

#include <stddef.h>
#include <stdint.h>

#include <ArduinoJson.h>

#include "agent_q_payload_delivery_primitives.h"
#include "agent_q_session.h"
#include "agent_q_sign_route.h"
#include "agent_q_user_signing_limits.h"

namespace agent_q {

enum class AgentQSignTransactionUserValidationResult {
    ok,
    invalid_request_shape,
    unsupported_version,
    invalid_session,
    invalid_params_shape,
    unsupported_field,
    unsupported_method,
    invalid_network,
    invalid_tx_bytes,
    invalid_payload_ref,
    invalid_payload_descriptor,
};

struct AgentQSignTransactionUserEnvelope {
    char request_id[kAgentQUserSigningIdSize];
};

struct AgentQSignTransactionUserSessionRef {
    char session_id[kAgentQSessionIdSize];
};

enum class AgentQSignTransactionPayloadForm {
    inline_tx_bytes,
    staged_payload_ref,
};

struct AgentQSignTransactionUserParams {
    AgentQSignTransactionPayloadForm payload_form;
    char network[kAgentQUserSigningNetworkSize];
    const char* tx_bytes_base64;
    size_t tx_bytes_decoded_size;
    char payload_ref[kAgentQPayloadDeliveryPayloadRefSize];
};

AgentQSignTransactionUserValidationResult validate_sign_transaction_user_envelope(
    JsonDocument& request,
    AgentQSignTransactionUserEnvelope* output);

AgentQSignTransactionUserValidationResult validate_sign_transaction_user_session_format(
    JsonDocument& request,
    AgentQSignTransactionUserSessionRef* output);

AgentQSignTransactionUserValidationResult validate_sign_transaction_user_params(
    JsonDocument& request,
    AgentQSupportedSignRoute route,
    AgentQSignTransactionUserParams* output);

const char* sign_transaction_user_validation_result_name(
    AgentQSignTransactionUserValidationResult result);

}  // namespace agent_q
