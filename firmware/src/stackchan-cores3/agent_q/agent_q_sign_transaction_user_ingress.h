#pragma once

#include <ArduinoJson.h>

#include "agent_q_session.h"
#include "agent_q_sign_transaction_user_validation.h"

namespace agent_q {

enum class AgentQSignTransactionUserIngressResult {
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

using AgentQSignTransactionUserSessionValidateFn =
    AgentQSessionValidationResult (*)(const char* session_id, void* context);

struct AgentQSignTransactionUserIngressState {
    bool material_ready;
    bool busy;
    AgentQSignTransactionUserSessionValidateFn validate_session;
    void* session_context;
};

struct AgentQSignTransactionUserIngressOutput {
    AgentQSignTransactionUserEnvelope envelope;
    AgentQSignTransactionUserSessionRef session;
    AgentQSignTransactionUserParams params;
};

AgentQSignTransactionUserIngressResult evaluate_sign_transaction_user_ingress(
    JsonDocument& request,
    AgentQSupportedSignRoute route,
    const AgentQSignTransactionUserIngressState& state,
    AgentQSignTransactionUserIngressOutput* output);

const char* sign_transaction_user_ingress_result_name(
    AgentQSignTransactionUserIngressResult result);

}  // namespace agent_q
