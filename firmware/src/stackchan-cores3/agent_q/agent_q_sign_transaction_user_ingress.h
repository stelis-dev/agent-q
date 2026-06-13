#pragma once

#include <ArduinoJson.h>

#include "agent_q_payload_delivery_admission.h"
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
    invalid_payload_ref,
    invalid_payload_descriptor,
};

using AgentQSignTransactionUserSessionValidateFn =
    AgentQSessionValidationResult (*)(const char* session_id, void* context);

struct AgentQSignTransactionUserIngressState {
    AgentQTimeoutTick now_tick;
    bool material_ready;
    bool busy;
    AgentQSignTransactionUserSessionValidateFn validate_session;
    void* session_context;
    AgentQPayloadDeliverySignTransactionAdmissionFn admit_payload_delivery = nullptr;
    void* payload_delivery_admission_context = nullptr;
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
