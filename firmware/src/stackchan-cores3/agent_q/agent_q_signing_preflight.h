#pragma once

#include <ArduinoJson.h>

#include "agent_q_sign_personal_message_user_ingress.h"
#include "agent_q_sign_request_identity.h"
#include "agent_q_sign_transaction_user_ingress.h"
#include "agent_q_signing_mode.h"
#include "agent_q_signing_retry_delivery.h"
#include "agent_q_sui_signing_preparation.h"

namespace agent_q {

enum class AgentQSigningPreflightResult {
    ok,
    route_invalid_params,
    route_unsupported_chain,
    route_unsupported_method,
    transaction_ingress_error,
    personal_message_ingress_error,
    identity_error,
    retry_consumed,
    signing_mode_unavailable,
    personal_message_policy_mode,
    transaction_preparation_error,
    personal_message_preparation_error,
};

enum class AgentQSigningPreflightRetryDisposition {
    continue_preflight,
    consumed,
};

using AgentQSigningModeReadFn =
    bool (*)(AgentQSigningAuthorizationMode* mode, void* context);

using AgentQSigningPreflightRetryResponder =
    AgentQSigningPreflightRetryDisposition (*)(
        const char* request_id,
        const AgentQSigningRetryDeliveryResult& retry,
        const char* stored_result,
        void* context);

struct AgentQSigningPreflightRuntime {
    AgentQSigningModeReadFn read_signing_mode;
    void* signing_mode_context;
    AgentQSigningPreflightRetryResponder retry_responder;
    void* retry_responder_context;
    char* retry_stored_result;
    size_t retry_stored_result_size;
};

struct AgentQSignTransactionPreflightOutput {
    AgentQSupportedSignRoute route;
    AgentQSignRouteResult route_result;
    AgentQSignTransactionUserIngressResult ingress_result;
    AgentQSuiSigningPreparationResult preparation_result;
    AgentQSigningAuthorizationMode signing_mode;
    AgentQSignTransactionUserIngressOutput ingress;
    uint8_t request_identity[kAgentQSignRequestIdentitySize];
    AgentQSuiPreparedSignTransaction prepared;
};

struct AgentQSignPersonalMessagePreflightOutput {
    AgentQSupportedSignRoute route;
    AgentQSignRouteResult route_result;
    AgentQSignPersonalMessageUserIngressResult ingress_result;
    AgentQSuiSigningPreparationResult preparation_result;
    AgentQSigningAuthorizationMode signing_mode;
    AgentQSignPersonalMessageUserIngressOutput ingress;
    uint8_t request_identity[kAgentQSignRequestIdentitySize];
    AgentQSuiPreparedPersonalMessage prepared;
};

AgentQSigningPreflightResult evaluate_sign_transaction_preflight(
    JsonDocument& request,
    const AgentQSignTransactionUserIngressState& state,
    const AgentQSigningPreflightRuntime& runtime,
    AgentQSignTransactionPreflightOutput* output);

AgentQSigningPreflightResult evaluate_sign_personal_message_preflight(
    JsonDocument& request,
    const AgentQSignPersonalMessageUserIngressState& state,
    const AgentQSigningPreflightRuntime& runtime,
    AgentQSignPersonalMessagePreflightOutput* output);

}  // namespace agent_q
