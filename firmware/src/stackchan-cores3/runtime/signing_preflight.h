#pragma once

#include <ArduinoJson.h>

#include "sign_personal_message_user_ingress.h"
#include "sign_request_identity.h"
#include "sign_transaction_user_ingress.h"
#include "signing_mode.h"
#include "signing_retry_delivery.h"
#include "sui_signing_preparation.h"
#include "timeout_window.h"

namespace signing {

enum class PreflightResult {
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

enum class PreflightRetryDisposition {
    continue_preflight,
    consumed,
};

using ModeReadFn =
    bool (*)(AuthorizationMode* mode, void* context);

using PreflightRetryResponder =
    PreflightRetryDisposition (*)(
        const char* request_id,
        const char* method,
        const RetryDeliveryResult& retry,
        const char* stored_response,
        void* context);

struct PreflightRuntime {
    TimeoutTick now_tick;
    ModeReadFn read_signing_mode;
    void* signing_mode_context;
    PreflightRetryResponder retry_responder;
    void* retry_responder_context;
    char* retry_stored_response;
    size_t retry_stored_response_size;
};

struct SignTransactionPreflightOutput {
    SupportedSignRoute route;
    SignRouteResult route_result;
    SignTransactionUserIngressResult ingress_result;
    SuiSigningPreparationResult preparation_result;
    AuthorizationMode signing_mode;
    SignTransactionUserIngressOutput ingress;
    uint8_t request_identity[kSignRequestIdentitySize];
    SuiPreparedSignTransaction prepared;
};

struct SignPersonalMessagePreflightOutput {
    SupportedSignRoute route;
    SignRouteResult route_result;
    SignPersonalMessageUserIngressResult ingress_result;
    SuiSigningPreparationResult preparation_result;
    AuthorizationMode signing_mode;
    SignPersonalMessageUserIngressOutput ingress;
    uint8_t request_identity[kSignRequestIdentitySize];
    SuiPreparedPersonalMessage prepared;
};

PreflightResult evaluate_sign_transaction_preflight(
    JsonDocument& request,
    const SignTransactionUserIngressState& state,
    const PreflightRuntime& runtime,
    SignTransactionPreflightOutput* output);

PreflightResult evaluate_sign_personal_message_preflight(
    JsonDocument& request,
    const SignPersonalMessageUserIngressState& state,
    const PreflightRuntime& runtime,
    SignPersonalMessagePreflightOutput* output);

}  // namespace signing
