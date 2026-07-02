#pragma once

#include <ArduinoJson.h>

#include "payload_delivery_admission.h"
#include "session.h"
#include "sign_transaction_user_validation.h"

namespace signing {

enum class SignTransactionUserIngressResult {
    ok,
    invalid_request_shape,
    unsupported_version,
    invalid_state,
    busy,
    invalid_session,
    invalid_params_shape,
    unsupported_field,
    unsupported_method,
    invalid_network,
    invalid_tx_bytes,
};

using SignTransactionUserSessionValidateFn =
    SessionValidationResult (*)(const char* session_id, void* context);

struct SignTransactionUserIngressState {
    TimeoutTick now_tick;
    bool material_ready;
    bool busy;
    SignTransactionUserSessionValidateFn validate_session;
    void* session_context;
    PayloadDeliveryOperationAdmissionFn admit_payload_delivery = nullptr;
};

struct SignTransactionUserIngressOutput {
    SignTransactionUserEnvelope envelope;
    SignTransactionUserSessionRef session;
    SignTransactionUserParams params;
};

SignTransactionUserIngressResult evaluate_sign_transaction_user_ingress(
    JsonDocument& request,
    SupportedSignRoute route,
    const SignTransactionUserIngressState& state,
    SignTransactionUserIngressOutput* output);

const char* sign_transaction_user_ingress_result_name(
    SignTransactionUserIngressResult result);

}  // namespace signing
