#pragma once

#include <ArduinoJson.h>

#include "protocol/session_state.h"
#include "sign_personal_message_user_validation.h"

namespace signing {

enum class SignPersonalMessageUserIngressResult {
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
    invalid_message,
    message_too_large,
};

using SignPersonalMessageUserSessionValidateFn =
    SessionValidationResult (*)(const char* session_id, void* context);

struct SignPersonalMessageUserIngressState {
    bool material_ready;
    bool busy;
    SignPersonalMessageUserSessionValidateFn validate_session;
    void* session_context;
};

struct SignPersonalMessageUserIngressOutput {
    SignPersonalMessageUserEnvelope envelope;
    SignPersonalMessageUserSessionRef session;
    SignPersonalMessageUserParams params;
};

SignPersonalMessageUserIngressResult
evaluate_sign_personal_message_user_ingress(
    JsonDocument& request,
    SupportedSignRoute route,
    const SignPersonalMessageUserIngressState& state,
    SignPersonalMessageUserIngressOutput* output);

const char* sign_personal_message_user_ingress_result_name(
    SignPersonalMessageUserIngressResult result);

}  // namespace signing
