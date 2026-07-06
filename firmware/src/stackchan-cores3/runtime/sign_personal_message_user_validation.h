#pragma once

#include <stddef.h>
#include <stdint.h>

#include <ArduinoJson.h>

#include "protocol/session_state.h"
#include "protocol/sign_route.h"
#include "signing/user_signing_limits.h"

namespace signing {

enum class SignPersonalMessageUserValidationResult {
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

struct SignPersonalMessageUserEnvelope {
    char request_id[kUserSigningIdSize];
};

struct SignPersonalMessageUserSessionRef {
    char session_id[kSessionIdSize];
};

struct SignPersonalMessageUserParams {
    char network[kUserSigningNetworkSize];
    const char* message_base64;
    size_t message_decoded_size;
};

SignPersonalMessageUserValidationResult
validate_sign_personal_message_user_envelope(
    JsonDocument& request,
    SignPersonalMessageUserEnvelope* output);

SignPersonalMessageUserValidationResult
validate_sign_personal_message_user_session_format(
    JsonDocument& request,
    SignPersonalMessageUserSessionRef* output);

SignPersonalMessageUserValidationResult
validate_sign_personal_message_user_params(
    JsonDocument& request,
    SupportedSignRoute route,
    SignPersonalMessageUserParams* output);

const char* sign_personal_message_user_validation_result_name(
    SignPersonalMessageUserValidationResult result);

}  // namespace signing
