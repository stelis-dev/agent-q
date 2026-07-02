#pragma once

#include <stddef.h>
#include <stdint.h>

#include <ArduinoJson.h>

#include "session.h"
#include "protocol/sign_route.h"
#include "user_signing_limits.h"

namespace signing {

enum class SignTransactionUserValidationResult {
    ok,
    invalid_request_shape,
    unsupported_version,
    invalid_session,
    invalid_params_shape,
    unsupported_field,
    unsupported_method,
    invalid_network,
    invalid_tx_bytes,
};

struct SignTransactionUserEnvelope {
    char request_id[kUserSigningIdSize];
};

struct SignTransactionUserSessionRef {
    char session_id[kSessionIdSize];
};

struct SignTransactionUserParams {
    char network[kUserSigningNetworkSize];
    const char* tx_bytes_base64;
    size_t tx_bytes_decoded_size;
};

SignTransactionUserValidationResult validate_sign_transaction_user_envelope(
    JsonDocument& request,
    SignTransactionUserEnvelope* output);

SignTransactionUserValidationResult validate_sign_transaction_user_session_format(
    JsonDocument& request,
    SignTransactionUserSessionRef* output);

SignTransactionUserValidationResult validate_sign_transaction_user_params(
    JsonDocument& request,
    SupportedSignRoute route,
    SignTransactionUserParams* output);

const char* sign_transaction_user_validation_result_name(
    SignTransactionUserValidationResult result);

}  // namespace signing
