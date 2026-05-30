#pragma once

#include <stddef.h>

#include <ArduinoJson.h>

namespace agent_q {

constexpr size_t kCallMethodChainMaxLength = 32;
constexpr size_t kCallMethodNameMaxLength = 64;
constexpr size_t kCallMethodParamsJsonMaxBytes = 600;
constexpr size_t kSuiSignTransactionTxBytesMaxBytes = 384;
constexpr size_t kSuiSignTransactionTxBytesMaxBase64Size = 512;

enum class CallMethodFieldValidation {
    valid,
    invalid_method,
    invalid_params_shape,
    invalid_params_size,
};

bool is_call_method_identifier(const char* value, size_t max_length);

// Validate the shared call_method request fields after Firmware state/session
// gates have passed. This helper intentionally does not inspect provisioning,
// session, UI, policy, or signing state.
CallMethodFieldValidation validate_call_method_request_fields(JsonDocument& request);

// Validate the currently recognized Sui sign_transaction smoke params. Returns
// the decoded txBytes size when the base64 is canonical and inside the runtime
// envelope bounds.
bool validate_sui_sign_transaction_params(JsonVariant params, size_t* decoded_tx_size);

}  // namespace agent_q
