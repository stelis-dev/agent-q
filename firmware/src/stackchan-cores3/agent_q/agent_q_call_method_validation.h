#pragma once

#include <stddef.h>

#include <ArduinoJson.h>

#include "agent_q_method_limits.h"

namespace agent_q {

constexpr size_t kCallMethodChainMaxLength = 32;
constexpr size_t kCallMethodNameMaxLength = 64;
constexpr size_t kCallMethodParamsJsonMaxBytes = 600;
constexpr size_t kSuiSignTransactionTxBytesMaxBytes = kAgentQSuiSignTransactionTxBytesMaxBytes;
constexpr size_t kSuiSignTransactionTxBytesMaxBase64Size =
    kAgentQSuiSignTransactionTxBytesMaxBase64Size;

enum class CallMethodFieldValidation {
    valid,
    invalid_method,
    invalid_params_shape,
    invalid_params_size,
};

enum class CallMethodNamespaceValidation {
    chain_scoped,
    admin_scoped,
    invalid_namespace,
};

bool is_call_method_identifier(const char* value, size_t max_length);

// Classify the call_method namespace by field presence, not by field value.
// Admin methods must not carry chain, and chain-scoped methods must not carry
// methodNamespace, even when the extra field is explicit JSON null.
CallMethodNamespaceValidation classify_call_method_namespace(JsonDocument& request);

// Validate the shared call_method request fields after Firmware state/session
// gates have passed. This helper intentionally does not inspect provisioning,
// session, UI, policy, or signing state.
CallMethodFieldValidation validate_call_method_request_fields(JsonDocument& request);

// Validate the currently recognized Sui sign_transaction params. Returns
// the decoded txBytes size when the base64 is canonical and inside the runtime
// envelope bounds.
bool validate_sui_sign_transaction_params(JsonVariant params, size_t* decoded_tx_size);

}  // namespace agent_q
