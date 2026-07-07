#pragma once

#include <ArduinoJson.h>

#include "signing/signing_retry_delivery.h"

namespace signing {

enum class RetryResponseResult {
    not_found,
    replayed_result,
    replay_write_failed,
    error_response,
    error_write_failed,
    invalid_stored_response,
};

using RetryResponseWriter = bool (*)(JsonDocument& response, void* context);

RetryResponseResult deliver_signing_retry_response(
    const char* request_id,
    const char* method,
    const RetryDeliveryResult& retry,
    const char* stored_response,
    RetryResponseWriter write_response,
    void* context);

}  // namespace signing
