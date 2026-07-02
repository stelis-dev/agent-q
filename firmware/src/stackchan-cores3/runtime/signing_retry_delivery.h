#pragma once

#include <stddef.h>
#include <stdint.h>

#include "signing_response_store.h"

namespace signing {

enum class RetryDeliveryStatus {
    not_found,
    match,
    request_id_conflict,
    lookup_error,
};

struct RetryDeliveryResult {
    RetryDeliveryStatus status;
    size_t stored_response_len;
    const char* error_code;
};

RetryDeliveryResult evaluate_signing_retry_delivery(
    const char* session_id,
    const char* request_id,
    const uint8_t* request_identity,
    size_t request_identity_size,
    char* stored_response,
    size_t stored_response_size);

}  // namespace signing
