#include "signing_retry_delivery.h"

#include <string.h>

namespace signing {

RetryDeliveryResult evaluate_signing_retry_delivery(
    const char* session_id,
    const char* request_id,
    const uint8_t* request_identity,
    size_t request_identity_size,
    char* stored_response,
    size_t stored_response_size)
{
    RetryDeliveryResult result = {};
    result.status = RetryDeliveryStatus::lookup_error;
    result.error_code = "internal_output_error";

    const ResponseRetryLookup lookup =
        signing_response_find_for_retry(
            session_id,
            request_id,
            request_identity,
            request_identity_size,
            stored_response,
            stored_response_size,
            &result.stored_response_len);

    switch (lookup) {
        case ResponseRetryLookup::not_found:
            result.status = RetryDeliveryStatus::not_found;
            result.error_code = nullptr;
            if (stored_response != nullptr && stored_response_size > 0) {
                memset(stored_response, 0, stored_response_size);
            }
            result.stored_response_len = 0;
            return result;
        case ResponseRetryLookup::match:
            result.status = RetryDeliveryStatus::match;
            result.error_code = nullptr;
            return result;
        case ResponseRetryLookup::conflict:
            result.status = RetryDeliveryStatus::request_id_conflict;
            result.error_code = "request_id_conflict";
            if (stored_response != nullptr && stored_response_size > 0) {
                memset(stored_response, 0, stored_response_size);
            }
            result.stored_response_len = 0;
            return result;
        case ResponseRetryLookup::invalid:
            break;
    }

    if (stored_response != nullptr && stored_response_size > 0) {
        memset(stored_response, 0, stored_response_size);
    }
    result.stored_response_len = 0;
    return result;
}

}  // namespace signing
