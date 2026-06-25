#include "agent_q_signing_retry_delivery.h"

#include <string.h>

namespace agent_q {

AgentQSigningRetryDeliveryResult evaluate_signing_retry_delivery(
    const char* session_id,
    const char* request_id,
    const uint8_t* request_identity,
    size_t request_identity_size,
    char* stored_response,
    size_t stored_response_size)
{
    AgentQSigningRetryDeliveryResult result = {};
    result.status = AgentQSigningRetryDeliveryStatus::lookup_error;
    result.error_code = "internal_output_error";

    const SigningResponseRetryLookup lookup =
        signing_response_find_for_retry(
            session_id,
            request_id,
            request_identity,
            request_identity_size,
            stored_response,
            stored_response_size,
            &result.stored_response_len);

    switch (lookup) {
        case SigningResponseRetryLookup::not_found:
            result.status = AgentQSigningRetryDeliveryStatus::not_found;
            result.error_code = nullptr;
            if (stored_response != nullptr && stored_response_size > 0) {
                memset(stored_response, 0, stored_response_size);
            }
            result.stored_response_len = 0;
            return result;
        case SigningResponseRetryLookup::match:
            result.status = AgentQSigningRetryDeliveryStatus::match;
            result.error_code = nullptr;
            return result;
        case SigningResponseRetryLookup::conflict:
            result.status = AgentQSigningRetryDeliveryStatus::request_id_conflict;
            result.error_code = "request_id_conflict";
            if (stored_response != nullptr && stored_response_size > 0) {
                memset(stored_response, 0, stored_response_size);
            }
            result.stored_response_len = 0;
            return result;
        case SigningResponseRetryLookup::invalid:
            break;
    }

    if (stored_response != nullptr && stored_response_size > 0) {
        memset(stored_response, 0, stored_response_size);
    }
    result.stored_response_len = 0;
    return result;
}

}  // namespace agent_q
