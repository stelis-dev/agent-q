#include "agent_q_signing_retry_delivery.h"

#include <string.h>

namespace agent_q {

AgentQSigningRetryDeliveryResult evaluate_signing_retry_delivery(
    const char* session_id,
    const char* request_id,
    const uint8_t* request_identity,
    size_t request_identity_size,
    char* stored_result,
    size_t stored_result_size)
{
    AgentQSigningRetryDeliveryResult result = {};
    result.status = AgentQSigningRetryDeliveryStatus::lookup_error;
    result.error_code = "internal_output_error";

    const SigningResultRetryLookup lookup =
        signing_result_find_for_retry(
            session_id,
            request_id,
            request_identity,
            request_identity_size,
            stored_result,
            stored_result_size,
            &result.stored_result_len);

    switch (lookup) {
        case SigningResultRetryLookup::not_found:
            result.status = AgentQSigningRetryDeliveryStatus::not_found;
            result.error_code = nullptr;
            if (stored_result != nullptr && stored_result_size > 0) {
                memset(stored_result, 0, stored_result_size);
            }
            result.stored_result_len = 0;
            return result;
        case SigningResultRetryLookup::match:
            result.status = AgentQSigningRetryDeliveryStatus::match;
            result.error_code = nullptr;
            return result;
        case SigningResultRetryLookup::conflict:
            result.status = AgentQSigningRetryDeliveryStatus::request_id_conflict;
            result.error_code = "request_id_conflict";
            if (stored_result != nullptr && stored_result_size > 0) {
                memset(stored_result, 0, stored_result_size);
            }
            result.stored_result_len = 0;
            return result;
        case SigningResultRetryLookup::invalid:
            break;
    }

    if (stored_result != nullptr && stored_result_size > 0) {
        memset(stored_result, 0, stored_result_size);
    }
    result.stored_result_len = 0;
    return result;
}

}  // namespace agent_q
