#include "agent_q_signing_retry_delivery.h"

#include <string.h>

namespace agent_q {

AgentQSigningRetryDeliveryResult evaluate_signing_retry_delivery(
    const char* session_id,
    const char* request_id,
    const uint8_t* request_identity,
    size_t request_identity_size)
{
    AgentQSigningRetryDeliveryResult result = {};
    result.status = AgentQSigningRetryDeliveryStatus::lookup_error;
    result.error_code = "protocol_error";
    result.error_message = "Stored signing result lookup failed.";

    const SigningResultRetryLookup lookup =
        signing_result_find_for_retry(
            session_id,
            request_id,
            request_identity,
            request_identity_size,
            result.stored_result,
            sizeof(result.stored_result),
            &result.stored_result_len);

    switch (lookup) {
        case SigningResultRetryLookup::not_found:
            result.status = AgentQSigningRetryDeliveryStatus::not_found;
            result.error_code = nullptr;
            result.error_message = nullptr;
            memset(result.stored_result, 0, sizeof(result.stored_result));
            result.stored_result_len = 0;
            return result;
        case SigningResultRetryLookup::match:
            result.status = AgentQSigningRetryDeliveryStatus::match;
            result.error_code = nullptr;
            result.error_message = nullptr;
            return result;
        case SigningResultRetryLookup::conflict:
            result.status = AgentQSigningRetryDeliveryStatus::request_id_conflict;
            result.error_code = "request_id_conflict";
            result.error_message = "Request id is already bound to a different signing request.";
            memset(result.stored_result, 0, sizeof(result.stored_result));
            result.stored_result_len = 0;
            return result;
        case SigningResultRetryLookup::invalid:
            break;
    }

    memset(result.stored_result, 0, sizeof(result.stored_result));
    result.stored_result_len = 0;
    return result;
}

}  // namespace agent_q
