#include "agent_q_signing_retry_response.h"

#include "agent_q_protocol_constants.h"

namespace agent_q {
namespace {

bool write_error(
    const char* request_id,
    const char* code,
    const char* message,
    AgentQSigningRetryResponseWriter write_response,
    void* context)
{
    if (write_response == nullptr) {
        return false;
    }
    JsonDocument response;
    if (request_id != nullptr && request_id[0] != '\0') {
        response["id"] = request_id;
    }
    response["version"] = kAgentQProtocolVersion;
    response["type"] = "error";
    response["error"]["code"] = code != nullptr ? code : "protocol_error";
    response["error"]["message"] =
        message != nullptr ? message : "Stored signing result lookup failed.";
    return write_response(response, context);
}

}  // namespace

AgentQSigningRetryResponseResult deliver_signing_retry_response(
    const char* request_id,
    const AgentQSigningRetryDeliveryResult& retry,
    const char* stored_result,
    AgentQSigningRetryResponseWriter write_response,
    void* context)
{
    if (retry.status == AgentQSigningRetryDeliveryStatus::not_found) {
        return AgentQSigningRetryResponseResult::not_found;
    }
    if (retry.status == AgentQSigningRetryDeliveryStatus::request_id_conflict ||
        retry.status == AgentQSigningRetryDeliveryStatus::lookup_error) {
        return write_error(
                   request_id,
                   retry.error_code,
                   retry.error_message,
                   write_response,
                   context)
                   ? AgentQSigningRetryResponseResult::error_response
                   : AgentQSigningRetryResponseResult::error_write_failed;
    }
    if (retry.status != AgentQSigningRetryDeliveryStatus::match) {
        return write_error(
                   request_id,
                   "protocol_error",
                   "Stored signing result lookup failed.",
                   write_response,
                   context)
                   ? AgentQSigningRetryResponseResult::error_response
                   : AgentQSigningRetryResponseResult::error_write_failed;
    }
    if (stored_result == nullptr || retry.stored_result_len == 0 || write_response == nullptr) {
        return AgentQSigningRetryResponseResult::invalid_stored_result;
    }
    JsonDocument response;
    if (deserializeJson(response, stored_result, retry.stored_result_len)) {
        return AgentQSigningRetryResponseResult::invalid_stored_result;
    }
    return write_response(response, context)
               ? AgentQSigningRetryResponseResult::replayed_result
               : AgentQSigningRetryResponseResult::replay_write_failed;
}

}  // namespace agent_q
