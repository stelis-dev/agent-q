#include "agent_q_signing_retry_response.h"

#include "agent_q_device_contract.h"
#include "agent_q_protocol_constants.h"

namespace agent_q {
namespace {

bool write_error(
    const char* request_id,
    const char* method,
    const char* code,
    AgentQSigningRetryResponseWriter write_response,
    void* context)
{
    if (write_response == nullptr) {
        return false;
    }
    const AgentQDeviceErrorRow* error = device_error_row(code);
    if (error == nullptr) {
        error = device_error_row("unknown_error");
    }
    if (error == nullptr) {
        return false;
    }
    JsonDocument response;
    if (request_id != nullptr && request_id[0] != '\0') {
        response["id"] = request_id;
    }
    response["version"] = kAgentQProtocolVersion;
    response["success"] = false;
    if (method != nullptr && method[0] != '\0') {
        response["method"] = method;
    }
    response["error"]["code"] = error->code;
    response["error"]["message"] = error->message;
    response["error"]["retryable"] = error->retryable;
    return write_response(response, context);
}

bool stored_response_is_device_response(JsonDocument& response)
{
    if (response["version"] != kAgentQProtocolVersion ||
        !response["success"].is<bool>()) {
        return false;
    }
    if (response["success"] == true) {
        return response["method"].is<const char*>() &&
               response["result"].is<JsonObjectConst>();
    }
    return response["error"].is<JsonObjectConst>();
}

}  // namespace

AgentQSigningRetryResponseResult deliver_signing_retry_response(
    const char* request_id,
    const char* method,
    const AgentQSigningRetryDeliveryResult& retry,
    const char* stored_response,
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
                   method,
                   retry.error_code,
                   write_response,
                   context)
                   ? AgentQSigningRetryResponseResult::error_response
                   : AgentQSigningRetryResponseResult::error_write_failed;
    }
    if (retry.status != AgentQSigningRetryDeliveryStatus::match) {
        return write_error(
                   request_id,
                   method,
                   "internal_output_error",
                   write_response,
                   context)
                   ? AgentQSigningRetryResponseResult::error_response
                   : AgentQSigningRetryResponseResult::error_write_failed;
    }
    if (stored_response == nullptr || retry.stored_response_len == 0 || write_response == nullptr) {
        return AgentQSigningRetryResponseResult::invalid_stored_response;
    }
    JsonDocument response;
    if (deserializeJson(response, stored_response, retry.stored_response_len)) {
        return AgentQSigningRetryResponseResult::invalid_stored_response;
    }
    if (!stored_response_is_device_response(response)) {
        return AgentQSigningRetryResponseResult::invalid_stored_response;
    }
    return write_response(response, context)
               ? AgentQSigningRetryResponseResult::replayed_result
               : AgentQSigningRetryResponseResult::replay_write_failed;
}

}  // namespace agent_q
