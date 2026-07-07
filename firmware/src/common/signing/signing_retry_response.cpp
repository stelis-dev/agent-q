#include "signing/signing_retry_response.h"

#include "protocol/device_response.h"
#include "protocol/protocol_constants.h"

namespace signing {
namespace {

bool write_error(
    const char* request_id,
    const char* method,
    const char* code,
    RetryResponseWriter write_response,
    void* context)
{
    if (write_response == nullptr) {
        return false;
    }
    JsonDocument response;
    if (!device_response_prepare_method_error(response, request_id, method, code)) {
        return false;
    }
    return write_response(response, context);
}

bool stored_response_is_device_response(JsonDocument& response)
{
    if (response["version"] != kProtocolVersion ||
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

RetryResponseResult deliver_signing_retry_response(
    const char* request_id,
    const char* method,
    const RetryDeliveryResult& retry,
    const char* stored_response,
    RetryResponseWriter write_response,
    void* context)
{
    if (retry.status == RetryDeliveryStatus::not_found) {
        return RetryResponseResult::not_found;
    }
    if (retry.status == RetryDeliveryStatus::request_id_conflict ||
        retry.status == RetryDeliveryStatus::lookup_error) {
        return write_error(
                   request_id,
                   method,
                   retry.error_code,
                   write_response,
                   context)
                   ? RetryResponseResult::error_response
                   : RetryResponseResult::error_write_failed;
    }
    if (retry.status != RetryDeliveryStatus::match) {
        return write_error(
                   request_id,
                   method,
                   "internal_output_error",
                   write_response,
                   context)
                   ? RetryResponseResult::error_response
                   : RetryResponseResult::error_write_failed;
    }
    if (stored_response == nullptr || retry.stored_response_len == 0 || write_response == nullptr) {
        return RetryResponseResult::invalid_stored_response;
    }
    JsonDocument response;
    if (deserializeJson(response, stored_response, retry.stored_response_len)) {
        return RetryResponseResult::invalid_stored_response;
    }
    if (!stored_response_is_device_response(response)) {
        return RetryResponseResult::invalid_stored_response;
    }
    return write_response(response, context)
               ? RetryResponseResult::replayed_result
               : RetryResponseResult::replay_write_failed;
}

}  // namespace signing
