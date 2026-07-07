#include "signing/usb_signing_outcome_writer.h"

#include <stdlib.h>
#include <string.h>

#include "protocol/device_response.h"
#include "protocol/sign_request_identity.h"
#include "protocol/signing_mode.h"
#include "protocol/signing_response_store.h"
#include "sui/signature_scheme.h"
#include "sui/signing_limits.h"
#include "sui/zklogin_signature.h"

extern "C" {
#include "byte_conversions.h"
}

namespace signing {
namespace {

void clear_heap_buffer(char* buffer, size_t size)
{
    volatile char* cursor = buffer;
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

const char* user_terminal_device_error_code(UserSigningTerminalResult result)
{
    switch (result) {
        case UserSigningTerminalResult::rejected:
            return "user_rejected";
        case UserSigningTerminalResult::timed_out:
            return "timeout";
        case UserSigningTerminalResult::signing_failed:
            return "signing_failed";
        case UserSigningTerminalResult::signed_success:
        case UserSigningTerminalResult::canceled:
        case UserSigningTerminalResult::history_error:
        case UserSigningTerminalResult::none:
        default:
            return "";
    }
}

bool method_error_response_write(
    const char* id,
    const char* method,
    const char* code,
    const UsbSigningOutcomeWriterOps& ops)
{
    if (ops.write_method_error == nullptr) {
        return false;
    }
    const char* safe_code = code != nullptr && code[0] != '\0' ? code : "internal_output_error";
    return ops.write_method_error(
        id,
        method,
        safe_code,
        ops.write_method_error_context);
}

bool signing_response_buffer_store(
    const char* session_id,
    const char* request_id,
    const uint8_t* request_identity,
    const JsonDocument& response)
{
    if (session_id == nullptr || session_id[0] == '\0') {
        return false;
    }
    const size_t measured_len = measureJson(response);
    if (!usb_signing_outcome_response_fits(response)) {
        return false;
    }
    const size_t serialized_capacity = measured_len + 1;
    char* serialized_response = static_cast<char*>(malloc(serialized_capacity));
    if (serialized_response == nullptr) {
        return false;
    }
    memset(serialized_response, 0, serialized_capacity);
    const size_t serialized_len =
        serializeJson(response, serialized_response, serialized_capacity);
    bool stored = false;
    if (serialized_len == measured_len) {
        const ResponseStoreOutcome outcome = signing_response_store(
            session_id,
            request_id,
            request_identity,
            kSignRequestIdentitySize,
            serialized_response,
            serialized_len);
        stored = outcome == ResponseStoreOutcome::stored ||
                 outcome == ResponseStoreOutcome::duplicate;
    }
    clear_heap_buffer(serialized_response, serialized_capacity);
    free(serialized_response);
    return stored;
}

bool buffer_and_write_response(
    const char* session_id,
    const char* request_id,
    const uint8_t* request_identity,
    JsonDocument& response,
    const UsbSigningOutcomeWriterOps& ops)
{
    if (!signing_response_buffer_store(session_id, request_id, request_identity, response)) {
        return false;
    }
    return usb_json_response_write(response, ops.response_write_ops);
}

bool write_signed_signing_response(
    const char* id,
    const char* session_id,
    const uint8_t* request_identity,
    const char* authorization,
    Route signing_route,
    const uint8_t* signature,
    size_t signature_size,
    const uint8_t* message_bytes,
    size_t message_bytes_size,
    const UsbSigningOutcomeWriterOps& ops)
{
    JsonDocument response;
    if (!usb_signing_outcome_prepare_signed_response(
            response,
            id,
            authorization,
            signing_route,
            signature,
            signature_size,
            message_bytes,
            message_bytes_size)) {
        return false;
    }
    return buffer_and_write_response(session_id, id, request_identity, response, ops);
}

bool write_policy_rejected_signing_response(
    const char* id,
    const char* session_id,
    const uint8_t* request_identity,
    const char* policy_hash,
    const char* rule_ref,
    const UsbSigningOutcomeWriterOps& ops)
{
    if (policy_hash == nullptr || policy_hash[0] == '\0' ||
        rule_ref == nullptr || rule_ref[0] == '\0') {
        return false;
    }
    JsonDocument response;
    if (!device_response_prepare_method_error(response, id, "sign_transaction", "policy_rejected")) {
        return false;
    }
    return buffer_and_write_response(session_id, id, request_identity, response, ops);
}

bool write_failed_signing_response(
    const char* id,
    const char* session_id,
    const uint8_t* request_identity,
    const char* authorization,
    const char* code,
    const UsbSigningOutcomeWriterOps& ops)
{
    if (authorization == nullptr ||
        (strcmp(authorization, "user") != 0 && strcmp(authorization, "policy") != 0)) {
        return false;
    }
    const char* safe_code = code != nullptr && code[0] != '\0' ? code : "signing_failed";
    JsonDocument response;
    if (!device_response_prepare_method_error(response, id, "sign_transaction", safe_code)) {
        return false;
    }
    return buffer_and_write_response(session_id, id, request_identity, response, ops);
}

}  // namespace

bool usb_signing_outcome_response_fits(const JsonDocument& response)
{
    const size_t measured_len = measureJson(response);
    return measured_len != 0 && measured_len < kResponseMaxSize;
}

bool usb_signing_outcome_prepare_signed_response(
    JsonDocument& response,
    const char* id,
    const char* authorization,
    Route signing_route,
    const uint8_t* signature,
    size_t signature_size,
    const uint8_t* message_bytes,
    size_t message_bytes_size)
{
    if (authorization == nullptr ||
        (strcmp(authorization, "user") != 0 && strcmp(authorization, "policy") != 0) ||
        signature == nullptr ||
        signature_size == 0 ||
        signature_size > kSuiSignatureEnvelopeMaxBytes) {
        return false;
    }
    if (signing_route == Route::unsupported) {
        return false;
    }
    const bool ed25519_signature =
        signature[0] == kSuiSignatureSchemeFlagEd25519 &&
        signature_size == kSuiEd25519SignatureBytes;
    const bool zklogin_signature =
        signature[0] == kSuiSignatureSchemeFlagZkLogin &&
        signature_size > kSuiEd25519SignatureBytes;
    if (!ed25519_signature && !zklogin_signature) {
        return false;
    }
    const char* chain = sign_route_wire_chain(signing_route);
    const char* method = sign_route_wire_method(signing_route);
    if (chain == nullptr || chain[0] == '\0' ||
        method == nullptr || method[0] == '\0') {
        return false;
    }
    const AuthorizationMode authorization_mode =
        strcmp(authorization, "policy") == 0
            ? AuthorizationMode::policy
            : AuthorizationMode::user;
    if (!sign_route_allowed_for_authorization_mode(
            signing_route,
            authorization_mode)) {
        return false;
    }
    char signature_base64[kSuiSignatureEnvelopeBase64MaxChars + 1] = {};
    if (bytes_to_base64(
            signature,
            signature_size,
            signature_base64,
            sizeof(signature_base64)) != 0) {
        return false;
    }
    char message_base64[kSuiSignPersonalMessageMaxBase64Size + 1] = {};
    if (sign_route_requires_message_bytes(signing_route)) {
        if (message_bytes == nullptr ||
            message_bytes_size == 0 ||
            message_bytes_size > kSuiSignPersonalMessageMaxBytes ||
            bytes_to_base64(
                message_bytes,
                message_bytes_size,
                message_base64,
                sizeof(message_base64)) != 0) {
            return false;
        }
    } else if (message_bytes != nullptr || message_bytes_size != 0) {
        return false;
    }

    JsonDocument result_document;
    JsonObject result = result_document.to<JsonObject>();
    result["authorization"] = authorization;
    result["chain"] = chain;
    result["method"] = method;
    result["signature"] = signature_base64;
    if (sign_route_requires_message_bytes(signing_route)) {
        result["messageBytes"] = message_base64;
    }

    response.clear();
    if (!device_response_prepare_success_result(response, id, method, result)) {
        return false;
    }
    return true;
}

bool usb_signing_outcome_write_user_signed(
    const char* id,
    const char* session_id,
    const char* authorization,
    const UserSigningFlowCoreSnapshot& snapshot,
    const UserSigningOutput& signing_output,
    const UsbSigningOutcomeWriterOps& ops)
{
    if (snapshot.signing_route == Route::unsupported ||
        signing_output.signing_route != snapshot.signing_route) {
        return false;
    }
    return write_signed_signing_response(
        id,
        session_id,
        snapshot.request_identity,
        authorization,
        snapshot.signing_route,
        signing_output.signature,
        signing_output.signature_size,
        signing_output.message_bytes_size > 0 ? signing_output.message_bytes : nullptr,
        signing_output.message_bytes_size,
        ops);
}

bool usb_signing_outcome_user_signed_response_fits(
    const char* id,
    const char* authorization,
    const UserSigningFlowCoreSnapshot& snapshot,
    const UserSigningOutput& signing_output)
{
    if (snapshot.signing_route == Route::unsupported ||
        signing_output.signing_route != snapshot.signing_route) {
        return false;
    }
    JsonDocument response;
    if (!usb_signing_outcome_prepare_signed_response(
            response,
            id,
            authorization,
            snapshot.signing_route,
            signing_output.signature,
            signing_output.signature_size,
            signing_output.message_bytes_size > 0 ? signing_output.message_bytes : nullptr,
            signing_output.message_bytes_size)) {
        return false;
    }
    return usb_signing_outcome_response_fits(response);
}

bool usb_signing_outcome_write_user_terminal(
    const char* id,
    const char* session_id,
    const uint8_t* request_identity,
    const char* method,
    UserSigningTerminalResult result,
    const UsbSigningOutcomeWriterOps& ops)
{
    const char* error_code = user_terminal_device_error_code(result);
    if (method == nullptr || method[0] == '\0' ||
        error_code == nullptr || error_code[0] == '\0') {
        return false;
    }

    JsonDocument response;
    if (!device_response_prepare_method_error(response, id, method, error_code)) {
        return false;
    }
    return buffer_and_write_response(session_id, id, request_identity, response, ops);
}

bool usb_signing_outcome_write_policy_execution(
    const char* id,
    const char* session_id,
    const uint8_t* request_identity,
    const PolicySigningExecutionResult& result,
    const UsbSigningOutcomeWriterOps& ops)
{
    switch (result.status) {
        case PolicySigningExecutionStatus::request_error:
        case PolicySigningExecutionStatus::history_error:
        case PolicySigningExecutionStatus::account_error:
            return method_error_response_write(id, "sign_transaction", result.code, ops);
        case PolicySigningExecutionStatus::policy_rejected:
            return write_policy_rejected_signing_response(
                id,
                session_id,
                request_identity,
                result.policy_hash,
                result.rule_ref,
                ops);
        case PolicySigningExecutionStatus::signing_failed:
            return write_failed_signing_response(
                id,
                session_id,
                request_identity,
                "policy",
                result.code,
                ops);
        case PolicySigningExecutionStatus::signed_success:
            return write_signed_signing_response(
                id,
                session_id,
                request_identity,
                "policy",
                result.signing_route,
                result.signature,
                result.signature_size,
                nullptr,
                0,
                ops);
        default:
            return method_error_response_write(
                id,
                "sign_transaction",
                "internal_output_error",
                ops);
    }
}

}  // namespace signing
