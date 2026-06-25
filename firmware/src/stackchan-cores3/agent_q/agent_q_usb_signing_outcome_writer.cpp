#include "agent_q_usb_signing_outcome_writer.h"

#include <stdlib.h>
#include <string.h>

#include <ArduinoJson.h>

#include "agent_q_protocol_constants.h"
#include "agent_q_sign_personal_message_limits.h"
#include "agent_q_signing_mode.h"
#include "agent_q_signing_response_store.h"
#include "agent_q_sui_signing_service.h"
#include "agent_q_sui_zklogin_proof_store.h"
#include "agent_q_usb_response_writer.h"

extern "C" {
#include "byte_conversions.h"
}

namespace agent_q {
namespace {

void clear_heap_buffer(char* buffer, size_t size)
{
    volatile char* cursor = buffer;
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

const char* user_terminal_device_error_code(AgentQUserSigningTerminalResult result)
{
    switch (result) {
        case AgentQUserSigningTerminalResult::rejected:
            return "user_rejected";
        case AgentQUserSigningTerminalResult::timed_out:
            return "timeout";
        case AgentQUserSigningTerminalResult::signing_failed:
            return "signing_failed";
        case AgentQUserSigningTerminalResult::signed_success:
        case AgentQUserSigningTerminalResult::canceled:
        case AgentQUserSigningTerminalResult::history_error:
        case AgentQUserSigningTerminalResult::none:
        default:
            return "";
    }
}

bool buffer_signing_response_for_retry(
    const char* session_id,
    const char* request_id,
    const uint8_t* request_identity,
    const JsonDocument& response)
{
    if (session_id == nullptr || session_id[0] == '\0') {
        return false;
    }
    char* serialized_response = static_cast<char*>(malloc(kSigningResponseMaxSize));
    if (serialized_response == nullptr) {
        return false;
    }
    const size_t serialized_len =
        serializeJson(response, serialized_response, kSigningResponseMaxSize);
    bool stored = false;
    if (serialized_len != 0 && serialized_len < kSigningResponseMaxSize) {
        const SigningResponseStoreOutcome outcome = signing_response_store(
            session_id,
            request_id,
            request_identity,
            kAgentQSignRequestIdentitySize,
            serialized_response,
            serialized_len);
        stored = outcome == SigningResponseStoreOutcome::stored ||
                 outcome == SigningResponseStoreOutcome::duplicate ||
                 outcome == SigningResponseStoreOutcome::conflict;
    }
    clear_heap_buffer(serialized_response, kSigningResponseMaxSize);
    free(serialized_response);
    return stored;
}

bool buffer_and_write_response(
    const char* session_id,
    const char* request_id,
    const uint8_t* request_identity,
    JsonDocument& response)
{
    buffer_signing_response_for_retry(session_id, request_id, request_identity, response);
    return usb_response_write_json(response);
}

bool write_signed_signing_response(
    const char* id,
    const char* session_id,
    const uint8_t* request_identity,
    const char* authorization,
    AgentQSigningRoute signing_route,
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
    if (signing_route == AgentQSigningRoute::unsupported) {
        return false;
    }
    const bool ed25519_signature =
        signature[0] == kAgentQSuiSignatureSchemeFlagEd25519 &&
        signature_size == kSuiEd25519SignatureBytes;
    const bool zklogin_signature =
        signature[0] == kAgentQSuiSignatureSchemeFlagZkLogin &&
        signature_size > kSuiEd25519SignatureBytes;
    if (!ed25519_signature && !zklogin_signature) {
        return false;
    }
    const char* chain = signing_route_wire_chain(signing_route);
    const char* method = signing_route_wire_method(signing_route);
    if (chain == nullptr || chain[0] == '\0' ||
        method == nullptr || method[0] == '\0') {
        return false;
    }
    const AgentQSigningAuthorizationMode authorization_mode =
        strcmp(authorization, "policy") == 0
            ? AgentQSigningAuthorizationMode::policy
            : AgentQSigningAuthorizationMode::user;
    if (!signing_route_allowed_for_authorization_mode(
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
    char message_base64[kAgentQSuiSignPersonalMessageMaxBase64Size + 1] = {};
    if (signing_route_requires_message_bytes(signing_route)) {
        if (message_bytes == nullptr ||
            message_bytes_size == 0 ||
            message_bytes_size > kAgentQSuiSignPersonalMessageMaxBytes ||
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
    if (signing_route_requires_message_bytes(signing_route)) {
        result["messageBytes"] = message_base64;
    }

    JsonDocument response;
    if (!usb_response_prepare_success_result(response, id, method, result)) {
        return false;
    }
    return buffer_and_write_response(session_id, id, request_identity, response);
}

bool write_policy_rejected_signing_response(
    const char* id,
    const char* session_id,
    const uint8_t* request_identity,
    const char* policy_hash,
    const char* rule_ref)
{
    if (policy_hash == nullptr || policy_hash[0] == '\0' ||
        rule_ref == nullptr || rule_ref[0] == '\0') {
        return false;
    }
    JsonDocument response;
    if (!usb_response_prepare_method_error(response, id, "sign_transaction", "policy_rejected")) {
        return false;
    }
    return buffer_and_write_response(session_id, id, request_identity, response);
}

bool write_failed_signing_response(
    const char* id,
    const char* session_id,
    const uint8_t* request_identity,
    const char* authorization)
{
    if (authorization == nullptr ||
        (strcmp(authorization, "user") != 0 && strcmp(authorization, "policy") != 0)) {
        return false;
    }
    JsonDocument response;
    if (!usb_response_prepare_method_error(response, id, "sign_transaction", "signing_failed")) {
        return false;
    }
    return buffer_and_write_response(session_id, id, request_identity, response);
}

}  // namespace

bool usb_signing_outcome_write_user_signed(
    const char* id,
    const char* session_id,
    const char* authorization,
    const AgentQUserSigningFlowCoreSnapshot& snapshot,
    const AgentQUserSigningOutput& signing_output)
{
    if (snapshot.signing_route == AgentQSigningRoute::unsupported ||
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
        signing_output.message_bytes_size);
}

bool usb_signing_outcome_write_user_terminal(
    const char* id,
    const char* session_id,
    const uint8_t* request_identity,
    const char* method,
    AgentQUserSigningTerminalResult result)
{
    const char* error_code = user_terminal_device_error_code(result);
    if (method == nullptr || method[0] == '\0' ||
        error_code == nullptr || error_code[0] == '\0') {
        return false;
    }

    JsonDocument response;
    if (!usb_response_prepare_method_error(response, id, method, error_code)) {
        return false;
    }
    return buffer_and_write_response(session_id, id, request_identity, response);
}

bool usb_signing_outcome_write_policy_execution(
    const char* id,
    const char* session_id,
    const uint8_t* request_identity,
    const AgentQPolicySigningExecutionResult& result)
{
    switch (result.status) {
        case AgentQPolicySigningExecutionStatus::request_error:
        case AgentQPolicySigningExecutionStatus::history_error:
        case AgentQPolicySigningExecutionStatus::account_error:
            return usb_response_write_method_error(id, "sign_transaction", result.code);
        case AgentQPolicySigningExecutionStatus::policy_rejected:
            return write_policy_rejected_signing_response(
                id,
                session_id,
                request_identity,
                result.policy_hash,
                result.rule_ref);
        case AgentQPolicySigningExecutionStatus::signing_failed:
            return write_failed_signing_response(id, session_id, request_identity, "policy");
        case AgentQPolicySigningExecutionStatus::signed_success:
            return write_signed_signing_response(
                id,
                session_id,
                request_identity,
                "policy",
                result.signing_route,
                result.signature,
                result.signature_size,
                nullptr,
                0);
        default:
            return usb_response_write_method_error(
                id,
                "sign_transaction",
                "internal_output_error");
    }
}

}  // namespace agent_q
