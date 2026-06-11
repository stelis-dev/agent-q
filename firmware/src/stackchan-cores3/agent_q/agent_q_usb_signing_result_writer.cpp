#include "agent_q_usb_signing_result_writer.h"

#include <string.h>

#include <ArduinoJson.h>

#include "agent_q_protocol_constants.h"
#include "agent_q_sign_personal_message_limits.h"
#include "agent_q_signing_mode.h"
#include "agent_q_signing_result_store.h"
#include "agent_q_sui_signing_service.h"
#include "agent_q_usb_response_writer.h"

extern "C" {
#include "byte_conversions.h"
}

namespace agent_q {
namespace {

const char* sign_result_user_error_message(
    AgentQUserSigningTerminalResult result)
{
    switch (result) {
        case AgentQUserSigningTerminalResult::rejected:
            return "The signing request was rejected on the device.";
        case AgentQUserSigningTerminalResult::timed_out:
            return "The signing request timed out on the device.";
        case AgentQUserSigningTerminalResult::signing_failed:
            return "The device could not produce a signature.";
        case AgentQUserSigningTerminalResult::signed_success:
        case AgentQUserSigningTerminalResult::canceled:
        case AgentQUserSigningTerminalResult::history_error:
        case AgentQUserSigningTerminalResult::none:
        default:
            return "";
    }
}

bool buffer_sign_result_for_retry(
    const char* session_id,
    const char* request_id,
    const uint8_t* request_identity,
    const JsonDocument& response)
{
    if (session_id == nullptr || session_id[0] == '\0') {
        return false;
    }
    static char serialized_result[kSigningResultMaxSize];
    const size_t serialized_len = serializeJson(response, serialized_result, sizeof(serialized_result));
    if (serialized_len == 0 || serialized_len >= sizeof(serialized_result)) {
        return false;
    }
    return signing_result_store(
               session_id,
               request_id,
               request_identity,
               kAgentQSignRequestIdentitySize,
               serialized_result,
               serialized_len) !=
           SigningResultStoreOutcome::invalid;
}

bool write_sign_result_signed_fields(
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
        signature_size != kSuiEd25519SignatureBytes) {
        return false;
    }
    if (signing_route == AgentQSigningRoute::unsupported) {
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
    char signature_base64[kSuiEd25519SignatureBase64Chars + 1] = {};
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

    JsonDocument response;
    response["id"] = id;
    response["version"] = kAgentQProtocolVersion;
    response["type"] = "sign_result";
    response["authorization"] = authorization;
    response["status"] = "signed";
    response["chain"] = chain;
    response["method"] = method;
    response["signature"] = signature_base64;
    if (signing_route_requires_message_bytes(signing_route)) {
        response["messageBytes"] = message_base64;
    }
    buffer_sign_result_for_retry(session_id, id, request_identity, response);
    return usb_response_write_json(response);
}

bool write_sign_result_policy_rejected(
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
    response["id"] = id;
    response["version"] = kAgentQProtocolVersion;
    response["type"] = "sign_result";
    response["authorization"] = "policy";
    response["status"] = "policy_rejected";
    response["policyHash"] = policy_hash;
    response["ruleRef"] = rule_ref;
    response["error"]["code"] = "policy_rejected";
    response["error"]["message"] = "The signing request was rejected by device policy.";
    buffer_sign_result_for_retry(session_id, id, request_identity, response);
    return usb_response_write_json(response);
}

bool write_sign_result_signing_failed(
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
    response["id"] = id;
    response["version"] = kAgentQProtocolVersion;
    response["type"] = "sign_result";
    response["authorization"] = authorization;
    response["status"] = "signing_failed";
    response["error"]["code"] = "signing_failed";
    response["error"]["message"] = "The device could not produce a signature.";
    buffer_sign_result_for_retry(session_id, id, request_identity, response);
    return usb_response_write_json(response);
}

}  // namespace

bool usb_signing_result_write_user_signed(
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
    return write_sign_result_signed_fields(
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

bool usb_signing_result_write_user_terminal(
    const char* id,
    const char* session_id,
    const uint8_t* request_identity,
    AgentQUserSigningTerminalResult result)
{
    const char* status = user_signing_flow_terminal_status(result);
    const char* reason = user_signing_flow_terminal_reason(result);
    const char* message = sign_result_user_error_message(result);
    if (status == nullptr || status[0] == '\0' ||
        reason == nullptr || reason[0] == '\0' ||
        message == nullptr || message[0] == '\0') {
        return false;
    }

    JsonDocument response;
    response["id"] = id;
    response["version"] = kAgentQProtocolVersion;
    response["type"] = "sign_result";
    response["authorization"] = "user";
    response["status"] = status;
    response["error"]["code"] = reason;
    response["error"]["message"] = message;
    buffer_sign_result_for_retry(session_id, id, request_identity, response);
    return usb_response_write_json(response);
}

bool usb_signing_result_write_policy_execution(
    const char* id,
    const char* session_id,
    const uint8_t* request_identity,
    const AgentQPolicySigningExecutionResult& result)
{
    switch (result.status) {
        case AgentQPolicySigningExecutionStatus::request_error:
        case AgentQPolicySigningExecutionStatus::history_error:
        case AgentQPolicySigningExecutionStatus::account_error:
            return usb_response_write_error(id, result.code, result.message);
        case AgentQPolicySigningExecutionStatus::policy_rejected:
            return write_sign_result_policy_rejected(
                id,
                session_id,
                request_identity,
                result.policy_hash,
                result.rule_ref);
        case AgentQPolicySigningExecutionStatus::signing_failed:
            return write_sign_result_signing_failed(id, session_id, request_identity, "policy");
        case AgentQPolicySigningExecutionStatus::signed_success:
            return write_sign_result_signed_fields(
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
            return usb_response_write_error(id, "protocol_error", "Policy signing request is invalid.");
    }
}

}  // namespace agent_q
