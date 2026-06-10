#include "agent_q_sign_personal_message_user_validation.h"

#include <string.h>

#include "agent_q_protocol_input_copy.h"

#include "agent_q_base64.h"
#include "agent_q_json_input.h"
#include "agent_q_protocol_constants.h"
#include "agent_q_request_id.h"
#include "agent_q_sui_network.h"

namespace agent_q {
namespace {

bool request_top_level_fields_supported(JsonObjectConst request)
{
    for (JsonPairConst pair : request) {
        if (!agent_q_json_string_equals(pair.key(), "id") &&
            !agent_q_json_string_equals(pair.key(), "version") &&
            !agent_q_json_string_equals(pair.key(), "type") &&
            !agent_q_json_string_equals(pair.key(), "sessionId") &&
            !agent_q_json_string_equals(pair.key(), "chain") &&
            !agent_q_json_string_equals(pair.key(), "method") &&
            !agent_q_json_string_equals(pair.key(), "params")) {
            return false;
        }
    }
    return true;
}

bool request_params_fields_supported(JsonObjectConst params)
{
    for (JsonPairConst pair : params) {
        if (!agent_q_json_string_equals(pair.key(), "network") &&
            !agent_q_json_string_equals(pair.key(), "message")) {
            return false;
        }
    }
    return true;
}

}  // namespace

AgentQSignPersonalMessageUserValidationResult
validate_sign_personal_message_user_envelope(
    JsonDocument& request,
    AgentQSignPersonalMessageUserEnvelope* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return AgentQSignPersonalMessageUserValidationResult::invalid_request_shape;
    }

    JsonObjectConst request_object = request.as<JsonObjectConst>();
    if (request_object.isNull()) {
        return AgentQSignPersonalMessageUserValidationResult::invalid_request_shape;
    }
    if (!request_top_level_fields_supported(request_object)) {
        return AgentQSignPersonalMessageUserValidationResult::unsupported_field;
    }

    const char* request_id = nullptr;
    if (!agent_q_json_value_c_string(request_object["id"], &request_id) ||
        !request_id_format_valid(request_id) ||
        !copy_nonempty_c_string(request_id, output->request_id, sizeof(output->request_id))) {
        memset(output, 0, sizeof(*output));
        return AgentQSignPersonalMessageUserValidationResult::invalid_request_shape;
    }

    JsonVariantConst version = request_object["version"];
    if (!version.is<uint32_t>() ||
        version.as<uint32_t>() != kAgentQProtocolVersion) {
        memset(output, 0, sizeof(*output));
        return AgentQSignPersonalMessageUserValidationResult::unsupported_version;
    }

    const char* request_type = nullptr;
    if (!agent_q_json_value_c_string(request_object["type"], &request_type) ||
        strcmp(request_type, "sign_personal_message") != 0) {
        memset(output, 0, sizeof(*output));
        return AgentQSignPersonalMessageUserValidationResult::unsupported_type;
    }

    return AgentQSignPersonalMessageUserValidationResult::ok;
}

AgentQSignPersonalMessageUserValidationResult
validate_sign_personal_message_user_session_format(
    JsonDocument& request,
    AgentQSignPersonalMessageUserSessionRef* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return AgentQSignPersonalMessageUserValidationResult::invalid_session;
    }

    JsonObjectConst request_object = request.as<JsonObjectConst>();
    if (request_object.isNull()) {
        return AgentQSignPersonalMessageUserValidationResult::invalid_session;
    }

    const char* session_id = nullptr;
    if (!agent_q_json_value_c_string(request_object["sessionId"], &session_id) ||
        !session_id_format_valid(session_id) ||
        !copy_nonempty_c_string(session_id, output->session_id, sizeof(output->session_id))) {
        memset(output, 0, sizeof(*output));
        return AgentQSignPersonalMessageUserValidationResult::invalid_session;
    }

    return AgentQSignPersonalMessageUserValidationResult::ok;
}

AgentQSignPersonalMessageUserValidationResult
validate_sign_personal_message_user_params(
    JsonDocument& request,
    AgentQSupportedSignRoute route,
    AgentQSignPersonalMessageUserParams* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return AgentQSignPersonalMessageUserValidationResult::invalid_params_shape;
    }

    JsonObjectConst request_object = request.as<JsonObjectConst>();
    if (request_object.isNull()) {
        return AgentQSignPersonalMessageUserValidationResult::invalid_params_shape;
    }

    JsonVariantConst params_value = request_object["params"];
    JsonObjectConst params = params_value.as<JsonObjectConst>();
    if (params.isNull()) {
        memset(output, 0, sizeof(*output));
        return AgentQSignPersonalMessageUserValidationResult::invalid_params_shape;
    }
    if (!request_params_fields_supported(params)) {
        memset(output, 0, sizeof(*output));
        return AgentQSignPersonalMessageUserValidationResult::unsupported_field;
    }

    // Helper boundary assertion: USB preflight classifies the route first, but
    // direct callers must still fail closed before method-parameter decoding.
    if (route != AgentQSupportedSignRoute::sui_sign_personal_message) {
        memset(output, 0, sizeof(*output));
        return AgentQSignPersonalMessageUserValidationResult::unsupported_method;
    }

    const char* network = nullptr;
    if (!agent_q_json_value_c_string(params["network"], &network) ||
        !copy_nonempty_c_string(network, output->network, sizeof(output->network)) ||
        !sui_network_supported(output->network)) {
        memset(output, 0, sizeof(*output));
        return AgentQSignPersonalMessageUserValidationResult::invalid_network;
    }

    const char* message_base64 = nullptr;
    if (!agent_q_json_value_c_string(params["message"], &message_base64) ||
        !validate_canonical_base64_syntax(
            message_base64,
            kAgentQSignRequestBase64MaxSize,
            &output->message_decoded_size)) {
        memset(output, 0, sizeof(*output));
        return AgentQSignPersonalMessageUserValidationResult::invalid_message;
    }
    output->message_base64 = message_base64;

    return AgentQSignPersonalMessageUserValidationResult::ok;
}

const char* sign_personal_message_user_validation_result_name(
    AgentQSignPersonalMessageUserValidationResult result)
{
    switch (result) {
        case AgentQSignPersonalMessageUserValidationResult::ok:
            return "ok";
        case AgentQSignPersonalMessageUserValidationResult::invalid_request_shape:
            return "invalid_request_shape";
        case AgentQSignPersonalMessageUserValidationResult::unsupported_version:
            return "unsupported_version";
        case AgentQSignPersonalMessageUserValidationResult::unsupported_type:
            return "unsupported_type";
        case AgentQSignPersonalMessageUserValidationResult::invalid_session:
            return "invalid_session";
        case AgentQSignPersonalMessageUserValidationResult::invalid_params_shape:
            return "invalid_params_shape";
        case AgentQSignPersonalMessageUserValidationResult::unsupported_field:
            return "unsupported_field";
        case AgentQSignPersonalMessageUserValidationResult::unsupported_method:
            return "unsupported_method";
        case AgentQSignPersonalMessageUserValidationResult::invalid_network:
            return "invalid_network";
        case AgentQSignPersonalMessageUserValidationResult::invalid_message:
            return "invalid_message";
    }
    return "unknown";
}

}  // namespace agent_q
