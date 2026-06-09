#include "agent_q_sign_personal_message_user_ingress.h"

#include <string.h>

#include "agent_q_protocol_input_copy.h"

#include "agent_q_json_input.h"
#include "agent_q_request_id.h"

namespace agent_q {
namespace {

AgentQSignPersonalMessageUserIngressResult map_validation_result(
    AgentQSignPersonalMessageUserValidationResult result)
{
    switch (result) {
        case AgentQSignPersonalMessageUserValidationResult::ok:
            return AgentQSignPersonalMessageUserIngressResult::ok;
        case AgentQSignPersonalMessageUserValidationResult::invalid_request_shape:
            return AgentQSignPersonalMessageUserIngressResult::invalid_request_shape;
        case AgentQSignPersonalMessageUserValidationResult::unsupported_version:
            return AgentQSignPersonalMessageUserIngressResult::unsupported_version;
        case AgentQSignPersonalMessageUserValidationResult::unsupported_type:
            return AgentQSignPersonalMessageUserIngressResult::unsupported_type;
        case AgentQSignPersonalMessageUserValidationResult::invalid_session:
            return AgentQSignPersonalMessageUserIngressResult::invalid_session;
        case AgentQSignPersonalMessageUserValidationResult::invalid_params_shape:
            return AgentQSignPersonalMessageUserIngressResult::invalid_params_shape;
        case AgentQSignPersonalMessageUserValidationResult::unsupported_field:
            return AgentQSignPersonalMessageUserIngressResult::unsupported_field;
        case AgentQSignPersonalMessageUserValidationResult::unsupported_method:
            return AgentQSignPersonalMessageUserIngressResult::unsupported_method;
        case AgentQSignPersonalMessageUserValidationResult::invalid_network:
            return AgentQSignPersonalMessageUserIngressResult::invalid_network;
        case AgentQSignPersonalMessageUserValidationResult::invalid_message:
            return AgentQSignPersonalMessageUserIngressResult::invalid_message;
    }
    return AgentQSignPersonalMessageUserIngressResult::invalid_request_shape;
}

AgentQSignPersonalMessageUserValidationResult
validate_sign_personal_message_user_identity(
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

    const char* request_id = nullptr;
    if (!agent_q_json_value_c_string(request_object["id"], &request_id) ||
        !request_id_format_valid(request_id) ||
        !copy_nonempty_c_string(request_id, output->request_id, sizeof(output->request_id))) {
        memset(output, 0, sizeof(*output));
        return AgentQSignPersonalMessageUserValidationResult::invalid_request_shape;
    }

    JsonVariantConst version = request_object["version"];
    if (!version.is<uint32_t>() || version.as<uint32_t>() != 1) {
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

}  // namespace

AgentQSignPersonalMessageUserIngressResult
evaluate_sign_personal_message_user_ingress(
    JsonDocument& request,
    AgentQSupportedSignRoute route,
    const AgentQSignPersonalMessageUserIngressState& state,
    AgentQSignPersonalMessageUserIngressOutput* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return AgentQSignPersonalMessageUserIngressResult::invalid_request_shape;
    }

    AgentQSignPersonalMessageUserEnvelope envelope = {};
    AgentQSignPersonalMessageUserValidationResult validation =
        validate_sign_personal_message_user_identity(request, &envelope);
    if (validation != AgentQSignPersonalMessageUserValidationResult::ok) {
        return map_validation_result(validation);
    }

    if (!state.material_ready) {
        return AgentQSignPersonalMessageUserIngressResult::invalid_state;
    }
    if (state.busy) {
        return AgentQSignPersonalMessageUserIngressResult::busy;
    }

    AgentQSignPersonalMessageUserSessionRef session = {};
    validation = validate_sign_personal_message_user_session_format(request, &session);
    if (validation != AgentQSignPersonalMessageUserValidationResult::ok) {
        return map_validation_result(validation);
    }
    if (state.validate_session == nullptr ||
        state.validate_session(session.session_id, state.session_context) !=
            AgentQSessionValidationResult::ok) {
        return AgentQSignPersonalMessageUserIngressResult::invalid_session;
    }

    validation = validate_sign_personal_message_user_envelope(request, &envelope);
    if (validation != AgentQSignPersonalMessageUserValidationResult::ok) {
        return map_validation_result(validation);
    }

    AgentQSignPersonalMessageUserParams params = {};
    validation = validate_sign_personal_message_user_params(request, route, &params);
    if (validation != AgentQSignPersonalMessageUserValidationResult::ok) {
        return map_validation_result(validation);
    }

    output->envelope = envelope;
    output->session = session;
    output->params = params;
    return AgentQSignPersonalMessageUserIngressResult::ok;
}

const char* sign_personal_message_user_ingress_result_name(
    AgentQSignPersonalMessageUserIngressResult result)
{
    switch (result) {
        case AgentQSignPersonalMessageUserIngressResult::ok:
            return "ok";
        case AgentQSignPersonalMessageUserIngressResult::invalid_request_shape:
            return "invalid_request_shape";
        case AgentQSignPersonalMessageUserIngressResult::unsupported_version:
            return "unsupported_version";
        case AgentQSignPersonalMessageUserIngressResult::unsupported_type:
            return "unsupported_type";
        case AgentQSignPersonalMessageUserIngressResult::invalid_state:
            return "invalid_state";
        case AgentQSignPersonalMessageUserIngressResult::busy:
            return "busy";
        case AgentQSignPersonalMessageUserIngressResult::invalid_session:
            return "invalid_session";
        case AgentQSignPersonalMessageUserIngressResult::invalid_params_shape:
            return "invalid_params_shape";
        case AgentQSignPersonalMessageUserIngressResult::unsupported_field:
            return "unsupported_field";
        case AgentQSignPersonalMessageUserIngressResult::unsupported_method:
            return "unsupported_method";
        case AgentQSignPersonalMessageUserIngressResult::invalid_network:
            return "invalid_network";
        case AgentQSignPersonalMessageUserIngressResult::invalid_message:
            return "invalid_message";
    }
    return "invalid_request_shape";
}

}  // namespace agent_q
