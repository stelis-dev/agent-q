#include "agent_q_sign_by_user_ingress.h"

#include <string.h>

#include "agent_q_json_input.h"
#include "agent_q_request_id.h"

namespace agent_q {
namespace {

bool copy_nonempty_c_string(const char* input, char* output, size_t output_size)
{
    if (input == nullptr || input[0] == '\0' || output == nullptr || output_size == 0) {
        return false;
    }
    size_t index = 0;
    while (input[index] != '\0' && index + 1 < output_size) {
        output[index] = input[index];
        ++index;
    }
    if (input[index] != '\0') {
        output[0] = '\0';
        return false;
    }
    output[index] = '\0';
    return true;
}

AgentQSignByUserIngressResult map_validation_result(
    AgentQSignByUserValidationResult result)
{
    switch (result) {
        case AgentQSignByUserValidationResult::ok:
            return AgentQSignByUserIngressResult::ok;
        case AgentQSignByUserValidationResult::invalid_request_shape:
            return AgentQSignByUserIngressResult::invalid_request_shape;
        case AgentQSignByUserValidationResult::unsupported_version:
            return AgentQSignByUserIngressResult::unsupported_version;
        case AgentQSignByUserValidationResult::unsupported_type:
            return AgentQSignByUserIngressResult::unsupported_type;
        case AgentQSignByUserValidationResult::invalid_session:
            return AgentQSignByUserIngressResult::invalid_session;
        case AgentQSignByUserValidationResult::invalid_params_shape:
            return AgentQSignByUserIngressResult::invalid_params_shape;
        case AgentQSignByUserValidationResult::unsupported_field:
            return AgentQSignByUserIngressResult::unsupported_field;
        case AgentQSignByUserValidationResult::unsupported_method:
            return AgentQSignByUserIngressResult::unsupported_method;
        case AgentQSignByUserValidationResult::invalid_network:
            return AgentQSignByUserIngressResult::invalid_network;
        case AgentQSignByUserValidationResult::invalid_tx_bytes:
            return AgentQSignByUserIngressResult::invalid_tx_bytes;
    }
    return AgentQSignByUserIngressResult::invalid_request_shape;
}

AgentQSignByUserValidationResult validate_sign_by_user_identity(
    JsonDocument& request,
    AgentQSignByUserEnvelope* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return AgentQSignByUserValidationResult::invalid_request_shape;
    }

    JsonObjectConst request_object = request.as<JsonObjectConst>();
    if (request_object.isNull()) {
        return AgentQSignByUserValidationResult::invalid_request_shape;
    }

    const char* request_id = nullptr;
    if (!agent_q_json_value_c_string(request_object["id"], &request_id) ||
        !request_id_format_valid(request_id) ||
        !copy_nonempty_c_string(request_id, output->request_id, sizeof(output->request_id))) {
        memset(output, 0, sizeof(*output));
        return AgentQSignByUserValidationResult::invalid_request_shape;
    }

    JsonVariantConst version = request_object["version"];
    if (!version.is<uint32_t>() || version.as<uint32_t>() != 1) {
        memset(output, 0, sizeof(*output));
        return AgentQSignByUserValidationResult::unsupported_version;
    }

    const char* request_type = nullptr;
    if (!agent_q_json_value_c_string(request_object["type"], &request_type) ||
        strcmp(request_type, "sign_by_user") != 0) {
        memset(output, 0, sizeof(*output));
        return AgentQSignByUserValidationResult::unsupported_type;
    }

    return AgentQSignByUserValidationResult::ok;
}

}  // namespace

AgentQSignByUserIngressResult evaluate_sign_by_user_ingress(
    JsonDocument& request,
    const AgentQSignByUserIngressState& state,
    AgentQSignByUserIngressOutput* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return AgentQSignByUserIngressResult::invalid_request_shape;
    }

    AgentQSignByUserEnvelope envelope = {};
    AgentQSignByUserValidationResult validation =
        validate_sign_by_user_identity(request, &envelope);
    if (validation != AgentQSignByUserValidationResult::ok) {
        return map_validation_result(validation);
    }

    if (!state.material_ready) {
        return AgentQSignByUserIngressResult::invalid_state;
    }
    if (state.busy) {
        return AgentQSignByUserIngressResult::busy;
    }

    AgentQSignByUserSessionRef session = {};
    validation = validate_sign_by_user_session_format(request, &session);
    if (validation != AgentQSignByUserValidationResult::ok) {
        return map_validation_result(validation);
    }
    if (state.validate_session == nullptr ||
        state.validate_session(session.session_id, state.session_context) !=
            AgentQSessionValidationResult::ok) {
        return AgentQSignByUserIngressResult::invalid_session;
    }

    validation = validate_sign_by_user_envelope(request, &envelope);
    if (validation != AgentQSignByUserValidationResult::ok) {
        return map_validation_result(validation);
    }

    AgentQSignByUserParams params = {};
    validation = validate_sign_by_user_params(request, &params);
    if (validation != AgentQSignByUserValidationResult::ok) {
        return map_validation_result(validation);
    }

    output->envelope = envelope;
    output->session = session;
    output->params = params;
    return AgentQSignByUserIngressResult::ok;
}

const char* sign_by_user_ingress_result_name(
    AgentQSignByUserIngressResult result)
{
    switch (result) {
        case AgentQSignByUserIngressResult::ok:
            return "ok";
        case AgentQSignByUserIngressResult::invalid_request_shape:
            return "invalid_request_shape";
        case AgentQSignByUserIngressResult::unsupported_version:
            return "unsupported_version";
        case AgentQSignByUserIngressResult::unsupported_type:
            return "unsupported_type";
        case AgentQSignByUserIngressResult::invalid_state:
            return "invalid_state";
        case AgentQSignByUserIngressResult::busy:
            return "busy";
        case AgentQSignByUserIngressResult::invalid_session:
            return "invalid_session";
        case AgentQSignByUserIngressResult::invalid_params_shape:
            return "invalid_params_shape";
        case AgentQSignByUserIngressResult::unsupported_field:
            return "unsupported_field";
        case AgentQSignByUserIngressResult::unsupported_method:
            return "unsupported_method";
        case AgentQSignByUserIngressResult::invalid_network:
            return "invalid_network";
        case AgentQSignByUserIngressResult::invalid_tx_bytes:
            return "invalid_tx_bytes";
    }
    return "invalid_request_shape";
}

}  // namespace agent_q
