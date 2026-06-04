#include "agent_q_signature_request_ingress.h"

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

AgentQSignatureRequestIngressResult map_validation_result(
    AgentQSignatureRequestValidationResult result)
{
    switch (result) {
        case AgentQSignatureRequestValidationResult::ok:
            return AgentQSignatureRequestIngressResult::ok;
        case AgentQSignatureRequestValidationResult::invalid_request_shape:
            return AgentQSignatureRequestIngressResult::invalid_request_shape;
        case AgentQSignatureRequestValidationResult::unsupported_version:
            return AgentQSignatureRequestIngressResult::unsupported_version;
        case AgentQSignatureRequestValidationResult::unsupported_type:
            return AgentQSignatureRequestIngressResult::unsupported_type;
        case AgentQSignatureRequestValidationResult::invalid_session:
            return AgentQSignatureRequestIngressResult::invalid_session;
        case AgentQSignatureRequestValidationResult::invalid_params_shape:
            return AgentQSignatureRequestIngressResult::invalid_params_shape;
        case AgentQSignatureRequestValidationResult::unsupported_field:
            return AgentQSignatureRequestIngressResult::unsupported_field;
        case AgentQSignatureRequestValidationResult::unsupported_method:
            return AgentQSignatureRequestIngressResult::unsupported_method;
        case AgentQSignatureRequestValidationResult::invalid_network:
            return AgentQSignatureRequestIngressResult::invalid_network;
        case AgentQSignatureRequestValidationResult::invalid_tx_bytes:
            return AgentQSignatureRequestIngressResult::invalid_tx_bytes;
    }
    return AgentQSignatureRequestIngressResult::invalid_request_shape;
}

AgentQSignatureRequestValidationResult validate_signature_request_identity(
    JsonDocument& request,
    AgentQSignatureRequestEnvelope* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return AgentQSignatureRequestValidationResult::invalid_request_shape;
    }

    JsonObjectConst request_object = request.as<JsonObjectConst>();
    if (request_object.isNull()) {
        return AgentQSignatureRequestValidationResult::invalid_request_shape;
    }

    const char* request_id = nullptr;
    if (!agent_q_json_value_c_string(request_object["id"], &request_id) ||
        !request_id_format_valid(request_id) ||
        !copy_nonempty_c_string(request_id, output->request_id, sizeof(output->request_id))) {
        memset(output, 0, sizeof(*output));
        return AgentQSignatureRequestValidationResult::invalid_request_shape;
    }

    JsonVariantConst version = request_object["version"];
    if (!version.is<uint32_t>() || version.as<uint32_t>() != 1) {
        memset(output, 0, sizeof(*output));
        return AgentQSignatureRequestValidationResult::unsupported_version;
    }

    const char* request_type = nullptr;
    if (!agent_q_json_value_c_string(request_object["type"], &request_type) ||
        strcmp(request_type, "request_signature") != 0) {
        memset(output, 0, sizeof(*output));
        return AgentQSignatureRequestValidationResult::unsupported_type;
    }

    return AgentQSignatureRequestValidationResult::ok;
}

}  // namespace

AgentQSignatureRequestIngressResult evaluate_signature_request_ingress(
    JsonDocument& request,
    const AgentQSignatureRequestIngressState& state,
    AgentQSignatureRequestIngressOutput* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return AgentQSignatureRequestIngressResult::invalid_request_shape;
    }

    AgentQSignatureRequestEnvelope envelope = {};
    AgentQSignatureRequestValidationResult validation =
        validate_signature_request_identity(request, &envelope);
    if (validation != AgentQSignatureRequestValidationResult::ok) {
        return map_validation_result(validation);
    }

    if (!state.material_ready) {
        return AgentQSignatureRequestIngressResult::invalid_state;
    }
    if (state.busy) {
        return AgentQSignatureRequestIngressResult::busy;
    }

    AgentQSignatureRequestSessionRef session = {};
    validation = validate_signature_request_session_format(request, &session);
    if (validation != AgentQSignatureRequestValidationResult::ok) {
        return map_validation_result(validation);
    }
    if (state.validate_session == nullptr ||
        state.validate_session(session.session_id, state.session_context) !=
            AgentQSessionValidationResult::ok) {
        return AgentQSignatureRequestIngressResult::invalid_session;
    }

    validation = validate_signature_request_envelope(request, &envelope);
    if (validation != AgentQSignatureRequestValidationResult::ok) {
        return map_validation_result(validation);
    }

    AgentQSignatureRequestParams params = {};
    validation = validate_signature_request_params(request, &params);
    if (validation != AgentQSignatureRequestValidationResult::ok) {
        return map_validation_result(validation);
    }

    output->envelope = envelope;
    output->session = session;
    output->params = params;
    return AgentQSignatureRequestIngressResult::ok;
}

const char* signature_request_ingress_result_name(
    AgentQSignatureRequestIngressResult result)
{
    switch (result) {
        case AgentQSignatureRequestIngressResult::ok:
            return "ok";
        case AgentQSignatureRequestIngressResult::invalid_request_shape:
            return "invalid_request_shape";
        case AgentQSignatureRequestIngressResult::unsupported_version:
            return "unsupported_version";
        case AgentQSignatureRequestIngressResult::unsupported_type:
            return "unsupported_type";
        case AgentQSignatureRequestIngressResult::invalid_state:
            return "invalid_state";
        case AgentQSignatureRequestIngressResult::busy:
            return "busy";
        case AgentQSignatureRequestIngressResult::invalid_session:
            return "invalid_session";
        case AgentQSignatureRequestIngressResult::invalid_params_shape:
            return "invalid_params_shape";
        case AgentQSignatureRequestIngressResult::unsupported_field:
            return "unsupported_field";
        case AgentQSignatureRequestIngressResult::unsupported_method:
            return "unsupported_method";
        case AgentQSignatureRequestIngressResult::invalid_network:
            return "invalid_network";
        case AgentQSignatureRequestIngressResult::invalid_tx_bytes:
            return "invalid_tx_bytes";
    }
    return "invalid_request_shape";
}

}  // namespace agent_q
