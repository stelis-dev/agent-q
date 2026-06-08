#include "agent_q_sign_transaction_user_ingress.h"

#include <string.h>

#include "agent_q_protocol_input_copy.h"

#include "agent_q_json_input.h"
#include "agent_q_request_id.h"

namespace agent_q {
namespace {

AgentQSignTransactionUserIngressResult map_validation_result(
    AgentQSignTransactionUserValidationResult result)
{
    switch (result) {
        case AgentQSignTransactionUserValidationResult::ok:
            return AgentQSignTransactionUserIngressResult::ok;
        case AgentQSignTransactionUserValidationResult::invalid_request_shape:
            return AgentQSignTransactionUserIngressResult::invalid_request_shape;
        case AgentQSignTransactionUserValidationResult::unsupported_version:
            return AgentQSignTransactionUserIngressResult::unsupported_version;
        case AgentQSignTransactionUserValidationResult::unsupported_type:
            return AgentQSignTransactionUserIngressResult::unsupported_type;
        case AgentQSignTransactionUserValidationResult::invalid_session:
            return AgentQSignTransactionUserIngressResult::invalid_session;
        case AgentQSignTransactionUserValidationResult::invalid_params_shape:
            return AgentQSignTransactionUserIngressResult::invalid_params_shape;
        case AgentQSignTransactionUserValidationResult::unsupported_field:
            return AgentQSignTransactionUserIngressResult::unsupported_field;
        case AgentQSignTransactionUserValidationResult::unsupported_method:
            return AgentQSignTransactionUserIngressResult::unsupported_method;
        case AgentQSignTransactionUserValidationResult::invalid_network:
            return AgentQSignTransactionUserIngressResult::invalid_network;
        case AgentQSignTransactionUserValidationResult::invalid_tx_bytes:
            return AgentQSignTransactionUserIngressResult::invalid_tx_bytes;
    }
    return AgentQSignTransactionUserIngressResult::invalid_request_shape;
}

AgentQSignTransactionUserValidationResult validate_sign_transaction_user_identity(
    JsonDocument& request,
    AgentQSignTransactionUserEnvelope* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return AgentQSignTransactionUserValidationResult::invalid_request_shape;
    }

    JsonObjectConst request_object = request.as<JsonObjectConst>();
    if (request_object.isNull()) {
        return AgentQSignTransactionUserValidationResult::invalid_request_shape;
    }

    const char* request_id = nullptr;
    if (!agent_q_json_value_c_string(request_object["id"], &request_id) ||
        !request_id_format_valid(request_id) ||
        !copy_nonempty_c_string(request_id, output->request_id, sizeof(output->request_id))) {
        memset(output, 0, sizeof(*output));
        return AgentQSignTransactionUserValidationResult::invalid_request_shape;
    }

    JsonVariantConst version = request_object["version"];
    if (!version.is<uint32_t>() || version.as<uint32_t>() != 1) {
        memset(output, 0, sizeof(*output));
        return AgentQSignTransactionUserValidationResult::unsupported_version;
    }

    const char* request_type = nullptr;
    if (!agent_q_json_value_c_string(request_object["type"], &request_type) ||
        strcmp(request_type, "sign_transaction") != 0) {
        memset(output, 0, sizeof(*output));
        return AgentQSignTransactionUserValidationResult::unsupported_type;
    }

    return AgentQSignTransactionUserValidationResult::ok;
}

}  // namespace

AgentQSignTransactionUserIngressResult evaluate_sign_transaction_user_ingress(
    JsonDocument& request,
    const AgentQSignTransactionUserIngressState& state,
    AgentQSignTransactionUserIngressOutput* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return AgentQSignTransactionUserIngressResult::invalid_request_shape;
    }

    AgentQSignTransactionUserEnvelope envelope = {};
    AgentQSignTransactionUserValidationResult validation =
        validate_sign_transaction_user_identity(request, &envelope);
    if (validation != AgentQSignTransactionUserValidationResult::ok) {
        return map_validation_result(validation);
    }

    if (!state.material_ready) {
        return AgentQSignTransactionUserIngressResult::invalid_state;
    }
    if (state.busy) {
        return AgentQSignTransactionUserIngressResult::busy;
    }

    AgentQSignTransactionUserSessionRef session = {};
    validation = validate_sign_transaction_user_session_format(request, &session);
    if (validation != AgentQSignTransactionUserValidationResult::ok) {
        return map_validation_result(validation);
    }
    if (state.validate_session == nullptr ||
        state.validate_session(session.session_id, state.session_context) !=
            AgentQSessionValidationResult::ok) {
        return AgentQSignTransactionUserIngressResult::invalid_session;
    }

    validation = validate_sign_transaction_user_envelope(request, &envelope);
    if (validation != AgentQSignTransactionUserValidationResult::ok) {
        return map_validation_result(validation);
    }

    AgentQSignTransactionUserParams params = {};
    validation = validate_sign_transaction_user_params(request, &params);
    if (validation != AgentQSignTransactionUserValidationResult::ok) {
        return map_validation_result(validation);
    }

    output->envelope = envelope;
    output->session = session;
    output->params = params;
    return AgentQSignTransactionUserIngressResult::ok;
}

const char* sign_transaction_user_ingress_result_name(
    AgentQSignTransactionUserIngressResult result)
{
    switch (result) {
        case AgentQSignTransactionUserIngressResult::ok:
            return "ok";
        case AgentQSignTransactionUserIngressResult::invalid_request_shape:
            return "invalid_request_shape";
        case AgentQSignTransactionUserIngressResult::unsupported_version:
            return "unsupported_version";
        case AgentQSignTransactionUserIngressResult::unsupported_type:
            return "unsupported_type";
        case AgentQSignTransactionUserIngressResult::invalid_state:
            return "invalid_state";
        case AgentQSignTransactionUserIngressResult::busy:
            return "busy";
        case AgentQSignTransactionUserIngressResult::invalid_session:
            return "invalid_session";
        case AgentQSignTransactionUserIngressResult::invalid_params_shape:
            return "invalid_params_shape";
        case AgentQSignTransactionUserIngressResult::unsupported_field:
            return "unsupported_field";
        case AgentQSignTransactionUserIngressResult::unsupported_method:
            return "unsupported_method";
        case AgentQSignTransactionUserIngressResult::invalid_network:
            return "invalid_network";
        case AgentQSignTransactionUserIngressResult::invalid_tx_bytes:
            return "invalid_tx_bytes";
    }
    return "invalid_request_shape";
}

}  // namespace agent_q
