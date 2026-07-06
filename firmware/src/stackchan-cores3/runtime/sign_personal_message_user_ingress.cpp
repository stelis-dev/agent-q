#include "sign_personal_message_user_ingress.h"

#include <string.h>

#include "protocol/protocol_input_copy.h"

#include "protocol/json_input.h"
#include "protocol/protocol_constants.h"
#include "protocol/request_id.h"

namespace signing {
namespace {

SignPersonalMessageUserIngressResult map_validation_result(
    SignPersonalMessageUserValidationResult result)
{
    switch (result) {
        case SignPersonalMessageUserValidationResult::ok:
            return SignPersonalMessageUserIngressResult::ok;
        case SignPersonalMessageUserValidationResult::invalid_request_shape:
            return SignPersonalMessageUserIngressResult::invalid_request_shape;
        case SignPersonalMessageUserValidationResult::unsupported_version:
            return SignPersonalMessageUserIngressResult::unsupported_version;
        case SignPersonalMessageUserValidationResult::invalid_session:
            return SignPersonalMessageUserIngressResult::invalid_session;
        case SignPersonalMessageUserValidationResult::invalid_params_shape:
            return SignPersonalMessageUserIngressResult::invalid_params_shape;
        case SignPersonalMessageUserValidationResult::unsupported_field:
            return SignPersonalMessageUserIngressResult::unsupported_field;
        case SignPersonalMessageUserValidationResult::unsupported_method:
            return SignPersonalMessageUserIngressResult::unsupported_method;
        case SignPersonalMessageUserValidationResult::invalid_network:
            return SignPersonalMessageUserIngressResult::invalid_network;
        case SignPersonalMessageUserValidationResult::invalid_message:
            return SignPersonalMessageUserIngressResult::invalid_message;
        case SignPersonalMessageUserValidationResult::message_too_large:
            return SignPersonalMessageUserIngressResult::message_too_large;
    }
    return SignPersonalMessageUserIngressResult::invalid_request_shape;
}

SignPersonalMessageUserValidationResult
validate_sign_personal_message_user_identity(
    JsonDocument& request,
    SignPersonalMessageUserEnvelope* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return SignPersonalMessageUserValidationResult::invalid_request_shape;
    }

    JsonObjectConst request_object = request.as<JsonObjectConst>();
    if (request_object.isNull()) {
        return SignPersonalMessageUserValidationResult::invalid_request_shape;
    }

    const char* request_id = nullptr;
    if (!json_value_c_string(request_object["id"], &request_id) ||
        !request_id_format_valid(request_id) ||
        !copy_nonempty_c_string(request_id, output->request_id, sizeof(output->request_id))) {
        memset(output, 0, sizeof(*output));
        return SignPersonalMessageUserValidationResult::invalid_request_shape;
    }

    JsonVariantConst version = request_object["version"];
    if (!version.is<uint32_t>() ||
        version.as<uint32_t>() != kProtocolVersion) {
        memset(output, 0, sizeof(*output));
        return SignPersonalMessageUserValidationResult::unsupported_version;
    }

    const char* method = nullptr;
    if (!json_value_c_string(request_object["method"], &method) ||
        strcmp(method, "sign_personal_message") != 0) {
        memset(output, 0, sizeof(*output));
        return SignPersonalMessageUserValidationResult::unsupported_method;
    }

    return SignPersonalMessageUserValidationResult::ok;
}

}  // namespace

SignPersonalMessageUserIngressResult
evaluate_sign_personal_message_user_ingress(
    JsonDocument& request,
    SupportedSignRoute route,
    const SignPersonalMessageUserIngressState& state,
    SignPersonalMessageUserIngressOutput* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return SignPersonalMessageUserIngressResult::invalid_request_shape;
    }

    SignPersonalMessageUserEnvelope envelope = {};
    SignPersonalMessageUserValidationResult validation =
        validate_sign_personal_message_user_identity(request, &envelope);
    if (validation != SignPersonalMessageUserValidationResult::ok) {
        return map_validation_result(validation);
    }

    if (!state.material_ready) {
        return SignPersonalMessageUserIngressResult::invalid_state;
    }
    if (state.busy) {
        return SignPersonalMessageUserIngressResult::busy;
    }

    SignPersonalMessageUserSessionRef session = {};
    validation = validate_sign_personal_message_user_session_format(request, &session);
    if (validation != SignPersonalMessageUserValidationResult::ok) {
        return map_validation_result(validation);
    }
    if (state.validate_session == nullptr ||
        state.validate_session(session.session_id, state.session_context) !=
            SessionValidationResult::ok) {
        return SignPersonalMessageUserIngressResult::invalid_session;
    }

    validation = validate_sign_personal_message_user_envelope(request, &envelope);
    if (validation != SignPersonalMessageUserValidationResult::ok) {
        return map_validation_result(validation);
    }

    SignPersonalMessageUserParams params = {};
    validation = validate_sign_personal_message_user_params(request, route, &params);
    if (validation != SignPersonalMessageUserValidationResult::ok) {
        return map_validation_result(validation);
    }

    output->envelope = envelope;
    output->session = session;
    output->params = params;
    return SignPersonalMessageUserIngressResult::ok;
}

const char* sign_personal_message_user_ingress_result_name(
    SignPersonalMessageUserIngressResult result)
{
    switch (result) {
        case SignPersonalMessageUserIngressResult::ok:
            return "ok";
        case SignPersonalMessageUserIngressResult::invalid_request_shape:
            return "invalid_request_shape";
        case SignPersonalMessageUserIngressResult::unsupported_version:
            return "unsupported_version";
        case SignPersonalMessageUserIngressResult::invalid_state:
            return "invalid_state";
        case SignPersonalMessageUserIngressResult::busy:
            return "busy";
        case SignPersonalMessageUserIngressResult::invalid_session:
            return "invalid_session";
        case SignPersonalMessageUserIngressResult::invalid_params_shape:
            return "invalid_params_shape";
        case SignPersonalMessageUserIngressResult::unsupported_field:
            return "unsupported_field";
        case SignPersonalMessageUserIngressResult::unsupported_method:
            return "unsupported_method";
        case SignPersonalMessageUserIngressResult::invalid_network:
            return "invalid_network";
        case SignPersonalMessageUserIngressResult::invalid_message:
            return "invalid_message";
        case SignPersonalMessageUserIngressResult::message_too_large:
            return "message_too_large";
    }
    return "invalid_request_shape";
}

}  // namespace signing
