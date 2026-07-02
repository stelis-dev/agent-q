#include "sign_transaction_user_ingress.h"

#include <string.h>

#include "protocol_input_copy.h"

#include "protocol/json_input.h"
#include "protocol/protocol_constants.h"
#include "protocol/request_id.h"

namespace signing {
namespace {

SignTransactionUserIngressResult map_validation_result(
    SignTransactionUserValidationResult result)
{
    switch (result) {
        case SignTransactionUserValidationResult::ok:
            return SignTransactionUserIngressResult::ok;
        case SignTransactionUserValidationResult::invalid_request_shape:
            return SignTransactionUserIngressResult::invalid_request_shape;
        case SignTransactionUserValidationResult::unsupported_version:
            return SignTransactionUserIngressResult::unsupported_version;
        case SignTransactionUserValidationResult::invalid_session:
            return SignTransactionUserIngressResult::invalid_session;
        case SignTransactionUserValidationResult::invalid_params_shape:
            return SignTransactionUserIngressResult::invalid_params_shape;
        case SignTransactionUserValidationResult::unsupported_field:
            return SignTransactionUserIngressResult::unsupported_field;
        case SignTransactionUserValidationResult::unsupported_method:
            return SignTransactionUserIngressResult::unsupported_method;
        case SignTransactionUserValidationResult::invalid_network:
            return SignTransactionUserIngressResult::invalid_network;
        case SignTransactionUserValidationResult::invalid_tx_bytes:
            return SignTransactionUserIngressResult::invalid_tx_bytes;
    }
    return SignTransactionUserIngressResult::invalid_request_shape;
}

SignTransactionUserValidationResult validate_sign_transaction_user_identity(
    JsonDocument& request,
    SignTransactionUserEnvelope* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return SignTransactionUserValidationResult::invalid_request_shape;
    }

    JsonObjectConst request_object = request.as<JsonObjectConst>();
    if (request_object.isNull()) {
        return SignTransactionUserValidationResult::invalid_request_shape;
    }

    const char* request_id = nullptr;
    if (!json_value_c_string(request_object["id"], &request_id) ||
        !request_id_format_valid(request_id) ||
        !copy_nonempty_c_string(request_id, output->request_id, sizeof(output->request_id))) {
        memset(output, 0, sizeof(*output));
        return SignTransactionUserValidationResult::invalid_request_shape;
    }

    JsonVariantConst version = request_object["version"];
    if (!version.is<uint32_t>() ||
        version.as<uint32_t>() != kProtocolVersion) {
        memset(output, 0, sizeof(*output));
        return SignTransactionUserValidationResult::unsupported_version;
    }

    const char* method = nullptr;
    if (!json_value_c_string(request_object["method"], &method) ||
        strcmp(method, "sign_transaction") != 0) {
        memset(output, 0, sizeof(*output));
        return SignTransactionUserValidationResult::unsupported_method;
    }

    return SignTransactionUserValidationResult::ok;
}

}  // namespace

SignTransactionUserIngressResult evaluate_sign_transaction_user_ingress(
    JsonDocument& request,
    SupportedSignRoute route,
    const SignTransactionUserIngressState& state,
    SignTransactionUserIngressOutput* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return SignTransactionUserIngressResult::invalid_request_shape;
    }

    SignTransactionUserEnvelope envelope = {};
    SignTransactionUserValidationResult validation =
        validate_sign_transaction_user_identity(request, &envelope);
    if (validation != SignTransactionUserValidationResult::ok) {
        return map_validation_result(validation);
    }

    if (!state.material_ready) {
        return SignTransactionUserIngressResult::invalid_state;
    }
    if (state.busy) {
        return SignTransactionUserIngressResult::busy;
    }

    SignTransactionUserSessionRef session = {};
    validation = validate_sign_transaction_user_session_format(request, &session);
    if (validation != SignTransactionUserValidationResult::ok) {
        return map_validation_result(validation);
    }
    if (state.validate_session == nullptr ||
        state.validate_session(session.session_id, state.session_context) !=
            SessionValidationResult::ok) {
        return SignTransactionUserIngressResult::invalid_session;
    }

    validation = validate_sign_transaction_user_envelope(request, &envelope);
    if (validation != SignTransactionUserValidationResult::ok) {
        return map_validation_result(validation);
    }

    SignTransactionUserParams params = {};
    validation = validate_sign_transaction_user_params(request, route, &params);
    if (validation != SignTransactionUserValidationResult::ok) {
        return map_validation_result(validation);
    }

    output->envelope = envelope;
    output->session = session;
    output->params = params;
    return SignTransactionUserIngressResult::ok;
}

const char* sign_transaction_user_ingress_result_name(
    SignTransactionUserIngressResult result)
{
    switch (result) {
        case SignTransactionUserIngressResult::ok:
            return "ok";
        case SignTransactionUserIngressResult::invalid_request_shape:
            return "invalid_request_shape";
        case SignTransactionUserIngressResult::unsupported_version:
            return "unsupported_version";
        case SignTransactionUserIngressResult::invalid_state:
            return "invalid_state";
        case SignTransactionUserIngressResult::busy:
            return "busy";
        case SignTransactionUserIngressResult::invalid_session:
            return "invalid_session";
        case SignTransactionUserIngressResult::invalid_params_shape:
            return "invalid_params_shape";
        case SignTransactionUserIngressResult::unsupported_field:
            return "unsupported_field";
        case SignTransactionUserIngressResult::unsupported_method:
            return "unsupported_method";
        case SignTransactionUserIngressResult::invalid_network:
            return "invalid_network";
        case SignTransactionUserIngressResult::invalid_tx_bytes:
            return "invalid_tx_bytes";
    }
    return "invalid_request_shape";
}

}  // namespace signing
