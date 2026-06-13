#include "agent_q_sign_transaction_user_ingress.h"

#include <string.h>

#include "agent_q_protocol_input_copy.h"

#include "agent_q_json_input.h"
#include "agent_q_protocol_constants.h"
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
        case AgentQSignTransactionUserValidationResult::invalid_payload_ref:
            return AgentQSignTransactionUserIngressResult::invalid_payload_ref;
        case AgentQSignTransactionUserValidationResult::invalid_payload_descriptor:
            return AgentQSignTransactionUserIngressResult::invalid_payload_descriptor;
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
    if (!version.is<uint32_t>() ||
        version.as<uint32_t>() != kAgentQProtocolVersion) {
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

struct AgentQSignTransactionPayloadSourceForAdmission {
    bool staged_payload_ref;
    const char* payload_ref;
};

bool object_has_key(JsonObjectConst object, const char* key)
{
    if (key == nullptr) {
        return false;
    }
    for (JsonPairConst pair : object) {
        if (agent_q_json_string_equals(pair.key(), key)) {
            return true;
        }
    }
    return false;
}

AgentQSignTransactionUserIngressResult map_payload_delivery_admission_result(
    const AgentQPayloadDeliveryAdmissionDecision& decision)
{
    switch (decision.result) {
        case AgentQPayloadDeliveryAdmissionResult::ok:
            return AgentQSignTransactionUserIngressResult::ok;
        case AgentQPayloadDeliveryAdmissionResult::busy:
            return AgentQSignTransactionUserIngressResult::busy;
        case AgentQPayloadDeliveryAdmissionResult::invalid_session:
            return AgentQSignTransactionUserIngressResult::invalid_session;
        case AgentQPayloadDeliveryAdmissionResult::invalid_payload_ref:
        case AgentQPayloadDeliveryAdmissionResult::unknown_request:
            return AgentQSignTransactionUserIngressResult::invalid_payload_ref;
    }
    return AgentQSignTransactionUserIngressResult::invalid_params_shape;
}

AgentQSignTransactionUserIngressResult read_payload_source_for_admission(
    JsonDocument& request,
    AgentQSignTransactionPayloadSourceForAdmission* output)
{
    if (output != nullptr) {
        memset(output, 0, sizeof(*output));
    }
    if (output == nullptr) {
        return AgentQSignTransactionUserIngressResult::invalid_params_shape;
    }
    JsonObjectConst request_object = request.as<JsonObjectConst>();
    if (request_object.isNull()) {
        return AgentQSignTransactionUserIngressResult::invalid_params_shape;
    }
    JsonObjectConst params = request_object["params"].as<JsonObjectConst>();
    if (params.isNull()) {
        return AgentQSignTransactionUserIngressResult::invalid_params_shape;
    }

    const bool has_tx_bytes = object_has_key(params, "txBytes");
    const bool has_payload_ref = object_has_key(params, "payloadRef");
    if (has_tx_bytes == has_payload_ref) {
        return AgentQSignTransactionUserIngressResult::invalid_params_shape;
    }
    if (has_payload_ref) {
        if (!params["payloadRef"].is<const char*>()) {
            return AgentQSignTransactionUserIngressResult::invalid_payload_ref;
        }
        output->staged_payload_ref = true;
        output->payload_ref = params["payloadRef"].as<const char*>();
    }
    return AgentQSignTransactionUserIngressResult::ok;
}

}  // namespace

AgentQSignTransactionUserIngressResult evaluate_sign_transaction_user_ingress(
    JsonDocument& request,
    AgentQSupportedSignRoute route,
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

    AgentQSignTransactionPayloadSourceForAdmission payload_source = {};
    AgentQSignTransactionUserIngressResult payload_source_result =
        read_payload_source_for_admission(request, &payload_source);
    if (payload_source_result != AgentQSignTransactionUserIngressResult::ok) {
        return payload_source_result;
    }
    if (state.admit_payload_delivery != nullptr) {
        const AgentQPayloadDeliveryAdmissionDecision admission =
            state.admit_payload_delivery(
                AgentQPayloadDeliverySignTransactionAdmissionInput{
                    state.now_tick,
                    session.session_id,
                    payload_source.staged_payload_ref,
                    payload_source.payload_ref,
                },
                state.payload_delivery_admission_context);
        const AgentQSignTransactionUserIngressResult mapped_result =
            map_payload_delivery_admission_result(admission);
        if (mapped_result != AgentQSignTransactionUserIngressResult::ok) {
            return mapped_result;
        }
    }

    AgentQSignTransactionUserParams params = {};
    validation = validate_sign_transaction_user_params(request, route, &params);
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
        case AgentQSignTransactionUserIngressResult::invalid_payload_ref:
            return "invalid_payload_ref";
        case AgentQSignTransactionUserIngressResult::invalid_payload_descriptor:
            return "invalid_payload_descriptor";
    }
    return "invalid_request_shape";
}

}  // namespace agent_q
