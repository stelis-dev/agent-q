#include "agent_q_signing_preflight.h"

#include <string.h>

#include "agent_q_json_input.h"

namespace agent_q {
namespace {

AgentQSigningPreflightResult route_result_to_preflight_result(
    AgentQSignRouteResult result)
{
    switch (result) {
        case AgentQSignRouteResult::invalid_params:
            return AgentQSigningPreflightResult::route_invalid_params;
        case AgentQSignRouteResult::unsupported_chain:
            return AgentQSigningPreflightResult::route_unsupported_chain;
        case AgentQSignRouteResult::unsupported_method:
            return AgentQSigningPreflightResult::route_unsupported_method;
        case AgentQSignRouteResult::ok:
            break;
    }
    return AgentQSigningPreflightResult::identity_error;
}

bool read_route_identifiers(
    JsonDocument& request,
    const char** chain,
    const char** method)
{
    return agent_q_json_value_c_string(request["chain"], chain) &&
           agent_q_json_value_c_string(request["method"], method);
}

bool read_signing_mode(
    const AgentQSigningPreflightRuntime& runtime,
    AgentQSigningAuthorizationMode* signing_mode)
{
    if (runtime.read_signing_mode == nullptr || signing_mode == nullptr) {
        return false;
    }
    return runtime.read_signing_mode(signing_mode, runtime.signing_mode_context);
}

bool retry_allows_preflight_to_continue(
    const char* request_id,
    const char* session_id,
    const uint8_t* request_identity,
    const AgentQSigningPreflightRuntime& runtime)
{
    if (runtime.retry_stored_result == nullptr ||
        runtime.retry_stored_result_size == 0) {
        return false;
    }
    const AgentQSigningRetryDeliveryResult retry =
        evaluate_signing_retry_delivery(
            session_id,
            request_id,
            request_identity,
            kAgentQSignRequestIdentitySize,
            runtime.retry_stored_result,
            runtime.retry_stored_result_size);
    if (runtime.retry_responder == nullptr) {
        return retry.status == AgentQSigningRetryDeliveryStatus::not_found;
    }
    return runtime.retry_responder(
               request_id,
               retry,
               runtime.retry_stored_result,
               runtime.retry_responder_context) ==
           AgentQSigningPreflightRetryDisposition::continue_preflight;
}

AgentQSigningPreflightResult evaluate_common_post_ingress_preflight(
    AgentQSupportedSignRoute route,
    const char* request_id,
    const char* session_id,
    const char* network,
    const char* payload_base64,
    const AgentQSigningPreflightRuntime& runtime,
    uint8_t* request_identity,
    size_t request_identity_size,
    AgentQSigningAuthorizationMode* signing_mode)
{
    if (!sign_request_identity(
            route,
            network,
            payload_base64,
            request_identity,
            request_identity_size)) {
        return AgentQSigningPreflightResult::identity_error;
    }

    if (!retry_allows_preflight_to_continue(
            request_id,
            session_id,
            request_identity,
            runtime)) {
        return AgentQSigningPreflightResult::retry_consumed;
    }

    if (!read_signing_mode(runtime, signing_mode)) {
        return AgentQSigningPreflightResult::signing_mode_unavailable;
    }
    return AgentQSigningPreflightResult::ok;
}

}  // namespace

AgentQSigningPreflightResult evaluate_sign_transaction_preflight(
    JsonDocument& request,
    const AgentQSignTransactionUserIngressState& state,
    const AgentQSigningPreflightRuntime& runtime,
    AgentQSignTransactionPreflightOutput* output)
{
    if (output == nullptr) {
        return AgentQSigningPreflightResult::identity_error;
    }
    memset(output, 0, sizeof(*output));
    output->route = AgentQSupportedSignRoute::unsupported;
    output->route_result = AgentQSignRouteResult::invalid_params;
    output->ingress_result = AgentQSignTransactionUserIngressResult::invalid_request_shape;
    output->preparation_result = AgentQSuiSigningPreparationResult::invalid_argument;
    output->signing_mode = AgentQSigningAuthorizationMode::user;

    const char* chain = nullptr;
    const char* method = nullptr;
    read_route_identifiers(request, &chain, &method);
    const AgentQSignRouteClassification classification =
        classify_sign_route(AgentQSignOperation::sign_transaction, chain, method);
    output->route_result = classification.result;
    output->route = classification.route;
    if (classification.result != AgentQSignRouteResult::ok) {
        return route_result_to_preflight_result(classification.result);
    }

    output->ingress_result =
        evaluate_sign_transaction_user_ingress(
            request,
            classification.route,
            state,
            &output->ingress);
    if (output->ingress_result != AgentQSignTransactionUserIngressResult::ok) {
        return AgentQSigningPreflightResult::transaction_ingress_error;
    }

    const AgentQSigningPreflightResult common_result =
        evaluate_common_post_ingress_preflight(
            classification.route,
            output->ingress.envelope.request_id,
            output->ingress.session.session_id,
            output->ingress.params.network,
            output->ingress.params.tx_bytes_base64,
            runtime,
            output->request_identity,
            sizeof(output->request_identity),
            &output->signing_mode);
    if (common_result != AgentQSigningPreflightResult::ok) {
        return common_result;
    }

    output->preparation_result =
        prepare_sui_sign_transaction(
            classification.route,
            output->ingress.params.network,
            output->ingress.params.tx_bytes_base64,
            output->ingress.params.tx_bytes_decoded_size,
            &output->prepared);
    if (output->preparation_result != AgentQSuiSigningPreparationResult::ok) {
        clear_prepared_sui_sign_transaction(&output->prepared);
        return AgentQSigningPreflightResult::transaction_preparation_error;
    }

    return AgentQSigningPreflightResult::ok;
}

AgentQSigningPreflightResult evaluate_sign_personal_message_preflight(
    JsonDocument& request,
    const AgentQSignPersonalMessageUserIngressState& state,
    const AgentQSigningPreflightRuntime& runtime,
    AgentQSignPersonalMessagePreflightOutput* output)
{
    if (output == nullptr) {
        return AgentQSigningPreflightResult::identity_error;
    }
    memset(output, 0, sizeof(*output));
    output->route = AgentQSupportedSignRoute::unsupported;
    output->route_result = AgentQSignRouteResult::invalid_params;
    output->ingress_result = AgentQSignPersonalMessageUserIngressResult::invalid_request_shape;
    output->preparation_result = AgentQSuiSigningPreparationResult::invalid_argument;
    output->signing_mode = AgentQSigningAuthorizationMode::user;

    const char* chain = nullptr;
    const char* method = nullptr;
    read_route_identifiers(request, &chain, &method);
    const AgentQSignRouteClassification classification =
        classify_sign_route(AgentQSignOperation::sign_personal_message, chain, method);
    output->route_result = classification.result;
    output->route = classification.route;
    if (classification.result != AgentQSignRouteResult::ok) {
        return route_result_to_preflight_result(classification.result);
    }

    output->ingress_result =
        evaluate_sign_personal_message_user_ingress(
            request,
            classification.route,
            state,
            &output->ingress);
    if (output->ingress_result != AgentQSignPersonalMessageUserIngressResult::ok) {
        return AgentQSigningPreflightResult::personal_message_ingress_error;
    }

    const AgentQSigningPreflightResult common_result =
        evaluate_common_post_ingress_preflight(
            classification.route,
            output->ingress.envelope.request_id,
            output->ingress.session.session_id,
            output->ingress.params.network,
            output->ingress.params.message_base64,
            runtime,
            output->request_identity,
            sizeof(output->request_identity),
            &output->signing_mode);
    if (common_result != AgentQSigningPreflightResult::ok) {
        return common_result;
    }
    if (output->signing_mode == AgentQSigningAuthorizationMode::policy) {
        return AgentQSigningPreflightResult::personal_message_policy_mode;
    }

    output->preparation_result =
        prepare_sui_sign_personal_message(
            classification.route,
            output->ingress.params.network,
            output->ingress.params.message_base64,
            output->ingress.params.message_decoded_size,
            &output->prepared);
    if (output->preparation_result != AgentQSuiSigningPreparationResult::ok) {
        clear_prepared_sui_sign_personal_message(&output->prepared);
        return AgentQSigningPreflightResult::personal_message_preparation_error;
    }

    return AgentQSigningPreflightResult::ok;
}

}  // namespace agent_q
