#include "signing_preflight.h"

#include <string.h>

#include "protocol/json_input.h"
#include "transport/payload_delivery_admission.h"
#include "sui_signing_authority.h"

namespace signing {
namespace {

PreflightResult route_result_to_preflight_result(
    SignRouteResult result)
{
    switch (result) {
        case SignRouteResult::invalid_params:
            return PreflightResult::route_invalid_params;
        case SignRouteResult::unsupported_chain:
            return PreflightResult::route_unsupported_chain;
        case SignRouteResult::unsupported_method:
            return PreflightResult::route_unsupported_method;
        case SignRouteResult::ok:
            break;
    }
    return PreflightResult::identity_error;
}

bool read_route_identifiers(
    JsonDocument& request,
    const char** chain,
    const char** method)
{
    return json_value_c_string(request["payload"]["chain"], chain) &&
           json_value_c_string(request["method"], method);
}

bool read_signing_mode(
    const PreflightRuntime& runtime,
    AuthorizationMode* signing_mode)
{
    if (runtime.read_signing_mode == nullptr || signing_mode == nullptr) {
        return false;
    }
    return runtime.read_signing_mode(signing_mode, runtime.signing_mode_context);
}

bool retry_allows_preflight_to_continue(
    const char* request_id,
    const char* method,
    const char* session_id,
    const uint8_t* request_identity,
    const PreflightRuntime& runtime)
{
    if (runtime.retry_stored_response == nullptr ||
        runtime.retry_stored_response_size == 0) {
        return false;
    }
    const RetryDeliveryResult retry =
        evaluate_signing_retry_delivery(
            session_id,
            request_id,
            request_identity,
            kSignRequestIdentitySize,
            runtime.retry_stored_response,
            runtime.retry_stored_response_size);
    if (runtime.retry_responder == nullptr) {
        return retry.status == RetryDeliveryStatus::not_found;
    }
    return runtime.retry_responder(
               request_id,
               method,
               retry,
               runtime.retry_stored_response,
               runtime.retry_responder_context) ==
           PreflightRetryDisposition::continue_preflight;
}

PreflightResult evaluate_post_identity_preflight(
    SupportedSignRoute route,
    const char* request_id,
    const char* session_id,
    const PreflightRuntime& runtime,
    uint8_t* request_identity,
    AuthorizationMode* signing_mode)
{
    if (!retry_allows_preflight_to_continue(
            request_id,
            sign_route_wire_method(route),
            session_id,
            request_identity,
            runtime)) {
        return PreflightResult::retry_consumed;
    }

    if (!read_signing_mode(runtime, signing_mode)) {
        return PreflightResult::signing_mode_unavailable;
    }
    return PreflightResult::ok;
}

PreflightResult evaluate_common_post_ingress_preflight(
    SupportedSignRoute route,
    const char* request_id,
    const char* session_id,
    const char* network,
    const char* payload_base64,
    const PreflightRuntime& runtime,
    uint8_t* request_identity,
    size_t request_identity_size,
    AuthorizationMode* signing_mode)
{
    if (!sign_request_identity(
            route,
            network,
            payload_base64,
            request_identity,
            request_identity_size)) {
        return PreflightResult::identity_error;
    }

    return evaluate_post_identity_preflight(
        route,
        request_id,
        session_id,
        runtime,
        request_identity,
        signing_mode);
}

SignTransactionUserIngressResult map_payload_delivery_admission_result(
    const PayloadDeliveryAdmissionDecision& decision)
{
    switch (decision.result) {
        case PayloadDeliveryAdmissionResult::ok:
            return SignTransactionUserIngressResult::ok;
        case PayloadDeliveryAdmissionResult::busy:
            return SignTransactionUserIngressResult::busy;
        case PayloadDeliveryAdmissionResult::unknown_request:
            return SignTransactionUserIngressResult::invalid_params_shape;
    }
    return SignTransactionUserIngressResult::invalid_params_shape;
}

SignTransactionUserIngressResult admit_transaction_payload_after_network_guard(
    const SignTransactionUserIngressState& state)
{
    if (state.admit_payload_delivery == nullptr) {
        return SignTransactionUserIngressResult::ok;
    }
    const PayloadDeliveryAdmissionDecision admission =
        state.admit_payload_delivery(
            PayloadDeliveryOperationAdmissionInput{
                state.now_tick,
                PayloadDeliveryOperationKind::sign_transaction,
            });
    return map_payload_delivery_admission_result(admission);
}

SuiSigningPreparationResult active_identity_network_result_to_preparation_result(
    SuiSigningActiveIdentityNetworkResult result)
{
    switch (result) {
        case SuiSigningActiveIdentityNetworkResult::ok:
            return SuiSigningPreparationResult::ok;
        case SuiSigningActiveIdentityNetworkResult::account_unavailable:
            return SuiSigningPreparationResult::account_unavailable;
        case SuiSigningActiveIdentityNetworkResult::active_identity_unavailable:
            return SuiSigningPreparationResult::active_identity_unavailable;
        case SuiSigningActiveIdentityNetworkResult::network_mismatch:
        default:
            return SuiSigningPreparationResult::invalid_network;
    }
}

SuiSigningPreparationResult validate_active_identity_network_before_preparation(
    const char* network)
{
    return active_identity_network_result_to_preparation_result(
        verify_sui_signing_active_identity_network(network));
}

}  // namespace

PreflightResult evaluate_sign_transaction_preflight(
    JsonDocument& request,
    const SignTransactionUserIngressState& state,
    const PreflightRuntime& runtime,
    SignTransactionPreflightOutput* output)
{
    if (output == nullptr) {
        return PreflightResult::identity_error;
    }
    memset(output, 0, sizeof(*output));
    output->route = SupportedSignRoute::unsupported;
    output->route_result = SignRouteResult::invalid_params;
    output->ingress_result = SignTransactionUserIngressResult::invalid_request_shape;
    output->preparation_result = SuiSigningPreparationResult::invalid_argument;
    output->signing_mode = AuthorizationMode::user;

    const char* chain = nullptr;
    const char* method = nullptr;
    read_route_identifiers(request, &chain, &method);
    const SignRouteClassification classification =
        classify_sign_route(SignOperation::sign_transaction, chain, method);
    output->route_result = classification.result;
    output->route = classification.route;
    if (classification.result != SignRouteResult::ok) {
        return route_result_to_preflight_result(classification.result);
    }

    output->ingress_result =
        evaluate_sign_transaction_user_ingress(
            request,
            classification.route,
            state,
            &output->ingress);
    if (output->ingress_result != SignTransactionUserIngressResult::ok) {
        return PreflightResult::transaction_ingress_error;
    }

    const PreflightResult common_result =
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
    if (common_result != PreflightResult::ok) {
        return common_result;
    }

    output->preparation_result =
        validate_active_identity_network_before_preparation(output->ingress.params.network);
    if (output->preparation_result != SuiSigningPreparationResult::ok) {
        return PreflightResult::transaction_preparation_error;
    }

    output->ingress_result =
        admit_transaction_payload_after_network_guard(state);
    if (output->ingress_result != SignTransactionUserIngressResult::ok) {
        return PreflightResult::transaction_ingress_error;
    }

    output->preparation_result =
        prepare_sui_sign_transaction(
            classification.route,
            output->ingress.params.network,
            output->ingress.params.tx_bytes_base64,
            output->ingress.params.tx_bytes_decoded_size,
            &output->prepared);
    if (output->preparation_result != SuiSigningPreparationResult::ok) {
        clear_prepared_sui_sign_transaction(&output->prepared);
        return PreflightResult::transaction_preparation_error;
    }

    return PreflightResult::ok;
}

PreflightResult evaluate_sign_personal_message_preflight(
    JsonDocument& request,
    const SignPersonalMessageUserIngressState& state,
    const PreflightRuntime& runtime,
    SignPersonalMessagePreflightOutput* output)
{
    if (output == nullptr) {
        return PreflightResult::identity_error;
    }
    memset(output, 0, sizeof(*output));
    output->route = SupportedSignRoute::unsupported;
    output->route_result = SignRouteResult::invalid_params;
    output->ingress_result = SignPersonalMessageUserIngressResult::invalid_request_shape;
    output->preparation_result = SuiSigningPreparationResult::invalid_argument;
    output->signing_mode = AuthorizationMode::user;

    const char* chain = nullptr;
    const char* method = nullptr;
    read_route_identifiers(request, &chain, &method);
    const SignRouteClassification classification =
        classify_sign_route(SignOperation::sign_personal_message, chain, method);
    output->route_result = classification.result;
    output->route = classification.route;
    if (classification.result != SignRouteResult::ok) {
        return route_result_to_preflight_result(classification.result);
    }

    output->ingress_result =
        evaluate_sign_personal_message_user_ingress(
            request,
            classification.route,
            state,
            &output->ingress);
    if (output->ingress_result != SignPersonalMessageUserIngressResult::ok) {
        return PreflightResult::personal_message_ingress_error;
    }

    const PreflightResult common_result =
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
    if (common_result != PreflightResult::ok) {
        return common_result;
    }
    if (output->signing_mode == AuthorizationMode::policy) {
        return PreflightResult::personal_message_policy_mode;
    }

    output->preparation_result =
        validate_active_identity_network_before_preparation(output->ingress.params.network);
    if (output->preparation_result != SuiSigningPreparationResult::ok) {
        return PreflightResult::personal_message_preparation_error;
    }

    output->preparation_result =
        prepare_sui_sign_personal_message(
            classification.route,
            output->ingress.params.network,
            output->ingress.params.message_base64,
            output->ingress.params.message_decoded_size,
            &output->prepared);
    if (output->preparation_result != SuiSigningPreparationResult::ok) {
        clear_prepared_sui_sign_personal_message(&output->prepared);
        return PreflightResult::personal_message_preparation_error;
    }

    return PreflightResult::ok;
}

}  // namespace signing
