#include "agent_q_signing_preflight.h"

#include <string.h>

#include "agent_q_json_input.h"
#include "agent_q_payload_delivery_admission.h"
#include "agent_q_payload_delivery_store.h"
#include "agent_q_sign_transaction_limits.h"
#include "agent_q_sui_signing_authority.h"

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
    return agent_q_json_value_c_string(request["payload"]["chain"], chain) &&
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
    const char* method,
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
               method,
               retry,
               runtime.retry_stored_result,
               runtime.retry_responder_context) ==
           AgentQSigningPreflightRetryDisposition::continue_preflight;
}

AgentQSigningPreflightResult evaluate_post_identity_preflight(
    AgentQSupportedSignRoute route,
    const char* request_id,
    const char* session_id,
    const AgentQSigningPreflightRuntime& runtime,
    uint8_t* request_identity,
    AgentQSigningAuthorizationMode* signing_mode)
{
    if (!retry_allows_preflight_to_continue(
            request_id,
            sign_route_wire_method(route),
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

    return evaluate_post_identity_preflight(
        route,
        request_id,
        session_id,
        runtime,
        request_identity,
        signing_mode);
}

AgentQSigningPreflightResult evaluate_staged_post_ingress_preflight(
    AgentQSupportedSignRoute route,
    const char* request_id,
    const char* session_id,
    const char* network,
    const char* payload_kind,
    size_t payload_size_bytes,
    const char* payload_digest,
    const AgentQSigningPreflightRuntime& runtime,
    uint8_t* request_identity,
    size_t request_identity_size,
    AgentQSigningAuthorizationMode* signing_mode)
{
    if (!sign_request_identity_for_payload_descriptor(
            route,
            network,
            payload_kind,
            payload_size_bytes,
            payload_digest,
            request_identity,
            request_identity_size)) {
        return AgentQSigningPreflightResult::identity_error;
    }

    return evaluate_post_identity_preflight(
        route,
        request_id,
        session_id,
        runtime,
        request_identity,
        signing_mode);
}

bool staged_descriptor_matches_request(
    const AgentQPayloadDeliveryDescriptor& descriptor,
    const AgentQSignTransactionUserParams& params)
{
    (void)params;
    return descriptor.size_bytes > 0 &&
           descriptor.payload_digest[0] != '\0';
}

AgentQSuiSigningPreparationResult payload_take_result_to_preparation_result(
    AgentQPayloadDeliveryResult result)
{
    switch (result) {
        case AgentQPayloadDeliveryResult::payload_too_large:
            return AgentQSuiSigningPreparationResult::payload_too_large;
        case AgentQPayloadDeliveryResult::ok:
            return AgentQSuiSigningPreparationResult::ok;
        case AgentQPayloadDeliveryResult::invalid_session:
        case AgentQPayloadDeliveryResult::invalid_payload_ref:
        case AgentQPayloadDeliveryResult::not_found:
            return AgentQSuiSigningPreparationResult::payload_unavailable;
        case AgentQPayloadDeliveryResult::invalid_argument:
        case AgentQPayloadDeliveryResult::invalid_state:
        case AgentQPayloadDeliveryResult::invalid_payload_digest:
        case AgentQPayloadDeliveryResult::invalid_transfer_id:
        case AgentQPayloadDeliveryResult::allocation_failed:
        case AgentQPayloadDeliveryResult::chunk_too_large:
        case AgentQPayloadDeliveryResult::offset_mismatch:
        case AgentQPayloadDeliveryResult::payload_overflow:
        case AgentQPayloadDeliveryResult::size_mismatch:
        case AgentQPayloadDeliveryResult::digest_mismatch:
        case AgentQPayloadDeliveryResult::digest_error:
        default:
            return AgentQSuiSigningPreparationResult::invalid_params;
    }
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

AgentQSignTransactionUserIngressResult admit_transaction_payload_after_network_guard(
    const AgentQSignTransactionUserIngressState& state,
    const AgentQSignTransactionUserIngressOutput& ingress)
{
    if (state.admit_payload_delivery == nullptr) {
        return AgentQSignTransactionUserIngressResult::ok;
    }
    const bool staged =
        ingress.params.payload_form == AgentQSignTransactionPayloadForm::staged_payload_ref;
    const AgentQPayloadDeliveryAdmissionDecision admission =
        state.admit_payload_delivery(
            AgentQPayloadDeliverySignTransactionAdmissionInput{
                state.now_tick,
                ingress.session.session_id,
                staged,
                staged ? ingress.params.payload_ref : nullptr,
            },
            state.payload_delivery_admission_context);
    return map_payload_delivery_admission_result(admission);
}

AgentQSuiSigningPreparationResult active_identity_network_result_to_preparation_result(
    AgentQSuiSigningActiveIdentityNetworkResult result)
{
    switch (result) {
        case AgentQSuiSigningActiveIdentityNetworkResult::ok:
            return AgentQSuiSigningPreparationResult::ok;
        case AgentQSuiSigningActiveIdentityNetworkResult::account_unavailable:
            return AgentQSuiSigningPreparationResult::account_unavailable;
        case AgentQSuiSigningActiveIdentityNetworkResult::active_identity_unavailable:
            return AgentQSuiSigningPreparationResult::active_identity_unavailable;
        case AgentQSuiSigningActiveIdentityNetworkResult::network_mismatch:
        default:
            return AgentQSuiSigningPreparationResult::invalid_network;
    }
}

AgentQSuiSigningPreparationResult validate_active_identity_network_before_preparation(
    const char* network)
{
    return active_identity_network_result_to_preparation_result(
        verify_sui_signing_active_identity_network(network));
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

    const bool staged =
        output->ingress.params.payload_form ==
        AgentQSignTransactionPayloadForm::staged_payload_ref;
    const AgentQSigningPreflightResult common_result =
        staged
            ? AgentQSigningPreflightResult::ok
            : evaluate_common_post_ingress_preflight(
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
        validate_active_identity_network_before_preparation(output->ingress.params.network);
    if (output->preparation_result != AgentQSuiSigningPreparationResult::ok) {
        return AgentQSigningPreflightResult::transaction_preparation_error;
    }

    output->ingress_result =
        admit_transaction_payload_after_network_guard(state, output->ingress);
    if (output->ingress_result != AgentQSignTransactionUserIngressResult::ok) {
        return AgentQSigningPreflightResult::transaction_ingress_error;
    }

    if (staged) {
        AgentQPayloadDeliveryView view = {};
        const AgentQPayloadDeliveryResult resolve_result =
            payload_delivery_resolve_finalized(
                runtime.now_tick,
                output->ingress.session.session_id,
                output->ingress.params.payload_ref,
                &view);
        if (resolve_result != AgentQPayloadDeliveryResult::ok) {
            output->preparation_result =
                payload_take_result_to_preparation_result(resolve_result);
            return AgentQSigningPreflightResult::transaction_preparation_error;
        }
        if (!staged_descriptor_matches_request(
                view.descriptor,
                output->ingress.params)) {
            output->preparation_result =
                AgentQSuiSigningPreparationResult::invalid_argument;
            return AgentQSigningPreflightResult::transaction_preparation_error;
        }
        const AgentQSigningPreflightResult staged_common_result =
            evaluate_staged_post_ingress_preflight(
                classification.route,
                output->ingress.envelope.request_id,
                output->ingress.session.session_id,
                output->ingress.params.network,
                kAgentQPayloadDeliveryPayloadKindTransaction,
                view.descriptor.size_bytes,
                view.descriptor.payload_digest,
                runtime,
                output->request_identity,
                sizeof(output->request_identity),
                &output->signing_mode);
        if (staged_common_result != AgentQSigningPreflightResult::ok) {
            return staged_common_result;
        }
        AgentQPayloadDeliveryOwnedPayload payload = {};
        const AgentQPayloadDeliveryResult take_result =
            payload_delivery_take_finalized(
                runtime.now_tick,
                output->ingress.session.session_id,
                output->ingress.params.payload_ref,
                &payload);
        if (take_result != AgentQPayloadDeliveryResult::ok) {
            output->preparation_result =
                payload_take_result_to_preparation_result(take_result);
            return AgentQSigningPreflightResult::transaction_preparation_error;
        }
        output->preparation_result =
            prepare_sui_sign_transaction_from_owned_bytes(
                classification.route,
                output->ingress.params.network,
                payload.bytes,
                payload.size_bytes,
                payload.descriptor.payload_digest,
                &output->prepared);
    } else {
        if (output->ingress.params.tx_bytes_decoded_size >
            kAgentQSuiSignTransactionInlineTxBytesMaxBytes) {
            output->preparation_result =
                AgentQSuiSigningPreparationResult::payload_too_large;
            return AgentQSigningPreflightResult::transaction_preparation_error;
        }
        output->preparation_result =
            prepare_sui_sign_transaction(
                classification.route,
                output->ingress.params.network,
                output->ingress.params.tx_bytes_base64,
                output->ingress.params.tx_bytes_decoded_size,
                &output->prepared);
    }
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
        validate_active_identity_network_before_preparation(output->ingress.params.network);
    if (output->preparation_result != AgentQSuiSigningPreparationResult::ok) {
        return AgentQSigningPreflightResult::personal_message_preparation_error;
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
