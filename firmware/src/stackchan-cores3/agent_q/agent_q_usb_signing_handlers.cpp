#include "agent_q_usb_signing_handlers.h"

#include <string.h>

namespace agent_q {

namespace {

AgentQSignTransactionPreflightOutput g_sign_transaction_preflight_scratch;

enum class CommonSignatureIngressError {
    ok,
    invalid_request_shape,
    unsupported_version,
    unsupported_type,
    invalid_state,
    busy,
    invalid_session,
    unsupported_method,
    invalid_params_shape,
    unsupported_field,
    invalid_network,
    payload_invalid,
};

const char* signature_payload_invalid_message(AgentQSigningRoute route)
{
    switch (route) {
        case AgentQSigningRoute::sui_sign_transaction:
            return "Signing txBytes are invalid.";
        case AgentQSigningRoute::sui_sign_personal_message:
            return "Signing message is invalid.";
        case AgentQSigningRoute::unsupported:
        default:
            return "Signing payload is invalid.";
    }
}

const char* signature_unavailable_message(AgentQSigningRoute route)
{
    switch (route) {
        case AgentQSigningRoute::sui_sign_transaction:
            return "sign_transaction is available only after provisioning is complete.";
        case AgentQSigningRoute::sui_sign_personal_message:
            return "sign_personal_message is available only after provisioning is complete.";
        case AgentQSigningRoute::unsupported:
        default:
            return "Signing is available only after provisioning is complete.";
    }
}

const char* signature_ingress_error_code(CommonSignatureIngressError result)
{
    switch (result) {
        case CommonSignatureIngressError::invalid_request_shape:
            return "invalid_id";
        case CommonSignatureIngressError::unsupported_version:
            return "unsupported_version";
        case CommonSignatureIngressError::unsupported_type:
            return "unsupported_type";
        case CommonSignatureIngressError::invalid_state:
            return "invalid_state";
        case CommonSignatureIngressError::busy:
            return "busy";
        case CommonSignatureIngressError::invalid_session:
            return "invalid_session";
        case CommonSignatureIngressError::unsupported_method:
            return "unsupported_method";
        case CommonSignatureIngressError::invalid_params_shape:
        case CommonSignatureIngressError::unsupported_field:
        case CommonSignatureIngressError::invalid_network:
        case CommonSignatureIngressError::payload_invalid:
            return "invalid_params";
        case CommonSignatureIngressError::ok:
        default:
            return "protocol_error";
    }
}

const char* signature_ingress_error_message(
    CommonSignatureIngressError result,
    AgentQSigningRoute route)
{
    switch (result) {
        case CommonSignatureIngressError::invalid_state:
            return signature_unavailable_message(route);
        case CommonSignatureIngressError::busy:
            return "Device is busy with another request.";
        case CommonSignatureIngressError::invalid_session:
            return "Session is unknown or already ended.";
        case CommonSignatureIngressError::unsupported_method:
            return "Signing method is not supported.";
        case CommonSignatureIngressError::invalid_network:
            return "Signing network is unsupported.";
        case CommonSignatureIngressError::payload_invalid:
            return signature_payload_invalid_message(route);
        case CommonSignatureIngressError::unsupported_field:
            return "Signing request contains unsupported fields.";
        case CommonSignatureIngressError::invalid_params_shape:
            return "Signing request params are invalid.";
        case CommonSignatureIngressError::unsupported_version:
            return "Unsupported protocol version.";
        case CommonSignatureIngressError::unsupported_type:
            return "Unsupported request type.";
        case CommonSignatureIngressError::invalid_request_shape:
            return "Signing request envelope is invalid.";
        case CommonSignatureIngressError::ok:
        default:
            return "Signing request is invalid.";
    }
}

CommonSignatureIngressError common_signature_ingress_error(
    AgentQSignTransactionUserIngressResult result)
{
    switch (result) {
        case AgentQSignTransactionUserIngressResult::invalid_request_shape:
            return CommonSignatureIngressError::invalid_request_shape;
        case AgentQSignTransactionUserIngressResult::unsupported_version:
            return CommonSignatureIngressError::unsupported_version;
        case AgentQSignTransactionUserIngressResult::unsupported_type:
            return CommonSignatureIngressError::unsupported_type;
        case AgentQSignTransactionUserIngressResult::invalid_state:
            return CommonSignatureIngressError::invalid_state;
        case AgentQSignTransactionUserIngressResult::busy:
            return CommonSignatureIngressError::busy;
        case AgentQSignTransactionUserIngressResult::invalid_session:
            return CommonSignatureIngressError::invalid_session;
        case AgentQSignTransactionUserIngressResult::unsupported_method:
            return CommonSignatureIngressError::unsupported_method;
        case AgentQSignTransactionUserIngressResult::invalid_params_shape:
            return CommonSignatureIngressError::invalid_params_shape;
        case AgentQSignTransactionUserIngressResult::unsupported_field:
            return CommonSignatureIngressError::unsupported_field;
        case AgentQSignTransactionUserIngressResult::invalid_network:
            return CommonSignatureIngressError::invalid_network;
        case AgentQSignTransactionUserIngressResult::invalid_tx_bytes:
            return CommonSignatureIngressError::payload_invalid;
        case AgentQSignTransactionUserIngressResult::ok:
        default:
            return CommonSignatureIngressError::ok;
    }
}

CommonSignatureIngressError common_signature_ingress_error(
    AgentQSignPersonalMessageUserIngressResult result)
{
    switch (result) {
        case AgentQSignPersonalMessageUserIngressResult::invalid_request_shape:
            return CommonSignatureIngressError::invalid_request_shape;
        case AgentQSignPersonalMessageUserIngressResult::unsupported_version:
            return CommonSignatureIngressError::unsupported_version;
        case AgentQSignPersonalMessageUserIngressResult::unsupported_type:
            return CommonSignatureIngressError::unsupported_type;
        case AgentQSignPersonalMessageUserIngressResult::invalid_state:
            return CommonSignatureIngressError::invalid_state;
        case AgentQSignPersonalMessageUserIngressResult::busy:
            return CommonSignatureIngressError::busy;
        case AgentQSignPersonalMessageUserIngressResult::invalid_session:
            return CommonSignatureIngressError::invalid_session;
        case AgentQSignPersonalMessageUserIngressResult::unsupported_method:
            return CommonSignatureIngressError::unsupported_method;
        case AgentQSignPersonalMessageUserIngressResult::invalid_params_shape:
            return CommonSignatureIngressError::invalid_params_shape;
        case AgentQSignPersonalMessageUserIngressResult::unsupported_field:
            return CommonSignatureIngressError::unsupported_field;
        case AgentQSignPersonalMessageUserIngressResult::invalid_network:
            return CommonSignatureIngressError::invalid_network;
        case AgentQSignPersonalMessageUserIngressResult::invalid_message:
            return CommonSignatureIngressError::payload_invalid;
        case AgentQSignPersonalMessageUserIngressResult::ok:
        default:
            return CommonSignatureIngressError::ok;
    }
}

const char* signature_ingress_error_code(
    AgentQSignTransactionUserIngressResult result)
{
    return signature_ingress_error_code(common_signature_ingress_error(result));
}

const char* signature_ingress_error_message(
    AgentQSignTransactionUserIngressResult result)
{
    return signature_ingress_error_message(
        common_signature_ingress_error(result),
        AgentQSigningRoute::sui_sign_transaction);
}

const char* signature_ingress_error_code(
    AgentQSignPersonalMessageUserIngressResult result)
{
    return signature_ingress_error_code(common_signature_ingress_error(result));
}

const char* signature_ingress_error_message(
    AgentQSignPersonalMessageUserIngressResult result)
{
    return signature_ingress_error_message(
        common_signature_ingress_error(result),
        AgentQSigningRoute::sui_sign_personal_message);
}

const char* signature_begin_error_code(AgentQUserSigningFlowBeginResult result)
{
    switch (result) {
        case AgentQUserSigningFlowBeginResult::active:
            return "busy";
        case AgentQUserSigningFlowBeginResult::invalid_session:
            return "invalid_session";
        case AgentQUserSigningFlowBeginResult::malformed_transaction:
            return "malformed_transaction";
        case AgentQUserSigningFlowBeginResult::unsupported_transaction:
            return "unsupported_transaction";
        case AgentQUserSigningFlowBeginResult::account_unavailable:
        case AgentQUserSigningFlowBeginResult::invalid_account:
            return "account_error";
        case AgentQUserSigningFlowBeginResult::digest_error:
            return "history_error";
        case AgentQUserSigningFlowBeginResult::invalid_network:
        case AgentQUserSigningFlowBeginResult::invalid_payload:
        case AgentQUserSigningFlowBeginResult::invalid_argument:
        case AgentQUserSigningFlowBeginResult::invalid_deadline:
            return "invalid_params";
        case AgentQUserSigningFlowBeginResult::ok:
        default:
            return "invalid_state";
    }
}

const char* signature_begin_error_message(AgentQUserSigningFlowBeginResult result)
{
    switch (result) {
        case AgentQUserSigningFlowBeginResult::active:
            return "Device has a pending signing request.";
        case AgentQUserSigningFlowBeginResult::invalid_session:
            return "Session is unknown or already ended.";
        case AgentQUserSigningFlowBeginResult::malformed_transaction:
            return "Transaction bytes are malformed.";
        case AgentQUserSigningFlowBeginResult::unsupported_transaction:
            return "Transaction shape is not supported.";
        case AgentQUserSigningFlowBeginResult::account_unavailable:
            return "Signing account is unavailable.";
        case AgentQUserSigningFlowBeginResult::invalid_account:
            return "Transaction sender does not match the device account.";
        case AgentQUserSigningFlowBeginResult::digest_error:
            return "Could not digest signing request.";
        case AgentQUserSigningFlowBeginResult::invalid_network:
        case AgentQUserSigningFlowBeginResult::invalid_payload:
        case AgentQUserSigningFlowBeginResult::invalid_argument:
        case AgentQUserSigningFlowBeginResult::invalid_deadline:
        case AgentQUserSigningFlowBeginResult::ok:
        default:
            return "Signing request params are invalid.";
    }
}

const char* sui_preparation_error_code(AgentQSuiSigningPreparationResult result)
{
    switch (result) {
        case AgentQSuiSigningPreparationResult::invalid_params:
        case AgentQSuiSigningPreparationResult::invalid_argument:
            return "invalid_params";
        case AgentQSuiSigningPreparationResult::unsupported_payload_size:
            return "unsupported_payload_size";
        case AgentQSuiSigningPreparationResult::malformed_transaction:
            return "malformed_transaction";
        case AgentQSuiSigningPreparationResult::unsupported_transaction:
            return "unsupported_transaction";
        case AgentQSuiSigningPreparationResult::account_unavailable:
        case AgentQSuiSigningPreparationResult::invalid_account:
            return "account_error";
        case AgentQSuiSigningPreparationResult::digest_error:
            return "history_error";
        case AgentQSuiSigningPreparationResult::ok:
        default:
            return "invalid_state";
    }
}

const char* sui_preparation_error_message(AgentQSuiSigningPreparationResult result)
{
    switch (result) {
        case AgentQSuiSigningPreparationResult::unsupported_payload_size:
            return "Signing payload exceeds the current Sui adapter capacity.";
        case AgentQSuiSigningPreparationResult::malformed_transaction:
            return "Transaction bytes are malformed.";
        case AgentQSuiSigningPreparationResult::unsupported_transaction:
            return "Transaction shape is not supported.";
        case AgentQSuiSigningPreparationResult::account_unavailable:
            return "Signing account is unavailable.";
        case AgentQSuiSigningPreparationResult::invalid_account:
            return "Transaction sender does not match the device account.";
        case AgentQSuiSigningPreparationResult::digest_error:
            return "Could not digest signing request.";
        case AgentQSuiSigningPreparationResult::invalid_params:
        case AgentQSuiSigningPreparationResult::invalid_argument:
        case AgentQSuiSigningPreparationResult::ok:
        default:
            return "Signing request params are invalid.";
    }
}

bool write_sign_route_preflight_error(
    const char* id,
    AgentQSigningPreflightResult result,
    const AgentQUsbOperationResponseWriter& writer)
{
    switch (result) {
        case AgentQSigningPreflightResult::route_invalid_params:
            writer.write_error(id, "invalid_params", "Signing route identifiers are invalid.");
            return true;
        case AgentQSigningPreflightResult::route_unsupported_chain:
            writer.write_error(id, "unsupported_chain", "Signing chain is unsupported.");
            return true;
        case AgentQSigningPreflightResult::route_unsupported_method:
            writer.write_error(id, "unsupported_method", "Signing method is unsupported.");
            return true;
        default:
            break;
    }
    return false;
}

bool write_common_signing_preflight_error(
    const char* id,
    AgentQSigningPreflightResult result,
    const AgentQUsbOperationResponseWriter& writer)
{
    if (write_sign_route_preflight_error(id, result, writer)) {
        return true;
    }
    switch (result) {
        case AgentQSigningPreflightResult::identity_error:
            writer.write_error(id, "protocol_error", "Could not bind signing request identity.");
            return true;
        case AgentQSigningPreflightResult::retry_consumed:
            return true;
        case AgentQSigningPreflightResult::signing_mode_unavailable:
            writer.write_error(id, "invalid_state", "Signing authorization mode is unavailable.");
            return true;
        default:
            break;
    }
    return false;
}

void record_preparation_runtime_failure_if_needed(
    AgentQSuiSigningPreparationResult result,
    const AgentQUsbSigningHandlerOps& ops)
{
    if (result == AgentQSuiSigningPreparationResult::account_unavailable &&
        ops.record_account_unavailable_runtime_failure != nullptr) {
        ops.record_account_unavailable_runtime_failure();
    }
}

void write_sui_preparation_error(
    const char* id,
    AgentQSuiSigningPreparationResult result,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbSigningHandlerOps& ops)
{
    record_preparation_runtime_failure_if_needed(result, ops);
    writer.write_error(
        id,
        sui_preparation_error_code(result),
        sui_preparation_error_message(result));
}

bool write_sign_transaction_preflight_error(
    const char* id,
    AgentQSigningPreflightResult result,
    const AgentQSignTransactionPreflightOutput& output,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbSigningHandlerOps& ops)
{
    if (write_common_signing_preflight_error(id, result, writer)) {
        return true;
    }
    switch (result) {
        case AgentQSigningPreflightResult::transaction_ingress_error:
            writer.write_error(
                id,
                signature_ingress_error_code(output.ingress_result),
                signature_ingress_error_message(output.ingress_result));
            return true;
        case AgentQSigningPreflightResult::transaction_preparation_error:
            write_sui_preparation_error(id, output.preparation_result, writer, ops);
            return true;
        default:
            break;
    }
    writer.write_error(id, "protocol_error", "Signing preflight failed.");
    return true;
}

bool write_sign_personal_message_preflight_error(
    const char* id,
    AgentQSigningPreflightResult result,
    const AgentQSignPersonalMessagePreflightOutput& output,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbSigningHandlerOps& ops)
{
    if (write_common_signing_preflight_error(id, result, writer)) {
        return true;
    }
    switch (result) {
        case AgentQSigningPreflightResult::personal_message_ingress_error:
            writer.write_error(
                id,
                signature_ingress_error_code(output.ingress_result),
                signature_ingress_error_message(output.ingress_result));
            return true;
        case AgentQSigningPreflightResult::personal_message_policy_mode:
            writer.write_error(id, "unsupported_method", "sign_personal_message is not available in policy authorization mode.");
            return true;
        case AgentQSigningPreflightResult::personal_message_preparation_error:
            write_sui_preparation_error(id, output.preparation_result, writer, ops);
            return true;
        default:
            break;
    }
    writer.write_error(id, "protocol_error", "Signing preflight failed.");
    return true;
}

bool common_signing_handler_available(
    const AgentQUsbSigningHandlerOps& ops)
{
    if (ops.material_ready == nullptr ||
        ops.user_signing_ingress_busy == nullptr ||
        ops.validate_session == nullptr ||
        ops.read_signing_mode == nullptr ||
        ops.retry_responder == nullptr ||
        ops.retry_stored_result == nullptr ||
        ops.retry_stored_result_size == 0 ||
        ops.record_account_unavailable_runtime_failure == nullptr ||
        ops.make_user_signing_window == nullptr ||
        ops.show_user_signing_review == nullptr ||
        ops.clear_user_signing_flow == nullptr ||
        ops.show_user_signing_display_error == nullptr ||
        ops.record_user_signing_waiting == nullptr) {
        return false;
    }
    return true;
}

bool transaction_signing_handler_available(
    const AgentQUsbSigningHandlerOps& ops)
{
    return common_signing_handler_available(ops) &&
           ops.evaluate_transaction_preflight != nullptr &&
           ops.evaluate_transaction_policy != nullptr &&
           ops.execute_policy_transaction != nullptr &&
           ops.write_policy_execution_response != nullptr &&
           ops.clear_policy_execution_result != nullptr &&
           ops.clear_transaction_policy_result != nullptr &&
           ops.begin_transaction_user_signing != nullptr &&
           ops.clear_prepared_transaction != nullptr;
}

void clear_sign_transaction_preflight_scratch(
    const AgentQUsbSigningHandlerOps& ops,
    AgentQSignTransactionPreflightOutput& preflight)
{
    ops.clear_prepared_transaction(&preflight.prepared);
    memset(&preflight, 0, sizeof(preflight));
}

bool personal_message_signing_handler_available(
    const AgentQUsbSigningHandlerOps& ops)
{
    return common_signing_handler_available(ops) &&
           ops.evaluate_personal_message_preflight != nullptr &&
           ops.begin_personal_message_user_signing != nullptr &&
           ops.clear_prepared_personal_message != nullptr;
}

AgentQSigningPreflightRuntime make_preflight_runtime(
    const AgentQUsbSigningHandlerOps& ops)
{
    return AgentQSigningPreflightRuntime{
        ops.read_signing_mode,
        ops.read_signing_mode_context,
        ops.retry_responder,
        ops.retry_responder_context,
        ops.retry_stored_result,
        ops.retry_stored_result_size,
    };
}

void show_policy_notice(
    const AgentQUsbSigningHandlerOps& ops,
    const char* message,
    AgentQUsbSigningNoticeKind kind)
{
    if (ops.show_policy_signing_notice != nullptr) {
        ops.show_policy_signing_notice(message, kind);
    }
}

void log_response_write_failure(
    const AgentQUsbSigningHandlerOps& ops,
    const char* response_type,
    const char* id)
{
    if (ops.log_response_write_failure != nullptr) {
        ops.log_response_write_failure(response_type, id);
    }
}

bool policy_execution_status_reportable(AgentQPolicySigningExecutionStatus status)
{
    return status == AgentQPolicySigningExecutionStatus::policy_rejected ||
           status == AgentQPolicySigningExecutionStatus::signing_failed ||
           status == AgentQPolicySigningExecutionStatus::signed_success;
}

void log_policy_execution_status(
    const char* id,
    const AgentQSignTransactionPolicyRuntimeResult& sign_result,
    AgentQPolicySigningExecutionStatus status,
    const AgentQUsbSigningHandlerOps& ops)
{
    switch (status) {
        case AgentQPolicySigningExecutionStatus::policy_rejected:
            if (ops.log_policy_rejected != nullptr) {
                ops.log_policy_rejected(
                    id,
                    sign_result.chain,
                    sign_result.method,
                    sign_result.rule_ref);
            }
            break;
        case AgentQPolicySigningExecutionStatus::signing_failed:
            if (ops.log_policy_signing_failed != nullptr) {
                ops.log_policy_signing_failed(id, sign_result.chain, sign_result.method);
            }
            break;
        case AgentQPolicySigningExecutionStatus::signed_success:
            if (ops.log_policy_signed != nullptr) {
                ops.log_policy_signed(
                    id,
                    sign_result.chain,
                    sign_result.method,
                    sign_result.rule_ref);
            }
            break;
        default:
            break;
    }
}

const char* policy_execution_notice_message(
    AgentQPolicySigningExecutionStatus status,
    bool wrote_response)
{
    switch (status) {
        case AgentQPolicySigningExecutionStatus::policy_rejected:
            return wrote_response ? "Policy rejected" : "Rejected; USB failed";
        case AgentQPolicySigningExecutionStatus::signing_failed:
            return wrote_response ? "Signing failed" : "Failure; USB failed";
        case AgentQPolicySigningExecutionStatus::signed_success:
            return wrote_response ? "Policy signed" : "Signed; USB failed";
        default:
            return nullptr;
    }
}

AgentQUsbSigningNoticeKind policy_execution_notice_kind(
    AgentQPolicySigningExecutionStatus status,
    bool wrote_response)
{
    if (!wrote_response || status == AgentQPolicySigningExecutionStatus::signing_failed) {
        return AgentQUsbSigningNoticeKind::error;
    }
    if (status == AgentQPolicySigningExecutionStatus::policy_rejected) {
        return AgentQUsbSigningNoticeKind::rejected;
    }
    return AgentQUsbSigningNoticeKind::success;
}

void report_policy_execution_outcome(
    const char* id,
    const AgentQSignTransactionPolicyRuntimeResult& sign_result,
    AgentQPolicySigningExecutionStatus status,
    bool wrote_response,
    const AgentQUsbSigningHandlerOps& ops)
{
    if (!policy_execution_status_reportable(status)) {
        return;
    }
    if (wrote_response) {
        log_policy_execution_status(id, sign_result, status, ops);
    } else {
        log_response_write_failure(ops, "sign_result", id);
    }
    show_policy_notice(
        ops,
        policy_execution_notice_message(status, wrote_response),
        policy_execution_notice_kind(status, wrote_response));
}

void finish_user_signing_review_entry(
    const char* id,
    AgentQSigningRoute route,
    AgentQUserSigningFlowBeginResult begin_result,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbSigningHandlerOps& ops)
{
    if (begin_result != AgentQUserSigningFlowBeginResult::ok) {
        writer.write_error(
            id,
            signature_begin_error_code(begin_result),
            signature_begin_error_message(begin_result));
        return;
    }

    if (!ops.show_user_signing_review()) {
        ops.clear_user_signing_flow();
        writer.write_error(id, "ui_error", "Could not show signing review UI.");
        ops.show_user_signing_display_error();
        return;
    }
    ops.record_user_signing_waiting(id, route);
}

void handle_sign_transaction_policy_mode(
    const char* id,
    const AgentQSuiPreparedSignTransaction& prepared,
    const uint8_t* request_identity,
    const AgentQUsbSigningHandlerOps& ops)
{
    AgentQSignTransactionPolicyRuntimeResult sign_result =
        ops.evaluate_transaction_policy(prepared);
    if (sign_result.status == AgentQSignTransactionPolicyRuntimeStatus::policy_authorized) {
        show_policy_notice(ops, "Policy signing", AgentQUsbSigningNoticeKind::info);
    }
    AgentQPolicySigningExecutionResult execution_result =
        ops.execute_policy_transaction(sign_result);
    const bool wrote_response =
        ops.write_policy_execution_response(id, request_identity, execution_result);
    report_policy_execution_outcome(
        id,
        sign_result,
        execution_result.status,
        wrote_response,
        ops);
    ops.clear_policy_execution_result(&execution_result);
    ops.clear_transaction_policy_result(&sign_result);
}

}  // namespace

void handle_usb_sign_transaction_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbSigningHandlerOps& ops)
{
    if (!transaction_signing_handler_available(ops)) {
        writer.write_error(id, "protocol_error", "Signing handler is unavailable.");
        return;
    }

    AgentQSignTransactionPreflightOutput& preflight = g_sign_transaction_preflight_scratch;
    clear_sign_transaction_preflight_scratch(ops, preflight);
    const AgentQSigningPreflightResult preflight_result =
        ops.evaluate_transaction_preflight(
            request,
            AgentQSignTransactionUserIngressState{
                ops.material_ready(),
                ops.user_signing_ingress_busy(),
                ops.validate_session,
                ops.validate_session_context,
            },
            make_preflight_runtime(ops),
            &preflight);
    if (preflight_result != AgentQSigningPreflightResult::ok) {
        write_sign_transaction_preflight_error(id, preflight_result, preflight, writer, ops);
        clear_sign_transaction_preflight_scratch(ops, preflight);
        return;
    }
    if (preflight.signing_mode == AgentQSigningAuthorizationMode::policy) {
        handle_sign_transaction_policy_mode(
            id,
            preflight.prepared,
            preflight.request_identity,
            ops);
        clear_sign_transaction_preflight_scratch(ops, preflight);
        return;
    }

    const AgentQSigningRoute route = preflight.route;
    const AgentQUserSigningFlowBeginResult begin_result =
        ops.begin_transaction_user_signing(
            AgentQUserSigningTransactionBeginInput{
                preflight.ingress.envelope.request_id,
                preflight.request_identity,
                preflight.ingress.session.session_id,
                preflight.route,
                &preflight.prepared,
                ops.make_user_signing_window(),
            });
    clear_sign_transaction_preflight_scratch(ops, preflight);
    finish_user_signing_review_entry(id, route, begin_result, writer, ops);
}

void handle_usb_sign_personal_message_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbSigningHandlerOps& ops)
{
    if (!personal_message_signing_handler_available(ops)) {
        writer.write_error(id, "protocol_error", "Signing handler is unavailable.");
        return;
    }

    AgentQSignPersonalMessagePreflightOutput preflight = {};
    const AgentQSigningPreflightResult preflight_result =
        ops.evaluate_personal_message_preflight(
            request,
            AgentQSignPersonalMessageUserIngressState{
                ops.material_ready(),
                ops.user_signing_ingress_busy(),
                ops.validate_session,
                ops.validate_session_context,
            },
            make_preflight_runtime(ops),
            &preflight);
    if (preflight_result != AgentQSigningPreflightResult::ok) {
        write_sign_personal_message_preflight_error(id, preflight_result, preflight, writer, ops);
        return;
    }

    const AgentQUserSigningFlowBeginResult begin_result =
        ops.begin_personal_message_user_signing(
            AgentQUserSigningPersonalMessageBeginInput{
                preflight.ingress.envelope.request_id,
                preflight.request_identity,
                preflight.ingress.session.session_id,
                preflight.route,
                &preflight.prepared,
                ops.make_user_signing_window(),
            });
    ops.clear_prepared_personal_message(&preflight.prepared);
    finish_user_signing_review_entry(id, preflight.route, begin_result, writer, ops);
}

}  // namespace agent_q
