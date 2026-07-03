#include "usb_signing_handlers.h"

#include <string.h>

namespace signing {

namespace {

SignTransactionPreflightOutput g_sign_transaction_preflight_scratch;

enum class CommonSignatureIngressError {
    ok,
    invalid_request_shape,
    unsupported_version,
    invalid_state,
    busy,
    invalid_session,
    unsupported_method,
    invalid_params_shape,
    unsupported_field,
    invalid_network,
    payload_invalid,
    payload_too_large,
    payload_unavailable,
};

const char* signature_ingress_error_code(CommonSignatureIngressError result)
{
    switch (result) {
        case CommonSignatureIngressError::invalid_request_shape:
            return "invalid_request";
        case CommonSignatureIngressError::unsupported_version:
            return "unsupported_version";
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
        case CommonSignatureIngressError::payload_too_large:
            return "payload_too_large";
        case CommonSignatureIngressError::payload_unavailable:
            return "payload_unavailable";
        case CommonSignatureIngressError::ok:
        default:
            return "internal_output_error";
    }
}

CommonSignatureIngressError common_signature_ingress_error(
    SignTransactionUserIngressResult result)
{
    switch (result) {
        case SignTransactionUserIngressResult::invalid_request_shape:
            return CommonSignatureIngressError::invalid_request_shape;
        case SignTransactionUserIngressResult::unsupported_version:
            return CommonSignatureIngressError::unsupported_version;
        case SignTransactionUserIngressResult::invalid_state:
            return CommonSignatureIngressError::invalid_state;
        case SignTransactionUserIngressResult::busy:
            return CommonSignatureIngressError::busy;
        case SignTransactionUserIngressResult::invalid_session:
            return CommonSignatureIngressError::invalid_session;
        case SignTransactionUserIngressResult::unsupported_method:
            return CommonSignatureIngressError::unsupported_method;
        case SignTransactionUserIngressResult::invalid_params_shape:
            return CommonSignatureIngressError::invalid_params_shape;
        case SignTransactionUserIngressResult::unsupported_field:
            return CommonSignatureIngressError::unsupported_field;
        case SignTransactionUserIngressResult::invalid_network:
            return CommonSignatureIngressError::invalid_network;
        case SignTransactionUserIngressResult::invalid_tx_bytes:
            return CommonSignatureIngressError::payload_invalid;
        case SignTransactionUserIngressResult::ok:
        default:
            return CommonSignatureIngressError::ok;
    }
}

CommonSignatureIngressError common_signature_ingress_error(
    SignPersonalMessageUserIngressResult result)
{
    switch (result) {
        case SignPersonalMessageUserIngressResult::invalid_request_shape:
            return CommonSignatureIngressError::invalid_request_shape;
        case SignPersonalMessageUserIngressResult::unsupported_version:
            return CommonSignatureIngressError::unsupported_version;
        case SignPersonalMessageUserIngressResult::invalid_state:
            return CommonSignatureIngressError::invalid_state;
        case SignPersonalMessageUserIngressResult::busy:
            return CommonSignatureIngressError::busy;
        case SignPersonalMessageUserIngressResult::invalid_session:
            return CommonSignatureIngressError::invalid_session;
        case SignPersonalMessageUserIngressResult::unsupported_method:
            return CommonSignatureIngressError::unsupported_method;
        case SignPersonalMessageUserIngressResult::invalid_params_shape:
            return CommonSignatureIngressError::invalid_params_shape;
        case SignPersonalMessageUserIngressResult::unsupported_field:
            return CommonSignatureIngressError::unsupported_field;
        case SignPersonalMessageUserIngressResult::invalid_network:
            return CommonSignatureIngressError::invalid_network;
        case SignPersonalMessageUserIngressResult::invalid_message:
            return CommonSignatureIngressError::payload_invalid;
        case SignPersonalMessageUserIngressResult::message_too_large:
            return CommonSignatureIngressError::payload_too_large;
        case SignPersonalMessageUserIngressResult::ok:
        default:
            return CommonSignatureIngressError::ok;
    }
}

const char* signature_ingress_error_code(
    SignTransactionUserIngressResult result)
{
    return signature_ingress_error_code(common_signature_ingress_error(result));
}

const char* signature_ingress_error_code(
    SignPersonalMessageUserIngressResult result)
{
    return signature_ingress_error_code(common_signature_ingress_error(result));
}

const char* signature_begin_error_code(UserSigningFlowBeginResult result)
{
    switch (result) {
        case UserSigningFlowBeginResult::active:
            return "busy";
        case UserSigningFlowBeginResult::invalid_session:
            return "invalid_session";
        case UserSigningFlowBeginResult::malformed_transaction:
            return "malformed_transaction";
        case UserSigningFlowBeginResult::unsupported_transaction:
            return "unsupported_transaction";
        case UserSigningFlowBeginResult::account_unavailable:
        case UserSigningFlowBeginResult::invalid_account:
            return "account_unavailable";
        case UserSigningFlowBeginResult::digest_error:
            return "history_unavailable";
        case UserSigningFlowBeginResult::invalid_network:
        case UserSigningFlowBeginResult::invalid_payload:
        case UserSigningFlowBeginResult::invalid_argument:
        case UserSigningFlowBeginResult::invalid_deadline:
            return "invalid_params";
        case UserSigningFlowBeginResult::ok:
        default:
            return "invalid_state";
    }
}

bool signature_begin_error_should_notify(UserSigningFlowBeginResult result)
{
    return result == UserSigningFlowBeginResult::malformed_transaction ||
           result == UserSigningFlowBeginResult::unsupported_transaction;
}

const char* signature_begin_notice_message(UserSigningFlowBeginResult result)
{
    switch (result) {
        case UserSigningFlowBeginResult::malformed_transaction:
            return "Malformed transaction";
        case UserSigningFlowBeginResult::unsupported_transaction:
            return "Unsupported transaction";
        default:
            return nullptr;
    }
}

const char* sui_preparation_error_code(SuiSigningPreparationResult result)
{
    switch (result) {
        case SuiSigningPreparationResult::invalid_params:
        case SuiSigningPreparationResult::invalid_argument:
        case SuiSigningPreparationResult::invalid_network:
            return "invalid_params";
        case SuiSigningPreparationResult::payload_too_large:
            return "payload_too_large";
        case SuiSigningPreparationResult::payload_unavailable:
            return "payload_unavailable";
        case SuiSigningPreparationResult::malformed_transaction:
            return "malformed_transaction";
        case SuiSigningPreparationResult::unsupported_transaction:
            return "unsupported_transaction";
        case SuiSigningPreparationResult::account_unavailable:
        case SuiSigningPreparationResult::active_identity_unavailable:
        case SuiSigningPreparationResult::invalid_account:
            return "account_unavailable";
        case SuiSigningPreparationResult::digest_error:
            return "history_unavailable";
        case SuiSigningPreparationResult::ok:
        default:
            return "invalid_state";
    }
}

bool sui_preparation_error_should_notify(SuiSigningPreparationResult result)
{
    return result == SuiSigningPreparationResult::payload_too_large ||
           result == SuiSigningPreparationResult::malformed_transaction ||
           result == SuiSigningPreparationResult::unsupported_transaction;
}

const char* sui_preparation_notice_message(SuiSigningPreparationResult result)
{
    switch (result) {
        case SuiSigningPreparationResult::payload_too_large:
            return "Payload too large";
        case SuiSigningPreparationResult::malformed_transaction:
            return "Malformed transaction";
        case SuiSigningPreparationResult::unsupported_transaction:
            return "Unsupported transaction";
        default:
            return nullptr;
    }
}

bool write_sign_route_preflight_error(
    const char* id,
    PreflightResult result,
    const UsbOperationResponseWriter& writer)
{
    switch (result) {
        case PreflightResult::route_invalid_params:
            writer.write_error(id, "invalid_params");
            return true;
        case PreflightResult::route_unsupported_chain:
            writer.write_error(id, "unsupported_chain");
            return true;
        case PreflightResult::route_unsupported_method:
            writer.write_error(id, "unsupported_method");
            return true;
        default:
            break;
    }
    return false;
}

bool write_common_signing_preflight_error(
    const char* id,
    PreflightResult result,
    const UsbOperationResponseWriter& writer)
{
    if (write_sign_route_preflight_error(id, result, writer)) {
        return true;
    }
    switch (result) {
        case PreflightResult::identity_error:
            writer.write_error(id, "internal_output_error");
            return true;
        case PreflightResult::retry_consumed:
            return true;
        case PreflightResult::signing_mode_unavailable:
            writer.write_error(id, "invalid_state");
            return true;
        default:
            break;
    }
    return false;
}

void record_preparation_runtime_failure_if_needed(
    SuiSigningPreparationResult result,
    const UsbSigningHandlerOps& ops)
{
    if (result == SuiSigningPreparationResult::account_unavailable &&
        ops.record_account_unavailable_runtime_failure != nullptr) {
        ops.record_account_unavailable_runtime_failure();
    }
}

void write_sui_preparation_error(
    const char* id,
    SuiSigningPreparationResult result,
    const UsbOperationResponseWriter& writer,
    const UsbSigningHandlerOps& ops)
{
    record_preparation_runtime_failure_if_needed(result, ops);
    writer.write_error(
        id,
        sui_preparation_error_code(result));
    if (sui_preparation_error_should_notify(result) &&
        ops.show_policy_signing_notice != nullptr) {
        ops.show_policy_signing_notice(
            sui_preparation_notice_message(result),
            UsbSigningNoticeKind::error);
    }
}

bool write_sign_transaction_preflight_error(
    const char* id,
    PreflightResult result,
    const SignTransactionPreflightOutput& output,
    const UsbOperationResponseWriter& writer,
    const UsbSigningHandlerOps& ops)
{
    if (write_common_signing_preflight_error(id, result, writer)) {
        return true;
    }
    switch (result) {
        case PreflightResult::transaction_ingress_error:
            writer.write_error(
                id,
                signature_ingress_error_code(output.ingress_result));
            return true;
        case PreflightResult::transaction_preparation_error:
            write_sui_preparation_error(id, output.preparation_result, writer, ops);
            return true;
        default:
            break;
    }
    writer.write_error(id, "internal_output_error");
    return true;
}

bool write_sign_personal_message_preflight_error(
    const char* id,
    PreflightResult result,
    const SignPersonalMessagePreflightOutput& output,
    const UsbOperationResponseWriter& writer,
    const UsbSigningHandlerOps& ops)
{
    if (write_common_signing_preflight_error(id, result, writer)) {
        return true;
    }
    switch (result) {
        case PreflightResult::personal_message_ingress_error:
            writer.write_error(
                id,
                signature_ingress_error_code(output.ingress_result));
            return true;
        case PreflightResult::personal_message_policy_mode:
            writer.write_error(id, "unsupported_method");
            return true;
        case PreflightResult::personal_message_preparation_error:
            write_sui_preparation_error(id, output.preparation_result, writer, ops);
            return true;
        default:
            break;
    }
    writer.write_error(id, "internal_output_error");
    return true;
}

bool common_signing_handler_available(
    const UsbSigningHandlerOps& ops)
{
    if (ops.material_ready == nullptr ||
        ops.user_signing_ingress_busy == nullptr ||
        ops.unrelated_user_signing_ingress_busy == nullptr ||
        ops.current_tick == nullptr ||
        ops.validate_session == nullptr ||
        ops.admit_transaction_payload_delivery == nullptr ||
        ops.read_signing_mode == nullptr ||
        ops.retry_responder == nullptr ||
        ops.retry_stored_response == nullptr ||
        ops.retry_stored_response_size == 0 ||
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
    const UsbSigningHandlerOps& ops)
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
    const UsbSigningHandlerOps& ops,
    SignTransactionPreflightOutput& preflight)
{
    ops.clear_prepared_transaction(&preflight.prepared);
    memset(&preflight, 0, sizeof(preflight));
}

bool personal_message_signing_handler_available(
    const UsbSigningHandlerOps& ops)
{
    return common_signing_handler_available(ops) &&
           ops.evaluate_personal_message_preflight != nullptr &&
           ops.begin_personal_message_user_signing != nullptr &&
           ops.clear_prepared_personal_message != nullptr;
}

PreflightRuntime make_preflight_runtime(
    const UsbSigningHandlerOps& ops,
    TimeoutTick now_tick)
{
    return PreflightRuntime{
        now_tick,
        ops.read_signing_mode,
        ops.read_signing_mode_context,
        ops.retry_responder,
        ops.retry_responder_context,
        ops.retry_stored_response,
        ops.retry_stored_response_size,
    };
}

void show_policy_notice(
    const UsbSigningHandlerOps& ops,
    const char* message,
    UsbSigningNoticeKind kind)
{
    if (ops.show_policy_signing_notice != nullptr) {
        ops.show_policy_signing_notice(message, kind);
    }
}

void log_response_write_failure(
    const UsbSigningHandlerOps& ops,
    const char* response_type,
    const char* id)
{
    if (ops.log_response_write_failure != nullptr) {
        ops.log_response_write_failure(response_type, id);
    }
}

bool policy_execution_request_error_reportable(const char* code)
{
    return code != nullptr &&
           (strcmp(code, "unsupported_transaction") == 0 ||
            strcmp(code, "payload_too_large") == 0 ||
            strcmp(code, "malformed_transaction") == 0);
}

bool policy_execution_status_reportable(
    PolicySigningExecutionStatus status,
    const char* code)
{
    return status == PolicySigningExecutionStatus::policy_rejected ||
           status == PolicySigningExecutionStatus::signing_failed ||
           status == PolicySigningExecutionStatus::signed_success ||
           (status == PolicySigningExecutionStatus::request_error &&
            policy_execution_request_error_reportable(code));
}

void log_policy_execution_status(
    const char* id,
    const SignTransactionPolicyRuntimeResult& policy_result,
    PolicySigningExecutionStatus status,
    const UsbSigningHandlerOps& ops)
{
    switch (status) {
        case PolicySigningExecutionStatus::policy_rejected:
            if (ops.log_policy_rejected != nullptr) {
                ops.log_policy_rejected(
                    id,
                    policy_result.chain,
                    policy_result.method,
                    policy_result.rule_ref);
            }
            break;
        case PolicySigningExecutionStatus::signing_failed:
            if (ops.log_policy_signing_failed != nullptr) {
                ops.log_policy_signing_failed(id, policy_result.chain, policy_result.method);
            }
            break;
        case PolicySigningExecutionStatus::signed_success:
            if (ops.log_policy_signed != nullptr) {
                ops.log_policy_signed(
                    id,
                    policy_result.chain,
                    policy_result.method,
                    policy_result.rule_ref);
            }
            break;
        default:
            break;
    }
}

const char* policy_execution_notice_message(
    PolicySigningExecutionStatus status,
    const char* code,
    bool wrote_response)
{
    switch (status) {
        case PolicySigningExecutionStatus::request_error:
            if (!wrote_response) {
                return "Request failed; USB failed";
            }
            if (strcmp(code, "payload_too_large") == 0) {
                return "Payload too large";
            }
            if (strcmp(code, "malformed_transaction") == 0) {
                return "Malformed transaction";
            }
            if (strcmp(code, "unsupported_transaction") == 0) {
                return "Policy cannot evaluate";
            }
            return "Unsupported transaction";
        case PolicySigningExecutionStatus::policy_rejected:
            return wrote_response ? "Policy rejected" : "Rejected; USB failed";
        case PolicySigningExecutionStatus::signing_failed:
            return wrote_response ? "Signing failed" : "Failure; USB failed";
        case PolicySigningExecutionStatus::signed_success:
            return wrote_response ? "Policy signed" : "Signed; USB failed";
        default:
            return nullptr;
    }
}

UsbSigningNoticeKind policy_execution_notice_kind(
    PolicySigningExecutionStatus status,
    bool wrote_response)
{
    if (!wrote_response ||
        status == PolicySigningExecutionStatus::request_error ||
        status == PolicySigningExecutionStatus::signing_failed) {
        return UsbSigningNoticeKind::error;
    }
    if (status == PolicySigningExecutionStatus::policy_rejected) {
        return UsbSigningNoticeKind::rejected;
    }
    return UsbSigningNoticeKind::success;
}

void report_policy_execution_outcome(
    const char* id,
    const SignTransactionPolicyRuntimeResult& policy_result,
    PolicySigningExecutionStatus status,
    bool wrote_response,
    const UsbSigningHandlerOps& ops)
{
    if (!policy_execution_status_reportable(status, policy_result.code)) {
        return;
    }
    if (wrote_response) {
        log_policy_execution_status(id, policy_result, status, ops);
    } else {
        log_response_write_failure(ops, "policy_result", id);
    }
    show_policy_notice(
        ops,
        policy_execution_notice_message(status, policy_result.code, wrote_response),
        policy_execution_notice_kind(status, wrote_response));
}

void finish_user_signing_review_entry(
    const char* id,
    Route route,
    UserSigningFlowBeginResult begin_result,
    const UsbOperationResponseWriter& writer,
    const UsbSigningHandlerOps& ops)
{
    if (begin_result != UserSigningFlowBeginResult::ok) {
        writer.write_error(
            id,
            signature_begin_error_code(begin_result));
        if (signature_begin_error_should_notify(begin_result) &&
            ops.show_policy_signing_notice != nullptr) {
            ops.show_policy_signing_notice(
                signature_begin_notice_message(begin_result),
                UsbSigningNoticeKind::error);
        }
        return;
    }

    if (!ops.show_user_signing_review()) {
        ops.clear_user_signing_flow();
        writer.write_error(id, "ui_error");
        ops.show_user_signing_display_error();
        return;
    }
    ops.record_user_signing_waiting(id, route);
}

void handle_sign_transaction_policy_mode_with_prepared_borrow(
    const char* id,
    const SuiPreparedSignTransaction& prepared,
    const uint8_t* request_identity,
    const UsbSigningHandlerOps& ops)
{
    // Policy runtime results borrow prepared.tx_bytes. Keep evaluation,
    // execution, response writing, and policy cleanup inside this helper so the
    // caller can clear the prepared payload only after the borrowed result is
    // fully consumed.
    SignTransactionPolicyRuntimeResult policy_result =
        ops.evaluate_transaction_policy(prepared);
    if (policy_result.status == SignTransactionPolicyRuntimeStatus::policy_authorized) {
        show_policy_notice(ops, "Policy signing", UsbSigningNoticeKind::info);
    }
    PolicySigningExecutionResult execution_result =
        ops.execute_policy_transaction(policy_result);
    const bool wrote_response =
        ops.write_policy_execution_response(id, request_identity, execution_result);
    report_policy_execution_outcome(
        id,
        policy_result,
        execution_result.status,
        wrote_response,
        ops);
    ops.clear_policy_execution_result(&execution_result);
    ops.clear_transaction_policy_result(&policy_result);
}

}  // namespace

void handle_usb_sign_transaction_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbSigningHandlerOps& ops)
{
    if (!transaction_signing_handler_available(ops)) {
        writer.write_error(id, "internal_output_error");
        return;
    }

    SignTransactionPreflightOutput& preflight = g_sign_transaction_preflight_scratch;
    clear_sign_transaction_preflight_scratch(ops, preflight);
    const TimeoutTick now_tick = ops.current_tick();
    const PreflightResult preflight_result =
        ops.evaluate_transaction_preflight(
            request,
            SignTransactionUserIngressState{
                now_tick,
                ops.material_ready(),
                ops.user_signing_ingress_busy(),
                ops.validate_session,
                ops.validate_session_context,
                ops.admit_transaction_payload_delivery,
            },
            make_preflight_runtime(ops, now_tick),
            &preflight);
    if (preflight_result != PreflightResult::ok) {
        write_sign_transaction_preflight_error(id, preflight_result, preflight, writer, ops);
        clear_sign_transaction_preflight_scratch(ops, preflight);
        return;
    }
    if (!ops.material_ready()) {
        writer.write_error(id, "invalid_state");
        clear_sign_transaction_preflight_scratch(ops, preflight);
        return;
    }
    if (preflight.signing_mode == AuthorizationMode::policy) {
        handle_sign_transaction_policy_mode_with_prepared_borrow(
            id,
            preflight.prepared,
            preflight.request_identity,
            ops);
        clear_sign_transaction_preflight_scratch(ops, preflight);
        return;
    }

    const Route route = preflight.route;
    const TimeoutWindow request_window = ops.make_user_signing_window(now_tick);
    const UserSigningFlowBeginResult begin_result =
        ops.begin_transaction_user_signing(
            now_tick,
            UserSigningTransactionBeginInput{
                preflight.ingress.envelope.request_id,
                preflight.request_identity,
                preflight.ingress.session.session_id,
                preflight.route,
                &preflight.prepared,
                request_window,
            });
    clear_sign_transaction_preflight_scratch(ops, preflight);
    finish_user_signing_review_entry(id, route, begin_result, writer, ops);
}

void handle_usb_sign_personal_message_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbSigningHandlerOps& ops)
{
    if (!personal_message_signing_handler_available(ops)) {
        writer.write_error(id, "internal_output_error");
        return;
    }

    SignPersonalMessagePreflightOutput preflight = {};
    const TimeoutTick now_tick = ops.current_tick();
    const PreflightResult preflight_result =
        ops.evaluate_personal_message_preflight(
            request,
            SignPersonalMessageUserIngressState{
                ops.material_ready(),
                ops.unrelated_user_signing_ingress_busy(),
                ops.validate_session,
                ops.validate_session_context,
            },
            make_preflight_runtime(ops, now_tick),
            &preflight);
    if (preflight_result != PreflightResult::ok) {
        write_sign_personal_message_preflight_error(id, preflight_result, preflight, writer, ops);
        return;
    }
    if (!ops.material_ready()) {
        writer.write_error(id, "invalid_state");
        ops.clear_prepared_personal_message(&preflight.prepared);
        return;
    }

    const UserSigningFlowBeginResult begin_result =
        ops.begin_personal_message_user_signing(
            now_tick,
            UserSigningPersonalMessageBeginInput{
                preflight.ingress.envelope.request_id,
                preflight.request_identity,
                preflight.ingress.session.session_id,
                preflight.route,
                &preflight.prepared,
                ops.make_user_signing_window(now_tick),
            });
    ops.clear_prepared_personal_message(&preflight.prepared);
    finish_user_signing_review_entry(id, preflight.route, begin_result, writer, ops);
}

}  // namespace signing
