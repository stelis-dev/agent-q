#pragma once

#include <ArduinoJson.h>

#include "protocol/usb_operation_response_writer.h"
#include "transport/payload_delivery_admission.h"
#include "signing/policy_signing_execution_result.h"
#include "signing/sign_transaction_policy_runtime.h"
#include "signing/signing_preflight.h"
#include "transport/timeout_window.h"
#include "signing/user_signing_flow.h"

namespace signing {

enum class UsbSigningNoticeKind {
    info,
    rejected,
    error,
    success,
};

using EvaluateSignTransactionPreflightFn =
    PreflightResult (*)(
        JsonDocument& request,
        const SignTransactionUserIngressState& state,
        const PreflightRuntime& runtime,
        SignTransactionPreflightOutput* output);

using EvaluateSignPersonalMessagePreflightFn =
    PreflightResult (*)(
        JsonDocument& request,
        const SignPersonalMessageUserIngressState& state,
        const PreflightRuntime& runtime,
        SignPersonalMessagePreflightOutput* output);

struct UsbSigningHandlerOps {
    bool (*material_ready)();
    bool (*user_signing_ingress_busy)();
    bool (*unrelated_user_signing_ingress_busy)();
    TimeoutTick (*current_tick)();
    SessionValidationResult (*validate_session)(const char* session_id, void* context);
    void* validate_session_context;
    PayloadDeliveryOperationAdmissionFn admit_transaction_payload_delivery;
    ModeReadFn read_signing_mode;
    void* read_signing_mode_context;
    PreflightRetryResponder retry_responder;
    void* retry_responder_context;
    char* retry_stored_response;
    size_t retry_stored_response_size;
    SuiSigningPreparationOps preparation_ops;
    EvaluateSignTransactionPreflightFn evaluate_transaction_preflight;
    EvaluateSignPersonalMessagePreflightFn evaluate_personal_message_preflight;
    void (*record_account_unavailable_runtime_failure)();
    SignTransactionPolicyRuntimeResult (*evaluate_transaction_policy)(
        const SuiPreparedSignTransaction& prepared);
    PolicySigningExecutionResult (*execute_policy_transaction)(
        const SignTransactionPolicyRuntimeResult& policy_result);
    bool (*write_policy_execution_response)(
        const char* id,
        const uint8_t* request_identity,
        const PolicySigningExecutionResult& result);
    void (*clear_policy_execution_result)(PolicySigningExecutionResult* result);
    void (*clear_transaction_policy_result)(SignTransactionPolicyRuntimeResult* result);
    TimeoutWindow (*make_user_signing_window)(TimeoutTick now);
    UserSigningFlowBeginResult (*begin_transaction_user_signing)(
        TimeoutTick now,
        const UserSigningTransactionBeginInput& input);
    UserSigningFlowBeginResult (*begin_personal_message_user_signing)(
        TimeoutTick now,
        const UserSigningPersonalMessageBeginInput& input);
    void (*clear_prepared_transaction)(SuiPreparedSignTransaction* prepared);
    void (*clear_prepared_personal_message)(SuiPreparedPersonalMessage* prepared);
    bool (*show_user_signing_review)();
    void (*clear_user_signing_flow)();
    void (*show_user_signing_display_error)();
    void (*record_user_signing_waiting)(const char* id, Route signing_route);
    void (*show_policy_signing_notice)(const char* message, UsbSigningNoticeKind kind);
    void (*log_policy_rejected)(
        const char* id,
        const char* chain,
        const char* method,
        const char* rule_ref);
    void (*log_policy_signing_failed)(
        const char* id,
        const char* chain,
        const char* method);
    void (*log_policy_signed)(
        const char* id,
        const char* chain,
        const char* method,
        const char* rule_ref);
    void (*log_response_write_failure)(const char* response_type, const char* id);
};

void handle_usb_sign_transaction_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbSigningHandlerOps& ops);

void handle_usb_sign_personal_message_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbSigningHandlerOps& ops);

}  // namespace signing
