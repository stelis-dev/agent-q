#pragma once

#include <ArduinoJson.h>

#include "agent_q_policy_signing_execution.h"
#include "agent_q_payload_delivery_admission.h"
#include "agent_q_sign_transaction_policy_runtime.h"
#include "agent_q_signing_preflight.h"
#include "agent_q_timeout_window.h"
#include "agent_q_usb_operation_response_writer.h"
#include "agent_q_user_signing_flow.h"

namespace agent_q {

enum class AgentQUsbSigningNoticeKind {
    info,
    rejected,
    error,
    success,
};

using AgentQEvaluateSignTransactionPreflightFn =
    AgentQSigningPreflightResult (*)(
        JsonDocument& request,
        const AgentQSignTransactionUserIngressState& state,
        const AgentQSigningPreflightRuntime& runtime,
        AgentQSignTransactionPreflightOutput* output);

using AgentQEvaluateSignPersonalMessagePreflightFn =
    AgentQSigningPreflightResult (*)(
        JsonDocument& request,
        const AgentQSignPersonalMessageUserIngressState& state,
        const AgentQSigningPreflightRuntime& runtime,
        AgentQSignPersonalMessagePreflightOutput* output);

struct AgentQUsbSigningHandlerOps {
    bool (*material_ready)();
    bool (*user_signing_ingress_busy)();
    bool (*unrelated_user_signing_ingress_busy)();
    AgentQTimeoutTick (*current_tick)();
    AgentQSessionValidationResult (*validate_session)(const char* session_id, void* context);
    void* validate_session_context;
    AgentQPayloadDeliveryOperationAdmissionFn admit_transaction_payload_delivery;
    AgentQSigningModeReadFn read_signing_mode;
    void* read_signing_mode_context;
    AgentQSigningPreflightRetryResponder retry_responder;
    void* retry_responder_context;
    char* retry_stored_response;
    size_t retry_stored_response_size;
    AgentQEvaluateSignTransactionPreflightFn evaluate_transaction_preflight;
    AgentQEvaluateSignPersonalMessagePreflightFn evaluate_personal_message_preflight;
    void (*record_account_unavailable_runtime_failure)();
    AgentQSignTransactionPolicyRuntimeResult (*evaluate_transaction_policy)(
        const AgentQSuiPreparedSignTransaction& prepared);
    AgentQPolicySigningExecutionResult (*execute_policy_transaction)(
        const AgentQSignTransactionPolicyRuntimeResult& policy_result);
    bool (*write_policy_execution_response)(
        const char* id,
        const uint8_t* request_identity,
        const AgentQPolicySigningExecutionResult& result);
    void (*clear_policy_execution_result)(AgentQPolicySigningExecutionResult* result);
    void (*clear_transaction_policy_result)(AgentQSignTransactionPolicyRuntimeResult* result);
    AgentQTimeoutWindow (*make_user_signing_window)(AgentQTimeoutTick now);
    AgentQUserSigningFlowBeginResult (*begin_transaction_user_signing)(
        AgentQTimeoutTick now,
        const AgentQUserSigningTransactionBeginInput& input);
    AgentQUserSigningFlowBeginResult (*begin_personal_message_user_signing)(
        AgentQTimeoutTick now,
        const AgentQUserSigningPersonalMessageBeginInput& input);
    void (*clear_prepared_transaction)(AgentQSuiPreparedSignTransaction* prepared);
    void (*clear_prepared_personal_message)(AgentQSuiPreparedPersonalMessage* prepared);
    bool (*show_user_signing_review)();
    void (*clear_user_signing_flow)();
    void (*show_user_signing_display_error)();
    void (*record_user_signing_waiting)(const char* id, AgentQSigningRoute signing_route);
    void (*show_policy_signing_notice)(const char* message, AgentQUsbSigningNoticeKind kind);
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
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbSigningHandlerOps& ops);

void handle_usb_sign_personal_message_request(
    const char* id,
    JsonDocument& request,
    const AgentQUsbOperationResponseWriter& writer,
    const AgentQUsbSigningHandlerOps& ops);

}  // namespace agent_q
