#include "agent_q_policy_signing_execution.h"

#include <string.h>

#include "agent_q_bip39.h"

#include "esp_timer.h"

namespace agent_q {
namespace {

bool copy_policy_execution_string(char* output, size_t output_size, const char* value)
{
    if (output == nullptr || output_size == 0 || value == nullptr || value[0] == '\0') {
        return false;
    }
    memset(output, 0, output_size);
    size_t index = 0;
    while (value[index] != '\0') {
        if (index + 1 >= output_size) {
            memset(output, 0, output_size);
            return false;
        }
        output[index] = value[index];
        ++index;
    }
    output[index] = '\0';
    return true;
}

uint64_t current_uptime_ms()
{
    return static_cast<uint64_t>(esp_timer_get_time() / 1000LL);
}

AgentQPolicySigningExecutionResult make_policy_execution_result(
    AgentQPolicySigningExecutionStatus status,
    const char* code,
    const char* message)
{
    AgentQPolicySigningExecutionResult result = {};
    result.status = status;
    result.signing_route = AgentQSigningRoute::sui_sign_transaction;
    result.code = code;
    result.message = message;
    return result;
}

bool copy_policy_metadata(
    AgentQPolicySigningExecutionResult* output,
    const AgentQSignTransactionPolicyRuntimeResult& input)
{
    return output != nullptr &&
           copy_policy_execution_string(output->policy_hash, sizeof(output->policy_hash), input.policy_hash) &&
           copy_policy_execution_string(output->rule_ref, sizeof(output->rule_ref), input.rule_ref);
}

bool write_policy_signing_history(
    const AgentQSignTransactionPolicyRuntimeResult& result,
    AgentQSigningHistoryRecordKind record_kind,
    AgentQSigningHistoryTerminalResult terminal_result,
    const char* reason_code,
    bool enforce_write_budget)
{
    if (result.chain[0] == '\0' ||
        result.method[0] == '\0' ||
        result.payload_digest[0] == '\0' ||
        result.policy_hash[0] == '\0' ||
        result.rule_ref[0] == '\0' ||
        reason_code == nullptr ||
        reason_code[0] == '\0') {
        return false;
    }
    const AgentQSigningHistoryAppendInput input{
        record_kind,
        AgentQApprovalHistoryConfirmationKind::policy,
        terminal_result,
        result.chain,
        result.method,
        reason_code,
        result.payload_digest,
        result.policy_hash,
        result.rule_ref,
    };
    const uint64_t uptime_ms = current_uptime_ms();
    return enforce_write_budget
               ? approval_history_append_budgeted_signing(input, uptime_ms)
               : approval_history_append_required_signing(input, uptime_ms);
}

bool write_policy_signing_confirmation_history(
    const AgentQSignTransactionPolicyRuntimeResult& result)
{
    return write_policy_signing_history(
        result,
        AgentQSigningHistoryRecordKind::confirmation,
        AgentQSigningHistoryTerminalResult::none,
        "policy_authorized",
        false);
}

bool write_policy_signing_terminal_history(
    const AgentQSignTransactionPolicyRuntimeResult& result,
    AgentQSigningHistoryTerminalResult terminal_result,
    const char* reason_code,
    bool enforce_write_budget)
{
    return write_policy_signing_history(
        result,
        AgentQSigningHistoryRecordKind::terminal,
        terminal_result,
        reason_code,
        enforce_write_budget);
}

AgentQPolicySigningExecutionResult handle_policy_filter_result(
    const AgentQSignTransactionPolicyRuntimeResult& policy_result,
    const AgentQPersistentMaterialOps& material_ops)
{
    if (policy_result.status == AgentQSignTransactionPolicyRuntimeStatus::invalid_params ||
        policy_result.status == AgentQSignTransactionPolicyRuntimeStatus::unsupported_method ||
        policy_result.status == AgentQSignTransactionPolicyRuntimeStatus::unsupported_transaction ||
        policy_result.status == AgentQSignTransactionPolicyRuntimeStatus::account_mismatch) {
        return make_policy_execution_result(
            AgentQPolicySigningExecutionStatus::request_error,
            policy_result.code,
            policy_result.message);
    }

    if (policy_result.status == AgentQSignTransactionPolicyRuntimeStatus::policy_error) {
        persistent_material_record_runtime_failure(
            AgentQPersistentMaterialRuntimeFailure::active_policy_unavailable,
            material_ops);
        return make_policy_execution_result(
            AgentQPolicySigningExecutionStatus::request_error,
            policy_result.code,
            policy_result.message);
    }

    if (policy_result.status == AgentQSignTransactionPolicyRuntimeStatus::account_unavailable) {
        persistent_material_record_runtime_failure(
            AgentQPersistentMaterialRuntimeFailure::root_material_unreadable,
            material_ops);
        return make_policy_execution_result(
            AgentQPolicySigningExecutionStatus::request_error,
            "account_error",
            "Stored signing account is unavailable.");
    }

    if (policy_result.status == AgentQSignTransactionPolicyRuntimeStatus::policy_rejected) {
        const char* reason_code =
            policy_result.reason_code[0] != '\0'
                ? policy_result.reason_code
                : "policy_rejected";
        if (!write_policy_signing_terminal_history(
                policy_result,
                AgentQSigningHistoryTerminalResult::policy_rejected,
                reason_code,
                true)) {
            return make_policy_execution_result(
                AgentQPolicySigningExecutionStatus::history_error,
                "history_error",
                "Could not record policy signing terminal result.");
        }
        AgentQPolicySigningExecutionResult result = make_policy_execution_result(
            AgentQPolicySigningExecutionStatus::policy_rejected,
            "policy_rejected",
            "The signing request was rejected by device policy.");
        if (!copy_policy_metadata(&result, policy_result)) {
            return make_policy_execution_result(
                AgentQPolicySigningExecutionStatus::history_error,
                "history_error",
                "Could not record policy signing terminal result.");
        }
        return result;
    }

    return make_policy_execution_result(
        AgentQPolicySigningExecutionStatus::request_error,
        "protocol_error",
        "Policy signing request is invalid.");
}

}  // namespace

AgentQPolicySigningExecutionResult execute_policy_sign_transaction(
    const AgentQSignTransactionPolicyRuntimeResult& policy_result,
    const AgentQPersistentMaterialOps& material_ops)
{
    if (policy_result.status != AgentQSignTransactionPolicyRuntimeStatus::policy_authorized) {
        return handle_policy_filter_result(policy_result, material_ops);
    }

    if (!write_policy_signing_confirmation_history(policy_result)) {
        return make_policy_execution_result(
            AgentQPolicySigningExecutionStatus::history_error,
            "history_error",
            "Could not record policy signing approval.");
    }

    AgentQPolicySigningExecutionResult result = make_policy_execution_result(
        AgentQPolicySigningExecutionStatus::signed_success,
        "policy_signed",
        "Policy authorized signing.");
    if (!copy_policy_metadata(&result, policy_result)) {
        return make_policy_execution_result(
            AgentQPolicySigningExecutionStatus::history_error,
            "history_error",
            "Could not record policy signing terminal result.");
    }
    if (policy_result.tx_bytes == nullptr || policy_result.tx_bytes_size == 0) {
        return make_policy_execution_result(
            AgentQPolicySigningExecutionStatus::request_error,
            "invalid_params",
            "Policy signing payload is unavailable.");
    }

    const SuiTransactionSigningResult signing_result =
        sign_sui_transaction_from_active_identity(
            policy_result.tx_bytes,
            policy_result.tx_bytes_size,
            result.signature,
            &result.signature_size);
    if (signing_result != SuiTransactionSigningResult::ok) {
        wipe_sensitive_buffer(result.signature, sizeof(result.signature));
        result.signature_size = 0;
        if (signing_result == SuiTransactionSigningResult::root_material_unavailable) {
            const bool terminal_recorded = write_policy_signing_terminal_history(
                policy_result,
                AgentQSigningHistoryTerminalResult::signing_failed,
                "root_material_unreadable",
                false);
            persistent_material_record_runtime_failure(
                AgentQPersistentMaterialRuntimeFailure::root_material_unreadable,
                material_ops);
            if (!terminal_recorded) {
                return make_policy_execution_result(
                    AgentQPolicySigningExecutionStatus::history_error,
                    "history_error",
                    "Could not record policy signing terminal result.");
            }
            return make_policy_execution_result(
                AgentQPolicySigningExecutionStatus::account_error,
                "account_error",
                "Stored signing account is unavailable.");
        }
        if (!write_policy_signing_terminal_history(
                policy_result,
                AgentQSigningHistoryTerminalResult::signing_failed,
                "signing_failed",
                false)) {
            return make_policy_execution_result(
                AgentQPolicySigningExecutionStatus::history_error,
                "history_error",
                "Could not record policy signing terminal result.");
        }
        return make_policy_execution_result(
            AgentQPolicySigningExecutionStatus::signing_failed,
            "signing_failed",
            "The device could not produce a signature.");
    }

    if (!write_policy_signing_terminal_history(
            policy_result,
            AgentQSigningHistoryTerminalResult::signed_success,
            "policy_signed",
            false)) {
        wipe_sensitive_buffer(result.signature, sizeof(result.signature));
        result.signature_size = 0;
        return make_policy_execution_result(
            AgentQPolicySigningExecutionStatus::history_error,
            "history_error",
            "Could not record policy signing terminal result.");
    }
    return result;
}

void clear_policy_signing_execution_result(AgentQPolicySigningExecutionResult* result)
{
    if (result == nullptr) {
        return;
    }
    wipe_sensitive_buffer(result->signature, sizeof(result->signature));
    memset(result, 0, sizeof(*result));
}

}  // namespace agent_q
