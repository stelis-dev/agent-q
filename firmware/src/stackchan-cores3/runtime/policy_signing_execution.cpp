#include "policy_signing_execution.h"

#include <string.h>

#include "bip39.h"

#include "esp_timer.h"

namespace signing {
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

PolicySigningExecutionResult make_policy_execution_result(
    PolicySigningExecutionStatus status,
    const char* code,
    const char* message)
{
    PolicySigningExecutionResult result = {};
    result.status = status;
    result.signing_route = Route::sui_sign_transaction;
    result.code = code;
    result.message = message;
    return result;
}

bool copy_policy_metadata(
    PolicySigningExecutionResult* output,
    const SignTransactionPolicyRuntimeResult& input)
{
    return output != nullptr &&
           copy_policy_execution_string(output->policy_hash, sizeof(output->policy_hash), input.policy_hash) &&
           copy_policy_execution_string(output->rule_ref, sizeof(output->rule_ref), input.rule_ref);
}

bool write_policy_signing_history(
    const SignTransactionPolicyRuntimeResult& result,
    HistoryRecordKind record_kind,
    HistoryTerminalResult terminal_result,
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
    const HistoryAppendInput input{
        record_kind,
        ApprovalHistoryConfirmationKind::policy,
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
    const SignTransactionPolicyRuntimeResult& result)
{
    return write_policy_signing_history(
        result,
        HistoryRecordKind::confirmation,
        HistoryTerminalResult::none,
        "policy_authorized",
        false);
}

bool write_policy_signing_terminal_history(
    const SignTransactionPolicyRuntimeResult& result,
    HistoryTerminalResult terminal_result,
    const char* reason_code,
    bool enforce_write_budget)
{
    return write_policy_signing_history(
        result,
        HistoryRecordKind::terminal,
        terminal_result,
        reason_code,
        enforce_write_budget);
}

PolicySigningExecutionResult handle_policy_filter_result(
    const SignTransactionPolicyRuntimeResult& policy_result,
    const PersistentMaterialOps& material_ops)
{
    if (policy_result.status == SignTransactionPolicyRuntimeStatus::invalid_params ||
        policy_result.status == SignTransactionPolicyRuntimeStatus::unsupported_method ||
        policy_result.status == SignTransactionPolicyRuntimeStatus::unsupported_transaction ||
        policy_result.status == SignTransactionPolicyRuntimeStatus::account_mismatch) {
        return make_policy_execution_result(
            PolicySigningExecutionStatus::request_error,
            policy_result.code,
            policy_result.message);
    }

    if (policy_result.status == SignTransactionPolicyRuntimeStatus::policy_error) {
        persistent_material_record_runtime_failure(
            PersistentMaterialRuntimeFailure::active_policy_unavailable,
            material_ops);
        return make_policy_execution_result(
            PolicySigningExecutionStatus::request_error,
            policy_result.code,
            policy_result.message);
    }

    if (policy_result.status == SignTransactionPolicyRuntimeStatus::account_unavailable) {
        persistent_material_record_runtime_failure(
            PersistentMaterialRuntimeFailure::root_material_unreadable,
            material_ops);
        return make_policy_execution_result(
            PolicySigningExecutionStatus::request_error,
            "account_unavailable",
            "Stored signing account is unavailable.");
    }

    if (policy_result.status == SignTransactionPolicyRuntimeStatus::policy_rejected) {
        const char* reason_code =
            policy_result.reason_code[0] != '\0'
                ? policy_result.reason_code
                : "policy_rejected";
        if (!write_policy_signing_terminal_history(
                policy_result,
                HistoryTerminalResult::policy_rejected,
                reason_code,
                true)) {
            return make_policy_execution_result(
                PolicySigningExecutionStatus::history_error,
                "history_unavailable",
                "Could not record policy signing terminal result.");
        }
        PolicySigningExecutionResult result = make_policy_execution_result(
            PolicySigningExecutionStatus::policy_rejected,
            "policy_rejected",
            "The signing request was rejected by device policy.");
        if (!copy_policy_metadata(&result, policy_result)) {
            return make_policy_execution_result(
                PolicySigningExecutionStatus::history_error,
                "history_unavailable",
                "Could not record policy signing terminal result.");
        }
        return result;
    }

    return make_policy_execution_result(
        PolicySigningExecutionStatus::request_error,
        "internal_output_error",
        "Policy signing request is invalid.");
}

}  // namespace

PolicySigningExecutionResult execute_policy_sign_transaction(
    const SignTransactionPolicyRuntimeResult& policy_result,
    const PersistentMaterialOps& material_ops)
{
    if (policy_result.status != SignTransactionPolicyRuntimeStatus::policy_authorized) {
        return handle_policy_filter_result(policy_result, material_ops);
    }

    if (!write_policy_signing_confirmation_history(policy_result)) {
        return make_policy_execution_result(
            PolicySigningExecutionStatus::history_error,
            "history_unavailable",
            "Could not record policy signing approval.");
    }

    PolicySigningExecutionResult result = make_policy_execution_result(
        PolicySigningExecutionStatus::signed_success,
        "policy_signed",
        "Policy authorized signing.");
    if (!copy_policy_metadata(&result, policy_result)) {
        return make_policy_execution_result(
            PolicySigningExecutionStatus::history_error,
            "history_unavailable",
            "Could not record policy signing terminal result.");
    }
    if (policy_result.tx_bytes == nullptr || policy_result.tx_bytes_size == 0) {
        return make_policy_execution_result(
            PolicySigningExecutionStatus::request_error,
            "invalid_params",
            "Policy signing payload is unavailable.");
    }

    const SuiSigningStatus signing_status =
        sign_sui_transaction_from_active_identity(
            policy_result.tx_bytes,
            policy_result.tx_bytes_size,
            result.signature,
            &result.signature_size);
    if (signing_status != SuiSigningStatus::ok) {
        wipe_sensitive_buffer(result.signature, sizeof(result.signature));
        result.signature_size = 0;
        if (signing_status == SuiSigningStatus::root_material_unavailable) {
            const bool terminal_recorded = write_policy_signing_terminal_history(
                policy_result,
                HistoryTerminalResult::signing_failed,
                "root_material_unreadable",
                false);
            persistent_material_record_runtime_failure(
                PersistentMaterialRuntimeFailure::root_material_unreadable,
                material_ops);
            if (!terminal_recorded) {
                return make_policy_execution_result(
                    PolicySigningExecutionStatus::history_error,
                    "history_unavailable",
                    "Could not record policy signing terminal result.");
            }
            return make_policy_execution_result(
                PolicySigningExecutionStatus::account_error,
                "account_unavailable",
                "Stored signing account is unavailable.");
        }
        if (!write_policy_signing_terminal_history(
                policy_result,
                HistoryTerminalResult::signing_failed,
                "signing_failed",
                false)) {
            return make_policy_execution_result(
                PolicySigningExecutionStatus::history_error,
                "history_unavailable",
                "Could not record policy signing terminal result.");
        }
        return make_policy_execution_result(
            PolicySigningExecutionStatus::signing_failed,
            "signing_failed",
            "The device could not produce a signature.");
    }

    if (!write_policy_signing_terminal_history(
            policy_result,
            HistoryTerminalResult::signed_success,
            "policy_signed",
            false)) {
        wipe_sensitive_buffer(result.signature, sizeof(result.signature));
        result.signature_size = 0;
        return make_policy_execution_result(
            PolicySigningExecutionStatus::history_error,
            "history_unavailable",
            "Could not record policy signing terminal result.");
    }
    return result;
}

}  // namespace signing
