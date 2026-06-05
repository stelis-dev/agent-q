#include "agent_q_sign_transaction_user_signing.h"

#include "agent_q_bip39.h"
#include "agent_q_sign_transaction_limits.h"

#include <string.h>

namespace agent_q {
namespace {

AgentQSignTransactionUserSigningHandoffReport make_report(
    AgentQSignTransactionUserSigningHandoffResult result,
    AgentQSignTransactionUserTransitionResult flow_result,
    SuiTransactionSigningResult signing_result)
{
    return AgentQSignTransactionUserSigningHandoffReport{
        result,
        flow_result,
        signing_result,
    };
}

AgentQSignTransactionUserSigningHandoffResult map_consume_failure(
    AgentQSignTransactionUserTransitionResult result)
{
    switch (result) {
        case AgentQSignTransactionUserTransitionResult::inactive:
            return AgentQSignTransactionUserSigningHandoffResult::inactive;
        case AgentQSignTransactionUserTransitionResult::wrong_stage:
            return AgentQSignTransactionUserSigningHandoffResult::wrong_stage;
        case AgentQSignTransactionUserTransitionResult::payload_unavailable:
            return AgentQSignTransactionUserSigningHandoffResult::payload_unavailable;
        case AgentQSignTransactionUserTransitionResult::output_too_small:
            return AgentQSignTransactionUserSigningHandoffResult::output_too_small;
        case AgentQSignTransactionUserTransitionResult::ok:
        case AgentQSignTransactionUserTransitionResult::invalid_argument:
        case AgentQSignTransactionUserTransitionResult::invalid_session:
        case AgentQSignTransactionUserTransitionResult::invalid_deadline:
        case AgentQSignTransactionUserTransitionResult::deadline_expired:
        case AgentQSignTransactionUserTransitionResult::deadline_not_reached:
        case AgentQSignTransactionUserTransitionResult::session_still_active:
        case AgentQSignTransactionUserTransitionResult::history_error:
        case AgentQSignTransactionUserTransitionResult::stale_state:
        case AgentQSignTransactionUserTransitionResult::payload_not_consumed:
        case AgentQSignTransactionUserTransitionResult::busy:
            return AgentQSignTransactionUserSigningHandoffResult::terminal_error;
    }
    return AgentQSignTransactionUserSigningHandoffResult::terminal_error;
}

bool should_terminalize_signing_failure(
    AgentQSignTransactionUserTransitionResult consume_result)
{
    return consume_result == AgentQSignTransactionUserTransitionResult::payload_unavailable ||
           consume_result == AgentQSignTransactionUserTransitionResult::output_too_small;
}

}  // namespace

void sign_transaction_user_signing_output_wipe(
    AgentQSignTransactionUserSigningOutput* output)
{
    if (output == nullptr) {
        return;
    }
    wipe_sensitive_buffer(output->signature, sizeof(output->signature));
    output->signature_size = 0;
}

AgentQSignTransactionUserSigningHandoffReport
sign_transaction_user_signing_execute_critical_section(
    AgentQSignTransactionUserSigningOutput* output)
{
    if (output == nullptr) {
        return make_report(
            AgentQSignTransactionUserSigningHandoffResult::invalid_output,
            AgentQSignTransactionUserTransitionResult::invalid_argument,
            SuiTransactionSigningResult::invalid_input);
    }
    sign_transaction_user_signing_output_wipe(output);

    uint8_t payload[kAgentQSuiSignTransactionTxBytesMaxBytes] = {};
    uint8_t signature[kSuiEd25519SignatureBytes] = {};
    size_t payload_size = 0;

    const AgentQSignTransactionUserTransitionResult consume_result =
        sign_transaction_user_flow_consume_signable_payload(
            payload,
            sizeof(payload),
            &payload_size);
    if (consume_result != AgentQSignTransactionUserTransitionResult::ok) {
        if (should_terminalize_signing_failure(consume_result)) {
            const AgentQSignTransactionUserTransitionResult terminal_result =
                sign_transaction_user_flow_record_signing_failed();
            wipe_sensitive_buffer(payload, sizeof(payload));
            wipe_sensitive_buffer(signature, sizeof(signature));
            return make_report(
                map_consume_failure(consume_result),
                terminal_result,
                SuiTransactionSigningResult::invalid_input);
        }
        wipe_sensitive_buffer(payload, sizeof(payload));
        wipe_sensitive_buffer(signature, sizeof(signature));
        return make_report(
            map_consume_failure(consume_result),
            consume_result,
            SuiTransactionSigningResult::invalid_input);
    }

    const SuiTransactionSigningResult signing_result =
        sign_sui_ed25519_transaction_from_stored_root(
            payload,
            payload_size,
            signature);
    wipe_sensitive_buffer(payload, sizeof(payload));

    if (signing_result != SuiTransactionSigningResult::ok) {
        wipe_sensitive_buffer(signature, sizeof(signature));
        const AgentQSignTransactionUserTransitionResult terminal_result =
            sign_transaction_user_flow_record_signing_failed();
        return make_report(
            AgentQSignTransactionUserSigningHandoffResult::signing_failed,
            terminal_result,
            signing_result);
    }

    const AgentQSignTransactionUserTransitionResult terminal_result =
        sign_transaction_user_flow_complete_signed();
    if (terminal_result != AgentQSignTransactionUserTransitionResult::ok) {
        wipe_sensitive_buffer(signature, sizeof(signature));
        return make_report(
            AgentQSignTransactionUserSigningHandoffResult::terminal_error,
            terminal_result,
            signing_result);
    }
    memcpy(output->signature, signature, sizeof(output->signature));
    output->signature_size = sizeof(output->signature);
    wipe_sensitive_buffer(signature, sizeof(signature));
    return make_report(
        AgentQSignTransactionUserSigningHandoffResult::ok,
        terminal_result,
        signing_result);
}

const char* sign_transaction_user_signing_handoff_result_name(
    AgentQSignTransactionUserSigningHandoffResult result)
{
    switch (result) {
        case AgentQSignTransactionUserSigningHandoffResult::ok:
            return "ok";
        case AgentQSignTransactionUserSigningHandoffResult::inactive:
            return "inactive";
        case AgentQSignTransactionUserSigningHandoffResult::wrong_stage:
            return "wrong_stage";
        case AgentQSignTransactionUserSigningHandoffResult::invalid_output:
            return "invalid_output";
        case AgentQSignTransactionUserSigningHandoffResult::payload_unavailable:
            return "payload_unavailable";
        case AgentQSignTransactionUserSigningHandoffResult::output_too_small:
            return "output_too_small";
        case AgentQSignTransactionUserSigningHandoffResult::signing_failed:
            return "signing_failed";
        case AgentQSignTransactionUserSigningHandoffResult::terminal_error:
            return "terminal_error";
    }
    return "unknown";
}

}  // namespace agent_q
