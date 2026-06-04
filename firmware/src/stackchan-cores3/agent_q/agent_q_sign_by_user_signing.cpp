#include "agent_q_sign_by_user_signing.h"

#include "agent_q_bip39.h"
#include "agent_q_method_limits.h"

#include <string.h>

namespace agent_q {
namespace {

AgentQSignByUserSigningHandoffReport make_report(
    AgentQSignByUserSigningHandoffResult result,
    AgentQSignByUserTransitionResult flow_result,
    SuiTransactionSigningResult signing_result)
{
    return AgentQSignByUserSigningHandoffReport{
        result,
        flow_result,
        signing_result,
    };
}

AgentQSignByUserSigningHandoffResult map_consume_failure(
    AgentQSignByUserTransitionResult result)
{
    switch (result) {
        case AgentQSignByUserTransitionResult::inactive:
            return AgentQSignByUserSigningHandoffResult::inactive;
        case AgentQSignByUserTransitionResult::wrong_stage:
            return AgentQSignByUserSigningHandoffResult::wrong_stage;
        case AgentQSignByUserTransitionResult::payload_unavailable:
            return AgentQSignByUserSigningHandoffResult::payload_unavailable;
        case AgentQSignByUserTransitionResult::output_too_small:
            return AgentQSignByUserSigningHandoffResult::output_too_small;
        case AgentQSignByUserTransitionResult::ok:
        case AgentQSignByUserTransitionResult::invalid_argument:
        case AgentQSignByUserTransitionResult::invalid_session:
        case AgentQSignByUserTransitionResult::invalid_deadline:
        case AgentQSignByUserTransitionResult::deadline_expired:
        case AgentQSignByUserTransitionResult::deadline_not_reached:
        case AgentQSignByUserTransitionResult::session_still_active:
        case AgentQSignByUserTransitionResult::history_error:
        case AgentQSignByUserTransitionResult::stale_state:
        case AgentQSignByUserTransitionResult::payload_not_consumed:
        case AgentQSignByUserTransitionResult::busy:
            return AgentQSignByUserSigningHandoffResult::terminal_error;
    }
    return AgentQSignByUserSigningHandoffResult::terminal_error;
}

bool should_terminalize_signing_failure(
    AgentQSignByUserTransitionResult consume_result)
{
    return consume_result == AgentQSignByUserTransitionResult::payload_unavailable ||
           consume_result == AgentQSignByUserTransitionResult::output_too_small;
}

}  // namespace

void sign_by_user_signing_output_wipe(
    AgentQSignByUserSigningOutput* output)
{
    if (output == nullptr) {
        return;
    }
    wipe_sensitive_buffer(output->signature, sizeof(output->signature));
    output->signature_size = 0;
}

AgentQSignByUserSigningHandoffReport
sign_by_user_signing_execute_critical_section(
    AgentQSignByUserSigningOutput* output)
{
    if (output == nullptr) {
        return make_report(
            AgentQSignByUserSigningHandoffResult::invalid_output,
            AgentQSignByUserTransitionResult::invalid_argument,
            SuiTransactionSigningResult::invalid_input);
    }
    sign_by_user_signing_output_wipe(output);

    uint8_t payload[kAgentQSuiSignTransactionTxBytesMaxBytes] = {};
    uint8_t signature[kSuiEd25519SignatureBytes] = {};
    size_t payload_size = 0;

    const AgentQSignByUserTransitionResult consume_result =
        sign_by_user_flow_consume_signable_payload(
            payload,
            sizeof(payload),
            &payload_size);
    if (consume_result != AgentQSignByUserTransitionResult::ok) {
        if (should_terminalize_signing_failure(consume_result)) {
            const AgentQSignByUserTransitionResult terminal_result =
                sign_by_user_flow_record_signing_failed();
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
        const AgentQSignByUserTransitionResult terminal_result =
            sign_by_user_flow_record_signing_failed();
        return make_report(
            AgentQSignByUserSigningHandoffResult::signing_failed,
            terminal_result,
            signing_result);
    }

    const AgentQSignByUserTransitionResult terminal_result =
        sign_by_user_flow_complete_signed();
    if (terminal_result != AgentQSignByUserTransitionResult::ok) {
        wipe_sensitive_buffer(signature, sizeof(signature));
        return make_report(
            AgentQSignByUserSigningHandoffResult::terminal_error,
            terminal_result,
            signing_result);
    }
    memcpy(output->signature, signature, sizeof(output->signature));
    output->signature_size = sizeof(output->signature);
    wipe_sensitive_buffer(signature, sizeof(signature));
    return make_report(
        AgentQSignByUserSigningHandoffResult::ok,
        terminal_result,
        signing_result);
}

const char* sign_by_user_signing_handoff_result_name(
    AgentQSignByUserSigningHandoffResult result)
{
    switch (result) {
        case AgentQSignByUserSigningHandoffResult::ok:
            return "ok";
        case AgentQSignByUserSigningHandoffResult::inactive:
            return "inactive";
        case AgentQSignByUserSigningHandoffResult::wrong_stage:
            return "wrong_stage";
        case AgentQSignByUserSigningHandoffResult::invalid_output:
            return "invalid_output";
        case AgentQSignByUserSigningHandoffResult::payload_unavailable:
            return "payload_unavailable";
        case AgentQSignByUserSigningHandoffResult::output_too_small:
            return "output_too_small";
        case AgentQSignByUserSigningHandoffResult::signing_failed:
            return "signing_failed";
        case AgentQSignByUserSigningHandoffResult::terminal_error:
            return "terminal_error";
    }
    return "unknown";
}

}  // namespace agent_q
