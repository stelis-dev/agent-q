#include "agent_q_signature_request_signing.h"

#include "agent_q_bip39.h"
#include "agent_q_method_limits.h"

#include <string.h>

namespace agent_q {
namespace {

AgentQSignatureRequestSigningHandoffReport make_report(
    AgentQSignatureRequestSigningHandoffResult result,
    AgentQSignatureRequestTransitionResult flow_result,
    SuiTransactionSigningResult signing_result)
{
    return AgentQSignatureRequestSigningHandoffReport{
        result,
        flow_result,
        signing_result,
    };
}

AgentQSignatureRequestSigningHandoffResult map_consume_failure(
    AgentQSignatureRequestTransitionResult result)
{
    switch (result) {
        case AgentQSignatureRequestTransitionResult::inactive:
            return AgentQSignatureRequestSigningHandoffResult::inactive;
        case AgentQSignatureRequestTransitionResult::wrong_stage:
            return AgentQSignatureRequestSigningHandoffResult::wrong_stage;
        case AgentQSignatureRequestTransitionResult::payload_unavailable:
            return AgentQSignatureRequestSigningHandoffResult::payload_unavailable;
        case AgentQSignatureRequestTransitionResult::output_too_small:
            return AgentQSignatureRequestSigningHandoffResult::output_too_small;
        case AgentQSignatureRequestTransitionResult::ok:
        case AgentQSignatureRequestTransitionResult::invalid_argument:
        case AgentQSignatureRequestTransitionResult::invalid_session:
        case AgentQSignatureRequestTransitionResult::invalid_deadline:
        case AgentQSignatureRequestTransitionResult::deadline_expired:
        case AgentQSignatureRequestTransitionResult::deadline_not_reached:
        case AgentQSignatureRequestTransitionResult::session_still_active:
        case AgentQSignatureRequestTransitionResult::history_error:
        case AgentQSignatureRequestTransitionResult::stale_state:
        case AgentQSignatureRequestTransitionResult::payload_not_consumed:
        case AgentQSignatureRequestTransitionResult::busy:
            return AgentQSignatureRequestSigningHandoffResult::terminal_error;
    }
    return AgentQSignatureRequestSigningHandoffResult::terminal_error;
}

bool should_terminalize_signing_failure(
    AgentQSignatureRequestTransitionResult consume_result)
{
    return consume_result == AgentQSignatureRequestTransitionResult::payload_unavailable ||
           consume_result == AgentQSignatureRequestTransitionResult::output_too_small;
}

}  // namespace

void signature_request_signing_output_wipe(
    AgentQSignatureRequestSigningOutput* output)
{
    if (output == nullptr) {
        return;
    }
    wipe_sensitive_buffer(output->signature, sizeof(output->signature));
    output->signature_size = 0;
}

AgentQSignatureRequestSigningHandoffReport
signature_request_signing_execute_critical_section(
    AgentQSignatureRequestSigningOutput* output)
{
    if (output == nullptr) {
        return make_report(
            AgentQSignatureRequestSigningHandoffResult::invalid_output,
            AgentQSignatureRequestTransitionResult::invalid_argument,
            SuiTransactionSigningResult::invalid_input);
    }
    signature_request_signing_output_wipe(output);

    uint8_t payload[kAgentQSuiSignTransactionTxBytesMaxBytes] = {};
    uint8_t signature[kSuiEd25519SignatureBytes] = {};
    size_t payload_size = 0;

    const AgentQSignatureRequestTransitionResult consume_result =
        signature_request_flow_consume_signable_payload(
            payload,
            sizeof(payload),
            &payload_size);
    if (consume_result != AgentQSignatureRequestTransitionResult::ok) {
        if (should_terminalize_signing_failure(consume_result)) {
            const AgentQSignatureRequestTransitionResult terminal_result =
                signature_request_flow_record_signing_failed();
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
        const AgentQSignatureRequestTransitionResult terminal_result =
            signature_request_flow_record_signing_failed();
        return make_report(
            AgentQSignatureRequestSigningHandoffResult::signing_failed,
            terminal_result,
            signing_result);
    }

    const AgentQSignatureRequestTransitionResult terminal_result =
        signature_request_flow_complete_signed();
    if (terminal_result != AgentQSignatureRequestTransitionResult::ok) {
        wipe_sensitive_buffer(signature, sizeof(signature));
        return make_report(
            AgentQSignatureRequestSigningHandoffResult::terminal_error,
            terminal_result,
            signing_result);
    }
    memcpy(output->signature, signature, sizeof(output->signature));
    output->signature_size = sizeof(output->signature);
    wipe_sensitive_buffer(signature, sizeof(signature));
    return make_report(
        AgentQSignatureRequestSigningHandoffResult::ok,
        terminal_result,
        signing_result);
}

const char* signature_request_signing_handoff_result_name(
    AgentQSignatureRequestSigningHandoffResult result)
{
    switch (result) {
        case AgentQSignatureRequestSigningHandoffResult::ok:
            return "ok";
        case AgentQSignatureRequestSigningHandoffResult::inactive:
            return "inactive";
        case AgentQSignatureRequestSigningHandoffResult::wrong_stage:
            return "wrong_stage";
        case AgentQSignatureRequestSigningHandoffResult::invalid_output:
            return "invalid_output";
        case AgentQSignatureRequestSigningHandoffResult::payload_unavailable:
            return "payload_unavailable";
        case AgentQSignatureRequestSigningHandoffResult::output_too_small:
            return "output_too_small";
        case AgentQSignatureRequestSigningHandoffResult::signing_failed:
            return "signing_failed";
        case AgentQSignatureRequestSigningHandoffResult::terminal_error:
            return "terminal_error";
    }
    return "unknown";
}

}  // namespace agent_q
