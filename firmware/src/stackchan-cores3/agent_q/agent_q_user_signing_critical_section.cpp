#include "agent_q_user_signing_critical_section.h"

#include "agent_q_bip39.h"

#include <stdlib.h>
#include <string.h>

namespace agent_q {
namespace {

AgentQUserSigningHandoffReport make_report(
    AgentQUserSigningHandoffResult result,
    AgentQUserSigningTransitionResult flow_result,
    SuiTransactionSigningResult signing_result)
{
    return AgentQUserSigningHandoffReport{
        result,
        flow_result,
        signing_result,
    };
}

AgentQUserSigningHandoffResult map_consume_failure(
    AgentQUserSigningTransitionResult result)
{
    switch (result) {
        case AgentQUserSigningTransitionResult::inactive:
            return AgentQUserSigningHandoffResult::inactive;
        case AgentQUserSigningTransitionResult::wrong_stage:
            return AgentQUserSigningHandoffResult::wrong_stage;
        case AgentQUserSigningTransitionResult::payload_unavailable:
            return AgentQUserSigningHandoffResult::payload_unavailable;
        case AgentQUserSigningTransitionResult::output_too_small:
            return AgentQUserSigningHandoffResult::output_too_small;
        case AgentQUserSigningTransitionResult::ok:
        case AgentQUserSigningTransitionResult::invalid_argument:
        case AgentQUserSigningTransitionResult::invalid_session:
        case AgentQUserSigningTransitionResult::invalid_deadline:
        case AgentQUserSigningTransitionResult::deadline_expired:
        case AgentQUserSigningTransitionResult::deadline_not_reached:
        case AgentQUserSigningTransitionResult::session_still_active:
        case AgentQUserSigningTransitionResult::history_error:
        case AgentQUserSigningTransitionResult::stale_state:
        case AgentQUserSigningTransitionResult::payload_not_consumed:
        case AgentQUserSigningTransitionResult::busy:
            return AgentQUserSigningHandoffResult::terminal_error;
    }
    return AgentQUserSigningHandoffResult::terminal_error;
}

bool should_terminalize_signing_failure(
    AgentQUserSigningTransitionResult consume_result)
{
    return consume_result == AgentQUserSigningTransitionResult::payload_unavailable ||
           consume_result == AgentQUserSigningTransitionResult::output_too_small;
}

SuiTransactionSigningResult sign_payload_for_route(
    AgentQSigningRoute route,
    const uint8_t* payload,
    size_t payload_size,
    uint8_t* signature)
{
    switch (route) {
        case AgentQSigningRoute::sui_sign_transaction:
            return sign_sui_ed25519_transaction_from_stored_root(
                payload,
                payload_size,
                signature);
        case AgentQSigningRoute::sui_sign_personal_message:
            return sign_sui_ed25519_personal_message_from_stored_root(
                payload,
                payload_size,
                signature);
        case AgentQSigningRoute::unsupported:
        default:
            return SuiTransactionSigningResult::invalid_input;
    }
}

}  // namespace

void user_signing_output_wipe(
    AgentQUserSigningOutput* output)
{
    if (output == nullptr) {
        return;
    }
    output->signing_route = AgentQSigningRoute::unsupported;
    wipe_sensitive_buffer(output->signature, sizeof(output->signature));
    output->signature_size = 0;
    wipe_sensitive_buffer(output->message_bytes, sizeof(output->message_bytes));
    output->message_bytes_size = 0;
}

AgentQUserSigningHandoffReport
user_signing_execute_critical_section(
    AgentQUserSigningOutput* output)
{
    if (output == nullptr) {
        return make_report(
            AgentQUserSigningHandoffResult::invalid_output,
            AgentQUserSigningTransitionResult::invalid_argument,
            SuiTransactionSigningResult::invalid_input);
    }
    user_signing_output_wipe(output);

    const AgentQUserSigningFlowCoreSnapshot snapshot =
        user_signing_flow_core_snapshot();
    uint8_t* payload = nullptr;
    uint8_t signature[kSuiEd25519SignatureBytes] = {};
    size_t payload_size = 0;

    const AgentQUserSigningTransitionResult consume_result =
        user_signing_flow_take_signable_payload(&payload, &payload_size);
    if (consume_result != AgentQUserSigningTransitionResult::ok) {
        if (should_terminalize_signing_failure(consume_result)) {
            const AgentQUserSigningTransitionResult terminal_result =
                user_signing_flow_record_signing_failed();
            wipe_sensitive_buffer(signature, sizeof(signature));
            return make_report(
                map_consume_failure(consume_result),
                terminal_result,
                SuiTransactionSigningResult::invalid_input);
        }
        wipe_sensitive_buffer(signature, sizeof(signature));
        return make_report(
            map_consume_failure(consume_result),
            consume_result,
            SuiTransactionSigningResult::invalid_input);
    }

    const AgentQSigningRoute route = snapshot.signing_route;
    if (route == AgentQSigningRoute::unsupported) {
        wipe_sensitive_buffer(payload, payload_size);
        free(payload);
        wipe_sensitive_buffer(signature, sizeof(signature));
        const AgentQUserSigningTransitionResult terminal_result =
            user_signing_flow_record_signing_failed();
        return make_report(
            AgentQUserSigningHandoffResult::signing_failed,
            terminal_result,
            SuiTransactionSigningResult::invalid_input);
    }

    const SuiTransactionSigningResult signing_result =
        sign_payload_for_route(route, payload, payload_size, signature);

    if (signing_result != SuiTransactionSigningResult::ok) {
        wipe_sensitive_buffer(payload, payload_size);
        free(payload);
        wipe_sensitive_buffer(signature, sizeof(signature));
        const AgentQUserSigningTransitionResult terminal_result =
            user_signing_flow_record_signing_failed();
        return make_report(
            AgentQUserSigningHandoffResult::signing_failed,
            terminal_result,
            signing_result);
    }

    const AgentQUserSigningTransitionResult terminal_result =
        user_signing_flow_complete_signed();
    if (terminal_result != AgentQUserSigningTransitionResult::ok) {
        wipe_sensitive_buffer(payload, payload_size);
        free(payload);
        wipe_sensitive_buffer(signature, sizeof(signature));
        return make_report(
            AgentQUserSigningHandoffResult::terminal_error,
            terminal_result,
            signing_result);
    }
    memcpy(output->signature, signature, sizeof(output->signature));
    output->signature_size = sizeof(output->signature);
    output->signing_route = route;
    if (route == AgentQSigningRoute::sui_sign_personal_message) {
        memcpy(output->message_bytes, payload, payload_size);
        output->message_bytes_size = payload_size;
    }
    wipe_sensitive_buffer(signature, sizeof(signature));
    wipe_sensitive_buffer(payload, payload_size);
    free(payload);
    return make_report(
        AgentQUserSigningHandoffResult::ok,
        terminal_result,
        signing_result);
}

const char* user_signing_handoff_result_name(
    AgentQUserSigningHandoffResult result)
{
    switch (result) {
        case AgentQUserSigningHandoffResult::ok:
            return "ok";
        case AgentQUserSigningHandoffResult::inactive:
            return "inactive";
        case AgentQUserSigningHandoffResult::wrong_stage:
            return "wrong_stage";
        case AgentQUserSigningHandoffResult::invalid_output:
            return "invalid_output";
        case AgentQUserSigningHandoffResult::payload_unavailable:
            return "payload_unavailable";
        case AgentQUserSigningHandoffResult::output_too_small:
            return "output_too_small";
        case AgentQUserSigningHandoffResult::signing_failed:
            return "signing_failed";
        case AgentQUserSigningHandoffResult::terminal_error:
            return "terminal_error";
    }
    return "unknown";
}

}  // namespace agent_q
