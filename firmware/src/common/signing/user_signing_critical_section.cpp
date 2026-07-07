#include "signing/user_signing_critical_section.h"

#include <stdlib.h>
#include <string.h>

namespace signing {
namespace {

UserSigningHandoffReport make_report(
    UserSigningHandoffResult result,
    UserSigningTransitionResult flow_result,
    UserSigningSignStatus signing_status)
{
    return UserSigningHandoffReport{
        result,
        flow_result,
        signing_status,
    };
}

UserSigningHandoffFinishReport make_finish_report(
    UserSigningHandoffReport handoff,
    bool terminal_written)
{
    return UserSigningHandoffFinishReport{
        handoff,
        terminal_written,
    };
}

UserSigningHandoffResult map_consume_failure(
    UserSigningTransitionResult result)
{
    switch (result) {
        case UserSigningTransitionResult::inactive:
            return UserSigningHandoffResult::inactive;
        case UserSigningTransitionResult::wrong_stage:
            return UserSigningHandoffResult::wrong_stage;
        case UserSigningTransitionResult::payload_unavailable:
            return UserSigningHandoffResult::payload_unavailable;
        case UserSigningTransitionResult::output_too_small:
            return UserSigningHandoffResult::output_too_small;
        case UserSigningTransitionResult::ok:
        case UserSigningTransitionResult::invalid_argument:
        case UserSigningTransitionResult::invalid_session:
        case UserSigningTransitionResult::invalid_deadline:
        case UserSigningTransitionResult::deadline_expired:
        case UserSigningTransitionResult::deadline_not_reached:
        case UserSigningTransitionResult::session_still_active:
        case UserSigningTransitionResult::history_error:
        case UserSigningTransitionResult::stale_state:
        case UserSigningTransitionResult::payload_not_consumed:
        case UserSigningTransitionResult::busy:
            return UserSigningHandoffResult::terminal_error;
    }
    return UserSigningHandoffResult::terminal_error;
}

bool should_terminalize_signing_failure(
    UserSigningTransitionResult consume_result)
{
    return consume_result == UserSigningTransitionResult::payload_unavailable ||
           consume_result == UserSigningTransitionResult::output_too_small;
}

void wipe_user_signing_critical_buffer(void* data, size_t size)
{
    volatile uint8_t* cursor = static_cast<volatile uint8_t*>(data);
    while (cursor != nullptr && size > 0) {
        *cursor++ = 0;
        --size;
    }
}

void wipe_and_free_user_signing_critical_buffer(uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    wipe_user_signing_critical_buffer(data, size);
    free(data);
}

}  // namespace

void user_signing_output_wipe(
    UserSigningOutput* output)
{
    if (output == nullptr) {
        return;
    }
    output->signing_route = Route::unsupported;
    wipe_user_signing_critical_buffer(output->signature, sizeof(output->signature));
    output->signature_size = 0;
    wipe_user_signing_critical_buffer(output->message_bytes, sizeof(output->message_bytes));
    output->message_bytes_size = 0;
}

UserSigningHandoffReport
user_signing_execute_critical_section(
    UserSigningOutput* output,
    UserSigningOutputReadyFn output_ready,
    void* context,
    const UserSigningCriticalSectionOps& ops)
{
    if (output == nullptr || output_ready == nullptr || ops.sign_payload == nullptr) {
        return make_report(
            UserSigningHandoffResult::invalid_output,
            UserSigningTransitionResult::invalid_argument,
            UserSigningSignStatus::invalid_input);
    }
    user_signing_output_wipe(output);

    const UserSigningFlowCoreSnapshot snapshot =
        user_signing_flow_core_snapshot();
    uint8_t* payload = nullptr;
    uint8_t* signature = static_cast<uint8_t*>(malloc(kSuiSignatureEnvelopeMaxBytes));
    if (signature == nullptr) {
        const UserSigningTransitionResult terminal_result =
            user_signing_flow_record_signing_failed();
        return make_report(
            UserSigningHandoffResult::signing_failed,
            terminal_result,
            UserSigningSignStatus::signature_output_too_small);
    }
    memset(signature, 0, kSuiSignatureEnvelopeMaxBytes);
    size_t signature_size = 0;
    size_t payload_size = 0;

    const UserSigningTransitionResult consume_result =
        user_signing_flow_take_signable_payload(&payload, &payload_size);
    if (consume_result != UserSigningTransitionResult::ok) {
        if (should_terminalize_signing_failure(consume_result)) {
            const UserSigningTransitionResult terminal_result =
                user_signing_flow_record_signing_failed();
            wipe_and_free_user_signing_critical_buffer(signature, kSuiSignatureEnvelopeMaxBytes);
            return make_report(
                map_consume_failure(consume_result),
                terminal_result,
                UserSigningSignStatus::invalid_input);
        }
        wipe_and_free_user_signing_critical_buffer(signature, kSuiSignatureEnvelopeMaxBytes);
        return make_report(
            map_consume_failure(consume_result),
            consume_result,
            UserSigningSignStatus::invalid_input);
    }

    const Route route = snapshot.signing_route;
    if (route == Route::unsupported) {
        wipe_user_signing_critical_buffer(payload, payload_size);
        free(payload);
        wipe_and_free_user_signing_critical_buffer(signature, kSuiSignatureEnvelopeMaxBytes);
        const UserSigningTransitionResult terminal_result =
            user_signing_flow_record_signing_failed();
        return make_report(
            UserSigningHandoffResult::signing_failed,
            terminal_result,
            UserSigningSignStatus::invalid_input);
    }

    const UserSigningSignStatus signing_status =
        ops.sign_payload(
            route,
            payload,
            payload_size,
            signature,
            &signature_size,
            ops.sign_payload_context);

    if (signing_status != UserSigningSignStatus::ok) {
        wipe_user_signing_critical_buffer(payload, payload_size);
        free(payload);
        wipe_and_free_user_signing_critical_buffer(signature, kSuiSignatureEnvelopeMaxBytes);
        const UserSigningTransitionResult terminal_result =
            user_signing_flow_record_signing_failed();
        return make_report(
            UserSigningHandoffResult::signing_failed,
            terminal_result,
            signing_status);
    }

    if (signature_size == 0 || signature_size > sizeof(output->signature)) {
        wipe_user_signing_critical_buffer(payload, payload_size);
        free(payload);
        wipe_and_free_user_signing_critical_buffer(signature, kSuiSignatureEnvelopeMaxBytes);
        const UserSigningTransitionResult failed_terminal_result =
            user_signing_flow_record_signing_failed();
        return make_report(
            UserSigningHandoffResult::signing_failed,
            failed_terminal_result,
            UserSigningSignStatus::signature_output_too_small);
    }

    memcpy(output->signature, signature, signature_size);
    output->signature_size = signature_size;
    output->signing_route = route;
    if (route == Route::sui_sign_personal_message) {
        memcpy(output->message_bytes, payload, payload_size);
        output->message_bytes_size = payload_size;
    }

    if (!output_ready(snapshot, *output, context)) {
        user_signing_output_wipe(output);
        wipe_user_signing_critical_buffer(payload, payload_size);
        free(payload);
        wipe_and_free_user_signing_critical_buffer(signature, kSuiSignatureEnvelopeMaxBytes);
        const UserSigningTransitionResult failed_terminal_result =
            user_signing_flow_record_signing_failed();
        return make_report(
            UserSigningHandoffResult::response_unavailable,
            failed_terminal_result,
            signing_status);
    }

    const UserSigningTransitionResult terminal_result =
        user_signing_flow_complete_signed();
    if (terminal_result != UserSigningTransitionResult::ok) {
        user_signing_output_wipe(output);
        wipe_user_signing_critical_buffer(payload, payload_size);
        free(payload);
        wipe_and_free_user_signing_critical_buffer(signature, kSuiSignatureEnvelopeMaxBytes);
        return make_report(
            UserSigningHandoffResult::terminal_error,
            terminal_result,
            signing_status);
    }
    wipe_and_free_user_signing_critical_buffer(signature, kSuiSignatureEnvelopeMaxBytes);
    wipe_user_signing_critical_buffer(payload, payload_size);
    free(payload);
    return make_report(
        UserSigningHandoffResult::ok,
        terminal_result,
        signing_status);
}

UserSigningHandoffFinishReport
user_signing_execute_critical_section_and_finish(
    UserSigningOutputReadyFn output_ready,
    void* output_ready_context,
    UserSigningTerminalFinishFn finish_terminal,
    void* finish_terminal_context,
    const UserSigningCriticalSectionOps& ops)
{
    if (output_ready == nullptr || finish_terminal == nullptr) {
        return make_finish_report(
            make_report(
                UserSigningHandoffResult::invalid_output,
                UserSigningTransitionResult::invalid_argument,
                UserSigningSignStatus::invalid_input),
            false);
    }

    UserSigningOutput* output =
        static_cast<UserSigningOutput*>(malloc(sizeof(UserSigningOutput)));
    if (output == nullptr) {
        const UserSigningTransitionResult terminal_result =
            user_signing_flow_record_signing_failed();
        const bool terminal_written =
            finish_terminal(nullptr, finish_terminal_context);
        return make_finish_report(
            make_report(
                UserSigningHandoffResult::signing_failed,
                terminal_result,
                UserSigningSignStatus::signature_output_too_small),
            terminal_written);
    }
    memset(output, 0, sizeof(*output));

    const UserSigningHandoffReport handoff =
        user_signing_execute_critical_section(
            output,
            output_ready,
            output_ready_context,
            ops);
    const bool terminal_written =
        finish_terminal(
            handoff.result == UserSigningHandoffResult::ok ? output : nullptr,
            finish_terminal_context);
    user_signing_output_wipe(output);
    free(output);
    return make_finish_report(handoff, terminal_written);
}

const char* user_signing_handoff_result_name(
    UserSigningHandoffResult result)
{
    switch (result) {
        case UserSigningHandoffResult::ok:
            return "ok";
        case UserSigningHandoffResult::inactive:
            return "inactive";
        case UserSigningHandoffResult::wrong_stage:
            return "wrong_stage";
        case UserSigningHandoffResult::invalid_output:
            return "invalid_output";
        case UserSigningHandoffResult::payload_unavailable:
            return "payload_unavailable";
        case UserSigningHandoffResult::output_too_small:
            return "output_too_small";
        case UserSigningHandoffResult::response_unavailable:
            return "response_unavailable";
        case UserSigningHandoffResult::signing_failed:
            return "signing_failed";
        case UserSigningHandoffResult::terminal_error:
            return "terminal_error";
    }
    return "unknown";
}

const char* user_signing_sign_status_name(
    UserSigningSignStatus status)
{
    switch (status) {
        case UserSigningSignStatus::ok:
            return "ok";
        case UserSigningSignStatus::invalid_input:
            return "invalid_input";
        case UserSigningSignStatus::account_unavailable:
            return "account_unavailable";
        case UserSigningSignStatus::signing_error:
            return "signing_error";
        case UserSigningSignStatus::signature_output_too_small:
            return "signature_output_too_small";
        case UserSigningSignStatus::signature_envelope_error:
            return "signature_envelope_error";
    }
    return "unknown";
}

}  // namespace signing
