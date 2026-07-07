#pragma once

#include "signing/user_signing_flow.h"
#include "sui/zklogin_signature.h"

namespace signing {

enum class UserSigningHandoffResult {
    ok,
    inactive,
    wrong_stage,
    invalid_output,
    payload_unavailable,
    output_too_small,
    response_unavailable,
    signing_failed,
    terminal_error,
};

enum class UserSigningSignStatus {
    ok,
    invalid_input,
    account_unavailable,
    signing_error,
    signature_output_too_small,
    signature_envelope_error,
};

struct UserSigningOutput {
    Route signing_route;
    uint8_t signature[kSuiSignatureEnvelopeMaxBytes];
    size_t signature_size;
    uint8_t message_bytes[kSuiSignPersonalMessageMaxBytes];
    size_t message_bytes_size;
};

struct UserSigningHandoffReport {
    UserSigningHandoffResult result;
    UserSigningTransitionResult flow_result;
    UserSigningSignStatus signing_status;
};

struct UserSigningHandoffFinishReport {
    UserSigningHandoffReport handoff;
    bool terminal_written;
};

using UserSigningSignPayloadFn =
    UserSigningSignStatus (*)(
        Route route,
        const uint8_t* payload,
        size_t payload_size,
        uint8_t signature_out[kSuiSignatureEnvelopeMaxBytes],
        size_t* signature_size_out,
        void* context);

struct UserSigningCriticalSectionOps {
    UserSigningSignPayloadFn sign_payload;
    void* sign_payload_context;
};

using UserSigningOutputReadyFn =
    bool (*)(
        const UserSigningFlowCoreSnapshot& snapshot,
        const UserSigningOutput& output,
        void* context);

using UserSigningTerminalFinishFn =
    bool (*)(
        const UserSigningOutput* output,
        void* context);

void user_signing_output_wipe(
    UserSigningOutput* output);

UserSigningHandoffReport
user_signing_execute_critical_section(
    UserSigningOutput* output,
    UserSigningOutputReadyFn output_ready,
    void* context,
    const UserSigningCriticalSectionOps& ops);

UserSigningHandoffFinishReport
user_signing_execute_critical_section_and_finish(
    UserSigningOutputReadyFn output_ready,
    void* output_ready_context,
    UserSigningTerminalFinishFn finish_terminal,
    void* finish_terminal_context,
    const UserSigningCriticalSectionOps& ops);

const char* user_signing_handoff_result_name(
    UserSigningHandoffResult result);

const char* user_signing_sign_status_name(
    UserSigningSignStatus status);

}  // namespace signing
