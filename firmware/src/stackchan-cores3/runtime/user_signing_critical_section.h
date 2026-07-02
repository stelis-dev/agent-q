#pragma once

#include "user_signing_flow.h"
#include "sui_signing_service.h"

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
    SuiSigningStatus signing_status;
};

using UserSigningOutputReadyFn =
    bool (*)(
        const UserSigningFlowCoreSnapshot& snapshot,
        const UserSigningOutput& output,
        void* context);

void user_signing_output_wipe(
    UserSigningOutput* output);

UserSigningHandoffReport
user_signing_execute_critical_section(
    UserSigningOutput* output,
    UserSigningOutputReadyFn output_ready,
    void* context);

const char* user_signing_handoff_result_name(
    UserSigningHandoffResult result);

}  // namespace signing
