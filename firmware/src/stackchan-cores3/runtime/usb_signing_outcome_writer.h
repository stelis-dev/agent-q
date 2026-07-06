#pragma once

#include <stddef.h>
#include <stdint.h>

#include "policy_signing_execution.h"
#include "signing/user_signing_critical_section.h"
#include "signing/user_signing_flow.h"

namespace signing {

bool usb_signing_outcome_write_user_signed(
    const char* id,
    const char* session_id,
    const char* authorization,
    const UserSigningFlowCoreSnapshot& snapshot,
    const UserSigningOutput& signing_output);

bool usb_signing_outcome_user_signed_response_fits(
    const char* id,
    const char* authorization,
    const UserSigningFlowCoreSnapshot& snapshot,
    const UserSigningOutput& signing_output);

bool usb_signing_outcome_write_user_terminal(
    const char* id,
    const char* session_id,
    const uint8_t* request_identity,
    const char* method,
    UserSigningTerminalResult result);

bool usb_signing_outcome_write_policy_execution(
    const char* id,
    const char* session_id,
    const uint8_t* request_identity,
    const PolicySigningExecutionResult& result);

}  // namespace signing
