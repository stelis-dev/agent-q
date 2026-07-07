#pragma once

#include <stddef.h>
#include <stdint.h>

#include <ArduinoJson.h>

#include "protocol/usb_json_response.h"
#include "signing/policy_signing_execution_result.h"
#include "signing/user_signing_critical_section.h"
#include "signing/user_signing_flow.h"

namespace signing {

using UsbSigningWriteMethodErrorFn =
    bool (*)(const char* id, const char* method, const char* code, void* context);

struct UsbSigningOutcomeWriterOps {
    UsbJsonResponseWriteOps response_write_ops;
    UsbSigningWriteMethodErrorFn write_method_error;
    void* write_method_error_context;
};

bool usb_signing_outcome_prepare_signed_response(
    JsonDocument& response,
    const char* id,
    const char* authorization,
    Route signing_route,
    const uint8_t* signature,
    size_t signature_size,
    const uint8_t* message_bytes,
    size_t message_bytes_size);

bool usb_signing_outcome_response_fits(const JsonDocument& response);

bool usb_signing_outcome_write_user_signed(
    const char* id,
    const char* session_id,
    const char* authorization,
    const UserSigningFlowCoreSnapshot& snapshot,
    const UserSigningOutput& signing_output,
    const UsbSigningOutcomeWriterOps& ops);

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
    UserSigningTerminalResult result,
    const UsbSigningOutcomeWriterOps& ops);

bool usb_signing_outcome_write_policy_execution(
    const char* id,
    const char* session_id,
    const uint8_t* request_identity,
    const PolicySigningExecutionResult& result,
    const UsbSigningOutcomeWriterOps& ops);

}  // namespace signing
