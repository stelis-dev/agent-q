#pragma once

#include <stddef.h>
#include <stdint.h>

#include <ArduinoJson.h>

#include "protocol/usb_active_session_request_guard.h"
#include "protocol/usb_operation_response_writer.h"
#include "sui/zklogin_credential_outcome.h"
#include "sui/zklogin_proof_record.h"
#include "transport/timeout_window.h"

namespace signing {

constexpr size_t kSuiZkLoginCredentialPublicKeyBase64MaxChars =
    ((kSuiZkLoginPublicKeyMaxBytes + 2) / 3) * 4 + 1;

enum class UsbSuiZkLoginCredentialPrepareResult {
    ok,
    invalid_state,
    invalid_session,
    internal_output_error,
};

enum class UsbSuiZkLoginCredentialProposalBeginResult {
    ok,
    invalid_state,
    invalid_proof,
    internal_output_error,
};

struct UsbSuiZkLoginCredentialPreparation {
    char address[kSuiAddressStringBufferSize];
    uint8_t public_key[kSuiZkLoginPublicKeyMaxBytes];
    size_t public_key_size;
    char public_key_base64[kSuiZkLoginCredentialPublicKeyBase64MaxChars];
};

struct UsbSuiZkLoginCredentialHandlerOps {
    bool (*write_credential_prepare_admission_error)(
        const char* id,
        const UsbOperationResponseWriter& writer);
    bool (*write_credential_propose_admission_error)(
        const char* id,
        const UsbOperationResponseWriter& writer);
    bool (*write_credential_prepare_state_error)(
        const char* id,
        const UsbOperationResponseWriter& writer);
    bool (*write_credential_propose_state_error)(
        const char* id,
        const UsbOperationResponseWriter& writer);
    UsbActiveSessionRequestGuardOps prepare_guard;
    UsbActiveSessionRequestGuardOps propose_guard;
    UsbSessionIdMode prepare_session_id_mode;
    UsbSessionIdMode propose_session_id_mode;
    UsbSuiZkLoginCredentialPrepareResult (*prepare_credential)(
        const char* session_id,
        UsbSuiZkLoginCredentialPreparation* output);
    TimeoutTick (*current_tick)();
    TimeoutWindow (*make_proposal_window)(TimeoutTick now);
    UsbSuiZkLoginCredentialProposalBeginResult (*begin_proposal)(
        JsonVariantConst params,
        const char* request_id,
        const char* session_id,
        TimeoutTick now,
        TimeoutWindow request_window);
    void (*on_proposal_begin_failure)();
    bool (*show_proposal_review)(const char* request_id);
};

void handle_usb_credential_prepare_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbSuiZkLoginCredentialHandlerOps& ops);

void handle_usb_credential_propose_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbSuiZkLoginCredentialHandlerOps& ops);

bool write_usb_credential_proposal_outcome_response(
    const char* id,
    const UsbOperationResponseWriter& writer,
    SuiZkLoginProposalTerminalResult terminal_result,
    bool session_ended);

}  // namespace signing
