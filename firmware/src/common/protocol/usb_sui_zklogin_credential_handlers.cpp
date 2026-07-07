#include "protocol/usb_sui_zklogin_credential_handlers.h"

#include <string.h>

#include "protocol/json_input.h"
#include "sui/zklogin_credential_outcome.h"
#include "sui/zklogin_credential_payload.h"

extern "C" {
#include "byte_conversions.h"
}

namespace signing {
namespace {

bool parse_supported_credential_params(
    const char* id,
    JsonVariantConst params,
    const UsbOperationResponseWriter& writer,
    bool prepare_only)
{
    const bool valid = prepare_only
        ? sui_zklogin_credential_prepare_payload_shape_valid(params)
        : sui_zklogin_credential_propose_payload_shape_valid(params);
    if (!valid) {
        writer.write_error(id, "invalid_params");
        return false;
    }
    return true;
}

bool copy_bounded_c_string(char* output, size_t output_size, const char* input)
{
    if (output == nullptr || output_size == 0 || input == nullptr) {
        return false;
    }
    size_t index = 0;
    for (; index + 1 < output_size && input[index] != '\0'; ++index) {
        output[index] = input[index];
    }
    output[index] = '\0';
    return input[index] == '\0' && index > 0;
}

bool guard_credential_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    UsbOperationType operation,
    const UsbActiveSessionRequestGuardOps& guard_ops,
    UsbSessionIdMode session_id_mode,
    const char** session_id)
{
    const char* const allowed_request_fields[] = {"id", "version", "method", "sessionId", "payload"};
    return guard_usb_active_session_request(
        id,
        request,
        writer,
        operation,
        guard_ops,
        session_id_mode,
        allowed_request_fields,
        5,
        session_id);
}

const char* prepare_result_error_code(UsbSuiZkLoginCredentialPrepareResult result)
{
    switch (result) {
        case UsbSuiZkLoginCredentialPrepareResult::invalid_state:
            return "invalid_state";
        case UsbSuiZkLoginCredentialPrepareResult::invalid_session:
            return "invalid_session";
        case UsbSuiZkLoginCredentialPrepareResult::internal_output_error:
        case UsbSuiZkLoginCredentialPrepareResult::ok:
        default:
            return "internal_output_error";
    }
}

bool preparation_public_key_base64(
    const UsbSuiZkLoginCredentialPreparation& preparation,
    char output[kSuiZkLoginCredentialPublicKeyBase64MaxChars])
{
    if (output == nullptr) {
        return false;
    }
    memset(output, 0, kSuiZkLoginCredentialPublicKeyBase64MaxChars);
    if (preparation.public_key_base64[0] != '\0') {
        return copy_bounded_c_string(
            output,
            kSuiZkLoginCredentialPublicKeyBase64MaxChars,
            preparation.public_key_base64);
    }
    if (preparation.public_key_size == 0 ||
        preparation.public_key_size > sizeof(preparation.public_key)) {
        return false;
    }
    return bytes_to_base64(
               preparation.public_key,
               preparation.public_key_size,
               output,
               kSuiZkLoginCredentialPublicKeyBase64MaxChars) == 0 &&
           output[0] != '\0';
}

bool write_credential_preparation_response(
    const char* id,
    const UsbOperationResponseWriter& writer,
    const UsbSuiZkLoginCredentialPreparation& preparation)
{
    if (id == nullptr ||
        preparation.address[0] == '\0') {
        return false;
    }

    char public_key_base64[kSuiZkLoginCredentialPublicKeyBase64MaxChars] = {};
    if (!preparation_public_key_base64(preparation, public_key_base64)) {
        return false;
    }

    JsonDocument result;
    result["chain"] = "sui";
    result["credential"] = "zklogin";
    JsonObject preparation_json = result["preparation"].to<JsonObject>();
    preparation_json["publicKey"] = public_key_base64;
    preparation_json["keyScheme"] = "ed25519";
    preparation_json["address"] = preparation.address;
    return writer.write_success_result(
        id,
        "credential_prepare",
        result.as<JsonObjectConst>());
}

}  // namespace

bool write_usb_credential_proposal_outcome_response(
    const char* id,
    const UsbOperationResponseWriter& writer,
    SuiZkLoginProposalTerminalResult terminal_result,
    bool session_ended)
{
    const char* status = sui_zklogin_proposal_terminal_status(terminal_result);
    const char* reason = sui_zklogin_proposal_terminal_reason(terminal_result);
    if (id == nullptr ||
        status == nullptr ||
        status[0] == '\0' ||
        reason == nullptr ||
        reason[0] == '\0') {
        return false;
    }

    JsonDocument result;
    result["status"] = status;
    result["reasonCode"] = reason;
    result["sessionEnded"] = session_ended;
    return writer.write_success_result(
        id,
        "credential_propose",
        result.as<JsonObjectConst>());
}

namespace {

void write_proposal_begin_failure(
    const char* id,
    const UsbOperationResponseWriter& writer,
    const UsbSuiZkLoginCredentialHandlerOps& ops,
    UsbSuiZkLoginCredentialProposalBeginResult result)
{
    if (ops.on_proposal_begin_failure != nullptr) {
        ops.on_proposal_begin_failure();
    }
    if (result == UsbSuiZkLoginCredentialProposalBeginResult::invalid_state) {
        writer.write_error(id, "invalid_state");
        return;
    }
    if (result == UsbSuiZkLoginCredentialProposalBeginResult::internal_output_error) {
        writer.write_error(id, "internal_output_error");
        return;
    }
    if (!write_usb_credential_proposal_outcome_response(
            id,
            writer,
            SuiZkLoginProposalTerminalResult::invalid_proof,
            false)) {
        writer.log_write_failure("credential_propose", id);
    }
}

}  // namespace

void handle_usb_credential_prepare_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbSuiZkLoginCredentialHandlerOps& ops)
{
    if (ops.write_credential_prepare_admission_error != nullptr &&
        ops.write_credential_prepare_admission_error(id, writer)) {
        return;
    }

    const char* session_id = nullptr;
    if (!guard_credential_request(
            id,
            request,
            writer,
            UsbOperationType::credential_prepare,
            ops.prepare_guard,
            ops.prepare_session_id_mode,
            &session_id)) {
        return;
    }
    if (ops.write_credential_prepare_state_error != nullptr &&
        ops.write_credential_prepare_state_error(id, writer)) {
        return;
    }
    if (!parse_supported_credential_params(id, request["payload"], writer, true)) {
        return;
    }
    if (ops.prepare_credential == nullptr) {
        writer.write_error(id, "internal_output_error");
        return;
    }
    UsbSuiZkLoginCredentialPreparation preparation = {};
    const UsbSuiZkLoginCredentialPrepareResult prepare_result =
        ops.prepare_credential(session_id, &preparation);
    if (prepare_result != UsbSuiZkLoginCredentialPrepareResult::ok) {
        writer.write_error(id, prepare_result_error_code(prepare_result));
        return;
    }
    if (!write_credential_preparation_response(id, writer, preparation)) {
        writer.log_write_failure("credential_prepare", id);
    }
}

void handle_usb_credential_propose_request(
    const char* id,
    JsonDocument& request,
    const UsbOperationResponseWriter& writer,
    const UsbSuiZkLoginCredentialHandlerOps& ops)
{
    if (ops.write_credential_propose_admission_error != nullptr &&
        ops.write_credential_propose_admission_error(id, writer)) {
        return;
    }

    const char* session_id = nullptr;
    if (!guard_credential_request(
            id,
            request,
            writer,
            UsbOperationType::credential_propose,
            ops.propose_guard,
            ops.propose_session_id_mode,
            &session_id)) {
        return;
    }
    if (ops.write_credential_propose_state_error != nullptr &&
        ops.write_credential_propose_state_error(id, writer)) {
        return;
    }
    if (!parse_supported_credential_params(id, request["payload"], writer, false)) {
        return;
    }
    if (ops.current_tick == nullptr ||
        ops.make_proposal_window == nullptr ||
        ops.begin_proposal == nullptr ||
        ops.show_proposal_review == nullptr) {
        writer.write_error(id, "internal_output_error");
        return;
    }

    const TimeoutTick now = ops.current_tick();
    const TimeoutWindow request_window = ops.make_proposal_window(now);
    const UsbSuiZkLoginCredentialProposalBeginResult begin_result =
        ops.begin_proposal(
            request["payload"],
            id,
            session_id,
            now,
            request_window);
    if (begin_result != UsbSuiZkLoginCredentialProposalBeginResult::ok) {
        write_proposal_begin_failure(id, writer, ops, begin_result);
        return;
    }

    if (!ops.show_proposal_review(id)) {
        writer.write_error(id, "internal_output_error");
    }
}

}  // namespace signing
