#include "usb_sui_zklogin_credential_outcome_writer.h"

#include <ArduinoJson.h>

#include "protocol/protocol_constants.h"
#include "sui_zklogin_proof_store.h"
#include "usb_response_writer.h"

extern "C" {
#include "byte_conversions.h"
}

namespace signing {

bool usb_sui_zklogin_credential_preparation_write(
    const char* id,
    const char* address,
    const uint8_t* scheme_prefixed_public_key,
    size_t scheme_prefixed_public_key_size)
{
    if (id == nullptr ||
        address == nullptr ||
        scheme_prefixed_public_key == nullptr ||
        scheme_prefixed_public_key_size != kSuiSchemePrefixedEd25519PublicKeyBytes) {
        return false;
    }

    char public_key_base64[((kSuiSchemePrefixedEd25519PublicKeyBytes + 2) / 3) * 4 + 1] = {};
    if (bytes_to_base64(
            scheme_prefixed_public_key,
            scheme_prefixed_public_key_size,
            public_key_base64,
            sizeof(public_key_base64)) != 0) {
        return false;
    }

    JsonDocument result;
    result["chain"] = "sui";
    result["credential"] = "zklogin";
    JsonObject preparation = result["preparation"].to<JsonObject>();
    preparation["publicKey"] = public_key_base64;
    preparation["keyScheme"] = "ed25519";
    preparation["address"] = address;
    return usb_response_write_success_result(id, "credential_prepare", result.as<JsonObjectConst>());
}

bool usb_sui_zklogin_credential_proposal_outcome_write(
    const char* id,
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
    return usb_response_write_success_result(id, "credential_propose", result.as<JsonObjectConst>());
}

}  // namespace signing
