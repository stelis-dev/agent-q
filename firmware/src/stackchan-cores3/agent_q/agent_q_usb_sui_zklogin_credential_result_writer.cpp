#include "agent_q_usb_sui_zklogin_credential_result_writer.h"

#include <ArduinoJson.h>

#include "agent_q_protocol_constants.h"
#include "agent_q_sui_zklogin_proof_store.h"
#include "agent_q_usb_response_writer.h"

extern "C" {
#include "byte_conversions.h"
}

namespace agent_q {

bool usb_sui_zklogin_credential_prepare_result_write(
    const char* id,
    const char* address,
    const uint8_t* scheme_prefixed_public_key,
    size_t scheme_prefixed_public_key_size)
{
    if (id == nullptr ||
        address == nullptr ||
        scheme_prefixed_public_key == nullptr ||
        scheme_prefixed_public_key_size != kAgentQSuiSchemePrefixedEd25519PublicKeyBytes) {
        return false;
    }

    char public_key_base64[((kAgentQSuiSchemePrefixedEd25519PublicKeyBytes + 2) / 3) * 4 + 1] = {};
    if (bytes_to_base64(
            scheme_prefixed_public_key,
            scheme_prefixed_public_key_size,
            public_key_base64,
            sizeof(public_key_base64)) != 0) {
        return false;
    }

    JsonDocument response;
    response["id"] = id;
    response["version"] = kAgentQProtocolVersion;
    response["type"] = "credential_prepare_result";
    response["status"] = "prepared";
    response["chain"] = "sui";
    response["credential"] = "zklogin";
    JsonObject preparation = response["preparation"].to<JsonObject>();
    preparation["publicKey"] = public_key_base64;
    preparation["keyScheme"] = "ed25519";
    preparation["address"] = address;
    return usb_response_write_json(response);
}

bool usb_sui_zklogin_credential_propose_result_write(
    const char* id,
    AgentQSuiZkLoginProposalTerminalResult result,
    bool session_ended)
{
    const char* status = sui_zklogin_proposal_terminal_status(result);
    const char* reason = sui_zklogin_proposal_terminal_reason(result);
    if (id == nullptr ||
        status == nullptr ||
        status[0] == '\0' ||
        reason == nullptr ||
        reason[0] == '\0') {
        return false;
    }

    JsonDocument response;
    response["id"] = id;
    response["version"] = kAgentQProtocolVersion;
    response["type"] = "credential_propose_result";
    response["status"] = status;
    response["reasonCode"] = reason;
    response["sessionEnded"] = session_ended;
    return usb_response_write_json(response);
}

}  // namespace agent_q
