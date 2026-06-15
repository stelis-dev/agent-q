#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_sui_zklogin_proposal_flow.h"

namespace agent_q {

bool usb_sui_zklogin_credential_prepare_result_write(
    const char* id,
    const char* address,
    const uint8_t* scheme_prefixed_public_key,
    size_t scheme_prefixed_public_key_size);

bool usb_sui_zklogin_credential_propose_result_write(
    const char* id,
    AgentQSuiZkLoginProposalTerminalResult result,
    bool session_ended);

}  // namespace agent_q
