#pragma once

#include <stddef.h>
#include <stdint.h>

#include "sui_zklogin_proposal_flow.h"

namespace signing {

bool usb_sui_zklogin_credential_preparation_write(
    const char* id,
    const char* address,
    const uint8_t* scheme_prefixed_public_key,
    size_t scheme_prefixed_public_key_size);

bool usb_sui_zklogin_credential_proposal_outcome_write(
    const char* id,
    SuiZkLoginProposalTerminalResult result,
    bool session_ended);

}  // namespace signing
