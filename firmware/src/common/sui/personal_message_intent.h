#pragma once

#include <stddef.h>
#include <stdint.h>

#include "sui/signing_limits.h"

namespace signing {

bool build_sui_personal_message_intent_digest(
    const uint8_t* message,
    size_t message_size,
    uint8_t digest_out[kSuiPersonalMessageIntentDigestBytes]);

}  // namespace signing
