#pragma once

#include <stddef.h>
#include <stdint.h>

#include "signing/user_signing_critical_section.h"

namespace signing {

UserSigningSignStatus sign_user_signing_payload_from_active_identity(
    Route route,
    const uint8_t* payload,
    size_t payload_size,
    uint8_t signature_out[kSuiSignatureEnvelopeMaxBytes],
    size_t* signature_size_out,
    void* context);

}  // namespace signing
