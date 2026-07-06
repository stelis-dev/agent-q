#pragma once

#include <stddef.h>
#include <stdint.h>

#include "protocol/sign_route.h"

namespace signing {

constexpr size_t kSignRequestIdentitySize = 32;

bool sign_request_identity(
    SupportedSignRoute route,
    const char* network,
    const char* canonical_base64_payload,
    uint8_t* output,
    size_t output_size);

}  // namespace signing
