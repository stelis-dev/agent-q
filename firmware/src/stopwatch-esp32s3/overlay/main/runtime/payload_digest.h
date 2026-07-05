#pragma once

#include <stddef.h>
#include <stdint.h>

#include "payload_transfer_state.h"

namespace stopwatch_target {

bool payload_digest_sha256(const uint8_t* data, size_t size, char out[kPayloadDigestSize]);

}  // namespace stopwatch_target
