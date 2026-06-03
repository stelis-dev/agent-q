#pragma once

#include <stddef.h>

namespace agent_q {

bool validate_canonical_base64(
    const char* value,
    size_t max_base64_size,
    size_t max_decoded_size,
    size_t* decoded_size);

}  // namespace agent_q
