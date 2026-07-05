#pragma once

#include <stddef.h>

namespace signing {

bool validate_canonical_base64_syntax(
    const char* value,
    size_t max_base64_size,
    size_t* decoded_size);

}  // namespace signing
