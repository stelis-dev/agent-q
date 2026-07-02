#pragma once

#include <stddef.h>

namespace signing {

constexpr size_t kRequestIdSize = 80;

bool request_id_format_valid(const char* value);

}  // namespace signing
