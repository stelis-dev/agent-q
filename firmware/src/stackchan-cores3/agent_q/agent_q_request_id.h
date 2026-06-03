#pragma once

#include <stddef.h>

namespace agent_q {

constexpr size_t kAgentQRequestIdSize = 80;

bool request_id_format_valid(const char* value);

}  // namespace agent_q
