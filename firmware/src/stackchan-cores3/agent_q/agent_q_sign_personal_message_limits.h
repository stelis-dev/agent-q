#pragma once

#include <stddef.h>

namespace agent_q {

constexpr size_t kAgentQSuiSignPersonalMessageMaxBytes = 768;
constexpr size_t kAgentQSuiSignPersonalMessageMaxBase64Size =
    ((kAgentQSuiSignPersonalMessageMaxBytes + 2) / 3) * 4;
constexpr size_t kAgentQSignPersonalMessagePreviewSize = 49;
constexpr size_t kAgentQSuiPersonalMessageIntentDigestBytes = 32;

}  // namespace agent_q
