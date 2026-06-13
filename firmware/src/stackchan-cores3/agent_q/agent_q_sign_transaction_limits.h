#pragma once

#include <stddef.h>

namespace agent_q {

constexpr size_t kAgentQSuiSignTransactionTxBytesMaxBytes = 128 * 1024;
constexpr size_t kAgentQSuiSignTransactionTxBytesMaxBase64Size =
    ((kAgentQSuiSignTransactionTxBytesMaxBytes + 2) / 3) * 4;
constexpr size_t kAgentQSuiSignTransactionInlineTxBytesMaxBytes = 384;

}  // namespace agent_q
