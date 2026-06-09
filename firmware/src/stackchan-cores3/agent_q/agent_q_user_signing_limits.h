#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_request_id.h"
#include "agent_q_sign_personal_message_limits.h"
#include "agent_q_sign_transaction_limits.h"

namespace agent_q {

constexpr size_t kAgentQUserSigningIdSize = kAgentQRequestIdSize;
constexpr size_t kAgentQUserSigningChainSize = 33;
constexpr size_t kAgentQUserSigningMethodSize = 65;
constexpr size_t kAgentQUserSigningNetworkSize = 9;
constexpr size_t kAgentQSignRequestBase64MaxSize = 4096;
constexpr uint32_t kAgentQUserSigningApprovalWindowMs = 30000;
constexpr size_t kAgentQUserSigningPayloadMaxBytes =
    kAgentQSuiSignTransactionTxBytesMaxBytes > kAgentQSuiSignPersonalMessageMaxBytes
        ? kAgentQSuiSignTransactionTxBytesMaxBytes
        : kAgentQSuiSignPersonalMessageMaxBytes;

}  // namespace agent_q
