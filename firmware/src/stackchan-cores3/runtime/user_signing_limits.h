#pragma once

#include <stddef.h>
#include <stdint.h>

#include "request_id.h"
#include "sign_personal_message_limits.h"
#include "sign_transaction_limits.h"

namespace signing {

constexpr size_t kUserSigningIdSize = kRequestIdSize;
constexpr size_t kUserSigningChainSize = 33;
constexpr size_t kUserSigningMethodSize = 65;
constexpr size_t kUserSigningNetworkSize = 9;
constexpr uint32_t kUserSigningApprovalWindowMs = 30000;
constexpr size_t kUserSigningPayloadMaxBytes =
    kSuiSignTransactionTxBytesMaxBytes > kSuiSignPersonalMessageMaxBytes
        ? kSuiSignTransactionTxBytesMaxBytes
        : kSuiSignPersonalMessageMaxBytes;

}  // namespace signing
