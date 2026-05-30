#pragma once

#include <stddef.h>
#include <stdint.h>

namespace agent_q {

constexpr size_t kSuiTransferAddressBufferSize = 67;
constexpr size_t kSuiTransferU64StringBufferSize = 21;
constexpr size_t kSuiTransferAssetBufferSize = 32;

enum class SuiTransactionFactsResult {
    ok,
    malformed,
    unsupported,
    too_large,
};

struct SuiTransferFacts {
    char sender[kSuiTransferAddressBufferSize];
    char recipient[kSuiTransferAddressBufferSize];
    char asset[kSuiTransferAssetBufferSize];
    char amount[kSuiTransferU64StringBufferSize];
    char gas_budget[kSuiTransferU64StringBufferSize];
    char gas_price[kSuiTransferU64StringBufferSize];
    uint16_t command_count;
};

const char* sui_transaction_facts_result_name(SuiTransactionFactsResult result);

SuiTransactionFactsResult parse_sui_transfer_facts(
    const uint8_t* tx_bytes,
    size_t tx_len,
    SuiTransferFacts* out);

}  // namespace agent_q
