#include "agent_q_sui_sign_transaction_adapter.h"

#include <string.h>

namespace agent_q {
namespace {

constexpr const char* kSuiAsset = "0x2::sui::SUI";
constexpr size_t kSuiAddressHexLength = 64;
constexpr size_t kSuiAddressStringLength = 2 + kSuiAddressHexLength;
constexpr uint16_t kRestrictedSuiTransferCommandCount = 2;

bool bounded_string_present(const char* value, size_t value_size)
{
    return value != nullptr &&
           value_size > 0 &&
           value[0] != '\0' &&
           memchr(value, '\0', value_size) != nullptr;
}

bool decimal_string_valid(const char* value, size_t value_size)
{
    if (!bounded_string_present(value, value_size)) {
        return false;
    }
    for (size_t index = 0; value[index] != '\0'; ++index) {
        if (value[index] < '0' || value[index] > '9') {
            return false;
        }
    }
    return true;
}

bool hex_char(char value)
{
    return (value >= '0' && value <= '9') ||
           (value >= 'a' && value <= 'f') ||
           (value >= 'A' && value <= 'F');
}

bool sui_address_valid(const char* value, size_t value_size)
{
    if (!bounded_string_present(value, value_size) ||
        strlen(value) != kSuiAddressStringLength ||
        value[0] != '0' ||
        value[1] != 'x') {
        return false;
    }
    for (size_t index = 2; value[index] != '\0'; ++index) {
        if (!hex_char(value[index])) {
            return false;
        }
    }
    return true;
}

bool supported_transfer_facts(const SuiTransferFacts& facts)
{
    return sui_address_valid(facts.sender, sizeof(facts.sender)) &&
           sui_address_valid(facts.gas_owner, sizeof(facts.gas_owner)) &&
           sui_address_valid(facts.recipient, sizeof(facts.recipient)) &&
           bounded_string_present(facts.asset, sizeof(facts.asset)) &&
           strcmp(facts.asset, kSuiAsset) == 0 &&
           decimal_string_valid(facts.amount, sizeof(facts.amount)) &&
           decimal_string_valid(facts.gas_budget, sizeof(facts.gas_budget)) &&
           decimal_string_valid(facts.gas_price, sizeof(facts.gas_price)) &&
           facts.command_count == kRestrictedSuiTransferCommandCount;
}

}  // namespace

AgentQSuiSignTransactionAdapterResult classify_sui_sign_transaction(
    const uint8_t* tx_bytes,
    size_t tx_bytes_size,
    SuiTransferFacts* out)
{
    if (tx_bytes == nullptr || tx_bytes_size == 0 || out == nullptr) {
        return AgentQSuiSignTransactionAdapterResult::invalid_argument;
    }
    *out = {};
    const SuiTransactionFactsResult parse_result =
        parse_sui_transfer_facts(tx_bytes, tx_bytes_size, out);
    if (parse_result == SuiTransactionFactsResult::malformed) {
        *out = {};
        return AgentQSuiSignTransactionAdapterResult::malformed_transaction;
    }
    if (parse_result != SuiTransactionFactsResult::ok ||
        !supported_transfer_facts(*out)) {
        *out = {};
        return AgentQSuiSignTransactionAdapterResult::unsupported_transaction;
    }
    return AgentQSuiSignTransactionAdapterResult::ok;
}

}  // namespace agent_q
