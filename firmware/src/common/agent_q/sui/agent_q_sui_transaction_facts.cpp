#include "agent_q_sui_transaction_facts.h"

#include "agent_q_u64_decimal.h"
#include "agent_q_sui_bcs_reader.h"

#include <stdio.h>
#include <string.h>

namespace agent_q {
namespace {

constexpr size_t kMaxTxBytes = 4096;
constexpr size_t kAddressBytes = 32;
constexpr size_t kDigestBytes = 32;
constexpr uint32_t kMaxInputs = 8;
constexpr uint32_t kMaxCommands = 2;
constexpr uint32_t kMaxGasPayments = 8;
constexpr uint32_t kMaxPureBytes = 64;
constexpr const char* kSuiAsset = "0x2::sui::SUI";

enum class ArgumentKind {
    gas_coin,
    input,
    result,
    nested_result,
};

struct ArgumentValue {
    ArgumentKind kind;
    uint16_t index;
    uint16_t nested_index;
};

struct PureInput {
    bool present;
    uint8_t bytes[kMaxPureBytes];
    uint32_t length;
};

SuiTransactionFactsResult result_from_reader(const SuiBcsReader& reader)
{
    if (reader.error() == SuiBcsReaderError::length_out_of_bounds) {
        return SuiTransactionFactsResult::too_large;
    }
    return SuiTransactionFactsResult::malformed;
}

SuiTransactionFactsResult result_from_argument_reader(const SuiBcsReader& reader)
{
    if (reader.ok()) {
        return SuiTransactionFactsResult::unsupported;
    }
    return result_from_reader(reader);
}

bool read_variant(SuiBcsReader& reader, uint32_t* out)
{
    return reader.read_uleb128_u32(out);
}

bool read_argument(SuiBcsReader& reader, ArgumentValue* out)
{
    if (out == nullptr) {
        reader.set_error(SuiBcsReaderError::malformed);
        return false;
    }

    uint32_t variant = 0;
    if (!read_variant(reader, &variant)) {
        return false;
    }

    out->index = 0;
    out->nested_index = 0;
    switch (variant) {
        case 0:
            out->kind = ArgumentKind::gas_coin;
            return true;
        case 1:
            out->kind = ArgumentKind::input;
            return reader.read_u16_le(&out->index);
        case 2:
            out->kind = ArgumentKind::result;
            return reader.read_u16_le(&out->index);
        case 3:
            out->kind = ArgumentKind::nested_result;
            return reader.read_u16_le(&out->index) && reader.read_u16_le(&out->nested_index);
        default:
            return false;
    }
}

bool read_address(SuiBcsReader& reader, uint8_t* out)
{
    return reader.read_fixed_bytes(out, kAddressBytes);
}

bool skip_object_digest(SuiBcsReader& reader)
{
    uint32_t digest_len = 0;
    if (!reader.read_vector_length(kDigestBytes, &digest_len)) {
        return false;
    }
    if (digest_len != kDigestBytes) {
        reader.set_error(SuiBcsReaderError::malformed);
        return false;
    }
    return reader.skip_bytes(kDigestBytes);
}

bool skip_sui_object_ref(SuiBcsReader& reader)
{
    uint8_t object_id[kAddressBytes] = {};
    uint64_t version = 0;
    return read_address(reader, object_id) && reader.read_u64_le(&version) && skip_object_digest(reader);
}

bool format_address(const uint8_t* bytes, char* out, size_t out_size)
{
    static constexpr char kHex[] = "0123456789abcdef";
    if (bytes == nullptr || out == nullptr || out_size < kSuiTransferAddressBufferSize) {
        return false;
    }
    out[0] = '0';
    out[1] = 'x';
    for (size_t index = 0; index < kAddressBytes; ++index) {
        out[2 + (index * 2)] = kHex[(bytes[index] >> 4) & 0x0F];
        out[3 + (index * 2)] = kHex[bytes[index] & 0x0F];
    }
    out[66] = '\0';
    return true;
}

bool format_u64(uint64_t value, char* out, size_t out_size)
{
    return format_u64_decimal(value, out, out_size);
}

uint64_t read_u64_from_pure(const PureInput& input)
{
    uint64_t value = 0;
    for (size_t index = 0; index < 8; ++index) {
        value |= static_cast<uint64_t>(input.bytes[index]) << (index * 8);
    }
    return value;
}

bool is_input_argument(const ArgumentValue& arg, uint16_t* index_out)
{
    if (arg.kind != ArgumentKind::input) {
        return false;
    }
    if (index_out != nullptr) {
        *index_out = arg.index;
    }
    return true;
}

bool is_split_result_argument(const ArgumentValue& arg)
{
    return arg.kind == ArgumentKind::result && arg.index == 0;
}

}  // namespace

const char* sui_transaction_facts_result_name(SuiTransactionFactsResult result)
{
    switch (result) {
        case SuiTransactionFactsResult::ok:
            return "ok";
        case SuiTransactionFactsResult::malformed:
            return "malformed";
        case SuiTransactionFactsResult::unsupported:
            return "unsupported";
        case SuiTransactionFactsResult::too_large:
            return "too_large";
    }
    return "unknown";
}

SuiTransactionFactsResult parse_sui_transfer_facts(
    const uint8_t* tx_bytes,
    size_t tx_len,
    SuiTransferFacts* out)
{
    if (out != nullptr) {
        memset(out, 0, sizeof(*out));
    }
    if (tx_bytes == nullptr || tx_len == 0 || out == nullptr) {
        return SuiTransactionFactsResult::malformed;
    }
    if (tx_len > kMaxTxBytes) {
        return SuiTransactionFactsResult::too_large;
    }

    SuiBcsReader reader(tx_bytes, tx_len);

    uint32_t tx_variant = 0;
    if (!read_variant(reader, &tx_variant)) {
        return result_from_reader(reader);
    }
    if (tx_variant != 0) {
        return SuiTransactionFactsResult::unsupported;
    }

    uint32_t kind_variant = 0;
    if (!read_variant(reader, &kind_variant)) {
        return result_from_reader(reader);
    }
    if (kind_variant != 0) {
        return SuiTransactionFactsResult::unsupported;
    }

    PureInput inputs[kMaxInputs] = {};
    uint32_t input_count = 0;
    if (!reader.read_vector_length(kMaxInputs, &input_count)) {
        return result_from_reader(reader);
    }
    for (uint32_t index = 0; index < input_count; ++index) {
        uint32_t call_arg_variant = 0;
        if (!read_variant(reader, &call_arg_variant)) {
            return result_from_reader(reader);
        }
        if (call_arg_variant != 0) {
            return SuiTransactionFactsResult::unsupported;
        }

        uint32_t pure_len = 0;
        if (!reader.read_vector_length(kMaxPureBytes, &pure_len)) {
            return result_from_reader(reader);
        }
        inputs[index].present = true;
        inputs[index].length = pure_len;
        if (!reader.read_fixed_bytes(inputs[index].bytes, pure_len)) {
            return result_from_reader(reader);
        }
    }

    uint32_t command_count = 0;
    if (!reader.read_vector_length(kMaxCommands, &command_count)) {
        return result_from_reader(reader);
    }
    if (command_count != 2) {
        return SuiTransactionFactsResult::unsupported;
    }

    uint32_t command_variant = 0;
    if (!read_variant(reader, &command_variant)) {
        return result_from_reader(reader);
    }
    if (command_variant != 2) {
        return SuiTransactionFactsResult::unsupported;
    }

    ArgumentValue split_coin = {};
    if (!read_argument(reader, &split_coin)) {
        return result_from_argument_reader(reader);
    }
    if (split_coin.kind != ArgumentKind::gas_coin) {
        return SuiTransactionFactsResult::unsupported;
    }

    uint32_t amount_count = 0;
    if (!reader.read_vector_length(1, &amount_count)) {
        return result_from_reader(reader);
    }
    if (amount_count != 1) {
        return SuiTransactionFactsResult::unsupported;
    }

    ArgumentValue amount_arg = {};
    uint16_t amount_input_index = 0;
    if (!read_argument(reader, &amount_arg)) {
        return result_from_argument_reader(reader);
    }
    if (!is_input_argument(amount_arg, &amount_input_index) || amount_input_index >= input_count ||
        !inputs[amount_input_index].present || inputs[amount_input_index].length != 8) {
        return SuiTransactionFactsResult::unsupported;
    }

    if (!read_variant(reader, &command_variant)) {
        return result_from_reader(reader);
    }
    if (command_variant != 1) {
        return SuiTransactionFactsResult::unsupported;
    }

    uint32_t object_count = 0;
    if (!reader.read_vector_length(1, &object_count)) {
        return result_from_reader(reader);
    }
    if (object_count != 1) {
        return SuiTransactionFactsResult::unsupported;
    }

    ArgumentValue transfer_object = {};
    if (!read_argument(reader, &transfer_object)) {
        return result_from_argument_reader(reader);
    }
    if (!is_split_result_argument(transfer_object)) {
        return SuiTransactionFactsResult::unsupported;
    }

    ArgumentValue recipient_arg = {};
    uint16_t recipient_input_index = 0;
    if (!read_argument(reader, &recipient_arg)) {
        return result_from_argument_reader(reader);
    }
    if (!is_input_argument(recipient_arg, &recipient_input_index) || recipient_input_index >= input_count ||
        !inputs[recipient_input_index].present || inputs[recipient_input_index].length != kAddressBytes) {
        return SuiTransactionFactsResult::unsupported;
    }

    uint8_t sender[kAddressBytes] = {};
    if (!read_address(reader, sender)) {
        return result_from_reader(reader);
    }

    uint32_t gas_payment_count = 0;
    if (!reader.read_vector_length(kMaxGasPayments, &gas_payment_count)) {
        return result_from_reader(reader);
    }
    for (uint32_t index = 0; index < gas_payment_count; ++index) {
        if (!skip_sui_object_ref(reader)) {
            return result_from_reader(reader);
        }
    }

    uint8_t gas_owner[kAddressBytes] = {};
    uint64_t gas_price = 0;
    uint64_t gas_budget = 0;
    if (!read_address(reader, gas_owner) || !reader.read_u64_le(&gas_price) || !reader.read_u64_le(&gas_budget)) {
        return result_from_reader(reader);
    }

    uint32_t expiration_variant = 0;
    if (!read_variant(reader, &expiration_variant)) {
        return result_from_reader(reader);
    }
    if (expiration_variant != 0) {
        return SuiTransactionFactsResult::unsupported;
    }

    if (!reader.expect_eof()) {
        return result_from_reader(reader);
    }

    const uint64_t amount = read_u64_from_pure(inputs[amount_input_index]);
    if (!format_address(sender, out->sender, sizeof(out->sender)) ||
        !format_address(gas_owner, out->gas_owner, sizeof(out->gas_owner)) ||
        !format_address(inputs[recipient_input_index].bytes, out->recipient, sizeof(out->recipient)) ||
        !format_u64(amount, out->amount, sizeof(out->amount)) ||
        !format_u64(gas_budget, out->gas_budget, sizeof(out->gas_budget)) ||
        !format_u64(gas_price, out->gas_price, sizeof(out->gas_price))) {
        memset(out, 0, sizeof(*out));
        return SuiTransactionFactsResult::malformed;
    }
    snprintf(out->asset, sizeof(out->asset), "%s", kSuiAsset);
    out->command_count = static_cast<uint16_t>(command_count);
    return SuiTransactionFactsResult::ok;
}

}  // namespace agent_q
