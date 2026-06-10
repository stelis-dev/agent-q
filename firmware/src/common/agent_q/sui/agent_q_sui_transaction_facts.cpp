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
constexpr uint32_t kMaxTypeArguments = kSuiPolicyFactMaxTypeArguments;
constexpr uint32_t kMaxMoveCallArguments = kSuiPolicyFactMaxCommandArguments;
constexpr uint32_t kMaxCommandArguments = kSuiPolicyFactMaxCommandArguments;
constexpr uint32_t kMaxMoveIdentifierBytes = 64;
constexpr uint32_t kMaxModuleBytes = 4096;
constexpr uint32_t kMaxPublishModules = 4;
constexpr uint32_t kMaxPublishDependencies = 16;
constexpr uint32_t kMaxTypeTagDepth = 8;
constexpr const char* kSuiAsset = "0x2::sui::SUI";

struct ParsedCommandShape {
    SuiCommandFactKind kind;
    SuiArgumentFact first;
    SuiArgumentFact second;
    uint16_t argument_count;
};

SuiTransactionFactsResult result_from_reader(const SuiBcsReader& reader)
{
    if (reader.error() == SuiBcsReaderError::length_out_of_bounds) {
        return SuiTransactionFactsResult::too_large;
    }
    return SuiTransactionFactsResult::malformed;
}

SuiTransactionFactsResult result_from_shape_reader(const SuiBcsReader& reader)
{
    if (reader.ok()) {
        return SuiTransactionFactsResult::unsupported_shape;
    }
    return result_from_reader(reader);
}

bool read_variant(SuiBcsReader& reader, uint32_t* out)
{
    return reader.read_uleb128_u32(out);
}

bool format_hex_bytes(const uint8_t* bytes, size_t len, char* out, size_t out_size)
{
    static constexpr char kHex[] = "0123456789abcdef";
    if (bytes == nullptr || out == nullptr || out_size < (len * 2) + 1) {
        return false;
    }
    for (size_t index = 0; index < len; ++index) {
        out[index * 2] = kHex[(bytes[index] >> 4) & 0x0F];
        out[(index * 2) + 1] = kHex[bytes[index] & 0x0F];
    }
    out[len * 2] = '\0';
    return true;
}

bool format_address(const uint8_t* bytes, char* out, size_t out_size)
{
    static constexpr char kHex[] = "0123456789abcdef";
    if (bytes == nullptr || out == nullptr || out_size < kSuiAddressStringBufferSize) {
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

bool read_address(SuiBcsReader& reader, char* out, size_t out_size)
{
    uint8_t bytes[kAddressBytes] = {};
    return reader.read_fixed_bytes(bytes, sizeof(bytes)) &&
           format_address(bytes, out, out_size);
}

bool read_object_digest(SuiBcsReader& reader, char* out, size_t out_size)
{
    uint32_t digest_len = 0;
    uint8_t digest[kDigestBytes] = {};
    if (!reader.read_vector_length(kDigestBytes, &digest_len)) {
        return false;
    }
    if (digest_len != kDigestBytes) {
        reader.set_error(SuiBcsReaderError::malformed);
        return false;
    }
    return reader.read_fixed_bytes(digest, sizeof(digest)) &&
           format_hex_bytes(digest, sizeof(digest), out, out_size);
}

bool read_object_ref(SuiBcsReader& reader, SuiObjectRefFact* out)
{
    if (out == nullptr) {
        reader.set_error(SuiBcsReaderError::malformed);
        return false;
    }
    memset(out, 0, sizeof(*out));
    uint64_t version = 0;
    return read_address(reader, out->object_id, sizeof(out->object_id)) &&
           reader.read_u64_le(&version) &&
           format_u64(version, out->version, sizeof(out->version)) &&
           read_object_digest(reader, out->digest_hex, sizeof(out->digest_hex));
}

bool read_argument(SuiBcsReader& reader, SuiArgumentFact* out)
{
    if (out == nullptr) {
        reader.set_error(SuiBcsReaderError::malformed);
        return false;
    }
    *out = {};
    uint32_t variant = 0;
    if (!read_variant(reader, &variant)) {
        return false;
    }
    switch (variant) {
        case 0:
            out->kind = SuiArgumentFactKind::gas_coin;
            return true;
        case 1:
            out->kind = SuiArgumentFactKind::input;
            return reader.read_u16_le(&out->index);
        case 2:
            out->kind = SuiArgumentFactKind::result;
            return reader.read_u16_le(&out->index);
        case 3:
            out->kind = SuiArgumentFactKind::nested_result;
            return reader.read_u16_le(&out->index) && reader.read_u16_le(&out->nested_index);
        default:
            out->kind = SuiArgumentFactKind::unsupported;
            return false;
    }
}

bool read_bounded_string(SuiBcsReader& reader, char* out, size_t out_size);
bool read_type_tag(SuiBcsReader& reader, SuiTypeTagFact* out, uint32_t depth);

bool read_struct_tag(SuiBcsReader& reader, SuiStructTypeTagFact* out, uint32_t depth)
{
    SuiStructTypeTagFact scratch = {};
    SuiStructTypeTagFact* target = out != nullptr ? out : &scratch;
    uint32_t type_param_count = 0;
    if (!read_address(reader, target->address, sizeof(target->address)) ||
        !read_bounded_string(reader, target->module, sizeof(target->module)) ||
        !read_bounded_string(reader, target->name, sizeof(target->name)) ||
        !reader.read_vector_length(kMaxTypeArguments, &type_param_count)) {
        return false;
    }
    target->type_argument_count = static_cast<uint16_t>(type_param_count);
    for (uint32_t index = 0; index < type_param_count; ++index) {
        if (!read_type_tag(reader, nullptr, depth + 1)) {
            return false;
        }
    }
    return true;
}

bool read_type_tag(SuiBcsReader& reader, SuiTypeTagFact* out, uint32_t depth)
{
    if (out != nullptr) {
        *out = {};
    }
    if (depth > kMaxTypeTagDepth) {
        reader.set_error(SuiBcsReaderError::length_out_of_bounds);
        return false;
    }
    uint32_t variant = 0;
    if (!read_variant(reader, &variant)) {
        return false;
    }
    switch (variant) {
        case 0:
            if (out != nullptr) {
                out->kind = SuiTypeTagFactKind::bool_;
            }
            return true;
        case 1:
            if (out != nullptr) {
                out->kind = SuiTypeTagFactKind::u8;
            }
            return true;
        case 2:
            if (out != nullptr) {
                out->kind = SuiTypeTagFactKind::u64;
            }
            return true;
        case 3:
            if (out != nullptr) {
                out->kind = SuiTypeTagFactKind::u128;
            }
            return true;
        case 4:
            if (out != nullptr) {
                out->kind = SuiTypeTagFactKind::address;
            }
            return true;
        case 5:
            if (out != nullptr) {
                out->kind = SuiTypeTagFactKind::signer;
            }
            return true;
        case 8:
            if (out != nullptr) {
                out->kind = SuiTypeTagFactKind::u16;
            }
            return true;
        case 9:
            if (out != nullptr) {
                out->kind = SuiTypeTagFactKind::u32;
            }
            return true;
        case 10:
            if (out != nullptr) {
                out->kind = SuiTypeTagFactKind::u256;
            }
            return true;
        case 6:  // vector
            if (out != nullptr) {
                out->kind = SuiTypeTagFactKind::vector;
            }
            return read_type_tag(reader, nullptr, depth + 1);
        case 7:  // struct
            if (out != nullptr) {
                out->kind = SuiTypeTagFactKind::struct_;
            }
            return read_struct_tag(reader, out != nullptr ? &out->struct_tag : nullptr, depth + 1);
        default:
            if (out != nullptr) {
                out->kind = SuiTypeTagFactKind::unsupported;
            }
            return false;
    }
}

bool read_bounded_string(SuiBcsReader& reader, char* out, size_t out_size)
{
    if (out == nullptr || out_size == 0) {
        reader.set_error(SuiBcsReaderError::malformed);
        return false;
    }
    memset(out, 0, out_size);
    uint32_t len = 0;
    if (!reader.read_vector_length(kMaxMoveIdentifierBytes, &len)) {
        return false;
    }
    if (len + 1 > out_size) {
        reader.set_error(SuiBcsReaderError::length_out_of_bounds);
        return false;
    }
    if (!reader.read_fixed_bytes(reinterpret_cast<uint8_t*>(out), len)) {
        return false;
    }
    out[len] = '\0';
    return len > 0;
}

bool read_call_arg(SuiBcsReader& reader, SuiCallArgFact* out)
{
    if (out == nullptr) {
        reader.set_error(SuiBcsReaderError::malformed);
        return false;
    }
    *out = {};
    uint32_t variant = 0;
    if (!read_variant(reader, &variant)) {
        return false;
    }
    switch (variant) {
        case 0: {
            out->kind = SuiCallArgFactKind::pure;
            uint32_t pure_len = 0;
            if (!reader.read_vector_length(kSuiPolicyFactMaxPureBytes, &pure_len)) {
                return false;
            }
            out->pure_length = pure_len;
            return reader.read_fixed_bytes(out->pure_bytes, pure_len);
        }
        case 1: {
            uint32_t object_variant = 0;
            if (!read_variant(reader, &object_variant)) {
                return false;
            }
            switch (object_variant) {
                case 0:
                    out->kind = SuiCallArgFactKind::object_imm_or_owned;
                    return read_object_ref(reader, &out->object_ref);
                case 1: {
                    out->kind = SuiCallArgFactKind::object_shared;
                    uint64_t initial_version = 0;
                    uint8_t mutable_flag = 0;
                    return read_address(reader, out->object_ref.object_id, sizeof(out->object_ref.object_id)) &&
                           reader.read_u64_le(&initial_version) &&
                           format_u64(initial_version, out->shared_initial_version, sizeof(out->shared_initial_version)) &&
                           reader.read_u8(&mutable_flag) &&
                           (mutable_flag <= 1) &&
                           ((out->shared_mutable = mutable_flag == 1), true);
                }
                case 2:
                    out->kind = SuiCallArgFactKind::object_receiving;
                    return read_object_ref(reader, &out->object_ref);
                default:
                    out->kind = SuiCallArgFactKind::unsupported;
                    return false;
            }
        }
        case 2: {
            out->kind = SuiCallArgFactKind::funds_withdrawal;
            uint32_t reservation_variant = 0;
            uint64_t amount = 0;
            uint32_t withdrawal_type_variant = 0;
            uint32_t withdraw_from_variant = 0;
            if (!read_variant(reader, &reservation_variant) ||
                reservation_variant != 0 ||
                !reader.read_u64_le(&amount) ||
                !read_variant(reader, &withdrawal_type_variant) ||
                withdrawal_type_variant != 0 ||
                !read_type_tag(reader, nullptr, 0) ||
                !read_variant(reader, &withdraw_from_variant) ||
                withdraw_from_variant > 1) {
                return false;
            }
            return true;
        }
        default:
            out->kind = SuiCallArgFactKind::unsupported;
            return false;
    }
}

bool read_argument_vector(
    SuiBcsReader& reader,
    uint32_t max_len,
    SuiArgumentFact* out_args,
    uint16_t* out_count)
{
    uint32_t count = 0;
    if (!reader.read_vector_length(max_len, &count)) {
        return false;
    }
    for (uint32_t index = 0; index < count; ++index) {
        SuiArgumentFact arg = {};
        if (!read_argument(reader, &arg)) {
            return false;
        }
        if (out_args != nullptr) {
            out_args[index] = arg;
        }
    }
    if (out_count != nullptr) {
        *out_count = static_cast<uint16_t>(count);
    }
    return true;
}

bool skip_module_vector(SuiBcsReader& reader)
{
    uint32_t count = 0;
    if (!reader.read_vector_length(kMaxPublishModules, &count)) {
        return false;
    }
    for (uint32_t index = 0; index < count; ++index) {
        uint32_t len = 0;
        if (!reader.read_vector_length(kMaxModuleBytes, &len) ||
            !reader.skip_bytes(len)) {
            return false;
        }
    }
    return true;
}

bool skip_dependency_vector(SuiBcsReader& reader)
{
    uint32_t count = 0;
    if (!reader.read_vector_length(kMaxPublishDependencies, &count)) {
        return false;
    }
    for (uint32_t index = 0; index < count; ++index) {
        char address[kSuiAddressStringBufferSize] = {};
        if (!read_address(reader, address, sizeof(address))) {
            return false;
        }
    }
    return true;
}

bool read_move_call(SuiBcsReader& reader, SuiMoveCallFact* out, SuiArgumentFact* out_args)
{
    if (out == nullptr) {
        reader.set_error(SuiBcsReaderError::malformed);
        return false;
    }
    memset(out, 0, sizeof(*out));
    if (!read_address(reader, out->package, sizeof(out->package)) ||
        !read_bounded_string(reader, out->module, sizeof(out->module)) ||
        !read_bounded_string(reader, out->function, sizeof(out->function))) {
        return false;
    }
    uint32_t type_arg_count = 0;
    if (!reader.read_vector_length(kMaxTypeArguments, &type_arg_count)) {
        return false;
    }
    for (uint32_t index = 0; index < type_arg_count; ++index) {
        if (!read_type_tag(reader, &out->type_arguments[index], 0)) {
            return false;
        }
    }
    uint16_t argument_count = 0;
    if (!read_argument_vector(reader, kMaxMoveCallArguments, out_args, &argument_count)) {
        return false;
    }
    out->type_argument_count = static_cast<uint16_t>(type_arg_count);
    out->argument_count = argument_count;
    return true;
}

bool read_command(SuiBcsReader& reader, SuiCommandFact* out, ParsedCommandShape* shape)
{
    if (out == nullptr || shape == nullptr) {
        reader.set_error(SuiBcsReaderError::malformed);
        return false;
    }
    *out = {};
    *shape = {};
    uint32_t variant = 0;
    if (!read_variant(reader, &variant)) {
        return false;
    }
    switch (variant) {
        case 0:
            out->kind = SuiCommandFactKind::move_call;
            shape->kind = out->kind;
            if (!read_move_call(reader, &out->move_call, out->arguments)) {
                return false;
            }
            out->argument_count = out->move_call.argument_count;
            return true;
        case 1: {
            out->kind = SuiCommandFactKind::transfer_objects;
            shape->kind = out->kind;
            uint16_t object_count = 0;
            if (!read_argument_vector(reader, kMaxCommandArguments - 1, out->arguments, &object_count) ||
                !read_argument(reader, &shape->second)) {
                return false;
            }
            if (object_count > 0) {
                shape->first = out->arguments[0];
            }
            out->arguments[object_count] = shape->second;
            out->argument_count = static_cast<uint16_t>(object_count + 1);
            shape->argument_count = out->argument_count;
            return true;
        }
        case 2: {
            out->kind = SuiCommandFactKind::split_coins;
            shape->kind = out->kind;
            uint16_t amount_count = 0;
            if (!read_argument(reader, &shape->first) ||
                !read_argument_vector(reader, kMaxCommandArguments - 1, &out->arguments[1], &amount_count)) {
                return false;
            }
            out->arguments[0] = shape->first;
            if (amount_count > 0) {
                shape->second = out->arguments[1];
            }
            out->argument_count = static_cast<uint16_t>(amount_count + 1);
            shape->argument_count = amount_count;
            return true;
        }
        case 3:
            out->kind = SuiCommandFactKind::merge_coins;
            shape->kind = out->kind;
            if (!read_argument(reader, &shape->first) ||
                !read_argument_vector(reader, kMaxCommandArguments - 1, &out->arguments[1], &out->argument_count)) {
                return false;
            }
            out->arguments[0] = shape->first;
            out->argument_count = static_cast<uint16_t>(out->argument_count + 1);
            return true;
        case 4:
            out->kind = SuiCommandFactKind::publish;
            shape->kind = out->kind;
            return skip_module_vector(reader) && skip_dependency_vector(reader);
        case 5: {
            out->kind = SuiCommandFactKind::make_move_vec;
            shape->kind = out->kind;
            uint32_t option_variant = 0;
            if (!read_variant(reader, &option_variant)) {
                return false;
            }
            if (option_variant == 1) {
                out->has_make_move_vec_type = true;
                if (!read_type_tag(reader, &out->make_move_vec_type, 0)) {
                    return false;
                }
            }
            if (option_variant > 1) {
                return false;
            }
            return read_argument_vector(reader, kMaxCommandArguments, out->arguments, &out->argument_count);
        }
        case 6:
            out->kind = SuiCommandFactKind::upgrade;
            shape->kind = out->kind;
            if (!skip_module_vector(reader) ||
                !skip_dependency_vector(reader) ||
                !read_address(reader, out->move_call.package, sizeof(out->move_call.package)) ||
                !read_argument(reader, &shape->first)) {
                return false;
            }
            out->arguments[0] = shape->first;
            out->argument_count = 1;
            return true;
        default:
            out->kind = SuiCommandFactKind::unsupported;
            return false;
    }
}

uint64_t read_u64_from_pure(const SuiCallArgFact& input)
{
    uint64_t value = 0;
    for (size_t index = 0; index < 8; ++index) {
        value |= static_cast<uint64_t>(input.pure_bytes[index]) << (index * 8);
    }
    return value;
}

bool is_input_argument(const SuiArgumentFact& arg, uint16_t* index_out)
{
    if (arg.kind != SuiArgumentFactKind::input) {
        return false;
    }
    if (index_out != nullptr) {
        *index_out = arg.index;
    }
    return true;
}

bool is_split_result_argument(const SuiArgumentFact& arg)
{
    return arg.kind == SuiArgumentFactKind::nested_result && arg.index == 0 && arg.nested_index == 0;
}

bool argument_ref_in_range(
    const SuiArgumentFact& arg,
    uint16_t input_count,
    uint16_t command_index)
{
    switch (arg.kind) {
        case SuiArgumentFactKind::gas_coin:
            return true;
        case SuiArgumentFactKind::input:
            return arg.index < input_count;
        case SuiArgumentFactKind::result:
        case SuiArgumentFactKind::nested_result:
            return arg.index < command_index;
        case SuiArgumentFactKind::unsupported:
            return false;
    }
    return false;
}

bool command_argument_refs_in_range(
    const SuiCommandFact& command,
    uint16_t input_count,
    uint16_t command_index)
{
    for (uint16_t index = 0; index < command.argument_count; ++index) {
        if (!argument_ref_in_range(command.arguments[index], input_count, command_index)) {
            return false;
        }
    }
    return true;
}

bool derive_restricted_transfer(
    const ParsedCommandShape* shapes,
    size_t shape_count,
    SuiTransactionPolicyFacts* out)
{
    if (shapes == nullptr || out == nullptr || shape_count != 2) {
        return false;
    }
    if (shapes[0].kind != SuiCommandFactKind::split_coins ||
        shapes[1].kind != SuiCommandFactKind::transfer_objects ||
        shapes[0].first.kind != SuiArgumentFactKind::gas_coin ||
        shapes[0].argument_count != 1 ||
        shapes[1].argument_count != 2 ||
        !is_split_result_argument(shapes[1].first)) {
        return false;
    }

    uint16_t amount_input_index = 0;
    uint16_t recipient_input_index = 0;
    if (!is_input_argument(shapes[0].second, &amount_input_index) ||
        !is_input_argument(shapes[1].second, &recipient_input_index) ||
        amount_input_index >= out->input_count ||
        recipient_input_index >= out->input_count) {
        return false;
    }
    const SuiCallArgFact& amount_input = out->inputs[amount_input_index];
    const SuiCallArgFact& recipient_input = out->inputs[recipient_input_index];
    if (amount_input.kind != SuiCallArgFactKind::pure ||
        amount_input.pure_length != 8 ||
        recipient_input.kind != SuiCallArgFactKind::pure ||
        recipient_input.pure_length != kAddressBytes) {
        return false;
    }

    SuiRestrictedTransferFact& transfer = out->restricted_transfer;
    memset(&transfer, 0, sizeof(transfer));
    const uint64_t amount = read_u64_from_pure(amount_input);
    if (out->sender[0] == '\0' ||
        out->gas_owner[0] == '\0' ||
        !format_address(recipient_input.pure_bytes, transfer.recipient, sizeof(transfer.recipient)) ||
        !format_u64(amount, transfer.amount, sizeof(transfer.amount))) {
        memset(&transfer, 0, sizeof(transfer));
        return false;
    }
    snprintf(transfer.sender, sizeof(transfer.sender), "%s", out->sender);
    snprintf(transfer.gas_owner, sizeof(transfer.gas_owner), "%s", out->gas_owner);
    snprintf(transfer.asset, sizeof(transfer.asset), "%s", kSuiAsset);
    snprintf(transfer.gas_budget, sizeof(transfer.gas_budget), "%s", out->gas_budget);
    snprintf(transfer.gas_price, sizeof(transfer.gas_price), "%s", out->gas_price);
    transfer.command_count = static_cast<uint16_t>(shape_count);
    out->has_restricted_transfer = true;
    return true;
}

SuiTransactionFactsResult parse_transaction_data(
    SuiBcsReader& reader,
    SuiTransactionPolicyFacts* out)
{
    uint32_t tx_variant = 0;
    if (!read_variant(reader, &tx_variant)) {
        return result_from_reader(reader);
    }
    if (tx_variant != 0) {
        return SuiTransactionFactsResult::unsupported_kind;
    }

    uint32_t kind_variant = 0;
    if (!read_variant(reader, &kind_variant)) {
        return result_from_reader(reader);
    }
    if (kind_variant != 0) {
        out->transaction_kind = SuiTransactionKindFact::unsupported;
        return SuiTransactionFactsResult::unsupported_kind;
    }
    out->transaction_kind = SuiTransactionKindFact::programmable_transaction;

    uint32_t input_count = 0;
    if (!reader.read_vector_length(kSuiPolicyFactMaxInputs, &input_count)) {
        return result_from_reader(reader);
    }
    out->input_count = static_cast<uint16_t>(input_count);
    for (uint32_t index = 0; index < input_count; ++index) {
        if (!read_call_arg(reader, &out->inputs[index])) {
            return result_from_shape_reader(reader);
        }
    }

    ParsedCommandShape shapes[kSuiPolicyFactMaxCommands] = {};
    uint32_t command_count = 0;
    if (!reader.read_vector_length(kSuiPolicyFactMaxCommands, &command_count)) {
        return result_from_reader(reader);
    }
    out->command_count = static_cast<uint16_t>(command_count);
    for (uint32_t index = 0; index < command_count; ++index) {
        if (!read_command(reader, &out->commands[index], &shapes[index])) {
            return result_from_shape_reader(reader);
        }
        if (!command_argument_refs_in_range(
                out->commands[index],
                out->input_count,
                static_cast<uint16_t>(index))) {
            return SuiTransactionFactsResult::malformed;
        }
    }

    if (!read_address(reader, out->sender, sizeof(out->sender))) {
        return result_from_reader(reader);
    }

    uint32_t gas_payment_count = 0;
    if (!reader.read_vector_length(kSuiPolicyFactMaxGasPayments, &gas_payment_count)) {
        return result_from_reader(reader);
    }
    out->gas_payment_count = static_cast<uint16_t>(gas_payment_count);
    for (uint32_t index = 0; index < gas_payment_count; ++index) {
        if (!read_object_ref(reader, &out->gas_payments[index])) {
            return result_from_reader(reader);
        }
    }

    uint64_t gas_price = 0;
    uint64_t gas_budget = 0;
    if (!read_address(reader, out->gas_owner, sizeof(out->gas_owner)) ||
        !reader.read_u64_le(&gas_price) ||
        !reader.read_u64_le(&gas_budget) ||
        !format_u64(gas_price, out->gas_price, sizeof(out->gas_price)) ||
        !format_u64(gas_budget, out->gas_budget, sizeof(out->gas_budget))) {
        return result_from_reader(reader);
    }

    uint32_t expiration_variant = 0;
    if (!read_variant(reader, &expiration_variant)) {
        return result_from_reader(reader);
    }
    switch (expiration_variant) {
        case 0:
            out->expiration_kind = SuiTransactionExpirationFact::none;
            break;
        case 1: {
            out->expiration_kind = SuiTransactionExpirationFact::epoch;
            uint64_t epoch = 0;
            if (!reader.read_u64_le(&epoch) ||
                !format_u64(epoch, out->expiration_epoch, sizeof(out->expiration_epoch))) {
                return result_from_reader(reader);
            }
            break;
        }
        case 2: {
            out->expiration_kind = SuiTransactionExpirationFact::valid_during;
            for (uint32_t option_index = 0; option_index < 4; ++option_index) {
                uint32_t option_variant = 0;
                uint64_t value = 0;
                if (!read_variant(reader, &option_variant) || option_variant > 1) {
                    return result_from_reader(reader);
                }
                if (option_variant == 1 && !reader.read_u64_le(&value)) {
                    return result_from_reader(reader);
                }
            }
            char chain_digest[kSuiPolicyFactDigestHexBufferSize] = {};
            uint32_t nonce = 0;
            if (!read_object_digest(reader, chain_digest, sizeof(chain_digest)) ||
                !reader.read_u32_le(&nonce)) {
                return result_from_reader(reader);
            }
            break;
        }
        default:
            return SuiTransactionFactsResult::unsupported_shape;
    }

    if (!reader.expect_eof()) {
        return result_from_reader(reader);
    }

    derive_restricted_transfer(shapes, command_count, out);
    return SuiTransactionFactsResult::ok;
}

bool transaction_kind_only_parse_ok(const uint8_t* tx_bytes, size_t tx_len)
{
    SuiBcsReader reader(tx_bytes, tx_len);
    uint32_t kind_variant = 0;
    if (!read_variant(reader, &kind_variant) || kind_variant != 0) {
        return false;
    }
    SuiTransactionPolicyFacts scratch = {};
    uint32_t input_count = 0;
    if (!reader.read_vector_length(kSuiPolicyFactMaxInputs, &input_count)) {
        return false;
    }
    for (uint32_t index = 0; index < input_count; ++index) {
        if (!read_call_arg(reader, &scratch.inputs[index])) {
            return false;
        }
    }
    uint32_t command_count = 0;
    ParsedCommandShape shapes[kSuiPolicyFactMaxCommands] = {};
    if (!reader.read_vector_length(kSuiPolicyFactMaxCommands, &command_count)) {
        return false;
    }
    for (uint32_t index = 0; index < command_count; ++index) {
        if (!read_command(reader, &scratch.commands[index], &shapes[index])) {
            return false;
        }
        if (!command_argument_refs_in_range(
                scratch.commands[index],
                static_cast<uint16_t>(input_count),
                static_cast<uint16_t>(index))) {
            return false;
        }
    }
    return reader.expect_eof();
}

}  // namespace

const char* sui_transaction_facts_result_name(SuiTransactionFactsResult result)
{
    switch (result) {
        case SuiTransactionFactsResult::ok:
            return "ok";
        case SuiTransactionFactsResult::malformed:
            return "malformed";
        case SuiTransactionFactsResult::transaction_kind_only:
            return "transaction_kind_only";
        case SuiTransactionFactsResult::unsupported_kind:
            return "unsupported_kind";
        case SuiTransactionFactsResult::unsupported_shape:
            return "unsupported_shape";
        case SuiTransactionFactsResult::too_large:
            return "too_large";
    }
    return "unknown";
}

SuiTransactionFactsResult parse_sui_transaction_policy_facts(
    const uint8_t* tx_bytes,
    size_t tx_len,
    SuiTransactionPolicyFacts* out)
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
    const SuiTransactionFactsResult result = parse_transaction_data(reader, out);
    if (result == SuiTransactionFactsResult::ok) {
        return result;
    }

    memset(out, 0, sizeof(*out));
    if (transaction_kind_only_parse_ok(tx_bytes, tx_len)) {
        return SuiTransactionFactsResult::transaction_kind_only;
    }
    return result;
}

}  // namespace agent_q
