#include "transaction_facts.h"

#include "numeric/u64_decimal.h"
#include "bcs_reader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

namespace signing {
namespace {

constexpr size_t kMaxTxBytes = 128 * 1024;
constexpr size_t kAddressBytes = 32;
constexpr size_t kDigestBytes = 32;
constexpr uint32_t kMaxTypeArguments = kSuiPolicyFactMaxTypeArguments;
constexpr uint32_t kMaxMoveCallArguments = kSuiPolicyFactMaxCommandArguments;
constexpr uint32_t kMaxCommandArguments = kSuiPolicyFactMaxCommandArguments;
constexpr uint32_t kMaxMoveIdentifierBytes = 64;
constexpr uint32_t kMaxModuleBytes = 4096;
constexpr uint32_t kMaxPublishModules = kSuiPolicyFactMaxPackageModules;
constexpr uint32_t kMaxPublishDependencies = kSuiPolicyFactMaxPackageDependencies;
constexpr uint32_t kMaxTypeTagDepth = 8;
constexpr uint32_t kMinimumParseMaxVectorItems = 1024;

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

bool append_canonical(char* out, size_t out_size, const char* value)
{
    if (out == nullptr || out_size == 0 || value == nullptr) {
        return false;
    }
    const size_t current = strlen(out);
    if (current >= out_size) {
        return false;
    }
    const int written = snprintf(out + current, out_size - current, "%s", value);
    return written >= 0 && static_cast<size_t>(written) < out_size - current;
}

bool set_canonical(char* out, size_t out_size, const char* value)
{
    if (out == nullptr || out_size == 0 || value == nullptr) {
        return false;
    }
    out[0] = '\0';
    return append_canonical(out, out_size, value);
}

bool set_scalar_type_tag(SuiTypeTagFact* out, SuiTypeTagFactKind kind, const char* canonical)
{
    if (out == nullptr) {
        return true;
    }
    out->kind = kind;
    return set_canonical(out->canonical, sizeof(out->canonical), canonical);
}

bool read_struct_tag(
    SuiBcsReader& reader,
    SuiStructTypeTagFact* out,
    char* canonical,
    size_t canonical_size,
    uint32_t depth)
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
    if (canonical != nullptr &&
        (!set_canonical(canonical, canonical_size, target->address) ||
         !append_canonical(canonical, canonical_size, "::") ||
         !append_canonical(canonical, canonical_size, target->module) ||
         !append_canonical(canonical, canonical_size, "::") ||
         !append_canonical(canonical, canonical_size, target->name))) {
        return false;
    }
    if (canonical != nullptr && type_param_count > 0 &&
        !append_canonical(canonical, canonical_size, "<")) {
        return false;
    }
    for (uint32_t index = 0; index < type_param_count; ++index) {
        SuiTypeTagFact type_arg = {};
        if (!read_type_tag(reader, canonical != nullptr ? &type_arg : nullptr, depth + 1)) {
            return false;
        }
        if (canonical != nullptr &&
            ((index > 0 && !append_canonical(canonical, canonical_size, ",")) ||
             !append_canonical(canonical, canonical_size, type_arg.canonical))) {
            return false;
        }
    }
    if (canonical != nullptr && type_param_count > 0 &&
        !append_canonical(canonical, canonical_size, ">")) {
        return false;
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
            return set_scalar_type_tag(out, SuiTypeTagFactKind::bool_, "bool");
        case 1:
            return set_scalar_type_tag(out, SuiTypeTagFactKind::u8, "u8");
        case 2:
            return set_scalar_type_tag(out, SuiTypeTagFactKind::u64, "u64");
        case 3:
            return set_scalar_type_tag(out, SuiTypeTagFactKind::u128, "u128");
        case 4:
            return set_scalar_type_tag(out, SuiTypeTagFactKind::address, "address");
        case 5:
            return set_scalar_type_tag(out, SuiTypeTagFactKind::signer, "signer");
        case 8:
            return set_scalar_type_tag(out, SuiTypeTagFactKind::u16, "u16");
        case 9:
            return set_scalar_type_tag(out, SuiTypeTagFactKind::u32, "u32");
        case 10:
            return set_scalar_type_tag(out, SuiTypeTagFactKind::u256, "u256");
        case 6:  // vector
            if (out != nullptr) {
                out->kind = SuiTypeTagFactKind::vector;
            }
            if (out == nullptr) {
                return read_type_tag(reader, nullptr, depth + 1);
            }
            {
                SuiTypeTagFact element = {};
                return read_type_tag(reader, &element, depth + 1) &&
                       set_canonical(out->canonical, sizeof(out->canonical), "vector<") &&
                       append_canonical(out->canonical, sizeof(out->canonical), element.canonical) &&
                       append_canonical(out->canonical, sizeof(out->canonical), ">");
            }
        case 7:  // struct
            if (out != nullptr) {
                out->kind = SuiTypeTagFactKind::struct_;
            }
            return read_struct_tag(
                reader,
                out != nullptr ? &out->struct_tag : nullptr,
                out != nullptr ? out->canonical : nullptr,
                out != nullptr ? sizeof(out->canonical) : 0,
                depth + 1);
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
                !read_type_tag(reader, &out->funds_withdrawal.type, 0) ||
                !read_variant(reader, &withdraw_from_variant) ||
                withdraw_from_variant > 1 ||
                !format_u64(amount, out->funds_withdrawal.amount, sizeof(out->funds_withdrawal.amount))) {
                return false;
            }
            out->funds_withdrawal.source =
                withdraw_from_variant == 0 ? SuiFundsWithdrawalSourceFact::sender
                                           : SuiFundsWithdrawalSourceFact::sponsor;
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

bool read_module_vector(SuiBcsReader& reader, uint16_t* out_count)
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
    if (out_count != nullptr) {
        *out_count = static_cast<uint16_t>(count);
    }
    return true;
}

bool read_dependency_vector(
    SuiBcsReader& reader,
    char (*out_dependencies)[kSuiAddressStringBufferSize],
    uint16_t* out_count)
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
        if (out_dependencies != nullptr) {
            snprintf(out_dependencies[index], kSuiAddressStringBufferSize, "%s", address);
        }
    }
    if (out_count != nullptr) {
        *out_count = static_cast<uint16_t>(count);
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

bool read_command(SuiBcsReader& reader, SuiCommandFact* out)
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
            out->kind = SuiCommandFactKind::move_call;
            if (!read_move_call(reader, &out->move_call, out->arguments)) {
                return false;
            }
            out->argument_count = out->move_call.argument_count;
            return true;
        case 1: {
            out->kind = SuiCommandFactKind::transfer_objects;
            uint16_t object_count = 0;
            SuiArgumentFact recipient = {};
            if (!read_argument_vector(reader, kMaxCommandArguments - 1, out->arguments, &object_count) ||
                !read_argument(reader, &recipient)) {
                return false;
            }
            out->arguments[object_count] = recipient;
            out->argument_count = static_cast<uint16_t>(object_count + 1);
            return true;
        }
        case 2: {
            out->kind = SuiCommandFactKind::split_coins;
            uint16_t amount_count = 0;
            if (!read_argument(reader, &out->arguments[0]) ||
                !read_argument_vector(reader, kMaxCommandArguments - 1, &out->arguments[1], &amount_count)) {
                return false;
            }
            out->argument_count = static_cast<uint16_t>(amount_count + 1);
            return true;
        }
        case 3:
            out->kind = SuiCommandFactKind::merge_coins;
            if (!read_argument(reader, &out->arguments[0]) ||
                !read_argument_vector(reader, kMaxCommandArguments - 1, &out->arguments[1], &out->argument_count)) {
                return false;
            }
            out->argument_count = static_cast<uint16_t>(out->argument_count + 1);
            return true;
        case 4:
            out->kind = SuiCommandFactKind::publish;
            return read_module_vector(reader, &out->publish.module_count) &&
                   read_dependency_vector(
                       reader,
                       out->publish.dependencies,
                       &out->publish.dependency_count);
        case 5: {
            out->kind = SuiCommandFactKind::make_move_vec;
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
            if (!read_module_vector(reader, &out->upgrade.module_count) ||
                !read_dependency_vector(
                    reader,
                    out->upgrade.dependencies,
                    &out->upgrade.dependency_count) ||
                !read_address(reader, out->upgrade.package, sizeof(out->upgrade.package)) ||
                !read_argument(reader, &out->arguments[0])) {
                return false;
            }
            out->upgrade.ticket = out->arguments[0];
            out->argument_count = 1;
            return true;
        default:
            out->kind = SuiCommandFactKind::unsupported;
            return false;
    }
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

bool skip_address(SuiBcsReader& reader)
{
    return reader.skip_bytes(kAddressBytes);
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

bool skip_object_ref(SuiBcsReader& reader)
{
    uint64_t version = 0;
    return skip_address(reader) &&
           reader.read_u64_le(&version) &&
           skip_object_digest(reader);
}

bool skip_bounded_string(SuiBcsReader& reader, uint32_t max_len)
{
    uint32_t len = 0;
    return reader.read_vector_length(max_len, &len) &&
           reader.skip_bytes(len);
}

bool skip_type_tag(SuiBcsReader& reader, uint32_t depth)
{
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
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 8:
        case 9:
        case 10:
            return true;
        case 6:
            return skip_type_tag(reader, depth + 1);
        case 7: {
            uint32_t type_arg_count = 0;
            if (!skip_address(reader) ||
                !skip_bounded_string(reader, kMaxMoveIdentifierBytes) ||
                !skip_bounded_string(reader, kMaxMoveIdentifierBytes) ||
                !reader.read_vector_length(kMinimumParseMaxVectorItems, &type_arg_count)) {
                return false;
            }
            for (uint32_t index = 0; index < type_arg_count; ++index) {
                if (!skip_type_tag(reader, depth + 1)) {
                    return false;
                }
            }
            return true;
        }
        default:
            return false;
    }
}

bool skip_argument(SuiBcsReader& reader)
{
    uint32_t variant = 0;
    if (!read_variant(reader, &variant)) {
        return false;
    }
    uint16_t ignored = 0;
    switch (variant) {
        case 0:
            return true;
        case 1:
        case 2:
            return reader.read_u16_le(&ignored);
        case 3:
            return reader.read_u16_le(&ignored) && reader.read_u16_le(&ignored);
        default:
            return false;
    }
}

bool skip_argument_vector(SuiBcsReader& reader)
{
    uint32_t count = 0;
    if (!reader.read_vector_length(kMinimumParseMaxVectorItems, &count)) {
        return false;
    }
    for (uint32_t index = 0; index < count; ++index) {
        if (!skip_argument(reader)) {
            return false;
        }
    }
    return true;
}

bool skip_call_arg(SuiBcsReader& reader)
{
    uint32_t variant = 0;
    if (!read_variant(reader, &variant)) {
        return false;
    }
    switch (variant) {
        case 0: {
            uint32_t pure_len = 0;
            return reader.read_vector_length(static_cast<uint32_t>(kMaxTxBytes), &pure_len) &&
                   reader.skip_bytes(pure_len);
        }
        case 1: {
            uint32_t object_variant = 0;
            if (!read_variant(reader, &object_variant)) {
                return false;
            }
            switch (object_variant) {
                case 0:
                case 2:
                    return skip_object_ref(reader);
                case 1: {
                    uint64_t initial_version = 0;
                    uint8_t mutable_flag = 0;
                    return skip_address(reader) &&
                           reader.read_u64_le(&initial_version) &&
                           reader.read_u8(&mutable_flag) &&
                           mutable_flag <= 1;
                }
                default:
                    return false;
            }
        }
        case 2: {
            uint32_t reservation_variant = 0;
            uint64_t amount = 0;
            uint32_t withdrawal_type_variant = 0;
            uint32_t withdraw_from_variant = 0;
            return read_variant(reader, &reservation_variant) &&
                   reservation_variant == 0 &&
                   reader.read_u64_le(&amount) &&
                   read_variant(reader, &withdrawal_type_variant) &&
                   withdrawal_type_variant == 0 &&
                   skip_type_tag(reader, 0) &&
                   read_variant(reader, &withdraw_from_variant) &&
                   withdraw_from_variant <= 1;
        }
        default:
            return false;
    }
}

bool skip_call_arg_vector(SuiBcsReader& reader)
{
    uint32_t count = 0;
    if (!reader.read_vector_length(kMinimumParseMaxVectorItems, &count)) {
        return false;
    }
    for (uint32_t index = 0; index < count; ++index) {
        if (!skip_call_arg(reader)) {
            return false;
        }
    }
    return true;
}

bool skip_module_vector(SuiBcsReader& reader)
{
    uint32_t count = 0;
    if (!reader.read_vector_length(kMinimumParseMaxVectorItems, &count)) {
        return false;
    }
    for (uint32_t index = 0; index < count; ++index) {
        uint32_t len = 0;
        if (!reader.read_vector_length(static_cast<uint32_t>(kMaxTxBytes), &len) ||
            !reader.skip_bytes(len)) {
            return false;
        }
    }
    return true;
}

bool skip_dependency_vector(SuiBcsReader& reader)
{
    uint32_t count = 0;
    if (!reader.read_vector_length(kMinimumParseMaxVectorItems, &count)) {
        return false;
    }
    for (uint32_t index = 0; index < count; ++index) {
        if (!skip_address(reader)) {
            return false;
        }
    }
    return true;
}

bool skip_move_call(SuiBcsReader& reader)
{
    if (!skip_address(reader) ||
        !skip_bounded_string(reader, kMaxMoveIdentifierBytes) ||
        !skip_bounded_string(reader, kMaxMoveIdentifierBytes)) {
        return false;
    }
    uint32_t type_arg_count = 0;
    if (!reader.read_vector_length(kMinimumParseMaxVectorItems, &type_arg_count)) {
        return false;
    }
    for (uint32_t index = 0; index < type_arg_count; ++index) {
        if (!skip_type_tag(reader, 0)) {
            return false;
        }
    }
    return skip_argument_vector(reader);
}

bool skip_command(SuiBcsReader& reader)
{
    uint32_t variant = 0;
    if (!read_variant(reader, &variant)) {
        return false;
    }
    switch (variant) {
        case 0:
            return skip_move_call(reader);
        case 1:
            return skip_argument_vector(reader) && skip_argument(reader);
        case 2:
            return skip_argument(reader) && skip_argument_vector(reader);
        case 3:
            return skip_argument(reader) && skip_argument_vector(reader);
        case 4:
            return skip_module_vector(reader) && skip_dependency_vector(reader);
        case 5: {
            uint32_t option_variant = 0;
            if (!read_variant(reader, &option_variant) || option_variant > 1) {
                return false;
            }
            return (option_variant == 0 || skip_type_tag(reader, 0)) &&
                   skip_argument_vector(reader);
        }
        case 6:
            return skip_module_vector(reader) &&
                   skip_dependency_vector(reader) &&
                   skip_address(reader) &&
                   skip_argument(reader);
        default:
            return false;
    }
}

bool skip_command_vector(SuiBcsReader& reader)
{
    uint32_t count = 0;
    if (!reader.read_vector_length(kMinimumParseMaxVectorItems, &count)) {
        return false;
    }
    for (uint32_t index = 0; index < count; ++index) {
        if (!skip_command(reader)) {
            return false;
        }
    }
    return true;
}

bool skip_gas_payment_vector(SuiBcsReader& reader)
{
    uint32_t count = 0;
    if (!reader.read_vector_length(kMinimumParseMaxVectorItems, &count)) {
        return false;
    }
    for (uint32_t index = 0; index < count; ++index) {
        if (!skip_object_ref(reader)) {
            return false;
        }
    }
    return true;
}

bool skip_expiration(SuiBcsReader& reader)
{
    uint32_t expiration_variant = 0;
    if (!read_variant(reader, &expiration_variant)) {
        return false;
    }
    switch (expiration_variant) {
        case 0:
            return true;
        case 1: {
            uint64_t epoch = 0;
            return reader.read_u64_le(&epoch);
        }
        case 2: {
            for (uint32_t option_index = 0; option_index < 4; ++option_index) {
                uint32_t option_variant = 0;
                uint64_t value = 0;
                if (!read_variant(reader, &option_variant) || option_variant > 1) {
                    return false;
                }
                if (option_variant == 1 && !reader.read_u64_le(&value)) {
                    return false;
                }
            }
            uint32_t nonce = 0;
            return skip_object_digest(reader) && reader.read_u32_le(&nonce);
        }
        default:
            return false;
    }
}

const char* command_kind_name(SuiCommandFactKind kind)
{
    switch (kind) {
        case SuiCommandFactKind::move_call:
            return "MoveCall";
        case SuiCommandFactKind::transfer_objects:
            return "TransferObjects";
        case SuiCommandFactKind::split_coins:
            return "SplitCoins";
        case SuiCommandFactKind::merge_coins:
            return "MergeCoins";
        case SuiCommandFactKind::publish:
            return "Publish";
        case SuiCommandFactKind::make_move_vec:
            return "MakeMoveVec";
        case SuiCommandFactKind::upgrade:
            return "Upgrade";
        case SuiCommandFactKind::unsupported:
            return "Unsupported";
    }
    return "Unsupported";
}

const char* expiration_kind_name(SuiTransactionExpirationFact kind)
{
    switch (kind) {
        case SuiTransactionExpirationFact::none:
            return "none";
        case SuiTransactionExpirationFact::epoch:
            return "epoch";
        case SuiTransactionExpirationFact::valid_during:
            return "valid_during";
    }
    return "unsupported";
}

const char* funds_withdrawal_source_name(SuiFundsWithdrawalSourceFact source)
{
    switch (source) {
        case SuiFundsWithdrawalSourceFact::sender:
            return "sender";
        case SuiFundsWithdrawalSourceFact::sponsor:
            return "sponsor";
        case SuiFundsWithdrawalSourceFact::unsupported:
            return "unsupported";
    }
    return "unsupported";
}

bool format_ok(int written, size_t out_size)
{
    return written >= 0 && static_cast<size_t>(written) < out_size;
}

char hex_digit(uint8_t value)
{
    return value < 10 ? static_cast<char>('0' + value)
                      : static_cast<char>('a' + (value - 10));
}

bool format_argument_ref(const SuiArgumentFact& argument, char* out, size_t out_size)
{
    if (out == nullptr || out_size == 0) {
        return false;
    }
    switch (argument.kind) {
        case SuiArgumentFactKind::gas_coin:
            return format_ok(snprintf(out, out_size, "%s", "gas"), out_size);
        case SuiArgumentFactKind::input:
            return format_ok(
                snprintf(out, out_size, "input %u", static_cast<unsigned>(argument.index)),
                out_size);
        case SuiArgumentFactKind::result:
            return format_ok(
                snprintf(out, out_size, "result %u", static_cast<unsigned>(argument.index)),
                out_size);
        case SuiArgumentFactKind::nested_result:
            return format_ok(
                snprintf(
                    out,
                    out_size,
                    "result %u.%u",
                    static_cast<unsigned>(argument.index),
                    static_cast<unsigned>(argument.nested_index)),
                out_size);
        case SuiArgumentFactKind::unsupported:
            return format_ok(snprintf(out, out_size, "%s", "unsupported"), out_size);
    }
    return false;
}

bool format_call_arg_summary(const SuiCallArgFact& input, char* out, size_t out_size)
{
    if (out == nullptr || out_size == 0) {
        return false;
    }
    switch (input.kind) {
        case SuiCallArgFactKind::pure:
            return format_ok(
                snprintf(
                    out,
                    out_size,
                    "pure %lu bytes",
                    static_cast<unsigned long>(input.pure_length)),
                out_size);
        case SuiCallArgFactKind::object_imm_or_owned:
            return format_ok(
                snprintf(out, out_size, "object %s", input.object_ref.object_id),
                out_size);
        case SuiCallArgFactKind::object_shared:
            return format_ok(
                snprintf(
                    out,
                    out_size,
                    "shared %s",
                    input.object_ref.object_id),
                out_size);
        case SuiCallArgFactKind::object_receiving:
            return format_ok(
                snprintf(out, out_size, "receiving %s", input.object_ref.object_id),
                out_size);
        case SuiCallArgFactKind::funds_withdrawal:
            return format_ok(
                snprintf(
                    out,
                    out_size,
                    "funds %s from %s",
                    input.funds_withdrawal.amount,
                    funds_withdrawal_source_name(input.funds_withdrawal.source)),
                out_size);
        case SuiCallArgFactKind::unsupported:
            return format_ok(snprintf(out, out_size, "%s", "unsupported"), out_size);
    }
    return false;
}

const SuiCallArgFact* referenced_input(
    const SuiParsedTransactionFacts& parsed,
    const SuiArgumentFact& argument)
{
    if (argument.kind != SuiArgumentFactKind::input || argument.index >= parsed.input_count) {
        return nullptr;
    }
    return &parsed.inputs[argument.index];
}

bool format_pure_u64(const SuiCallArgFact& input, char* out, size_t out_size)
{
    if (out == nullptr ||
        out_size == 0 ||
        input.kind != SuiCallArgFactKind::pure ||
        input.pure_length != 8) {
        return false;
    }
    uint64_t value = 0;
    for (uint32_t index = 0; index < 8; ++index) {
        value |= static_cast<uint64_t>(input.pure_bytes[index]) << (8 * index);
    }
    return format_ok(snprintf(out, out_size, "%llu", static_cast<unsigned long long>(value)), out_size);
}

bool format_pure_address(const SuiCallArgFact& input, char* out, size_t out_size)
{
    if (out == nullptr ||
        out_size < kSuiAddressStringBufferSize ||
        input.kind != SuiCallArgFactKind::pure ||
        input.pure_length != 32) {
        return false;
    }
    out[0] = '0';
    out[1] = 'x';
    for (uint32_t index = 0; index < 32; ++index) {
        const uint8_t byte = input.pure_bytes[index];
        out[2 + index * 2] = hex_digit(static_cast<uint8_t>(byte >> 4));
        out[2 + index * 2 + 1] = hex_digit(static_cast<uint8_t>(byte & 0x0f));
    }
    out[66] = '\0';
    return true;
}

bool copy_c_string(char* out, size_t out_size, const char* value)
{
    if (out == nullptr || out_size == 0 || value == nullptr) {
        return false;
    }
    const int written = snprintf(out, out_size, "%s", value);
    return written >= 0 && static_cast<size_t>(written) < out_size;
}

bool add_review_row(
    SuiReviewSummary* out,
    SuiReviewRowKind kind,
    const char* label,
    const char* value)
{
    if (out == nullptr || out->row_count >= kSuiReviewSummaryMaxRows) {
        return false;
    }
    SuiReviewRow& row = out->rows[out->row_count];
    row.kind = kind;
    if (!copy_c_string(row.label, sizeof(row.label), label) ||
        !copy_c_string(row.value, sizeof(row.value), value)) {
        return false;
    }
    ++out->row_count;
    return true;
}

bool add_review_row_u16(
    SuiReviewSummary* out,
    SuiReviewRowKind kind,
    const char* label,
    uint16_t value)
{
    char buffer[kSuiU64StringBufferSize] = {};
    if (snprintf(buffer, sizeof(buffer), "%u", static_cast<unsigned>(value)) <= 0) {
        return false;
    }
    return add_review_row(out, kind, label, buffer);
}

bool add_review_row_label_value(
    SuiReviewSummary* out,
    SuiReviewRowKind kind,
    const char* label_prefix,
    uint16_t index,
    const char* label_suffix,
    const char* value)
{
    char label[kSuiReviewSummaryRowLabelSize] = {};
    if (!format_ok(
            snprintf(
                label,
                sizeof(label),
                "%s%u %s",
                label_prefix,
                static_cast<unsigned>(index),
                label_suffix),
            sizeof(label))) {
        return false;
    }
    return add_review_row(out, kind, label, value);
}

const char* review_row_value(const SuiReviewSummary& summary, const char* label)
{
    if (label == nullptr) {
        return nullptr;
    }
    for (uint16_t index = 0; index < summary.row_count; ++index) {
        if (strcmp(summary.rows[index].label, label) == 0) {
            return summary.rows[index].value;
        }
    }
    return nullptr;
}

bool review_row_present(const SuiReviewSummary& summary, const char* label)
{
    const char* value = review_row_value(summary, label);
    return value != nullptr && value[0] != '\0';
}

bool review_row_label_value_present(
    const SuiReviewSummary& summary,
    const char* label_prefix,
    uint16_t index,
    const char* label_suffix)
{
    char label[kSuiReviewSummaryRowLabelSize] = {};
    return format_ok(
               snprintf(
                   label,
                   sizeof(label),
                   "%s%u %s",
                   label_prefix,
                   static_cast<unsigned>(index),
                   label_suffix),
               sizeof(label)) &&
           review_row_present(summary, label);
}

bool review_command_arg_row_present(
    const SuiReviewSummary& summary,
    uint16_t command_index,
    uint16_t arg_index)
{
    char label[kSuiReviewSummaryRowLabelSize] = {};
    return format_ok(
               snprintf(
                   label,
                   sizeof(label),
                   "Cmd%u arg%u",
                   static_cast<unsigned>(command_index),
                   static_cast<unsigned>(arg_index)),
               sizeof(label)) &&
           review_row_present(summary, label);
}

bool review_type_arg_row_present(
    const SuiReviewSummary& summary,
    uint16_t command_index,
    uint16_t type_arg_index)
{
    char label[kSuiReviewSummaryRowLabelSize] = {};
    return format_ok(
               snprintf(
                   label,
                   sizeof(label),
                   "Cmd%u type%u",
                   static_cast<unsigned>(command_index),
                   static_cast<unsigned>(type_arg_index)),
               sizeof(label)) &&
           review_row_present(summary, label);
}

bool review_split_amount_row_present(
    const SuiReviewSummary& summary,
    uint16_t command_index,
    uint16_t amount_index)
{
    char label[kSuiReviewSummaryRowLabelSize] = {};
    return format_ok(
               snprintf(
                   label,
                   sizeof(label),
                   "Cmd%u amount%u",
                   static_cast<unsigned>(command_index),
                   static_cast<unsigned>(amount_index)),
               sizeof(label)) &&
           review_row_present(summary, label);
}

bool review_pure_hex_rows_present(
    const SuiReviewSummary& summary,
    uint16_t input_index,
    uint32_t pure_length)
{
    if (pure_length == 0) {
        return true;
    }
    const size_t max_chunk_bytes = (kSuiReviewSummaryRowValueSize - 1) / 2;
    if (max_chunk_bytes == 0) {
        return false;
    }
    uint32_t remaining = pure_length;
    uint16_t chunk_index = 0;
    while (remaining > 0) {
        char label[kSuiReviewSummaryRowLabelSize] = {};
        if (!format_ok(
                snprintf(
                    label,
                    sizeof(label),
                    "Input%u hex%u",
                    static_cast<unsigned>(input_index),
                    static_cast<unsigned>(chunk_index)),
                sizeof(label)) ||
            !review_row_present(summary, label)) {
            return false;
        }
        remaining = remaining > max_chunk_bytes
                        ? static_cast<uint32_t>(remaining - max_chunk_bytes)
                        : 0;
        ++chunk_index;
    }
    return true;
}

bool add_review_gas_rows(SuiReviewSummary* out, const SuiParsedTransactionFacts& parsed)
{
    return add_review_row(out, SuiReviewRowKind::normal, "Gas max", parsed.gas_budget) &&
           add_review_row(out, SuiReviewRowKind::normal, "Gas price", parsed.gas_price);
}

bool add_object_ref_review_rows(
    SuiReviewSummary* out,
    const char* label_prefix,
    uint16_t index,
    const SuiObjectRefFact& object_ref)
{
    return add_review_row_label_value(
               out,
               SuiReviewRowKind::wrapped_value,
               label_prefix,
               index,
               "object",
               object_ref.object_id) &&
           add_review_row_label_value(
               out,
               SuiReviewRowKind::normal,
               label_prefix,
               index,
               "version",
               object_ref.version) &&
           add_review_row_label_value(
               out,
               SuiReviewRowKind::wrapped_value,
               label_prefix,
               index,
               "digest",
               object_ref.digest_hex);
}

bool add_review_gas_payment_rows(SuiReviewSummary* out, const SuiParsedTransactionFacts& parsed)
{
    if (!add_review_row_u16(
            out,
            SuiReviewRowKind::normal,
            "Gas coins",
            parsed.gas_payment_count)) {
        return false;
    }
    for (uint16_t index = 0; index < parsed.gas_payment_count; ++index) {
        if (!add_object_ref_review_rows(out, "Gas", index, parsed.gas_payments[index])) {
            return false;
        }
    }
    return true;
}

bool add_review_expiration_rows(SuiReviewSummary* out, const SuiParsedTransactionFacts& parsed)
{
    if (parsed.expiration_kind == SuiTransactionExpirationFact::epoch) {
        return add_review_row(out, SuiReviewRowKind::normal, "Expiration", "epoch") &&
               add_review_row(out, SuiReviewRowKind::normal, "Exp epoch", parsed.expiration_epoch);
    }
    if (parsed.expiration_kind == SuiTransactionExpirationFact::valid_during) {
        return add_review_row(out, SuiReviewRowKind::normal, "Expiration", "valid_during") &&
               (!parsed.valid_during.has_min_epoch ||
                add_review_row(out, SuiReviewRowKind::normal, "Min epoch", parsed.valid_during.min_epoch)) &&
               (!parsed.valid_during.has_max_epoch ||
                add_review_row(out, SuiReviewRowKind::normal, "Max epoch", parsed.valid_during.max_epoch)) &&
               (!parsed.valid_during.has_min_timestamp ||
                add_review_row(out, SuiReviewRowKind::normal, "Min time", parsed.valid_during.min_timestamp)) &&
               (!parsed.valid_during.has_max_timestamp ||
                add_review_row(out, SuiReviewRowKind::normal, "Max time", parsed.valid_during.max_timestamp)) &&
               add_review_row(
                   out,
                   SuiReviewRowKind::wrapped_value,
                   "Chain digest",
                   parsed.valid_during.chain_digest_hex) &&
               add_review_row(out, SuiReviewRowKind::normal, "Nonce", parsed.valid_during.nonce);
    }
    return add_review_row(
        out,
        SuiReviewRowKind::normal,
        "Expiration",
        expiration_kind_name(parsed.expiration_kind));
}

bool add_review_input_rows(SuiReviewSummary* out, const SuiParsedTransactionFacts& parsed)
{
    if (!add_review_row_u16(
            out,
            SuiReviewRowKind::normal,
            "Inputs",
            parsed.input_count)) {
        return false;
    }
    for (uint16_t index = 0; index < parsed.input_count; ++index) {
        char value[kSuiReviewSummaryRowValueSize] = {};
        const SuiCallArgFact& input = parsed.inputs[index];
        if (!format_call_arg_summary(input, value, sizeof(value)) ||
            !add_review_row_label_value(
                out,
                SuiReviewRowKind::wrapped_value,
                "Input",
                index,
                "kind",
                value)) {
            return false;
        }
        if (input.kind == SuiCallArgFactKind::pure) {
            if (!add_review_row_label_value(
                    out,
                    SuiReviewRowKind::warning,
                    "Input",
                    index,
                    "pure",
                    "opaque bytes")) {
                return false;
            }
            size_t offset = 0;
            uint16_t chunk_index = 0;
            while (offset < input.pure_length && offset < kSuiPolicyFactMaxPureBytes) {
                char label[kSuiReviewSummaryRowLabelSize] = {};
                char hex[kSuiReviewSummaryRowValueSize] = {};
                const size_t remaining = input.pure_length - offset;
                const size_t max_chunk_bytes = (sizeof(hex) - 1) / 2;
                const size_t chunk_bytes =
                    remaining < max_chunk_bytes ? remaining : max_chunk_bytes;
                for (size_t byte_index = 0; byte_index < chunk_bytes; ++byte_index) {
                    const uint8_t byte = input.pure_bytes[offset + byte_index];
                    hex[byte_index * 2] = hex_digit(static_cast<uint8_t>(byte >> 4));
                    hex[byte_index * 2 + 1] = hex_digit(static_cast<uint8_t>(byte & 0x0f));
                }
                if (!format_ok(
                        snprintf(
                            label,
                            sizeof(label),
                            "Input%u hex%u",
                            static_cast<unsigned>(index),
                            static_cast<unsigned>(chunk_index)),
                        sizeof(label)) ||
                    !add_review_row(out, SuiReviewRowKind::wrapped_value, label, hex)) {
                    return false;
                }
                offset += chunk_bytes;
                ++chunk_index;
            }
        } else if (input.kind == SuiCallArgFactKind::object_imm_or_owned ||
                   input.kind == SuiCallArgFactKind::object_shared ||
                   input.kind == SuiCallArgFactKind::object_receiving) {
            if (!add_review_row_label_value(
                    out,
                    SuiReviewRowKind::wrapped_value,
                    "Input",
                    index,
                    "object",
                    input.object_ref.object_id) ||
                !add_review_row_label_value(
                    out,
                    SuiReviewRowKind::normal,
                    "Input",
                    index,
                    "version",
                    input.kind == SuiCallArgFactKind::object_shared
                        ? input.shared_initial_version
                        : input.object_ref.version)) {
                return false;
            }
            if (input.kind != SuiCallArgFactKind::object_shared &&
                !add_review_row_label_value(
                    out,
                    SuiReviewRowKind::wrapped_value,
                    "Input",
                    index,
                    "digest",
                    input.object_ref.digest_hex)) {
                return false;
            }
            if (input.kind == SuiCallArgFactKind::object_shared &&
                !add_review_row_label_value(
                    out,
                    SuiReviewRowKind::normal,
                    "Input",
                    index,
                    "mutable",
                    input.shared_mutable ? "yes" : "no")) {
                return false;
            }
        } else if (input.kind == SuiCallArgFactKind::funds_withdrawal) {
            if (!add_review_row_label_value(
                    out,
                    SuiReviewRowKind::normal,
                    "Input",
                    index,
                    "amount",
                    input.funds_withdrawal.amount) ||
                !add_review_row_label_value(
                    out,
                    SuiReviewRowKind::wrapped_value,
                    "Input",
                    index,
                    "type",
                    input.funds_withdrawal.type.canonical) ||
                !add_review_row_label_value(
                    out,
                    SuiReviewRowKind::normal,
                    "Input",
                    index,
                    "source",
                    funds_withdrawal_source_name(input.funds_withdrawal.source))) {
                return false;
            }
        }
    }
    return true;
}

bool add_command_argument_rows(
    SuiReviewSummary* out,
    uint16_t command_index,
    const SuiCommandFact& command)
{
    char count[kSuiU64StringBufferSize] = {};
    if (!format_ok(
            snprintf(count, sizeof(count), "%u", static_cast<unsigned>(command.argument_count)),
            sizeof(count)) ||
        !add_review_row_label_value(
            out,
            SuiReviewRowKind::normal,
            "Cmd",
            command_index,
            "args",
            count)) {
        return false;
    }
    for (uint16_t arg_index = 0; arg_index < command.argument_count; ++arg_index) {
        char label[kSuiReviewSummaryRowLabelSize] = {};
        char value[kSuiReviewSummaryRowValueSize] = {};
        if (!format_ok(
                snprintf(
                    label,
                    sizeof(label),
                    "Cmd%u arg%u",
                    static_cast<unsigned>(command_index),
                    static_cast<unsigned>(arg_index)),
                sizeof(label)) ||
            !format_argument_ref(command.arguments[arg_index], value, sizeof(value)) ||
            !add_review_row(out, SuiReviewRowKind::normal, label, value)) {
            return false;
        }
    }
    return true;
}

bool add_move_call_detail_rows(
    SuiReviewSummary* out,
    uint16_t command_index,
    const SuiCommandFact& command)
{
    if (!add_review_row_label_value(
            out,
            SuiReviewRowKind::wrapped_value,
            "Cmd",
            command_index,
            "package",
            command.move_call.package) ||
        !add_review_row_label_value(
            out,
            SuiReviewRowKind::normal,
            "Cmd",
            command_index,
            "module",
            command.move_call.module) ||
        !add_review_row_label_value(
            out,
            SuiReviewRowKind::normal,
            "Cmd",
            command_index,
            "function",
            command.move_call.function)) {
        return false;
    }
    for (uint16_t type_index = 0;
         type_index < command.move_call.type_argument_count &&
         type_index < kSuiPolicyFactMaxTypeArguments;
         ++type_index) {
        char label[kSuiReviewSummaryRowLabelSize] = {};
        if (!format_ok(
                snprintf(
                    label,
                    sizeof(label),
                    "Cmd%u type%u",
                    static_cast<unsigned>(command_index),
                    static_cast<unsigned>(type_index)),
                sizeof(label)) ||
            !add_review_row(
                out,
                SuiReviewRowKind::wrapped_value,
                label,
                command.move_call.type_arguments[type_index].canonical)) {
            return false;
        }
    }
    return true;
}

bool add_package_dependencies_rows(
    SuiReviewSummary* out,
    uint16_t command_index,
    const char dependencies[][kSuiAddressStringBufferSize],
    uint16_t dependency_count)
{
    for (uint16_t dependency_index = 0;
         dependency_index < dependency_count &&
         dependency_index < kSuiPolicyFactMaxPackageDependencies;
         ++dependency_index) {
        char label[kSuiReviewSummaryRowLabelSize] = {};
        if (!format_ok(
                snprintf(
                    label,
                    sizeof(label),
                    "Cmd%u dep%u",
                    static_cast<unsigned>(command_index),
                    static_cast<unsigned>(dependency_index)),
                sizeof(label)) ||
            !add_review_row(
                out,
                SuiReviewRowKind::wrapped_value,
                label,
                dependencies[dependency_index])) {
            return false;
        }
    }
    return true;
}

bool format_u16_string(uint16_t value, char* output, size_t output_size)
{
    return format_ok(
        snprintf(output, output_size, "%u", static_cast<unsigned>(value)),
        output_size);
}

bool add_command_detail_rows(
    SuiReviewSummary* out,
    const SuiParsedTransactionFacts& parsed,
    uint16_t command_index,
    const SuiCommandFact& command)
{
    switch (command.kind) {
        case SuiCommandFactKind::move_call:
            return add_move_call_detail_rows(out, command_index, command) &&
                   add_command_argument_rows(out, command_index, command);
        case SuiCommandFactKind::transfer_objects: {
            if (!add_command_argument_rows(out, command_index, command)) {
                return false;
            }
            if (command.argument_count > 0) {
                const SuiCallArgFact* recipient =
                    referenced_input(parsed, command.arguments[command.argument_count - 1]);
                char address[kSuiAddressStringBufferSize] = {};
                if (recipient != nullptr &&
                    format_pure_address(*recipient, address, sizeof(address)) &&
                    !add_review_row_label_value(
                        out,
                        SuiReviewRowKind::wrapped_value,
                        "Cmd",
                        command_index,
                        "recipient",
                        address)) {
                    return false;
                }
            }
            return true;
        }
        case SuiCommandFactKind::split_coins: {
            if (!add_command_argument_rows(out, command_index, command)) {
                return false;
            }
            for (uint16_t arg_index = 1; arg_index < command.argument_count; ++arg_index) {
                const SuiCallArgFact* amount =
                    referenced_input(parsed, command.arguments[arg_index]);
                char amount_text[kSuiU64StringBufferSize] = {};
                char label[kSuiReviewSummaryRowLabelSize] = {};
                if (amount != nullptr &&
                    format_pure_u64(*amount, amount_text, sizeof(amount_text))) {
                    if (!format_ok(
                            snprintf(
                                label,
                                sizeof(label),
                                "Cmd%u amount%u",
                                static_cast<unsigned>(command_index),
                                static_cast<unsigned>(arg_index - 1)),
                            sizeof(label)) ||
                        !add_review_row(
                            out,
                            SuiReviewRowKind::normal,
                            label,
                            amount_text)) {
                        return false;
                    }
                }
            }
            return true;
        }
        case SuiCommandFactKind::merge_coins:
            return add_command_argument_rows(out, command_index, command);
        case SuiCommandFactKind::publish: {
            char module_count[kSuiU64StringBufferSize] = {};
            char dependency_count[kSuiU64StringBufferSize] = {};
            if (!format_u16_string(command.publish.module_count, module_count, sizeof(module_count)) ||
                !format_u16_string(command.publish.dependency_count, dependency_count, sizeof(dependency_count))) {
                return false;
            }
            return add_review_row_label_value(
                       out,
                       SuiReviewRowKind::normal,
                       "Cmd",
                       command_index,
                       "modules",
                       module_count) &&
                   add_review_row_label_value(
                       out,
                       SuiReviewRowKind::normal,
                       "Cmd",
                       command_index,
                       "deps",
                       dependency_count) &&
                   add_package_dependencies_rows(
                       out,
                       command_index,
                       command.publish.dependencies,
                       command.publish.dependency_count) &&
                   add_command_argument_rows(out, command_index, command);
        }
        case SuiCommandFactKind::make_move_vec:
            if (command.has_make_move_vec_type &&
                !add_review_row_label_value(
                    out,
                    SuiReviewRowKind::wrapped_value,
                    "Cmd",
                    command_index,
                    "type",
                    command.make_move_vec_type.canonical)) {
                return false;
            }
            return add_command_argument_rows(out, command_index, command);
        case SuiCommandFactKind::upgrade: {
            char module_count[kSuiU64StringBufferSize] = {};
            char dependency_count[kSuiU64StringBufferSize] = {};
            if (!format_u16_string(command.upgrade.module_count, module_count, sizeof(module_count)) ||
                !format_u16_string(command.upgrade.dependency_count, dependency_count, sizeof(dependency_count))) {
                return false;
            }
            return add_review_row_label_value(
                       out,
                       SuiReviewRowKind::wrapped_value,
                       "Cmd",
                       command_index,
                       "package",
                       command.upgrade.package) &&
                   add_review_row_label_value(
                       out,
                       SuiReviewRowKind::normal,
                       "Cmd",
                       command_index,
                       "modules",
                       module_count) &&
                   add_review_row_label_value(
                       out,
                       SuiReviewRowKind::normal,
                       "Cmd",
                       command_index,
                       "deps",
                       dependency_count) &&
                   add_package_dependencies_rows(
                       out,
                       command_index,
                       command.upgrade.dependencies,
                       command.upgrade.dependency_count) &&
                   add_command_argument_rows(out, command_index, command);
        }
        case SuiCommandFactKind::unsupported:
            return false;
    }
    return false;
}

bool add_review_command_rows(SuiReviewSummary* out, const SuiParsedTransactionFacts& parsed)
{
    if (!add_review_row_u16(
            out,
            SuiReviewRowKind::normal,
            "Commands",
            parsed.command_count)) {
        return false;
    }
    for (uint16_t index = 0; index < parsed.command_count; ++index) {
        char label[kSuiReviewSummaryRowLabelSize] = {};
        if (!format_ok(
                snprintf(label, sizeof(label), "Command %u", static_cast<unsigned>(index)),
                sizeof(label))) {
            return false;
        }
        if (!add_review_row(
                out,
                SuiReviewRowKind::normal,
                label,
                command_kind_name(parsed.commands[index].kind)) ||
            !add_command_detail_rows(out, parsed, index, parsed.commands[index])) {
            return false;
        }
    }
    return true;
}

bool add_common_review_rows(
    SuiReviewSummary* out,
    const SuiParsedTransactionFacts& parsed)
{
    return add_review_row(out, SuiReviewRowKind::normal, "Type", out->type_summary) &&
           add_review_row(out, SuiReviewRowKind::warning, "Risk", out->risk_label) &&
           add_review_row(out, SuiReviewRowKind::wrapped_value, "Sender", parsed.sender) &&
           add_review_row(out, SuiReviewRowKind::wrapped_value, "Gas owner", parsed.gas_owner) &&
           add_review_gas_rows(out, parsed) &&
           add_review_gas_payment_rows(out, parsed) &&
           add_review_expiration_rows(out, parsed) &&
           add_review_input_rows(out, parsed) &&
           add_review_command_rows(out, parsed);
}

bool review_common_rows_complete(
    const SuiParsedTransactionFacts& parsed,
    const SuiReviewSummary& summary)
{
    if (!review_row_present(summary, "Type") ||
        !review_row_present(summary, "Risk") ||
        !review_row_present(summary, "Sender") ||
        !review_row_present(summary, "Gas owner") ||
        !review_row_present(summary, "Gas max") ||
        !review_row_present(summary, "Gas price") ||
        !review_row_present(summary, "Gas coins") ||
        !review_row_present(summary, "Expiration") ||
        !review_row_present(summary, "Inputs") ||
        !review_row_present(summary, "Commands")) {
        return false;
    }
    for (uint16_t index = 0; index < parsed.gas_payment_count; ++index) {
        if (!review_row_label_value_present(summary, "Gas", index, "object") ||
            !review_row_label_value_present(summary, "Gas", index, "version") ||
            !review_row_label_value_present(summary, "Gas", index, "digest")) {
            return false;
        }
    }
    if (parsed.expiration_kind == SuiTransactionExpirationFact::epoch &&
        !review_row_present(summary, "Exp epoch")) {
        return false;
    }
    if (parsed.expiration_kind == SuiTransactionExpirationFact::valid_during) {
        if ((parsed.valid_during.has_min_epoch &&
             !review_row_present(summary, "Min epoch")) ||
            (parsed.valid_during.has_max_epoch &&
             !review_row_present(summary, "Max epoch")) ||
            (parsed.valid_during.has_min_timestamp &&
             !review_row_present(summary, "Min time")) ||
            (parsed.valid_during.has_max_timestamp &&
             !review_row_present(summary, "Max time")) ||
            !review_row_present(summary, "Chain digest") ||
            !review_row_present(summary, "Nonce")) {
            return false;
        }
    }
    return true;
}

bool review_input_rows_complete(
    const SuiParsedTransactionFacts& parsed,
    const SuiReviewSummary& summary)
{
    for (uint16_t index = 0; index < parsed.input_count; ++index) {
        const SuiCallArgFact& input = parsed.inputs[index];
        if (!review_row_label_value_present(summary, "Input", index, "kind")) {
            return false;
        }
        switch (input.kind) {
            case SuiCallArgFactKind::pure:
                if (!review_row_label_value_present(summary, "Input", index, "pure") ||
                    !review_pure_hex_rows_present(summary, index, input.pure_length)) {
                    return false;
                }
                break;
            case SuiCallArgFactKind::object_imm_or_owned:
            case SuiCallArgFactKind::object_receiving:
                if (!review_row_label_value_present(summary, "Input", index, "object") ||
                    !review_row_label_value_present(summary, "Input", index, "version") ||
                    !review_row_label_value_present(summary, "Input", index, "digest")) {
                    return false;
                }
                break;
            case SuiCallArgFactKind::object_shared:
                if (!review_row_label_value_present(summary, "Input", index, "object") ||
                    !review_row_label_value_present(summary, "Input", index, "version") ||
                    !review_row_label_value_present(summary, "Input", index, "mutable")) {
                    return false;
                }
                break;
            case SuiCallArgFactKind::funds_withdrawal:
                if (!review_row_label_value_present(summary, "Input", index, "amount") ||
                    !review_row_label_value_present(summary, "Input", index, "type") ||
                    !review_row_label_value_present(summary, "Input", index, "source")) {
                    return false;
                }
                break;
            case SuiCallArgFactKind::unsupported:
                return false;
        }
    }
    return true;
}

bool review_command_argument_rows_complete(
    const SuiReviewSummary& summary,
    uint16_t command_index,
    const SuiCommandFact& command)
{
    if (!review_row_label_value_present(summary, "Cmd", command_index, "args")) {
        return false;
    }
    for (uint16_t arg_index = 0; arg_index < command.argument_count; ++arg_index) {
        if (!review_command_arg_row_present(summary, command_index, arg_index)) {
            return false;
        }
    }
    return true;
}

bool review_command_rows_complete(
    const SuiParsedTransactionFacts& parsed,
    const SuiReviewSummary& summary)
{
    for (uint16_t command_index = 0; command_index < parsed.command_count; ++command_index) {
        char command_label[kSuiReviewSummaryRowLabelSize] = {};
        if (!format_ok(
                snprintf(
                    command_label,
                    sizeof(command_label),
                    "Command %u",
                    static_cast<unsigned>(command_index)),
                sizeof(command_label)) ||
            !review_row_present(summary, command_label) ||
            !review_command_argument_rows_complete(
                summary,
                command_index,
                parsed.commands[command_index])) {
            return false;
        }

        const SuiCommandFact& command = parsed.commands[command_index];
        switch (command.kind) {
            case SuiCommandFactKind::move_call:
                if (!review_row_label_value_present(summary, "Cmd", command_index, "package") ||
                    !review_row_label_value_present(summary, "Cmd", command_index, "module") ||
                    !review_row_label_value_present(summary, "Cmd", command_index, "function")) {
                    return false;
                }
                for (uint16_t type_index = 0;
                     type_index < command.move_call.type_argument_count;
                     ++type_index) {
                    if (!review_type_arg_row_present(summary, command_index, type_index)) {
                        return false;
                    }
                }
                break;
            case SuiCommandFactKind::transfer_objects: {
                if (command.argument_count == 0) {
                    return false;
                }
                const SuiCallArgFact* recipient =
                    referenced_input(parsed, command.arguments[command.argument_count - 1]);
                char address[kSuiAddressStringBufferSize] = {};
                if (recipient == nullptr ||
                    !format_pure_address(*recipient, address, sizeof(address)) ||
                    !review_row_label_value_present(summary, "Cmd", command_index, "recipient")) {
                    return false;
                }
                break;
            }
            case SuiCommandFactKind::split_coins:
                if (command.argument_count < 2) {
                    return false;
                }
                for (uint16_t arg_index = 1; arg_index < command.argument_count; ++arg_index) {
                    const SuiCallArgFact* amount =
                        referenced_input(parsed, command.arguments[arg_index]);
                    char amount_text[kSuiU64StringBufferSize] = {};
                    if (amount == nullptr ||
                        !format_pure_u64(*amount, amount_text, sizeof(amount_text)) ||
                        !review_split_amount_row_present(
                            summary,
                            command_index,
                            static_cast<uint16_t>(arg_index - 1))) {
                        return false;
                    }
                }
                break;
            case SuiCommandFactKind::merge_coins:
                break;
            case SuiCommandFactKind::make_move_vec:
                if (command.has_make_move_vec_type &&
                    !review_row_label_value_present(summary, "Cmd", command_index, "type")) {
                    return false;
                }
                break;
            case SuiCommandFactKind::publish:
            case SuiCommandFactKind::upgrade:
            case SuiCommandFactKind::unsupported:
                return false;
        }
    }
    return true;
}

bool review_coverage_complete_for_user_confirmation(
    const SuiParsedTransactionFacts& parsed,
    const SuiReviewSummary& summary)
{
    if (parsed.transaction_data_version != SuiTransactionDataVersionFact::v1 ||
        parsed.transaction_kind != SuiTransactionKindFact::programmable_transaction ||
        parsed.command_count == 0) {
        return false;
    }
    return review_common_rows_complete(parsed, summary) &&
           review_input_rows_complete(parsed, summary) &&
           review_command_rows_complete(parsed, summary);
}

bool build_move_call_review_summary(
    const SuiParsedTransactionFacts& parsed,
    SuiReviewSummary* out)
{
    return copy_c_string(out->title, sizeof(out->title), "Review Sui transaction") &&
           copy_c_string(out->type_summary, sizeof(out->type_summary), "Move call") &&
           copy_c_string(out->risk_label, sizeof(out->risk_label), "High") &&
           add_common_review_rows(out, parsed);
}

bool build_publish_review_summary(
    const SuiParsedTransactionFacts& parsed,
    SuiReviewSummary* out)
{
    return copy_c_string(out->title, sizeof(out->title), "Review Sui transaction") &&
           copy_c_string(out->type_summary, sizeof(out->type_summary), "Publish package") &&
           copy_c_string(out->risk_label, sizeof(out->risk_label), "High") &&
           add_common_review_rows(out, parsed);
}

bool build_upgrade_review_summary(
    const SuiParsedTransactionFacts& parsed,
    SuiReviewSummary* out)
{
    return copy_c_string(out->title, sizeof(out->title), "Review Sui transaction") &&
           copy_c_string(out->type_summary, sizeof(out->type_summary), "Upgrade package") &&
           copy_c_string(out->risk_label, sizeof(out->risk_label), "High") &&
           add_common_review_rows(out, parsed);
}

bool build_generic_review_summary(
    const SuiParsedTransactionFacts& parsed,
    SuiReviewSummary* out)
{
    return copy_c_string(out->title, sizeof(out->title), "Review Sui transaction") &&
           copy_c_string(out->type_summary, sizeof(out->type_summary), "Programmable transaction") &&
           copy_c_string(out->risk_label, sizeof(out->risk_label), "High") &&
           add_common_review_rows(out, parsed);
}

bool build_incomplete_review_capacity_summary(
    const SuiParsedTransactionFacts& parsed,
    SuiReviewSummary* out)
{
    memset(out, 0, sizeof(*out));
    out->status = SuiReviewSummaryStatus::insufficient_review;
    out->risk = SuiReviewRiskLevel::high;
    return copy_c_string(out->title, sizeof(out->title), "Review Sui transaction") &&
           copy_c_string(out->type_summary, sizeof(out->type_summary), "Transaction review incomplete") &&
           copy_c_string(out->risk_label, sizeof(out->risk_label), "High") &&
           add_review_row(out, SuiReviewRowKind::warning, "Type", out->type_summary) &&
           add_review_row(
               out,
               SuiReviewRowKind::warning,
               "Reason",
               "Transaction review exceeds review capacity") &&
           add_review_row(out, SuiReviewRowKind::wrapped_value, "Sender", parsed.sender) &&
           add_review_row(out, SuiReviewRowKind::wrapped_value, "Gas owner", parsed.gas_owner) &&
           add_review_row(out, SuiReviewRowKind::normal, "Gas max", parsed.gas_budget) &&
           add_review_row(out, SuiReviewRowKind::normal, "Gas price", parsed.gas_price);
}

SuiTransactionFactsResult parse_transaction_data(
    SuiBcsReader& reader,
    SuiParsedTransactionFacts* out)
{
    uint32_t tx_variant = 0;
    if (!read_variant(reader, &tx_variant)) {
        return result_from_reader(reader);
    }
    if (tx_variant != 0) {
        out->transaction_data_version = SuiTransactionDataVersionFact::unsupported;
        return SuiTransactionFactsResult::unsupported_version;
    }
    out->transaction_data_version = SuiTransactionDataVersionFact::v1;

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

    uint32_t command_count = 0;
    if (!reader.read_vector_length(kSuiPolicyFactMaxCommands, &command_count)) {
        return result_from_reader(reader);
    }
    out->command_count = static_cast<uint16_t>(command_count);
    for (uint32_t index = 0; index < command_count; ++index) {
        if (!read_command(reader, &out->commands[index])) {
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
            bool* option_flags[] = {
                &out->valid_during.has_min_epoch,
                &out->valid_during.has_max_epoch,
                &out->valid_during.has_min_timestamp,
                &out->valid_during.has_max_timestamp,
            };
            char* option_values[] = {
                out->valid_during.min_epoch,
                out->valid_during.max_epoch,
                out->valid_during.min_timestamp,
                out->valid_during.max_timestamp,
            };
            for (uint32_t option_index = 0; option_index < 4; ++option_index) {
                uint32_t option_variant = 0;
                uint64_t value = 0;
                if (!read_variant(reader, &option_variant) || option_variant > 1) {
                    return result_from_reader(reader);
                }
                if (option_variant == 1 && !reader.read_u64_le(&value)) {
                    return result_from_reader(reader);
                }
                if (option_variant == 1) {
                    *option_flags[option_index] = true;
                    if (!format_u64(value, option_values[option_index], kSuiU64StringBufferSize)) {
                        return result_from_reader(reader);
                    }
                }
            }
            uint32_t nonce = 0;
            if (!read_object_digest(
                    reader,
                    out->valid_during.chain_digest_hex,
                    sizeof(out->valid_during.chain_digest_hex)) ||
                !reader.read_u32_le(&nonce) ||
                !format_u64(nonce, out->valid_during.nonce, sizeof(out->valid_during.nonce))) {
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

    return SuiTransactionFactsResult::ok;
}

bool transaction_kind_only_parse_ok(const uint8_t* tx_bytes, size_t tx_len)
{
    SuiBcsReader reader(tx_bytes, tx_len);
    uint32_t kind_variant = 0;
    if (!read_variant(reader, &kind_variant) || kind_variant != 0) {
        return false;
    }
    SuiParsedTransactionFacts* scratch =
        static_cast<SuiParsedTransactionFacts*>(malloc(sizeof(SuiParsedTransactionFacts)));
    if (scratch == nullptr) {
        return false;
    }
    memset(scratch, 0, sizeof(*scratch));
    uint32_t input_count = 0;
    if (!reader.read_vector_length(kSuiPolicyFactMaxInputs, &input_count)) {
        free(scratch);
        return false;
    }
    for (uint32_t index = 0; index < input_count; ++index) {
        if (!read_call_arg(reader, &scratch->inputs[index])) {
            free(scratch);
            return false;
        }
    }
    uint32_t command_count = 0;
    if (!reader.read_vector_length(kSuiPolicyFactMaxCommands, &command_count)) {
        free(scratch);
        return false;
    }
    for (uint32_t index = 0; index < command_count; ++index) {
        if (!read_command(reader, &scratch->commands[index])) {
            free(scratch);
            return false;
        }
        if (!command_argument_refs_in_range(
                scratch->commands[index],
                static_cast<uint16_t>(input_count),
                static_cast<uint16_t>(index))) {
            free(scratch);
            return false;
        }
    }
    const bool ok = reader.expect_eof();
    free(scratch);
    return ok;
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
        case SuiTransactionFactsResult::unsupported_version:
            return "unsupported_version";
        case SuiTransactionFactsResult::unsupported_kind:
            return "unsupported_kind";
        case SuiTransactionFactsResult::unsupported_shape:
            return "unsupported_shape";
        case SuiTransactionFactsResult::too_large:
            return "too_large";
    }
    return "unknown";
}

SuiTransactionFactsResult parse_sui_parsed_transaction_facts(
    const uint8_t* tx_bytes,
    size_t tx_len,
    SuiParsedTransactionFacts* out)
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

SuiTransactionFactsResult parse_sui_minimum_transaction_facts(
    const uint8_t* tx_bytes,
    size_t tx_len,
    SuiMinimumTransactionFacts* out)
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
        out->transaction_data_version = SuiTransactionDataVersionFact::unsupported;
        return SuiTransactionFactsResult::unsupported_version;
    }
    out->transaction_data_version = SuiTransactionDataVersionFact::v1;

    uint32_t kind_variant = 0;
    if (!read_variant(reader, &kind_variant)) {
        return result_from_reader(reader);
    }
    if (kind_variant != 0) {
        out->transaction_kind = SuiTransactionKindFact::unsupported;
        if (transaction_kind_only_parse_ok(tx_bytes, tx_len)) {
            memset(out, 0, sizeof(*out));
            return SuiTransactionFactsResult::transaction_kind_only;
        }
        return SuiTransactionFactsResult::unsupported_kind;
    }
    out->transaction_kind = SuiTransactionKindFact::programmable_transaction;

    if (!skip_call_arg_vector(reader) ||
        !skip_command_vector(reader) ||
        !read_address(reader, out->sender, sizeof(out->sender)) ||
        !skip_gas_payment_vector(reader) ||
        !read_address(reader, out->gas_owner, sizeof(out->gas_owner))) {
        memset(out, 0, sizeof(*out));
        return result_from_shape_reader(reader);
    }

    uint64_t gas_price = 0;
    uint64_t gas_budget = 0;
    if (!reader.read_u64_le(&gas_price) ||
        !reader.read_u64_le(&gas_budget) ||
        !format_u64(gas_price, out->gas_price, sizeof(out->gas_price)) ||
        !format_u64(gas_budget, out->gas_budget, sizeof(out->gas_budget))) {
        memset(out, 0, sizeof(*out));
        return result_from_reader(reader);
    }
    if (!skip_expiration(reader)) {
        memset(out, 0, sizeof(*out));
        return result_from_shape_reader(reader);
    }
    if (!reader.expect_eof()) {
        memset(out, 0, sizeof(*out));
        return result_from_reader(reader);
    }

    return SuiTransactionFactsResult::ok;
}

bool build_sui_policy_subject_facts(
    const SuiParsedTransactionFacts& parsed,
    SuiPolicySubjectFacts* out)
{
    if (out == nullptr ||
        parsed.transaction_data_version != SuiTransactionDataVersionFact::v1 ||
        parsed.transaction_kind != SuiTransactionKindFact::programmable_transaction) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->transaction_data_version = parsed.transaction_data_version;
    out->transaction_kind = parsed.transaction_kind;
    snprintf(out->sender, sizeof(out->sender), "%s", parsed.sender);
    snprintf(out->gas_owner, sizeof(out->gas_owner), "%s", parsed.gas_owner);
    snprintf(out->gas_price, sizeof(out->gas_price), "%s", parsed.gas_price);
    snprintf(out->gas_budget, sizeof(out->gas_budget), "%s", parsed.gas_budget);
    out->expiration_kind = parsed.expiration_kind;
    snprintf(out->expiration_epoch, sizeof(out->expiration_epoch), "%s", parsed.expiration_epoch);
    out->command_count = parsed.command_count;
    const uint16_t command_fact_count =
        parsed.command_count < kSuiPolicyFactMaxCommands
            ? parsed.command_count
            : static_cast<uint16_t>(kSuiPolicyFactMaxCommands);
    for (uint16_t index = 0; index < command_fact_count; ++index) {
        out->commands[index].kind = parsed.commands[index].kind;
        if (parsed.commands[index].kind == SuiCommandFactKind::move_call) {
            out->commands[index].has_move_call = true;
            snprintf(
                out->commands[index].move_call_package,
                sizeof(out->commands[index].move_call_package),
                "%s",
                parsed.commands[index].move_call.package);
            snprintf(
                out->commands[index].move_call_module,
                sizeof(out->commands[index].move_call_module),
                "%s",
                parsed.commands[index].move_call.module);
            snprintf(
                out->commands[index].move_call_function,
                sizeof(out->commands[index].move_call_function),
                "%s",
                parsed.commands[index].move_call.function);
            out->commands[index].type_argument_count =
                parsed.commands[index].move_call.type_argument_count;
            const uint16_t type_arg_count =
                parsed.commands[index].move_call.type_argument_count < kSuiPolicyFactMaxTypeArguments
                    ? parsed.commands[index].move_call.type_argument_count
                    : static_cast<uint16_t>(kSuiPolicyFactMaxTypeArguments);
            for (uint16_t type_arg_index = 0; type_arg_index < type_arg_count; ++type_arg_index) {
                snprintf(
                    out->commands[index].move_call_type_args[type_arg_index],
                    sizeof(out->commands[index].move_call_type_args[type_arg_index]),
                    "%s",
                    parsed.commands[index].move_call.type_arguments[type_arg_index].canonical);
            }
        }
    }
    return true;
}

bool build_sui_review_summary(
    const SuiParsedTransactionFacts& parsed,
    SuiReviewSummary* out)
{
    if (out == nullptr ||
        parsed.transaction_data_version != SuiTransactionDataVersionFact::v1 ||
        parsed.transaction_kind != SuiTransactionKindFact::programmable_transaction) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    // Start fail-closed. Builders below may promote this to ok only when the
    // parsed shape has complete device-confirmation review coverage.
    out->status = SuiReviewSummaryStatus::insufficient_review;
    out->risk = SuiReviewRiskLevel::high;

    bool built = false;
    if (parsed.command_count == 1) {
        const SuiCommandFact& command = parsed.commands[0];
        switch (command.kind) {
            case SuiCommandFactKind::move_call:
                built = build_move_call_review_summary(parsed, out);
                break;
            case SuiCommandFactKind::publish:
                built = build_publish_review_summary(parsed, out);
                break;
            case SuiCommandFactKind::upgrade:
                built = build_upgrade_review_summary(parsed, out);
                break;
            case SuiCommandFactKind::transfer_objects:
            case SuiCommandFactKind::split_coins:
            case SuiCommandFactKind::merge_coins:
            case SuiCommandFactKind::make_move_vec:
            case SuiCommandFactKind::unsupported:
                break;
        }
    }
    if (!built) {
        built = build_generic_review_summary(parsed, out);
    }
    if (!built) {
        return build_incomplete_review_capacity_summary(parsed, out);
    }
    out->status = review_coverage_complete_for_user_confirmation(parsed, *out)
                      ? SuiReviewSummaryStatus::ok
                      : SuiReviewSummaryStatus::insufficient_review;
    return true;
}

}  // namespace signing
