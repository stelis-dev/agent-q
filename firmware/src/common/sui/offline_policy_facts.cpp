#include "offline_policy_facts.h"

#include "numeric/u64_decimal.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

namespace signing {
namespace {

constexpr const char* kSuiTypeTag =
    "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI";

struct TokenTypePool {
    uint16_t count;
    char values[kSuiOfflinePolicyMaxTokenTotals][kSuiPolicyFactTypeTagBufferSize];
};

struct TokenState {
    bool present;
    bool known;
    uint16_t type_index;
    SuiOfflinePolicyTokenSourceKind source;
    uint64_t amount;
    SuiOfflinePolicyTokenProvenance provenance;
};

bool copy_text(char* out, size_t out_size, const char* value)
{
    if (out == nullptr || out_size == 0 || value == nullptr) {
        return false;
    }
    const int written = snprintf(out, out_size, "%s", value);
    return written >= 0 && static_cast<size_t>(written) < out_size;
}

bool format_u64_text(uint64_t value, char* out, size_t out_size)
{
    return format_u64_decimal(value, out, out_size);
}

bool parse_u64_text(const char* value, uint64_t* out)
{
    if (value == nullptr || value[0] == '\0' || out == nullptr) {
        return false;
    }
    char* end = nullptr;
    errno = 0;
    const unsigned long long parsed = strtoull(value, &end, 10);
    if (end == value || *end != '\0' || errno == ERANGE ||
        parsed > static_cast<unsigned long long>(UINT64_MAX)) {
        return false;
    }
    *out = static_cast<uint64_t>(parsed);
    return true;
}

bool set_reason(
    SuiOfflinePolicyConditionFacts* out,
    SuiOfflinePolicyFactsCompleteness completeness,
    SuiOfflinePolicyFactsReason reason)
{
    if (out == nullptr) {
        return false;
    }
    if (out->completeness == SuiOfflinePolicyFactsCompleteness::complete) {
        out->completeness = completeness;
        out->reason = reason;
    }
    return true;
}

bool string_set_contains(const SuiOfflinePolicyStringSet& set, const char* value)
{
    for (uint16_t index = 0; index < set.count; ++index) {
        if (strcmp(set.values[index], value) == 0) {
            return true;
        }
    }
    return false;
}

bool add_string_set_value(
    SuiOfflinePolicyStringSet* set,
    const char* value,
    SuiOfflinePolicyConditionFacts* facts)
{
    if (set == nullptr || value == nullptr || value[0] == '\0') {
        return true;
    }
    if (string_set_contains(*set, value)) {
        return true;
    }
    if (set->count >= kSuiOfflinePolicyMaxSetValues) {
        return set_reason(
            facts,
            SuiOfflinePolicyFactsCompleteness::capacity_exceeded,
            SuiOfflinePolicyFactsReason::fact_capacity_exceeded);
    }
    return copy_text(set->values[set->count++], kSuiPolicyFactTypeTagBufferSize, value);
}

bool token_type_pool_find(const TokenTypePool& pool, const char* type_tag, uint16_t* out_index)
{
    if (type_tag == nullptr || out_index == nullptr) {
        return false;
    }
    for (uint16_t index = 0; index < pool.count; ++index) {
        if (strcmp(pool.values[index], type_tag) == 0) {
            *out_index = index;
            return true;
        }
    }
    return false;
}

bool token_type_pool_add(
    TokenTypePool* pool,
    const char* type_tag,
    SuiOfflinePolicyConditionFacts* facts,
    uint16_t* out_index)
{
    if (pool == nullptr || type_tag == nullptr || type_tag[0] == '\0' || out_index == nullptr) {
        return false;
    }
    if (token_type_pool_find(*pool, type_tag, out_index)) {
        return true;
    }
    if (pool->count >= kSuiOfflinePolicyMaxTokenTotals) {
        set_reason(
            facts,
            SuiOfflinePolicyFactsCompleteness::capacity_exceeded,
            SuiOfflinePolicyFactsReason::fact_capacity_exceeded);
        return false;
    }
    if (!copy_text(pool->values[pool->count], sizeof(pool->values[pool->count]), type_tag)) {
        return false;
    }
    *out_index = pool->count++;
    return true;
}

const char* token_type_tag_from_state(const TokenTypePool& pool, const TokenState& state)
{
    if (!state.known || state.type_index >= pool.count) {
        return nullptr;
    }
    return pool.values[state.type_index];
}

const char* command_kind_name(SuiCommandFactKind kind)
{
    switch (kind) {
        case SuiCommandFactKind::move_call:
            return "move_call";
        case SuiCommandFactKind::transfer_objects:
            return "transfer_objects";
        case SuiCommandFactKind::split_coins:
            return "split_coins";
        case SuiCommandFactKind::merge_coins:
            return "merge_coins";
        case SuiCommandFactKind::publish:
            return "publish";
        case SuiCommandFactKind::make_move_vec:
            return "make_move_vec";
        case SuiCommandFactKind::upgrade:
            return "upgrade";
        case SuiCommandFactKind::unsupported:
            return "unsupported";
    }
    return "unsupported";
}

bool pure_u64_arg(
    const SuiParsedTransactionFacts& parsed,
    const SuiArgumentFact& argument,
    uint64_t* out)
{
    if (argument.kind != SuiArgumentFactKind::input || argument.index >= parsed.input_count) {
        return false;
    }
    const SuiCallArgFact& input = parsed.inputs[argument.index];
    if (input.kind != SuiCallArgFactKind::pure || input.pure_length != 8) {
        return false;
    }
    uint64_t value = 0;
    for (uint32_t index = 0; index < 8; ++index) {
        value |= static_cast<uint64_t>(input.pure_bytes[index]) << (8 * index);
    }
    *out = value;
    return true;
}

bool pure_address_arg(
    const SuiParsedTransactionFacts& parsed,
    const SuiArgumentFact& argument,
    char* out,
    size_t out_size)
{
    if (argument.kind != SuiArgumentFactKind::input || argument.index >= parsed.input_count) {
        return false;
    }
    const SuiCallArgFact& input = parsed.inputs[argument.index];
    if (input.kind != SuiCallArgFactKind::pure || input.pure_length != 32 ||
        out == nullptr || out_size < kSuiAddressStringBufferSize) {
        return false;
    }
    static constexpr char kHex[] = "0123456789abcdef";
    out[0] = '0';
    out[1] = 'x';
    for (uint32_t index = 0; index < 32; ++index) {
        const uint8_t byte = input.pure_bytes[index];
        out[2 + index * 2] = kHex[(byte >> 4) & 0x0f];
        out[3 + index * 2] = kHex[byte & 0x0f];
    }
    out[66] = '\0';
    return true;
}

bool add_token_source(
    SuiOfflinePolicyConditionFacts* out,
    const char* type_tag,
    SuiOfflinePolicyTokenSourceKind source,
    uint64_t amount,
    SuiOfflinePolicyTokenProvenance provenance)
{
    if (out == nullptr || type_tag == nullptr || type_tag[0] == '\0') {
        return false;
    }
    if (out->token_source_count >= kSuiOfflinePolicyMaxTokenSources) {
        return set_reason(
            out,
            SuiOfflinePolicyFactsCompleteness::capacity_exceeded,
            SuiOfflinePolicyFactsReason::fact_capacity_exceeded);
    }
    SuiOfflinePolicyTokenSourceFact& target = out->token_sources[out->token_source_count++];
    target.source = source;
    target.amount_known = true;
    target.provenance = provenance;
    return copy_text(target.type_tag, sizeof(target.type_tag), type_tag) &&
           format_u64_text(amount, target.amount_raw, sizeof(target.amount_raw));
}

bool add_token_total(
    SuiOfflinePolicyConditionFacts* out,
    const char* type_tag,
    uint64_t amount)
{
    for (uint16_t index = 0; index < out->token_total_count; ++index) {
        SuiOfflinePolicyTokenTotalFact& total = out->token_totals_by_type[index];
        if (strcmp(total.type_tag, type_tag) == 0) {
            uint64_t current = 0;
            if (!parse_u64_text(total.amount_raw, &current) ||
                UINT64_MAX - current < amount) {
                return set_reason(
                    out,
                    SuiOfflinePolicyFactsCompleteness::incomplete,
                    SuiOfflinePolicyFactsReason::token_amount_overflow);
            }
            return format_u64_text(current + amount, total.amount_raw, sizeof(total.amount_raw));
        }
    }
    if (out->token_total_count >= kSuiOfflinePolicyMaxTokenTotals) {
        return set_reason(
            out,
            SuiOfflinePolicyFactsCompleteness::capacity_exceeded,
            SuiOfflinePolicyFactsReason::fact_capacity_exceeded);
    }
    SuiOfflinePolicyTokenTotalFact& total = out->token_totals_by_type[out->token_total_count++];
    return copy_text(total.type_tag, sizeof(total.type_tag), type_tag) &&
           format_u64_text(amount, total.amount_raw, sizeof(total.amount_raw));
}

bool add_token_amount_source(
    SuiOfflinePolicyConditionFacts* out,
    const char* type_tag,
    SuiOfflinePolicyTokenSourceKind source,
    uint64_t amount,
    SuiOfflinePolicyTokenProvenance provenance)
{
    return add_token_source(out, type_tag, source, amount, provenance) &&
           add_token_total(out, type_tag, amount);
}

void mark_unknown_token_amount(
    SuiOfflinePolicyConditionFacts* out,
    SuiOfflinePolicyFactsReason reason)
{
    if (out != nullptr) {
        if (!out->token_unknown_amount_present) {
            out->token_unknown_amount_reason = reason;
        }
        out->token_unknown_amount_present = true;
    }
}

bool state_from_funds_withdrawal(
    const SuiCallArgFact& input,
    TokenTypePool* token_types,
    SuiOfflinePolicyConditionFacts* facts,
    TokenState* out)
{
    if (out == nullptr || input.kind != SuiCallArgFactKind::funds_withdrawal) {
        return false;
    }
    uint64_t amount = 0;
    if (!parse_u64_text(input.funds_withdrawal.amount, &amount)) {
        return false;
    }
    out->present = true;
    out->known = true;
    out->amount = amount;
    out->source = input.funds_withdrawal.source == SuiFundsWithdrawalSourceFact::sponsor
                      ? SuiOfflinePolicyTokenSourceKind::funds_withdrawal_sponsor
                      : SuiOfflinePolicyTokenSourceKind::funds_withdrawal_sender;
    out->provenance = SuiOfflinePolicyTokenProvenance::funds_withdrawal;
    return token_type_pool_add(token_types, input.funds_withdrawal.type.canonical, facts, &out->type_index);
}

bool resolve_token_state(
    const SuiParsedTransactionFacts& parsed,
    TokenState states[kSuiPolicyFactMaxCommands][kSuiPolicyFactMaxCommandArguments],
    TokenTypePool* token_types,
    SuiOfflinePolicyConditionFacts* facts,
    const SuiArgumentFact& argument,
    TokenState* out)
{
    if (out == nullptr) {
        return false;
    }
    *out = {};
    switch (argument.kind) {
        case SuiArgumentFactKind::input:
            if (argument.index >= parsed.input_count) {
                return false;
            }
            if (parsed.inputs[argument.index].kind == SuiCallArgFactKind::funds_withdrawal) {
                return state_from_funds_withdrawal(parsed.inputs[argument.index], token_types, facts, out);
            }
            return false;
        case SuiArgumentFactKind::nested_result:
            if (argument.index >= kSuiPolicyFactMaxCommands ||
                argument.nested_index >= kSuiPolicyFactMaxCommandArguments) {
                return false;
            }
            if (states[argument.index][argument.nested_index].present) {
                *out = states[argument.index][argument.nested_index];
                return out->known;
            }
            return false;
        case SuiArgumentFactKind::result:
            if (argument.index >= kSuiPolicyFactMaxCommands) {
                return false;
            }
            if (states[argument.index][0].present) {
                *out = states[argument.index][0];
                return out->known;
            }
            return false;
        case SuiArgumentFactKind::gas_coin:
        case SuiArgumentFactKind::unsupported:
            return false;
    }
    return false;
}

bool add_funds_withdrawal_inputs(
    const SuiParsedTransactionFacts& parsed,
    TokenTypePool* token_types,
    SuiOfflinePolicyConditionFacts* out)
{
    for (uint16_t index = 0; index < parsed.input_count; ++index) {
        const SuiCallArgFact& input = parsed.inputs[index];
        if (input.kind != SuiCallArgFactKind::funds_withdrawal) {
            continue;
        }
        TokenState state = {};
        if (!state_from_funds_withdrawal(input, token_types, out, &state)) {
            return set_reason(
                out,
                SuiOfflinePolicyFactsCompleteness::incomplete,
                SuiOfflinePolicyFactsReason::token_amount_decode_failed);
        }
        const char* type_tag = token_type_tag_from_state(*token_types, state);
        if (type_tag == nullptr) {
            return false;
        }
        if (!add_token_amount_source(
                out,
                type_tag,
                state.source,
                state.amount,
                state.provenance)) {
            return false;
        }
    }
    return true;
}

bool process_split_coins(
    const SuiParsedTransactionFacts& parsed,
    uint16_t command_index,
    const SuiCommandFact& command,
    TokenState states[kSuiPolicyFactMaxCommands][kSuiPolicyFactMaxCommandArguments],
    TokenTypePool* token_types,
    SuiOfflinePolicyConditionFacts* out)
{
    if (command.argument_count == 0) {
        return true;
    }
    TokenState source = {};
    bool source_known = false;
    bool add_split_amount_as_source = false;
    if (command.arguments[0].kind == SuiArgumentFactKind::gas_coin) {
        source.present = true;
        source.known = true;
        source.source = SuiOfflinePolicyTokenSourceKind::gas_coin;
        source.provenance = SuiOfflinePolicyTokenProvenance::gas_coin_split;
        source_known = token_type_pool_add(token_types, kSuiTypeTag, out, &source.type_index);
        add_split_amount_as_source = true;
    } else {
        source_known = resolve_token_state(parsed, states, token_types, out, command.arguments[0], &source);
    }

    for (uint16_t arg_index = 1; arg_index < command.argument_count; ++arg_index) {
        TokenState& result = states[command_index][arg_index - 1];
        result.present = true;
        if (!source_known) {
            result.known = false;
            mark_unknown_token_amount(out, SuiOfflinePolicyFactsReason::unknown_token_provenance);
            continue;
        }
        uint64_t amount = 0;
        if (!pure_u64_arg(parsed, command.arguments[arg_index], &amount)) {
            result.known = false;
            return set_reason(
                out,
                SuiOfflinePolicyFactsCompleteness::incomplete,
                SuiOfflinePolicyFactsReason::token_amount_decode_failed);
        }
        result.known = true;
        result.amount = amount;
        result.source = source.source;
        result.provenance = source.provenance;
        result.type_index = source.type_index;
        const char* result_type_tag = token_type_tag_from_state(*token_types, result);
        if (result_type_tag == nullptr) {
            return false;
        }
        if (add_split_amount_as_source &&
            !add_token_amount_source(
                out,
                result_type_tag,
                result.source,
                result.amount,
                result.provenance)) {
            return false;
        }
    }
    return true;
}

bool store_token_state_for_argument(
    TokenState states[kSuiPolicyFactMaxCommands][kSuiPolicyFactMaxCommandArguments],
    const SuiArgumentFact& argument,
    const TokenState& state)
{
    if (argument.kind == SuiArgumentFactKind::nested_result &&
        argument.index < kSuiPolicyFactMaxCommands &&
        argument.nested_index < kSuiPolicyFactMaxCommandArguments) {
        states[argument.index][argument.nested_index] = state;
        states[argument.index][argument.nested_index].present = true;
        return true;
    }
    if (argument.kind == SuiArgumentFactKind::result &&
        argument.index < kSuiPolicyFactMaxCommands) {
        states[argument.index][0] = state;
        states[argument.index][0].present = true;
        return true;
    }
    return false;
}

bool process_merge_coins(
    const SuiParsedTransactionFacts& parsed,
    const SuiCommandFact& command,
    TokenState states[kSuiPolicyFactMaxCommands][kSuiPolicyFactMaxCommandArguments],
    TokenTypePool* token_types,
    SuiOfflinePolicyConditionFacts* out)
{
    if (command.argument_count == 0) {
        return true;
    }
    TokenState merged = {};
    bool merged_known =
        resolve_token_state(parsed, states, token_types, out, command.arguments[0], &merged);
    if (!merged_known) {
        mark_unknown_token_amount(out, SuiOfflinePolicyFactsReason::unknown_token_provenance);
    }
    for (uint16_t arg_index = 1; arg_index < command.argument_count; ++arg_index) {
        TokenState source = {};
        if (!resolve_token_state(parsed, states, token_types, out, command.arguments[arg_index], &source) ||
            !merged_known ||
            merged.type_index != source.type_index ||
            merged.source != source.source ||
            UINT64_MAX - merged.amount < source.amount) {
            merged_known = false;
            mark_unknown_token_amount(out, SuiOfflinePolicyFactsReason::mixed_known_unknown_token_merge);
            continue;
        }
        merged.amount += source.amount;
    }
    if (merged_known) {
        if (!store_token_state_for_argument(states, command.arguments[0], merged)) {
            mark_unknown_token_amount(out, SuiOfflinePolicyFactsReason::unknown_token_provenance);
        }
        return true;
    }

    TokenState unknown = {};
    unknown.present = true;
    store_token_state_for_argument(states, command.arguments[0], unknown);
    return true;
}

void observe_token_argument(
    const SuiParsedTransactionFacts& parsed,
    TokenState states[kSuiPolicyFactMaxCommands][kSuiPolicyFactMaxCommandArguments],
    TokenTypePool* token_types,
    const SuiArgumentFact& argument,
    SuiOfflinePolicyConditionFacts* out)
{
    TokenState resolved = {};
    if (argument.kind == SuiArgumentFactKind::gas_coin) {
        mark_unknown_token_amount(out, SuiOfflinePolicyFactsReason::unknown_token_provenance);
        return;
    }
    if (argument.kind == SuiArgumentFactKind::input && argument.index < parsed.input_count) {
        const SuiCallArgFact& input = parsed.inputs[argument.index];
        if (input.kind == SuiCallArgFactKind::object_imm_or_owned ||
            input.kind == SuiCallArgFactKind::object_shared ||
            input.kind == SuiCallArgFactKind::object_receiving) {
            mark_unknown_token_amount(out, SuiOfflinePolicyFactsReason::direct_object_token_amount_unknown);
        }
        return;
    }
    if ((argument.kind == SuiArgumentFactKind::result ||
         argument.kind == SuiArgumentFactKind::nested_result) &&
        !resolve_token_state(parsed, states, token_types, out, argument, &resolved)) {
        mark_unknown_token_amount(out, SuiOfflinePolicyFactsReason::unknown_token_provenance);
    }
}

bool process_command(
    const SuiParsedTransactionFacts& parsed,
    uint16_t command_index,
    const SuiCommandFact& command,
    TokenState states[kSuiPolicyFactMaxCommands][kSuiPolicyFactMaxCommandArguments],
    TokenTypePool* token_types,
    SuiOfflinePolicyConditionFacts* out)
{
    if (!add_string_set_value(&out->command_kinds, command_kind_name(command.kind), out)) {
        return false;
    }
    switch (command.kind) {
        case SuiCommandFactKind::move_call:
            if (!add_string_set_value(&out->move_call_packages, command.move_call.package, out) ||
                !add_string_set_value(&out->move_call_modules, command.move_call.module, out) ||
                !add_string_set_value(&out->move_call_functions, command.move_call.function, out)) {
                return false;
            }
            for (uint16_t arg_index = 0; arg_index < command.argument_count; ++arg_index) {
                observe_token_argument(parsed, states, token_types, command.arguments[arg_index], out);
            }
            return true;
        case SuiCommandFactKind::transfer_objects:
            if (command.argument_count > 0) {
                char recipient[kSuiAddressStringBufferSize] = {};
                if (!pure_address_arg(
                        parsed,
                        command.arguments[command.argument_count - 1],
                        recipient,
                        sizeof(recipient))) {
                    return set_reason(
                        out,
                        SuiOfflinePolicyFactsCompleteness::incomplete,
                        SuiOfflinePolicyFactsReason::recipient_address_decode_failed);
                }
                if (!add_string_set_value(&out->recipient_addresses, recipient, out) ||
                    !add_string_set_value(&out->pure_address_arguments, recipient, out)) {
                    return false;
                }
                for (uint16_t arg_index = 0; arg_index + 1 < command.argument_count; ++arg_index) {
                    observe_token_argument(parsed, states, token_types, command.arguments[arg_index], out);
                }
            }
            return true;
        case SuiCommandFactKind::split_coins:
            return process_split_coins(parsed, command_index, command, states, token_types, out);
        case SuiCommandFactKind::merge_coins:
            return process_merge_coins(parsed, command, states, token_types, out);
        case SuiCommandFactKind::publish:
            out->publish_present = true;
            return true;
        case SuiCommandFactKind::upgrade:
            out->upgrade_present = true;
            return true;
        case SuiCommandFactKind::make_move_vec:
            for (uint16_t arg_index = 0; arg_index < command.argument_count; ++arg_index) {
                observe_token_argument(parsed, states, token_types, command.arguments[arg_index], out);
            }
            return true;
        case SuiCommandFactKind::unsupported:
            return set_reason(
                out,
                SuiOfflinePolicyFactsCompleteness::unsupported,
                SuiOfflinePolicyFactsReason::unsupported_transaction_kind);
    }
    return false;
}

SuiOfflinePolicyFactsReason reason_from_parse_result(SuiTransactionFactsResult result)
{
    switch (result) {
        case SuiTransactionFactsResult::ok:
            return SuiOfflinePolicyFactsReason::none;
        case SuiTransactionFactsResult::malformed:
            return SuiOfflinePolicyFactsReason::malformed_bcs;
        case SuiTransactionFactsResult::transaction_kind_only:
            return SuiOfflinePolicyFactsReason::transaction_kind_only;
        case SuiTransactionFactsResult::unsupported_version:
            return SuiOfflinePolicyFactsReason::unsupported_transaction_version;
        case SuiTransactionFactsResult::unsupported_kind:
        case SuiTransactionFactsResult::unsupported_shape:
            return SuiOfflinePolicyFactsReason::unsupported_transaction_kind;
        case SuiTransactionFactsResult::too_large:
            return SuiOfflinePolicyFactsReason::fact_capacity_exceeded;
    }
    return SuiOfflinePolicyFactsReason::malformed_bcs;
}

SuiOfflinePolicyFactsCompleteness completeness_from_parse_result(SuiTransactionFactsResult result)
{
    switch (result) {
        case SuiTransactionFactsResult::ok:
            return SuiOfflinePolicyFactsCompleteness::complete;
        case SuiTransactionFactsResult::too_large:
            return SuiOfflinePolicyFactsCompleteness::capacity_exceeded;
        case SuiTransactionFactsResult::malformed:
            return SuiOfflinePolicyFactsCompleteness::malformed;
        case SuiTransactionFactsResult::transaction_kind_only:
        case SuiTransactionFactsResult::unsupported_version:
        case SuiTransactionFactsResult::unsupported_kind:
        case SuiTransactionFactsResult::unsupported_shape:
            return SuiOfflinePolicyFactsCompleteness::unsupported;
    }
    return SuiOfflinePolicyFactsCompleteness::malformed;
}

}  // namespace

const char* sui_offline_policy_facts_reason_name(SuiOfflinePolicyFactsReason reason)
{
    switch (reason) {
        case SuiOfflinePolicyFactsReason::none:
            return "none";
        case SuiOfflinePolicyFactsReason::malformed_bcs:
            return "malformed_bcs";
        case SuiOfflinePolicyFactsReason::unsupported_transaction_version:
            return "unsupported_transaction_version";
        case SuiOfflinePolicyFactsReason::unsupported_transaction_kind:
            return "unsupported_transaction_kind";
        case SuiOfflinePolicyFactsReason::transaction_kind_only:
            return "transaction_kind_only";
        case SuiOfflinePolicyFactsReason::trailing_bytes:
            return "trailing_bytes";
        case SuiOfflinePolicyFactsReason::input_capacity_exceeded:
            return "input_capacity_exceeded";
        case SuiOfflinePolicyFactsReason::command_capacity_exceeded:
            return "command_capacity_exceeded";
        case SuiOfflinePolicyFactsReason::fact_capacity_exceeded:
            return "fact_capacity_exceeded";
        case SuiOfflinePolicyFactsReason::invalid_command_reference:
            return "invalid_command_reference";
        case SuiOfflinePolicyFactsReason::invalid_result_reference:
            return "invalid_result_reference";
        case SuiOfflinePolicyFactsReason::recipient_address_decode_failed:
            return "recipient_address_decode_failed";
        case SuiOfflinePolicyFactsReason::token_amount_decode_failed:
            return "token_amount_decode_failed";
        case SuiOfflinePolicyFactsReason::token_amount_overflow:
            return "token_amount_overflow";
        case SuiOfflinePolicyFactsReason::unknown_token_provenance:
            return "unknown_token_provenance";
        case SuiOfflinePolicyFactsReason::mixed_known_unknown_token_merge:
            return "mixed_known_unknown_token_merge";
        case SuiOfflinePolicyFactsReason::direct_object_token_amount_unknown:
            return "direct_object_token_amount_unknown";
    }
    return "unknown";
}

bool build_sui_offline_policy_condition_facts(
    const SuiParsedTransactionFacts& parsed,
    SuiOfflinePolicyConditionFacts* out)
{
    if (out == nullptr) {
        return false;
    }
    *out = {};
    out->valid_transaction_data =
        parsed.transaction_data_version == SuiTransactionDataVersionFact::v1 &&
        parsed.transaction_kind == SuiTransactionKindFact::programmable_transaction;
    out->completeness = SuiOfflinePolicyFactsCompleteness::complete;
    out->reason = SuiOfflinePolicyFactsReason::none;
    out->sponsored = strcmp(parsed.sender, parsed.gas_owner) != 0;
    if (!copy_text(out->gas_budget_raw, sizeof(out->gas_budget_raw), parsed.gas_budget) ||
        !copy_text(out->gas_price_raw, sizeof(out->gas_price_raw), parsed.gas_price) ||
        !copy_text(out->gas_owner, sizeof(out->gas_owner), parsed.gas_owner) ||
        !copy_text(out->sender, sizeof(out->sender), parsed.sender) ||
        !format_u64_text(parsed.command_count, out->command_count, sizeof(out->command_count))) {
        return false;
    }
    TokenTypePool token_types = {};
    if (!add_funds_withdrawal_inputs(parsed, &token_types, out)) {
        return false;
    }

    TokenState states[kSuiPolicyFactMaxCommands][kSuiPolicyFactMaxCommandArguments] = {};
    for (uint16_t index = 0; index < parsed.command_count; ++index) {
        if (!process_command(parsed, index, parsed.commands[index], states, &token_types, out)) {
            return false;
        }
    }
    return true;
}

SuiTransactionFactsResult parse_sui_offline_policy_condition_facts(
    const uint8_t* tx_bytes,
    size_t tx_len,
    SuiOfflinePolicyConditionFacts* out)
{
    if (out == nullptr) {
        return SuiTransactionFactsResult::malformed;
    }
    *out = {};
    SuiParsedTransactionFacts* parsed =
        static_cast<SuiParsedTransactionFacts*>(malloc(sizeof(SuiParsedTransactionFacts)));
    if (parsed == nullptr) {
        out->completeness = SuiOfflinePolicyFactsCompleteness::capacity_exceeded;
        out->reason = SuiOfflinePolicyFactsReason::fact_capacity_exceeded;
        return SuiTransactionFactsResult::too_large;
    }
    const SuiTransactionFactsResult result =
        parse_sui_parsed_transaction_facts(tx_bytes, tx_len, parsed);
    if (result != SuiTransactionFactsResult::ok) {
        out->completeness = completeness_from_parse_result(result);
        out->reason = reason_from_parse_result(result);
        free(parsed);
        return result;
    }
    if (!build_sui_offline_policy_condition_facts(*parsed, out)) {
        if (out->reason == SuiOfflinePolicyFactsReason::none) {
            out->completeness = SuiOfflinePolicyFactsCompleteness::incomplete;
            out->reason = SuiOfflinePolicyFactsReason::fact_capacity_exceeded;
        }
    }
    free(parsed);
    return result;
}

}  // namespace signing
