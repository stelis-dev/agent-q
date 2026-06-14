#include "agent_q_sui_token_flow_facts.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "agent_q_u64_decimal.h"

namespace agent_q {
namespace {

struct AmountValue {
    bool relevant;
    SuiTokenAmountState state;
    SuiTokenAssetState asset_state;
    uint64_t value;
    SuiTokenFlowSourceKind source_kind;
    const char* object_id;
};

struct CommandResultValue {
    bool relevant;
    SuiTokenAmountState state;
    SuiTokenAssetState asset_state;
    uint64_t value;
    SuiTokenFlowSourceKind source_kind;
    char object_id[kSuiAddressStringBufferSize];
};

bool copy_c_string(char* out, size_t out_size, const char* value)
{
    if (out == nullptr || out_size == 0 || value == nullptr) {
        return false;
    }
    const int written = snprintf(out, out_size, "%s", value);
    return written >= 0 && static_cast<size_t>(written) < out_size;
}

bool set_decimal(uint64_t value, char* out, size_t out_size)
{
    return format_u64_decimal(value, out, out_size);
}

bool set_aggregate_decimal(
    SuiTokenAmountState state,
    uint64_t value,
    char* out,
    size_t out_size)
{
    if (out == nullptr || out_size == 0) {
        return false;
    }
    if (state != SuiTokenAmountState::known) {
        out[0] = '\0';
        return true;
    }
    return set_decimal(value, out, out_size);
}

bool add_checked(uint64_t* total, uint64_t value)
{
    if (total == nullptr || UINT64_MAX - *total < value) {
        return false;
    }
    *total += value;
    return true;
}

bool read_pure_u64(const SuiCallArgFact& input, uint64_t* out)
{
    if (out == nullptr ||
        input.kind != SuiCallArgFactKind::pure ||
        input.pure_length != 8) {
        return false;
    }

    uint64_t value = 0;
    for (uint32_t index = 0; index < input.pure_length; ++index) {
        value |= static_cast<uint64_t>(input.pure_bytes[index]) << (index * 8);
    }
    *out = value;
    return true;
}

bool read_pure_address(const SuiCallArgFact& input, char* out, size_t out_size)
{
    if (out == nullptr || out_size < kSuiAddressStringBufferSize ||
        input.kind != SuiCallArgFactKind::pure ||
        input.pure_length != 32) {
        return false;
    }

    int written = snprintf(out, out_size, "0x");
    if (written != 2) {
        return false;
    }
    for (uint32_t index = 0; index < input.pure_length; ++index) {
        written = snprintf(
            out + 2 + (index * 2),
            out_size - 2 - (index * 2),
            "%02x",
            static_cast<unsigned>(input.pure_bytes[index]));
        if (written != 2) {
            return false;
        }
    }
    return out[66] == '\0';
}

SuiTokenAmountState combine_aggregate_state(
    SuiTokenAmountState current,
    bool has_known_amount,
    SuiTokenAmountState incoming)
{
    if (current == SuiTokenAmountState::incomplete ||
        incoming == SuiTokenAmountState::incomplete) {
        return SuiTokenAmountState::incomplete;
    }
    if (incoming == SuiTokenAmountState::unknown) {
        if (current == SuiTokenAmountState::unknown || !has_known_amount) {
            return SuiTokenAmountState::unknown;
        }
        return SuiTokenAmountState::incomplete;
    }
    if (current == SuiTokenAmountState::unknown) {
        return SuiTokenAmountState::incomplete;
    }
    return SuiTokenAmountState::known;
}

bool append_flow(
    SuiTokenFlowFacts* out,
    SuiTokenFlowSourceKind source_kind,
    SuiTokenFlowSinkKind sink_kind,
    SuiTokenAssetState asset_state,
    SuiTokenAmountState amount_state,
    uint64_t amount,
    const char* object_id)
{
    if (out == nullptr || out->flow_count >= kSuiTokenFlowMaxFlows) {
        return false;
    }

    SuiTokenFlowFact& flow = out->flows[out->flow_count++];
    flow.source_kind = source_kind;
    flow.sink_kind = sink_kind;
    flow.asset_state = asset_state;
    flow.amount_state = amount_state;
    if (amount_state == SuiTokenAmountState::known) {
        if (!set_decimal(amount, flow.amount_raw, sizeof(flow.amount_raw))) {
            return false;
        }
    } else {
        flow.amount_raw[0] = '\0';
    }
    if (object_id != nullptr && object_id[0] != '\0') {
        return copy_c_string(flow.object_id, sizeof(flow.object_id), object_id);
    }
    flow.object_id[0] = '\0';
    return true;
}

SuiTokenAssetState combine_asset_state(
    SuiTokenAssetState current,
    SuiTokenAssetState incoming)
{
    if (current == SuiTokenAssetState::proven_sui &&
        incoming == SuiTokenAssetState::proven_sui) {
        return SuiTokenAssetState::proven_sui;
    }
    return SuiTokenAssetState::unproven;
}

SuiTokenAmountState sui_amount_state(const AmountValue& value)
{
    if (!value.relevant) {
        return SuiTokenAmountState::unknown;
    }
    if (value.asset_state != SuiTokenAssetState::proven_sui) {
        return SuiTokenAmountState::incomplete;
    }
    return value.state;
}

bool command_result_index_in_range(uint16_t command_index)
{
    return command_index < kSuiPolicyFactMaxCommands;
}

bool nested_result_index_in_range(uint16_t result_index)
{
    return result_index < kSuiPolicyFactMaxCommandArguments;
}

AmountValue resolve_argument_amount(
    const SuiParsedTransactionFacts& parsed,
    const CommandResultValue command_results
        [kSuiPolicyFactMaxCommands][kSuiPolicyFactMaxCommandArguments],
    const SuiArgumentFact& arg)
{
    AmountValue value = {};
    value.state = SuiTokenAmountState::unknown;
    value.asset_state = SuiTokenAssetState::unproven;
    value.source_kind = SuiTokenFlowSourceKind::unknown;

    switch (arg.kind) {
        case SuiArgumentFactKind::gas_coin:
            value.relevant = true;
            value.state = SuiTokenAmountState::unknown;
            value.asset_state = SuiTokenAssetState::proven_sui;
            value.source_kind = SuiTokenFlowSourceKind::gas_coin;
            return value;
        case SuiArgumentFactKind::input:
            if (arg.index >= parsed.input_count) {
                value.relevant = true;
                value.state = SuiTokenAmountState::incomplete;
                return value;
            }
            switch (parsed.inputs[arg.index].kind) {
                case SuiCallArgFactKind::object_imm_or_owned:
                case SuiCallArgFactKind::object_shared:
                case SuiCallArgFactKind::object_receiving:
                    value.relevant = true;
                    value.state = SuiTokenAmountState::unknown;
                    value.asset_state = SuiTokenAssetState::unproven;
                    value.source_kind = SuiTokenFlowSourceKind::direct_object;
                    value.object_id = parsed.inputs[arg.index].object_ref.object_id;
                    return value;
                case SuiCallArgFactKind::funds_withdrawal: {
                    uint64_t parsed_amount = 0;
                    value.relevant = true;
                    if (!parse_canonical_u64_decimal_string(
                            parsed.inputs[arg.index].funds_withdrawal.amount,
                            &parsed_amount)) {
                        value.state = SuiTokenAmountState::incomplete;
                        return value;
                    }
                    value.state = SuiTokenAmountState::known;
                    value.asset_state = SuiTokenAssetState::unproven;
                    value.value = parsed_amount;
                    value.source_kind = SuiTokenFlowSourceKind::funds_withdrawal;
                    return value;
                }
                case SuiCallArgFactKind::pure:
                case SuiCallArgFactKind::unsupported:
                    return value;
            }
            return value;
        case SuiArgumentFactKind::result:
            if (!command_result_index_in_range(arg.index)) {
                value.relevant = true;
                value.state = SuiTokenAmountState::incomplete;
                return value;
            }
            if (command_results[arg.index][0].relevant) {
                value.relevant = true;
                value.state = command_results[arg.index][0].state;
                value.asset_state = command_results[arg.index][0].asset_state;
                value.value = command_results[arg.index][0].value;
                value.source_kind = command_results[arg.index][0].source_kind;
                value.object_id = command_results[arg.index][0].object_id;
            }
            return value;
        case SuiArgumentFactKind::nested_result:
            if (!command_result_index_in_range(arg.index) ||
                !nested_result_index_in_range(arg.nested_index)) {
                value.relevant = true;
                value.state = SuiTokenAmountState::incomplete;
                return value;
            }
            if (command_results[arg.index][arg.nested_index].relevant) {
                value.relevant = true;
                value.state = command_results[arg.index][arg.nested_index].state;
                value.asset_state = command_results[arg.index][arg.nested_index].asset_state;
                value.value = command_results[arg.index][arg.nested_index].value;
                value.source_kind = command_results[arg.index][arg.nested_index].source_kind;
                value.object_id = command_results[arg.index][arg.nested_index].object_id;
            }
            return value;
        case SuiArgumentFactKind::unsupported:
            value.relevant = true;
            value.state = SuiTokenAmountState::incomplete;
            return value;
    }
    return value;
}

CommandResultValue* mutable_command_result_for_argument(
    CommandResultValue command_results
        [kSuiPolicyFactMaxCommands][kSuiPolicyFactMaxCommandArguments],
    const SuiArgumentFact& arg)
{
    switch (arg.kind) {
        case SuiArgumentFactKind::result:
            if (!command_result_index_in_range(arg.index)) {
                return nullptr;
            }
            return &command_results[arg.index][0];
        case SuiArgumentFactKind::nested_result:
            if (!command_result_index_in_range(arg.index) ||
                !nested_result_index_in_range(arg.nested_index)) {
                return nullptr;
            }
            return &command_results[arg.index][arg.nested_index];
        case SuiArgumentFactKind::gas_coin:
        case SuiArgumentFactKind::input:
        case SuiArgumentFactKind::unsupported:
            return nullptr;
    }
    return nullptr;
}

SuiTokenFlowFactsResult handle_split_coins(
    const SuiParsedTransactionFacts& parsed,
    const SuiCommandFact& command,
    uint16_t command_index,
    CommandResultValue command_results
        [kSuiPolicyFactMaxCommands][kSuiPolicyFactMaxCommandArguments])
{
    if (command.argument_count == 0) {
        return SuiTokenFlowFactsResult::unsupported_shape;
    }

    const AmountValue source =
        resolve_argument_amount(parsed, command_results, command.arguments[0]);
    if (!source.relevant) {
        return SuiTokenFlowFactsResult::unsupported_shape;
    }

    const uint16_t amount_count = static_cast<uint16_t>(command.argument_count - 1);
    for (uint16_t amount_index = 0; amount_index < amount_count; ++amount_index) {
        const SuiArgumentFact& amount_arg = command.arguments[amount_index + 1];
        CommandResultValue& result = command_results[command_index][amount_index];
        result.relevant = true;
        result.source_kind = SuiTokenFlowSourceKind::split_result;
        result.asset_state = source.asset_state;
        if (amount_arg.kind != SuiArgumentFactKind::input ||
            amount_arg.index >= parsed.input_count) {
            result.state = SuiTokenAmountState::incomplete;
            continue;
        }
        uint64_t amount = 0;
        if (!read_pure_u64(parsed.inputs[amount_arg.index], &amount)) {
            result.state = SuiTokenAmountState::incomplete;
            continue;
        }
        result.state = SuiTokenAmountState::known;
        result.value = amount;
    }
    return SuiTokenFlowFactsResult::ok;
}

SuiTokenFlowFactsResult handle_transfer_objects(
    const SuiParsedTransactionFacts& parsed,
    const SuiCommandFact& command,
    const CommandResultValue command_results
        [kSuiPolicyFactMaxCommands][kSuiPolicyFactMaxCommandArguments],
    SuiTokenFlowFacts* out,
    uint64_t* transfer_total,
    uint64_t* sui_total,
    uint64_t* recipient0_total,
    bool* transfer_has_known,
    bool* sui_has_known,
    bool* recipient0_has_known)
{
    if (command.argument_count == 0) {
        return SuiTokenFlowFactsResult::unsupported_shape;
    }

    const bool is_recipient0 = out->recipient_count == 0;
    const SuiArgumentFact& recipient_arg = command.arguments[command.argument_count - 1];
    if (is_recipient0 &&
        recipient_arg.kind == SuiArgumentFactKind::input &&
        recipient_arg.index < parsed.input_count) {
        out->recipient0_address_known = read_pure_address(
            parsed.inputs[recipient_arg.index],
            out->recipient0_address,
            sizeof(out->recipient0_address));
    }
    out->recipient_count += 1;

    for (uint16_t index = 0; index + 1 < command.argument_count; ++index) {
        const AmountValue amount =
            resolve_argument_amount(parsed, command_results, command.arguments[index]);
        if (!amount.relevant) {
            continue;
        }
        const SuiTokenAmountState aggregate_state = sui_amount_state(amount);
        out->transfer_total_out_state = combine_aggregate_state(
            out->transfer_total_out_state,
            transfer_has_known != nullptr && *transfer_has_known,
            aggregate_state);
        out->sui_total_out_state = combine_aggregate_state(
            out->sui_total_out_state,
            sui_has_known != nullptr && *sui_has_known,
            aggregate_state);
        if (is_recipient0) {
            out->recipient0_amount_state = combine_aggregate_state(
                out->recipient0_amount_state,
                recipient0_has_known != nullptr && *recipient0_has_known,
                aggregate_state);
        }
        if (aggregate_state == SuiTokenAmountState::known) {
            if (!add_checked(transfer_total, amount.value) ||
                !add_checked(sui_total, amount.value) ||
                (is_recipient0 && !add_checked(recipient0_total, amount.value))) {
                return SuiTokenFlowFactsResult::overflow;
            }
            if (transfer_has_known != nullptr) {
                *transfer_has_known = true;
            }
            if (sui_has_known != nullptr) {
                *sui_has_known = true;
            }
            if (is_recipient0 && recipient0_has_known != nullptr) {
                *recipient0_has_known = true;
            }
        }
        if (!append_flow(
                out,
                amount.source_kind,
                SuiTokenFlowSinkKind::transfer_recipient,
                amount.asset_state,
                amount.state,
                amount.value,
                amount.object_id)) {
            return SuiTokenFlowFactsResult::overflow;
        }
    }
    return SuiTokenFlowFactsResult::ok;
}

SuiTokenFlowFactsResult handle_move_call(
    const SuiParsedTransactionFacts& parsed,
    const SuiCommandFact& command,
    const CommandResultValue command_results
        [kSuiPolicyFactMaxCommands][kSuiPolicyFactMaxCommandArguments],
    SuiTokenFlowFacts* out,
    uint64_t* move_call_total,
    uint64_t* sui_total,
    uint64_t* move_call0_total,
    bool* move_call_has_known,
    bool* sui_has_known,
    bool* move_call0_has_known)
{
    const bool is_move_call0 = out->move_call_count == 0;
    if (is_move_call0) {
        if (!copy_c_string(out->move_call0_package, sizeof(out->move_call0_package), command.move_call.package) ||
            !copy_c_string(out->move_call0_module, sizeof(out->move_call0_module), command.move_call.module) ||
            !copy_c_string(out->move_call0_function, sizeof(out->move_call0_function), command.move_call.function)) {
            return SuiTokenFlowFactsResult::unsupported_shape;
        }
    }
    out->move_call_count += 1;

    for (uint16_t index = 0; index < command.argument_count; ++index) {
        const AmountValue amount =
            resolve_argument_amount(parsed, command_results, command.arguments[index]);
        if (!amount.relevant) {
            continue;
        }
        const SuiTokenAmountState aggregate_state = sui_amount_state(amount);
        out->move_call_total_in_state = combine_aggregate_state(
            out->move_call_total_in_state,
            move_call_has_known != nullptr && *move_call_has_known,
            aggregate_state);
        out->sui_total_out_state = combine_aggregate_state(
            out->sui_total_out_state,
            sui_has_known != nullptr && *sui_has_known,
            aggregate_state);
        if (is_move_call0) {
            out->move_call0_sui_amount_state = combine_aggregate_state(
                out->move_call0_sui_amount_state,
                move_call0_has_known != nullptr && *move_call0_has_known,
                aggregate_state);
        }
        if (aggregate_state == SuiTokenAmountState::known) {
            if (!add_checked(move_call_total, amount.value) ||
                !add_checked(sui_total, amount.value) ||
                (is_move_call0 && !add_checked(move_call0_total, amount.value))) {
                return SuiTokenFlowFactsResult::overflow;
            }
            if (move_call_has_known != nullptr) {
                *move_call_has_known = true;
            }
            if (sui_has_known != nullptr) {
                *sui_has_known = true;
            }
            if (is_move_call0 && move_call0_has_known != nullptr) {
                *move_call0_has_known = true;
            }
        }
        if (!append_flow(
                out,
                amount.source_kind,
                SuiTokenFlowSinkKind::move_call_argument,
                amount.asset_state,
                amount.state,
                amount.value,
                amount.object_id)) {
            return SuiTokenFlowFactsResult::overflow;
        }
    }
    return SuiTokenFlowFactsResult::ok;
}

SuiTokenFlowFactsResult handle_merge_coins(
    const SuiParsedTransactionFacts& parsed,
    const SuiCommandFact& command,
    CommandResultValue command_results
        [kSuiPolicyFactMaxCommands][kSuiPolicyFactMaxCommandArguments],
    SuiTokenFlowFacts* out,
    uint64_t* merge_total,
    bool* merge_has_known)
{
    if (command.argument_count < 2) {
        return SuiTokenFlowFactsResult::unsupported_shape;
    }

    const AmountValue destination =
        resolve_argument_amount(parsed, command_results, command.arguments[0]);
    if (!destination.relevant) {
        return SuiTokenFlowFactsResult::unsupported_shape;
    }

    SuiTokenAmountState merged_state = destination.state;
    SuiTokenAssetState merged_asset_state = destination.asset_state;
    uint64_t merged_value = destination.value;
    bool merged_has_known = destination.state == SuiTokenAmountState::known;

    for (uint16_t index = 1; index < command.argument_count; ++index) {
        const AmountValue amount =
            resolve_argument_amount(parsed, command_results, command.arguments[index]);
        if (!amount.relevant) {
            continue;
        }
        merged_state = combine_aggregate_state(merged_state, merged_has_known, amount.state);
        merged_asset_state = combine_asset_state(merged_asset_state, amount.asset_state);
        if (amount.state == SuiTokenAmountState::known) {
            if (!add_checked(&merged_value, amount.value)) {
                return SuiTokenFlowFactsResult::overflow;
            }
            merged_has_known = true;
        }
        if (!append_flow(
                out,
                amount.source_kind,
                SuiTokenFlowSinkKind::merge_destination,
                amount.asset_state,
                amount.state,
                amount.value,
                amount.object_id)) {
            return SuiTokenFlowFactsResult::overflow;
        }
    }

    out->merge_total_state = combine_aggregate_state(
        out->merge_total_state,
        merge_has_known != nullptr && *merge_has_known,
        merged_state);
    if (merged_state == SuiTokenAmountState::known) {
        if (!add_checked(merge_total, merged_value)) {
            return SuiTokenFlowFactsResult::overflow;
        }
        if (merge_has_known != nullptr) {
            *merge_has_known = true;
        }
    }

    CommandResultValue* destination_result =
        mutable_command_result_for_argument(command_results, command.arguments[0]);
    if (destination_result != nullptr) {
        destination_result->relevant = true;
        destination_result->state = merged_state;
        destination_result->asset_state = merged_asset_state;
        destination_result->value = merged_state == SuiTokenAmountState::known ? merged_value : 0;
        destination_result->source_kind = SuiTokenFlowSourceKind::merge_result;
        if (destination.object_id != nullptr && destination.object_id[0] != '\0') {
            copy_c_string(
                destination_result->object_id,
                sizeof(destination_result->object_id),
                destination.object_id);
        } else {
            destination_result->object_id[0] = '\0';
        }
    }
    return SuiTokenFlowFactsResult::ok;
}

}  // namespace

const char* sui_token_flow_facts_result_name(SuiTokenFlowFactsResult result)
{
    switch (result) {
        case SuiTokenFlowFactsResult::ok:
            return "ok";
        case SuiTokenFlowFactsResult::invalid_argument:
            return "invalid_argument";
        case SuiTokenFlowFactsResult::unsupported_shape:
            return "unsupported_shape";
        case SuiTokenFlowFactsResult::invalid_amount:
            return "invalid_amount";
        case SuiTokenFlowFactsResult::overflow:
            return "overflow";
    }
    return "unknown";
}

const char* sui_token_amount_state_name(SuiTokenAmountState state)
{
    switch (state) {
        case SuiTokenAmountState::known:
            return "known";
        case SuiTokenAmountState::unknown:
            return "unknown";
        case SuiTokenAmountState::incomplete:
            return "incomplete";
    }
    return "unknown";
}

const char* sui_token_asset_state_name(SuiTokenAssetState state)
{
    switch (state) {
        case SuiTokenAssetState::proven_sui:
            return "proven_sui";
        case SuiTokenAssetState::unproven:
            return "unproven";
    }
    return "unknown";
}

SuiTokenFlowFactsResult build_sui_token_flow_facts(
    const SuiParsedTransactionFacts& parsed,
    SuiTokenFlowFacts* out)
{
    if (out == nullptr) {
        return SuiTokenFlowFactsResult::invalid_argument;
    }
    *out = {};
    out->sui_total_out_state = SuiTokenAmountState::known;
    out->transfer_total_out_state = SuiTokenAmountState::known;
    out->move_call_total_in_state = SuiTokenAmountState::known;
    out->merge_total_state = SuiTokenAmountState::known;
    out->recipient0_amount_state = SuiTokenAmountState::known;
    out->move_call0_sui_amount_state = SuiTokenAmountState::known;
    copy_c_string(out->recipient0_address, sizeof(out->recipient0_address), "none");
    copy_c_string(out->move_call0_package, sizeof(out->move_call0_package), "none");
    copy_c_string(out->move_call0_module, sizeof(out->move_call0_module), "none");
    copy_c_string(out->move_call0_function, sizeof(out->move_call0_function), "none");

    if (parsed.transaction_data_version != SuiTransactionDataVersionFact::v1 ||
        parsed.transaction_kind != SuiTransactionKindFact::programmable_transaction) {
        return SuiTokenFlowFactsResult::unsupported_shape;
    }

    CommandResultValue command_results
        [kSuiPolicyFactMaxCommands][kSuiPolicyFactMaxCommandArguments] = {};
    uint64_t sui_total = 0;
    uint64_t transfer_total = 0;
    uint64_t move_call_total = 0;
    uint64_t merge_total = 0;
    uint64_t recipient0_total = 0;
    uint64_t move_call0_total = 0;
    bool sui_has_known = false;
    bool transfer_has_known = false;
    bool move_call_has_known = false;
    bool merge_has_known = false;
    bool recipient0_has_known = false;
    bool move_call0_has_known = false;

    for (uint16_t command_index = 0; command_index < parsed.command_count; ++command_index) {
        const SuiCommandFact& command = parsed.commands[command_index];
        SuiTokenFlowFactsResult result = SuiTokenFlowFactsResult::ok;
        switch (command.kind) {
            case SuiCommandFactKind::split_coins:
                result = handle_split_coins(parsed, command, command_index, command_results);
                break;
            case SuiCommandFactKind::transfer_objects:
                result = handle_transfer_objects(
                    parsed,
                    command,
                    command_results,
                    out,
                    &transfer_total,
                    &sui_total,
                    &recipient0_total,
                    &transfer_has_known,
                    &sui_has_known,
                    &recipient0_has_known);
                break;
            case SuiCommandFactKind::move_call:
                result = handle_move_call(
                    parsed,
                    command,
                    command_results,
                    out,
                    &move_call_total,
                    &sui_total,
                    &move_call0_total,
                    &move_call_has_known,
                    &sui_has_known,
                    &move_call0_has_known);
                break;
            case SuiCommandFactKind::merge_coins:
                result = handle_merge_coins(
                    parsed,
                    command,
                    command_results,
                    out,
                    &merge_total,
                    &merge_has_known);
                break;
            case SuiCommandFactKind::publish:
            case SuiCommandFactKind::make_move_vec:
            case SuiCommandFactKind::upgrade:
                break;
            case SuiCommandFactKind::unsupported:
                return SuiTokenFlowFactsResult::unsupported_shape;
        }
        if (result != SuiTokenFlowFactsResult::ok) {
            return result;
        }
    }

    if (!set_aggregate_decimal(
            out->sui_total_out_state,
            sui_total,
            out->sui_total_out_raw,
            sizeof(out->sui_total_out_raw)) ||
        !set_aggregate_decimal(
            out->transfer_total_out_state,
            transfer_total,
            out->transfer_total_out_raw,
            sizeof(out->transfer_total_out_raw)) ||
        !set_aggregate_decimal(
            out->move_call_total_in_state,
            move_call_total,
            out->move_call_total_in_raw,
            sizeof(out->move_call_total_in_raw)) ||
        !set_aggregate_decimal(
            out->merge_total_state,
            merge_total,
            out->merge_total_raw,
            sizeof(out->merge_total_raw)) ||
        !set_aggregate_decimal(
            out->recipient0_amount_state,
            recipient0_total,
            out->recipient0_amount_raw,
            sizeof(out->recipient0_amount_raw)) ||
        !set_aggregate_decimal(
            out->move_call0_sui_amount_state,
            move_call0_total,
            out->move_call0_sui_amount_raw,
            sizeof(out->move_call0_sui_amount_raw))) {
        return SuiTokenFlowFactsResult::overflow;
    }

    return SuiTokenFlowFactsResult::ok;
}

}  // namespace agent_q
