#include "agent_q_sui_method_adapter.h"

#include <stdio.h>
#include <string.h>

namespace agent_q {
namespace {

static_assert(
    kSuiPolicyFactMaxCommands == 8,
    "Sui policy field names are defined for the bounded command capacity");

constexpr const char* kCommandKindFields[kSuiPolicyFactMaxCommands] = {
    "sui.command0_kind",
    "sui.command1_kind",
    "sui.command2_kind",
    "sui.command3_kind",
    "sui.command4_kind",
    "sui.command5_kind",
    "sui.command6_kind",
    "sui.command7_kind",
};

constexpr const char* kCommandMoveCallPackageFields[kSuiPolicyFactMaxCommands] = {
    "sui.command0_move_call_package",
    "sui.command1_move_call_package",
    "sui.command2_move_call_package",
    "sui.command3_move_call_package",
    "sui.command4_move_call_package",
    "sui.command5_move_call_package",
    "sui.command6_move_call_package",
    "sui.command7_move_call_package",
};

constexpr const char* kCommandMoveCallModuleFields[kSuiPolicyFactMaxCommands] = {
    "sui.command0_move_call_module",
    "sui.command1_move_call_module",
    "sui.command2_move_call_module",
    "sui.command3_move_call_module",
    "sui.command4_move_call_module",
    "sui.command5_move_call_module",
    "sui.command6_move_call_module",
    "sui.command7_move_call_module",
};

constexpr const char* kCommandMoveCallFunctionFields[kSuiPolicyFactMaxCommands] = {
    "sui.command0_move_call_function",
    "sui.command1_move_call_function",
    "sui.command2_move_call_function",
    "sui.command3_move_call_function",
    "sui.command4_move_call_function",
    "sui.command5_move_call_function",
    "sui.command6_move_call_function",
    "sui.command7_move_call_function",
};

constexpr const char* kCommandMoveCallTypeArgCountFields[kSuiPolicyFactMaxCommands] = {
    "sui.command0_move_call_type_args",
    "sui.command1_move_call_type_args",
    "sui.command2_move_call_type_args",
    "sui.command3_move_call_type_args",
    "sui.command4_move_call_type_args",
    "sui.command5_move_call_type_args",
    "sui.command6_move_call_type_args",
    "sui.command7_move_call_type_args",
};

static_assert(
    kSuiPolicyFactMaxTypeArguments == 4,
    "Sui policy MoveCall type argument field names are defined for the bounded type-argument capacity");

constexpr const char* kCommandMoveCallTypeArgFields
    [kSuiPolicyFactMaxCommands][kSuiPolicyFactMaxTypeArguments] = {
        {
            "sui.command0_move_call_type_arg0",
            "sui.command0_move_call_type_arg1",
            "sui.command0_move_call_type_arg2",
            "sui.command0_move_call_type_arg3",
        },
        {
            "sui.command1_move_call_type_arg0",
            "sui.command1_move_call_type_arg1",
            "sui.command1_move_call_type_arg2",
            "sui.command1_move_call_type_arg3",
        },
        {
            "sui.command2_move_call_type_arg0",
            "sui.command2_move_call_type_arg1",
            "sui.command2_move_call_type_arg2",
            "sui.command2_move_call_type_arg3",
        },
        {
            "sui.command3_move_call_type_arg0",
            "sui.command3_move_call_type_arg1",
            "sui.command3_move_call_type_arg2",
            "sui.command3_move_call_type_arg3",
        },
        {
            "sui.command4_move_call_type_arg0",
            "sui.command4_move_call_type_arg1",
            "sui.command4_move_call_type_arg2",
            "sui.command4_move_call_type_arg3",
        },
        {
            "sui.command5_move_call_type_arg0",
            "sui.command5_move_call_type_arg1",
            "sui.command5_move_call_type_arg2",
            "sui.command5_move_call_type_arg3",
        },
        {
            "sui.command6_move_call_type_arg0",
            "sui.command6_move_call_type_arg1",
            "sui.command6_move_call_type_arg2",
            "sui.command6_move_call_type_arg3",
        },
        {
            "sui.command7_move_call_type_arg0",
            "sui.command7_move_call_type_arg1",
            "sui.command7_move_call_type_arg2",
            "sui.command7_move_call_type_arg3",
        },
    };

constexpr AgentQPolicyFieldDescriptor kSuiSignTransactionPolicyFields[] = {
    {"sui.transaction_kind", AgentQPolicyValueType::string, true, true, false},
    {"sui.sender_address", AgentQPolicyValueType::string, true, true, false},
    {"sui.gas_owner_address", AgentQPolicyValueType::string, true, true, false},
    {"sui.command_count", AgentQPolicyValueType::u64_decimal, true, false, true},
    {"sui.gas_budget", AgentQPolicyValueType::u64_decimal, true, false, true},
    {"sui.gas_price", AgentQPolicyValueType::u64_decimal, true, false, true},
    {"sui.expiration_kind", AgentQPolicyValueType::string, true, true, false},
    {kCommandKindFields[0], AgentQPolicyValueType::string, true, true, false},
    {kCommandKindFields[1], AgentQPolicyValueType::string, true, true, false},
    {kCommandKindFields[2], AgentQPolicyValueType::string, true, true, false},
    {kCommandKindFields[3], AgentQPolicyValueType::string, true, true, false},
    {kCommandKindFields[4], AgentQPolicyValueType::string, true, true, false},
    {kCommandKindFields[5], AgentQPolicyValueType::string, true, true, false},
    {kCommandKindFields[6], AgentQPolicyValueType::string, true, true, false},
    {kCommandKindFields[7], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallPackageFields[0], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallPackageFields[1], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallPackageFields[2], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallPackageFields[3], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallPackageFields[4], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallPackageFields[5], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallPackageFields[6], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallPackageFields[7], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallModuleFields[0], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallModuleFields[1], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallModuleFields[2], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallModuleFields[3], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallModuleFields[4], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallModuleFields[5], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallModuleFields[6], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallModuleFields[7], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallFunctionFields[0], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallFunctionFields[1], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallFunctionFields[2], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallFunctionFields[3], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallFunctionFields[4], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallFunctionFields[5], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallFunctionFields[6], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallFunctionFields[7], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgCountFields[0], AgentQPolicyValueType::u64_decimal, true, false, true},
    {kCommandMoveCallTypeArgCountFields[1], AgentQPolicyValueType::u64_decimal, true, false, true},
    {kCommandMoveCallTypeArgCountFields[2], AgentQPolicyValueType::u64_decimal, true, false, true},
    {kCommandMoveCallTypeArgCountFields[3], AgentQPolicyValueType::u64_decimal, true, false, true},
    {kCommandMoveCallTypeArgCountFields[4], AgentQPolicyValueType::u64_decimal, true, false, true},
    {kCommandMoveCallTypeArgCountFields[5], AgentQPolicyValueType::u64_decimal, true, false, true},
    {kCommandMoveCallTypeArgCountFields[6], AgentQPolicyValueType::u64_decimal, true, false, true},
    {kCommandMoveCallTypeArgCountFields[7], AgentQPolicyValueType::u64_decimal, true, false, true},
    {kCommandMoveCallTypeArgFields[0][0], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[0][1], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[0][2], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[0][3], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[1][0], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[1][1], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[1][2], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[1][3], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[2][0], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[2][1], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[2][2], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[2][3], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[3][0], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[3][1], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[3][2], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[3][3], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[4][0], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[4][1], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[4][2], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[4][3], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[5][0], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[5][1], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[5][2], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[5][3], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[6][0], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[6][1], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[6][2], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[6][3], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[7][0], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[7][1], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[7][2], AgentQPolicyValueType::string, true, true, false},
    {kCommandMoveCallTypeArgFields[7][3], AgentQPolicyValueType::string, true, true, false},
};

static_assert(
    sizeof(kSuiSignTransactionPolicyFields) / sizeof(kSuiSignTransactionPolicyFields[0]) <=
        kAgentQPolicyMaxFieldDescriptors,
    "Sui sign_transaction policy descriptor count exceeds policy capacity");

bool string_present(const char* value)
{
    return value != nullptr && value[0] != '\0';
}

bool format_u16(uint16_t value, char* out, size_t out_size)
{
    const int written = snprintf(out, out_size, "%u", static_cast<unsigned>(value));
    return written >= 0 && static_cast<size_t>(written) < out_size;
}

const char* command_kind_policy_name(SuiCommandFactKind kind)
{
    switch (kind) {
        case SuiCommandFactKind::move_call:
            return kAgentQSuiPolicyCommandKindMoveCall;
        case SuiCommandFactKind::transfer_objects:
            return kAgentQSuiPolicyCommandKindTransferObjects;
        case SuiCommandFactKind::split_coins:
            return kAgentQSuiPolicyCommandKindSplitCoins;
        case SuiCommandFactKind::merge_coins:
            return "merge_coins";
        case SuiCommandFactKind::publish:
            return "publish";
        case SuiCommandFactKind::make_move_vec:
            return "make_move_vec";
        case SuiCommandFactKind::upgrade:
            return "upgrade";
        case SuiCommandFactKind::unsupported:
            break;
    }
    return nullptr;
}

const char* expiration_kind_policy_name(SuiTransactionExpirationFact kind)
{
    switch (kind) {
        case SuiTransactionExpirationFact::none:
            return "none";
        case SuiTransactionExpirationFact::epoch:
            return "epoch";
        case SuiTransactionExpirationFact::valid_during:
            return "valid_during";
    }
    return nullptr;
}

bool base_facts_supported(const SuiPolicySubjectFacts& sui_facts)
{
    return sui_facts.transaction_kind == SuiTransactionKindFact::programmable_transaction &&
           string_present(sui_facts.sender) &&
           string_present(sui_facts.gas_owner) &&
           string_present(sui_facts.gas_budget) &&
           string_present(sui_facts.gas_price) &&
           sui_facts.command_count > 0 &&
           sui_facts.command_count <= kSuiPolicyFactMaxCommands &&
           expiration_kind_policy_name(sui_facts.expiration_kind) != nullptr;
}

bool add_fact(
    AgentQSuiSignTransactionPolicyFacts* out,
    size_t* index,
    const char* field,
    AgentQPolicyValueType type,
    const char* value)
{
    if (out == nullptr ||
        index == nullptr ||
        *index >= kAgentQSuiSignTransactionPolicyFactCount ||
        !string_present(field) ||
        !string_present(value)) {
        return false;
    }
    out->entries[(*index)++] = AgentQPolicyFact{field, type, value};
    return true;
}

bool add_command_facts(
    const SuiPolicySubjectFacts& sui_facts,
    AgentQSuiSignTransactionPolicyFacts* out,
    size_t* index)
{
    for (uint16_t command_index = 0; command_index < sui_facts.command_count; ++command_index) {
        const SuiPolicyCommandFact& command = sui_facts.commands[command_index];
        const char* kind = command_kind_policy_name(command.kind);
        if (!string_present(kind) ||
            !add_fact(
                out,
                index,
                kCommandKindFields[command_index],
                AgentQPolicyValueType::string,
                kind)) {
            return false;
        }
        if (!command.has_move_call) {
            continue;
        }
        if (!string_present(command.move_call_package) ||
            !string_present(command.move_call_module) ||
            !string_present(command.move_call_function) ||
            !format_u16(
                command.type_argument_count,
                out->command_type_argument_counts[command_index],
                sizeof(out->command_type_argument_counts[command_index]))) {
            return false;
        }
        if (!add_fact(
                out,
                index,
                kCommandMoveCallPackageFields[command_index],
                AgentQPolicyValueType::string,
                command.move_call_package) ||
            !add_fact(
                out,
                index,
                kCommandMoveCallModuleFields[command_index],
                AgentQPolicyValueType::string,
                command.move_call_module) ||
            !add_fact(
                out,
                index,
                kCommandMoveCallFunctionFields[command_index],
                AgentQPolicyValueType::string,
                command.move_call_function) ||
            !add_fact(
                out,
                index,
                kCommandMoveCallTypeArgCountFields[command_index],
                AgentQPolicyValueType::u64_decimal,
                out->command_type_argument_counts[command_index])) {
            return false;
        }
        if (command.type_argument_count > kSuiPolicyFactMaxTypeArguments) {
            return false;
        }
        for (uint16_t type_arg_index = 0; type_arg_index < command.type_argument_count; ++type_arg_index) {
            if (!add_fact(
                    out,
                    index,
                    kCommandMoveCallTypeArgFields[command_index][type_arg_index],
                    AgentQPolicyValueType::string,
                    command.move_call_type_args[type_arg_index])) {
                return false;
            }
        }
    }
    return true;
}

}  // namespace

bool make_sui_sign_transaction_policy_facts(
    const SuiPolicySubjectFacts& sui_facts,
    AgentQSuiSignTransactionPolicyFacts* out)
{
    if (out == nullptr) {
        return false;
    }
    *out = {};

    if (!base_facts_supported(sui_facts) ||
        !format_u16(sui_facts.command_count, out->command_count, sizeof(out->command_count))) {
        return false;
    }

    size_t index = 0;
    if (!add_fact(out, &index, "common.chain", AgentQPolicyValueType::string, kAgentQSuiPolicyChain) ||
        !add_fact(
            out,
            &index,
            "common.method",
            AgentQPolicyValueType::string,
            kAgentQSuiPolicyOperationSignTransaction) ||
        !add_fact(
            out,
            &index,
            "common.intent",
            AgentQPolicyValueType::string,
            kAgentQPolicyIntentProgrammableTransaction) ||
        !add_fact(
            out,
            &index,
            "sui.transaction_kind",
            AgentQPolicyValueType::string,
            "programmable_transaction") ||
        !add_fact(
            out,
            &index,
            "sui.sender_address",
            AgentQPolicyValueType::string,
            sui_facts.sender) ||
        !add_fact(
            out,
            &index,
            "sui.gas_owner_address",
            AgentQPolicyValueType::string,
            sui_facts.gas_owner) ||
        !add_fact(
            out,
            &index,
            "sui.command_count",
            AgentQPolicyValueType::u64_decimal,
            out->command_count) ||
        !add_fact(
            out,
            &index,
            "sui.gas_budget",
            AgentQPolicyValueType::u64_decimal,
            sui_facts.gas_budget) ||
        !add_fact(
            out,
            &index,
            "sui.gas_price",
            AgentQPolicyValueType::u64_decimal,
            sui_facts.gas_price) ||
        !add_fact(
            out,
            &index,
            "sui.expiration_kind",
            AgentQPolicyValueType::string,
            expiration_kind_policy_name(sui_facts.expiration_kind)) ||
        !add_command_facts(sui_facts, out, &index)) {
        *out = {};
        return false;
    }

    out->facts = AgentQPolicyFacts{
        out->entries,
        index,
        kSuiSignTransactionPolicyFields,
        sizeof(kSuiSignTransactionPolicyFields) / sizeof(kSuiSignTransactionPolicyFields[0]),
    };
    return true;
}

AgentQPolicyMethodDescriptor sui_sign_transaction_policy_method_descriptor()
{
    return AgentQPolicyMethodDescriptor{
        kAgentQSuiPolicyChain,
        kAgentQSuiPolicyOperationSignTransaction,
        kSuiSignTransactionPolicyFields,
        sizeof(kSuiSignTransactionPolicyFields) / sizeof(kSuiSignTransactionPolicyFields[0]),
        true,
        false,
    };
}

}  // namespace agent_q
