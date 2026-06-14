#include "agent_q_sui_method_adapter.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "agent_q_sui_network.h"
#include "../policy/agent_q_policy_u64.h"

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

// Projection of specs/sui-sign-transaction-policy-contract.tsv for the
// Firmware policy method descriptor. Firmware remains the runtime authority;
// host tests verify this descriptor against the shared manifest.
constexpr AgentQPolicyFieldDescriptor kSuiSignTransactionPolicyFields[] = {
    {"sui.transaction_kind", AgentQPolicyValueType::string, true, true, false},
    {"sui.sender_address", AgentQPolicyValueType::string, true, true, false},
    {"sui.gas_owner_address", AgentQPolicyValueType::string, true, true, false},
    {"sui.command_count", AgentQPolicyValueType::u64_decimal, true, false, true},
    {"sui.gas_budget", AgentQPolicyValueType::u64_decimal, true, false, true},
    {"sui.gas_price", AgentQPolicyValueType::u64_decimal, true, false, true},
    {"sui.expiration_kind", AgentQPolicyValueType::string, true, true, false},
    {"sui.sui_total_out_complete", AgentQPolicyValueType::string, true, false, false},
    {"sui.sui_total_out_raw", AgentQPolicyValueType::u64_decimal, true, true, true},
    {"sui.transfer_total_out_raw", AgentQPolicyValueType::u64_decimal, true, true, true},
    {"sui.move_call_total_in_raw", AgentQPolicyValueType::u64_decimal, true, true, true},
    {"sui.recipient_count", AgentQPolicyValueType::u64_decimal, true, true, true},
    {"sui.recipient0_address", AgentQPolicyValueType::string, true, true, false},
    {"sui.recipient0_amount_raw", AgentQPolicyValueType::u64_decimal, true, true, true},
    {"sui.move_call0_package", AgentQPolicyValueType::string, true, true, false},
    {"sui.move_call0_module", AgentQPolicyValueType::string, true, true, false},
    {"sui.move_call0_function", AgentQPolicyValueType::string, true, true, false},
    {"sui.move_call0_sui_amount_raw", AgentQPolicyValueType::u64_decimal, true, true, true},
    {"sui.coin_flow0_source_kind", AgentQPolicyValueType::string, true, true, false},
    {"sui.coin_flow0_asset_state", AgentQPolicyValueType::string, true, true, false},
    {"sui.coin_flow0_amount_known", AgentQPolicyValueType::string, true, false, false},
    {"sui.coin_flow0_amount_raw", AgentQPolicyValueType::u64_decimal, true, true, true},
    {"sui.coin_flow0_sink_kind", AgentQPolicyValueType::string, true, true, false},
    {"sui.coin_flow0_object_id", AgentQPolicyValueType::string, true, true, false},
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

bool string_eq(const char* left, const char* right)
{
    return left != nullptr && right != nullptr && strcmp(left, right) == 0;
}

bool format_u16(uint16_t value, char* out, size_t out_size)
{
    const int written = snprintf(out, out_size, "%u", static_cast<unsigned>(value));
    return written >= 0 && static_cast<size_t>(written) < out_size;
}

const char* policy_bool(bool value)
{
    return value ? "yes" : "no";
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
            return kAgentQSuiPolicyCommandKindMergeCoins;
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

const AgentQPolicyCriterion* find_criterion(
    const AgentQPolicyRule& rule,
    const char* field)
{
    if (field == nullptr || rule.criteria == nullptr) {
        return nullptr;
    }
    for (size_t index = 0; index < rule.criterion_count; ++index) {
        const AgentQPolicyCriterion& criterion = rule.criteria[index];
        if (string_eq(criterion.field, field)) {
            return &criterion;
        }
    }
    return nullptr;
}

enum class SuiRequiredSignBoundKind {
    eq,
    string,
    string_eq,
    lte,
};

struct SuiRequiredSignBound {
    SuiRequiredSignBoundKind kind;
    const char* field;
    const char* value;
};

// Keep this bounded sign-rule contract aligned with the shared manifest above.
constexpr SuiRequiredSignBound kSuiSignTransactionRequiredSignBounds[] = {
    {SuiRequiredSignBoundKind::eq, "common.chain", kAgentQSuiPolicyChain},
    {SuiRequiredSignBoundKind::eq, "common.method", kAgentQSuiPolicyOperationSignTransaction},
    {SuiRequiredSignBoundKind::eq, "common.intent", kAgentQPolicyIntentProgrammableTransaction},
    {SuiRequiredSignBoundKind::eq, "sui.transaction_kind", kAgentQPolicyIntentProgrammableTransaction},
    {SuiRequiredSignBoundKind::string, "sui.sender_address", nullptr},
    {SuiRequiredSignBoundKind::string, "sui.gas_owner_address", nullptr},
    {SuiRequiredSignBoundKind::lte, "sui.gas_budget", nullptr},
    {SuiRequiredSignBoundKind::lte, "sui.gas_price", nullptr},
    {SuiRequiredSignBoundKind::string, "sui.expiration_kind", nullptr},
    {SuiRequiredSignBoundKind::eq, "sui.sui_total_out_complete", "yes"},
    {SuiRequiredSignBoundKind::lte, "sui.sui_total_out_raw", nullptr},
    {SuiRequiredSignBoundKind::eq, "sui.command_count", "2"},
    {SuiRequiredSignBoundKind::eq, kCommandKindFields[0], kAgentQSuiPolicyCommandKindSplitCoins},
    {SuiRequiredSignBoundKind::eq, kCommandKindFields[1], kAgentQSuiPolicyCommandKindTransferObjects},
    {SuiRequiredSignBoundKind::eq, "sui.recipient_count", "1"},
    {SuiRequiredSignBoundKind::string_eq, "sui.recipient0_address", nullptr},
    {SuiRequiredSignBoundKind::lte, "sui.recipient0_amount_raw", nullptr},
    {SuiRequiredSignBoundKind::eq, "sui.coin_flow0_source_kind", "split_result"},
    {SuiRequiredSignBoundKind::eq, "sui.coin_flow0_asset_state", "proven_sui"},
    {SuiRequiredSignBoundKind::eq, "sui.coin_flow0_amount_known", "yes"},
    {SuiRequiredSignBoundKind::eq, "sui.coin_flow0_sink_kind", "transfer_recipient"},
};

bool criterion_eq_value(const AgentQPolicyCriterion* criterion, const char* value)
{
    return criterion != nullptr &&
           criterion->op == AgentQPolicyOperator::eq &&
           string_eq(criterion->value, value) &&
           criterion->values == nullptr &&
           criterion->value_count == 0;
}

bool criterion_lte_bound_present(const AgentQPolicyCriterion* criterion)
{
    return criterion != nullptr &&
           criterion->op == AgentQPolicyOperator::lte &&
           agent_q_policy_is_canonical_decimal_u64_string(criterion->value) &&
           criterion->values == nullptr &&
           criterion->value_count == 0;
}

bool string_criterion_bounded(const AgentQPolicyCriterion* criterion)
{
    if (criterion == nullptr) {
        return false;
    }
    if (criterion->op == AgentQPolicyOperator::eq) {
        return string_present(criterion->value) &&
               criterion->values == nullptr &&
               criterion->value_count == 0;
    }
    if (criterion->op != AgentQPolicyOperator::in ||
        criterion->value != nullptr ||
        criterion->values == nullptr ||
        criterion->value_count == 0 ||
        criterion->value_count > kAgentQPolicyMaxCriterionValues) {
        return false;
    }
    for (size_t index = 0; index < criterion->value_count; ++index) {
        if (!string_present(criterion->values[index])) {
            return false;
        }
    }
    return true;
}

bool string_eq_bound_present(const AgentQPolicyCriterion* criterion)
{
    return criterion != nullptr &&
           criterion->op == AgentQPolicyOperator::eq &&
           string_present(criterion->value) &&
           criterion->values == nullptr &&
           criterion->value_count == 0;
}

const char* criterion_string_eq_value(const AgentQPolicyCriterion* criterion)
{
    if (!string_eq_bound_present(criterion)) {
        return nullptr;
    }
    return criterion->value;
}

const char* criterion_lte_value(const AgentQPolicyCriterion* criterion)
{
    if (!criterion_lte_bound_present(criterion)) {
        return nullptr;
    }
    return criterion->value;
}

void format_short_address(const char* input, char* output, size_t output_size)
{
    if (output == nullptr || output_size == 0) {
        return;
    }
    output[0] = '\0';
    if (!string_present(input)) {
        return;
    }
    const size_t length = strlen(input);
    if (length <= 18 || output_size < 14) {
        snprintf(output, output_size, "%s", input);
        return;
    }
    snprintf(
        output,
        output_size,
        "%.6s..%.4s",
        input,
        input + length - 4);
}

bool required_sign_bound_present(
    const AgentQPolicyRule& rule,
    const SuiRequiredSignBound& bound)
{
    const AgentQPolicyCriterion* criterion = find_criterion(rule, bound.field);
    switch (bound.kind) {
        case SuiRequiredSignBoundKind::eq:
            return criterion_eq_value(criterion, bound.value);
        case SuiRequiredSignBoundKind::string:
            return string_criterion_bounded(criterion);
        case SuiRequiredSignBoundKind::string_eq:
            return string_eq_bound_present(criterion);
        case SuiRequiredSignBoundKind::lte:
            return criterion_lte_bound_present(criterion);
    }
    return false;
}

bool sui_sign_rule_has_required_bounds(const AgentQPolicyRule& rule)
{
    for (const SuiRequiredSignBound& bound : kSuiSignTransactionRequiredSignBounds) {
        if (!required_sign_bound_present(rule, bound)) {
            return false;
        }
    }
    return true;
}

const char* token_flow_source_kind_policy_name(SuiTokenFlowSourceKind kind)
{
    switch (kind) {
        case SuiTokenFlowSourceKind::gas_coin:
            return "gas_coin";
        case SuiTokenFlowSourceKind::split_result:
            return "split_result";
        case SuiTokenFlowSourceKind::direct_object:
            return "direct_object";
        case SuiTokenFlowSourceKind::funds_withdrawal:
            return "funds_withdrawal";
        case SuiTokenFlowSourceKind::merge_result:
            return "merge_result";
        case SuiTokenFlowSourceKind::unknown:
            return "unknown";
    }
    return nullptr;
}

const char* token_flow_sink_kind_policy_name(SuiTokenFlowSinkKind kind)
{
    switch (kind) {
        case SuiTokenFlowSinkKind::transfer_recipient:
            return "transfer_recipient";
        case SuiTokenFlowSinkKind::move_call_argument:
            return "move_call_argument";
        case SuiTokenFlowSinkKind::merge_destination:
            return "merge_destination";
        case SuiTokenFlowSinkKind::unknown:
            return "unknown";
    }
    return nullptr;
}

const char* token_flow_asset_state_policy_name(SuiTokenAssetState state)
{
    switch (state) {
        case SuiTokenAssetState::proven_sui:
            return "proven_sui";
        case SuiTokenAssetState::unproven:
            return "unproven";
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

bool transfer_objects_policy_coverage_complete(const SuiTokenFlowFacts& token_flow)
{
    return token_flow.recipient_count == 1 &&
           token_flow.recipient0_address_known &&
           string_present(token_flow.recipient0_address) &&
           token_flow.recipient0_amount_state == SuiTokenAmountState::known &&
           token_flow.flow_count == 1 &&
           token_flow.flows[0].source_kind == SuiTokenFlowSourceKind::split_result &&
           token_flow.flows[0].sink_kind == SuiTokenFlowSinkKind::transfer_recipient &&
           token_flow.flows[0].asset_state == SuiTokenAssetState::proven_sui &&
           token_flow.flows[0].amount_state == SuiTokenAmountState::known;
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

bool add_known_amount_fact(
    AgentQSuiSignTransactionPolicyFacts* out,
    size_t* index,
    const char* field,
    SuiTokenAmountState state,
    const char* amount_raw)
{
    if (state != SuiTokenAmountState::known) {
        return true;
    }
    return add_fact(out, index, field, AgentQPolicyValueType::u64_decimal, amount_raw);
}

bool add_token_flow_facts(
    const SuiTokenFlowFacts& token_flow,
    AgentQSuiSignTransactionPolicyFacts* out,
    size_t* index)
{
    if (out == nullptr ||
        index == nullptr ||
        !format_u16(
            token_flow.recipient_count,
            out->recipient_count,
            sizeof(out->recipient_count))) {
        return false;
    }

    if (!add_fact(
            out,
            index,
            "sui.sui_total_out_complete",
            AgentQPolicyValueType::string,
            policy_bool(token_flow.sui_total_out_state == SuiTokenAmountState::known)) ||
        !add_known_amount_fact(
            out,
            index,
            "sui.sui_total_out_raw",
            token_flow.sui_total_out_state,
            token_flow.sui_total_out_raw) ||
        !add_known_amount_fact(
            out,
            index,
            "sui.transfer_total_out_raw",
            token_flow.transfer_total_out_state,
            token_flow.transfer_total_out_raw) ||
        !add_known_amount_fact(
            out,
            index,
            "sui.move_call_total_in_raw",
            token_flow.move_call_total_in_state,
            token_flow.move_call_total_in_raw) ||
        !add_fact(
            out,
            index,
            "sui.recipient_count",
            AgentQPolicyValueType::u64_decimal,
            out->recipient_count)) {
        return false;
    }

    if (token_flow.recipient_count > 0) {
        if (token_flow.recipient0_address_known &&
            string_present(token_flow.recipient0_address) &&
            !add_fact(
                out,
                index,
                "sui.recipient0_address",
                AgentQPolicyValueType::string,
                token_flow.recipient0_address)) {
            return false;
        }
        if (!add_known_amount_fact(
                out,
                index,
                "sui.recipient0_amount_raw",
                token_flow.recipient0_amount_state,
                token_flow.recipient0_amount_raw)) {
            return false;
        }
    }

    if (token_flow.move_call_count > 0) {
        if (string_present(token_flow.move_call0_package) &&
            !add_fact(
                out,
                index,
                "sui.move_call0_package",
                AgentQPolicyValueType::string,
                token_flow.move_call0_package)) {
            return false;
        }
        if (string_present(token_flow.move_call0_module) &&
            !add_fact(
                out,
                index,
                "sui.move_call0_module",
                AgentQPolicyValueType::string,
                token_flow.move_call0_module)) {
            return false;
        }
        if (string_present(token_flow.move_call0_function) &&
            !add_fact(
                out,
                index,
                "sui.move_call0_function",
                AgentQPolicyValueType::string,
                token_flow.move_call0_function)) {
            return false;
        }
        if (!add_known_amount_fact(
                out,
                index,
                "sui.move_call0_sui_amount_raw",
                token_flow.move_call0_sui_amount_state,
                token_flow.move_call0_sui_amount_raw)) {
            return false;
        }
    }

    if (token_flow.flow_count > 0) {
        const SuiTokenFlowFact& first_flow = token_flow.flows[0];
        const char* source_kind = token_flow_source_kind_policy_name(first_flow.source_kind);
        const char* sink_kind = token_flow_sink_kind_policy_name(first_flow.sink_kind);
        const char* asset_state = token_flow_asset_state_policy_name(first_flow.asset_state);
        if (!string_present(source_kind) ||
            !string_present(sink_kind) ||
            !string_present(asset_state) ||
            !add_fact(
                out,
                index,
                "sui.coin_flow0_source_kind",
                AgentQPolicyValueType::string,
                source_kind) ||
            !add_fact(
                out,
                index,
                "sui.coin_flow0_asset_state",
                AgentQPolicyValueType::string,
                asset_state) ||
            !add_fact(
                out,
                index,
                "sui.coin_flow0_amount_known",
                AgentQPolicyValueType::string,
                policy_bool(first_flow.amount_state == SuiTokenAmountState::known)) ||
            !add_known_amount_fact(
                out,
                index,
                "sui.coin_flow0_amount_raw",
                first_flow.amount_state,
                first_flow.amount_raw) ||
            !add_fact(
                out,
                index,
                "sui.coin_flow0_sink_kind",
                AgentQPolicyValueType::string,
                sink_kind)) {
            return false;
        }
        if (string_present(first_flow.object_id) &&
            !add_fact(
                out,
                index,
                "sui.coin_flow0_object_id",
                AgentQPolicyValueType::string,
                first_flow.object_id)) {
            return false;
        }
    }

    return true;
}

}  // namespace

bool sui_sign_transaction_policy_sign_rule_is_bounded(const AgentQPolicyRule& rule)
{
    if (rule.action != AgentQPolicyAction::sign ||
        !string_eq(rule.chain, kAgentQSuiPolicyChain) ||
        !string_eq(rule.operation, kAgentQSuiPolicyOperationSignTransaction) ||
        rule.criteria == nullptr ||
        rule.criterion_count == 0 ||
        rule.criterion_count > kAgentQPolicyMaxRuleCriteria) {
        return false;
    }
    return sui_sign_rule_has_required_bounds(rule);
}

bool sui_sign_transaction_policy_build_sign_rule_summary(
    const AgentQPolicyRule& rule,
    char* output,
    size_t output_size)
{
    if (output == nullptr || output_size == 0) {
        return false;
    }
    output[0] = '\0';

    if (!sui_sign_transaction_policy_sign_rule_is_bounded(rule)) {
        return false;
    }

    const char* recipient = criterion_string_eq_value(find_criterion(rule, "sui.recipient0_address"));
    const char* amount = criterion_lte_value(find_criterion(rule, "sui.recipient0_amount_raw"));
    const char* total_out = criterion_lte_value(find_criterion(rule, "sui.sui_total_out_raw"));
    const char* gas_budget = criterion_lte_value(find_criterion(rule, "sui.gas_budget"));
    const char* gas_price = criterion_lte_value(find_criterion(rule, "sui.gas_price"));
    if (recipient == nullptr ||
        amount == nullptr ||
        total_out == nullptr ||
        gas_budget == nullptr ||
        gas_price == nullptr) {
        return false;
    }

    char short_recipient[16] = {};
    format_short_address(recipient, short_recipient, sizeof(short_recipient));
    if (short_recipient[0] == '\0') {
        return false;
    }

    const int written = snprintf(
        output,
        output_size,
        "GasCoin split-result transfer\n%s amt<=%s total<=%s\ngas<=%s/%s",
        short_recipient,
        amount,
        total_out,
        gas_budget,
        gas_price);
    return written > 0 && static_cast<size_t>(written) < output_size;
}

bool sui_sign_transaction_policy_authorization_covered(
    const SuiPolicySubjectFacts& transaction,
    const SuiTokenFlowFacts& token_flow)
{
    if (!base_facts_supported(transaction) ||
        token_flow.sui_total_out_state != SuiTokenAmountState::known) {
        return false;
    }

    return transaction.command_count == 2 &&
           transaction.commands[0].kind == SuiCommandFactKind::split_coins &&
           transaction.commands[1].kind == SuiCommandFactKind::transfer_objects &&
           transfer_objects_policy_coverage_complete(token_flow);
}

bool build_sui_sign_transaction_policy_subject(
    const SuiParsedTransactionFacts& parsed,
    const char* request_network,
    AgentQSuiSignTransactionPolicySubject* out)
{
    if (out == nullptr) {
        return false;
    }
    *out = {};
    if (!sui_network_supported(request_network) ||
        !build_sui_policy_subject_facts(parsed, &out->transaction) ||
        build_sui_token_flow_facts(parsed, &out->token_flow) != SuiTokenFlowFactsResult::ok) {
        *out = {};
        return false;
    }
    const int written = snprintf(
        out->request_network,
        sizeof(out->request_network),
        "%s",
        request_network);
    if (written < 0 || static_cast<size_t>(written) >= sizeof(out->request_network)) {
        *out = {};
        return false;
    }
    return true;
}

bool make_sui_sign_transaction_policy_facts(
    const AgentQSuiSignTransactionPolicySubject& subject,
    AgentQSuiSignTransactionPolicyFacts* out)
{
    if (out == nullptr) {
        return false;
    }
    *out = {};

    const SuiPolicySubjectFacts& sui_facts = subject.transaction;
    if (!base_facts_supported(sui_facts) ||
        !sui_network_supported(subject.request_network) ||
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
        !add_token_flow_facts(subject.token_flow, out, &index) ||
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
        true,
        sui_sign_transaction_policy_sign_rule_is_bounded,
    };
}

}  // namespace agent_q
