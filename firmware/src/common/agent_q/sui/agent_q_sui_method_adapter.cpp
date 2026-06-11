#include "agent_q_sui_method_adapter.h"

#include <stdio.h>
#include <string.h>

namespace agent_q {
namespace {

constexpr const char* kSuiAsset = "0x2::sui::SUI";

constexpr AgentQPolicyFieldDescriptor kSuiSignTransactionPolicyFields[] = {
    {"sui.command_shape", AgentQPolicyValueType::string, true, true, false},
    {"sui.sender_address", AgentQPolicyValueType::string, true, true, false},
    {"sui.gas_owner_address", AgentQPolicyValueType::string, true, true, false},
    {"sui.command_count", AgentQPolicyValueType::u64_decimal, true, false, true},
    {"sui.command0_kind", AgentQPolicyValueType::string, true, true, false},
    {"sui.command1_kind", AgentQPolicyValueType::string, true, true, false},
    {"sui.recipient_address", AgentQPolicyValueType::string, true, true, false},
    {"sui.coin_type", AgentQPolicyValueType::string, true, true, false},
    {"sui.amount_raw", AgentQPolicyValueType::u64_decimal, true, false, true},
    {"sui.gas_budget", AgentQPolicyValueType::u64_decimal, true, false, true},
    {"sui.gas_price", AgentQPolicyValueType::u64_decimal, true, false, true},
};

bool string_present(const char* value)
{
    return value != nullptr && value[0] != '\0';
}

}  // namespace

bool make_sui_sign_transaction_policy_facts(
    const SuiTransactionPolicyFacts& sui_facts,
    AgentQSuiSignTransactionPolicyFacts* out)
{
    if (out == nullptr) {
        return false;
    }
    *out = {};

    const SuiRestrictedTransferFact& transfer = sui_facts.restricted_transfer;
    if (!sui_facts.has_restricted_transfer ||
        !string_present(sui_facts.sender) ||
        !string_present(sui_facts.gas_owner) ||
        !string_present(transfer.recipient) ||
        !string_present(transfer.amount) ||
        !string_present(sui_facts.gas_budget) ||
        !string_present(sui_facts.gas_price) ||
        strcmp(sui_facts.gas_owner, sui_facts.sender) != 0 ||
        strcmp(transfer.asset, kSuiAsset) != 0 ||
        transfer.command_count != 2 ||
        sui_facts.command_count != 2 ||
        sui_facts.commands[0].kind != SuiCommandFactKind::split_coins ||
        sui_facts.commands[1].kind != SuiCommandFactKind::transfer_objects) {
        return false;
    }

    if (snprintf(
            out->command_count,
            sizeof(out->command_count),
            "%u",
            static_cast<unsigned>(sui_facts.command_count)) <= 0) {
        return false;
    }

    size_t index = 0;
    out->entries[index++] = AgentQPolicyFact{
        "common.chain",
        AgentQPolicyValueType::string,
        kAgentQSuiPolicyChain,
    };
    out->entries[index++] = AgentQPolicyFact{
        "common.method",
        AgentQPolicyValueType::string,
        kAgentQSuiPolicyOperationSignTransaction,
    };
    out->entries[index++] = AgentQPolicyFact{
        "common.intent",
        AgentQPolicyValueType::string,
        kAgentQPolicyIntentSingleAssetTransfer,
    };
    out->entries[index++] = AgentQPolicyFact{
        "sui.command_shape",
        AgentQPolicyValueType::string,
        kAgentQSuiPolicyCommandShapeRestrictedTransfer,
    };
    out->entries[index++] = AgentQPolicyFact{
        "sui.sender_address",
        AgentQPolicyValueType::string,
        sui_facts.sender,
    };
    out->entries[index++] = AgentQPolicyFact{
        "sui.gas_owner_address",
        AgentQPolicyValueType::string,
        sui_facts.gas_owner,
    };
    out->entries[index++] = AgentQPolicyFact{
        "sui.command_count",
        AgentQPolicyValueType::u64_decimal,
        out->command_count,
    };
    out->entries[index++] = AgentQPolicyFact{
        "sui.command0_kind",
        AgentQPolicyValueType::string,
        kAgentQSuiPolicyCommandKindSplitCoins,
    };
    out->entries[index++] = AgentQPolicyFact{
        "sui.command1_kind",
        AgentQPolicyValueType::string,
        kAgentQSuiPolicyCommandKindTransferObjects,
    };
    out->entries[index++] = AgentQPolicyFact{
        "sui.recipient_address",
        AgentQPolicyValueType::string,
        transfer.recipient,
    };
    out->entries[index++] = AgentQPolicyFact{
        "sui.coin_type",
        AgentQPolicyValueType::string,
        transfer.asset,
    };
    out->entries[index++] = AgentQPolicyFact{
        "sui.amount_raw",
        AgentQPolicyValueType::u64_decimal,
        transfer.amount,
    };
    out->entries[index++] = AgentQPolicyFact{
        "sui.gas_budget",
        AgentQPolicyValueType::u64_decimal,
        sui_facts.gas_budget,
    };
    out->entries[index++] = AgentQPolicyFact{
        "sui.gas_price",
        AgentQPolicyValueType::u64_decimal,
        sui_facts.gas_price,
    };
    static_assert(kAgentQSuiTransferPolicyFactCount == 14, "Sui transfer policy fact count mismatch");
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
    };
}

}  // namespace agent_q
