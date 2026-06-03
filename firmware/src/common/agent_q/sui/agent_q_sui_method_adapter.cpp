#include "agent_q_sui_method_adapter.h"

#include <string.h>

namespace agent_q {
namespace {

constexpr const char* kSuiAsset = "0x2::sui::SUI";

constexpr AgentQPolicyFieldDescriptor kSuiSignTransactionPolicyFields[] = {
    {"sui.command_shape", AgentQPolicyValueType::string, true, true, false},
    {"sui.sender_address", AgentQPolicyValueType::string, true, true, false},
    {"sui.recipient_address", AgentQPolicyValueType::string, true, true, false},
    {"sui.coin_type", AgentQPolicyValueType::string, true, true, false},
    {"sui.amount_raw", AgentQPolicyValueType::u64_decimal, true, false, true},
    {"sui.gas_budget", AgentQPolicyValueType::u64_decimal, true, false, true},
    {"sui.gas_price", AgentQPolicyValueType::u64_decimal, true, false, true},
};

constexpr AgentQPolicyRequiredCriterion kSuiSignTransactionAskRequiredCriteria[] = {
    {"common.network", AgentQPolicyOperator::eq, nullptr},
    {"common.intent", AgentQPolicyOperator::eq, kAgentQPolicyIntentSingleAssetTransfer},
    {"sui.command_shape", AgentQPolicyOperator::eq, kAgentQSuiPolicyCommandShapeRestrictedTransfer},
    {"sui.recipient_address", AgentQPolicyOperator::in, nullptr},
    {"sui.coin_type", AgentQPolicyOperator::eq, kSuiAsset},
    {"sui.amount_raw", AgentQPolicyOperator::lte, nullptr},
    {"sui.gas_budget", AgentQPolicyOperator::lte, nullptr},
    {"sui.gas_price", AgentQPolicyOperator::lte, nullptr},
};

constexpr AgentQPolicyActionConstraint kSuiSignTransactionActionConstraints[] = {
    {
        AgentQPolicyAction::ask,
        kSuiSignTransactionAskRequiredCriteria,
        sizeof(kSuiSignTransactionAskRequiredCriteria) /
            sizeof(kSuiSignTransactionAskRequiredCriteria[0]),
    },
};

bool string_present(const char* value)
{
    return value != nullptr && value[0] != '\0';
}

}  // namespace

bool make_sui_sign_transaction_policy_facts(
    const SuiTransferFacts& sui_facts,
    const char* network,
    AgentQSuiSignTransactionPolicyFacts* out)
{
    if (out == nullptr) {
        return false;
    }
    *out = {};

    if (!string_present(network) ||
        !string_present(sui_facts.sender) ||
        !string_present(sui_facts.recipient) ||
        !string_present(sui_facts.amount) ||
        !string_present(sui_facts.gas_budget) ||
        !string_present(sui_facts.gas_price) ||
        strcmp(sui_facts.asset, kSuiAsset) != 0 ||
        sui_facts.command_count != 2) {
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
        "common.network",
        AgentQPolicyValueType::string,
        network,
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
        "sui.recipient_address",
        AgentQPolicyValueType::string,
        sui_facts.recipient,
    };
    out->entries[index++] = AgentQPolicyFact{
        "sui.coin_type",
        AgentQPolicyValueType::string,
        sui_facts.asset,
    };
    out->entries[index++] = AgentQPolicyFact{
        "sui.amount_raw",
        AgentQPolicyValueType::u64_decimal,
        sui_facts.amount,
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
    static_assert(kAgentQSuiTransferPolicyFactCount == 11, "Sui transfer policy fact count mismatch");
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
        false,
        kSuiSignTransactionActionConstraints,
        sizeof(kSuiSignTransactionActionConstraints) /
            sizeof(kSuiSignTransactionActionConstraints[0]),
    };
}

}  // namespace agent_q
