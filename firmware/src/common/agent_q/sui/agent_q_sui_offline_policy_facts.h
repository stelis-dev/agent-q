#pragma once

#include "agent_q_sui_transaction_facts.h"

#include <stddef.h>
#include <stdint.h>

namespace agent_q {

constexpr size_t kSuiOfflinePolicyMaxSetValues = kSuiPolicyFactMaxCommands;
constexpr size_t kSuiOfflinePolicyMaxTokenSources = 16;
constexpr size_t kSuiOfflinePolicyMaxTokenTotals = 16;

enum class SuiOfflinePolicyFactsCompleteness {
    complete,
    incomplete,
    malformed,
    unsupported,
    capacity_exceeded,
};

enum class SuiOfflinePolicyFactsReason {
    none,
    malformed_bcs,
    unsupported_transaction_version,
    unsupported_transaction_kind,
    transaction_kind_only,
    trailing_bytes,
    input_capacity_exceeded,
    command_capacity_exceeded,
    fact_capacity_exceeded,
    invalid_command_reference,
    invalid_result_reference,
    recipient_address_decode_failed,
    token_amount_decode_failed,
    token_amount_overflow,
    unknown_token_provenance,
    mixed_known_unknown_token_merge,
    direct_object_token_amount_unknown,
};

enum class SuiOfflinePolicyTokenSourceKind {
    gas_coin,
    funds_withdrawal_sender,
    funds_withdrawal_sponsor,
    unknown,
};

enum class SuiOfflinePolicyTokenProvenance {
    gas_coin_split,
    funds_withdrawal,
    unknown,
};

struct SuiOfflinePolicyStringSet {
    uint16_t count;
    char values[kSuiOfflinePolicyMaxSetValues][kSuiPolicyFactTypeTagBufferSize];
};

struct SuiOfflinePolicyTokenSourceFact {
    char type_tag[kSuiPolicyFactTypeTagBufferSize];
    SuiOfflinePolicyTokenSourceKind source;
    char amount_raw[kSuiU64StringBufferSize];
    bool amount_known;
    SuiOfflinePolicyTokenProvenance provenance;
};

struct SuiOfflinePolicyTokenTotalFact {
    char type_tag[kSuiPolicyFactTypeTagBufferSize];
    char amount_raw[kSuiU64StringBufferSize];
};

struct SuiOfflinePolicyConditionFacts {
    bool valid_transaction_data;
    char gas_budget_raw[kSuiU64StringBufferSize];
    char gas_price_raw[kSuiU64StringBufferSize];
    char gas_owner[kSuiAddressStringBufferSize];
    char sender[kSuiAddressStringBufferSize];
    bool sponsored;
    char command_count[kSuiU64StringBufferSize];
    SuiOfflinePolicyStringSet command_kinds;
    SuiOfflinePolicyStringSet move_call_packages;
    SuiOfflinePolicyStringSet move_call_modules;
    SuiOfflinePolicyStringSet move_call_functions;
    bool publish_present;
    bool upgrade_present;
    SuiOfflinePolicyStringSet recipient_addresses;
    SuiOfflinePolicyStringSet pure_address_arguments;
    uint16_t token_source_count;
    SuiOfflinePolicyTokenSourceFact token_sources[kSuiOfflinePolicyMaxTokenSources];
    uint16_t token_total_count;
    SuiOfflinePolicyTokenTotalFact token_totals_by_type[kSuiOfflinePolicyMaxTokenTotals];
    bool token_unknown_amount_present;
    SuiOfflinePolicyFactsReason token_unknown_amount_reason;
    SuiOfflinePolicyFactsCompleteness completeness;
    SuiOfflinePolicyFactsReason reason;
};

const char* sui_offline_policy_facts_reason_name(SuiOfflinePolicyFactsReason reason);

bool build_sui_offline_policy_condition_facts(
    const SuiParsedTransactionFacts& parsed,
    SuiOfflinePolicyConditionFacts* out);

SuiTransactionFactsResult parse_sui_offline_policy_condition_facts(
    const uint8_t* tx_bytes,
    size_t tx_len,
    SuiOfflinePolicyConditionFacts* out);

}  // namespace agent_q
