#pragma once

#include <stddef.h>
#include <stdint.h>

namespace agent_q {

constexpr size_t kSuiAddressStringBufferSize = 67;
constexpr size_t kSuiU64StringBufferSize = 21;
constexpr size_t kSuiPolicyFactModuleBufferSize = 65;
constexpr size_t kSuiPolicyFactFunctionBufferSize = 65;
constexpr size_t kSuiPolicyFactDigestHexBufferSize = 65;
constexpr size_t kSuiPolicyFactTypeTagBufferSize = 256;
constexpr size_t kSuiPolicyFactMaxInputs = 8;
constexpr size_t kSuiPolicyFactMaxCommands = 8;
constexpr size_t kSuiPolicyFactMaxPureBytes = 64;
constexpr size_t kSuiPolicyFactMaxGasPayments = 8;
constexpr size_t kSuiPolicyFactMaxCommandArguments = 16;
constexpr size_t kSuiPolicyFactMaxTypeArguments = 4;
constexpr size_t kSuiPolicyFactMaxPackageModules = 4;
constexpr size_t kSuiPolicyFactMaxPackageDependencies = 16;
constexpr size_t kSuiReviewSummaryMaxRows = 64;
constexpr size_t kSuiReviewSummaryTitleSize = 40;
constexpr size_t kSuiReviewSummaryRowLabelSize = 18;
constexpr size_t kSuiReviewSummaryRowValueSize = 96;

enum class SuiTransactionFactsResult {
    ok,
    malformed,
    transaction_kind_only,
    unsupported_version,
    unsupported_kind,
    unsupported_shape,
    too_large,
};

enum class SuiTransactionDataVersionFact {
    v1,
    unsupported,
};

enum class SuiTransactionKindFact {
    programmable_transaction,
    unsupported,
};

enum class SuiTransactionExpirationFact {
    none,
    epoch,
    valid_during,
};

enum class SuiCallArgFactKind {
    pure,
    object_imm_or_owned,
    object_shared,
    object_receiving,
    funds_withdrawal,
    unsupported,
};

enum class SuiCommandFactKind {
    move_call,
    transfer_objects,
    split_coins,
    merge_coins,
    publish,
    make_move_vec,
    upgrade,
    unsupported,
};

enum class SuiArgumentFactKind {
    gas_coin,
    input,
    result,
    nested_result,
    unsupported,
};

enum class SuiTypeTagFactKind {
    bool_,
    u8,
    u64,
    u128,
    address,
    signer,
    vector,
    struct_,
    u16,
    u32,
    u256,
    unsupported,
};

enum class SuiFundsWithdrawalSourceFact {
    sender,
    sponsor,
    unsupported,
};

struct SuiArgumentFact {
    SuiArgumentFactKind kind;
    uint16_t index;
    uint16_t nested_index;
};

struct SuiObjectRefFact {
    char object_id[kSuiAddressStringBufferSize];
    char version[kSuiU64StringBufferSize];
    char digest_hex[kSuiPolicyFactDigestHexBufferSize];
};

struct SuiStructTypeTagFact {
    char address[kSuiAddressStringBufferSize];
    char module[kSuiPolicyFactModuleBufferSize];
    char name[kSuiPolicyFactFunctionBufferSize];
    uint16_t type_argument_count;
};

struct SuiTypeTagFact {
    SuiTypeTagFactKind kind;
    char canonical[kSuiPolicyFactTypeTagBufferSize];
    SuiStructTypeTagFact struct_tag;
};

struct SuiFundsWithdrawalFact {
    char amount[kSuiU64StringBufferSize];
    SuiTypeTagFact type;
    SuiFundsWithdrawalSourceFact source;
};

struct SuiCallArgFact {
    SuiCallArgFactKind kind;
    uint32_t pure_length;
    union {
        uint8_t pure_bytes[kSuiPolicyFactMaxPureBytes];
        SuiObjectRefFact object_ref;
        SuiFundsWithdrawalFact funds_withdrawal;
    };
    char shared_initial_version[kSuiU64StringBufferSize];
    bool shared_mutable;
};

struct SuiMoveCallFact {
    char package[kSuiAddressStringBufferSize];
    char module[kSuiPolicyFactModuleBufferSize];
    char function[kSuiPolicyFactFunctionBufferSize];
    uint16_t type_argument_count;
    uint16_t argument_count;
    SuiTypeTagFact type_arguments[kSuiPolicyFactMaxTypeArguments];
};

struct SuiPackagePublishFact {
    uint16_t module_count;
    uint16_t dependency_count;
    char dependencies[kSuiPolicyFactMaxPackageDependencies][kSuiAddressStringBufferSize];
};

struct SuiPackageUpgradeFact {
    uint16_t module_count;
    uint16_t dependency_count;
    char dependencies[kSuiPolicyFactMaxPackageDependencies][kSuiAddressStringBufferSize];
    char package[kSuiAddressStringBufferSize];
    SuiArgumentFact ticket;
};

struct SuiValidDuringFact {
    bool has_min_epoch;
    char min_epoch[kSuiU64StringBufferSize];
    bool has_max_epoch;
    char max_epoch[kSuiU64StringBufferSize];
    bool has_min_timestamp;
    char min_timestamp[kSuiU64StringBufferSize];
    bool has_max_timestamp;
    char max_timestamp[kSuiU64StringBufferSize];
    char chain_digest_hex[kSuiPolicyFactDigestHexBufferSize];
    char nonce[kSuiU64StringBufferSize];
};

struct SuiCommandFact {
    SuiCommandFactKind kind;
    union {
        SuiMoveCallFact move_call;
        SuiPackagePublishFact publish;
        SuiPackageUpgradeFact upgrade;
        SuiTypeTagFact make_move_vec_type;
    };
    uint16_t argument_count;
    SuiArgumentFact arguments[kSuiPolicyFactMaxCommandArguments];
    bool has_make_move_vec_type;
};

struct SuiPolicyCommandFact {
    SuiCommandFactKind kind;
    bool has_move_call;
    char move_call_package[kSuiAddressStringBufferSize];
    char move_call_module[kSuiPolicyFactModuleBufferSize];
    char move_call_function[kSuiPolicyFactFunctionBufferSize];
    uint16_t type_argument_count;
    char move_call_type_args[kSuiPolicyFactMaxTypeArguments][kSuiPolicyFactTypeTagBufferSize];
};

struct SuiParsedTransactionFacts {
    SuiTransactionDataVersionFact transaction_data_version;
    SuiTransactionKindFact transaction_kind;
    char sender[kSuiAddressStringBufferSize];
    char gas_owner[kSuiAddressStringBufferSize];
    char gas_price[kSuiU64StringBufferSize];
    char gas_budget[kSuiU64StringBufferSize];
    SuiTransactionExpirationFact expiration_kind;
    char expiration_epoch[kSuiU64StringBufferSize];
    SuiValidDuringFact valid_during;
    uint16_t input_count;
    uint16_t command_count;
    uint16_t gas_payment_count;
    SuiObjectRefFact gas_payments[kSuiPolicyFactMaxGasPayments];
    SuiCallArgFact inputs[kSuiPolicyFactMaxInputs];
    SuiCommandFact commands[kSuiPolicyFactMaxCommands];
};

struct SuiPolicySubjectFacts {
    SuiTransactionDataVersionFact transaction_data_version;
    SuiTransactionKindFact transaction_kind;
    char sender[kSuiAddressStringBufferSize];
    char gas_owner[kSuiAddressStringBufferSize];
    char gas_price[kSuiU64StringBufferSize];
    char gas_budget[kSuiU64StringBufferSize];
    SuiTransactionExpirationFact expiration_kind;
    char expiration_epoch[kSuiU64StringBufferSize];
    uint16_t command_count;
    SuiPolicyCommandFact commands[kSuiPolicyFactMaxCommands];
};

struct SuiMinimumTransactionFacts {
    SuiTransactionDataVersionFact transaction_data_version;
    SuiTransactionKindFact transaction_kind;
    char sender[kSuiAddressStringBufferSize];
    char gas_owner[kSuiAddressStringBufferSize];
    char gas_price[kSuiU64StringBufferSize];
    char gas_budget[kSuiU64StringBufferSize];
};

enum class SuiReviewSummaryStatus {
    ok,
    unsupported_review,
    insufficient_review,
};

enum class SuiReviewRiskLevel {
    low,
    medium,
    high,
};

enum class SuiReviewRowKind {
    normal,
    wrapped_value,
    section,
    warning,
};

struct SuiReviewRow {
    SuiReviewRowKind kind;
    char label[kSuiReviewSummaryRowLabelSize];
    char value[kSuiReviewSummaryRowValueSize];
};

struct SuiReviewSummary {
    SuiReviewSummaryStatus status;
    SuiReviewRiskLevel risk;
    char title[kSuiReviewSummaryTitleSize];
    char type_summary[kSuiReviewSummaryRowValueSize];
    char risk_label[kSuiReviewSummaryRowValueSize];
    SuiReviewRow rows[kSuiReviewSummaryMaxRows];
    uint16_t row_count;
};

const char* sui_transaction_facts_result_name(SuiTransactionFactsResult result);

SuiTransactionFactsResult parse_sui_parsed_transaction_facts(
    const uint8_t* tx_bytes,
    size_t tx_len,
    SuiParsedTransactionFacts* out);

SuiTransactionFactsResult parse_sui_minimum_transaction_facts(
    const uint8_t* tx_bytes,
    size_t tx_len,
    SuiMinimumTransactionFacts* out);

bool build_sui_policy_subject_facts(
    const SuiParsedTransactionFacts& parsed,
    SuiPolicySubjectFacts* out);

bool build_sui_review_summary(
    const SuiParsedTransactionFacts& parsed,
    SuiReviewSummary* out);

}  // namespace agent_q
