#pragma once

#include <stddef.h>
#include <stdint.h>

namespace agent_q {

constexpr size_t kSuiAddressStringBufferSize = 67;
constexpr size_t kSuiU64StringBufferSize = 21;
constexpr size_t kSuiAssetStringBufferSize = 32;
constexpr size_t kSuiPolicyFactModuleBufferSize = 65;
constexpr size_t kSuiPolicyFactFunctionBufferSize = 65;
constexpr size_t kSuiPolicyFactDigestHexBufferSize = 65;
constexpr size_t kSuiPolicyFactMaxInputs = 8;
constexpr size_t kSuiPolicyFactMaxCommands = 8;
constexpr size_t kSuiPolicyFactMaxPureBytes = 64;
constexpr size_t kSuiPolicyFactMaxGasPayments = 8;
constexpr size_t kSuiPolicyFactMaxCommandArguments = 16;
constexpr size_t kSuiPolicyFactMaxTypeArguments = 4;

enum class SuiTransactionFactsResult {
    ok,
    malformed,
    transaction_kind_only,
    unsupported_kind,
    unsupported_shape,
    too_large,
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

struct SuiCallArgFact {
    SuiCallArgFactKind kind;
    uint32_t pure_length;
    uint8_t pure_bytes[kSuiPolicyFactMaxPureBytes];
    SuiObjectRefFact object_ref;
    char shared_initial_version[kSuiU64StringBufferSize];
    bool shared_mutable;
};

struct SuiStructTypeTagFact {
    char address[kSuiAddressStringBufferSize];
    char module[kSuiPolicyFactModuleBufferSize];
    char name[kSuiPolicyFactFunctionBufferSize];
    uint16_t type_argument_count;
};

struct SuiTypeTagFact {
    SuiTypeTagFactKind kind;
    SuiStructTypeTagFact struct_tag;
};

struct SuiMoveCallFact {
    char package[kSuiAddressStringBufferSize];
    char module[kSuiPolicyFactModuleBufferSize];
    char function[kSuiPolicyFactFunctionBufferSize];
    uint16_t type_argument_count;
    uint16_t argument_count;
    SuiTypeTagFact type_arguments[kSuiPolicyFactMaxTypeArguments];
};

struct SuiCommandFact {
    SuiCommandFactKind kind;
    SuiMoveCallFact move_call;
    uint16_t argument_count;
    SuiArgumentFact arguments[kSuiPolicyFactMaxCommandArguments];
    bool has_make_move_vec_type;
    SuiTypeTagFact make_move_vec_type;
};

struct SuiRestrictedTransferFact {
    char sender[kSuiAddressStringBufferSize];
    char gas_owner[kSuiAddressStringBufferSize];
    char recipient[kSuiAddressStringBufferSize];
    char asset[kSuiAssetStringBufferSize];
    char amount[kSuiU64StringBufferSize];
    char gas_budget[kSuiU64StringBufferSize];
    char gas_price[kSuiU64StringBufferSize];
    uint16_t command_count;
};

struct SuiTransactionPolicyFacts {
    SuiTransactionKindFact transaction_kind;
    char sender[kSuiAddressStringBufferSize];
    char gas_owner[kSuiAddressStringBufferSize];
    char gas_price[kSuiU64StringBufferSize];
    char gas_budget[kSuiU64StringBufferSize];
    SuiTransactionExpirationFact expiration_kind;
    char expiration_epoch[kSuiU64StringBufferSize];
    uint16_t input_count;
    uint16_t command_count;
    uint16_t gas_payment_count;
    SuiObjectRefFact gas_payments[kSuiPolicyFactMaxGasPayments];
    SuiCallArgFact inputs[kSuiPolicyFactMaxInputs];
    SuiCommandFact commands[kSuiPolicyFactMaxCommands];
    bool has_restricted_transfer;
    SuiRestrictedTransferFact restricted_transfer;
};

const char* sui_transaction_facts_result_name(SuiTransactionFactsResult result);

SuiTransactionFactsResult parse_sui_transaction_policy_facts(
    const uint8_t* tx_bytes,
    size_t tx_len,
    SuiTransactionPolicyFacts* out);

}  // namespace agent_q
