#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_q_sui_transaction_facts.h"

namespace agent_q {

constexpr size_t kSuiTokenFlowMaxFlows = 16;

enum class SuiTokenFlowFactsResult {
    ok,
    invalid_argument,
    unsupported_shape,
    invalid_amount,
    overflow,
};

enum class SuiTokenAmountState {
    known,
    unknown,
    incomplete,
};

enum class SuiTokenAssetState {
    proven_sui,
    unproven,
};

enum class SuiTokenFlowSourceKind {
    gas_coin,
    split_result,
    direct_object,
    funds_withdrawal,
    merge_result,
    unknown,
};

enum class SuiTokenFlowSinkKind {
    transfer_recipient,
    move_call_argument,
    merge_destination,
    unknown,
};

struct SuiTokenFlowFact {
    SuiTokenFlowSourceKind source_kind;
    SuiTokenFlowSinkKind sink_kind;
    SuiTokenAssetState asset_state;
    SuiTokenAmountState amount_state;
    char amount_raw[kSuiU64StringBufferSize];
    char object_id[kSuiAddressStringBufferSize];
};

struct SuiTokenFlowFacts {
    SuiTokenAmountState sui_total_out_state;
    char sui_total_out_raw[kSuiU64StringBufferSize];
    SuiTokenAmountState transfer_total_out_state;
    char transfer_total_out_raw[kSuiU64StringBufferSize];
    SuiTokenAmountState move_call_total_in_state;
    char move_call_total_in_raw[kSuiU64StringBufferSize];
    SuiTokenAmountState merge_total_state;
    char merge_total_raw[kSuiU64StringBufferSize];
    uint16_t recipient_count;
    bool recipient0_address_known;
    char recipient0_address[kSuiAddressStringBufferSize];
    SuiTokenAmountState recipient0_amount_state;
    char recipient0_amount_raw[kSuiU64StringBufferSize];
    uint16_t move_call_count;
    char move_call0_package[kSuiAddressStringBufferSize];
    char move_call0_module[kSuiPolicyFactModuleBufferSize];
    char move_call0_function[kSuiPolicyFactFunctionBufferSize];
    SuiTokenAmountState move_call0_sui_amount_state;
    char move_call0_sui_amount_raw[kSuiU64StringBufferSize];
    uint16_t flow_count;
    SuiTokenFlowFact flows[kSuiTokenFlowMaxFlows];
};

const char* sui_token_flow_facts_result_name(SuiTokenFlowFactsResult result);
const char* sui_token_amount_state_name(SuiTokenAmountState state);
const char* sui_token_asset_state_name(SuiTokenAssetState state);

SuiTokenFlowFactsResult build_sui_token_flow_facts(
    const SuiParsedTransactionFacts& parsed,
    SuiTokenFlowFacts* out);

}  // namespace agent_q
