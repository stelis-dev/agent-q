export type PolicyValueType = "string" | "u64_decimal";
export type SignRuleBoundKind = "eq" | "string" | "string_eq" | "lte";

export interface PolicyFieldDescriptor {
  type: PolicyValueType;
  allowEq: boolean;
  allowIn: boolean;
  allowLte: boolean;
}

export interface SignRuleBound {
  kind: SignRuleBoundKind;
  field: string;
  value?: string;
}

// Projection of specs/sui-sign-transaction-policy-contract.tsv for the Core
// protocol sanitizer. Firmware remains the signing authority; Core tests verify
// this projection against the shared manifest.
export const COMMON_POLICY_FIELDS: Record<string, PolicyFieldDescriptor> = {
  "common.chain": { type: "string", allowEq: true, allowIn: true, allowLte: false },
  "common.method": { type: "string", allowEq: true, allowIn: true, allowLte: false },
  "common.intent": { type: "string", allowEq: true, allowIn: true, allowLte: false },
};

const SUI_POLICY_MAX_COMMANDS = 8;
const SUI_POLICY_MAX_MOVE_CALL_TYPE_ARGS = 4;

function makeSuiSignTransactionPolicyFields(): Record<string, PolicyFieldDescriptor> {
  const fields: Record<string, PolicyFieldDescriptor> = {
    "sui.transaction_kind": { type: "string", allowEq: true, allowIn: true, allowLte: false },
    "sui.sender_address": { type: "string", allowEq: true, allowIn: true, allowLte: false },
    "sui.gas_owner_address": { type: "string", allowEq: true, allowIn: true, allowLte: false },
    "sui.command_count": { type: "u64_decimal", allowEq: true, allowIn: false, allowLte: true },
    "sui.gas_budget": { type: "u64_decimal", allowEq: true, allowIn: false, allowLte: true },
    "sui.gas_price": { type: "u64_decimal", allowEq: true, allowIn: false, allowLte: true },
    "sui.expiration_kind": { type: "string", allowEq: true, allowIn: true, allowLte: false },
    "sui.sui_total_out_complete": { type: "string", allowEq: true, allowIn: false, allowLte: false },
    "sui.sui_total_out_raw": { type: "u64_decimal", allowEq: true, allowIn: true, allowLte: true },
    "sui.transfer_total_out_raw": { type: "u64_decimal", allowEq: true, allowIn: true, allowLte: true },
    "sui.move_call_total_in_raw": { type: "u64_decimal", allowEq: true, allowIn: true, allowLte: true },
    "sui.recipient_count": { type: "u64_decimal", allowEq: true, allowIn: true, allowLte: true },
    "sui.recipient0_address": { type: "string", allowEq: true, allowIn: true, allowLte: false },
    "sui.recipient0_amount_raw": { type: "u64_decimal", allowEq: true, allowIn: true, allowLte: true },
    "sui.move_call0_package": { type: "string", allowEq: true, allowIn: true, allowLte: false },
    "sui.move_call0_module": { type: "string", allowEq: true, allowIn: true, allowLte: false },
    "sui.move_call0_function": { type: "string", allowEq: true, allowIn: true, allowLte: false },
    "sui.move_call0_sui_amount_raw": { type: "u64_decimal", allowEq: true, allowIn: true, allowLte: true },
    "sui.coin_flow0_source_kind": { type: "string", allowEq: true, allowIn: true, allowLte: false },
    "sui.coin_flow0_asset_state": { type: "string", allowEq: true, allowIn: true, allowLte: false },
    "sui.coin_flow0_amount_known": { type: "string", allowEq: true, allowIn: false, allowLte: false },
    "sui.coin_flow0_amount_raw": { type: "u64_decimal", allowEq: true, allowIn: true, allowLte: true },
    "sui.coin_flow0_sink_kind": { type: "string", allowEq: true, allowIn: true, allowLte: false },
    "sui.coin_flow0_object_id": { type: "string", allowEq: true, allowIn: true, allowLte: false },
  };
  for (let commandIndex = 0; commandIndex < SUI_POLICY_MAX_COMMANDS; commandIndex += 1) {
    fields[`sui.command${commandIndex}_kind`] = { type: "string", allowEq: true, allowIn: true, allowLte: false };
    fields[`sui.command${commandIndex}_move_call_package`] = { type: "string", allowEq: true, allowIn: true, allowLte: false };
    fields[`sui.command${commandIndex}_move_call_module`] = { type: "string", allowEq: true, allowIn: true, allowLte: false };
    fields[`sui.command${commandIndex}_move_call_function`] = { type: "string", allowEq: true, allowIn: true, allowLte: false };
    fields[`sui.command${commandIndex}_move_call_type_args`] = { type: "u64_decimal", allowEq: true, allowIn: false, allowLte: true };
    for (let typeArgIndex = 0; typeArgIndex < SUI_POLICY_MAX_MOVE_CALL_TYPE_ARGS; typeArgIndex += 1) {
      fields[`sui.command${commandIndex}_move_call_type_arg${typeArgIndex}`] = {
        type: "string",
        allowEq: true,
        allowIn: true,
        allowLte: false,
      };
    }
  }
  return fields;
}

export const SUI_SIGN_TRANSACTION_POLICY_FIELDS = makeSuiSignTransactionPolicyFields();

export const SUI_CURRENT_SIGN_RULE_BOUNDS: readonly SignRuleBound[] = [
  { kind: "eq", field: "common.chain", value: "sui" },
  { kind: "eq", field: "common.method", value: "sign_transaction" },
  { kind: "eq", field: "common.intent", value: "programmable_transaction" },
  { kind: "eq", field: "sui.transaction_kind", value: "programmable_transaction" },
  { kind: "string", field: "sui.sender_address" },
  { kind: "string", field: "sui.gas_owner_address" },
  { kind: "lte", field: "sui.gas_budget" },
  { kind: "lte", field: "sui.gas_price" },
  { kind: "string", field: "sui.expiration_kind" },
  { kind: "eq", field: "sui.sui_total_out_complete", value: "yes" },
  { kind: "lte", field: "sui.sui_total_out_raw" },
  { kind: "eq", field: "sui.command_count", value: "2" },
  { kind: "eq", field: "sui.command0_kind", value: "split_coins" },
  { kind: "eq", field: "sui.command1_kind", value: "transfer_objects" },
  { kind: "eq", field: "sui.recipient_count", value: "1" },
  { kind: "string_eq", field: "sui.recipient0_address" },
  { kind: "lte", field: "sui.recipient0_amount_raw" },
  { kind: "eq", field: "sui.coin_flow0_source_kind", value: "split_result" },
  { kind: "eq", field: "sui.coin_flow0_asset_state", value: "proven_sui" },
  { kind: "eq", field: "sui.coin_flow0_amount_known", value: "yes" },
  { kind: "eq", field: "sui.coin_flow0_sink_kind", value: "transfer_recipient" },
];
