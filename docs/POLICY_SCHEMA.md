# Agent-Q Policy Schema

This document describes the current Agent-Q policy document shape, request
context validation, and Sui `sign_transaction` facts that Firmware currently
derives from serialized transaction bytes.

It describes implemented source behavior only. It is not a product-active
claim.

The current Sui `sign_transaction` policy field/operator list and required
bounded `sign` rule shape are authored in
`specs/sui-sign-transaction-policy-contract.tsv`. Core and Firmware consume
generated projections from that manifest, and freshness checks fail when the
tracked projections drift. Firmware remains the runtime authority for policy
evaluation and signing decisions.

## 1. Current Status

- The current policy schema is `agentq.policy.v0`.
- Firmware stores one active policy document.
- Firmware evaluates policy rules.
- Host process, MCP, provider, Sui CLI signer, Admin Page, apps, SDK JSON,
  dry-run output, and display strings are not policy authorities.
- Sui `sign_transaction` policy-mode signing is source-wired for
  current-contract GasCoin-derived proven-SUI split-result transfer
  transactions whose active policy has one matching bounded `sign` rule.
  Firmware rejects other valid policy-incomplete Sui transactions.
- Policy mode does not fall back to user confirmation or user-mode blind
  signing.

## 2. Current Policy Document Shape

```text
schema = agentq.policy.v0
default_action = reject

rules[]:
  rule A OR rule B OR rule C

criteria[] inside one rule:
  criterion 1 AND criterion 2 AND criterion 3
```

Current actions:

| Action | Meaning |
| --- | --- |
| `reject` | Reject the request. |
| `sign` | Sign only for methods whose policy descriptor supports signing and whose matching rule is bounded. |

Current operators:

| Operator | Meaning |
| --- | --- |
| `eq` | The field value equals one value. |
| `in` | The field value equals one value from a bounded list. |
| `lte` | The unsigned decimal field value is less than or equal to one bound. |

Current policy fact value types:

| Type | Representation |
| --- | --- |
| `string` | Canonical ASCII string. |
| `u64_decimal` | Canonical unsigned decimal string. |

## 3. Current Sui `sign_transaction` Policy Behavior

Current Sui `sign_transaction` policy behavior:

| Condition | Outcome |
| --- | --- |
| Malformed transaction bytes | No signing. |
| Unsupported transaction identity, version, or kind | No signing. |
| Wrong account or sponsored gas owner | No signing. |
| Valid transaction with incomplete policy coverage | `policy_rejected`. |
| Valid transaction with matching `reject` rule | `policy_rejected`. |
| Valid transaction matching the current automatic signing contract and a bounded `sign` rule | Signed through policy mode. |
| User-mode clear or blind signing is available | Not used by policy mode. |

The current Sui method descriptor supports policy `reject` rules and bounded
policy `sign` rules for Sui `sign_transaction`.

Current policy examples:

- Default reject: `defaultAction: "reject"` with no rules. This rejects all
  policy-mode signing requests.
- Explicit reject rule: `action: "reject"` with criteria over the supported
  fields below. Matching requests are rejected. A broader transaction whose
  policy coverage is incomplete is rejected before active rules are evaluated.
- Automatic Sui transfer sign rule: exactly one `action: "sign"` rule that
  bounds the current GasCoin-derived split-result transfer contract. The
  `policy_propose` example in `specs/PROTOCOL.md` and the Admin Page policy
  example use this shape.

Current automatic policy `sign` rules are intentionally narrower than the full
parser. They are accepted only for transaction-derived SUI transfer facts whose
amount and SUI provenance are both proven by Firmware without unexposed
arguments:

- Sui `TransactionData::V1 -> ProgrammableTransaction`.
- Stored-account sender and gas owner, gas budget, gas price, transaction kind,
  expiration kind, command count, command kinds, total SUI out, recipient count,
  recipient address, recipient amount, and first token-flow source/provenance
  are all bounded by the rule.
- The command list is exactly `SplitCoins` followed by one `TransferObjects`
  command. The transferred object must be the first split result, and that
  split result must come from `GasCoin`; non-gas coin sources are not automatic
  policy-signable.
- The policy document may contain at most one `sign` rule, because the current
  device review summary represents only one automatic signing rule.

`MoveCall`, `MergeCoins`, `Publish`, `Upgrade`, `MakeMoveVec`, direct-object
amounts, funds-withdrawal inputs, non-gas split sources, and unknown amounts do
not currently satisfy automatic policy signing coverage.

User-mode review is separate from policy-mode evaluation. Some broader parsed
transactions can still be shown for device-confirmed review when user review
coverage allows. In the product `sign_transaction` policy path, a valid
transaction whose policy coverage is incomplete returns `policy_rejected`
before the active policy document is evaluated, so broader parsed facts do not
currently create product-path `reject` rule matches.

## 4. Current Parser-Observable Sui Facts

Firmware currently parses Sui `TransactionData::V1` with
`ProgrammableTransaction` kind into bounded offline facts.

Source of truth:

- `firmware/src/common/agent_q/sui/agent_q_sui_transaction_facts.h`
- `firmware/src/common/agent_q/sui/agent_q_sui_transaction_facts.cpp`
- `firmware/src/common/agent_q/sui/testdata/sui_transaction_authorization_coverage.tsv`

Catalog columns:

| Column | Meaning |
| --- | --- |
| Policy field | Current policy field name, or `none` when Firmware observes the value but does not currently expose it as a policy fact. |
| Field type | Current policy value type when the value is a policy fact. |
| Source struct/path | Firmware parser struct or path that owns the observation. |
| Offline observable | Whether Firmware observes this from serialized transaction bytes without online lookup. |
| Policy usable now | Whether current policy facts expose this value. |
| Reason | Current reason for the classification. |
| Allowed operators | Current operators for the policy field. |

### Common Transaction Facts

| Policy field | Field type | Source struct/path | Offline observable | Policy usable now | Reason | Allowed operators |
| --- | --- | --- | --- | --- | --- | --- |
| `common.chain` | `string` | Sui method adapter constant | yes | yes | Route identity is known after `(type, chain, method)` classification. | `eq`, `in` |
| `common.method` | `string` | Sui method adapter constant | yes | yes | Method identity is known after route classification. | `eq`, `in` |
| `common.intent` | `string` | Sui method adapter constant | yes | yes | Current supported intent is `programmable_transaction`. | `eq`, `in` |
| `sui.transaction_kind` | `string` | `SuiParsedTransactionFacts.transaction_kind` | yes | yes | Firmware accepts Sui `ProgrammableTransaction` for this path. | `eq`, `in` |
| `sui.sender_address` | `string` | `SuiParsedTransactionFacts.sender` | yes | yes | Sender is encoded in transaction bytes. | `eq`, `in` |
| `sui.gas_owner_address` | `string` | `SuiParsedTransactionFacts.gas_owner` | yes | yes | Gas owner is encoded in transaction bytes. | `eq`, `in` |
| `sui.gas_budget` | `u64_decimal` | `SuiParsedTransactionFacts.gas_budget` | yes | yes | Gas budget is encoded as `u64`. | `eq`, `lte` |
| `sui.gas_price` | `u64_decimal` | `SuiParsedTransactionFacts.gas_price` | yes | yes | Gas price is encoded as `u64`. | `eq`, `lte` |
| `sui.expiration_kind` | `string` | `SuiParsedTransactionFacts.expiration_kind` | yes | yes | Expiration variant is encoded in transaction bytes. | `eq`, `in` |
| `none` | `n/a` | `SuiParsedTransactionFacts.expiration_epoch` | yes | no | Firmware parses epoch expiration, but current Sui policy facts do not expose it. | none |
| `none` | `n/a` | `SuiParsedTransactionFacts.valid_during` | yes | no | Firmware parses valid-during bounds, but current Sui policy facts do not expose them. | none |
| `sui.command_count` | `u64_decimal` | `SuiParsedTransactionFacts.command_count` | yes | yes | Command count is parsed and bounded by Firmware capacity. | `eq`, `lte` |
| `none` | `n/a` | `SuiParsedTransactionFacts.input_count` | yes | no | Firmware parses input count, but current Sui policy facts do not expose it. | none |

### Request Context

Request context values are not Sui transaction facts. They are protocol fields
validated by Firmware before signing work.

| Policy field | Field type | Source struct/path | Offline observable | Policy usable now | Reason | Allowed operators |
| --- | --- | --- | --- | --- | --- | --- |
| `none` | `n/a` | `sign_transaction params.network` | no | no | Firmware validates the request network as one of `mainnet`, `testnet`, `devnet`, or `localnet`, but current Sui transaction bytes do not prove network identity. Request network is not emitted as a policy authorization fact. | none |

### Gas Payment Object Facts

| Policy field | Field type | Source struct/path | Offline observable | Policy usable now | Reason | Allowed operators |
| --- | --- | --- | --- | --- | --- | --- |
| `none` | `n/a` | `SuiParsedTransactionFacts.gas_payments[].object_id` | yes | no | Firmware parses gas payment object ids, but current Sui policy facts do not expose them. | none |
| `none` | `n/a` | `SuiParsedTransactionFacts.gas_payments[].version` | yes | no | Firmware parses gas payment object versions, but current Sui policy facts do not expose them. | none |
| `none` | `n/a` | `SuiParsedTransactionFacts.gas_payments[].digest_hex` | yes | no | Firmware parses gas payment object digests, but current Sui policy facts do not expose them. | none |

### Input Facts

| Policy field | Field type | Source struct/path | Offline observable | Policy usable now | Reason | Allowed operators |
| --- | --- | --- | --- | --- | --- | --- |
| `none` | `n/a` | `SuiCallArgFact.kind` | yes | no | Firmware parses input kind, but current Sui policy facts do not expose it. | none |
| `none` | `n/a` | `SuiCallArgFact.pure_length` and `pure_bytes` | yes | no | Pure bytes are observable, but current Sui policy facts do not type or expose them. | none |
| `none` | `n/a` | `SuiCallArgFact.object_ref.object_id` | yes | no | Firmware parses input object ids, but current Sui policy facts do not expose them. | none |
| `none` | `n/a` | `SuiCallArgFact.object_ref.version` | yes | no | Firmware parses input object versions, but current Sui policy facts do not expose them. | none |
| `none` | `n/a` | `SuiCallArgFact.object_ref.digest_hex` | yes | no | Firmware parses input object digests, but current Sui policy facts do not expose them. | none |
| `none` | `n/a` | `SuiCallArgFact.shared_initial_version` | yes | no | Firmware parses shared object initial version, but current Sui policy facts do not expose it. | none |
| `none` | `n/a` | `SuiCallArgFact.shared_mutable` | yes | no | Firmware parses shared object mutability, but current Sui policy facts do not expose it. | none |
| `none` | `n/a` | `SuiCallArgFact.object_receiving` | yes | no | Firmware parses receiving object refs, but current Sui policy facts do not expose them. | none |
| `none` | `n/a` | `SuiFundsWithdrawalFact.amount` | yes | no | Firmware parses funds withdrawal amount, but current Sui policy facts do not expose it. | none |
| `none` | `n/a` | `SuiFundsWithdrawalFact.type` | yes | no | Firmware parses funds withdrawal type, but current Sui policy facts do not expose it. | none |
| `none` | `n/a` | `SuiFundsWithdrawalFact.source` | yes | no | Firmware parses funds withdrawal source, but current Sui policy facts do not expose it. | none |

### Command Facts

Policy field names with `N` mean `0 <= N < 8`, the current bounded command
capacity.

`Policy usable now` means the fact can be used by current policy evaluation.
It does not mean the command shape is automatically policy-signable. Automatic
policy signing is limited to the current transfer contract described above.

| Policy field | Field type | Source struct/path | Offline observable | Policy usable now | Reason | Allowed operators |
| --- | --- | --- | --- | --- | --- | --- |
| `sui.commandN_kind` | `string` | `SuiCommandFact.kind` | yes | yes | Command kind is parsed from transaction bytes. | `eq`, `in` |
| `sui.commandN_move_call_package` | `string` | `SuiCommandFact.move_call.package` | yes | yes | MoveCall package id is encoded in transaction bytes. | `eq`, `in` |
| `sui.commandN_move_call_module` | `string` | `SuiCommandFact.move_call.module` | yes | yes | MoveCall module name is encoded in transaction bytes. | `eq`, `in` |
| `sui.commandN_move_call_function` | `string` | `SuiCommandFact.move_call.function` | yes | yes | MoveCall function name is encoded in transaction bytes. | `eq`, `in` |
| `sui.commandN_move_call_type_args` | `u64_decimal` | `SuiCommandFact.move_call.type_argument_count` | yes | yes | MoveCall type-argument count is parsed and bounded. | `eq`, `lte` |
| `sui.commandN_move_call_type_argM` | `string` | `SuiCommandFact.move_call.type_arguments[M].canonical` | yes | yes | MoveCall type arguments are parsed into canonical strings. | `eq`, `in` |
| `none` | `n/a` | `SuiCommandFact.move_call.arguments[]` | yes | no | Firmware parses argument references, but current Sui policy facts do not expose them. | none |
| `sui.recipient_count` | `u64_decimal` | `TransferObjects` recipient commands | yes | yes | Firmware counts transfer-recipient commands in bounded parser output. | `eq`, `in`, `lte` |
| `sui.recipient0_address` | `string` | First `TransferObjects` recipient when it is a typed address input | yes | yes | Firmware emits this fact only when the first transfer recipient is decoded as an address. If decoding fails, policy coverage is incomplete. Automatic `sign` rules require `eq` for this field. | `eq`, `in` |
| `sui.recipient0_amount_raw` | `u64_decimal` | Known amount sent to the first transfer recipient | yes | yes when known | Firmware exposes the amount only when it is known from transaction bytes. Unknown object balances do not create this fact. | `eq`, `in`, `lte` |
| `sui.move_call0_package` | `string` | First `MoveCall` package | yes | yes | Firmware exposes the first MoveCall package for token-flow policy matching. | `eq`, `in` |
| `sui.move_call0_module` | `string` | First `MoveCall` module | yes | yes | Firmware exposes the first MoveCall module for token-flow policy matching. | `eq`, `in` |
| `sui.move_call0_function` | `string` | First `MoveCall` function | yes | yes | Firmware exposes the first MoveCall function for token-flow policy matching. | `eq`, `in` |
| `sui.move_call0_sui_amount_raw` | `u64_decimal` | Known SUI amount passed into the first MoveCall | yes | yes when known | Firmware exposes this amount only when the argument graph resolves to known transaction-encoded amounts. | `eq`, `in`, `lte` |
| `sui.sui_total_out_complete` | `string` | Token-flow analyzer aggregate state | yes | yes | Value is `yes` only when the total outgoing SUI amount is fully known from transaction bytes. | `eq` |
| `sui.sui_total_out_raw` | `u64_decimal` | Known total outgoing SUI amount | yes | yes when complete | Firmware exposes the aggregate only when every contributing amount is known. | `eq`, `in`, `lte` |
| `sui.transfer_total_out_raw` | `u64_decimal` | Known SUI amount sent through `TransferObjects` | yes | yes when complete | Firmware exposes the aggregate only when every contributing transfer amount is known. | `eq`, `in`, `lte` |
| `sui.move_call_total_in_raw` | `u64_decimal` | Known SUI amount passed into MoveCall arguments | yes | yes when complete | Firmware exposes the aggregate only when every contributing MoveCall amount is known. | `eq`, `in`, `lte` |
| `sui.coin_flow0_source_kind` | `string` | First token-flow source kind | yes | yes | Source kind is one of the Firmware-defined token-flow source labels. | `eq`, `in` |
| `sui.coin_flow0_asset_state` | `string` | First token-flow SUI provenance state | yes | yes | Value is `proven_sui` only when Firmware can prove the flow is SUI, currently from `GasCoin`; otherwise `unproven`. Automatic `sign` rules require `eq proven_sui`. | `eq`, `in` |
| `sui.coin_flow0_amount_known` | `string` | First token-flow amount state | yes | yes | Value is `yes` when the first flow amount is known and `no` otherwise. | `eq` |
| `sui.coin_flow0_amount_raw` | `u64_decimal` | First token-flow known amount | yes | yes when known | Firmware exposes the amount only when known from transaction bytes. | `eq`, `in`, `lte` |
| `sui.coin_flow0_sink_kind` | `string` | First token-flow sink kind | yes | yes | Sink kind is one of the Firmware-defined token-flow sink labels. | `eq`, `in` |
| `sui.coin_flow0_object_id` | `string` | First token-flow object id when present | yes | yes when present | Firmware exposes the object id only when the flow is tied to an object reference. | `eq`, `in` |
| `none` | `n/a` | `SplitCoins` source, amount args, and result refs beyond the exposed aggregates | yes | no | Firmware parses bounded command references but exposes only the current aggregate and first-flow policy fields. | none |
| `none` | `n/a` | `MergeCoins` destination and source refs beyond the exposed aggregates | yes | no | Firmware parses bounded command references but exposes merge effects through current aggregate policy fields. | none |
| `none` | `n/a` | `MakeMoveVec` type and argument refs | yes | no | Firmware parses vector construction facts, but current Sui policy facts do not expose them. | none |
| `none` | `n/a` | `Publish` module count and dependencies | yes | no | Firmware parses publish metadata, but current Sui policy facts do not expose it. | none |
| `none` | `n/a` | `Upgrade` module count, dependencies, package, and ticket | yes | no | Firmware parses upgrade metadata, but current Sui policy facts do not expose it. | none |

## 5. Current Token Amount Policy Status

Current Sui policy facts expose bounded token-flow amount fields when Firmware
can derive those amounts from serialized transaction bytes.

Firmware can observe `SplitCoins` amount arguments and connect split results to
`TransferObjects`, `MoveCall`, and `MergeCoins` uses inside the bounded parser
capacity. A split amount is counted as automatic-policy-signable SUI only when
the split source is `GasCoin`. A known numeric amount from a non-gas coin
source, direct object, funds-withdrawal input, or unproven merge result is not a
known SUI amount for automatic policy signing. `MergeCoins` is modeled as an
internal coin-state update, not as external SUI outflow. Firmware cannot infer
the balance or asset type of an existing coin object from its object id,
version, or digest.

Unknown amount is not zero. When an amount is unknown or incomplete, Firmware
does not emit the corresponding raw amount fact. A policy criterion that
requires that missing amount fact does not match. Sui policy-mode signing
requires the current automatic signing contract and a matching bounded `sign`
rule. Current automatic signing coverage is limited to GasCoin-derived
proven-SUI split-result transfer facts; broader parsed facts do not
automatically make a transaction policy-signable.

## 6. Unsupported Online-State Facts

These values are not policy facts because Firmware cannot verify them from
serialized transaction bytes alone:

| Unsupported value | Reason |
| --- | --- |
| Current coin object balance | Requires online object state. |
| Current object owner | Requires online object state. |
| Shared object live state | Requires online state at execution time. |
| Move function runtime behavior | Requires Move execution or dry-run. |
| Dry-run result | Host or fullnode output is not Firmware-derived policy input. |
| Token decimal or symbol | Requires registry or package metadata outside transaction bytes. |
| Upstream user/app/dapp/agent intent | Firmware cannot observe why the request was created. |
| Whether the host built the transaction online successfully | Firmware can validate bytes, not the host's build path. |
| Current network object availability or lock state | Requires online chain state. |
