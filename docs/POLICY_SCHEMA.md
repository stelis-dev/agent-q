# Agent-Q Policy Schema

This document describes the current Agent-Q policy document shape and the Sui
`sign_transaction` facts that Firmware can derive from serialized transaction
bytes for offline policy evaluation.

It describes source behavior only. It is not a product-active claim.

## Current Status

- The current policy schema is `agentq.policy`.
- Firmware stores one active policy document.
- Firmware owns policy validation, policy storage, policy evaluation, and
  signing decisions.
- Host process, MCP, provider, Sui CLI signer, Admin Page, apps, SDK JSON,
  dry-run output, and display strings are request surfaces, not policy
  authorities.
- Policy mode does not fall back to user confirmation or user-mode blind
  signing.
- Current source contains the policy document parser/storage/readback boundary,
  the Sui offline condition-facts extractor, and the current policy evaluator for
  Sui `sign_transaction`. Firmware signs in policy mode only when the active
  current policy has a matching `sign` policy over complete Firmware-derived
  offline condition facts. Missing, incomplete, unmatched, or reject-matched
  policy coverage fails closed with `policy_rejected`.

## Policy Document Shape

```text
schema = agentq.policy
defaultAction = reject

blockchains[]
  blockchain
  networks[]
    network
    policies[] = OR
      id
      action
      conditions[] = AND
        field
        op
        value | values
```

`blockchain` and `network` are scope selectors. They are not condition fields.
Network is request metadata; serialized Sui transaction bytes do not prove
network identity.

Current actions:

| Action | Meaning |
| --- | --- |
| `reject` | Reject when the policy matches. |
| `sign` | Allow policy-mode signing only when every selected condition evaluates true in Firmware. |

Current operators:

| Operator | Shape | Meaning |
| --- | --- | --- |
| `eq` | `value` | Scalar field equals one value. |
| `in` | `values[]` | Scalar field equals one value from a bounded list. |
| `not_in` | `values[]` | Scalar field does not equal any listed value. |
| `lte` | `value` | Unsigned decimal field is less than or equal to one bound. |
| `contains` | `value` | Set field contains one value. |
| `not_contains` | `value` | Set field does not contain one value. |
| `all_in` | `values[]` | Every observed set value is inside the allow list. |
| `none_in` | `values[]` | No observed set value is inside the deny list. |

Current value types:

| Type | Representation |
| --- | --- |
| `string` | Canonical ASCII string. |
| `u64_decimal` | Canonical unsigned decimal string. |
| `bool_string` | `true` or `false`. |

Sui type strings used in token conditions must match the canonical type string
that Firmware derives from transaction bytes. For SUI, use:

```text
0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI
```

## Sui Policy Fields

Firmware derives these fields from the same serialized `TransactionData` bytes
that would be signed. It does not trust host JSON or SDK JSON for policy facts.

### Scope

| Selector | Source | Values |
| --- | --- | --- |
| `blockchain` | Policy document scope | `sui` |
| `network` | Request metadata and policy document scope | `mainnet`, `testnet`, `devnet`, `localnet` |

### Transaction Fields

| Field | Type | Operators |
| --- | --- | --- |
| `sui.gas_budget_raw` | `u64_decimal` | `eq`, `lte` |
| `sui.gas_price_raw` | `u64_decimal` | `eq`, `lte` |
| `sui.gas_owner` | `string` | `eq`, `in`, `not_in` |
| `sui.sponsored` | `bool_string` | `eq` |
| `sui.command_count` | `u64_decimal` | `eq`, `lte` |

For sponsored Sui transactions, `sui.gas_owner`, `sui.gas_budget_raw`, and
`sui.gas_price_raw` describe the sponsor gas data in the serialized transaction.
They are not a user spending limit. Use `sui.sponsored eq false` when a policy
must reject sponsored transactions. Use token-source and token-total facts for
offline user-asset limits that Firmware can derive from the transaction bytes.

### Command Fields

| Field | Type | Operators |
| --- | --- | --- |
| `sui.command_kinds` | string set | `contains`, `not_contains`, `all_in`, `none_in` |
| `sui.move_call_packages` | string set | `contains`, `not_contains`, `all_in`, `none_in` |
| `sui.move_call_modules` | string set | `contains`, `not_contains`, `all_in`, `none_in` |
| `sui.move_call_functions` | string set | `contains`, `not_contains`, `all_in`, `none_in` |
| `sui.publish_present` | `bool_string` | `eq` |
| `sui.upgrade_present` | `bool_string` | `eq` |

`TransferObjects`, `SplitCoins`, and `MergeCoins` can be controlled through
`sui.command_kinds` as coarse command switches. They are not token type or
token amount facts by themselves.

### Address Fields

| Field | Type | Operators |
| --- | --- | --- |
| `sui.recipient_addresses` | address string set | `contains`, `not_contains`, `all_in`, `none_in` |
| `sui.pure_address_arguments` | address string set | `contains`, `not_contains`, `none_in` |

Firmware treats arbitrary pure bytes as addresses only when the transaction
context expects an address and the bytes decode as a canonical Sui address.

### Token Fields

| Field | Type | Operators |
| --- | --- | --- |
| `sui.token_sources.type` | type string | `eq`, `in`, `not_in` |
| `sui.token_sources.source` | string | `eq`, `in` |
| `sui.token_sources.amount_raw` | `u64_decimal` | `eq`, `lte` |
| `sui.token_totals_by_type.amount_raw` | `u64_decimal` | `eq`, `lte` |
| `sui.token_unknown_amount_present` | `bool_string` | `eq` |

`sui.token_totals_by_type.amount_raw` requires a `where.type` selector. The
selector is the canonical token type whose aggregate amount is compared:

```json
{
  "field": "sui.token_totals_by_type.amount_raw",
  "where": {
    "type": "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI"
  },
  "op": "lte",
  "value": "1000000000"
}
```

Without `where.type`, a token-total amount condition is invalid policy material.
Do not combine `sui.token_sources.type` with `sui.token_sources.amount_raw` to
express a per-token total amount policy. `token_sources` fields describe every
observed bounded source; they are not a row-join mechanism for selecting one
token type's total.

Supported offline token amount sources:

- `GasCoin` split: SUI only, amount from a pure `u64` split amount.
- `FundsWithdrawal<T>`: SUI or non-SUI, type and amount from transaction bytes,
  source from sender or sponsor.

Unsupported token amount sources:

- Direct object input.
- Object id, version, or digest used to infer token type or balance.
- Split or merge paths whose input token provenance is unknown.
- Any value requiring online object state, dry-run output, or registry metadata.

Unknown amount is not zero. If a token condition needs an amount or type that
Firmware cannot derive offline, policy evaluation must fail closed.

## Minimal Sui Testnet Policy Template

The Admin Page includes this current-schema template for testing policy-mode
signing on Sui testnet. It authorizes only requests whose Firmware-derived
offline facts show SUI from `GasCoin` splits, no unknown token amount, and a
total amount of at most 1 SUI.

```json
{
  "schema": "agentq.policy",
  "defaultAction": "reject",
  "blockchains": [
    {
      "blockchain": "sui",
      "networks": [
        {
          "network": "testnet",
          "policies": [
            {
              "id": "sign-testnet-sui-up-to-one",
              "action": "sign",
              "conditions": [
                {
                  "field": "sui.token_sources.source",
                  "op": "eq",
                  "value": "gas_coin"
                },
                {
                  "field": "sui.token_totals_by_type.amount_raw",
                  "where": {
                    "type": "0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI"
                  },
                  "op": "lte",
                  "value": "1000000000"
                },
                {
                  "field": "sui.token_unknown_amount_present",
                  "op": "eq",
                  "value": "false"
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}
```

This template is intentionally narrow. It is not a claim that every Sui
transaction spending at most 1 SUI will pass; the Firmware evaluator only uses
offline facts it can derive from the exact transaction bytes it signs.

## Requester Guidance

For policy-mode requests that need a SUI amount limit, build the transaction so
the amount is observable from transaction bytes:

- use `SplitCoins(GasCoin, [amount])` for SUI;
- keep split amounts as pure `u64` values;
- pass the split result into transfer or application commands;
- avoid direct coin-object inputs when the policy depends on token type or
  amount, because Firmware cannot know a direct object coin balance offline;
- avoid mixing known and unknown token provenance when the policy depends on
  token amount;
- send the request with the intended policy scope network, such as `testnet`.

For non-SUI token amount policy, use `FundsWithdrawal<T>` inputs when available
for the transaction form. Firmware can derive the type and amount from those
bytes. Object ids, object versions, object digests, symbols, decimals, dry-run
results, and fullnode state are not policy facts.

## Policy-Mode Outcomes

| Condition | Outcome |
| --- | --- |
| Malformed or unsupported transaction bytes | No signing. |
| Sender mismatch, rejected gas owner mismatch, or unsupported account binding | No signing. |
| No active policy or no matching blockchain/network scope | Reject. |
| Missing or incomplete condition facts | Reject. |
| Unknown token type, unknown token amount, mixed known/unknown token provenance, or amount overflow | Reject. |
| Matching reject policy | Reject. |
| Matching sign policy | Authorize policy-mode Sui `sign_transaction` signing after the active policy, request network, account-binding, and complete offline condition-facts gates pass. |

User-mode clear or blind signing is separate. Policy mode must not route to user
confirmation or blind signing.

## Unsupported Online-State Facts

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
