# <Hardware Id> Agent-Q Firmware Specification

This document describes the current `<Hardware Id>` Firmware target.

The shared host process/Firmware protocol is defined in `specs/PROTOCOL.md`.
This target must fit that protocol and must not define target-specific product
APIs.

## Target Role

`<Hardware Id>` is a Firmware target for:

- replace with implemented product role;
- replace with implemented transport;
- replace with implemented account and signing material model;
- replace with implemented local approval model.

It does not expose MCP directly, does not provide chain-specific signing APIs,
does not expose debug/internal-state inspection, and does not provide
host-triggered state setters.

## Target Status

Legend:

- `O`: implemented and verified on this target.
- `△`: source-wired or partially verified; not product-active.
- `X`: not implemented on this target.
- `N/A`: not applicable to this target.

| Capability | Status | Notes |
|---|---:|---|
| Transport | X | Replace with the implemented transport and framing. |
| `get_status` | X | Must project shared `device.state` and `provisioning.state`. |
| `identify_device` | X | Must be temporary UI only. |
| `connect` | X | Must use Firmware-owned approval when no live approved session exists. |
| `disconnect` | X | Must clear only matching session-scoped state. |
| `get_capabilities` | X | Must use the shared capability schema. |
| `get_accounts` | X | Must use the shared account schema and expose no private material. |
| Local authentication | X | State whether implemented, unavailable, or N/A. |
| Credential preparation/proposal | X | State whether implemented, unavailable, or N/A. |
| Payload transfer | X | Required for large credential or signing payloads. |
| Policy storage/read | X | State whether implemented, unavailable, or N/A. |
| Policy update | X | Must be proposal + Firmware-owned approval, not a direct setter. |
| Signing authorization mode | X | Must be Firmware-owned state, not a request parameter. |
| `sign_transaction` | X | State implemented chain/method routes and authorization gates. |
| `sign_personal_message` | X | State implemented chain/method routes and authorization gates. |
| Approval history | X | Must store only bounded Firmware-authored metadata. |
| Retained responses | X | Required when signing responses can exceed immediate delivery assumptions. |
| Display feedback | X | Target-local UI only. |
| Input feedback | X | Must map to shared approve/reject/timeout outcomes. |
| Power behavior | X | Target-local; must not authorize protocol behavior. |

## Common Modules Used

List every common source module consumed by this target and why it is the source
of truth.

| Common module | Owned invariant | Target adapter, if any |
|---|---|---|
| `firmware/src/common/protocol/device_contract.*` | Shared method/error table | None |
| `firmware/src/common/transport/payload_delivery_*` | Shared payload-transfer state rules | Transport adapter |
| `firmware/src/common/signing/user_signing_flow.*` | Shared user-signing state flow | UI/input/signing-material adapters |

Do not list expected future reuse. List only current consumed modules.

## Target Adapters

List target-owned adapters. These may differ by hardware, but they must not
change shared product state or protocol contracts.

| Adapter | Target owner | Common contract consumed |
|---|---|---|
| Transport adapter |  |  |
| Storage adapter |  |  |
| Identity adapter |  |  |
| Signing-material adapter |  |  |
| Display/input adapter |  |  |
| Power adapter |  |  |

## State Composition

Describe how this target composes shared product state with target-local
details. Do not define a separate product-state contract.

State projection:

- before local setup or required material exists:
- after local setup but before account/signing material exists:
- after account/signing material exists:
- while locked:
- while pending approval:
- while request processing is busy:
- while persistent material is inconsistent:

For every implemented state transition, specify:

- trigger;
- guard;
- side effects;
- state owner;
- sensitive scratch cleanup;
- post-failure state;
- protocol-visible result.

## Storage Layout

List current storage records only. Do not document previous layouts or migration
paths unless an explicit product requirement approves them.

| Record | Namespace / partition | Erased by settings repair? | Erased by Device reset? | Contains private material? |
|---|---|---:|---:|---:|
|  |  |  |  |  |

Rules:

- signing key material must not be erased by settings repair;
- mutable settings may be reset to current defaults when recoverable;
- unknown or unsupported persistent data must fail closed;
- product firmware must not call partition-wide erase as recovery;
- destructive key erasure must be device-local and explicit.

## Protocol Method Gates

For each method, state the allowed source states, rejected source states, and
shared error code. The host process may hide unavailable operations, but
Firmware must enforce the gates.

| Method | Allowed state | Rejected state | Error code | Approval/UI |
|---|---|---|---|---|
| `get_status` |  |  |  |  |
| `identify_device` |  |  |  |  |
| `connect` |  |  |  |  |
| `disconnect` |  |  |  |  |
| `get_capabilities` |  |  |  |  |
| `get_accounts` |  |  |  |  |
| `credential_prepare` |  |  |  |  |
| `credential_propose` |  |  |  |  |
| `payload_transfer` |  |  |  |  |
| `policy_get` |  |  |  |  |
| `policy_propose` |  |  |  |  |
| `get_approval_history` |  |  |  |  |
| `get_result` |  |  |  |  |
| `ack_result` |  |  |  |  |
| `sign_transaction` |  |  |  |  |
| `sign_personal_message` |  |  |  |  |

## UI And Power

Describe target-local UI and power behavior. UI state must not be the source of
truth for provisioning, session, account, policy, signing, or scratch state.

Required statements:

- how the target shows temporary identification;
- how the target asks for approval;
- how approve, reject, and timeout map to shared outcomes;
- how display off/on affects local authentication and request UI;
- how USB removal, reset, or power loss clears volatile state.

## Signing And Policy

If signing is implemented, state:

- supported routes;
- parser/source-of-truth module;
- account binding rule;
- authorization mode rule;
- policy-mode rule;
- user-confirmation rule;
- blind-signing rule, if any;
- history write requirement;
- retained-response requirement;
- scratch wipe requirement;
- hardware smoke evidence status.

If signing is not implemented, state the shared error returned for each signing
method in every relevant state.

## Unsupported Surfaces

This target does not implement:

- debug state setter;
- host-triggered setup;
- host-triggered reset;
- host-triggered proof clear;
- host-triggered signing-mode selection;
- signer selector;
- target-specific protocol method;
- target-specific public schema;
- internal-state inspection command.

Add target-specific unsupported surfaces only when they might be confused with
implemented behavior.
