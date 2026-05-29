# Agent-Q Implementation Status

This document is the source of truth for what Agent-Q currently implements
across the common protocol, Gateway, firmware targets, chain adapters, and
security profiles.

Legend:

- `O`: implemented and verified for at least one target.
- `△`: partially implemented, designed but not complete, or implemented only as
  a local diagnostic/self-test.
- `X`: not implemented.
- `N/A`: not applicable to that target.

This document tracks implementation status only. The wire protocol is defined in
`specs/PROTOCOL.md`. Target-specific details live under
`products/firmware/src/<hardware-id>/`.

## Common Protocol

| Item | Common Status | Notes |
|---|---:|---|
| `get_status` | O | Implemented by the current StackChan CoreS3 target and used by Gateway discovery. |
| `identify_device` | O | Implemented as temporary device UI for explicit user selection. |
| `connect` | O | Implemented as a runtime communication session with physical approval on supported targets. |
| `disconnect` | O | Implemented for active runtime sessions. |
| `get_capabilities` | X | Designed session-scoped request; not implemented. |
| `get_accounts` | X | Designed session-scoped request; not implemented. |
| `call_method` | X | Designed session-scoped dispatch for all chains and methods; not implemented. |
| Hardware diagnostic `display_signal` | O | Implemented for firmware/UI smoke testing. Not a public signing API. |

## Gateway

| Item | Status | Notes |
|---|---:|---|
| stdio MCP server | O | Starts with no CLI arguments. |
| USB device scan | O | Scans candidate USB serial ports and sends bounded status handshakes. |
| Device identification | O | Requests device-displayed short codes before selection. |
| Active device selection | O | Stores selected device id and USB transport hint locally. |
| Device labels | O | Gateway-local metadata only. Not a security boundary. |
| Purpose routing | O | Gateway-local routing metadata only. Not Firmware policy. |
| Runtime connection sessions | O | Held in Gateway memory only; session id is not exposed to MCP clients. |
| Cached device status | O | Exposed only for previously seen devices and marked non-live. |
| MCP output sanitization | O | Tool outputs and public errors are schema-bounded before reaching clients. |
| Admin Page | X | Intended Gateway capability; not implemented. |
| Firmware update/admin command path | X | Not exposed through MCP. |
| Signing APIs | X | Must be exposed through common `call_method`, not chain-specific top-level MCP tools. |

Current MCP tools:

| Tool | Status | Notes |
|---|---:|---|
| `scan_devices` | O | USB discovery. |
| `identify_devices` | O | Shows short codes on discovered devices. |
| `select_device` | O | Updates local Gateway selection only. |
| `get_device_status` | O | Returns live or clearly marked cached status. |
| `list_devices` | O | Lists Gateway-known devices and local metadata. |
| `set_device_metadata` | O | Sets or clears local label. |
| `connect_device` | O | Opens a runtime session after device approval. |
| `disconnect_device` | O | Ends a runtime session or clears stale local session state. |

## Firmware Targets

| Capability | StackChan CoreS3 | Minimal LED-only Device | Button/Display Approval Device | Notes |
|---|---:|---:|---:|---|
| USB transport | O | X | X | StackChan CoreS3 target is the only implemented firmware target. |
| Persistent `deviceId` | O | X | X | Stored in device-local NVS for the implemented target. |
| `get_status` | O | X | X | Common protocol request. |
| `identify_device` | O | X | X | Uses temporary avatar speech bubble on StackChan CoreS3. |
| `connect` physical approval | O | X | X | StackChan CoreS3 uses touch approval. |
| `disconnect` | O | X | X | StackChan CoreS3 clears matching runtime session. |
| Request/result UI | O | X | X | StackChan CoreS3 uses Agent-Q-owned avatar speech bubble and top decision strip. |
| Per-request `ask` approval | X | N/A | X | Not implemented for signing requests because signing requests are not implemented. |
| Automatic `sign` / `reject` policy action | X | X | X | Requires policy evaluator and signing method support. |
| Local key storage | X | X | X | Current signing code is only a boot-time self-test with a temporary seed. |
| Policy storage | X | X | X | Not implemented. |
| Secure user profile | X | X | X | Secure Boot, Flash Encryption, anti-rollback, and provisioning flow are documented but not implemented. |
| StackChan/Xiaozhi remote AI runtime | N/A | N/A | N/A | Disabled in the Agent-Q StackChan build; not part of Agent-Q signing firmware. |
| Camera / remote upload surfaces | N/A | N/A | N/A | Disabled in the Agent-Q StackChan build. |

Target-specific specification:

- StackChan CoreS3: `products/firmware/src/stackchan-cores3/SPEC.md`

## Hardware Chain Support

This table summarizes chain and method support by hardware target. Detailed
target-specific notes live in each target's `SPEC.md`.

| Hardware target | Sui Ed25519 | Sui zkLogin | EVM | Solana | Notes |
|---|---:|---:|---:|---:|---|
| StackChan CoreS3 | △ | X | X | X | Has only a boot-time Sui Ed25519 self-test with a temporary seed. No account or signing API exists yet. |
| Minimal LED-only Device | X | X | X | X | Planned target; no firmware implementation yet. |
| Button/Display Approval Device | X | X | X | X | Planned target class; no firmware implementation yet. |

## Chain And Method Adapters

Agent-Q must not create chain-specific top-level MCP tools. Chains and signing
methods must be exposed as capabilities and invoked through the common
session-scoped `call_method` protocol.

| Adapter | Status | Notes |
|---|---:|---|
| Sui Ed25519 signing self-test | △ | Firmware can link signing code, generate a runtime test seed, sign, verify, and wipe the test seed. This is not a signing API. |
| Sui `sign_personal_message` | X | Not implemented. |
| Sui `sign_transaction` | X | Not implemented. |
| Sui txBytes decoder | X | Not implemented. |
| Sui zkLogin | X | Not implemented; separate trust model required. |
| EVM | X | Not implemented. |
| Solana | X | Not implemented. |

## Policy And Security Profiles

| Item | Status | Notes |
|---|---:|---|
| Security model document | O | See `docs/SECURITY_MODEL.md`. |
| Deny-by-default policy model | △ | Documented target behavior; evaluator not implemented. |
| Policy evaluator | X | Not implemented. |
| Policy storage | X | Not implemented. |
| Policy update authorization | X | Not implemented. |
| Request replay protection | X | Not implemented. |
| Secure Boot profile | X | Documented target behavior; not implemented. |
| Flash Encryption profile | X | Documented target behavior; not implemented. |
| Anti-rollback / secure version | X | Documented target behavior; not implemented. |
| Owner firmware signing mode | X | Documented target behavior; not implemented. |

## Explicitly Unsupported Or Out Of Scope

- Ledger-grade or secure-element-backed physical extraction resistance.
- Agent, prompt, or host intent detection.
- Chain-specific top-level MCP tools such as `sign_sui_transaction`.
- MCP-admin commands that export keys, update policy, flash firmware, read
  memory, or bypass Firmware policy.
- Fiat cash-out, P&L, tax, or cost-basis features.
- Treating Gateway labels or purpose routing as security policy.
- Treating `connect_device` as signing approval.
