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
| Provisioning status reporting | O | `get_status` includes `provisioning.state`; Gateway parses and preserves it. This is not signing readiness. |
| Mnemonic UI flow v0 | △ | `start_provisioning` or the local setup speech bubble generates a DEV_PROFILE BIP-39 phrase into RAM from an early-boot-seeded Agent-Q CSPRNG and displays only up-to-4-letter prefixes on device in a 3-column by 4-row grid with bottom Cancel/Confirm buttons. Three-letter BIP-39 words are displayed as the full word. Local Confirm or approved `confirm_recovery_phrase_backup` stores root material and wipes volatile scratch; local Cancel or `cancel_provisioning` wipes volatile scratch. Gateway parser tests cover host-side shape and strict rejection of unsupported recovery phrase response fields. Hardware smoke is still required. |
| Persistent root material | △ | StackChan CoreS3 source stores the confirmed BIP-39 root entropy as an ordinary DEV_PROFILE NVS blob and reports `provisioned` only when that blob and `prov_state=provisioned` agree. This is not USER_PROFILE encrypted storage. Hardware smoke is still required. |
| Factory reset / root wipe | △ | StackChan CoreS3 source adds a physical-approval `factory_reset` path that clears RAM sessions, wipes volatile setup scratch, erases the DEV_PROFILE root entropy blob, persists `unprovisioned`, and recovers from root/state consistency error. This is a DEV_PROFILE development/recovery path and is not exposed as a normal agent-facing MCP tool. Hardware smoke is still required. |
| `identify_device` | O | Implemented as temporary device UI for explicit user selection. |
| `connect` | △ | Protocol and Gateway parser support exist. StackChan CoreS3 source restores provisioned-only Firmware sessions after persistent root material exists. Hardware smoke is still required. |
| `disconnect` | △ | Protocol and Gateway parser support exist. StackChan CoreS3 source clears a matching active Firmware session after `provisioned`. Hardware smoke is still required. |
| `get_capabilities` | △ | StackChan CoreS3 source returns Firmware-authored Sui Ed25519 account identity capability over an approved session while `provisioned`. The current `methods` list is empty because no concrete signing method, physical approval integration, or signing implementation exists. Hardware smoke is still required. |
| `get_accounts` | △ | StackChan CoreS3 source derives the Sui Ed25519 account (index 0, `m/44'/784'/0'/0'/0'`) from stored root material and returns it over an approved session while `provisioned`. Read-only: no mnemonic, seed, entropy, or private key in responses, logs, or UI. Derivation verified against Sui SDK address vectors on host (`test_sui_account_vectors.sh`); hardware smoke is still required. |
| `call_method` | △ | Runtime skeleton exists in Gateway and StackChan CoreS3 source. It is provisioned/session-scoped and currently rejects every method with `unsupported_method`; no txBytes parsing, policy decision consumption, physical approval, capability advertisement, or signing is connected. Hardware smoke is still required. |
| Hardware diagnostic `display_signal` | O | Implemented for firmware/UI smoke testing after material-backed `provisioned`. Not a public signing API. |

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
| Provisioning transition parser | O | Gateway can build and parse provisioning transition protocol messages. `start_provisioning` success is a recovery phrase display result in the current mnemonic UI flow. It does not expose a provisioning write MCP tool. |
| Recovery phrase setup parser | O | Gateway can parse recovery phrase setup results and rejects recovery phrase responses that carry unsupported fields or secret material. It does not expose these requests as MCP tools. |
| Factory reset parser | O | Gateway can build and parse the physical-approval `factory_reset` protocol messages. It does not expose this destructive request as a normal MCP signing tool. |
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
| `connect_device` | △ | Gateway tool exists. StackChan CoreS3 source accepts Firmware `connect` only after persistent root material and `provisioned` exist; hardware smoke is still required. |
| `disconnect_device` | △ | Ends a runtime session or clears stale local session state when a session exists. |
| `get_capabilities` | △ | Gateway tool and protocol parser exist. Returns Firmware-authored Sui Ed25519 account identity capability over an active runtime session with `methods: []`, rejects unsupported chains/methods/secret-like fields, and never exposes the session id to MCP. Hardware smoke is still required. |
| `get_accounts` | △ | Gateway tool and protocol parser exist. Returns public accounts over an active runtime session, strictly re-validates the account shape, recomputes the Sui address/public-key relationship, rejects secret-like fields, and never exposes the session id to MCP. Hardware smoke is still required. |
| `call_method` | △ | Gateway tool and protocol parser exist for the common session-scoped method path. The current skeleton returns Firmware-authored `rejected/unsupported_method` only and never exposes the session id to MCP. It is not signing support. |

## Firmware Targets

| Capability | StackChan CoreS3 | Minimal LED-only Device | Button/Display Approval Device | Notes |
|---|---:|---:|---:|---|
| USB transport | O | X | X | StackChan CoreS3 target is the only implemented firmware target. |
| Persistent `deviceId` | O | X | X | Stored in device-local NVS for the implemented target. |
| `get_status` | O | X | X | Common protocol request. |
| Provisioning status reporting | △ | X | X | StackChan CoreS3 firmware source reports `unprovisioned` or material-backed `provisioned`. Hardware smoke is still required. |
| Mnemonic UI flow v0 | △ | X | X | StackChan CoreS3 source adds DEV_PROFILE 12-word BIP-39 recovery phrase generation into RAM from an early-boot-seeded Agent-Q CSPRNG, device-only up-to-4-letter prefix display in 3 columns by 4 rows, persistent root material storage on confirmed backup, and wipe on cancel/confirm/reject/display expiry/timeout. Hardware smoke is still required. |
| `identify_device` | O | X | X | Uses temporary avatar speech bubble on StackChan CoreS3. |
| `connect` physical approval | △ | X | X | StackChan CoreS3 source supports physical approval only after material-backed `provisioned`; before that it returns `invalid_state`. Hardware smoke is still required. |
| `disconnect` | △ | X | X | StackChan CoreS3 source clears a matching active Firmware session after `provisioned`. Hardware smoke is still required. |
| `get_capabilities` | △ | X | X | StackChan CoreS3 source reports Sui Ed25519 account identity capability for account 0 over an approved session while `provisioned`; `methods` is empty until signing methods are implemented. Hardware smoke is still required. |
| `get_accounts` | △ | X | X | StackChan CoreS3 source derives and returns the Sui Ed25519 account 0 over an approved session while `provisioned`; read-only, no private material emitted. Hardware smoke is still required. |
| `call_method` | △ | X | X | StackChan CoreS3 source enforces provisioned/session gates and returns `unsupported_method` for every method. It does not parse txBytes, consume policy decisions, ask for signing approval, or sign. Hardware smoke is still required. |
| `factory_reset` | △ | X | X | StackChan CoreS3 source supports physical-approval wipe back to `unprovisioned`, including material/state consistency-error recovery. Hardware smoke is still required. |
| Request/result UI | O | X | X | StackChan CoreS3 uses Agent-Q-owned top avatar speech bubble and bottom decision strip. |
| Display power control | O | X | X | StackChan CoreS3 turns the screen backlight off after one minute of inactivity, skips the upstream screensaver, wakes for Agent-Q UI, toggles display power on side-button short press, and powers off on side-button long press. Before screen-off or power-off, it moves to a rest posture; when the screen wakes, it returns to awake posture. |
| Boot/sleep posture | O | X | X | StackChan CoreS3 centers yaw and raises pitch when the default avatar is attached at boot or the screen wakes, and moves to centered yaw and lowered pitch before screen-off or power-off. |
| Per-request `ask` approval | X | N/A | X | Not implemented for signing requests because signing requests are not implemented. |
| Automatic `sign` / `reject` policy action | X | X | X | Common policy source can calculate internal `sign`/`reject`/`ask` decisions and now has a default-reject runtime provider boundary in host tests, but no target connects policy decisions to runtime `call_method`, physical approval, or signing. |
| Persistent signing material | △ | X | X | StackChan CoreS3 source stores DEV_PROFILE BIP-39 root entropy after backup confirmation. Public account derivation is implemented (`get_accounts`, Sui Ed25519 account 0); it does not sign. |
| Policy storage | X | X | X | Not implemented. |
| Provisioning flow | △ | X | X | DEV_PROFILE mnemonic UI and persistent root material storage source exists for StackChan CoreS3. Public Sui account derivation is implemented via `get_accounts`; mnemonic import, signing use, policy, and USER_PROFILE secure provisioning are not implemented. |
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
| StackChan CoreS3 | △ | X | X | X | Boot-time Sui Ed25519 self-test plus read-only `get_accounts` account-0 derivation; no signing API exists yet. |
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
| Sui txBytes decoder | △ | Common firmware source includes a restricted host-tested SUI transfer facts parser for `TransactionData::V1 -> ProgrammableTransaction -> SplitCoins(GasCoin, [Input(amountPure)]) -> TransferObjects([Result(0)], Input(recipientPure))`. The parsed facts can feed the common policy evaluator/runtime boundary in host tests, but the `call_method` skeleton does not connect the parser to runtime requests, capability advertisement, or signing. |
| Sui zkLogin | X | Not implemented; separate trust model required. |
| EVM | X | Not implemented. |
| Solana | X | Not implemented. |

## Policy And Security Profiles

| Item | Status | Notes |
|---|---:|---|
| Security model document | O | See `docs/SECURITY_MODEL.md`. |
| State model document | O | See `docs/STATE_MODEL.md`. It defines product states, state-gated protocol functions, and responsibility boundaries. |
| Provisioning flow document | O | See `docs/PROVISIONING.md`. USER_PROFILE mnemonic/key provisioning is not implemented. |
| Provisioning status reporting | O | Firmware reports `provisioning.state`; Gateway exposes it without treating it as signing readiness. |
| Mnemonic UI flow v0 | △ | StackChan CoreS3 source adds DEV_PROFILE BIP-39 recovery phrase generation from an early-boot-seeded Agent-Q CSPRNG, device-only up-to-4-letter prefix display, and confirmed root material storage. It stores no mnemonic text, private key, account, or policy. Hardware smoke is still required. |
| Deny-by-default policy model | △ | Common firmware source includes a host-tested policy evaluator/runtime boundary that loads a compiled default-reject policy, rejects malformed/missing policy or unsupported facts, and returns `sign`, `reject`, or `ask` decisions only as internal calculation results. It is not connected to runtime signing. |
| Policy evaluator | △ | Common firmware source implements a declarative policy evaluator, a default-reject policy provider boundary, and a Sui restricted-transfer facts adapter. Host tests cover positive and negative decisions, missing/invalid policy provider failure, and unsupported facts. The `call_method` skeleton exists, but policy decisions are not connected to physical approval, capability advertisement, or signing. |
| Policy storage | X | Not implemented. |
| Policy update authorization | X | Not implemented. |
| Mnemonic generation/import | △ | DEV_PROFILE recovery phrase generation/display and persistent root material storage source exists for StackChan CoreS3. Mnemonic import, USER_PROFILE secure root storage, and signing use remain unimplemented. |
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
