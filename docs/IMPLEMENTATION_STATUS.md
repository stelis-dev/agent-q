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
| Provisioning status reporting | O | `get_status` includes `provisioning.state`; Gateway parses and preserves it. Firmware reports `error` instead of `provisioned` when persistent material consistency fails. This is not signing readiness. |
| Mnemonic UI flow | △ | The local setup speech bubble opens a Generate/Recover choice. Generate creates a DEV_PROFILE BIP-39 phrase into RAM from an early-boot-seeded Agent-Q CSPRNG and displays only up-to-4-letter prefixes on device in a 3-column by 4-row grid with bottom Cancel/Confirm buttons. Recover accepts 12 BIP-39 words through a device-local 3-word-per-page prefix/candidate UI and verifies checksum. Three-letter BIP-39 words are displayed as the full word. Local Confirm or successful Recover verification advances to local 6-digit PIN entry; matching PIN repeat stores root material, initializes the active default-reject policy, stores a salt + PIN verifier, and wipes volatile scratch. Local Cancel wipes volatile scratch. There is no USB protocol request for setup start, setup cancel, backup confirmation, or mnemonic import. Generate setup and PIN entry were manually smoke-tested after commit `2cb243b`; Recover was manually smoke-tested on StackChan CoreS3 during the recovery-entry slice. |
| Persistent material | △ | StackChan CoreS3 source stores the confirmed BIP-39 root entropy, active default-reject policy, and local PIN verifier as ordinary DEV_PROFILE NVS blobs and reports `provisioned` only when all three records and `prov_state=provisioned` agree. Existing DEV_PROFILE devices with `prov_state=provisioned` and valid root material but no policy record are migrated by installing the default-reject policy at boot; devices missing the local PIN verifier fail closed and must be reprovisioned. This is not USER_PROFILE encrypted storage. StackChan CoreS3 manual smoke observed `provisioned` after local setup and recovery setup; storage-failure and consistency-error paths still need targeted verification. |
| Local settings / reset | △ | StackChan CoreS3 source implements device-local Settings actions for `provisioned`: connect PIN toggle, Change PIN after current PIN verification, and Reset. Change PIN replaces only the salt/PIN verifier after current PIN verification and repeated new PIN entry; storage failure either preserves the previous verifier or fails closed if the post-write verifier state cannot be proven. Reset wipes root material, active policy, PIN verifier, approval history, connect-approval setting, session, and returns to `unprovisioned`. The source also implements a device-local, PIN-less, destructive erase-only recovery from persistent-material consistency `error` using the same reset-pending marker and wipe transaction, because the PIN verifier may be unreadable in that state. There is no USB/Gateway/MCP reset, recovery, or PIN-change API. StackChan CoreS3 local reset was manually smoke-tested after commit `7c6e65c`. A manual session/settings smoke verified that idle Settings keeps the active session usable, Change PIN does not end that session, and USB detach/replug invalidates the old session. Focused hardware smoke verified the error-recovery modal/layering and that erase/cancel interaction did not block the screen flow; this is not broader signing, policy-update, USER_PROFILE, or all-failure-path verification. Rerun hardware smoke after reset UI or reset-state changes. |
| `identify_device` | O | Implemented as temporary device UI for explicit user selection. |
| `connect` | O | Protocol and Gateway parser support exist. StackChan CoreS3 source gates Firmware session creation on material-backed `provisioned` plus Firmware-owned device-local approval. Default approval is local PIN entry; local settings can switch to physical Confirm after PIN verification. Manual hardware smoke verified local PIN approval and that USB detach/replug requires a fresh connect. Rerun hardware smoke after setup, session, or material-storage changes. |
| `disconnect` | O | Protocol and Gateway parser support exist. StackChan CoreS3 source clears only a matching active Firmware session; it does not require material readiness for session cleanup, but returns `busy` while local setup/PIN/reset or sensitive settings subflow state is active so external teardown cannot perturb a device-local sensitive flow. Idle Settings menu does not block disconnect. Rerun hardware smoke after setup, session, or material-storage changes. |
| `get_capabilities` | O | StackChan CoreS3 source reports Firmware-authored Sui Ed25519 account identity capability over an approved session while `provisioned`. The current `methods` list is empty because no concrete signing method, physical approval integration, or signing implementation exists. Rerun hardware smoke after setup, session, or material-storage changes. |
| `get_accounts` | O | StackChan CoreS3 source derives the Sui Ed25519 account (index 0, `m/44'/784'/0'/0'/0'`) from stored root material and returns it over an approved session while `provisioned`. Read-only: no mnemonic, seed, entropy, or private key in responses, logs, or UI. Derivation is verified against Sui SDK address vectors on host (`test_sui_account_vectors.sh`); manual hardware smoke verified `get_accounts` while idle Settings is open, after Change PIN on the same session, and after reconnect. Rerun hardware smoke after setup, session, or material-storage changes. |
| `get_policy` | △ | Read-only session-scoped policy summary path exists in Gateway/MCP and StackChan CoreS3 source. It reports only the active DEV_PROFILE default-reject policy metadata (`agentq.policy.v0`, hash id, `reject`, zero rules). Corrupt/unreadable policy is a material-consistency error rather than a normal `provisioned` state; a missing policy is migrated only for legacy root-only DEV_PROFILE devices. Gateway parser/MCP tests, the target policy-store host test, and manual hardware smoke for idle-Settings read access cover this path. |
| `get_approval_history` | △ | Read-only session-scoped approval-history path exists in Gateway/MCP and StackChan CoreS3 source. Firmware stores bounded persistent method-decision metadata in a fixed-size NVS ring buffer, currently only for validated `call_method` policy-rejected decisions. Invalid parameter, malformed transaction, and unsupported-method errors are not persisted as approval history. Persistent writes are Firmware-rate-limited to reduce flash wear. It stores no raw txBytes, decoded transaction, session id, request id, gateway name, PIN, secret material, or full policy document. Local reset and error-state erase recovery wipe it. Gateway/MCP parser tests and the target approval-history host test cover this path; hardware smoke remains required. |
| `call_method` | △ | Runtime skeleton exists in Gateway and StackChan CoreS3 source. It is provisioned/session-scoped, keeps unknown methods rejected with `unsupported_method`, and recognizes Sui `sign_transaction` only for restricted-transfer policy-decision smoke. The runtime consumes the stored active default-reject policy; valid policy-rejected decisions require approval-history persistence, and Firmware returns top-level `history_error` if that write fails or is rate-limited. Corrupt/unreadable policy fails closed as a material-consistency error before normal session-scoped methods are available, and missing policy is migrated only for legacy root-only DEV_PROFILE devices. Host tests cover the Firmware `call_method` field/type validation boundary and policy-store provider behavior. No signature, physical approval, capability advertisement, or signing support is connected. Hardware smoke remains required for the stored-policy path. |

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
| Provisioning transition parser | X | Removed. Current setup transitions are local device UX only, not USB protocol messages. |
| Recovery phrase setup parser | X | Removed. Firmware no longer returns recovery phrase setup result messages over USB. |
| Factory reset parser | X | Removed. No factory reset protocol request is implemented. |
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
| `connect_device` | O | Gateway tool exists. Firmware `connect` is expected only after persistent root material, active policy, and `provisioned` exist; rerun hardware smoke after setup, session, or material-storage changes. |
| `disconnect_device` | O | Gateway tool exists and Gateway tests cover stale local-session cleanup paths. Rerun hardware smoke after setup, session, or material-storage changes. |
| `get_capabilities` | O | Gateway tool and protocol parser exist for Firmware-authored Sui Ed25519 account identity capability over an active runtime session with `methods: []`; the parser rejects unsupported chains/methods/secret-like fields, and MCP never exposes the session id. Rerun hardware smoke after setup, session, or material-storage changes. |
| `get_accounts` | O | Gateway tool and protocol parser exist for public accounts over an active runtime session; the parser strictly re-validates the account shape, recomputes the Sui address/public-key relationship, rejects secret-like fields, and MCP never exposes the session id. Rerun hardware smoke after setup, session, or material-storage changes. |
| `get_policy` | △ | Gateway tool and protocol parser exist for the read-only active policy summary. The parser accepts only `agentq.policy.v0`, lowercase `sha256:` policy ids, `defaultAction: "reject"`, `ruleCount: 0`, no session id, and no secret-like fields. MCP never exposes the session id. Manual hardware smoke covered idle-Settings read access; rerun hardware smoke after setup, session, or material-storage changes. |
| `get_approval_history` | △ | Gateway tool and protocol parser exist for read-only persistent Firmware approval history over an active runtime session. The parser accepts only bounded method-decision records, preserves sequence and uptime as strings, rejects session ids and secret-like fields, and MCP never exposes the session id. Hardware smoke is still required. |
| `call_method` | △ | Gateway tool and protocol parser exist for the common session-scoped method path. The Sui `sign_transaction` rejected policy-decision path is implemented through MCP and Firmware source, but hardware smoke should be rerun after setup, session, or material-storage changes. It is not signing support, and MCP never exposes the session id. |

## Firmware Targets

| Capability | StackChan CoreS3 | Minimal LED-only Device | Button/Display Approval Device | Notes |
|---|---:|---:|---:|---|
| USB transport | O | X | X | StackChan CoreS3 target is the only implemented firmware target. |
| Persistent `deviceId` | O | X | X | Stored in device-local NVS for the implemented target. |
| `get_status` | O | X | X | Common protocol request. |
| Provisioning status reporting | △ | X | X | StackChan CoreS3 firmware source reports `unprovisioned`, material-backed `provisioned`, or `error` for persistent material inconsistency. Manual smoke observed `provisioned` after local setup and recovery setup on StackChan CoreS3; failure and consistency-error states still need targeted hardware checks. |
| Mnemonic UI flow | △ | X | X | StackChan CoreS3 source adds DEV_PROFILE 12-word BIP-39 recovery phrase generation into RAM from an early-boot-seeded Agent-Q CSPRNG, device-only up-to-4-letter prefix display in 3 columns by 4 rows, device-local 12-word mnemonic recovery entry with checksum verification, local 6-digit PIN setup after local Confirm or successful recovery verification, persistent root material/active policy/PIN verifier storage only after matching PIN repeat, and wipe on local Cancel/display expiry/PIN timeout/failure. Generate setup and PIN entry were manually smoke-tested after commit `2cb243b`; Recover was manually smoke-tested on StackChan CoreS3 during the recovery-entry slice. |
| `identify_device` | O | X | X | Uses temporary avatar speech bubble on StackChan CoreS3. |
| `connect` device-local approval | O | X | X | StackChan CoreS3 source requires Firmware-owned local approval only after material-backed `provisioned`; default approval is local PIN entry and the target can switch to physical Confirm through the local settings toggle. Before `provisioned`, the source returns `invalid_state`. Manual hardware smoke verified local PIN approval and fresh reconnect after USB detach/replug. Rerun hardware smoke after setup, session, or material-storage changes. |
| `disconnect` | O | X | X | StackChan CoreS3 source clears only a matching active Firmware session and is not gated on persistent material readiness. It may return `busy` while local setup/PIN/reset or sensitive settings subflow state is active; idle Settings menu does not block disconnect. Rerun hardware smoke after setup, session, or material-storage changes. |
| `get_capabilities` | O | X | X | StackChan CoreS3 source reports Sui Ed25519 account identity capability for account 0 over an approved session while `provisioned`; `methods` is empty until signing methods are implemented. Rerun hardware smoke after setup, session, or material-storage changes. |
| `get_accounts` | O | X | X | StackChan CoreS3 source derives and returns the Sui Ed25519 account 0 over an approved session while `provisioned`; read-only, no private material emitted. Manual hardware smoke verified this path while idle Settings is open, after Change PIN on the same session, and after reconnect. Rerun hardware smoke after setup, session, or material-storage changes. |
| `get_policy` | △ | X | X | StackChan CoreS3 source reads a session-scoped summary of the stored active default-reject policy. Corrupt/unreadable policy is a material-consistency error rather than a normal `provisioned` state; a missing policy is migrated only for legacy root-only DEV_PROFILE devices. Gateway/MCP parser tests, a target policy-store host test, and manual hardware smoke for idle-Settings read access cover this path. |
| `get_approval_history` | △ | X | X | StackChan CoreS3 source stores bounded persistent method-decision metadata in a fixed-size NVS ring buffer and exposes it through a read-only session-scoped protocol request. The current runtime records only validated policy-rejected decisions from the `call_method` skeleton. Gateway/MCP parser tests and a target approval-history host test cover this path; hardware smoke remains required. |
| `call_method` | △ | X | X | StackChan CoreS3 source enforces provisioned/session gates, keeps unknown methods rejected with `unsupported_method`, and recognizes Sui `sign_transaction` only to decode the restricted SUI transfer shape and consume the stored active default-reject policy decision as a rejected method result. Corrupt/unreadable policy fails closed as material inconsistency before normal session-scoped methods are available, and missing policy is migrated only for legacy root-only DEV_PROFILE devices. Host tests cover the Firmware request field/type validation boundary and policy-store provider behavior. It does not ask for signing approval or sign. Hardware smoke remains required for the stored-policy path. |
| Local settings / material wipe | △ | X | X | StackChan CoreS3 source implements device-local settings actions for `provisioned` devices: connect PIN toggle, Change PIN, and Reset/material wipe, plus a device-local destructive erase-only recovery from persistent-material consistency `error`. Reset and error-state erase wipe approval history with root material, active policy, PIN verifier, and the connect-approval setting. Host-triggered reset/debug/recovery/PIN-change protocol paths are intentionally not implemented. StackChan CoreS3 local reset was manually smoke-tested after commit `7c6e65c`; focused hardware smoke verified the error-recovery modal/layering and erase/cancel interaction. Rerun hardware smoke after settings or reset UI/state changes. |
| Request/result UI | O | X | X | StackChan CoreS3 uses Agent-Q-owned top avatar speech bubble and bottom decision strip. |
| Display power control | O | X | X | StackChan CoreS3 turns the screen backlight off after three minutes of inactivity, skips the upstream screensaver, wakes for Agent-Q UI, toggles display power on side-button short press, and powers off on side-button long press. Before screen-off or power-off, it moves to a rest posture; when the screen wakes, it returns to awake posture. |
| Boot/sleep posture | O | X | X | StackChan CoreS3 centers yaw and raises pitch when the default avatar is attached at boot or the screen wakes, and moves to centered yaw and lowered pitch before screen-off or power-off. |
| Per-request `ask` approval | X | N/A | X | Not implemented for signing requests because signing requests are not implemented. |
| Automatic `sign` / `reject` policy action | X | X | X | Common policy source can calculate internal `sign`/`reject`/`ask` decisions, and StackChan CoreS3 consumes the stored active default-reject decision only for Sui `sign_transaction` policy-decision smoke. `sign` and `ask` actions are still rejected as not implemented; no physical approval or signing is connected. |
| Persistent signing material | △ | X | X | StackChan CoreS3 source stores DEV_PROFILE BIP-39 root entropy after backup confirmation plus matching local PIN repeat. Public account derivation is implemented (`get_accounts`, Sui Ed25519 account 0); it does not sign. |
| Policy storage/read | △ | X | X | StackChan CoreS3 stores only a DEV_PROFILE active default-reject policy record in NVS after backup confirmation plus matching local PIN repeat, exposes a read-only `get_policy` summary, migrates legacy root-only missing policy to the default-reject record, and treats corrupt/unreadable policy as a material-consistency error. Policy update authorization and custom policy content are not implemented. |
| Provisioning flow | △ | X | X | DEV_PROFILE mnemonic UI, device-local mnemonic recovery entry, and persistent root material plus active default-reject policy plus local PIN verifier storage source exists for StackChan CoreS3. Public Sui account derivation is implemented via `get_accounts`; local settings reset/material wipe source exists; USB/Gateway/MCP mnemonic import, signing use, policy update, and USER_PROFILE secure provisioning are not implemented. |
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
| Sui `sign_transaction` | △ | This method is recognized inside `call_method` only for policy-decision smoke. It validates `network` and base64 `txBytes`, decodes the restricted SUI transfer shape, consumes the stored active default-reject policy runtime decision, and returns a rejected `method_result`; corrupt/unreadable policy fails closed as material inconsistency before normal session-scoped methods are available, and missing policy is migrated only for legacy root-only DEV_PROFILE devices. It is not advertised in `get_capabilities`, does not sign, and does not trigger approval UI. Hardware smoke remains required for the stored-policy path. |
| Sui txBytes decoder | △ | Common firmware source includes a restricted host-tested SUI transfer facts parser for `TransactionData::V1 -> ProgrammableTransaction -> SplitCoins(GasCoin, [Input(amountPure)]) -> TransferObjects([Result(0)], Input(recipientPure))`. StackChan CoreS3 connects that parser to Sui `sign_transaction` policy-decision smoke only; it is not connected to capability advertisement or signing. |
| Sui zkLogin | X | Not implemented; separate trust model required. |
| EVM | X | Not implemented. |
| Solana | X | Not implemented. |

## Policy And Security Profiles

| Item | Status | Notes |
|---|---:|---|
| Security model document | O | See `docs/SECURITY_MODEL.md`. |
| State model document | O | See `docs/STATE_MODEL.md`. It defines product states, state-gated protocol functions, and responsibility boundaries. |
| Provisioning flow document | O | See `docs/PROVISIONING.md`. USER_PROFILE mnemonic/key provisioning is not implemented. |
| Provisioning status reporting | O | Firmware reports `provisioning.state`, including `error` for persistent material inconsistency; Gateway exposes it without treating it as signing readiness. |
| Mnemonic UI flow | △ | StackChan CoreS3 source adds DEV_PROFILE BIP-39 recovery phrase generation from an early-boot-seeded Agent-Q CSPRNG, device-only up-to-4-letter prefix display, device-local mnemonic recovery entry with checksum verification, local 6-digit PIN setup after backup confirmation or successful recovery verification, matching-PIN root material storage, active default-reject policy initialization, and salt + PIN verifier storage. It stores no mnemonic text, private key, or account data. The PIN verifier is not root encryption. Generate setup and PIN entry were manually smoke-tested after commit `2cb243b`; Recover was manually smoke-tested on StackChan CoreS3 during the recovery-entry slice. |
| Deny-by-default policy model | △ | Common firmware source includes a host-tested policy evaluator/runtime boundary that loads policy through a provider, rejects malformed/missing policy or unsupported facts, and returns `sign`, `reject`, or `ask` decisions only as internal calculation results. The evaluator matches allowlisted namespace/field facts and owns only shared `common.*` fields; chain-specific field identifiers, descriptors, and transaction semantics stay in the method adapter. StackChan CoreS3 currently provides only the stored active default-reject policy. It is not connected to runtime signing. |
| Policy evaluator | △ | Common firmware source implements a declarative policy evaluator, provider boundary, and Sui restricted-transfer method adapter that exposes a policy-facts view for Sui `sign_transaction`. Host tests cover positive and negative decisions, missing/invalid policy provider failure, malformed policy rejection, and unsupported facts. StackChan CoreS3 consumes the stored active default-reject decision for Sui `sign_transaction` policy-decision smoke only; policy decisions are not connected to physical approval, capability advertisement, or signing. |
| Policy storage/read | △ | StackChan CoreS3 stores only the DEV_PROFILE active default-reject policy record in NVS, exposes a read-only `get_policy` summary, migrates legacy root-only missing policy to the default-reject record, and treats corrupt/unreadable policy as a material-consistency error. Policy update authorization and custom policy content are not implemented. |
| Approval history storage/read | △ | StackChan CoreS3 stores bounded persistent approval-history records in NVS and exposes a read-only session-scoped `get_approval_history` view. The current runtime records only validated policy-rejected metadata from the `call_method` skeleton, with Firmware-owned write rate limiting and fail-closed `history_error` when a required record cannot be persisted; future user approval, method-error, and signing decisions are not implemented. Reset and error-state erase wipe the history. |
| Policy update authorization | X | Not implemented. The design contract is now specified as a future Firmware-owned `propose_policy_update` flow: Gateway/Admin may submit a bounded policy proposal, Firmware validates it, requires device-local approval, commits through rollback-safe canonical storage, and rejects direct setters such as `set_policy` or `force_policy`. No protocol parser, Gateway/Admin surface, Firmware pending-update state, storage implementation, or approval UI exists yet. |
| Mnemonic generation/import | △ | DEV_PROFILE local recovery phrase generation/display, device-local mnemonic recovery entry, and persistent root material plus active policy plus local PIN verifier storage source exists for StackChan CoreS3. Local reset/material wipe source exists separately for provisioned devices. USB/Gateway/MCP mnemonic import, USER_PROFILE secure root storage, and signing use remain unimplemented. |
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
