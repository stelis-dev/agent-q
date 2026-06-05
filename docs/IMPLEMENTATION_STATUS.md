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

Sign API activation uses these status terms:

- `foundation`: standalone source modules, protocol shapes, host tests, and
  target-internal partial runtime modules may exist, but no public Firmware USB
  dispatcher, public response writer, Gateway/client/provider API, parser,
  capability advertisement, or MCP surface is active. If internal review, PIN,
  history, signing, or cleanup modules exist, the relevant row must say so
  explicitly; this status is still not product exposure.
- `source-wired`: source modules and target runtime glue are present, but public
  Firmware USB dispatcher, public response writer, Gateway/client/provider API,
  parser, capability advertisement, and MCP surface remain blocked. This status
  is still not product exposure.
- `provider-exposed-not-product-active`: public dispatcher, response writer,
  client/provider parser and API, and provider-facing capability advertisement
  are present in source, but current-tree product-active evidence is not yet
  complete. This status means the source has product exposure and must not be
  called `product-active`.
- `product-active`: public dispatcher, response writer, client/provider parser
  and API, capability advertisement, docs, tests, build, and current-tree target
  hardware and visual evidence are all complete for the same contract.

Current `sign_by_user` status is `provider-exposed-not-product-active`. Earlier
target positive/reject/timeout/session-loss smoke is historical evidence from
the pre-cutover wire names only. The current Sign API wire names still require
current-tree flash, hardware smoke, and LVGL visual evidence before any
`product-active` claim.

Current `sign_by_policy` status is source-exposed through MCP and Firmware, but
not `product-active`: package tests and host firmware tests cover the bounded
policy decision path, while current-tree hardware smoke for policy signed and
policy rejected results remains pending.

This document tracks implementation status only. The wire protocol is defined in
`specs/PROTOCOL.md`. Target-specific details live under
`firmware/src/<hardware-id>/`.

## Common Protocol

| Item | Common Status | Notes |
|---|---:|---|
| `get_status` | O | Implemented by the current StackChan CoreS3 target and used by Gateway discovery. |
| Provisioning status reporting | O | `get_status` includes `provisioning.state`; Gateway parses and preserves it. Firmware reports `error` instead of `provisioned` when persistent material consistency fails. This is not signing readiness. |
| Mnemonic UI flow | △ | The local setup speech bubble opens a Generate/Recover choice. Generate creates a DEV_PROFILE BIP-39 phrase into RAM from an early-boot-seeded Agent-Q CSPRNG and displays only up-to-4-letter prefixes on device in a 3-column by 4-row grid with bottom Cancel/Confirm buttons. Recover accepts 12 BIP-39 words through a device-local 3-word-per-page prefix/candidate UI and verifies checksum. Three-letter BIP-39 words are displayed as the full word. Local Confirm or successful Recover verification advances to local 6-digit PIN entry; matching PIN repeat stores root material, initializes the active default-reject policy, stores a salt + PIN verifier, and wipes volatile scratch. Local Cancel wipes volatile scratch. There is no USB protocol request for setup start, setup cancel, backup confirmation, or mnemonic import. Hardware smoke coverage exists for Generate setup, PIN entry, and Recover entry. |
| Persistent material | △ | StackChan CoreS3 source stores the confirmed BIP-39 root entropy, active default-reject policy, and local PIN verifier as ordinary DEV_PROFILE NVS blobs and reports `provisioned` only when all three records and `prov_state=provisioned` agree. Devices with `prov_state=provisioned` but missing, unreadable, or invalid current policy material fail closed and must be reprovisioned or erased through the device-local destructive recovery path. This is not USER_PROFILE encrypted storage. Hardware smoke coverage exists for local setup and recovery setup reaching `provisioned`; storage-failure and consistency-error paths still need targeted verification. |
| Local settings / reset | △ | StackChan CoreS3 source implements device-local Settings actions for `provisioned`: connect PIN toggle, Change PIN after current PIN verification, and Reset. Change PIN replaces only the salt/PIN verifier after current PIN verification and repeated new PIN entry; storage failure either preserves the previous verifier or fails closed if the post-write verifier state cannot be proven. Reset wipes root material, active policy, PIN verifier, approval history, policy-update terminal marker, connect-approval setting, session, and returns to `unprovisioned`. The source also implements a device-local, PIN-less, destructive erase-only recovery from persistent-material consistency `error` using the same reset-pending marker and wipe transaction, because the PIN verifier may be unreadable in that state. There is no USB/Gateway/MCP reset, recovery, or PIN-change API. Hardware smoke coverage exists for local reset, idle Settings session behavior, Change PIN session retention, USB detach/replug session invalidation, and error-recovery modal layering. This is not broader signing, policy-update, USER_PROFILE, or all-failure-path verification. |
| `identify_device` | O | Implemented as temporary device UI for explicit user selection. |
| `connect` | O | Protocol and Gateway parser support exist. StackChan CoreS3 source gates Firmware session creation on material-backed `provisioned` plus Firmware-owned device-local approval. Default approval is local PIN entry; local settings can switch to physical Confirm after PIN verification. Hardware smoke coverage exists for local PIN approval and fresh connect after USB detach/replug. |
| `disconnect` | O | Protocol and Gateway parser support exist. StackChan CoreS3 source clears only a matching active Firmware session; it does not require material readiness for session cleanup, but returns `busy` while local setup/PIN/reset or sensitive settings subflow state is active so external teardown cannot perturb a device-local sensitive flow. Idle Settings menu does not block disconnect. |
| `get_capabilities` | O | StackChan CoreS3 source reports Firmware-authored Sui Ed25519 account identity capability over an approved session while `provisioned`. Delegated public method capabilities are empty. Sign API availability is advertised through top-level `signing`, with separate user-confirmed and policy-authorized entries. MCP projects this raw Firmware capability to policy-authorized signing only, and provider projects it to user-confirmed signing only. |
| `get_accounts` | O | StackChan CoreS3 source derives the Sui Ed25519 account (index 0, `m/44'/784'/0'/0'/0'`) from stored root material and returns it over an approved session while `provisioned`. Read-only: no mnemonic, seed, entropy, or private key in responses, logs, or UI. Derivation is verified against Sui SDK address vectors on host (`test_sui_account_vectors.sh`); hardware smoke coverage exists for `get_accounts` while idle Settings is open, after Change PIN on the same session, and after reconnect. |
| `get_policy` | △ | Read-only session-scoped policy summary path exists in Gateway/MCP and StackChan CoreS3 source. The normal product flow installs the DEV_PROFILE default-reject policy (`agentq.policy.v0`, hash id, `reject`, zero rules), and the target store and Gateway parser accept bounded committed current-schema policy summaries from the active-policy storage boundary. Corrupt/unreadable, missing, or invalid current policy material is a material-consistency error rather than a normal `provisioned` state. Gateway parser/MCP tests, the target policy-store host test, and hardware smoke coverage for idle-Settings read access cover this path. |
| `get_approval_history` | △ | Read-only session-scoped approval-history path exists in Gateway/MCP and StackChan CoreS3 source. Firmware stores bounded persistent signing and policy-update terminal metadata in a fixed-size NVS ring buffer. The `sign_by_policy` path records policy confirmation only after policy approval, then records policy terminal signing metadata for signed, rejected, and failed outcomes; invalid parameter, malformed transaction, and unsupported-method errors are not persisted as approval history. The `propose_policy_update` flow emits recordable policy-update terminal records through a required-write path. `provider-exposed-not-product-active` `sign_by_user` creates pre-signing user confirmation and terminal signing records. Current Sign API hardware smoke is pending after the single-cutover rename. History stores no raw txBytes, decoded transaction, session id, request id, gateway name, PIN, secret material, raw policy, or full policy document. Local reset and error-state erase recovery wipe it. Gateway/MCP parser tests and the target approval-history host test cover current source behavior. |
| `sign_by_policy` | △ | Gateway/MCP and StackChan CoreS3 source support provisioned/session-scoped policy-authorized signing. Sui `sign_transaction` accepts only bounded restricted SUI transfer request inputs, consumes the committed active policy, rejects broad, multi-rule, or multi-recipient sign policies, persists required policy terminal metadata for `policy_rejected`, persists policy confirmation only after approval, and returns `signed` only after a current-schema bounded `sign` rule matches, signing succeeds, and durable signed terminal history is written. Corrupt/unreadable, missing, or invalid current policy material fails closed as a material-consistency error before normal session-scoped signing is available. Package tests and host firmware tests cover the source boundary; current-tree hardware smoke for policy signed/rejected remains pending. |
| `sign_by_user` | △ | StackChan CoreS3 source has `provider-exposed-not-product-active` status for provider-facing device-confirmed Sui `sign_transaction` over the bounded restricted-transfer shape. The public USB dispatcher, `sign_result` writer, Gateway core/client request builder and parser, provider `signByUser` API, and provider-facing `signing` capability are present. Firmware owns material/session/busy gates, `txBytes`-derived review facts, host-supplied `network` validation without displaying it as a transaction-derived fact, local PIN confirmation, required pre-signing history, signing-critical handoff, terminal history, response delivery, and cleanup. It is not an MCP signing tool, does not accept caller-controlled timing fields, and uses a different authorization source than `sign_by_policy`. Firmware-owned review/PIN input windows use a fixed internal 30-second window; submitting a complete PIN stops the input timer while stored-PIN cryptographic verification runs, the original signing confirmation deadline remains enforceable, the internal local-auth worker watchdog still fails closed as authentication unavailable, and wrong PIN results open a fresh input window capped by the original confirmation deadline unless the shared lockout is active. Current-tree hardware smoke for the new wire names remains pending, so current status is not yet `product-active`. |

## Gateway

| Item | Status | Notes |
|---|---:|---|
| Gateway process | O | Starts with no CLI arguments and exposes stdio MCP tools plus the local Admin Page through one shared Gateway runtime session owner. |
| USB device scan | O | Scans candidate USB serial ports and sends bounded status handshakes. |
| Device identification | O | Requests device-displayed short codes before selection. |
| Active device selection | O | Stores selected device id and USB transport hint locally. |
| Device labels | O | Gateway-local metadata only. Not a security boundary. |
| Purpose routing | O | Gateway-local routing metadata only. Not Firmware policy. |
| Runtime connection sessions | O | Held in Gateway memory only; session id is not exposed to MCP clients or the Admin Page. The local Admin Page and MCP tools share the same in-process `GatewayCore` session owner. |
| Cached device status | O | Exposed only for previously seen devices and marked non-live. |
| Provisioning transition parser | X | Removed. Current setup transitions are local device UX only, not USB protocol messages. |
| Recovery phrase setup parser | X | Removed. Firmware no longer returns recovery phrase setup result messages over USB. |
| Factory reset parser | X | Removed. No factory reset protocol request is implemented. |
| MCP output sanitization | O | Tool outputs and public errors are schema-bounded before reaching clients. |
| Admin Page | △ | Gateway-served local Admin Page supports device discovery, connection, read-only active policy and approval-history views, and the current policy proposal template. It is not a separate product and is not a policy authority. Full policy editing is not implemented. |
| Firmware update path | X | Not exposed through MCP. |
| Policy update proposal path | △ | Gateway/MCP exposes `propose_policy_update` as a bounded proposal path over an active session. It is not a direct setter: Firmware validates the proposal, rejects broad, multi-rule, and multi-recipient sign policies that the current device UI cannot review clearly, requires device-local local-PIN approval, commits through the active-policy store, and records required terminal history. The Gateway-served local Admin Page can submit the current policy proposal template. |
| Signing APIs | △ | The Sign API has a single-cutover source surface: provider exposes `signByUser`; MCP exposes `sign_by_policy`; both return `sign_result`; provider does not expose policy signing or Admin/policy update entrypoints; MCP does not expose user-confirmed provider signing. Package tests, host firmware tests, and StackChan CoreS3 firmware build pass for the source boundary. Current-tree flash, hardware smoke, and LVGL visual evidence for the new wire names remain pending, so this is not yet `product-active`. |

Current MCP tools:

MCP package tests cover tool projection, output schemas, and fail-closed
adapter boundaries. Direct USB/Firmware hardware smoke is client-owned so that
adapter tests do not become the source of truth for the device protocol path.

| Tool | Status | Notes |
|---|---:|---|
| `scan_devices` | O | USB discovery returns confirmed devices and sanitized candidate failure reasons for likely Agent-Q USB serial ports. |
| `identify_devices` | O | Shows short codes on discovered devices. |
| `select_device` | O | Updates local Gateway selection only. |
| `get_device_status` | O | Returns live or clearly marked cached status. |
| `list_devices` | O | Lists Gateway-known devices and local metadata. |
| `set_device_metadata` | O | Sets or clears local label. |
| `connect_device` | O | Gateway tool exists. Firmware `connect` is expected only after persistent root material, active policy, and `provisioned` exist. |
| `disconnect_device` | O | Gateway tool exists and Gateway tests cover stale local-session cleanup paths. |
| `get_capabilities` | O | Gateway parser accepts Firmware-authored Sui Ed25519 account identity capability over an active runtime session with `chains[].methods: []` and top-level `signing` for Sign API use. MCP never exposes the session id and fails closed if user-confirmed provider signing reaches the MCP output boundary. |
| `get_accounts` | O | Gateway tool and protocol parser exist for public accounts over an active runtime session; the parser strictly re-validates the account shape, recomputes the Sui address/public-key relationship, rejects secret-like fields, and MCP never exposes the session id. |
| `get_policy` | △ | Gateway tool and protocol parser exist for the read-only active policy summary. The parser accepts only `agentq.policy.v0`, lowercase `sha256:` policy ids, `defaultAction: "reject"`, bounded rule counts, no session id, and no secret-like fields. MCP never exposes the session id. Hardware smoke coverage exists for idle-Settings read access. |
| `get_approval_history` | △ | Gateway tool and protocol parser exist for read-only persistent Firmware approval history over an active runtime session. The parser accepts bounded signing and policy-update records, preserves sequence and uptime as strings, rejects session ids and secret-like fields, and MCP never exposes the session id. Current-tree hardware smoke for the new Sign API wire names is pending; that hardware evidence is collected through client-owned direct USB/Firmware smoke, not MCP adapter smoke. |
| `sign_by_policy` | △ | Gateway tool and protocol parser exist for the policy-authorized signing path. MCP can request bounded Sui `sign_transaction`; Firmware evaluates the active policy and returns `signed`, `policy_rejected`, or `signing_failed` through `sign_result`. Current-tree hardware smoke for policy signed/rejected remains pending. |
| `propose_policy_update` | △ | Gateway tool and protocol parser exist for the Firmware-owned policy update proposal path. MCP clients may submit a bounded policy proposal, but Gateway/MCP do not store, apply, or decide policy. Firmware returns `policy_update_result` only after validation, device-local approval, active-policy commit, and required terminal-history handling. Opt-in direct USB/Firmware smoke for this proposal path is owned by the client package. |

## Firmware Targets

| Capability | StackChan CoreS3 | Minimal LED-only Device | Button/Display Approval Device | Notes |
|---|---:|---:|---:|---|
| USB transport | O | X | X | StackChan CoreS3 target is the only implemented firmware target. |
| Persistent `deviceId` | O | X | X | Stored in device-local NVS for the implemented target. |
| `get_status` | O | X | X | Common protocol request. |
| Provisioning status reporting | △ | X | X | StackChan CoreS3 firmware source reports `unprovisioned`, material-backed `provisioned`, or `error` for persistent material inconsistency. Hardware smoke coverage exists for local setup and recovery setup reaching `provisioned`; failure and consistency-error states still need targeted hardware checks. |
| Mnemonic UI flow | △ | X | X | StackChan CoreS3 source adds DEV_PROFILE 12-word BIP-39 recovery phrase generation into RAM from an early-boot-seeded Agent-Q CSPRNG, device-only up-to-4-letter prefix display in 3 columns by 4 rows, device-local 12-word mnemonic recovery entry with checksum verification, local 6-digit PIN setup after local Confirm or successful recovery verification, persistent root material/active policy/PIN verifier storage only after matching PIN repeat, and wipe on local Cancel/display expiry/PIN timeout/failure. Hardware smoke coverage exists for Generate setup, PIN entry, and Recover entry. |
| `identify_device` | O | X | X | Uses temporary avatar speech bubble on StackChan CoreS3. |
| `connect` device-local approval | O | X | X | StackChan CoreS3 source requires Firmware-owned local approval only after material-backed `provisioned`; default approval is local PIN entry and the target can switch to physical Confirm through the local settings toggle. Before `provisioned`, the source returns `invalid_state`. Hardware smoke coverage exists for local PIN approval and fresh reconnect after USB detach/replug. |
| `disconnect` | O | X | X | StackChan CoreS3 source clears only a matching active Firmware session and is not gated on persistent material readiness. It may return `busy` while local setup/PIN/reset or sensitive settings subflow state is active; idle Settings menu does not block disconnect. |
| `get_capabilities` | O | X | X | StackChan CoreS3 source reports Sui Ed25519 account identity capability for account 0 over an approved session while `provisioned`. Delegated public method capabilities are empty. Raw Firmware signing availability is advertised through top-level `signing`; MCP projects it to policy-authorized signing only and provider projects it to user-confirmed signing only. |
| `get_accounts` | O | X | X | StackChan CoreS3 source derives and returns the Sui Ed25519 account 0 over an approved session while `provisioned`; read-only, no private material emitted. Hardware smoke coverage exists for this path while idle Settings is open, after Change PIN on the same session, and after reconnect. |
| `get_policy` | △ | X | X | StackChan CoreS3 source reads a session-scoped summary of the committed active policy. The current product flow installs the default-reject policy, while the target store can also load canonical current-schema policy records through its internal storage boundary. Corrupt/unreadable, missing, or invalid current committed policy material is a material-consistency error rather than a normal `provisioned` state. Gateway/MCP parser tests, a target policy-store host test, and hardware smoke coverage for idle-Settings read access cover this path. |
| `get_approval_history` | △ | X | X | StackChan CoreS3 source stores bounded persistent signing and policy-update terminal metadata in a fixed-size NVS ring buffer and exposes it through a read-only session-scoped protocol request. `sign_by_policy` records policy confirmation only after approval and records policy terminal signing metadata for signed, rejected, and failed outcomes; `sign_by_user` records user confirmation and terminal signing metadata. Gateway/MCP parser tests and the target approval-history host test cover current source behavior. Current-tree hardware smoke for the new Sign API wire names remains pending before `product-active`. |
| `sign_by_policy` | △ | X | X | StackChan CoreS3 source enforces provisioned/session gates, validates Sui `sign_transaction` restricted SUI transfer request inputs, evaluates the committed active policy, rejects broad, multi-rule, and multi-recipient sign policies, returns `policy_rejected` when no bounded `sign` rule matches, and returns `signed` only after policy approval and successful signing. Corrupt/unreadable, missing, or invalid current policy material fails closed as material consistency before normal session-scoped signing is available. Host tests cover the Firmware policy signing runtime, policy-store provider behavior, and bounded policy rules. Current-tree hardware smoke remains pending. |
| `sign_by_user` | △ | X | X | StackChan CoreS3 source has `provider-exposed-not-product-active` status for provider-facing device-confirmed Sui `sign_transaction` over the bounded restricted-transfer shape. The public USB dispatcher, `sign_result` writer, provider/client parser/API, and provider-facing `signing` capability are present. Host tests cover material/session/busy gating, `txBytes`-derived review facts, local PIN, required confirmation history, signing-critical handoff, terminal metadata, response boundaries, and cleanup behavior. Current-tree target hardware smoke and LVGL visual evidence remain pending, so this is not yet `product-active`. |
| Local settings / material wipe | △ | X | X | StackChan CoreS3 source implements device-local settings actions for `provisioned` devices: connect PIN toggle, Change PIN, and Reset/material wipe, plus a device-local destructive erase-only recovery from persistent-material consistency `error`. Reset and error-state erase wipe approval history and the policy-update terminal marker with root material, active policy, PIN verifier, and the connect-approval setting. Host-triggered reset/debug/recovery/PIN-change protocol paths are intentionally not implemented. Hardware smoke coverage exists for local reset and error-recovery modal/layering; all-failure-path coverage remains limited. |
| Request/result UI | O | X | X | StackChan CoreS3 uses Agent-Q-owned top avatar speech bubble and bottom decision strip. |
| Display power control | O | X | X | StackChan CoreS3 turns the screen backlight off after three minutes of inactivity, skips the upstream screensaver, wakes for Agent-Q UI, toggles display power on side-button short press, and powers off on side-button long press. Before screen-off or power-off, it moves to a rest posture; when the screen wakes, it returns to awake posture. |
| Boot/sleep posture | O | X | X | StackChan CoreS3 centers yaw and raises pitch when the default avatar is attached at boot or the screen wakes, and moves to centered yaw and lowered pitch before screen-off or power-off. |
| Per-request signing approval | △ | N/A | X | StackChan CoreS3 source has provider-facing device-confirmed signing approval for `sign_by_user` with local PIN and required pre-signing history under `provider-exposed-not-product-active` status. Current-tree target hardware smoke and LVGL visual evidence remain pending, so product-active status is not yet claimed. |
| Current policy action schema | △ | X | X | Common policy source accepts current `agentq.policy.v0` reject rules and at most one single-recipient bounded sign rule. StackChan CoreS3 consumes the committed active policy for Sui `sign_transaction` policy signing. Broad, multi-rule, and multi-recipient sign policies are invalid and fail closed before storage or evaluation. |
| Persistent signing material | △ | X | X | StackChan CoreS3 source stores DEV_PROFILE BIP-39 root entropy after backup confirmation plus matching local PIN repeat. Public account derivation is implemented (`get_accounts`, Sui Ed25519 account 0). Internal Sui transaction signing substrate is wired into `sign_by_user` and `sign_by_policy` for the bounded restricted transfer shape. Current-tree hardware smoke remains pending after the Sign API cutover. USER_PROFILE secure storage and import are not implemented. |
| Policy storage/read | △ | X | X | StackChan CoreS3 stores the active policy as a canonical `agentq.policy.v0` binary record in two bounded NVS slots plus commit metadata and a pending-write marker. Backup confirmation plus matching local PIN repeat still installs only the DEV_PROFILE default-reject policy, but the `propose_policy_update` flow can commit canonical current-schema policy records after Firmware validation and device-local approval. It exposes a read-only `get_policy` summary, preserves the previous committed policy only for interrupted writes identified by the pending marker, treats metadata flip as the commit point, classifies each write as applied, unchanged failure, or consistency error, tolerates stale pending markers that exactly match the selected committed policy, removes stale commit metadata before slot reuse, and treats corrupt/unreadable committed policy, invalid commit metadata without that marker, or pending targets that overlap active material without exactly matching it as a material-consistency error. |
| Provisioning flow | △ | X | X | DEV_PROFILE mnemonic UI, device-local mnemonic recovery entry, and persistent root material plus active default-reject policy plus local PIN verifier storage source exists for StackChan CoreS3. Public Sui account derivation is implemented via `get_accounts`; local settings reset/material wipe source exists; USB/Gateway/MCP mnemonic import and USER_PROFILE secure provisioning are not implemented. |
| Secure user profile | X | X | X | Secure Boot, Flash Encryption, anti-rollback, and provisioning flow are documented but not implemented. |
| StackChan/Xiaozhi remote AI runtime | N/A | N/A | N/A | Disabled in the Agent-Q StackChan build; not part of Agent-Q signing firmware. |
| Camera / remote upload surfaces | N/A | N/A | N/A | Disabled in the Agent-Q StackChan build. |

Target-specific specification:

- StackChan CoreS3: `firmware/src/stackchan-cores3/SPEC.md`

## Hardware Chain Support

This table summarizes chain and method support by hardware target. Detailed
target-specific notes live in each target's `SPEC.md`.

| Hardware target | Sui Ed25519 | Sui zkLogin | EVM | Solana | Notes |
|---|---:|---:|---:|---:|---|
| StackChan CoreS3 | △ | X | X | X | Boot-time Sui Ed25519 self-test, read-only `get_accounts` account-0 derivation, MCP-facing `sign_by_policy`, and provider-facing `sign_by_user` for the bounded restricted-transfer shape. Current-tree hardware smoke remains pending after the Sign API cutover. Broader Sui transaction shapes and other chains are not implemented. |
| Minimal LED-only Device | X | X | X | X | Planned target; no firmware implementation yet. |
| Button/Display Approval Device | X | X | X | X | Planned target class; no firmware implementation yet. |

## Chain And Method Adapters

Agent-Q must not create chain-specific top-level MCP tools. Chains and signing
methods must be exposed as capabilities and invoked through the common
session-scoped `sign_by_policy` protocol.

| Adapter | Status | Notes |
|---|---:|---|
| Sui Ed25519 signing self-test | △ | Firmware can link signing code, generate a runtime test seed, sign, verify, and wipe the test seed. This is not a signing API. |
| Sui `sign_personal_message` | X | Not implemented. |
| Sui `sign_transaction` | △ | `sign_by_policy` validates request-context `network` and base64 `txBytes`, derives policy facts only from the transaction bytes, decodes the restricted SUI transfer shape, consumes the committed active policy runtime decision, and returns `signed`, `policy_rejected`, or `signing_failed`. Provider-facing `sign_by_user` has `provider-exposed-not-product-active` status for the same bounded restricted-transfer shape with device confirmation, required history, signing, and `sign_result`. Current-tree hardware smoke remains pending after the Sign API cutover. Corrupt/unreadable, missing, or invalid current policy material fails closed as material consistency before normal session-scoped signing is available. |
| Sui txBytes decoder | △ | Common firmware source includes a restricted host-tested SUI transfer facts parser for `TransactionData::V1 -> ProgrammableTransaction -> SplitCoins(GasCoin, [Input(amountPure)]) -> TransferObjects([Result(0)], Input(recipientPure))`. StackChan CoreS3 connects that parser to Sui `sign_transaction` policy-authorized signing and user-confirmed signing. |
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
| Mnemonic UI flow | △ | StackChan CoreS3 source adds DEV_PROFILE BIP-39 recovery phrase generation from an early-boot-seeded Agent-Q CSPRNG, device-only up-to-4-letter prefix display, device-local mnemonic recovery entry with checksum verification, local 6-digit PIN setup after backup confirmation or successful recovery verification, matching-PIN root material storage, active default-reject policy initialization, and salt + PIN verifier storage. It stores no mnemonic text, private key, or account data. The PIN verifier is not root encryption. Hardware smoke coverage exists for Generate setup, PIN entry, and Recover entry. |
| Deny-by-default policy model | △ | Common firmware source includes a host-tested policy evaluator/runtime boundary that loads policy through a provider, rejects malformed/missing policy or unsupported facts, and returns `reject` or bounded `sign` decisions for current product-reachable Sui `sign_transaction`. The evaluator matches allowlisted namespace/field facts and owns only shared `common.*` fields; chain-specific field identifiers, descriptors, and transaction semantics stay in the method adapter. Broad, multi-rule, and multi-recipient sign policies are invalid. |
| Policy evaluator | △ | Common firmware source implements a declarative policy evaluator, provider boundary, and Sui restricted-transfer method adapter that exposes a policy-facts view for Sui `sign_transaction`. Host tests cover positive and negative reject/sign decisions, missing/invalid policy provider failure, malformed policy rejection, unsupported facts, and broad-sign rejection. StackChan CoreS3 consumes the committed active policy for Sui `sign_transaction` policy-authorized signing. |
| Policy storage/read | △ | StackChan CoreS3 stores the active policy as a canonical `agentq.policy.v0` binary record in NVS. The target store supports two bounded slots plus commit metadata and a pending-write marker, preserves the previous committed policy only for interrupted inactive-slot or metadata writes identified by that marker, treats metadata flip as the commit point, classifies each write as applied, unchanged failure, or consistency error, tolerates stale pending markers that exactly match the selected committed policy, removes stale commit metadata before slot reuse, exposes a read-only `get_policy` summary for the committed active policy, and treats corrupt/unreadable active policy, invalid commit metadata without a matching pending marker, or overlapping pending targets that do not exactly match the selected active material as a material-consistency error. The current provisioning flow installs the DEV_PROFILE default-reject policy; current-schema policy records enter through the Firmware-owned `propose_policy_update` proposal path. |
| Approval history storage/read | △ | StackChan CoreS3 stores bounded persistent approval-history records in NVS and exposes a read-only session-scoped `get_approval_history` view. The current runtime records signing confirmation/terminal metadata and terminal metadata from `propose_policy_update`. It rejects invalid current-schema storage blobs and returns fail-closed `history_error` when a required record cannot be persisted. Reset and error-state erase wipe the history. |
| Policy update authorization | △ | StackChan CoreS3 and Gateway/MCP implement a Firmware-owned `propose_policy_update` proposal flow: Gateway/MCP submit a bounded policy proposal over an active session, Firmware validates it, rejects broad, multi-rule, or multi-recipient sign policies that the current device UI cannot review clearly, requires device-local local-PIN approval with an on-device summary of the policy update, commits through the target's canonical active-policy store, records required recordable policy-update terminal history, and rejects direct setters such as `set_policy` or `force_policy`. The target accepts current-schema reject policies and at most one single-recipient bounded sign rule. The Gateway-served local Admin Page can submit the current policy proposal template. Full Admin policy editing is not implemented. |
| Mnemonic generation/import | △ | DEV_PROFILE local recovery phrase generation/display, device-local mnemonic recovery entry, and persistent root material plus active policy plus local PIN verifier storage source exists for StackChan CoreS3. Local reset/material wipe source exists separately for provisioned devices. USB/Gateway/MCP mnemonic import and USER_PROFILE secure root storage remain unimplemented. |
| Request replay protection | X | Not implemented. |
| Secure Boot profile | X | Documented target behavior; not implemented. |
| Flash Encryption profile | X | Documented target behavior; not implemented. |
| Anti-rollback / secure version | X | Documented target behavior; not implemented. |
| Owner firmware signing mode | X | Documented target behavior; not implemented. |

## Explicitly Unsupported Or Out Of Scope

- Ledger-grade or secure-element-backed physical extraction resistance.
- Agent, prompt, or host intent detection.
- Chain-specific top-level MCP tools such as `sign_sui_transaction`.
- Gateway, MCP, or Admin commands that export keys, directly set or clear
  policy, flash firmware, read memory, or bypass Firmware policy.
- Fiat cash-out, P&L, tax, or cost-basis features.
- Treating Gateway labels or purpose routing as security policy.
- Treating `connect_device` as signing approval.
