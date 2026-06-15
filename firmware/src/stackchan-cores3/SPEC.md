# StackChan CoreS3 Agent-Q Firmware Specification

This document describes the StackChan CoreS3 Agent-Q firmware target. It is the
target-specific detail document referenced by the project-wide implementation
status table.

The common host process/Firmware protocol is defined in `specs/PROTOCOL.md`. This
target must fit that protocol and must not define StackChan-specific product
APIs.

## Target Role

StackChan CoreS3 is an implemented Agent-Q firmware target.

Its current role is:

- expose the implemented USB JSONL protocol requests;
- keep a persistent protocol `deviceId`;
- show temporary identification, approval, and result UI on top of the default
  StackChan avatar face;
- provide hardware smoke coverage for implemented device flows.

It is not a general signing product. It does not expose MCP directly and does
not provide chain-specific signing APIs. The target exposes `sign_transaction`
for inline or same-session staged Sui transaction bytes and user-mode
`sign_personal_message` for bounded Sui personal-message bytes. Sui zkLogin
active identity support is also wired in source through common
`credential_prepare`/`credential_propose`, active account projection,
the device-local Sui account view display/clear, and final zkLogin signature-envelope
construction. Firmware reads its device-local signing authorization mode to use
either policy authorization or user confirmation internally for transaction
signing. Invalid, unbindable, unsupported-version/kind, `TransactionKind`-only,
malformed, trailing, or oversized Sui transaction bytes fail closed. Valid
account-bound transactions whose offline facts review coverage is incomplete
may enter explicit user-mode blind signing. Those Sign API and zkLogin paths have
`source-wired-not-product-active` status in the current tree.
Product-active status is not claimed unless `docs/IMPLEMENTATION_STATUS.md` says the
matching source, docs, tests, build, hardware, and visual evidence are complete.
The target classifies bounded shared `(type, chain, method)` signing routes
before state/session work. Sui is currently the only executable chain, and the
selected Sui adapter owns decoded-payload capacity and semantic classification.
Policy updates enter only through the Firmware-owned `policy_propose`
proposal flow; there is no direct policy setter. It links a host-tested Sui
`TransactionData` facts extractor plus current policy document storage/readback
and offline condition-facts extraction, stores
DEV_PROFILE root entropy and a DEV_PROFILE active
default-reject policy record plus a DEV_PROFILE local PIN verifier plus
device-local signing authorization mode, and consumes the committed active
policy for Sui `sign_transaction` policy mode only through Firmware-owned
gates. Policy-mode Sui transactions sign only when the active current policy has
a matching `sign` policy over complete Firmware-derived offline condition facts.

## Target Status

Legend:

- `O`: implemented and verified on this target.
- `△`: partially implemented or diagnostic-only.
- `X`: not implemented.
- `N/A`: not applicable to this target.

| Capability | Status | Notes |
|---|---:|---|
| USB JSONL transport | O | Uses ESP32-S3 USB Serial/JTAG. |
| Persistent protocol `deviceId` | O | Stored in NVS namespace `agent_q`, key `device_id`. |
| `get_status` | O | Returns device id, current state, and provisioning status without approval UI. Before reporting status, the target refreshes persistent-material consistency and can fail closed into `error` while clearing stale runtime session state. |
| Provisioning status reporting | △ | Reports `unprovisioned`, material-backed `provisioned`, or `error` for persistent material inconsistency. Hardware smoke coverage exists for local setup and import setup reaching `provisioned`; failure and consistency-error states still need targeted hardware checks. This is not signing approval. Sign API requests still require a matching active session, the selected authorization gate, required history, signing critical section, response writer, and current-tree hardware/LVGL evidence before product-active status. |
| Mnemonic UI flow | △ | The local setup speech bubble opens a Generate/Import choice. Generate creates DEV_PROFILE BIP-39 root entropy in RAM from an early-boot-seeded Agent-Q CSPRNG, displays only up-to-4-letter prefixes on device in a 3-column by 4-row grid, and advances to local 6-digit PIN entry after local backup confirmation. Import accepts 12 BIP-39 words through a device-local 3-word-per-page prefix/candidate UI, verifies checksum, then enters the same PIN setup path. The target stores root entropy plus an active default-reject policy plus a salt/PIN verifier plus signing authorization mode only after the repeated PIN matches. Three-letter BIP-39 words are displayed as the full word. The target keeps setup/import volatile state and cleanup decisions in a provisioning-flow state module; USB/UI code routes events and renders the current state. Local controls own the setup transitions; there are no USB setup transition requests. Hardware smoke coverage exists for Generate setup, PIN entry, and Import entry. |
| `identify_device` | O | Shows a short code using temporary Agent-Q avatar UI. |
| `connect` | O | Source accepts connection only after material-backed `provisioned` state and Firmware-owned device-local approval. The target shows a connect review modal first. The device-local human approval input mode then selects either local PIN entry or physical Confirm. The session is RAM-only and does not authorize signing. Hardware smoke coverage exists for local PIN approval and fresh reconnect after USB detach/replug. |
| `disconnect` | O | Source clears only a matching RAM-only Firmware session and does not require persistent material readiness. It returns `busy` while local setup/PIN/reset or sensitive settings subflow state is active, including Change PIN, so external session teardown cannot interleave with device-local sensitive UI. A matching disconnect cancels a pending policy update before the commit critical section, because that proposal is session-bound rather than generic local UI; the canceled policy-update request receives `invalid_session`, and the disconnect request receives `disconnect_result`. Idle Settings menu does not block disconnect. |
| Local settings / material wipe | △ | Source implements the device-local common Settings actions listed in the Local settings menu section and a separate device-local chain account menu whose current Sui account view displays active identity/proof state and can clear the local zkLogin proof. Common Settings actions are human approval input mode toggle, signing authorization mode toggle, policy reset to the default reject policy, Change PIN, and Reset. Policy reset, signing-mode changes, zkLogin proof clear, and Change PIN require local PIN verification. After proof-clear PIN verification, the terminal result restores the Sui account view from current device state. Change PIN verifies the current PIN, stores only a replacement salt/PIN verifier after repeated new PIN entry, and leaves root material/policy unchanged; storage failure either preserves the previous verifier or fails closed if the post-write verifier state cannot be proven. Reset wipes root material, active policy, Sui zkLogin proof material, PIN verifier, signing authorization mode, approval history, policy-update terminal marker, human approval input mode setting, session, and returns to `unprovisioned`. Source also implements device-local destructive erase-only recovery from persistent-material consistency `error`, without PIN because the verifier may be unreadable, using the same reset-pending marker and wipe transaction. Host-triggered reset/debug/recovery/PIN-change/signing-mode setter/policy-reset/proof-clear protocol paths are not implemented. Hardware smoke coverage exists for local reset, idle Settings session behavior, Change PIN session retention, USB detach/replug session invalidation, and error-recovery modal layering; Sui account-view proof display/clear is not hardware-verified. |
| Agent-Q avatar UI | O | Uses Agent-Q-owned top speech-bubble decorators, modal review panels for external-request human approval, local PIN panels where required, screen-bottom timer bars, and temporary result feedback. |
| Result feedback UI | O | Shows temporary result speech and returns to the default avatar. |
| Head movement feedback | O | Briefly raises the head for notification, approval, and success states. |
| Display power control | O | Turns the screen backlight off after three minutes of inactivity, skips the upstream screensaver, wakes for Agent-Q UI, toggles display power on side-button short press, and powers off on side-button long press. Before screen-off or power-off, the target moves to a rest posture; when the screen wakes, it returns to awake posture. |
| Boot/sleep posture | O | Centers yaw and raises pitch when the default avatar is attached at boot or the screen wakes. Moves to centered yaw and lowered pitch before screen-off or power-off. |
| Ed25519 signing self-test | △ | Runtime-generated test seed only; wiped after the self-test. Not a signing API. |
| Sui transaction signing substrate | △ | Source can derive the Sui account 0 signing seed from stored DEV_PROFILE root material, sign Sui transaction bytes with the pinned MicroSui Ed25519 transaction-intent routine, return only a Sui signature envelope to internal callers, and wipe root/mnemonic/seed scratch. Host tests cover a deterministic signature vector, verification, invalid-input output wiping, and missing-root failure. The substrate is not exposed as a public signing API. |
| `sign_transaction` | △ | Source is wired for Sui `sign_transaction` with inline `txBytes` and same-session staged payload delivery before the current Sui `TransactionData::V1 -> ProgrammableTransaction` facts extractor. The public USB dispatcher, payload upload handlers, `sign_result` writer, client/MCP/provider parser/API, Wallet Standard adapter, and raw `signing` capability are present in source. Host tests cover bounded request metadata parsed from inline `txBytes` or staged `payloadRef`, payload upload/digest/descriptor behavior, command argument refs, top-level TypeTag facts, malformed ref rejection, signable payload scratch, payload digest, policy runtime, review/PIN/history/signing stages, session ownership, terminal cleanup, review view-model rows derived from Firmware-parsed bytes, host-supplied `network` handling, active zkLogin proof network matching, required history writes, signing-critical handoff, response boundaries, and payload/signature scratch wiping. Firmware reads device-local signing authorization mode and selects one gate: policy mode validates active policy availability, request network scope, account binding, and complete offline policy condition facts, then signs only when the active current policy has a matching `sign` policy; user mode may enter offline facts review when complete offline facts review coverage exists or blind-signing review when Firmware can validate and bind the transaction but offline facts review coverage is incomplete. Invalid or unbindable Sui transaction bytes, active zkLogin proof network mismatch, caller-selected authorization, and caller-controlled timing fields fail closed or are not supported; Firmware-owned review/PIN input windows use a fixed internal 30-second window. Submitting a complete PIN pauses the input timer while stored-PIN cryptographic verification runs; the signing confirmation window is the review/PIN-entry admission boundary and is not the terminal timeout authority during stored-PIN processing after submit. The internal local-auth worker watchdog still fails closed as authentication unavailable, and wrong PIN results resume the remaining paused input window unless the shared lockout is active. Product-active status is tracked in `docs/IMPLEMENTATION_STATUS.md`. |
| `get_capabilities` | O | Source reports one active Sui account identity capability and no delegated public methods over an approved session while material-backed `provisioned`: native Ed25519 when no zkLogin proof is active, or zkLogin when proof material is active. Top-level `signing` reports read-only Firmware signing authorization mode and supported signing routes. While native identity is active, `credentials[]` may advertise common Sui zkLogin `credential_prepare`/`credential_propose` availability. |
| `get_accounts` | O | Source returns one active Sui account identity over an approved session while `provisioned`: native Sui Ed25519 account 0 (`m/44'/784'/0'/0'/0'`) derived from stored DEV_PROFILE root entropy, or the locally stored Sui zkLogin identity when proof material is active. Read-only; private material, raw JWTs, and proof secrets never leave Firmware. Native derivation is verified against Sui SDK address vectors on host; hardware smoke coverage exists for the native path while idle Settings is open, after Change PIN on the same session, and after reconnect. zkLogin projection is not hardware-verified. |
| Sui zkLogin credential preparation/proposal | △ | Source exposes common `credential_prepare` and `credential_propose` with `source-wired-not-product-active` status. `credential_prepare` returns native scheme-prefixed Ed25519 public material only while native Sui identity is active. `credential_propose` accepts bounded zkLogin proof inputs, shows a device-local proof review, requires local PIN, stores a bounded proof record after successful commit, and ends the session after activation so callers reconnect before reading the zkLogin account projection. It stores no raw JWT and does not claim local OAuth/prover/validator freshness verification. Preparation/proposal fail closed while zkLogin is active or proof storage is unavailable. Browser-to-device Web Serial operation is not hardware-verified. |
| `policy_get` | △ | Source implements session-scoped read-only document readback for the committed active `agentq.policy` policy record. The current product flow installs a valid empty default-reject policy, and the target active-policy store accepts bounded current-schema active policy material. Corrupt/unreadable active policy or missing policy under `provisioned` fails closed. Host process and MCP parser tests and target policy-store host tests cover the current source/parser/store behavior, including full-document readback shape and response-size bounds. Current-tree hardware readback evidence for the full document response remains pending. |
| `get_approval_history` | △ | Source implements a session-scoped read-only view of persistent Firmware-authored signing and policy-update terminal metadata. Records are stored in a fixed-size binary NVS ring buffer, newest-first paginated, and wiped by local reset or error-state erase recovery. `sign_transaction` records policy confirmation after policy approval, user confirmation after device-local approval, and terminal signing metadata for signed, rejected, timed-out, and failed outcomes as applicable; user-mode `sign_personal_message` records user confirmation and terminal signing metadata for supported terminal outcomes. Invalid parameter, malformed transaction/message, and unsupported-method errors are not persisted as approval history. The policy-update flow records `applied`, `rejected`, `timed_out`, and `storage_error` terminal records through a required-write path. Product-active status is tracked in `docs/IMPLEMENTATION_STATUS.md`; Host process and MCP parser tests, target approval-history host tests, and opt-in policy-update hardware smoke coverage cover current source behavior. |
| Persistent signing material | △ | DEV_PROFILE root entropy NVS blob exists after backup confirmation plus matching PIN repeat. Source can additionally store one bounded Sui zkLogin proof record after device-local review and local PIN approval. Public active account projection is implemented (`get_accounts`, native Sui Ed25519 account 0 or active Sui zkLogin identity). Internal Sui signing substrate is wired into `sign_transaction` after inline or staged Sui payload preparation and user-mode `sign_personal_message` for bounded personal-message bytes, then wraps the device-produced Ed25519 user signature in a zkLogin envelope when zkLogin is active. Product-active status is tracked in `docs/IMPLEMENTATION_STATUS.md`. USER_PROFILE secure storage and import are not implemented. |
| Mnemonic generation/import | △ | DEV_PROFILE backup phrase generation/display, device-local mnemonic import entry, local 6-digit PIN setup, and backup-confirmed/checksum-verified root entropy storage source exists. USB, host process, or MCP mnemonic import and USER_PROFILE secure provisioning are not implemented. |
| Provisioning flow | △ | DEV_PROFILE mnemonic UI and material-backed `provisioned` state source exists. Backup confirmation plus matching PIN repeat stores root entropy, initializes the active default-reject policy, stores the local PIN verifier, and initializes signing authorization mode. Public account derivation is implemented via `get_accounts`; USER_PROFILE secure provisioning is not implemented. |
| Policy evaluation | △ | Source has the current policy document parser/storage/readback boundary, a Sui offline condition-facts extractor over Firmware-derived `TransactionData` facts, and a current policy evaluator for Sui `sign_transaction`. Policy mode signs only when active policy availability, request network scope, account binding, complete offline condition facts, and a matching `sign` policy all pass. Missing, incomplete, unmatched, or reject-matched policy coverage returns `policy_rejected`. |
| Policy storage/read | △ | Stores the active policy as canonical `agentq.policy` binary records in two bounded NVS slots plus commit metadata and a pending-write marker, exposes read-only `policy_get` active policy document readback, preserves the previous committed policy only for interrupted writes identified by that pending marker, treats metadata flip as the commit point, classifies each write as applied, unchanged failure, or consistency error, tolerates stale pending markers that exactly match the selected committed policy, removes stale commit metadata before slot reuse, and treats corrupt/unreadable committed records, invalid commit metadata without a matching pending marker, or pending targets that overlap active material without exactly matching it as a material-consistency error. The current product flow installs a valid empty default-reject policy; the Firmware-owned `policy_propose` proposal path accepts bounded current-schema policy material. |
| Policy update | △ | Source implements a Firmware-owned `policy_propose` flow for active sessions: bounded proposal validation, a device-local policy summary review, local-PIN approval only after device-local Continue, canonical active-policy commit, required terminal history recording, and no direct policy setter. The target accepts bounded current-schema `agentq.policy` documents. Policy-mode signing consumes the committed active policy only through Firmware-owned signing gates. The flow uses the two-slot active-policy store plus a persistent policy-update terminal marker that makes an incomplete post-commit terminal sequence a material-consistency error on reboot. The host-process/MCP request/parser surface exists, and the host process has a local Admin Page for current-schema policy proposal submission and a minimal Sui testnet policy template. Policy reset is available only as a Firmware-local Settings action. |
| Secure user profile | X | Not implemented. |

## Chain And Method Support

This target exposes chain support only through the shared session-scoped
protocol. `sign_transaction` and user-mode `sign_personal_message` have
`source-wired-not-product-active` status. Product-active status is tracked in
`docs/IMPLEMENTATION_STATUS.md`. Firmware-local signing
mode selects policy authorization or user confirmation for transaction signing.

| Chain / method | Status | Notes |
|---|---:|---|
| Sui Ed25519 self-test | △ | Diagnostic only. It proves the signing dependency links and works on-device. |
| Sui transaction signing substrate | △ | Signs transaction bytes using Sui's transaction intent prefix and Ed25519 signature envelope for internal substrate tests and the `sign_transaction` critical section, then wipes private scratch. |
| `sign_transaction` | △ | Unified signing request with `source-wired-not-product-active` status for inline and same-session staged Sui transaction bytes. Public USB dispatcher, payload upload handlers, USB `sign_result` writer, provider/client/MCP parser/API, Wallet Standard adapter, and raw `signing` capability are present; Firmware-local signing mode selects either policy evaluation or user confirmation only after Firmware parsing and mode-specific authorization coverage checks. Product-active status is tracked in `docs/IMPLEMENTATION_STATUS.md`. |
| Sui `sign_personal_message` | △ | `source-wired-not-product-active` for bounded Sui personal-message bytes in user authorization mode. Public USB dispatcher, USB `sign_result` writer, provider/client/MCP parser/API, Wallet Standard `sui:signPersonalMessage`, user clear-signing review rows, approval-history metadata, and PersonalMessage intent digest signing are present in source. Policy mode fails closed with `unsupported_method`; policy facts/rules for personal-message signing are not implemented. Product-active status is tracked in `docs/IMPLEMENTATION_STATUS.md`. |
| Sui `sign_transaction` | △ | Through `sign_transaction`, this method validates request-context `network`, matches that request network against the stored proof network when zkLogin is active, and accepts either canonical base64 inline `txBytes` or a same-session staged `payloadRef`, derives offline-provable facts with the current Sui `TransactionData::V1 -> ProgrammableTransaction` facts extractor, and then uses the Firmware-local signing authorization mode only if the parsed shape has mode-specific authorization coverage. Policy mode validates active policy availability, request network scope, account binding, and offline policy condition facts, then signs only when the active current policy has a matching `sign` policy; user mode shows covered offline facts when offline facts review coverage is complete, or a blind-signing warning when Firmware can validate and bind the transaction but offline facts review coverage is incomplete. Product-active status is tracked in `docs/IMPLEMENTATION_STATUS.md`. Corrupt/unreadable or missing policy fails closed before policy-mode signing is available. |
| Sui transaction decoding | △ | The StackChan build links the common Sui `TransactionData::V1 -> ProgrammableTransaction` facts extractor for inline or staged transaction bytes. Host fixtures cover all PTB command variants currently decoded by the bounded extractor, MoveCall package/module/function metadata, TypeTag facts, command argument refs, `TransactionKind`-only rejection, out-of-range ref rejection, sponsored gas owner extraction, unsupported-version/kind/shape classification, and malformed/trailing/oversized rejects. The runtime keeps parser success separate from Sui `sign_transaction` policy and user authorization coverage. |
| Sui zkLogin | △ | `source-wired-not-product-active` for common proof preparation/proposal, bounded proof storage, active account projection, device-local Sui account-view display/clear, and final zkLogin signature-envelope construction after the existing signing authorization gate. It stores no raw JWT, does not claim local OAuth/prover/validator freshness verification, has no signer-selector API, and has no proof-clear protocol route. Browser/Web Serial setup, clear, reconnect, and signing are not verified. |
| EVM signing | X | Not implemented. |
| Solana signing | X | Not implemented. |

Current public chain support uses the common session-scoped protocol flow:
`connect -> get_capabilities -> get_accounts -> credential_prepare? ->
credential_propose? -> sign_transaction* -> sign_personal_message* ->
disconnect`. Credential operations are optional, supported only for the current
Sui zkLogin setup boundary, and do not choose a signer. Signing uses the shared
protocol; Firmware-local signing mode selects policy or user authorization
internally for `sign_transaction`; `sign_personal_message` is user-mode only.
This target must not add StackChan-specific or chain-specific MCP tools.

## StackChan Runtime Boundary

Agent-Q uses StackChan CoreS3 as an avatar-based approval surface, not as a
general StackChan AI firmware.

The Agent-Q build keeps:

- the local launcher;
- the local default avatar idle surface;
- the USB Agent-Q request server;
- local touch and motion feedback needed for Agent-Q UI.

The Agent-Q build disables or avoids:

- StackChan/Xiaozhi remote AI runtime;
- StackChan World login;
- Xiaozhi remote MCP tools;
- camera initialization;
- setup/login worker;
- remote avatar WebSocket service;
- camera, screen snapshot, and remote video upload surfaces.

Developers who need upstream StackChan AI/cloud features should flash upstream
StackChan firmware separately and must not treat that firmware as an Agent-Q
signing device.

## UI State Model

StackChan owns the default avatar face and normal device runtime.

Agent-Q owns only the temporary UI objects it creates:

- Agent-Q speech-bubble decorator;
- modal review panels for external-request human approval;
- temporary emotion override;
- temporary head movement feedback.

Agent-Q must remove only its own temporary UI. It must not force a dedicated
Agent-Q app mode for normal requests.

Current UI behavior:

| Request or state | UI behavior | Firmware state |
|---|---|---|
| `unprovisioned` idle | Touchable setup speech bubble | `idle` |
| `get_status` | No UI; may refresh persistent-material consistency before reporting status | `idle` unless approval UI, setup material, sensitive local subflow, or material/state error is active |
| `identify_device` | Temporary speech bubble with short code | `idle` |
| Local setup choice | Temporary Generate/Import setup panel | `busy` |
| Backup phrase displayed | Temporary setup panel with 12 numbered up-to-4-letter prefixes in 3 columns by 4 rows and bottom Cancel/Confirm buttons | `busy` |
| Mnemonic import entry | Temporary setup panel with three numbered word cells, A-Z prefix buttons, scrollable BIP-39 candidate bubbles, and local Cancel/Clear/Previous/Next controls | `busy` |
| Local backup phrase Confirm | Uses the backup phrase panel's bottom Confirm button and advances to local PIN entry | `busy` |
| Local PIN setup | Temporary setup panel with numeric keypad, masked 6-digit entry, Clear, backspace icon, Cancel, and Confirm | `busy` |
| Local settings menu | Temporary settings menu with a scrollable label/control list for common device settings. Current implemented common actions are human approval input mode toggle, signing authorization mode toggle, policy reset, Change PIN, and Reset. The same local settings state owns a separate chain account menu opened from the chain-specific touch entry; the current Sui account view displays active identity/proof state and can clear the local proof. Each sensitive write or clear action opens local PIN verification directly; proof-clear terminal result restores the current Sui account view. | `idle` while the menu or chain account view is idle; `busy` after entering a sensitive subflow |
| Local generate/import Cancel | The backup-phrase (generate) and import-word panels' bottom Cancel wipes setup scratch and returns to the setup-choice menu rather than ending setup; the setup-choice menu's own Cancel ends setup | `busy` (returns to setup choice) after scratch wipe |
| Local setup choice Cancel | The setup-choice menu's bottom Cancel button ends setup | `idle` after scratch wipe |
| Approved result | Temporary success speech and emotion | `idle` |
| Rejected result | Temporary rejected speech and emotion | `idle` |
| Timeout result | Temporary timeout speech and emotion | `idle` |

`idle` means no physical approval prompt, device-only setup material, or
sensitive local subflow is active. An idle Settings menu is local UI, but it does
not block existing session-scoped read or cleanup requests, so status remains
`idle`. Backup phrase display and PIN setup report `busy` so host process status
does not imply that UI-replacing setup requests are available.

The StackChan default avatar face remains visible. Agent-Q does not use the
upstream default speech bubble at runtime; it uses the Agent-Q-owned speech
bubble decorator so request UI ownership is explicit.

## Display Power And Posture

Display power and head posture are target-local runtime state. They must not
gate protocol APIs, provisioning, sessions, accounts, policy, or signing.

The Agent-Q StackChan CoreS3 build replaces the upstream screensaver with
display-power control:

- three minutes of LVGL inactivity turns the screen backlight off;
- Agent-Q request UI wakes the screen before showing setup material,
  notifications, or physical approval prompts;
- side-button short press toggles display power;
- side-button long press powers the device off.

The display-power state is owned by `agent_q_display_power`. StackChan-specific
motor posture and transient head-motion feedback are owned by
`agent_q_motion_state`. The board layer only translates AXP2101 power-key IRQs
into display-power events, target-local motion posture for power-off, or
hardware power-off; it does not change Agent-Q product state.

Boot posture is StackChan-specific motion feedback. After the default avatar is
attached, the Agent-Q build centers yaw and raises pitch (`yaw=0`, `pitch=540`).
Temporary Agent-Q head movement feedback may run during local notifications and
approvals, then returns control to StackChan motion.

Sleep and wake posture are also StackChan-specific motion feedback. Before
automatic screen-off, manual screen-off, or side-button power-off, the target
moves to centered yaw and lowered pitch (`yaw=0`, `pitch=0`). When the screen
wakes by touch, side-button toggle, or Agent-Q request UI, the target returns to
centered yaw and raised pitch (`yaw=0`, `pitch=540`). These posture changes are
not product state and must not clear sessions, provisioning scratch, accounts,
or pending approvals.

## Session Model

`connect` is defined by the shared protocol and is accepted only after the
target is material-backed `provisioned`. The session id is generated by
Firmware and held in RAM. A new approved `connect` replaces the previous
Firmware session. The host process reuses its RAM-held runtime session for
`connect_device` when a session-scoped read-only request confirms that the
Firmware session is still valid. The host process sends a fresh Firmware `connect`
request only when it has no valid local session or Firmware rejects the cached
session. The host process's RAM session mirror is not device authority; the host process clears it
when Firmware rejects the session or when a live USB scan no longer observes the
device.

By default this target uses device-local 6-digit PIN entry when Firmware enters
a human-approval branch for an external request such as `connect` or user-mode
signing. Successful PIN entry is the approval; there is no additional Confirm
step after PIN success. A device-local Settings action can switch the human
approval input mode to the physical Confirm path, but changing that setting
also requires stored PIN verification. The setting is stored as
`human_approval`: setup initializes it to `pin`, a missing key means the
secure default, `pin`, and an invalid value fails closed to `pin` and is
logged. When the target cannot read the setting, the settings menu shows the
fail-closed value but disables the toggle instead of allowing a write from an
uncertain source state. PIN entry is never submitted over USB.

USB link loss clears the Firmware RAM session by policy. For this target,
USB connected means USB host SOF is observed through
`usb_serial_jtag_is_connected()`. It does not prove The host process is running or that
the serial port is open, so cable removal, host sleep/suspend, or SOF loss ends
the session. The target advertises the maximum uint32 `sessionTtlMs` because
the session is USB-link-bound instead of time-expiring.

`disconnect` clears the session only when the supplied session id matches the
active Firmware session. It is a session-lifecycle operation, so material
readiness is not required; if a consistency error has already cleared the
session, `disconnect` returns `invalid_session`.

Sessions do not authorize signing. They only establish a communication session
for session-scoped protocol requests.

## Persistent Storage

This target persists the protocol `deviceId`, the provisioning state flag, a
DEV_PROFILE binary root entropy blob, the DEV_PROFILE active default-reject
policy record, a DEV_PROFILE local PIN verifier, and one optional bounded Sui
zkLogin proof record in ordinary NVS. Root entropy is stored after physical
backup confirmation plus matching PIN repeat. The zkLogin proof record is
stored only after device-local proof review and local PIN approval. Setup also
initializes device-local signing authorization mode and the human approval input
mode default. The provisioning state
flag is not signing material by itself and does not make the device ready to
sign. The target reports `provisioned` only when the persisted state, valid root
entropy blob, valid active policy record, valid local PIN verifier, and valid
signing authorization mode all exist. If those records disagree after boot or during runtime checks, the target
reports `provisioning.state = error` and fails closed. It does not store the
mnemonic display string, prefixes, seed, or account data to NVS. The local PIN
verifier is a UX gate for human-approval branches when the input mode is `pin`, settings changes, local
reset, the current policy-update proposal flow, and sensitive local writes; it
is not root-material encryption.
If the target boots with `prov_state = provisioned` and valid root entropy but
no active canonical policy record, it enters material/state consistency error.
Unsupported current policy-history or policy-storage blobs are not accepted as
product state; destructive local reset or error-state erase is the supported
recovery path. Existing DEV_PROFILE devices without the current local PIN
verifier fail closed until reprovisioned.

| Namespace | Key | Purpose |
|---|---|---|
| `agent_q` | `device_id` | host process reconnect and device-selection identity |
| `agent_q` | `prov_state` | Provisioning state flag; `provisioned` is valid only with root entropy, active policy, local PIN verifier, and signing authorization mode present |
| `agent_q` | `root_entropy` | DEV_PROFILE BIP-39 root entropy blob; not exported over USB |
| `agent_q` | `pol_s0`, `pol_s1` | Active policy canonical record slots |
| `agent_q` | `pol_c0`, `pol_c1` | Active policy commit metadata records |
| `agent_q` | `pol_p` | Active policy pending-write marker used to distinguish interrupted inactive-slot writes from post-commit corruption |
| `agent_q` | `pol_um` | Policy-update terminal marker; presence means an incomplete policy-update terminal sequence is material inconsistency |
| `agent_q` | `pin_auth` | DEV_PROFILE salt + PBKDF2-HMAC-SHA512 local PIN verifier; not root encryption |
| `agent_q` | `sign_auth_mode` | Device-local signing authorization mode; setup initializes it to user and Settings can change it after local PIN verification |
| `agent_q` | `human_approval` | Human approval input mode setting; setup initializes it to `pin`, missing or invalid read fails closed to `pin`, and local reset erases it back to the missing-key default |
| `agent_q` | `sui_zkl_proof` | Bounded Sui zkLogin proof record used only for active account projection and final zkLogin signature-envelope construction; local proof clear, reset, and error-state erase wipe it |
| `agent_q` | `approval_hist` | Fixed-size 32-record binary ring buffer of Firmware-authored signing and policy-update metadata; local reset and error-state erase wipe it |
| `agent_q` | `reset_pending` | Internal Firmware-owned marker used to resume an interrupted local reset wipe at boot; not a protocol state or host API |

The StackChan build preparation step patches the generated firmware
`partitions.csv` so this target owns a 64 KiB NVS partition. The upstream
StackChan 16 KiB NVS layout is not sufficient for the current Agent-Q material
set.

Agent-Q-owned modules are sources under `agent_q/` in this target tree. These
modules may share the `agent_q` namespace. New keys should be named by feature,
such as `<feature>_<name>`, to avoid collisions. ESP-IDF NVS key names are
limited to 15 characters, so this target uses `prov_state` rather than the
longer protocol field name `provisioning.state`.

## Approval History

This target implements persistent approval history as a Firmware-owned,
read-only approval-history log. It is not an on-chain transaction history and is
not a host activity log. The current source records bounded metadata for signing
confirmation and terminal results from `sign_transaction` and user-mode
`sign_personal_message`, plus recordable terminal results from `policy_propose`.
Invalid parameter, malformed transaction/message, and unsupported-method errors
are not persisted as approval history.

The history is a fixed-size binary NVS ring buffer under `approval_hist`, capped
at 32 records so it fits in the Agent-Q-patched 64 KiB StackChan CoreS3 NVS
partition alongside the other Agent-Q material records. Unsupported current
approval-history blobs are not accepted as product state; destructive local
reset or error-state erase is the supported recovery path.
Required signing and policy-update terminal history records are part of their
respective terminal contracts. The policy-update flow has its own active
session, request validation, and device-local approval gates before it can emit
them. If a required signing history record cannot be persisted, the signing path
returns top-level
`history_error` rather than claiming the decision result was delivered.
It stores sequence, uptime in milliseconds, signing record kind, terminal
result, confirmation kind, chain, method, reason code, optional payload digest,
optional policy hash, and optional rule reference for signing records.
Policy-update terminal records store result, reason code, policy hash, rule
count, and highest action.
It does not store raw transaction bytes, full decoded transactions, raw policy
documents, full rule content, session ids, raw request ids, client names,
mnemonic text, seed, private key material, PINs, or full policy documents.
Local reset and error-state erase recovery wipe the history with the rest of
the local material set.

The `get_approval_history` protocol request is session-scoped and read-only.
It is available only when the target is material-backed `provisioned` and the
request has a matching active session. There is no protocol request to add,
edit, delete, or clear history records.

## Provisioning Capability

Provisioning status reporting, the mnemonic UI flow, and DEV_PROFILE root
entropy persistence are implemented in the target firmware source. Hardware
smoke is still required. `get_status` returns `provisioning.state`.

Setup transition paths are local device UX only. The target does not implement
USB requests for setup start, setup cancel, backup phrase
confirmation, mnemonic import, factory reset, or diagnostic display
signaling. `provisioned` is set only after local backup confirmation or
checksum-verified local import, matching local PIN repeat, and successful
root entropy, active policy, local PIN verifier, signing authorization mode,
and provisioning-state persistence. `locked` is not used because no unlock
model exists.

Device-local backup phrase setup starts from the local setup speech bubble shown while
the device is `unprovisioned`, then shows local Generate and Import choices.
Generate uses an Agent-Q CSPRNG seeded from early boot entropy before HAL
initialization plus BIP-39 checksum logic to create a 12-word DEV_PROFILE
backup phrase in RAM, then displays only the up-to-4-letter word prefixes on
the device in a 3-column by 4-row grid. Three-letter BIP-39 words are displayed
as the full word. Import uses a device-local word-entry panel with three
numbered word cells per page for four pages. The user taps a cell, enters a
BIP-39 prefix through local A-Z buttons, and selects a matching word from
scrollable on-device candidate bubbles. BIP-39 English prefixes and recovered
words are secret material. No protocol response contains the phrase, prefixes,
imported words, entropy, seed, private key, account data, or policy data.
The target tracks volatile setup with RAM-only scratch substates: `none`,
`setup_choice`, `backup_phrase_displayed`, `import_word_entry`,
`pin_first_entry`, `pin_repeat_entry`, and `pin_committing`. This substate is
separate from persistent
`provisioning.state`, session state, display power state, and the LVGL panel
pointer.

Import `Next` is enabled only when all three words on the current page are
selected. After 12 words are selected, Firmware reconstructs 128-bit BIP-39
entropy and verifies the checksum before entering PIN setup. Checksum failure
stores nothing and keeps import entry active. Cancel, timeout, panel
deletion, or display allocation failure wipes import scratch and leaves the
target `unprovisioned`.

Backup confirmation is accepted only from the backup phrase panel's local
Confirm button after the scratch substate is `backup_phrase_displayed`. The
device-local Confirm button advances to local PIN entry; it does not store
persistent material by itself. The import path reaches the same PIN entry only
after 12 selected BIP-39 words pass checksum validation. The PIN entry screen
accepts exactly six digits, asks for a repeat, wipes typed PIN scratch on
mismatch, and returns to first PIN entry while retaining root entropy scratch.
Matching PIN repeat enters
`pin_committing`, keeps the PIN panel active with a non-interactive processing
overlay, stores the DEV_PROFILE root entropy blob, stores the active
default-reject policy, stores a salt + PIN verifier, stores the signing
authorization mode, persists `provisioned`, and then wipes volatile scratch.
Storage failure rolls back persistent setup
material where possible, wipes scratch, and must not report `provisioned`.
Hardware smoke coverage exists for StackChan CoreS3 Generate setup, PIN entry,
and Import entry. Targeted hardware verification remains required after setup
UI or setup-state changes.

The LVGL panel is not the source of truth for setup scratch validity. If the
backup phrase display or PIN panel is removed or replaced while the matching
scratch substate is active, the target treats that UI event as a transition to
`none` and wipes the volatile setup scratch. A subsequent backup confirmation or
PIN submit event must not succeed for setup material whose panel is gone. Display
power state is not part of this security state: screen/backlight sleep alone
does not invalidate scratch, and Agent-Q UI wakes the display before showing
setup material.

The phrase display and PIN setup panel have finite lifetimes. When either
expires, the target clears the setup panel, wipes volatile setup scratch, and no
subsequent backup confirmation or PIN submit can use that scratch.

The device-local Cancel button wipes volatile setup scratch and leaves
persistent state `unprovisioned`. Cancellation does not erase already-confirmed
root material, active policy, PIN verifier, or signing authorization mode.

Local settings actions are separate device-local flows under `provisioned`.
The target enters local settings only when no setup, approval, identification,
or Agent-Q temporary UI is active. The settings screen presents a scrollable
label/control list and Close as the only bottom action. Current implemented
settings actions are the human approval input mode toggle, signing authorization
mode toggle, policy reset to the default reject policy, Change PIN, and Reset.
The same local settings state owns a separate chain account menu whose current
Sui account view displays active identity/proof state and can clear the local
zkLogin proof. Selecting a sensitive action opens stored 6-digit PIN
verification directly. Change PIN then accepts and repeats a new 6-digit PIN,
stores only the replacement salt/verifier, and returns to Settings without
ending the active RAM session; storage failure either leaves the old verifier
in place or fails closed if the post-write verifier state cannot be proven.
Opening or closing the Settings menu alone does not end the active RAM session.
While the Settings menu is idle, existing session-scoped requests remain
available; PIN verification, PIN change, and Reset subflows return `busy` until
the local flow completes or is canceled.
Canceling human approval input mode, Change PIN, or Reset PIN verification, and
successfully changing the human approval input mode setting or PIN verifier, return to the
settings menu instead of closing local settings. Successfully changing the
human approval input mode setting affects the next external-request
human-approval branch; it does not end the current active RAM session.
Wrong PIN, timeout, or cancel leaves root material, active policy, PIN verifier,
signing authorization mode, the human approval input mode setting, and `provisioned` state
intact.
Submitting a complete PIN pauses the input deadline while stored-PIN
cryptographic verification runs. A wrong PIN result returns to the same PIN
entry state by resuming the remaining paused input window unless the shared
wrong-PIN lockout is active. For protocol-backed connect, policy-update, and
device-confirmed signing PIN purposes, their state owner also keeps an
immutable outer request window. That request window is the admission boundary
for review/PIN entry and caps PIN input before submit; it is not the terminal
timeout authority for stored-PIN cryptographic processing after submit. The
local-auth worker still has a separate internal watchdog; if the worker stalls
or its result is lost, the flow fails closed as an authentication error instead
of remaining in verification. For device-confirmed signing, PIN Back returns
to the signing review and wipes only PIN scratch; review Reject is the
terminal `user_rejected` action.
After Reset PIN confirm, the target keeps the reset PIN panel active and adds a
non-interactive processing overlay before PIN verification. Correct PIN
verification advances to destructive wipe while keeping the processing overlay
active, then wipes root material, active policy, Sui zkLogin proof material,
PIN verifier, signing authorization mode, the human approval input mode
setting, approval history, policy-update terminal marker, runtime session, and
provisioning state before reporting `unprovisioned`. Before destructive wipe starts, Firmware
writes an internal
reset-pending marker; if power is lost
mid-reset, boot resumes the material wipe before loading normal state. If the
marker cannot be written, reset aborts before material is wiped. After the
marker is written, partial wipe, marker-clear, or state persistence failure
enters material/state consistency error. This reset flow is not exposed over USB.
When the target detects a material/state consistency error, it clears any active
RAM session immediately and fails closed for session-scoped requests. The error
panel offers only a device-local destructive erase recovery: it cannot read,
repair, unlock, or export stored material, it does not require PIN because the
PIN verifier may be unreadable, and it uses the same reset-pending marker plus
material wipe transaction before returning to `unprovisioned`. Connect,
settings, Change PIN, and reset PIN verification share one RAM-only
5-failure, 30-second stored-PIN attempt budget. Closing one local PIN flow and
opening another does not clear that budget. Power cycling clears the local
lockout.

Read-only public active account projection (`get_accounts`), the Firmware-owned
`policy_propose` proposal flow, Sui zkLogin proof preparation/proposal, bounded
`sign_transaction`, and user-confirmed bounded `sign_personal_message` are
implemented in source. Product-active signing status still requires the current
hardware evidence tracked in the implementation status. Mnemonic import, direct
policy setters, Firmware-local Admin UI, arbitrary Sui transaction signing,
policy-authorized personal-message signing, host-triggered proof clearing, and
USER_PROFILE secure root-material handling are not implemented on this target.
Host-process Admin policy authority is not implemented: the Admin
Page may submit current-schema policy proposals and a minimal Sui testnet policy
template, but Firmware owns validation,
device-local approval, commit, policy evaluation, and signing decisions.

StackChan CoreS3 has a display and touch input, so the current DEV_PROFILE local
provisioning flow can:

- generate a new mnemonic on the device;
- show the mnemonic on the device once for backup;
- require local confirmation before storing it;
- require local 6-digit PIN entry/repeat before storing it;
- accept device-local mnemonic import input only through an explicitly weaker
  DEV_PROFILE setup path;
- expose only public keys and addresses after provisioning.

This target has `source-wired-not-product-active` Sign API paths for inline or
same-session staged Sui transaction bytes and user-mode bounded Sui
personal-message bytes. Firmware-local signing mode chooses policy or user
authorization internally for transaction signing. Unsupported Sui transaction
semantics, sponsored gas, and policy-authorized personal-message signing fail
closed or are not implemented.

## Build Inputs

This directory is an overlay for the pinned upstream StackChan firmware host.
It is not a standalone ESP-IDF project.

Pins:

- target host firmware pin: `firmware/src/stackchan-cores3/source.env`;
- shared firmware dependency pins: `firmware/source.env`.

Tracked helper scripts fetch pinned inputs into `.firmware-cache/`, apply the
Agent-Q overlay, and build. The build must not depend on `.WORK/`.
The BIP-39 English wordlist is fetched from a pinned `bitcoin/bips` commit and
converted into generated firmware source during `prepare.sh`; the generated
wordlist source is not tracked.

## Verification

Current verification expectations for this target:

Command-level build and flash usage lives in this target's README. A hardware
smoke pass is complete only when the evidence records the target hardware,
repository commit, build command, flash command, serial port, manual
device-local steps, observed result, and unchecked paths. If a listed smoke item
cannot be checked, mark it unchecked; do not infer it from source paths or host
tests.

- run `firmware/tools/stackchan-cores3/test_bip39_vectors.sh` after ESP-IDF
  v5.5.4 is active to check known BIP-39 entropy-to-mnemonic vectors against
  the tracked encoder, ESP-IDF mbedTLS SHA-256, and generated wordlist source;
- run `firmware/tools/stackchan-cores3/test_local_auth.sh` to check local
  6-digit PIN verifier storage, verification, fresh salt, wipe, and fail-closed
  behavior against host NVS/RNG stubs and pinned Monocypher;
- run `firmware/tools/stackchan-cores3/test_local_pin_auth.sh` to check local
  PIN authorization state transitions, including lockout release and paused
  input-window resume;
- run `firmware/tools/stackchan-cores3/test_connect_approval.sh` to check
  physical connect approval request/client-name/deadline/choice state ownership;
- run `firmware/tools/stackchan-cores3/test_protocol_pin_approval.sh` to check
  the protocol-backed local PIN approval request/session/input-deadline state
  owner;
- run `firmware/tools/stackchan-cores3/test_identification_display.sh` to check
  temporary identification display active/deadline state ownership;
- run `firmware/tools/stackchan-cores3/test_local_settings_touch_entry.sh` to
  check local Settings corner-touch hold state ownership;
- run `firmware/tools/stackchan-cores3/test_usb_link_state.sh` to check USB
  host SOF polling state ownership and link-edge classification;
- run `firmware/tools/stackchan-cores3/test_usb_session_loss.sh` to check the
  session-bound volatile cleanup plan for USB host SOF loss;
- run `firmware/tools/stackchan-cores3/test_device_activity_projection.sh` to
  check the host-compiled device activity projection matrix for
  policy-update stages, local Settings gates, signing ingress blocking, and the
  idle Settings menu USB exception, plus the retained-result read/cleanup route
  class for `get_result` and `ack_result`. This is not a hardware smoke test;
- run `firmware/tools/stackchan-cores3/test_sign_api_activation_boundary.sh`
  to check that chain-specific public Sign API names are absent,
  `sign_transaction` and `sign_personal_message` are wired through the intended
  client/MCP/provider/Firmware USB paths, and caller-controlled authorization or
  timing fields remain absent;
- run `firmware/tools/stackchan-cores3/test_ui_panel_cleanup.sh` to check
  panel-deletion cleanup routing between temporary UI and state owners;
- run `firmware/tools/stackchan-cores3/test_modal_layout_static.sh` to check
  bounded modal layout invariants such as the connect review client name not
  overlapping the approval row;
- run `firmware/tools/stackchan-cores3/test_local_reset.sh` to check local reset
  and error-state erase recovery state transitions, reset-pending marker
  behavior, destructive wipe orchestration, and failure cleanup against host
  NVS/material stubs;
- run `firmware/tools/stackchan-cores3/test_provisioning_flow.sh` to check
  Generate/Import/setup-PIN volatile state transitions, scratch lifetime,
  panel-loss cleanup, and commit readiness against host stubs;
- run `firmware/tools/stackchan-cores3/test_provisioning_runtime_state.sh` to
  check persistent provisioning runtime-state load, persist, material-ready,
  and reset-marker orchestration against host stubs;
- run `firmware/tools/stackchan-cores3/test_human_approval_settings.sh` to check
  the human approval input mode setting's missing-key secure default, stored
  Confirm override, invalid value fail-closed behavior, and reset wipe back to
  the missing-key default;
- run `firmware/tools/stackchan-cores3/test_approval_history.sh` after ESP-IDF
  v5.5.4 is active to check the persistent approval-history NVS ring buffer,
  newest-first pagination, payload digest formatting, wipe behavior, and
  corrupt-record fail-closed behavior;
- run `firmware/tools/stackchan-cores3/test_prepare_sync.sh` to check that
  `prepare.sh` materializes tracked overlay sources and generated wordlist
  output into the generated firmware tree and replaces stale target symlinks;
- build with `firmware/tools/stackchan-cores3/build.sh` after ESP-IDF v5.5.4 is
  active;
- flash to a StackChan CoreS3 device when hardware is available;
- smoke-test `get_status`;
- smoke-test `identify_device`;
- smoke-test `connect` returns `invalid_state` before `provisioned`;
- manually enter setup from the local unprovisioned setup speech bubble;
- visually verify the backup phrase panel displays 12 numbered
  up-to-4-letter prefixes in a 3-column by 4-row grid and that three-letter
  BIP-39 words are displayed as the full word;
- smoke-test local Cancel wipes scratch and leaves `provisioning.state =
  unprovisioned`;
- smoke-test local Confirm advances to local PIN setup without storing material;
- smoke-test matching local PIN repeat stores root material plus active
  default-reject policy plus local PIN verifier plus signing authorization
  mode, wipes scratch, and reports `provisioning.state = provisioned`;
- smoke-test PIN mismatch wipes typed PIN scratch only and retries first PIN
  entry;
- smoke-test PIN cancel/timeout wipes PIN plus root scratch and remains
  `unprovisioned`;
- smoke-test reboot persistence after matching PIN repeat;
- smoke-test `connect` after backup-confirmed root material, active policy,
  local PIN verifier, and signing authorization mode storage requires local PIN
  by default and returns a RAM-only session id;
- smoke-test local settings human approval input mode toggle requires current
  PIN, changes only that local setting, and leaves it unchanged after wrong PIN,
  cancel, or timeout;
- smoke-test local settings Change PIN requires the current PIN, stores the new
  PIN only after repeated new PIN entry, leaves the old PIN valid on mismatch,
  cancel, timeout, or storage failure, and never changes root material or policy;
- smoke-test USB host SOF loss clears the Firmware RAM session;
- smoke-test `disconnect` clears a matching active session and rejects an
  unknown or inactive session id;
- smoke-test `policy_propose` on a development device whose active
  policy may be changed: submit a bounded current-schema policy over an approved
  session, verify the device-local summary review appears, use device-local
  Continue to enter local PIN approval, verify `policy_propose_result` reports
  `applied`, verify `policy_get` reflects the committed policy hash and active
  rules, and verify `get_approval_history` returns a newest policy-update
  terminal record whose sequence advanced during this smoke run;
- smoke-test the policy-update review subpaths separately when that evidence is
  required: review Back from PIN returns to the same summary and wipes only PIN
  scratch, review Reject returns terminal `rejected` without committing, and
  review timeout returns terminal `timed_out` without committing;
- track separate follow-up smoke coverage for invalid, rejected, and timed-out
  `policy_propose` attempts, verifying that the previously committed
  active policy is still reported by `policy_get`; do not count the positive
  `applied` smoke as coverage for those terminal paths;
- rerun the tracked client-owned signing smoke harness when Sign API source,
  protocol, target runtime, timeout, PIN, modal, or display code changes. That
  harness covers the `source-wired-not-product-active` Sign API paths:
  `sign_transaction` positive signed result, user reject, timeout, policy
  signed/rejected outcomes, `sign_personal_message` user-mode
  signed/rejected/timeout outcomes plus policy-mode fail-closed behavior, USB
  detach/reconnect cleanup, newest approval history, and no client output leak
  of session ids, raw transaction bytes, PINs, secret-like fields, or raw
  message bytes outside the intended signed personal-message `messageBytes`
  echo. Treat its results as valid only for the tree they ran on, and rerun
  after such changes before relying on them;
- capture LVGL clear-signing visual evidence on current firmware before
  claiming product-active status;
- smoke-test local settings reset from `provisioned`: wrong PIN leaves
  `provisioned` material intact, cancel/timeout leaves material intact, correct
  PIN wipes root material, active policy, Sui zkLogin proof material, PIN
  verifier, signing authorization mode, approval history, policy-update
  terminal marker, human approval input mode setting, and session, then
  `get_status` reports
  `unprovisioned`;
- smoke-test three minutes of inactivity turns the screen backlight off, Agent-Q
  request UI wakes it, side-button short press toggles display power, and
  side-button long press powers off;
- visually verify boot posture centers yaw and raises pitch after the default
  avatar attaches;
- visually verify automatic screen-off, manual screen-off, and side-button
  power-off move the target to centered yaw and lowered pitch first;
- visually verify touch, side-button wake, and Agent-Q request UI wake return
  the target to centered yaw and raised pitch;
- smoke-test `get_status` reports `device.state = busy` while a backup phrase
  is displayed;
- smoke-test backup phrase display expiry clears the setup panel, wipes
  scratch, and prevents subsequent local confirmation;
- visually verify that Agent-Q temporary UI does not leave the avatar in an
  Agent-Q-specific mode after completion.
