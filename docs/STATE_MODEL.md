# Agent-Q State Model

This document defines Agent-Q product states, allowed protocol functions, and
module responsibility boundaries.

It is a design contract for the current implementation. Current implementation
status lives in `docs/IMPLEMENTATION_STATUS.md`. The wire message
contract lives in `specs/PROTOCOL.md`.

## Source Of Truth

State names are defined by:

- `specs/PROTOCOL.md`
- `packages/core/src/safe-text.ts`

Host wire validation is implemented in:

- `packages/core/src/protocol.ts`

Firmware owns state storage, state transitions, state gates, physical approval,
policy evaluation, and signing decisions.

The host process may cache and display Firmware-reported state. The host process must not treat a
state as signing readiness and must not decide whether signing is safe.

## Product State Diagram

This diagram shows the shared product-state flow, not UI state and not a full
target composition diagram. Firmware targets use this top-level flow and shared
state vocabulary at the protocol boundary. A target may compose the shared
state flow with target-specific UI, input, power behavior, storage adapters,
identity adapters, and signing-material adapters before it projects into the
shared states, but it must not redefine target-independent product state or
transition order for the same shared operation.
The host process, MCP clients, and Admin Page requests may submit requests, but
they are not authority. Firmware state transitions occur only as consequences
of Firmware-owned conditions and validated local input.

```mermaid
stateDiagram-v2
    [*] --> Unprovisioned: boot, no root signing material
    Unprovisioned --> Provisioning: local setup or import starts
    Provisioning --> Unprovisioned: local cancel, timeout, failure + scratch wipe
    Provisioning --> Locked: backup confirm or import verify + PIN repeat + encrypted root/keyslot/policy stored
    Locked --> Provisioned: local PIN unlock authenticates keyslot and mandatory records
    Locked --> Locked: wrong PIN or failed unlock
    Provisioned --> Locked: reboot or explicit target relock
    Locked --> Unprovisioned: device reset + destructive confirmation + keystore erased
    Provisioned --> Unprovisioned: device reset + destructive confirmation + signing material erased
    Provisioned --> PolicyUpdatePending: valid policy update proposal + local approval requested
    Provisioned --> Provisioned: invalid policy proposal rejected before pending approval
    PolicyUpdatePending --> Provisioned: approve + commit succeeds, reject, timeout, cancel, ui_error, or pre-commit storage_error
    PolicyUpdatePending --> Error: ambiguous policy commit state

    Unprovisioned: get_status, identify_device
    Unprovisioned: device-local setup bubble and backup phrase controls
    Unprovisioned: target-owned material-install bootstrap when a target has local setup but missing target-owned material
    Provisioning: get_status
    Provisioning: device-local cancel
    Locked: get_status, identify_device, local unlock, destructive device reset
    Provisioned: get_status, identify_device, connect, disconnect
    Provisioned: get_capabilities, get_accounts, policy_get, get_approval_history (read-only, session-scoped)
    Provisioned: Sign API runtime; Firmware-local signing mode selects supported signing gate
```

Current StackChan CoreS3 encrypted root-material flow starts from
`unprovisioned`. It generates backup phrase scratch in RAM, displays only
up-to-4-letter BIP-39 word prefixes on the device in a 3-column by 4-row grid,
stores the binary BIP-39 root entropy only in an authenticated encrypted record,
creates a PIN-wrapped random master-key slot, and stores an active policy record
only after physical backup confirmation and local 6-digit PIN setup. It wipes
scratch on confirmation, cancellation, timeout, failure, or display expiry.
Three-letter BIP-39 words are displayed as the full word. `provisioned` may be
reported only when the persisted state, structurally valid encrypted root and
keyslot, stored active policy, stored signing authorization mode, and account
settings all exist. The encrypted keyslot is the sole PIN verifier. A rebooted
provisioned target projects device state `locked` until local unlock
authenticates the keyslot and mandatory encrypted records.

Firmware recognizes only the current tracked persistent material layout as
product state. The current StackChan CoreS3 persisted provisioning-state schema
accepts only `unprovisioned` and `provisioned`; transient or unsupported
persisted values such as `provisioning` are not normalized into product state.
If Firmware boots with an unsupported `prov_state`, or with
`prov_state = provisioned` but no valid active policy record, signing
authorization mode, Sui account settings, encrypted root, or keyslot, the device
enters persistent material consistency error until device-local settings repair,
Device reset, or a development flash-erase workflow resolves the unsupported
material set according to the remaining authority-gate material. After Device
reset or development flash erase, local setup or import can
reprovision the device.

If persisted state disagrees with the encrypted root, keyslot, stored active
policy, signing authorization mode, or Sui account settings
while `provisioned`,
Firmware reports device `error` and fails closed for normal setup and session
requests. Detecting the consistency error also clears any active RAM session
immediately, so a session created before the error is not retained as a stale
local capability. On the current StackChan CoreS3 target, `get_status` performs
this consistency refresh before reporting status. It is read-like because it
does not accept host-supplied state changes, but it can fail closed by exposing
material inconsistency and clearing stale session state. The current StackChan
CoreS3 source does not expose a USB
reset or debug recovery request. Its local settings paths are device-local UX
only: provisioned devices can enter local settings, verify the stored local PIN
against the current keyslot to rewrap the unchanged master key, or choose Device
reset. Device reset is the normal destructive local action; it erases the
keyslot, encrypted root and private transport identity, active policy, signing authorization mode,
Sui account settings, Sui zkLogin proof material, approval history,
policy-update terminal marker, human approval input mode setting, runtime
session, and provisioning state before returning to `unprovisioned`. Firmware
records an internal storage-action marker before internal settings repair or
Device reset commits so an interrupted action can resume at boot. Device-local
recovery from the `error` state uses settings repair when the keyslot and
encrypted root remain structurally valid. That repair requires successful local
unlock, preserves the keyslot and encrypted root, and restores recoverable
mutable settings, including zkLogin proof state, to current defaults. When the
authority gate is unavailable, recovery uses Device reset. Device reset
recovery has no PIN requirement because the keyslot or encrypted root may be
unreadable, but it still requires on-device confirmation and is
not exposed as a USB, host process, MCP, or host-triggered API.

## State Layers And Owners

Agent-Q separates protocol-visible product state from target-local composition
details. Protocol-visible state names and shared product invariants are common
for targets that implement the corresponding capability. A target's UI, input,
power, storage adapter, identity adapter, and signing-material adapter may
differ by hardware or product variant, and those target-local details must be
documented in each target's `SPEC.md`. Hardware-independent product state,
transition order, error precedence, and scratch-wipe rules for a shared
operation must use common state capability modules once the shared contract is
proven.

| Layer | Examples | Owner | May gate protocol APIs? |
|---|---|---|---:|
| Persistent device state | provisioning state, encrypted keyslot and protected records, policy, signing authorization mode, approval history, policy-update terminal marker, Sui zkLogin proof record, active Sui identity, account availability | Firmware | Yes |
| Volatile sensitive scratch | generated backup phrase, setup entropy, pending backup confirmation, typed PIN digits, signable payload transfer bytes, finalized payload descriptors | Firmware | Yes |
| Local PIN authorization state | connect/settings/policy-update/storage-maintenance PIN entry purpose, verification stage, Firmware-owned input deadline, RAM-only lockout | Firmware | Yes |
| Pending approval state | active Firmware-owned device-local approval request, such as physical Confirm or local PIN approval; Firmware-owned deadline; requested action | Firmware | Yes |
| Pending policy update state | validated policy proposal summary, policy hash, review/PIN/commit stage, review deadline | Firmware | Yes |
| Pending Sui zkLogin proposal state | validated bounded proof proposal summary, proof hash, review/PIN/commit stage, review deadline | Firmware | Yes |
| Runtime session state | active protocol session id and link-bound cleanup state | Firmware; host process mirrors its own client session state in RAM and clears that mirror when Firmware rejects it or live USB scan no longer observes the device | Yes |
| Physical transport availability | USB data-link state and local encrypted-carrier state; the common policy gives an observed USB host link priority and closes the local carrier without route migration | Firmware common transport policy; target adapters provide link observation and UI | Yes |
| Target-local display state | screen on/off, brightness, screensaver replacement | Firmware target display module | No |
| Target-local posture state | servo position, haptics, LEDs, temporary expression feedback | Firmware target UI/motion module | No |
| UI object lifetime | speech bubble, modal, setup panel, decorator id | Firmware target UI module | No |

UI objects, display power, avatar expressions, servo movement, LEDs, and sounds
may represent or notify about product state. They must not be the source of
truth for provisioning, sessions, accounts, policy, signing, sensitive scratch,
or pending approval.

An ESP32-S3 USB Serial/JTAG link is connected only while host USB SOF packets
are observed. A power-only cable is not a data link. While that USB data link is
connected, Firmware does not admit the lower-priority QR/BLE carrier. If USB
appears while BLE is advertising, handshaking, or established, Firmware closes
BLE and applies the existing local-transport loss cleanup. It never moves a BLE
session, pending request, or response route to USB, and USB removal never starts
BLE automatically.

## Product States

### `unprovisioned`

No root signing material is stored.

For targets whose implemented account/signing capability does not use root
signing material, this projection means the target-owned material required for
that capability is not yet available. A limited material-install bootstrap
under `unprovisioned` is valid only after target-local setup is complete and
only for installing the target-owned material required by implemented
capabilities. That bootstrap uses shared protocol methods, shared schemas, and
shared errors. It does not expose signing readiness or account readiness until
the target-owned material exists.

Allowed:

- `get_status`
- `identify_device`
- device-local setup speech bubble, Generate/Import choice, backup phrase
  Cancel/Confirm controls, and mnemonic import word-entry controls

Rejected unless the material-install bootstrap below applies:

- `connect` in the current StackChan root-material flow until persistent root
  material is encrypted, a valid keyslot, active policy, and signing
  authorization mode exist, and the device is unlocked and `provisioned`
- `get_capabilities`
- `get_accounts`
- `policy_get`
- `get_approval_history`
- `sign_transaction`
- `sign_personal_message`
- unsupported USB provisioning/reset/diagnostic/debug requests
- policy read/write
- signing
- external evidence or price fetch

Material-install bootstrap:

- A target with completed local setup but missing target-owned account/signing
  material admits a limited `connect`, `disconnect`, `get_capabilities`,
  `get_accounts`, `credential_prepare`, `credential_propose`, and
  `payload_transfer` path only for installing that missing material. The path
  remains Firmware-owned and approval-gated. It does not allow policy
  read/write, approval history, transaction signing, personal-message signing,
  or any target-specific public schema.

Current mnemonic setup and mnemonic import are volatile substates under
`unprovisioned` until the user physically confirms backup or completes local
word entry, enters and repeats a 6-digit local PIN, and Firmware stores root
material in an encrypted record, creates the PIN-wrapped keyslot, and stores the
active policy. The host never receives the
phrase, its up-to-4-letter prefixes, entered imported words, or the PIN.

### `provisioning`

Local setup is active.

Allowed:

- `get_status`
- `identify_device` only when it does not disrupt setup UI
- device-local cancel

Rejected:

- `get_capabilities`
- `get_accounts`
- `policy_get`
- `get_approval_history`
- `sign_transaction`
- `sign_personal_message`
- policy read/write
- signing
- external evidence or price fetch

Scratch signing material may exist only inside Firmware during setup steps.
Canceling setup must wipe scratch material first. From `backup_phrase_displayed`/
`import_word_entry`, Cancel wipes scratch and returns to `setup_choice` (re-pick; setup
stays active); the `setup_choice` Cancel wipes scratch and returns to `unprovisioned`.
Current StackChan CoreS3 source limits backup phrase and typed PIN scratch to
RAM and tracks setup with volatile substates: `none`,
`setup_choice`, `backup_phrase_displayed`, `import_word_entry`,
`pin_first_entry`, `pin_repeat_entry`, and `pin_committing`. Those scratch
substates are separate from persistent
`provisioning.state`, pending approval state, and UI panel state.
The current StackChan CoreS3 persistent material implementation does not persist
`provisioning` for the normal generate-and-confirm flow and does not accept it
as a current tracked storage value. If an unsupported persisted
provisioning-state value is present, Firmware fails closed with persistent
material consistency error rather than silently resetting it to
`unprovisioned`.

### `provisioned`

Root signing material and a committed active policy exist in device-local
storage. In the current StackChan CoreS3 DEV_PROFILE implementation this means
the binary BIP-39 entropy is stored in an authenticated encrypted record and a
random master key is stored in a PIN-wrapped keyslot. Canonical active policy, device-local signing
authorization mode, Sui account settings, and zkLogin proof state are stored in
mutable settings storage, and `prov_state` is `provisioned`;
the normal product flow installs the default-reject policy and initializes Sui
account settings to reject gas sponsors, while read-only Sui account derivation,
read-only active policy document readback, internal settings repair, Device
reset, and the Firmware-owned
`policy_propose` proposal flow for current-schema policies is implemented. Sui
`sign_transaction` policy mode evaluates the active current policy after active
policy availability, request network, account-binding, and complete offline
condition-facts gates. It signs only when a matching `sign` policy authorizes
the request.
USER_PROFILE secure storage gates are still separate work.

Allowed:

- `get_status`
- `identify_device`
- `connect`
- `disconnect`
- `get_capabilities` (read-only, session-scoped)
- `get_accounts` (read-only, session-scoped)
- `policy_get` (read-only, session-scoped)
- `get_approval_history` (read-only, session-scoped)
- `credential_prepare` (session-scoped; Sui zkLogin only; read-like
  preparation material; available only while native Sui identity is active)
- `credential_propose` (session-scoped; Sui zkLogin only; bounded proof proposal
  that requires device-local review and local PIN before persistence)
- `payload_transfer` with `begin`, `chunk`, `finish`, and `abort` actions for
  same-session volatile signable payload delivery
- `sign_transaction` (session-scoped; unknown methods reject; Sui
  `sign_transaction` accepts inline `txBytes` or a same-session finalized
  `payloadRef`, validates the decoded transaction through the Sui adapter, and
  returns the selected gate's bounded `signing outcome` terminal status:
  policy mode can return `signed`, `policy_rejected`, or `signing_failed`;
  user mode can return `signed`, `user_rejected`, `user_timed_out`, or
  `signing_failed`)
- `sign_personal_message` (session-scoped; user authorization mode only;
  bounded Sui personal-message bytes return `signed`, `user_rejected`,
  `user_timed_out`, or `signing_failed`; policy mode fails closed with
  `unsupported_method`)
- device-local Device reset after destructive confirmation; successful reset
  erases the keyslot and encrypted private-material records, recoverable mutable settings
  including Sui zkLogin proof material, approval history, and the policy-update
  terminal marker, and returns to `unprovisioned`
- device-local settings repair from persistent material consistency `error`;
  successful repair preserves the keyslot and encrypted root, restores
  recoverable mutable settings to current defaults, clears Sui zkLogin proof
  material, approval history, and the policy-update terminal marker, and remains
  `provisioned`
- device-local Settings action for the human approval input mode used by
  external-request human approval branches; changing it requires stored PIN
  verification
- device-local Settings action for resetting active policy to the current
  default reject policy; changing it requires stored PIN verification and is
  not exposed as a protocol, host, Admin, or MCP reset request
- device-local chain account menu with a current Sui account view for active
  identity/proof metadata and local zkLogin proof clear; clearing requires
  stored PIN verification, wipes only the Sui zkLogin proof record, ends the
  active session, restores the Sui account view from current device state, and
  is not exposed as a protocol, host, Admin, or MCP proof-clear request
- policy update through the Firmware-owned `policy_propose` proposal
  flow, which requires an active session, Firmware validation, and device-local
  approval; the pending approval remains tied to the same session and cannot
  commit after that session ends, disconnects, or no longer matches

This state is not signing approval. In the current StackChan CoreS3
implementation, `provisioned` enables `connect`, `disconnect`, read-only
`get_capabilities` for one active Sui account identity with no delegated public
methods and top-level `signing`, optional Sui zkLogin credential-preparation
availability while native identity is active, read-only `get_accounts`
(native Sui Ed25519 account 0 or active Sui zkLogin identity),
read-only `policy_get` for the committed active policy document, read-only
`get_approval_history` for Firmware-owned persistent decision metadata, and the
session-scoped Sign API runtime. `sign_transaction` has
`source-wired-not-product-active` status for inline or same-session staged Sui
transaction bytes decoded by the Firmware Sui `TransactionData::V1 ->
ProgrammableTransaction` facts extractor. Policy authorization currently
returns `policy_rejected` for missing, incomplete, unmatched, or reject-matched
policy coverage, and signs only when a matching current `sign` policy authorizes
the request. User authorization enters device review only when
the parsed shape has either complete offline facts review coverage or an
explicit blind-signing warning for a valid, account-bound transaction whose
offline facts review coverage is incomplete.
The parsed Sui transaction sender must match the active account. The parsed gas
owner must also match unless the active account's Sui account setting accepts gas
sponsors; missing, unreadable, invalid, or false settings reject a gas owner
mismatch before user or policy authorization. When a sender-bound sponsored
transaction is accepted, Agent-Q still returns only the active sender signature.
Product-active status is not claimed unless
`docs/IMPLEMENTATION_STATUS.md` says the matching source, docs, tests, build,
hardware, and visual evidence are complete.
`sign_personal_message` also has `source-wired-not-product-active` status for
bounded Sui personal-message bytes in user authorization mode only; policy mode
fails closed because policy facts and rules for personal-message signing are not
implemented.
Sui zkLogin credential setup has `source-wired-not-product-active` status for
the current StackChan CoreS3 source. Firmware stores at most one Sui active
identity: native Ed25519 when no zkLogin proof record is active, or zkLogin when
a locally stored proof record is active. `get_accounts` and
`get_capabilities.chains[].accounts` project only that active identity.
On StackChan CoreS3, `credential_prepare` returns native scheme-prefixed
Ed25519 public material for an external zkLogin nonce/JWT/prover flow, but only
while native identity is active. The same shared credential methods also cover a
limited material-install bootstrap when a target's local setup is complete and
its target-owned credential material is missing.
`credential_propose` accepts bounded zkLogin proof material, shows a
device-local review, requires local authentication, and stores the proof only
after commit.
It does not store raw JWTs and does not claim local OAuth, prover, or Sui
validator verification. The stored proof record includes its Sui network; when
zkLogin is active, `sign_transaction` and `sign_personal_message` require the
request `network` to match that stored proof network before signing can proceed.
When zkLogin is active, preparation/proposal fail closed until the user clears
the proof locally through the Sui account view; clearing the proof ends the
active session and returns the next account projection to the native identity.
The host process must not evaluate policy. A corrupt, unreadable, missing,
or invalid current active policy is a persistent-material consistency
error, not a normal `provisioned` state. Provisioned DEV_PROFILE devices that
have an invalid keyslot or encrypted root fail closed because the authority gate
cannot be proven. Devices that retain a structurally valid keyslot and encrypted root but
lose mutable settings such as active canonical policy, signing authorization
mode, Sui account settings, or zkLogin proof state can enter root-preserving
settings repair instead of erasing root material.

#### Request Authority Paths

The Sign API is not a policy action, request-authority flag, blind-signing
selector, compatibility conversion, or host-selected authorization mode. Firmware
reads the device-local signing authorization mode and chooses the supported
Firmware-owned signing gate
for the requested method:

- policy mode validates active policy availability, request network scope,
  account binding, and complete offline policy condition facts, then signs only
  when the active current policy has a matching `sign` policy. It returns
  `policy_rejected` for missing, incomplete, unmatched, or reject-matched policy
  coverage, shows speech-bubble status notifications for rejection, and does not
  fall back to user confirmation. `sign_personal_message` is unsupported in
  policy mode and fails closed;
- user mode shows covered offline facts when offline facts review coverage is
  complete, or an explicit blind-signing warning when Firmware can validate and
  bind the transaction but offline facts review coverage is incomplete. Both
  paths require Firmware-owned human approval before signing `sign_transaction`.
  `sign_personal_message` remains a
  bounded clear-review user path.

Neither mode proves the upstream user, dapp, provider, host, or agent intent
that produced the request. The source state must be material-backed
`provisioned` with a matching active session. The target state after every
terminal outcome remains `provisioned`, unless the terminal outcome detects
persistent material inconsistency.

Before these state-scoped signing gates, the host process and Firmware may perform only
bounded, side-effect-free identification of the shared `(type, chain, method)`
route. Unsupported or malformed routes fail without reaching state/session,
replay, approval, policy, history, adapter, or signing work. For a supported
route, state/session checks occur before method-parameter validation and
chain-adapter decoding. After shallow method-parameter validation, Firmware
computes a form-discriminated internal signing-request identity from the selected
route and validated method parameters. For staged transaction signing, Firmware
first resolves the same-session internal `payloadRef` to method payload bytes;
the identity is derived from the resolved payload and selected route, not from
the live `payloadRef` handle alone. A same-id retry replays only when that
identity matches and the bounded RAM result entry is still retained; a different
request reusing the id fails with `request_id_conflict` before
adapter, approval, policy, history, or signing work only while the original
entry is still buffered. Stored signing responses are runtime recovery state, not
persistent replay protection. They are cleared by ack, session cleanup,
disconnect/session end, wipe, or reset, and the fixed-size store evicts the
oldest entry when full.

#### Human Approval Input Mode

`human approval input mode` is a device-local setting with current values
`pin` and `confirm`. It applies only when an external request enters a
Firmware-owned human-approval branch. It does not apply to policy authorization,
unsupported request methods, policy update proposals, settings changes, or
local destructive operations.

| Flow | Branch | `human approval input mode` applies | UI |
|---|---|---:|---|
| `connect` | human approval | yes | review -> PIN or review -> Confirm |
| `sign_transaction` in user authorization mode | human approval | yes | review -> PIN or review -> Confirm |
| `sign_transaction` in policy authorization mode | policy authorization | no | policy evaluation result |
| `sign_personal_message` in user authorization mode | human approval | yes | review -> PIN or review -> Confirm |
| `sign_personal_message` in policy authorization mode | unsupported | no | fail closed |
| `policy_propose` | sensitive write proposal | no | always review -> PIN |
| Settings changes | local sensitive operation | no | always PIN |
| Settings Device reset or Change PIN | local sensitive operation | no | always PIN |

Error-state Device reset is the recovery path when the keyslot or encrypted
root cannot authenticate local authority. It therefore cannot require that PIN,
but still requires on-device destructive confirmation and is not exposed as a
protocol operation.

This setting is not a signing authorization mode. Protocol requests and adapter
surfaces still cannot choose the signing authorization mode or the human
approval input mode.

Required owners for the device-confirmed signing pending state:

- persistent device state: Firmware-owned encrypted keyslot and protected
  signing material, active policy, signing authorization mode, and approval history;
- volatile sensitive scratch: Firmware-owned signable payload bytes, a request
  summary derived from the same signable payload bytes, the Firmware-derived
  sender and gas owner account binding, signature scratch, and any local PIN
  scratch;
- pending approval state: Firmware-owned request id, session id, chain, method,
  request digest, current internal review/PIN input deadline, and terminal
  stage. The signing review deadline can pause while the user scrolls the
  on-device review and resumes with the remaining time when scrolling ends or
  when the Firmware-owned abandoned-scroll fallback fires. The host cannot set
  or negotiate this deadline;
- UI/display state: target-local temporary review, approval, and result layers
  only. UI object lifetime must not decide whether signing is allowed.

Allowed while a device-confirmed signing request is pending:

- `get_status`;
- `disconnect` only as cleanup before a signing critical section, or `busy`
  during a defined critical section;
- read-only session APIs only if they cannot mutate, dismiss, overwrite, or
  leak the pending request.

Rejected while a device-confirmed signing request is pending:

- nested signing requests;
- policy update proposals;
- nested `sign_transaction` requests;
- nested `sign_personal_message` requests;
- host-triggered reset, debug, setup, recovery, PIN entry, or confirmation
  shortcuts.

Failure requirements for a device-confirmed signing request:

- reject, timeout, UI failure, invalid state, session loss, or disconnect before
  the signing critical section must wipe signable scratch and produce no
  signature;
- approval-history durability must complete before signing can occur. This is a
  pre-signing device-confirmation record, not a claim that a signature has
  already been generated. The owner must validate the active session before the
  required write and transition to the signing critical section in the same
  successful step; a session loss after that write succeeds cannot downgrade the
  request to pre-signing cleanup. Durable history writers must receive
  value-owned request metadata, and the owner must reject callback reentry that
  clears, restarts, or otherwise changes the pending request before critical
  entry;
- if signing, terminal history persistence, or response delivery fails after a
  durable confirmation record, terminal history and the user-visible result must
  distinguish signature generation, signed terminal proof, and host receipt;
- every terminal path must wipe signable payload and signature scratch.

#### Signable Payload Delivery Scratch

Signable payload delivery is a volatile Firmware-owned substate under
`provisioned` with an active matching session. It exists to carry large
signable bytes to Firmware before a supported signing request consumes them.
It is not a protocol state setter and does not authorize signing.

Store states and ownership phases:

- `idle`: no active upload or finalized payload exists.
- `receiving`: one same-session upload is receiving sequential chunks.
- `finalized`: one same-session immutable payload descriptor exists.
- `consuming`: not a payload-store enum value; a same-session signing request
  has taken ownership of the finalized bytes for adapter parsing,
  authorization, and signing.
- `cleanup`: not a payload-store enum value; Firmware is wiping or releasing
  volatile payload scratch under the owner that currently holds the bytes.

Allowed in `receiving`:

- same-session `payload_transfer` with action `chunk`;
- same-session `payload_transfer` with action `finish`;
- same-session `payload_transfer` with action `abort` and the active
  `transferId`;
- read-only session requests that do not mutate, dismiss, or leak upload state:
  `get_status`, `get_capabilities`, `get_accounts`, `policy_get`,
  `get_approval_history`, `get_result`, and `ack_result`.

Rejected in `receiving`:

- nested `payload_transfer` with action `begin`;
- `sign_transaction` using an incomplete upload;
- `sign_personal_message`;
- `policy_propose`;
- local settings sensitive subflows;
- different-session upload operations.

Allowed in `finalized`:

- same-session `sign_transaction` whose shallow payload source matches the
  finalized `payloadRef`; the payload store must validate the reference,
  session, and finalized state before Firmware consumes bytes;
- same-session `payload_transfer` with action `abort` and the finalized
  `payloadRef`;
- read-only session requests that do not mutate, dismiss, or leak the payload.

Rejected in `finalized`:

- chunk append or payload mutation;
- different-session `payloadRef` use;
- nested upload or signing work that would leave hidden finalized payload;
- policy proposal, connection approval, identification display, personal-message
  signing, or local settings sensitive flows unless Firmware first owns and
  completes an explicit cleanup transition for the finalized payload.

Cleanup requirements:

- upload abort, timeout, declared-size overflow, digest mismatch, session
  cleanup, disconnect/session end, material error, reset, and signing terminal
  cleanup must wipe or release the payload so it cannot later be confirmed or
  signed invisibly. Unrelated sensitive-flow attempts are rejected while payload
  scratch is pending unless Firmware explicitly owns a cleanup-before-replace
  transition;
- retained-response recovery for `(session, request id)` uses `get_result` and
  `ack_result` and must not depend on the finalized payload still existing.

Payload delivery request admission is owned by the Firmware operation admission
matrix, not by the display/device-state projection. The projection treats
receiving and finalized payload scratch as `busy` for ordinary USB requests.
A matching same-session staged signing request is a request-aware admission
exception that enters through the payload-aware operation path and still must
resolve the finalized payload before method validation. Unrelated sensitive
operations must be rejected unless Firmware first owns an explicit cleanup
transition.

The user-mode signing runtime models human approval for implemented
device-confirmed signing methods. Terminal stages for user-mode signing are:

- `reviewing`: parsed summary is displayed; no PIN or signing is active.
- `pin_entry`: local PIN input is active for this request.
- `history_write`: internal callback sub-stage entered only by the
  Firmware-owned PIN-verified transition. Device confirmation has completed;
  signing is still forbidden until the required pre-signing confirmation record
  is durable. Public flow callers must not be able to leave a request parked in
  this stage without attempting the required history write.
- `signing_critical_section`: history is durable and signing may execute; only
  the owner may consume or wipe signing scratch. Session loss or disconnect in
  this stage is `busy`; it cannot downgrade the request to pre-signing cleanup,
  and normal cleanup functions must not force-clear this stage.
- terminal `signed`, `user_rejected`, `user_timed_out`, or `signing_failed`.
  Pre-signing `canceled` and `history_error` are cleanup outcomes that wipe
  scratch and produce no signature. A post-signing terminal-history failure
  produces no provider signature result and no signed terminal proof, but it
  must still be displayed distinctly from signing failure or USB response
  delivery failure.

For device-confirmed signing, review Reject is the terminal
`user_rejected` action. Back from the PIN screen is not a terminal reject: it
wipes only PIN scratch and returns to the offline facts review with the
signable request still owned by the signing state owner. If the user rejects
from that review, the request then records terminal `user_rejected`.

History records for this path use `eventKind: "signing"`. The
required pre-signing record uses `recordKind: "confirmation"` and
`confirmationKind: "local_pin"` when human approval input mode is `pin`, or
`confirmationKind: "physical_confirm"` when human approval input mode is
`confirm`, after device confirmation succeeds. Terminal records use
`recordKind: "terminal"` and record whether Firmware generated a signature,
rejected the request, timed out, or failed during signing. A `signed` terminal
record means Firmware generated a signature after device confirmation and
persisted the signed terminal result; it does not prove host process received that
signature. If signature generation succeeds but the signed terminal record
cannot be persisted, Firmware must not return a provider signature result.

#### Pending Policy Update

Policy update is a Firmware-owned pending substate under `provisioned`, not an
external state setter.

Transition:

```text
provisioned
-> valid session-scoped policy proposal
-> Firmware validates bounded policy document
-> pending policy update summary review on device
-> local PIN approval after device-local Continue
-> canonical policy commit
-> required policy-update history record
-> provisioned with new active policy
```

Failure behavior:

- invalid policy returns `invalid_policy` before pending approval starts, with
  the previous active policy unchanged;
- user rejection, timeout, cancellation, or approval UI failure returns to
  `provisioned` with the previous active policy unchanged;
- review Reject is the terminal rejected action; PIN Back wipes only PIN scratch
  and returns to policy update summary review;
- required-history failure before the active-slot flip returns a top-level
  `history_error`, clears the pending proposal, and leaves the previous active
  policy unchanged;
- storage failure before the active-slot flip returns to `provisioned` with the
  previous active policy unchanged;
- required-history failure after the active-slot flip, or ambiguous storage
  state after interruption including a leftover policy-update terminal marker,
  reports `error` instead of a normal `provisioned` state;
- a second policy update proposal while pending is rejected with `busy`.

Allowed while pending:

- `get_status`;
- read-only session APIs only if they do not dismiss, overwrite, or mutate the
  pending proposal;
- `policy_get`, if allowed, reports only the committed active policy and not the
  pending proposal;
- `disconnect` as session cleanup except during the commit critical section,
  where Firmware may return `busy`.

Rejected while pending:

- nested policy updates;
- `sign_transaction` and `sign_personal_message`, because request evaluation
  must not race an uncommitted active policy replacement or sensitive pending
  write;
- host-triggered reset, debug, import, or state-changing shortcuts.

The pending state may be displayed by UI, but UI object lifetime is not the
source of truth. Firmware owns the proposal summary, commit stage, cleanup, and
rollback behavior. PIN entry deadlines are internal Firmware values, not
host-supplied request fields.

Firmware must accept only policy actions that the current schema allows and the
current runtime can enforce. Other action values are invalid input and are not
stored as dormant behavior.

### `error`

Firmware detected a persistent-material consistency error. This is a fail-closed
runtime report, not a persisted provisioning state. It is used when the stored
provisioning flag and the required material records disagree, or when material
becomes unreadable after a session had existed.

Allowed:

- `get_status`
- `identify_device`
- `disconnect` only as session lifecycle cleanup; if the session was already
  cleared, Firmware returns `invalid_session`
- device-local erase-only recovery after destructive on-device confirmation;
  this wipes the keyslot, encrypted private-material records, active policy, signing authorization
  mode, Sui zkLogin proof material, human approval input mode setting, approval
  history, policy-update terminal marker, runtime session, and provisioning
  state before returning to `unprovisioned`

Rejected:

- `connect`
- `get_capabilities`
- `get_accounts`
- `policy_get`
- `get_approval_history`
- `sign_transaction`
- `sign_personal_message`
- policy update
- signing

This recovery is destructive and cannot read, export, repair, or unlock private
material. It exists only to return a fail-closed device to the
normal local setup path when the stored material set is inconsistent. USB,
host process, and MCP clients still cannot trigger reset or recovery.

### `locked`

Sensitive actions require local unlock.

Allowed:

- `get_status`
- `identify_device`
- unlock flow
- device-local Device reset after destructive confirmation

Rejected until unlocked:

- `get_accounts`
- `policy_get`
- `sign_transaction`
- policy read
- policy update
- signing

Targets use this projection only after they implement a target-local unlock
model. While locked, status and identification remain available when the target
allows those read-like operations, but connect, account, policy, credential,
private local-transport, and signing methods fail closed until the target-local
unlock gate succeeds. Unlock authenticates storage authority; it does not count
as connect approval or signing authorization.

## API / State Matrix

| Function | `unprovisioned` | `provisioning` | `provisioned` | `error` | `locked` | Owner |
|---|---:|---:|---:|---:|---:|---|
| `get_status` | O | O | O | O | O | Firmware |
| `identify_device` | O | O* | O | O | O | Firmware |
| `connect` | B | X | O | X | X | Firmware |
| `disconnect` | S | S | S | S | S | Firmware |
| Unsupported USB provisioning/reset/diagnostic/debug requests | X | X | X | X | X | Firmware |
| `get_capabilities` | B | X | O | X | X | Firmware |
| `get_accounts` | B | X | O | X | X | Firmware |
| `policy_get` | X | X | O | X | X | Firmware |
| `get_approval_history` | X | X | O | X | X | Firmware |
| `get_result` | X | X | O | X | X | Firmware |
| `ack_result` | X | X | O | X | X | Firmware |
| `credential_prepare` | B | X | O (source-wired-not-product-active; StackChan native Sui identity only) | X | X | Firmware |
| `credential_propose` | B | X | O (source-wired-not-product-active; StackChan native Sui identity only; review + local authentication before persistence) | X | X | Firmware |
| `payload_transfer` actions | B | X | O | X | X | Firmware |
| `sign_transaction` | X | X | O (source-wired-not-product-active) | X | X | Firmware |
| `sign_personal_message` | X | X | O (source-wired-not-product-active; user authorization mode only) | X | X | Firmware |
| policy read | X | X | O | X | X | Firmware |
| policy update | X | X | O (validated proposal + device-local approval) | X | X | Firmware |

`get_status` is read-like, not a pure cache read: the current target refreshes
persistent-material consistency before emitting status, and a detected
inconsistency can fail closed into `error` and clear stale runtime session state.

`B` means target-owned material-install bootstrap only. The target must have
completed its local setup but still lack the target-owned material required for
its implemented account/signing capabilities. Bootstrap access is limited to
installing that material through shared methods and shared schemas; it must not
grant account readiness, signing readiness, policy access, approval-history
access, or alternate protocol behavior.

The `connect` row first recovers an already approved live Firmware session on
the current USB physical link. That recovery returns the existing session id
and does not start a new approval, create a replacement session, clear
session-bound scratch, or grant authority beyond the already approved session.
If no live session exists, `connect` admits a new Firmware session only when the
target's current session policy allows one. Firmware returns `invalid_state`
when its current session policy refuses both session recovery and new admission.

`O*`: allowed only when the request does not disrupt local setup UI. `S` means
session cleanup only: Firmware does not require material readiness, but a
missing or mismatched session returns `invalid_session`. `S` operations may
still return `busy` while local setup/PIN/reset or sensitive settings subflow
state is active, because external session teardown must not interleave with
device-local sensitive UI. Idle Settings menu is not itself a sensitive flow and
does not end the active RAM session. Other `O` operations may still return
`busy` while a physical approval prompt or device-only setup material display is
active. The current StackChan `get_status` path is not part of that busy-return
class for physical prompts or payload delivery; it remains a safe status read
except for its material-consistency fail-closed path.

The host process may hide unavailable operations, but Firmware must still reject them.

The current StackChan CoreS3 target has an explicit `local_pin_auth` runtime
substate for local PIN authorization. It records `purpose` (`unlock`, `connect`,
human-approval input, signing-mode, policy-reset, PIN-change, Sui gas-sponsor,
Sui zkLogin-clear settings, `policy_update`, `sui_zklogin_proposal`, or the
internal device-confirmed signing verifier purpose), `stage`
(`pin_entry`, `pin_verifying`, `new_pin_entry`, `repeat_pin_entry`,
`committing_setting`, or `committing_pin_change`), typed PIN scratch, new-PIN
scratch where applicable, input deadline, and the RAM-only stored-PIN attempt
budget shared with storage-maintenance PIN authentication. Submitting a complete PIN pauses
the input deadline while encrypted-keyslot authentication runs. A wrong PIN result
returns to the same PIN-entry state by resuming the remaining paused input
window, unless the shared lockout is active. While that lockout is active, PIN
input, delete, and submit stay unavailable until lockout release. On the
current StackChan target, this lockout is the RAM-only PIN attempt budget for
the local PIN flow; it is not projected as the protocol-visible `locked` device
state. Protocol-backed connect, policy-update, and device-confirmed signing PIN
flows keep their request-backed PIN input window paused while lockout is active.
After lockout release, the owner resumes the remaining PIN input window when
the request/session state is still valid; otherwise the owner closes through its
normal timeout, session, or cleanup path. The input pause does not pause the
state owner's PIN-authentication processing deadline; a stalled or lost worker
result fails closed as local authentication unavailable.
Protocol-backed PIN purposes (`connect`, `policy_update`, and device-confirmed
signing) also have an immutable outer request window owned by their protocol
state owner. That request window is the admission boundary for review/PIN entry
and caps PIN input windows before the PIN is submitted. A request-backed
sensitive flow owner stores a timeout window only when it is structurally valid
and currently open at the owner-observed tick; callers may create candidate
windows, but caller freshness is not the state authority. After a complete PIN
has been submitted, the request window is not the terminal timeout authority
for encrypted-keyslot processing; the state owner's PIN-authentication
processing deadline, session/material checks, and the next state guards
remain authoritative. For policy updates,
`local_pin_auth` owns
only PIN verification; the pending proposal summary, policy hash, commit stage,
and terminal result remain owned by the policy-update flow. For
device-confirmed signing, `local_pin_auth` is only a verifier input; the
request identity, signable payload scratch, history-write transition, and
terminal cleanup remain owned by the user-signing state owner and confirmation
coordinator. Signing PIN Back returns to the offline facts review instead of
writing a terminal rejection; only review Reject is recorded as
`user_rejected`. The internal signing PIN purpose is not a protocol
request, signing API, or capability advertisement. The UI panel may display
that state, but panel existence is not the source of truth. The target must not
expose a USB, host process, and MCP PIN submit request.

## Boot Flows

Initial setup:

```text
Boot
-> load provisioning state
-> no root signing material
-> unprovisioned
-> welcome with touchable setup speech bubble
-> setup speech bubble touch
-> generate mnemonic on device
-> show up-to-4-letter prefixes once on device
-> user confirms backup or cancels on device
-> if confirmed, enter and repeat a 6-digit local PIN on device
-> if PINs match, create the keyslot and encrypted root, then store active policy and signing authorization mode locally
-> only after storage succeeds, provisioned and unlocked for the current boot
-> wipe volatile scratch
-> ready
```

Reboot after provisioning:

```text
Boot
-> load provisioning state
-> verify encrypted root/keyslot shape, active policy, and signing authorization mode exist
-> locked
-> local PIN unlock authenticates keyslot and mandatory encrypted records
-> provisioned and unlocked
-> welcome
-> ready
```

If stored state and signing material disagree, Firmware must fail closed rather
than pretending signing is ready.

## UI State

UI state is not product state. UI only represents product state or a temporary
request.

Common UI states:

- welcome
- idle avatar
- backup phrase display
- notification
- decision prompt
- result notification
- error notification

Rules:

- Normal requests should not force a dedicated Agent-Q mode.
- Temporary UI should close and return control to the previous device mode when
  possible.
- Read-only requests must not open physical approval UI.

## Target-Local Display Power State

Display power state is not product state and must not gate protocol APIs,
provisioning, sessions, accounts, policy, or signing. It only controls whether
the local screen, backlight, or equivalent display surface is active.

Display power states:

- `screen_active`: backlight is on.
- `screen_off`: backlight is off; Firmware and protocol state continue running.

`screen_off` must not clear provisioning scratch, pending approvals, sessions,
or root material. Those states are owned by their explicit Firmware modules.
Agent-Q request UI should wake the screen before showing setup material,
notifications, or physical approval prompts when the target has a screen.

Hardware-specific timing, buttons, and power-off behavior are target-local. The
current StackChan CoreS3 behavior is documented in
`firmware/src/stackchan-cores3/SPEC.md`.

## Target-Local Posture State

Physical posture is not product state and must not gate protocol APIs,
provisioning, sessions, accounts, policy, or signing. It only controls the
target's optional motion, LED, haptic, sound, or expression feedback.

Posture changes must not clear provisioning scratch, pending approvals,
sessions, root material, or display power state. Hardware targets may move to a
target-local rest posture before screen-off or power-off and return to an awake
posture when the display wakes, but those postures are feedback only and must
not gate protocol behavior.
Hardware-specific posture ownership, boot feedback, sleep feedback, and wake
feedback are target-local. The current StackChan CoreS3 behavior is documented in
`firmware/src/stackchan-cores3/SPEC.md`.

## Request Patterns

```mermaid
flowchart TD
    Request["Request arrives"] --> StateGate["Firmware validates state gate"]
    StateGate -->|read-only allowed| Silent["Handle without approval UI"]
    StateGate -->|write action allowed| Decision["Show physical decision UI"]
    StateGate -->|not allowed| Reject["Return error without state change"]

    Silent --> Notify["Optional notification"]
    Notify --> ReturnUi["Return to previous UI"]

    Decision --> Confirm["User confirms"]
    Decision --> Deny["User rejects"]
    Decision --> Timeout["Approval times out"]

    Confirm --> Apply["Apply state/action"]
    Apply --> Result["Show result notification"]
    Deny --> NoChange["Preserve previous state"]
    Timeout --> NoChange
    NoChange --> Result
    Result --> ReturnUi
```

Silent internal handling:

```text
request
-> validate state gate
-> handle internally
-> optional notification
-> return to previous UI
```

User decision:

```text
request
-> validate state gate
-> show decision UI
-> confirm / reject / timeout
-> apply state or action only after confirm
-> show result
-> return to previous UI
```

While a decision is pending:

- UI-affecting write requests return `busy`.
- `get_status` remains allowed.
- state is not changed on reject or timeout.
