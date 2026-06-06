# Agent-Q Communication Protocol

This document defines the communication contract between Agent-Q Gateway and
Agent-Q Firmware.

The protocol is intentionally small. It is inspired by wallet capability
discovery patterns, but it does not copy a full wallet standard.

## Scope

The protocol only needs enough structure for Gateway and Firmware to agree on:

- device discovery and selection
- connection approval
- Firmware status
- provisioning setup-step boundary checks
- supported chains and methods
- addresses and public keys
- signing requests and signing results
- read-only Firmware decision history

Chain-specific requests must fit into the supported method list instead of
creating separate product-level protocols.

## Roles

Agent-Q Gateway:

- exposes MCP tools
- sends protocol messages to Firmware
- relays Firmware responses
- does not store keys
- does not make signing or policy decisions

Agent-Q Firmware:

- stores keys and policies
- evaluates requests
- requests device-local approval when required
- signs, rejects, or times out only request types implemented by the current
  target/runtime state

The local Admin Page served by Gateway exists for read-only device metadata and
the current policy proposal template. Firmware-owned admin methods exist
only where this protocol and a target implementation say so; Gateway/Admin
clients submit requests, but Firmware remains the authority for validation,
device-local approval, persistence, and failure state.

## Request Authority Model

Protocol requests are not authority. Gateway, MCP, Admin Page, provider, dapp,
and CLI callers can submit bounded input only. Firmware owns the state gates,
policy evaluation, device-local approval, signing execution, persistence, and
failure cleanup.

`sign_transaction` is the current transaction-signing protocol request.
Authorization is not selected by the request, Gateway, MCP, provider, Admin
Page, dapp, or CLI caller. Firmware reads its device-local signing
authorization mode and chooses one Firmware-owned signing gate:

- `authorization: "policy"` means Firmware evaluates the active policy for an
  implemented bounded signing request. Policy authorization is sufficient for
  signing, this path does not require device-local confirmation for each
  signing request, and policy rejection must not fall back to asking the user.
- `authorization: "user"` means Firmware uses device-local clear-signing review
  and local PIN confirmation for an implemented bounded signing request. User
  rejection or timeout is terminal and must not fall back to policy-only
  signing.

Both modes return a Firmware-authored `sign_result` that records the
authorization actually used. Adapter package surfaces may choose different UX
around the same protocol method, but adapter projection is not a security
boundary against direct imports of broader client/Admin package entrypoints.
Firmware remains responsible for enforcing the request type, local
authorization mode, selected signing gate, signing, persistence, and cleanup.

Policy documents may use only actions accepted by the current schema and
enforceable by the current runtime. Any other action value is invalid input and
is rejected during validation. Firmware must not add named compatibility
branches, reserved paths, migrations, or hidden conversion into another request
type for action values outside the current schema.

## Message Envelope

All request and response messages use JSON Lines. Each JSON value is one
complete message followed by `\n`.

Firmware rejects JSONL frames that contain a raw NUL byte or exceed the target
line buffer, and discards the rest of that frame until the next newline. JSON
escape sequences such as `\u0000` are parsed as JSON strings and then rejected
by string validators when the field requires a C-string-safe protocol value.

All request messages must include:

- `id`: request correlation id
- `version`: wire protocol version
- `type`: message type

Request ids must be 1-79 characters and use only ASCII letters, digits, `_`,
`-`, and `.`.

The current protocol version is `1`.

Example:

```json
{
  "id": "req_001",
  "version": 1,
  "type": "get_status"
}
```

Firmware rejects unsupported protocol versions with `unsupported_version`.

## Error Responses

Protocol errors use a stable error object.

Example:

```json
{
  "id": "req_001",
  "version": 1,
  "type": "error",
  "error": {
    "code": "unsupported_type",
    "message": "Unsupported request type."
  }
}
```

Protocol error codes:

- `invalid_json`
- `invalid_id`
- `invalid_code`
- `invalid_gateway_name`
- `invalid_session`
- `invalid_state`
- `invalid_method`
- `invalid_params`
- `protocol_error`
- `unsupported_version`
- `unsupported_type`
- `unsupported_method`
- `unsupported_transaction`
- `busy`
- `rejected`
- `timeout`
- `policy_error`
- `history_error`
- `auth_unavailable`
- `ui_error`
- `rng_error`
- `account_error`

Transport-layer errors are owned by Gateway and are not Firmware protocol
errors.

## Session Flow

Protocol interaction has a clear discovery step, session start, and session end.
The active-session baseline is:

```text
get_status
  -> identify_device?
  -> connect
    -> get_capabilities
    -> get_accounts
    -> policy_get
    -> get_approval_history
    -> sign_transaction*
    -> sign_personal_message*
  -> disconnect
```

`sign_transaction` uses the same wire shape regardless of the active
authorization mode. Product-active status depends on target implementation
status and current-tree hardware evidence; do not infer that status from this
protocol shape alone.

Flow rules:

- `get_status` can be called before a session exists.
- `get_status` is the transport handshake used to identify Firmware candidates.
- If multiple Firmware devices are connected, Gateway must not silently choose
  one. Gateway should request Firmware devices to display short identification
  codes, then use the user's selection to choose one active device.
- Gateway may store the selected `deviceId` and transport hint locally.
- A stored transport hint is not identity. Gateway must confirm identity with
  Firmware before treating a device as live.
- `connect` establishes a session when Gateway does not already hold a valid
  runtime session for the device. A fresh Firmware `connect` request requires
  Firmware-owned device-local approval. Hardware targets may implement that
  approval as a physical confirm or as local PIN verification, but PIN entry
  must never be a USB protocol request.
- `get_capabilities`, `get_accounts`, `policy_get`, `get_approval_history`,
  `sign_transaction`, `sign_personal_message`, and `policy_propose` require
  `sessionId`.
- `disconnect` ends the session.
- Firmware should reject session-scoped requests with an unknown or inactive
  `sessionId`.
- When Gateway has an active runtime session and a session teardown or fresh
  connect attempt ends with `invalid_session`, `timeout`, `port_not_found`,
  `port_in_use`, or `transport_closed`, Gateway must clear its local session
  view. This does not prove Firmware observed disconnect; it prevents Gateway
  from keeping a session it can no longer confirm.

Implemented: `get_status`, `identify_device`, `connect`, `disconnect`,
`get_capabilities`, `get_accounts`, `policy_get`, `get_approval_history`,
`policy_propose`, `sign_transaction`, `sign_personal_message`, explicit local
Gateway device selection, and local Gateway caching of discovered devices. The
current signing runtime enforces state and session gates, keeps unknown methods
rejected, recognizes bounded restricted SUI transfer request inputs for Sui
`sign_transaction`, recognizes bounded Sui personal-message bytes for
`sign_personal_message`, records required approval-history metadata, and
returns `sign_result`. In policy authorization mode, the active policy can
reject `sign_transaction` or authorize signing through a bounded `sign` rule.
`sign_personal_message` is user-mode only and fails closed in policy mode. In
user authorization mode, Firmware uses device-local clear-signing review and
local PIN confirmation. Product-active status for the current tree still
depends on target implementation status and hardware evidence in
`docs/IMPLEMENTATION_STATUS.md`.

Provisioning and material reset transitions are not USB protocol requests in the
current implementation. The StackChan CoreS3 target enters setup from its local
unprovisioned setup UI and confirms or cancels the recovery phrase on the
device. There is no implemented USB request for starting provisioning, canceling
provisioning, confirming a recovery phrase backup, factory reset, or diagnostic
display signaling.

`connect` and `disconnect` are defined by the protocol and parsed by Gateway.
The current StackChan CoreS3 target accepts `connect` only after persistent root
material, active policy, local PIN verifier, and a `provisioned` state exist.
Its default device-local approval is local PIN entry on the device. The target's
local settings can switch connect approval back to physical Confirm, but changing
that setting itself requires local PIN verification.

`connect` and `disconnect` establish and end a runtime communication session
between Gateway and Firmware. A connection session does not authorize signing,
does not prove agent identity, and does not change Firmware policy.

`get_capabilities` is implemented as a read-only, session-scoped capability
request that reports Sui account identity, no delegated public methods, and
top-level `signing` availability. `signing.authorization` is Firmware-authored
read-only runtime state that describes the current device-local signing
authorization mode; it is not a request option, setter, or security decision
made by Gateway, MCP, provider, Admin Page, dapp, or CLI callers.
`get_accounts` is implemented as a read-only, session-scoped identity request
for the Sui Ed25519 account at index 0 in the `provisioned` state.
`policy_get` is implemented as a read-only, session-scoped summary of the
committed active policy; it is metadata only and not a policy update surface.
The normal product flow still installs the DEV_PROFILE default-reject policy.
`get_approval_history` is implemented as a read-only, session-scoped
view of Firmware-owned persistent decision metadata. The current Sign API
runtime paths are session-scoped: unknown methods are rejected, Sui
`sign_transaction` validates bounded restricted SUI transfer request inputs and
uses the Firmware-local signing authorization mode, and Sui
`sign_personal_message` validates bounded personal-message bytes in user
authorization mode only. Both methods return `sign_result` for supported
terminal outcomes. Hardware verification remains required for product-active
claims after changes to `policy_get`, `get_approval_history`, policy-mode
`sign_transaction`, user-mode `sign_transaction`, and user-mode
`sign_personal_message` paths.

## Device Discovery And Selection

Gateway discovers Firmware candidates by scanning supported transports and
calling `get_status` only on likely candidates. Gateway must avoid blind writes
to unrelated ports or devices.

USB discovery writes a `get_status` handshake only to candidate serial ports
selected from currently observed USB metadata. A stored port path is only a
hint; it must be rechecked against current port metadata before any write.

Gateway must not silently change the active device after discovery. Even when
one Firmware candidate is found, Gateway should request the device to show an
identification code before saving it as the active device. If more than one
Firmware candidate is found, Gateway must require explicit user selection before
changing the active device.

The intended multi-device selection flow is:

```text
user asks to find devices
  -> Gateway scans transport candidates
  -> Gateway calls get_status on likely candidates
  -> Gateway requests temporary identification display on candidate devices
  -> Firmware devices show short codes
  -> user chooses one code
  -> Gateway stores the selected deviceId and transport hint
```

Identification display is temporary UI. Firmware must return to the previous
device state after showing the code.

## Status

Gateway can request whether Firmware is available and what status Firmware reports.

Read-only status requests must not show physical approval UI.

Request:

```json
{
  "id": "req_001",
  "version": 1,
  "type": "get_status"
}
```

Response:

```json
{
  "id": "req_001",
  "version": 1,
  "type": "status",
  "device": {
    "deviceId": "uuid-string",
    "state": "idle",
    "firmwareName": "Agent-Q Firmware",
    "hardware": "hardware-id",
    "firmwareVersion": "0.0.0"
  },
  "provisioning": {
    "state": "unprovisioned"
  }
}
```

Device states:

- `idle`: ready for read-only requests.
- `busy`: processing another request.
- `awaiting_approval`: Firmware-owned device-local approval UI is active.
- `locked`: device requires local unlock before sensitive actions.
- `error`: device is running but cannot currently serve requests.

The current Firmware emits `idle`, `busy`, `awaiting_approval`, and `error`. It
reports `busy` while device-only setup material or a sensitive local subflow is
active, reports `error` for material/state consistency failure, and also uses
`busy` as an error code for requests that cannot run while another operation
owns the device UI. An idle target Settings menu remains `idle` because existing
session-scoped read and cleanup requests can still proceed. Other states are
reserved for later behavior.

`deviceId` is a Firmware-generated UUID stored in device-local persistent
storage. It must not be derived from MAC address, USB serial number, account
public key, or signing key.

`firmwareName` is a descriptive label for display and diagnostics. It is not a
security boundary and must not be treated as proof that the device is trusted.

Provisioning states:

- `unprovisioned`: root signing material, active policy, local PIN verifier, and signing authorization mode are not present.
- `provisioning`: local provisioning is in progress.
- `provisioned`: root signing material, active policy, local PIN verifier, and signing authorization mode are present.
- `locked`: the provisioning state cannot be used until the device is unlocked.
- `error`: Firmware detected persistent-material inconsistency and is failing closed.

`provisioning.state` reports only the Firmware's provisioning state. It is not
signing readiness, it does not prove that signing APIs exist, and it does not
authorize Gateway to make policy decisions. Gateway must preserve and
display the value without treating it as authority.

The current StackChan CoreS3 target persists `unprovisioned` and `provisioned`
and may report `error` when the persisted state and material records disagree.
It may report `provisioned` only when `prov_state`, the device-local root
material blob, a committed active policy record, the local PIN verifier, and
the signing authorization mode all exist. The current product flow installs the
default-reject policy. It does not
use `locked` because no unlock model is
implemented. Source-level DEV_PROFILE recovery phrase display, device-local
mnemonic recovery entry, persistent root material, active policy storage, local
PIN verifier storage, signing authorization mode storage, local reset, and
read-only `get_accounts` Sui account derivation are implemented.
USB/Gateway/MCP mnemonic import is not implemented.
Policy updates are available only through the Firmware-owned
`policy_propose` proposal flow for current-schema reject policies and at
most one single-recipient bounded sign rule.

If a target boots with `prov_state = provisioned` but missing, unreadable, or
unsupported current active policy or signing authorization mode material,
Firmware must fail closed instead of reporting normal `provisioned`. Existing
DEV_PROFILE devices without the current local PIN verifier or signing
authorization mode fail closed until reprovisioned.

Device metadata strings are untrusted input and Gateway bounds them when
parsing a response:

- `deviceId`: a safe identifier of `[A-Za-z0-9_.-]`, 1-128 characters. A
  response whose `deviceId` is outside this set is rejected as malformed.
- `firmwareName`, `hardware`, `firmwareVersion`: display strings. Gateway keeps
  printable ASCII only and caps length (64, 64, and 32 characters), dropping
  control characters and newlines. These are display values, not a trust
  signal, so they are sanitized rather than rejected.

## Local Provisioning And Reset Boundary

Provisioning setup and destructive material reset are device-local UX flows in
the current protocol. Gateway can observe the resulting state through
`get_status`, but it cannot trigger setup, cancellation, recovery phrase backup
confirmation, mnemonic import/recovery, factory reset, or diagnostic display
approval by sending a USB request.

The StackChan CoreS3 target enters setup from the local unprovisioned setup
speech bubble and then shows a local Generate/Recover choice. Generate creates
a 12-word BIP-39 recovery phrase in RAM, displays up-to-4-letter word prefixes
on the device in a 3-column by 4-row grid, and exposes only local Cancel and
Confirm controls on the recovery phrase panel. Three-letter BIP-39 words are
displayed as the full word.

Firmware owns the volatile setup scratch substate, separate from
persistent `provisioning.state`, session state, display power state, and LVGL
object lifetime. The current substates are:

- `none`: no generated recovery phrase is valid in RAM.
- `setup_choice`: local setup mode selection is active; no root material is
  valid yet.
- `recovery_phrase_displayed`: root entropy and recovery phrase scratch exist
  in RAM and the device recovery phrase panel is active.
- `recover_word_entry`: local mnemonic recovery word-entry scratch exists in
  RAM; the device shows three word-entry cells per page, local A-Z prefix
  buttons, and scrollable BIP-39 candidate bubbles. No persistent material is
  stored in this state.
- `pin_first_entry`: root entropy and the first typed PIN scratch exist in RAM
  and the device-local numeric PIN setup panel is active.
- `pin_repeat_entry`: root entropy, the first PIN scratch, and the repeat typed
  PIN scratch exist in RAM and the device-local numeric PIN setup panel is
  active.
- `pin_committing`: root entropy and matching PIN scratch exist in RAM while
  Firmware persists root material, policy, PIN verifier, and provisioned state;
  the PIN panel remains active with a non-interactive processing overlay and
  further local input is ignored.

The UI panel is an output of this substate machine, not the source of truth. If
the recovery phrase or PIN panel is removed, replaced, expires, is canceled, or
fails to store material, Firmware wipes the volatile setup scratch and returns
the scratch substate to `none`. Screen/backlight sleep does not by itself change
the security state; Agent-Q UI wakes the display before showing setup material
or approval UI.

Local Confirm is the only implemented backup confirmation transition for the
Generate path. It stores no persistent material by itself; it advances the
scratch state to local 6-digit PIN entry and wipes phrase text/prefix scratch.
The Recover path accepts mnemonic input only through the device-local word-entry
UI: three word cells per page, A-Z prefix buttons, and on-device candidate
selection. After 12 selected BIP-39 words pass checksum validation, Firmware
reconstructs root entropy in RAM and enters the same local PIN setup state as
Generate. Matching PIN repeat stores binary root material, the active
default-reject policy, and the salt + PIN verifier first, then persists
`provisioned`, then wipes volatile scratch. If root material, policy, PIN
verifier, or state persistence fails, Firmware rolls back persistent setup
material where possible, wipes volatile scratch, and must not report
`provisioned`. Local Cancel wipes volatile scratch and leaves persistent state
`unprovisioned`.

Gateway must not receive the generated phrase, displayed prefixes, recovered
words, entropy, seed, private key, account data, policy data, or import text.
BIP-39 English word prefixes of up to four letters identify the words and must
be treated as secret material.

The current protocol intentionally has no factory-reset or reprovisioning USB
request. Destructive material reset is device-local UX only. A target reset flow
must start from `provisioned`, require local user action plus stored local
authentication, wipe root material, active policy, local-auth verifier,
signing authorization mode, approval-history records, policy-update terminal
markers, reset-scoped local settings such as connect-approval preferences, and
runtime session, and return to `unprovisioned`. Implementations that record an internal reset-pending marker
before destructive wipe starts can resume an interrupted reset at boot. Wrong
authentication, timeout, or cancel preserves existing material. Reset
authentication lockout is target-local state, not a protocol state, and must not
create a host-triggered recovery path. A target may offer a device-local,
PIN-less, destructive erase-only recovery from material/state consistency
`error` when the PIN verifier may be unreadable, but that path still must not be
exposed as a USB/Gateway/MCP request and must not read, export, repair, or
unlock stored material.

## Identify Device

Gateway can request Firmware to show a short temporary identification code. This is
used for selecting the intended device after discovery. It is not signing
approval.

`identify_device` may be used for one candidate or many candidates. Gateway must
not save an active device until the user has selected one of the displayed
codes.

Request:

```json
{
  "id": "req_identify_001",
  "version": 1,
  "type": "identify_device",
  "params": {
    "code": "1234"
  }
}
```

Response:

```json
{
  "id": "req_identify_001",
  "version": 1,
  "type": "identify_device_result",
  "status": "displayed",
  "code": "1234",
  "device": {
    "deviceId": "uuid-string",
    "state": "idle",
    "firmwareName": "Agent-Q Firmware",
    "hardware": "hardware-id",
    "firmwareVersion": "0.0.0"
  }
}
```

Identification codes are four decimal digits. Identification display duration is
Firmware-owned temporary UI with a fixed internal `30000` millisecond window; it
is not a request parameter. Gateway may stop waiting before the device clears
the temporary layer; there is no cancel message.

Identification display is temporary UI. Firmware must return to the previous
device state after the display duration or when another request replaces the
temporary layer.

## Connect

When Gateway has no valid in-memory runtime session for a live device, it opens
a communication session by sending `connect`. A Firmware `connect` request
requires Firmware-owned device-local approval every time it is sent. Connect is
not signing approval and does not authorize signing.

Request:

```json
{
  "id": "req_connect_001",
  "version": 1,
  "type": "connect",
  "params": {
    "gatewayName": "Agent-Q Gateway"
  }
}
```

Request rules:

- `connect` is valid only after Firmware reports `provisioned` from stored root
  material.
- `gatewayName` is a Gateway-supplied display label. It is not a security
  boundary and Firmware must not treat it as proof that the requester is
  trusted.
- `gatewayName` is required, 1-64 characters of printable ASCII.
- Firmware owns fixed internal `30000` millisecond physical-input windows for
  local approval/PIN entry. The host cannot set or negotiate them through the
  protocol.
- Gateway transport waits for `connect` are internally fixed and include a
  non-configurable budget for Firmware PIN retry/lockout handling plus a
  transport margin. This is not a request field and callers cannot set or
  negotiate it.

Approved response:

```json
{
  "id": "req_connect_001",
  "version": 1,
  "type": "connect_result",
  "status": "approved",
  "sessionId": "session_...",
  "sessionTtlMs": 4294967295,
  "device": {
    "deviceId": "uuid-string",
    "state": "idle",
    "firmwareName": "Agent-Q Firmware",
    "hardware": "hardware-id",
    "firmwareVersion": "0.0.0"
  }
}
```

Rejected response:

```json
{
  "id": "req_connect_001",
  "version": 1,
  "type": "connect_result",
  "status": "rejected",
  "error": {
    "code": "rejected",
    "message": "Connection rejected."
  }
}
```

Timeout response uses the rejected shape with:

```json
{
  "code": "timeout",
  "message": "Connection approval timed out."
}
```

Connect rules:

- Establishing a session requires Firmware-owned device-local approval every
  time a Firmware `connect` request is sent. Firmware does not remember a
  previously approved Gateway.
- `connect_device` may reuse a Gateway RAM-held session only after contacting
  Firmware with a session-scoped read-only request and receiving a response that
  proves the current `sessionId` is still valid. If validation fails with
  `invalid_session`, Gateway must clear its local session and send a fresh
  Firmware `connect` request, which requires device-local approval.
- Firmware remains the only authority that can issue a fresh `sessionId`. A
  direct USB `connect` request must not return an existing session id without
  device-local approval.
- The current StackChan CoreS3 target stores a local `requirePinOnConnect`
  setting. Missing setting means the secure default, ON. Invalid stored values
  fail closed to ON and are logged. The setting is device-local; there is no USB,
  Gateway, or MCP request for changing it.
- When `requirePinOnConnect` is ON, successful device-local PIN entry is the
  connect approval. Firmware must not add a second Confirm step after PIN
  success. Wrong PIN attempts are rate-limited as device-local touch attempts:
  five wrong stored-PIN verification attempts across connect, Settings, Change
  PIN, and reset lock the local PIN UI for 30 seconds in RAM. Canceling and
  reopening the PIN UI must not clear the lockout. Power cycling clears it.
- Device-local PIN entry uses a Firmware-owned input window. Submitting a
  complete PIN pauses that input timeout while Firmware performs stored-PIN
  verification. This pause does not disable Firmware's internal local-auth
  worker watchdog; a stalled or lost worker result fails closed as local
  authentication unavailable, not as a wrong PIN. The original connect request
  window is the admission boundary and caps PIN entry before the PIN is
  submitted; it is not the terminal timeout authority for stored-PIN
  cryptographic processing after submit. A correct PIN result may proceed after
  verification even if the prior input window would have expired during the
  cryptographic work. If the submitted PIN is wrong, Firmware returns to the
  same PIN-entry state by resuming the remaining paused input window, subject
  to the shared wrong-PIN lockout.
- When `requirePinOnConnect` is OFF, the target uses the existing physical
  Confirm approval path.
- PIN is never submitted over USB. There is no protocol request or parameter for
  connect PIN, settings PIN, reset PIN, PIN verifier write, PIN change, or PIN
  reset.
- `connect` does not authorize signing.
- `connect` does not prove which agent or upstream user triggered the request.
- `sessionId` is generated by Firmware. The format is `session_` followed by
  random hex.
- `sessionId` must be derived from device RNG. It must not be derived from MAC
  address, USB serial number, `deviceId`, account public key, or signing key.
- `sessionTtlMs` is Firmware-owned wire metadata. `sessionTtlMs` is a uint32
  millisecond value; Gateway treats a `connect_result` whose `sessionTtlMs` is
  not a positive integer within the uint32 range (`1`..`4294967295`) as a
  malformed response. A target whose sessions are bound to the physical USB link
  may advertise the maximum value to avoid implying a shorter time-based
  reapproval deadline.
- Approving a new connect replaces any previously active Firmware session.
- A Gateway runtime session is held in memory only. Gateway must not persist
  `sessionId` to disk. `sessionId` is a Firmware-issued token kept internal to
  Gateway; Gateway must not return it to untrusted MCP clients.
- When Gateway already has an in-memory runtime session for a live device,
  `connect_device` must validate that session with a session-scoped read-only
  request and return the existing connection if validation succeeds. It must not
  send a fresh Firmware `connect` request solely because the caller invoked
  `connect_device` again.
- Gateway restart and explicit disconnect end Gateway's view of the session;
  Firmware reboot ends the session on the device. Gateway restart clears only
  Gateway's in-memory record. Firmware cannot observe a Gateway restart and
  keeps its active session until target policy clears it, such as on USB link
  loss, reboot, explicit disconnect, persistent-material error cleanup, or
  replacement by a new approved connect.
- Firmware targets may clear an active session earlier when the transport link
  is lost. On StackChan CoreS3, USB connected means USB host SOF is observed by
  `usb_serial_jtag_is_connected()`. It does not prove Gateway is running or that
  the serial port is open. Cable removal, host suspend, or SOF loss can clear
  the Firmware RAM session by policy.
- Gateway's local session cache is a RAM-only mirror, not authority. Gateway
  must clear it when Firmware rejects the session or when the transport can no
  longer be confirmed. A successful live USB scan that no longer observes the
  device is enough evidence to clear Gateway's RAM mirror for that device.
  Gateway must not use local time alone to force reapproval while the Firmware
  session remains valid.
- Firmware should return `busy` for UI-affecting or session-changing requests
  (including `connect` and `disconnect`) while an approval UI, device-only setup
  material display, or sensitive local PIN/reset/settings subflow is already
  open. Idle target Settings menus are local UI and do not by themselves end the
  active session; existing session-scoped requests may still proceed when they
  do not mutate the Settings flow. `get_status` remains read-only and must not
  trigger or change approval UI.

## Disconnect

Gateway can disconnect and end the active session.

After disconnect, Gateway must call `connect` again before calling
session-scoped requests.

Request:

```json
{
  "id": "req_disconnect_001",
  "version": 1,
  "type": "disconnect",
  "sessionId": "session_..."
}
```

Disconnect rules:

- `disconnect` does not require physical approval.
- Firmware may return `busy` instead of clearing the session while an approval
  UI, device-only setup material display, or sensitive local PIN/reset/settings
  subflow is active. Idle target Settings menus do not by themselves block
  `disconnect`.
- A pending policy-update approval is session-bound rather than generic local
  UI. A matching `disconnect` cancels that pending proposal and clears the
  session unless Firmware is already inside the policy commit critical section.
  The canceled `policy_propose` request is terminated with
  `invalid_session`; the `disconnect` request receives `disconnect_result`.
- Firmware validates only the session lifecycle for `disconnect`; persistent
  material readiness is not a prerequisite. If material inconsistency already
  cleared the session, Firmware returns `invalid_session` rather than
  `invalid_state`.
- Firmware returns `invalid_session` when `sessionId` is missing, unknown,
  inactive, or does not match the active Firmware session.

Response:

```json
{
  "id": "req_disconnect_001",
  "version": 1,
  "type": "disconnect_result",
  "status": "disconnected"
}
```

## Capabilities

Gateway can request which chains and methods Firmware supports.

Request:

```json
{
  "id": "req_004",
  "version": 1,
  "type": "get_capabilities",
  "sessionId": "session_001"
}
```

Response:

```json
{
  "id": "req_004",
  "version": 1,
  "type": "capabilities",
  "chains": [
    {
      "id": "sui",
      "accounts": [
        {
          "keyScheme": "ed25519",
          "derivationPath": "m/44'/784'/0'/0'/0'"
        }
      ],
      "methods": []
    }
  ],
  "signing": {
    "authorization": "user",
    "methods": [
      {
        "chain": "sui",
        "method": "sign_transaction"
      },
      {
        "chain": "sui",
        "method": "sign_personal_message"
      }
    ]
  }
}
```

Rules:

- `get_capabilities` is session-scoped and requires `sessionId`.
- Firmware returns capabilities only when `provisioning.state` is `provisioned`
  and persistent material, including root material, active policy, local PIN
  verifier, and signing authorization mode, is consistent. Before that it returns
  `invalid_state`.
- A missing, inactive, or mismatched session returns `invalid_session`.
- The current StackChan CoreS3 target advertises Sui Ed25519 account identity
  for account 0 at `m/44'/784'/0'/0'/0'`, no entries in
  `chains[].methods`, and top-level Sui signing availability in
  `signing.methods`. In user authorization mode this includes
  `sign_transaction` and `sign_personal_message`; in policy authorization mode
  this includes `sign_transaction` only.
- `signing.authorization` is the Firmware-authored read-only local signing
  authorization mode (`"user"` or `"policy"`) that will be used for supported
  signing methods. Protocol requests must not contain this field, and there is
  no protocol setter.
- A non-empty `methods` list is a Firmware-authored availability claim. Firmware
  must advertise only delegated non-signing methods that have a connected
  runtime implementation, result schema, required approval behavior, required
  history behavior, Gateway parser/output support, MCP output support, and
  provider support for the same method boundary. Signing availability must use
  top-level `signing`.
- Gateway, MCP, provider-sui, and UI consumers may use
  `signing.authorization` only to describe expected behavior. The security
  decision is the Firmware-authored `sign_result` and its recorded
  authorization.
- Gateway validates the response strictly, rejects unknown chains, unsupported
  account schemes or derivation paths, unknown method lists, unknown signing
  availability entries,
  secret-like fields, and any unexpected `sessionId` in the response. Gateway
  does not infer or add capabilities.

## Accounts

`get_accounts` is a session-scoped read-only request that returns the public
account identity Firmware derives from its stored root material. It exposes only
public material: address, public key, key scheme, and derivation path. It never
returns a mnemonic, seed, entropy, private key, or any signing key, and it does
not perform signing.

Request:

```json
{
  "id": "req_005",
  "version": 1,
  "type": "get_accounts",
  "sessionId": "session_001"
}
```

Approved response:

```json
{
  "id": "req_005",
  "version": 1,
  "type": "accounts",
  "accounts": [
    {
      "chain": "sui",
      "address": "0x...",
      "publicKey": "base64...",
      "keyScheme": "ed25519",
      "derivationPath": "m/44'/784'/0'/0'/0'"
    }
  ]
}
```

Rules:

- `publicKey` is the raw 32-byte Ed25519 public key encoded as base64. The scheme
  is reported separately as `keyScheme`; the address is
  `0x` + lowercase hex of `blake2b256(0x00 || publicKey)`.
- Firmware returns accounts only when `provisioning.state` is `provisioned` and
  persistent material, including root material, active policy, local PIN
  verifier, and signing authorization mode, is consistent. Before that it
  returns `invalid_state`.
- The request requires `sessionId`. A missing, inactive, or mismatched session
  returns `invalid_session`.
- Account derivation runs in Firmware on demand and wipes all intermediate secret
  material. A derivation failure returns `account_error` with no partial account.
- Gateway parses and re-validates the account shape, rejects any response that
  carries a secret-like field, and recomputes the Sui Ed25519 address from
  `publicKey` to reject mismatched public identities. Firmware still owns account
  derivation; Gateway validation is consistency checking, not signing authority.
  The Gateway MCP `get_accounts` tool never exposes the session id.
- The current StackChan CoreS3 target implements the Sui Ed25519 account at index
  0 (`m/44'/784'/0'/0'/0'`) and returns exactly one `accounts[]` entry. Gateway
  rejects any other account count for this target. Additional chains and accounts
  are added as more `accounts[]` entries only after the protocol, capability
  response, and Gateway bounds are updated. StackChan CoreS3 hardware smoke
  verifies the current single-account response over an approved session.
  `get_accounts` reads identity only. Current delegated public method
  availability is reported by `get_capabilities.chains[].methods`.
  Signing availability is reported separately through top-level `signing`,
  including the Firmware-authored `authorization` mode and supported signing
  methods.

## Policy Summary

`policy_get` is a session-scoped read-only request that returns public metadata
for the active Firmware-owned policy provider used by `sign_transaction`. It does not
return policy secrets, signing material, or an editable policy document.

Request:

```json
{
  "id": "req_policy",
  "version": 1,
  "type": "policy_get",
  "sessionId": "session_001"
}
```

Response:

```json
{
  "id": "req_policy",
  "version": 1,
  "type": "policy",
  "policy": {
    "schema": "agentq.policy.v0",
    "policyId": "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
    "defaultAction": "reject",
    "ruleCount": 0
  }
}
```

Rules:

- Firmware returns a policy summary only when `provisioning.state` is
  `provisioned`, persistent material is consistent, a committed active policy
  record exists, and the request has a matching active session.
- Corrupt, unreadable, missing, or unsupported current active policy material is a
  persistent-material consistency error. Firmware must fail closed instead of
  continuing to report a normal `provisioned` state when the policy cannot be
  made active.
- `policyId` is the lowercase SHA-256 identifier for the canonical stored
  policy record. It is metadata for drift detection, not an authorization token.
- The current StackChan CoreS3 target supports only `agentq.policy.v0`,
  `defaultAction: "reject"`, and a bounded `ruleCount` summary. The normal
  product flow installs `ruleCount: 0`; custom current-schema policy records may become
  active only through the Firmware-owned `policy_propose` proposal flow.
  Full policy content exposure is not implemented.
- Gateway validates the response strictly, rejects secret-like fields and any
  unexpected `sessionId`, and does not evaluate policy.
- The Gateway MCP `policy_get` tool never exposes the session id.

## Approval History

`get_approval_history` is a session-scoped read-only request that returns
Firmware-authored decision metadata. It is not an on-chain transaction history,
not a host activity log, and not a policy edit surface. The current StackChan
CoreS3 implementation stores this history in a fixed-size binary NVS ring
buffer and wipes it during local material reset or error-state erase recovery.

Request:

```json
{
  "id": "req_history",
  "version": 1,
  "type": "get_approval_history",
  "sessionId": "session_001",
  "params": {
    "limit": 4,
    "beforeSeq": "42"
  }
}
```

`params` is optional. `limit` is an integer from `1` to `4`. `beforeSeq` is a
canonical unsigned 64-bit decimal string used for newest-first pagination; the
single value `"0"` is allowed, but other leading-zero encodings are rejected.

Response:

```json
{
  "id": "req_history",
  "version": 1,
  "type": "approval_history",
  "records": [
    {
      "seq": "41",
      "uptimeMs": "183204",
      "timeSource": "uptime",
      "eventKind": "signing",
      "recordKind": "terminal",
      "authorization": "policy",
      "terminalResult": "policy_rejected",
      "chain": "sui",
      "method": "sign_transaction",
      "reasonCode": "policy_rejected",
      "payloadDigest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "policyHash": "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
      "ruleRef": "default"
    },
    {
      "seq": "40",
      "uptimeMs": "183100",
      "timeSource": "uptime",
      "eventKind": "policy_update",
      "result": "applied",
      "reasonCode": "device_confirmed",
      "policyHash": "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
      "ruleCount": 1,
      "highestAction": "reject"
    }
  ],
  "hasMore": false
}
```

Rules:

- Firmware returns approval history only when `provisioning.state` is
  `provisioned`, persistent material is consistent, and the request has a
  matching active session.
- The API is read-only. The protocol has no request to add, edit, delete, or
  clear approval-history records.
- Records are newest-first. `seq` and `uptimeMs` are unsigned decimal strings.
  `timeSource: "uptime"` means the timestamp is device uptime, not wall-clock
  time.
- Current StackChan CoreS3 source records required signing confirmation and
  terminal metadata plus recordable terminal metadata from
  `policy_propose`. Invalid parameter, malformed transaction,
  unsupported-method, and unsupported policy-action errors are not persisted as
  approval history.
- Approval-history persistence is part of the terminal decision contract for
  decisions that are recorded. If Firmware cannot persist a required history
  record or its write budget is exhausted, `sign_transaction` returns the top-level
  `history_error` protocol error instead of a `sign_result`.
- Firmware rate-limits optional persistent signing history writes to reduce
  flash wear. Required signing and policy-update history records are part of
  their respective terminal contracts and must either be persisted before the
  corresponding terminal result is reported or fail closed through the defined
  error path.
- History records must not store or return raw `txBytes`, full decoded
  transactions, session ids, raw request ids, gateway names, mnemonic text,
  seed, private key material, PINs, or complete policy documents.
- Gateway validates the response strictly, rejects secret-like fields and any
  unexpected `sessionId`, preserves protocol integers as strings, and does not
  evaluate policy or signing safety.
- The Gateway MCP `get_approval_history` tool never exposes the session id.

## Transaction Signing Request

`sign_transaction` is the shared protocol request for transaction signing.
The request shape does not contain an authorization selector. Firmware reads
its device-local signing authorization mode and chooses the internal signing
gate:

- both modes validate the request envelope, parse the transaction bytes, bind
  sender and gas owner to the stored device account, and reject without
  fallback when their selected gate rejects the request;
- `policy`: build policy facts, evaluate the active policy, show
  non-confirming device notifications, and sign without per-request
  device-local confirmation only when policy authorizes the bounded request;
- `user`: build a clear-signing review, require device-local confirmation and
  local PIN, and either reject, time out, or sign the bounded request.

There is no fallback between gates. A policy rejection in policy mode ends the
request. A user rejection or timeout in user mode ends the request.

Request shape:

```json
{
  "id": "req_sign_001",
  "version": 1,
  "type": "sign_transaction",
  "sessionId": "session_001",
  "chain": "sui",
  "method": "sign_transaction",
  "params": {
    "network": "devnet",
    "txBytes": "AA..."
  }
}
```

Rules for the first implementation:

- `sign_transaction` is valid only in material-backed `provisioned` state with
  a matching active session.
- Request fields may not include `authorization`, `timeoutMs`,
  `approvalTimeoutMs`, `durationMs`, raw session tokens beyond the envelope
  `sessionId`, or signing material.
- The first implementation is limited to `chain: "sui"` and
  `method: "sign_transaction"` for the restricted SUI transfer shape accepted
  by the current Sui transaction-facts parser.
- `params.network` is required and must be one of `mainnet`, `testnet`,
  `devnet`, or `localnet`. Current Sui `txBytes` do not carry network identity,
  so Firmware validates this only as request context and does not expose it as a
  policy fact or transaction-derived history proof.
- `params.txBytes` must be canonical base64 and remain within the current Sui
  signing request bounds unless a later spec change widens the bound with
  matching parser, scratch, UI, and tests.
- Firmware must derive the signing account from stored device material, and
  the parsed sender and gas owner must both match that device-derived account.
  Sponsored gas and request-supplied expected-signer bindings are unsupported
  in the first implementation.
- Firmware must not call the signing service before the required
  approval-history record for the selected authorization mode is durable. If a
  required history write fails, Firmware returns top-level `history_error` and
  must not claim the corresponding terminal result.
- `get_capabilities.methods` does not advertise signing. Signing availability
  is advertised only through top-level `signing.authorization` and
  `signing.methods`.

Policy authorization mode:

- Firmware evaluates already extracted transaction facts against the stored
  active policy. The common evaluator owns shared `common.*` policy fields;
  chain-specific field identifiers, descriptor enablement, and transaction
  meaning stay in the corresponding method adapter.
- A `reject` decision returns `sign_result` with `authorization: "policy"` and
  `status: "policy_rejected"` after the corresponding terminal
  approval-history record is persisted.
- A `sign` decision writes the required policy signing confirmation history
  record before calling the signing service, then writes the durable signed
  terminal history record before returning `sign_result` with
  `authorization: "policy"` and `status: "signed"`.
- Missing or invalid active policy providers fail closed. In normal boot-time
  state handling that condition is a persistent-material consistency error, and
  any late provider failure is mapped to `policy_error`.

User authorization mode:

- Firmware must parse enough input to show a bounded clear-signing summary
  before entering device confirmation. Unsupported or malformed transactions
  must fail before any signing approval UI can be confirmed. The displayed
  summary must be derived from the same `txBytes` that would be signed; callers
  must not supply independent review facts.
- The first implementation requires local PIN confirmation. The connect-only
  `pin_on_connect` setting does not control signing confirmation.
- Firmware owns fixed internal `30000` millisecond physical-input windows for
  review confirmation and PIN entry. The host cannot set or negotiate them
  through the protocol. Submitting a complete PIN pauses the input timer while
  stored-PIN cryptographic verification runs. The original signing confirmation
  window is the review/PIN-entry admission boundary and caps PIN entry before
  submit; it is not the terminal timeout authority for stored-PIN
  cryptographic processing after submit. A wrong PIN result returns to the same
  PIN-entry state by resuming the remaining paused input window unless the
  shared wrong-PIN lockout is active. The internal local-auth worker watchdog
  still fails closed as authentication unavailable.
- Review Reject is the terminal `user_rejected` action. Back from the PIN
  screen wipes only PIN scratch and returns to the clear-signing review; it
  must not be reported as `user_rejected` or written as a terminal rejection.
- The state owner must validate the session immediately before performing the
  required confirmation history write and must enter the signing critical
  section in the same successful transition. A session loss after the write
  succeeds must not downgrade the request to pre-signing cleanup.

## Personal Message Signing Request

`sign_personal_message` is the shared protocol request for Sui personal-message
signing. The request shape does not contain an authorization selector. The
current implementation supports this method only in device-local `user`
authorization mode because policy facts and policy rules for personal-message
contents are not implemented.

Request shape:

```json
{
  "id": "req_sign_msg_001",
  "version": 1,
  "type": "sign_personal_message",
  "sessionId": "session_001",
  "chain": "sui",
  "method": "sign_personal_message",
  "params": {
    "network": "devnet",
    "message": "base64-message-bytes"
  }
}
```

Rules for the first implementation:

- `sign_personal_message` is valid only in material-backed `provisioned` state
  with a matching active session.
- Request fields may not include `authorization`, `timeoutMs`,
  `approvalTimeoutMs`, `durationMs`, raw session tokens beyond the envelope
  `sessionId`, or signing material.
- The first implementation is limited to `chain: "sui"` and
  `method: "sign_personal_message"` with canonical base64 `params.message`
  bytes inside the current target's bounded message-size limit.
- `params.network` is required and must be one of `mainnet`, `testnet`,
  `devnet`, or `localnet`. Current Sui personal-message bytes do not carry
  network identity, so Firmware validates this only as request context and does
  not expose it as a policy fact or message-derived history proof.
- Firmware must derive the signing account from stored device material and show
  a bounded clear-signing review derived from the exact message bytes that will
  be signed. Full message display may be replaced by bounded preview plus digest
  metadata, but callers must not supply independent review facts.
- Review Reject is the terminal `user_rejected` action. Back from the PIN
  screen wipes only PIN scratch and returns to the clear-signing review; it
  must not be reported as `user_rejected` or written as a terminal rejection.
- Firmware must build the Sui PersonalMessage intent digest by BCS-serializing
  the message as a byte vector, applying the Sui PersonalMessage intent, and
  signing that digest. It must not reuse the Sui transaction-intent signing path
  for this method.
- Firmware must not call the signing service before the required local-PIN
  confirmation history record is durable. If a required history write fails,
  Firmware returns top-level `history_error` and must not claim the corresponding
  terminal result.
- If the device-local signing authorization mode is `policy`, Firmware returns
  a fail-closed `unsupported_method` error. It must not fall back to user
  confirmation.
- `get_capabilities.methods` does not advertise signing. Signing availability
  is advertised only through top-level `signing.authorization` and
  `signing.methods`. `sign_personal_message` appears only when the current
  Firmware-local signing authorization mode is `user`.
- `sign_result` for a signed personal message includes `authorization: "user"`,
  `chain: "sui"`, `method: "sign_personal_message"`, `signature`, and
  `messageBytes`, where `messageBytes` is the canonical base64 message bytes
  that Firmware signed. Non-signed terminal responses do not include
  `messageBytes`.
- History must not store or return raw full message bytes, session ids, raw
  request ids, mnemonic text, seed, private key material, PINs, or device-local
  UI state.

## Sign Result Response Examples

The following examples apply to the signing requests above. Signed transaction
responses do not include `messageBytes`; signed personal-message responses
include the canonical base64 message bytes that Firmware signed.

Signed transaction response:

```json
{
  "id": "req_sign_tx_001",
  "version": 1,
  "type": "sign_result",
  "authorization": "user",
  "status": "signed",
  "chain": "sui",
  "method": "sign_transaction",
  "signature": "base64-sui-ed25519-signature-envelope"
}
```

Signed personal-message response:

```json
{
  "id": "req_sign_msg_001",
  "version": 1,
  "type": "sign_result",
  "authorization": "user",
  "status": "signed",
  "chain": "sui",
  "method": "sign_personal_message",
  "messageBytes": "base64-message-bytes",
  "signature": "base64-sui-ed25519-signature-envelope"
}
```

User rejected response:

```json
{
  "id": "req_sign_tx_001",
  "version": 1,
  "type": "sign_result",
  "authorization": "user",
  "status": "user_rejected",
  "error": {
    "code": "user_rejected",
    "message": "The signing request was rejected on the device."
  }
}
```

`sign_result.status` values for `authorization: "user"`:

- `signed`: Firmware generated the signature after device confirmation, the
  required pre-signing confirmation history record, and a durable signed
  terminal history record.
- `user_rejected`: device-local confirmation explicitly rejected the request.
- `user_timed_out`: device-local confirmation expired without approval.
- `signing_failed`: device confirmation succeeded, but signing failed before a
  signature response could be produced.

Pre-signing session loss, disconnect cancellation, or pre-signing confirmation
history write failure are cleanup failures, not signature results. They must
produce no signature and may return a top-level error instead of `sign_result`.

Terminal error mapping:

| status | error.code | error.message |
| --- | --- | --- |
| `user_rejected` | `user_rejected` | `The signing request was rejected on the device.` |
| `user_timed_out` | `user_timed_out` | `The signing request timed out on the device.` |
| `signing_failed` | `signing_failed` | `The device could not produce a signature.` |

`signed` transaction responses may contain only `authorization`, `chain`,
`method`, and `signature` as method-specific output. `signed`
personal-message responses also include canonical base64 `messageBytes` for the
message bytes that Firmware signed. Non-signed terminal responses may contain
only `authorization` and `error` beyond the shared envelope fields. A
`policy_rejected` response also includes `policyHash` and `ruleRef`. No
`sign_result` response may contain raw `txBytes`, decoded transaction
internals, session id, request id beyond the envelope id, account private
material, seed, mnemonic, PIN, policy scratch, or device-local UI state.
Client, provider, and MCP parsers must fail closed on extra or secret-like
fields. Current adapter projections may expose only a subset of signing paths,
but Firmware remains responsible for rejecting unavailable or invalid signing
requests.

## Response Delivery And Provider Boundary

- Firmware signature generation, terminal history persistence, USB response
  delivery, Gateway receipt, provider return, and application use of a
  signature are separate events.
- `sign_result.status: "signing_failed"` means the authorization source
  approved signing but Firmware could not produce a signature. It is not a
  response-delivery failure status.
- If Firmware generates a signature but cannot record the required signed
  terminal history record before sending `sign_result`, Firmware must not send
  the signature. It may return a top-level `history_error`. That error means
  signature generation occurred, provider receipt did not occur, and a later
  `get_approval_history` read must not be treated as signed terminal proof
  unless the signed terminal record exists.
- If Firmware generates a signature and records a durable `signed` terminal
  record, then response delivery fails before Gateway receives the response, the
  caller-facing result is a transport or protocol failure. That failure must
  not be reported as `user_rejected`, `user_timed_out`, `policy_rejected`, or
  `signing_failed`, and it must not claim that Firmware did not generate a
  signature. A later `get_approval_history` read may show the durable `signed`
  terminal record.
- The provider `signTransaction` API and MCP `sign_transaction` tool return
  discriminated results for Firmware-authored terminal `sign_result` statuses.
  Device rejection, device timeout, policy rejection, and signing failure are
  product outcomes, not provider or MCP exceptions. Adapter promise rejection is
  reserved for local adapter/programmer errors; Gateway or transport failures
  use the same structured public-error style as the current methods.
- Provider-sui must not expose Admin, policy proposal, active policy reads,
  approval-history reads, or a host-selected policy-signing API. MCP/Admin
  package surfaces may expose management and policy proposal tools, but
  Firmware remains the authority for security-relevant enforcement.

Approval-history contract:

- Device-confirmed and policy-authorized signing use `eventKind: "signing"`.
- Required pre-signing records use `recordKind: "confirmation"`. User-confirmed
  signing uses `confirmationKind: "local_pin"` for the first implementation.
  Policy-authorized signing uses `confirmationKind: "policy"` and includes
  `policyHash` and `ruleRef`.
- Recordable terminal results are `signed`, `user_rejected`,
  `user_timed_out`, `policy_rejected`, and `signing_failed`.
- Terminal records use `recordKind: "terminal"` and store only bounded metadata:
  authorization, chain, method, reason code, payload digest, optional
  `policyHash`, optional `ruleRef`, and optional terminal result. They must not
  store raw `txBytes`, decoded transaction internals, session ids, raw request
  ids, PINs, seed, mnemonic, private key material, or full UI text.
- A durable `signed` terminal record means Firmware generated a signature after
  device confirmation or policy authorization. It does not prove Gateway
  received the signature.
- If a required confirmation history write fails before signing, Firmware must
  return top-level `history_error` and must not call the signing service.

## Policy Update Proposal

Admin is a Gateway capability, not a separate product protocol. The current
policy-write path is the top-level `policy_propose` request. It is not a
signing method, it must not use `chain` or `method`, and it must not route
through `sign_transaction`.

### `policy_propose`

`policy_propose` is a policy-write proposal request. StackChan CoreS3
Firmware and Gateway/MCP implement the first supported path: a session-scoped
proposal is validated by Firmware, shown on device as a policy-update summary
review, advanced to local PIN approval only after device-local Continue,
committed through the canonical active-policy store, and reported as
`policy_propose_result`. The Gateway-served local Admin Page can submit the
current policy proposal template; full policy editing is not implemented.
MCP/API callers can submit bounded current-schema policy proposals.

The method is a proposal, not a setter. Gateway or Admin may submit a bounded
policy document, but Firmware remains the authority that validates the document,
shows device-local approval, commits the active policy, and reports the result.
The pending proposal remains bound to the same active `sessionId` until the
terminal result. If that session ends, disconnects, or no longer matches
before commit, Firmware must cancel the pending proposal and must not change the
active policy.

Request shape:

```json
{
  "id": "req_policy_propose",
  "version": 1,
  "type": "policy_propose",
  "sessionId": "session_001",
  "params": {
    "policy": {
      "schema": "agentq.policy.v0",
      "defaultAction": "reject",
      "rules": [
        {
          "id": "reject-sui-transfer",
          "chain": "sui",
          "method": "sign_transaction",
          "action": "reject",
          "criteria": [
            {
              "field": "common.intent",
              "op": "eq",
              "value": "single_asset_transfer"
            }
          ]
        }
      ]
    }
  }
}
```

Policy document rules for the first version:

- Wire format: JSON inside the existing JSONL protocol envelope. Firmware must
  parse the JSON into a bounded internal policy AST before validation or
  storage. The wire JSON is not stored directly.
- The protocol handler enforces a 4096-byte maximum raw JSON object before
  deserialization, not counting the trailing newline. Target-local proposal
  parser source may additionally
  bound the serialized policy object after deserialization; that check is not a
  substitute for the raw envelope limit.
- Stored format: a Firmware-canonical binary policy record derived from the
  bounded AST. Policy hash/id is computed over that canonical record.
- `schema` must be `agentq.policy.v0`.
- `defaultAction` must be `reject`.
- A policy may contain at most 16 rules.
- A rule id is a bounded printable identifier, not an authorization token. It
  must use the same grammar and 32-character maximum as approval-history
  `ruleRef`: lowercase letter first, followed by lowercase letters, digits,
  `_`, `-`, `.`, `:`, or `/`.
- Each rule has `chain`, `method`, `action`, and `criteria`.
- The current policy schema accepts only `reject` and `sign`.
- Action values outside the current schema are invalid policy input. A policy
  update must not store dormant behavior. Disabled policy drafts are out
  of scope for this version.
- A `reject` rule may have zero criteria.
- A `sign` rule must be bounded, and the first implementation accepts at most
  one `sign` rule in a policy document. For Sui `sign_transaction`, broad
  signing is invalid. The first implementation requires criteria that restrict
  the rule to the bounded restricted SUI transfer shape, including
  `common.intent = single_asset_transfer`,
  `sui.command_shape = restricted_transfer`,
  `sui.coin_type = 0x2::sui::SUI`, one concrete recipient criterion,
  amount bounds, and gas bounds. Multiple sign rules and multi-recipient sign
  allowlists are invalid until the device-local policy-update review can show
  every allowed signing rule and recipient clearly.
- A rule may contain at most 8 criteria.
- Criterion `field` is a bounded namespace/field id such as `common.intent` or
  `sui.amount_raw`. Common fields are owned by the common policy evaluator;
  chain-specific fields are owned by the corresponding method adapter.
- Criterion `op` may be `eq`, `in`, or `lte` only where the active method
  adapter's field descriptor allows that operator.
- `eq` and `lte` use exactly one scalar `value`. `in` uses exactly one
  non-empty `values[]` list with at most 16 entries. Unused scalar/list fields
  are rejected.
- `u64_decimal` values must be canonical unsigned decimal strings in the
  `uint64` range.
- No policy may depend on Gateway labels, purpose routing, gateway name, raw
  request id, session id, external market data, network fetches, JavaScript,
  Rego, CEL, JSONPath, arbitrary code execution, or a Sui host-supplied network
  label. Other chains may expose chain-specific transaction-bound network facts
  only when implemented by their chain adapter.

State and authorization rules:

- `unprovisioned`, `provisioning`, `error`, and `locked` reject policy update
  proposals with the state error defined for unavailable methods.
- `provisioned` plus a matching active session may accept a proposal for
  Firmware validation.
- A valid proposal enters a Firmware-owned pending policy-update state. The
  pending state is not a protocol state setter and is not derived from UI object
  lifetime.
- A second policy update proposal while one is pending is rejected with `busy`.
- Device-local approval is required before commit. For the current display
  target, approval is a two-step device flow: first a summary review showing a
  bounded policy hash prefix, rule count, default action, affected chain/method,
  highest action, and the current-schema action summary; then local PIN entry
  after device-local Continue. Rejecting or timing out on the summary review
  terminates the proposal without starting PIN state. Back from the PIN screen
  returns to the summary review and wipes only the PIN scratch; review Reject is
  the terminal rejected action. This implementation does not rely on host-only
  confirmation.
- During pending approval, read-only session methods may remain available only
  if they do not dismiss or mutate the pending state. `sign_transaction` and nested
  policy updates must return `busy` while a policy update is pending or
  committing.
- `policy_get` returns the committed active policy only. It must not include or
  imply the pending proposal.
- `disconnect` may perform session cleanup except during the commit critical
  section, where Firmware may return `busy`.

Storage and rollback rules:

- The active policy store uses two bounded binary slots plus small metadata
  identifying the current committed slot. NVS key names must fit the target
  NVS key limit.
- Commit writes a pending marker for the intended inactive slot and commit
  metadata record, writes and validates that slot, then flips the active
  metadata. The old policy remains authoritative until the metadata flip
  commits.
- The metadata flip is the commit point. After that point, Firmware must not
  return a storage failure that implies the old policy remained active. Pending
  marker cleanup after the flip is best-effort; a stale marker that exactly
  matches the selected committed policy is ignored by active-policy selection.
  Stale commit metadata is removed before its slot/metadata key is reused by a
  later write. A write result must terminate as exactly one of: new policy
  applied, previous policy proven unchanged, or persistent-material consistency
  error.
- On write, validation, or cleanup failure before the metadata flip, Firmware
  keeps the old policy and reports failure unless the material is left in a
  consistency-error state. The pending marker is the only reason a torn target
  slot or target commit record may be ignored in favor of the previous committed
  policy, and pending targets that overlap the selected active slot or commit
  metadata without exactly matching it are treated as corruption rather than
  erased. Firmware recognizes only the current tracked active-policy storage
  layout as product state.
- On ambiguous boot state, Firmware selects the newest valid committed slot
  unless a valid pending marker identifies an interrupted write target. Present
  but invalid commit metadata without that pending marker is a
  persistent-material consistency error rather than silent rollback.
- DEV_PROFILE slot selection is not rollback protection. USER_PROFILE policy
  storage requires secure anti-rollback or monotonic commit protection before it
  can claim rollback resistance.
- Local reset and error-state erase wipe all policy slots and policy metadata.

Response shape:

`policy_propose` returns `policy_propose_result` only after Firmware has
accepted the protocol envelope, authenticated the active session, and classified
the policy proposal path. Envelope, version, request id, session, state, busy,
and oversized raw-message failures remain top-level protocol errors.

When Firmware has a canonical policy proposal, `policy` is required:

```json
{
  "id": "req_policy_propose",
  "version": 1,
  "type": "policy_propose_result",
  "status": "applied",
  "reasonCode": "device_confirmed",
  "policy": {
    "policyHash": "sha256:7a44fa541071015b30b80d1165f76e4c88ccd2275e1df97bccdb3b1a341ad3c3",
    "ruleCount": 1,
    "highestAction": "reject"
  }
}
```

For `invalid_policy`, `policy` must be omitted because Firmware may not have a
canonical policy hash, rule count, or highest action:

```json
{
  "id": "req_policy_propose",
  "version": 1,
  "type": "policy_propose_result",
  "status": "invalid_policy",
  "reasonCode": "invalid_policy"
}
```

Response outcomes:

- `applied`: Firmware validated, approved, committed, and activated the new
  policy. The `policy` metadata is required.
- `rejected`: local user rejected the proposal. The `policy` metadata is
  required.
- `timed_out`: local approval expired with no change. The `policy` metadata is
  required.
- `invalid_policy`: Firmware rejected the proposal before a canonical policy was
  available. The `policy` metadata is forbidden.
- `ui_error`: Firmware accepted and canonicalized the proposal but could not
  display or restore the required device-local approval UI, so no policy changed.
  The `policy` metadata is required. This is not a user timeout and is not a
  durable policy-update history result.
- `storage_error`: Firmware could not commit the new policy; the old policy
  remains active unless Firmware reports a persistent-material consistency
  error on an ambiguous state. The `policy` metadata is required.
- `consistency_error`: Firmware reached an ambiguous policy-update terminal
  state, typically after the commit point. Firmware must fail closed through the
  persistent-material consistency boundary. The `policy` metadata is required
  when the response is tied to a canonical proposal.

`busy` is a top-level protocol error for a request that cannot enter the policy
update flow because another sensitive local flow or policy update is active. It
is not a `policy_propose_result` status and is not stored as policy-update
history.

Policy update history:

- Firmware records policy update proposal outcomes as approval-history metadata
  when the outcome is recordable.
  Recordable policy-update history results are `applied`, `rejected`,
  `timed_out`, and `storage_error`. `invalid_policy` is a response-only result
  for proposals rejected before a canonical policy hash exists. `ui_error` is a
  response-only display failure before local approval was usable. `history_error`
  is a top-level error meaning the required history record could not be
  persisted; `consistency_error` is a device/material state and must not be
  stored as a durable policy-update history `result`.
- Policy-update outcome history is part of the terminal-result contract. The
  implementation must not report `applied` unless the committed policy and the
  corresponding history record are both durable. Before the policy commit point,
  required-history failure leaves the previous active policy unchanged. After the
  policy commit point, required-history failure is an ambiguous terminal state:
  Firmware must leave/report persistent-material consistency error rather than
  claiming the old policy remained active.
- History records may include sequence, uptime, event kind, result, policy
  hash/id, rule count, highest-risk action, and reason code.
- History records must not store raw policy documents, full rule content,
  session ids, request ids, gateway names, PINs, mnemonic text, seed, or private
  key material.
