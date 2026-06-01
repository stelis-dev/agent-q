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
- method requests and method results
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
- evaluates signing requests
- asks for physical approval when required
- signs, rejects, or times out requests

Intended but not yet implemented: a local Admin Page served by Gateway, and
Firmware persistence of approved admin changes. Both depend on the admin methods
in [Admin Methods](#admin-methods), which are not implemented yet.

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
- `invalid_duration`
- `invalid_gateway_name`
- `invalid_approval_timeout`
- `invalid_session`
- `invalid_state`
- `invalid_method`
- `invalid_params`
- `unsupported_version`
- `unsupported_type`
- `busy`
- `rejected`
- `timeout`
- `policy_error`
- `history_error`
- `rng_error`
- `account_error`

Transport-layer errors are owned by Gateway and are not Firmware protocol
errors.

## Session Flow

Protocol interaction has a clear discovery step, session start, and session
end.

```text
get_status
  -> identify_device?
  -> connect
    -> get_capabilities
    -> get_accounts
    -> get_policy
    -> get_approval_history
    -> call_method*
  -> disconnect
```

Flow rules:

- `get_status` can be called before a session exists.
- `get_status` is the transport handshake used to identify Firmware candidates.
- If multiple Firmware devices are connected, Gateway must not silently choose
  one. Gateway should ask Firmware devices to display short identification
  codes, then use the user's selection to choose one active device.
- Gateway may store the selected `deviceId` and transport hint locally.
- A stored transport hint is not identity. Gateway must confirm identity with
  Firmware before treating a device as live.
- `connect` establishes a session and requires Firmware-owned device-local
  approval. Hardware targets may implement that approval as a physical confirm
  or as local PIN verification, but PIN entry must never be a USB protocol
  request.
- `get_capabilities`, `get_accounts`, `get_policy`, `get_approval_history`, and
  `call_method` require `sessionId`.
- `disconnect` ends the session.
- Firmware should reject session-scoped requests with an unknown or expired
  `sessionId`.
- When Gateway has an active runtime session and a session teardown or fresh
  connect attempt ends with `invalid_session`, `timeout`, `port_not_found`,
  `port_in_use`, or `transport_closed`, Gateway must clear its local session
  view. This does not prove Firmware observed disconnect; it prevents Gateway
  from keeping a session it can no longer confirm.

Implemented: `get_status`, `identify_device`, `connect`, `disconnect`,
`get_capabilities`, `get_accounts`, `get_policy`, `get_approval_history`, the
`call_method` runtime skeleton, explicit local Gateway device selection, and
local Gateway caching of discovered devices. The current `call_method` skeleton
enforces state and session gates, keeps unknown methods rejected, recognizes Sui
`sign_transaction` only for rejected policy-decision smoke against the active
stored default-reject policy, and records bounded persistent approval-history
metadata for those method decisions; it is not signing support.

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
request that currently reports Sui account identity with `methods: []`.
`get_accounts` is implemented as a read-only, session-scoped identity request
for the Sui Ed25519 account at index 0 in the `provisioned` state.
`get_policy` is implemented as a read-only, session-scoped summary of the
committed active policy; it is metadata only and not a policy update surface.
The normal product flow still installs the DEV_PROFILE default-reject policy.
`get_approval_history` is implemented as a read-only, session-scoped
view of Firmware-owned persistent decision metadata. `call_method` exists only
as a session-scoped runtime skeleton: unknown methods are rejected, while Sui
`sign_transaction` is recognized only for restricted-transfer policy-decision
smoke and still returns a rejected method result. No signing method is
implemented or advertised. Hardware smoke must be rerun for the `get_policy`,
`get_approval_history`, and policy-store-backed `call_method` paths.

## Device Discovery And Selection

Gateway discovers Firmware candidates by scanning supported transports and
calling `get_status` only on likely candidates. Gateway must avoid blind writes
to unrelated ports or devices.

USB discovery writes a `get_status` handshake only to candidate serial ports
selected from currently observed USB metadata. A stored port path is only a
hint; it must be rechecked against current port metadata before any write.

Gateway must not silently change the active device after discovery. Even when
one Firmware candidate is found, Gateway should ask the device to show an
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

Gateway can ask whether Firmware is available and what status Firmware reports.

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

- `unprovisioned`: root signing material, active policy, and local PIN verifier are not present.
- `provisioning`: local provisioning is in progress.
- `provisioned`: root signing material, active policy, and local PIN verifier are present.
- `locked`: the provisioning state cannot be used until the device is unlocked.
- `error`: Firmware detected persistent-material inconsistency and is failing closed.

`provisioning.state` reports only the Firmware's provisioning state. It is not
signing readiness, it does not prove that signing APIs exist, and it does not
authorize Gateway to make policy decisions. Gateway must preserve and
display the value without treating it as authority.

The current StackChan CoreS3 target persists `unprovisioned` and `provisioned`
and may report `error` when the persisted state and material records disagree.
It may report `provisioned` only when `prov_state`, the device-local root
material blob, a committed active policy record, and the local PIN verifier all
exist. The current product flow installs the default-reject policy. It does not
use `locked` because no unlock model is
implemented. Source-level DEV_PROFILE recovery phrase display, device-local
mnemonic recovery entry, persistent root material, active policy storage, local
PIN verifier storage, local reset, and read-only `get_accounts` Sui account
derivation are implemented. USB/Gateway/MCP mnemonic import, policy update, and
signing APIs are not implemented.

For DEV_PROFILE upgrade compatibility, a target that boots with the previous
development shape (`prov_state = provisioned` and valid root material, but no
policy record) may initialize the default-reject active policy before reporting
`provisioned`. If that initialization fails, Firmware must fail closed instead
of reporting normal `provisioned`. Existing DEV_PROFILE devices without the
local PIN verifier are not migrated and fail closed until reprovisioned.

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
authentication, wipe root material, active policy, local-auth verifier, and
runtime session, and return to `unprovisioned`. Implementations that record an
internal reset-pending marker before destructive wipe starts can resume an
interrupted reset at boot. Wrong authentication, timeout, or cancel preserves
existing material. Reset authentication lockout is target-local state, not a
protocol state, and must not create a host-triggered recovery path. A target may
offer a device-local, PIN-less, destructive erase-only recovery from
material/state consistency `error` when the PIN verifier may be unreadable, but
that path still must not be exposed as a USB/Gateway/MCP request and must not
read, export, repair, or unlock stored material.

## Identify Device

Gateway can ask Firmware to show a short temporary identification code. This is
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
    "code": "1234",
    "durationMs": 10000
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

Identification codes are four decimal digits. Identification display duration
must be a positive integer no greater than `30000` milliseconds.

Identification display is Firmware-owned temporary UI. Gateway may stop waiting
earlier than the requested display duration; there is no cancel message.

Identification display is temporary UI. Firmware must return to the previous
device state after the display duration or when another request replaces the
temporary layer.

## Connect

Gateway opens a communication session by sending `connect`. Connect requires
Firmware-owned device-local approval every time. Connect is not signing approval
and does not authorize signing.

Request:

```json
{
  "id": "req_connect_001",
  "version": 1,
  "type": "connect",
  "params": {
    "gatewayName": "Agent-Q Gateway",
    "approvalTimeoutMs": 30000
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
- `approvalTimeoutMs` is a positive integer with maximum `60000`.
- Default `approvalTimeoutMs` when Gateway omits it is `30000`.

Approved response:

```json
{
  "id": "req_connect_001",
  "version": 1,
  "type": "connect_result",
  "status": "approved",
  "sessionId": "session_...",
  "sessionTtlMs": 1800000,
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
- `connect_device` must not approve from Gateway-local session memory without
  contacting Firmware. Every `connect_device` call sends Firmware `connect`;
  Firmware remains the only authority that can issue a fresh `sessionId`.
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
- `sessionTtlMs` is Firmware-owned. Firmware may end a session earlier (for
  example on reboot) regardless of the advertised TTL. `sessionTtlMs` is a
  uint32 millisecond value; Gateway treats a `connect_result` whose
  `sessionTtlMs` is not a positive integer within the uint32 range
  (`1`..`4294967295`) as a malformed response.
- Approving a new connect replaces any previously active Firmware session.
- A Gateway runtime session is held in memory only. Gateway must not persist
  `sessionId` to disk. `sessionId` is a Firmware-issued token kept internal to
  Gateway; Gateway must not return it to untrusted MCP clients.
- Gateway restart and explicit disconnect end Gateway's view of the session;
  Firmware reboot ends the session on the device. Gateway restart clears only
  Gateway's in-memory record. Firmware cannot observe a Gateway restart and
  keeps its active session until its TTL, a reboot, an explicit disconnect, or
  replacement by a new approved connect.
- Firmware targets may clear an active session earlier when the transport link
  is lost. On StackChan CoreS3, USB connected means USB host SOF is observed by
  `usb_serial_jtag_is_connected()`. It does not prove Gateway is running or that
  the serial port is open. Cable removal, host suspend, or SOF loss can clear
  the Firmware RAM session by policy.
- Gateway TTL checks are local guards; Firmware remains the session authority.
  Gateway evicts an expired runtime session lazily, on the next access after
  `connectedAt + sessionTtlMs`, not on a timer.
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
- Firmware validates only the session lifecycle for `disconnect`; persistent
  material readiness is not a prerequisite. If material inconsistency already
  cleared the session, Firmware returns `invalid_session` rather than
  `invalid_state`.
- Firmware returns `invalid_session` when `sessionId` is missing, expired,
  unknown, or does not match the active Firmware session.

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

Gateway can ask which chains and methods Firmware supports.

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
  ]
}
```

Rules:

- `get_capabilities` is session-scoped and requires `sessionId`.
- Firmware returns capabilities only when `provisioning.state` is `provisioned`
  and persistent material, including root material, active policy, and local PIN
  verifier, is consistent. Before that it returns
  `invalid_state`.
- A missing, expired, or mismatched session returns `invalid_session`; an
  expired session is also cleared.
- The current StackChan CoreS3 target advertises Sui Ed25519 account identity
  only: account 0 at `m/44'/784'/0'/0'/0'`. `methods` is empty because
  no concrete `call_method` signing method, physical approval integration, or
  signing implementation exists.
- Gateway validates the response strictly, rejects unknown chains, unsupported
  account schemes or derivation paths, non-empty/unknown method lists,
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
  persistent material, including root material, active policy, and local PIN
  verifier, is consistent. Before that it returns `invalid_state`.
- The request requires `sessionId`. A missing, expired, or mismatched session
  returns `invalid_session`; an expired session is also cleared.
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
  `get_accounts` reads identity only; capability `methods` remains empty until
  signing methods are implemented.

## Policy Summary

`get_policy` is a session-scoped read-only request that returns public metadata
for the active Firmware-owned policy provider used by `call_method`. It does not
return policy secrets, signing material, or an editable policy document.

Request:

```json
{
  "id": "req_policy",
  "version": 1,
  "type": "get_policy",
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
    "policyId": "sha256:4d180eb74c192a7952def9d3932128bd91dac4ebbe9fe96e21eeb32671f441ab",
    "defaultAction": "reject",
    "ruleCount": 0
  }
}
```

Rules:

- Firmware returns a policy summary only when `provisioning.state` is
  `provisioned`, persistent material is consistent, a committed active policy
  record exists, and the request has a matching active session.
- Corrupt or unreadable active policy is a persistent-material consistency
  error. Missing active policy is migrated only for the documented DEV_PROFILE
  legacy shape where `prov_state = provisioned` and root material is valid;
  outside that compatibility path, missing policy is also a consistency error.
  Firmware must fail closed instead of continuing to report a normal
  `provisioned` state when the policy cannot be made active.
- `policyId` is the lowercase SHA-256 identifier for the canonical stored
  policy record. It is metadata for drift detection, not an authorization token.
- The current StackChan CoreS3 target supports only `agentq.policy.v0`,
  `defaultAction: "reject"`, and a bounded `ruleCount` summary. The normal
  product flow still installs `ruleCount: 0`; custom policy update
  authorization and full policy content exposure are not implemented.
- Gateway validates the response strictly, rejects secret-like fields and any
  unexpected `sessionId`, and does not evaluate policy.
- The Gateway MCP `get_policy` tool never exposes the session id.

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
      "eventKind": "method_decision",
      "decisionKind": "policy_rejected",
      "confirmationKind": "policy",
      "chain": "sui",
      "method": "sign_transaction",
      "reasonCode": "policy_rejected",
      "payloadDigest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "policyHash": "sha256:4d180eb74c192a7952def9d3932128bd91dac4ebbe9fe96e21eeb32671f441ab",
      "ruleRef": "default"
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
- Current StackChan CoreS3 source records only validated `policy_rejected`
  decisions from the `call_method` skeleton. Invalid parameter, malformed
  transaction, and unsupported-method errors are not persisted as approval
  history. Future signing work may add `policy_approved`, `method_error`,
  `user_approved`, `user_rejected`, and `user_timeout` records only when those
  decision paths exist.
- Approval-history persistence is part of the terminal decision contract for
  decisions that are recorded. If Firmware cannot persist a required history
  record or its write budget is exhausted, `call_method` returns the top-level
  `history_error` protocol error instead of a `method_result`.
- Firmware rate-limits persistent history writes to reduce flash wear. The
  limit is Firmware-owned and does not authorize Gateway to retry unbounded
  signing or method requests.
- History records must not store or return raw `txBytes`, full decoded
  transactions, session ids, raw request ids, gateway names, mnemonic text,
  seed, private key material, PINs, or complete policy documents.
- Gateway validates the response strictly, rejects secret-like fields and any
  unexpected `sessionId`, preserves protocol integers as strings, and does not
  evaluate policy or signing safety.
- The Gateway MCP `get_approval_history` tool never exposes the session id.

## Method Request

Gateway calls supported methods by name through `call_method`.

The current `call_method` implementation is a runtime skeleton with one internal
Sui `sign_transaction` policy-decision path. Firmware
validates the protocol envelope enough to identify the request, then enforces
`provisioned` state, setup/pending busy gates, and a matching active session.
After those gates pass, Firmware validates the `chain`, `method`, and `params`
field shape and size. StackChan CoreS3 keeps that validation in a host-tested
helper so JSON non-string values cannot be accepted through ArduinoJson fallback
semantics. Unknown methods still return `method_result` with `status: "rejected"`
and `error.code: "unsupported_method"`.

Sui `sign_transaction` is recognized only for policy-decision smoke. It accepts
`params.network` as `mainnet`, `testnet`, `devnet`, or `localnet`, and
`params.txBytes` as canonical base64 bounded by the current Firmware JSONL
request envelope. The current bound is `params` JSON up to 600 UTF-8 bytes,
with `txBytes` up to 384 decoded bytes and 512 canonical base64 characters.
Firmware decodes only the restricted SUI transfer shape documented in
[Implementation Status](../docs/IMPLEMENTATION_STATUS.md), adapts those facts
into the Firmware-owned policy runtime, and returns a rejected method result.
The current active stored policy is default reject, so valid supported
transactions return `policy_rejected` after the corresponding approval-history
record is persisted; if that required history write fails or is rate-limited,
Firmware returns top-level `history_error`. A corrupt or unreadable active policy
fails closed as a persistent-material consistency error before normal
session-scoped methods are available; missing active policy is migrated only for
legacy root-only DEV_PROFILE devices. Malformed BCS returns
`malformed_transaction`; unsupported transaction shapes return
`unsupported_transaction`. If a future test policy yields `sign` or `ask`, this
runtime still returns `policy_action_not_implemented`. No signature, physical
approval, or capability advertisement is connected to this runtime path yet.

Firmware must not advertise `sign_transaction` in `get_capabilities` until Sui
txBytes decoding, policy evaluation, negative parser fixtures, physical approval
where required, and signing are all implemented and connected to the runtime
request path. The current
restricted Sui transaction facts parser, Sui method adapter, stored-policy
provider boundary, and policy evaluator are Firmware-internal source
foundations; they do not make `call_method` a signing API.

Policy evaluation is currently a Firmware common-source foundation. It accepts
already extracted transaction facts, loads the stored active policy through a
Firmware-owned provider boundary, applies a declarative deny-by-default
policy model over allowlisted namespace/field facts, and returns an internal
`sign`, `reject`, or `ask` decision. The common evaluator owns only the shared
`common.*` policy fields; chain-specific field identifiers, descriptor
enablement, and transaction meaning stay in the corresponding method adapter.
The common evaluator does not decode Sui, EVM, or Solana transaction semantics.
That
decision is not a signature, does not update device state, does not trigger
physical approval yet, and is not exposed through Gateway or MCP as authority.
Missing or invalid active policy providers fail closed; in normal boot-time
state handling that condition is a persistent-material consistency error, and
any late provider failure is mapped to `policy_error`. Sui txBytes do not carry
network identity; future runtime integration must supply network context outside
the txBytes before evaluating network criteria. In the current schema, `sign`
and `ask` rules with no criteria are invalid; broad allow behavior must be
modeled explicitly in a later policy version if it is ever supported.

Request:

```json
{
  "id": "req_006",
  "version": 1,
  "type": "call_method",
  "sessionId": "session_001",
  "chain": "sui",
  "method": "sign_transaction",
  "params": {
    "network": "devnet",
    "txBytes": "AA..."
  }
}
```

Current policy-decision response for the normal default-reject policy:

```json
{
  "id": "req_006",
  "version": 1,
  "type": "method_result",
  "status": "rejected",
  "error": {
    "code": "policy_rejected",
    "message": "The request was rejected by device policy."
  }
}
```

Current response when the active policy provider fails after normal state and
session gates:

```json
{
  "id": "req_006",
  "version": 1,
  "type": "method_result",
  "status": "rejected",
  "error": {
    "code": "policy_error",
    "message": "Active policy is unavailable."
  }
}
```

Current method result status:

- `rejected`

Designed future method result statuses, not accepted by the current skeleton
parser:

- `approved`
- `requires_physical_approval`
- `timed_out`
- `error`

## Admin Methods

Admin is not a separate protocol. Admin actions are namespaced methods exposed
through capabilities in the shared protocol. Chain signing methods continue to
use `chain` plus `method`; admin/write methods must not overload `chain` with a
control namespace or route through a chain adapter. Like `get_capabilities` and
`call_method`, these admin methods are designed but not yet implemented.
`get_accounts` is implemented as a read-only identity request and does not
perform any admin or signing action.

Example methods:

- `propose_policy_update`
- `propose_key_generate`
- `propose_key_import`

Firmware must physically approve write methods before saving changes.

### Designed Future: `propose_policy_update`

`propose_policy_update` is the planned policy-write method. It is not
implemented and must not be advertised in `get_capabilities` until the Firmware,
Gateway/Admin, state model, storage, UI approval, and tests are all connected.

The method is a proposal, not a setter. Gateway or Admin may submit a bounded
policy document, but Firmware remains the authority that validates the document,
shows device-local approval, commits the active policy, and reports the result.

Planned request shape:

```json
{
  "id": "req_policy_update",
  "version": 1,
  "type": "call_method",
  "sessionId": "session_001",
  "methodNamespace": "admin",
  "method": "propose_policy_update",
  "params": {
    "policy": {
      "schema": "agentq.policy.v0",
      "defaultAction": "reject",
      "rules": [
        {
          "id": "reject-sui-mainnet-transfer",
          "chain": "sui",
          "method": "sign_transaction",
          "action": "reject",
          "criteria": [
            {
              "field": "common.network",
              "op": "eq",
              "value": "mainnet"
            }
          ]
        }
      ]
    }
  }
}
```

`methodNamespace: "admin"` is a planned shared-protocol namespace for
Firmware-owned administrative proposal methods. It is not implemented today.
Admin methods must reject a `chain` field; chain-scoped signing methods must
continue to use `chain` and must not use `methodNamespace`.

Policy document rules for the planned first version:

- Wire format: JSON inside the existing JSONL protocol envelope. Firmware must
  parse the JSON into a bounded internal policy AST before validation or
  storage. The wire JSON is not stored directly.
- The future protocol handler must enforce raw JSONL envelope size before
  deserialization. Target-local proposal parser source may additionally bound
  the serialized policy object after deserialization; that check is not a
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
- The policy schema may define `reject`, `ask`, and `sign`, but Firmware must
  reject any proposed action it cannot enforce in the current runtime. A policy
  update must not store unsupported `ask` or `sign` rules for future activation.
  Disabled policy drafts are out of scope for this version.
- A `reject` rule may have zero criteria. `ask` and `sign` rules require at
  least one criterion.
- A rule may contain at most 8 criteria.
- Criterion `field` is a bounded namespace/field id such as `common.network` or
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
  Rego, CEL, JSONPath, or arbitrary code execution.

Planned state and authorization rules:

- `unprovisioned`, `provisioning`, `error`, and `locked` reject policy update
  proposals with the state error defined for unavailable methods.
- `provisioned` plus a matching active session may accept a proposal for
  Firmware validation.
- A valid proposal enters a Firmware-owned pending policy-update state. The
  pending state is not a protocol state setter and is not derived from UI object
  lifetime.
- A second policy update proposal while one is pending is rejected with `busy`.
- Device-local approval is required before commit. For the current display
  target, the intended approval model is local PIN verification plus an
  on-device summary showing policy id/hash, rule count, default action, affected
  chains/methods, and highest-risk action (`sign`, `ask`, or `reject`). A future
  display-confirmed diff may strengthen this, but the first implementation must
  not rely on host-only confirmation.
- During pending approval, read-only session methods may remain available only
  if they do not dismiss or mutate the pending state. `call_method` and nested
  policy updates must return `busy` while a policy update is pending or
  committing.
- `get_policy` returns the committed active policy only. It must not include or
  imply the pending proposal unless a separate future review API is specified.
- `disconnect` may perform session cleanup except during the commit critical
  section, where Firmware may return `busy`.

Planned storage and rollback rules:

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
  erased. If a legacy `policy_v0` record is selected while pending-owned modern
  residue exists, Firmware must clean that residue before starting a new modern
  policy write or reject the write with the legacy policy still active.
- On ambiguous boot state, Firmware selects the newest valid committed slot
  unless a valid pending marker identifies an interrupted write target. Present
  but invalid commit metadata without that pending marker is a
  persistent-material consistency error rather than silent rollback.
- DEV_PROFILE slot selection is not rollback protection. USER_PROFILE policy
  storage requires secure anti-rollback or monotonic commit protection before it
  can claim rollback resistance.
- Local reset and error-state erase wipe all policy slots and policy metadata.

Planned response outcomes:

- `applied`: Firmware validated, approved, committed, and activated the new
  policy.
- `rejected`: local user rejected the proposal.
- `timed_out`: local approval expired with no change.
- `invalid_policy`: Firmware rejected the proposal before approval or commit.
- `storage_error`: Firmware could not commit the new policy; the old policy
  remains active unless Firmware reports a persistent-material consistency
  error on an ambiguous state.
- `busy`: another sensitive local flow or policy update is active.

Policy update history:

- Firmware must record policy update proposal outcomes as approval-history
  metadata once that decision path exists.
- Policy-update outcome history is part of the terminal-result contract. The
  implementation must not report `applied` unless the committed policy and the
  corresponding history record are both durable. If required history cannot be
  persisted, Firmware leaves the previous active policy unchanged and reports
  the failure instead of silently applying or silently omitting the record.
- History records may include sequence, uptime, event kind, result, policy
  hash/id, rule count, highest-risk action, and reason code.
- History records must not store raw policy documents, full rule content,
  session ids, request ids, gateway names, PINs, mnemonic text, seed, or private
  key material.
