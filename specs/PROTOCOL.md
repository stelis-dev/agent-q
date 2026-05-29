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
- `invalid_setup_step`
- `unsupported_version`
- `unsupported_type`
- `busy`
- `rejected`
- `timeout`
- `storage_error`
- `rng_error`
- `ui_error`
- `generation_error`

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
- `connect` establishes a session and requires physical approval.
- `get_capabilities`, `get_accounts`, and `call_method` require `sessionId`.
- `disconnect` ends the session.
- Firmware should reject session-scoped requests with an unknown or expired
  `sessionId`.
- When Gateway has an active runtime session and a disconnect attempt ends with
  `invalid_session`, `timeout`, `port_not_found`, `port_in_use`, or
  `transport_closed`, Gateway must clear its local session view. This does not
  prove Firmware observed disconnect; it prevents Gateway from reusing a session
  it can no longer confirm.

Implemented: `get_status`, `identify_device`, `connect`, `disconnect`,
`start_provisioning`, `cancel_provisioning`, explicit local Gateway device
selection, local Gateway caching of discovered devices, and a hardware
diagnostic request.

Source-level implementation added and firmware build verified, with hardware
smoke still pending: `provisioning_setup_check`, `generate_recovery_phrase`,
and `confirm_recovery_phrase_backup`.

`connect` and `disconnect` establish and end a runtime communication session
between Gateway and Firmware. A connection session does not authorize signing,
does not prove agent identity, and does not change Firmware policy.

Designed but not yet implemented: the session-scoped requests
`get_capabilities`, `get_accounts`, and `call_method`.

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
- `awaiting_approval`: physical approval UI is active.
- `locked`: device requires local unlock before sensitive actions.
- `error`: device is running but cannot currently serve requests.

The current Firmware emits `idle`, `busy`, and `awaiting_approval`. It reports
`busy` while device-only setup material is displayed, and also uses `busy` as an
error code for requests that cannot run while another operation owns the device
UI. Other states are reserved for later behavior.

`deviceId` is a Firmware-generated UUID stored in device-local persistent
storage. It must not be derived from MAC address, USB serial number, account
public key, or signing key.

`firmwareName` is a descriptive label for display and diagnostics. It is not a
security boundary and must not be treated as proof that the device is trusted.

Provisioning states:

- `unprovisioned`: root signing material is not present.
- `provisioning`: local provisioning is in progress.
- `provisioned`: root signing material is present.
- `locked`: the provisioning state cannot be used until the device is unlocked.

`provisioning.state` reports only the Firmware's provisioning state. It is not
signing readiness, it does not prove that account or signing APIs exist, and it
does not authorize Gateway to make policy decisions. Gateway must preserve and
display the value without treating it as authority.

The current StackChan CoreS3 target persists and reports only
`unprovisioned` and `provisioning`. It must not report `provisioned` until root
signing material exists, and it does not use `locked` because no unlock model is
implemented. Source-level DEV_PROFILE recovery phrase display exists only as a
volatile setup step. Runtime mnemonic import, persistent user signing material,
account derivation, and signing APIs are not implemented.

Device metadata strings are untrusted input and Gateway bounds them when
parsing a response:

- `deviceId`: a safe identifier of `[A-Za-z0-9_.-]`, 1-128 characters. A
  response whose `deviceId` is outside this set is rejected as malformed.
- `firmwareName`, `hardware`, `firmwareVersion`: display strings. Gateway keeps
  printable ASCII only and caps length (64, 64, and 32 characters), dropping
  control characters and newlines. These are display values, not a trust
  signal, so they are sanitized rather than rejected.

## Provisioning State Transitions

Provisioning state transition requests let Firmware enter or cancel local setup
state. They do not create, import, store, export, or reveal mnemonics, seeds,
private keys, accounts, or policies.

These requests are sensitive write actions. Firmware must change state only
after physical approval on the device. Gateway must not treat the resulting
state as signing readiness, and agent-facing MCP tools must not expose these
write actions.

Provisioning state transition requests do not require `sessionId`. The physical
approval on Firmware is the authority for the state change; the host request is
only an untrusted prompt to show that approval UI.

The current implemented states for these requests are:

- `unprovisioned`
- `provisioning`

The current implementation must not set:

- `provisioned`, because no root signing material exists.
- `locked`, because no unlock model exists.

### Start Provisioning

Request:

```json
{
  "id": "req_start_setup_001",
  "version": 1,
  "type": "start_provisioning",
  "params": {
    "approvalTimeoutMs": 30000
  }
}
```

Request rules:

- `approvalTimeoutMs` is a positive integer with maximum `60000`.
- Default `approvalTimeoutMs` when omitted is `30000`.
- The request contains no mnemonic, seed, private key, import text, account
  data, or policy data.

Approved response:

```json
{
  "id": "req_start_setup_001",
  "version": 1,
  "type": "provisioning_result",
  "status": "started",
  "provisioning": {
    "state": "provisioning"
  }
}
```

If the user rejects or approval times out, Firmware returns the common `error`
shape with `rejected` or `timeout`, and the persistent provisioning state is
preserved. This does not mean volatile setup scratch is preserved. If a cancel
approval prompt interrupts a displayed recovery phrase, Firmware must wipe that
volatile phrase on rejection or timeout and the user must generate a new phrase
to continue.

If Firmware cannot persist the new state, it returns `storage_error` and the
previous provisioning state is preserved.

After `type`, `id`, and `version` are syntactically valid, Firmware checks the
source provisioning state before request parameters such as `approvalTimeoutMs`.
If Firmware is not `unprovisioned`, it returns `invalid_state` without showing
approval UI and preserves the current provisioning state.

### Cancel Provisioning

Request:

```json
{
  "id": "req_cancel_setup_001",
  "version": 1,
  "type": "cancel_provisioning",
  "params": {
    "approvalTimeoutMs": 30000
  }
}
```

Approved response:

```json
{
  "id": "req_cancel_setup_001",
  "version": 1,
  "type": "provisioning_result",
  "status": "canceled",
  "provisioning": {
    "state": "unprovisioned"
  }
}
```

If the user rejects or approval times out, Firmware returns the common `error`
shape with `rejected` or `timeout`, and the persistent provisioning state is
preserved. This does not mean volatile setup scratch is preserved. If a cancel
approval prompt interrupts a displayed recovery phrase, Firmware must wipe that
volatile phrase on rejection or timeout and the user must generate a new phrase
to continue.

After `type`, `id`, and `version` are syntactically valid, Firmware checks the
source provisioning state before request parameters such as `approvalTimeoutMs`.
If Firmware is not `provisioning`, it returns `invalid_state` without showing
approval UI and preserves the current provisioning state.

Canceling provisioning wipes setup scratch state before returning to
`unprovisioned`. Current StackChan CoreS3 source may hold a generated recovery
phrase only in RAM while still in `provisioning`; cancel must wipe that scratch
material before reporting success and must not return it to the host. If the
scratch wipe succeeds but storing `unprovisioned` fails, Firmware must still keep
the scratch wiped and report `storage_error`; the host must not assume the
previous displayed phrase remains usable.

While a provisioning approval UI is active, Firmware should return `busy` for
new UI-affecting or session-changing requests. `get_status` remains read-only
and must keep working without changing approval UI.

## Provisioning Setup Check v0

`provisioning_setup_check` is the first provisioning setup-step message. It
exists to verify the state gate and temporary setup UI before mnemonic
generation exists.

This request does not create, import, store, export, derive, or reveal
mnemonics, seeds, private keys, accounts, or policies. It does not move the
device to `provisioned`, does not make signing ready, and must not be exposed as
a normal agent-facing MCP signing tool.

The request is valid only while Firmware reports `provisioning.state` as
`provisioning`. After `type`, `id`, and `version` are syntactically valid,
Firmware checks this source state before request parameters such as
`approvalTimeoutMs`. If Firmware is in any other provisioning state, it returns
`invalid_state` without showing approval UI and preserves the current state.

Request:

```json
{
  "id": "req_setup_check_001",
  "version": 1,
  "type": "provisioning_setup_check",
  "params": {
    "approvalTimeoutMs": 30000
  }
}
```

Request rules:

- `approvalTimeoutMs` is a positive integer with maximum `60000`.
- Default `approvalTimeoutMs` when omitted is `30000`.
- The request contains no mnemonic, seed, private key, import text, account
  data, or policy data.
- The request does not require `sessionId`. Firmware state and physical device
  approval are the authority for this setup step.

Approved response:

```json
{
  "id": "req_setup_check_001",
  "version": 1,
  "type": "provisioning_setup_check_result",
  "status": "checked",
  "provisioning": {
    "state": "provisioning"
  }
}
```

If the user rejects or approval times out, Firmware returns the common `error`
shape with `rejected` or `timeout`, and the previous provisioning state is
preserved.

While a provisioning setup check approval UI is active, Firmware should return
`busy` for new UI-affecting or session-changing requests. `get_status` remains
read-only and must keep working without changing approval UI.

## Recovery Phrase Setup v0

`generate_recovery_phrase` asks Firmware to generate a 12-word BIP-39 recovery
phrase while local setup is active. This is a setup/admin protocol message, not
a normal MCP signing method.

The generated phrase is displayed on the device only. Firmware must not include
the phrase, entropy, seed, private key, account data, policy data, or import
text in any response. StackChan CoreS3 seeds an Agent-Q CSPRNG from early boot
entropy before HAL initialization; recovery phrase entropy must come from that
CSPRNG, not a late direct `esp_fill_random` call. Gateway must parse only the
bounded result metadata and must not expose this request as an agent-facing
signing tool.

This v0 flow is DEV_PROFILE setup scaffolding. It does not derive a seed, store
root signing material, create accounts, install policy, or move the device to
`provisioned`. USER_PROFILE generation remains blocked until the firmware
integrity and encrypted storage gates in `docs/SECURITY_MODEL.md` are satisfied.

The request is valid only while Firmware reports `provisioning.state` as
`provisioning`. After `type`, `id`, and `version` are syntactically valid,
Firmware checks this source state before request parameters such as
`approvalTimeoutMs`. If Firmware is in any other provisioning state, it returns
`invalid_state` without showing approval UI and preserves the current state.

Firmware owns recovery phrase scratch as a volatile setup substate, separate
from persistent `provisioning.state`, pending physical approval, and LVGL panel
state. The v0 substates are:

- `none`: no generated recovery phrase is valid in RAM.
- `displayed`: a phrase exists in RAM and is considered shown for backup.
- `backup_confirmation_pending`: the phrase display was accepted for backup
  confirmation and a physical confirmation prompt is active.

The UI panel is an output of this substate machine, not the authority for it.
Panel deletion or replacement is only an input that must transition
`displayed` to `none` by wiping or invalidating the volatile phrase.

Generate request:

```json
{
  "id": "req_generate_phrase_001",
  "version": 1,
  "type": "generate_recovery_phrase",
  "params": {
    "approvalTimeoutMs": 30000
  }
}
```

Request rules:

- `approvalTimeoutMs` is a positive integer with maximum `60000`.
- Default `approvalTimeoutMs` when omitted is `30000`.
- The request contains no mnemonic, seed, private key, import text, account
  data, or policy data.
- The request does not require `sessionId`. Firmware state and physical device
  approval are the authority for this setup step.
- If a generated phrase is already displayed for backup confirmation, Firmware
  returns `busy` rather than replacing it.

Approved generate response:

```json
{
  "id": "req_generate_phrase_001",
  "version": 1,
  "type": "recovery_phrase_result",
  "status": "displayed",
  "provisioning": {
    "state": "provisioning"
  }
}
```

After display, the phrase remains volatile setup scratch. The host knows only
that Firmware reports it displayed a phrase; the host does not learn the phrase.
The successful generate transition is `none` to `displayed`.

Backup confirmation request:

```json
{
  "id": "req_confirm_phrase_001",
  "version": 1,
  "type": "confirm_recovery_phrase_backup",
  "params": {
    "approvalTimeoutMs": 30000
  }
}
```

Request rules:

- The request is valid only in `provisioning`.
- Firmware must have recovery phrase scratch in the `displayed` substate and the
  phrase must not have been invalidated by display removal.
- If no phrase is pending confirmation, Firmware returns `invalid_setup_step`
  without opening approval UI.
- The request does not require `sessionId`.

Approved backup confirmation response:

```json
{
  "id": "req_confirm_phrase_001",
  "version": 1,
  "type": "recovery_phrase_result",
  "status": "confirmed",
  "provisioning": {
    "state": "provisioning"
  }
}
```

In v0, backup confirmation wipes the volatile phrase and still leaves the
device in `provisioning`; it is not proof that root material was persisted.
If the user rejects or approval times out, Firmware returns the common `error`
shape with `rejected` or `timeout` and wipes the volatile phrase. The user must
generate a new phrase to continue.
Accepting a backup confirmation request transitions `displayed` to
`backup_confirmation_pending`; approval, rejection, or timeout transitions
`backup_confirmation_pending` to `none` and always wipes the phrase.

While a recovery phrase is displayed, Firmware should keep `get_status`
available and report `device.state = busy`. It should also return `busy` for
UI-affecting requests that would hide or replace the setup display.
`cancel_provisioning` remains available and wipes scratch state before returning
to `unprovisioned`. A displayed phrase must have a finite display lifetime; when
the display expires, Firmware clears the setup panel and wipes the volatile
phrase.

Firmware must not keep recovery phrase scratch marked `displayed` after the
display is no longer visible. If the recovery phrase display panel is removed or
replaced while the scratch substate is `displayed`, Firmware must wipe or
invalidate the volatile phrase for new requests so a later
`confirm_recovery_phrase_backup` request cannot confirm material the user can no
longer see. The only allowed exception is the already-started physical
confirmation prompt that replaced a visible recovery phrase display after
validating `confirm_recovery_phrase_backup`; that prompt owns the
`backup_confirmation_pending` substate and must end by confirming and wiping the
phrase, or by rejecting/timing out and wiping it.

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

## Hardware Diagnostic Request

`display_signal` is a hardware diagnostic request for local smoke tests. It is
not a public Gateway/MCP signing API.

Request:

```json
{
  "id": "req_display_001",
  "version": 1,
  "type": "display_signal",
  "params": {
    "message": "Request received"
  }
}
```

Approved response:

```json
{
  "id": "req_display_001",
  "version": 1,
  "type": "display_signal_result",
  "status": "approved"
}
```

Rejected or timed-out response:

```json
{
  "id": "req_display_001",
  "version": 1,
  "type": "display_signal_result",
  "status": "rejected",
  "error": {
    "code": "timeout",
    "message": "Request timed out."
  }
}
```

The `display_signal` approval lifetime is Firmware-owned temporary UI. Gateway
is permitted to stop waiting earlier than the Firmware timeout; there is no
cancel message. A late physical response may be ignored by Gateway if the
transport request already timed out.

## Connect

Gateway opens a communication session by sending `connect`. Connect requires
physical approval on Firmware every time. Connect is not signing approval and
does not authorize signing.

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

- Establishing a session requires physical approval every time a Firmware
  `connect` request is sent. Firmware does not remember a previously approved
  Gateway.
- Reuse is a Gateway-local optimization, not a Firmware behavior. While Gateway
  holds a non-expired runtime session for the target device, a `connect_device`
  call returns that session from local memory without sending a Firmware
  `connect` request and without re-approval. The session was already physically
  approved when it was established. Reuse reflects Gateway's local view only:
  Gateway does not re-verify with Firmware and cannot detect Firmware-side
  session loss (for example after a reboot). Such loss surfaces as
  `invalid_session` on the next disconnect or session-scoped request.
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
- Gateway TTL checks are local guards; Firmware remains the session authority.
  Gateway evicts an expired runtime session lazily, on the next access after
  `connectedAt + sessionTtlMs`, not on a timer.
- Firmware should return `busy` for UI-affecting or session-changing requests
  (including `connect` and `disconnect`) while an approval UI or device-only
  setup material display is already open. `get_status` remains read-only and
  must not trigger or change approval UI.

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
  UI or device-only setup material display is active.
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
      "methods": [
        "sign_transaction",
        "sign_personal_message"
      ]
    }
  ]
}
```

## Accounts

Gateway can ask for addresses and public keys exposed by Firmware.

Request:

```json
{
  "id": "req_005",
  "version": 1,
  "type": "get_accounts",
  "sessionId": "session_001"
}
```

Response:

```json
{
  "id": "req_005",
  "version": 1,
  "type": "accounts",
  "accounts": [
    {
      "chain": "sui",
      "address": "0x...",
      "publicKey": {
        "scheme": "ed25519",
        "encoding": "base64",
        "value": "..."
      },
      "methods": [
        "sign_transaction",
        "sign_personal_message"
      ]
    }
  ]
}
```

## Method Request

Gateway calls supported methods by name.

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
    "txBytes": "..."
  }
}
```

Response:

```json
{
  "id": "req_006",
  "version": 1,
  "type": "method_result",
  "status": "approved",
  "result": {
    "signature": "..."
  }
}
```

Possible method result statuses:

- `approved`
- `rejected`
- `requires_physical_approval`
- `timed_out`
- `error`

## Admin Methods

Admin is not a separate protocol. Admin actions are methods exposed through
capabilities. Like `get_capabilities`, `get_accounts`, and `call_method`, these
admin methods are designed but not yet implemented.

Example methods:

- `propose_policy_update`
- `propose_key_generate`
- `propose_key_import`

Firmware must physically approve write methods before saving changes.
