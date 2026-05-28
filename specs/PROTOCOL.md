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
- supported chains and methods
- addresses and public keys
- method requests and method results

Chain-specific requests must fit into the supported method list instead of
creating separate product-level protocols.

## Roles

Agent-Q Gateway:

- exposes MCP tools
- serves the local Admin Page
- sends protocol messages to Firmware
- relays Firmware responses
- does not store keys
- does not make signing or policy decisions

Agent-Q Firmware:

- stores keys and policies
- evaluates signing requests
- asks for physical approval when required
- signs, rejects, or times out requests
- stores approved admin changes

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

M1 protocol error codes:

- `invalid_json`
- `invalid_id`
- `invalid_code`
- `invalid_duration`
- `unsupported_version`
- `unsupported_type`
- `busy`
- `timeout`

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
- `connect` starts a session.
- The first `connect` from a Gateway should require physical approval.
- `get_capabilities`, `get_accounts`, and `call_method` require `sessionId`.
- `disconnect` ends the session.
- Firmware should reject session-scoped requests with an unknown or expired
  `sessionId`.
- Gateway should treat disconnect, timeout, transport close, or Firmware reboot
  as the end of the session.

M1 implements `get_status`, `identify_device`, explicit local Gateway device
selection, local Gateway caching of discovered devices, and a hardware
diagnostic request. Session messages remain protocol design, not implemented M1
behavior.

## Device Discovery And Selection

Gateway discovers Firmware candidates by scanning supported transports and
calling `get_status` only on likely candidates. Gateway must avoid blind writes
to unrelated ports or devices.

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

Gateway can ask whether Firmware is available and ready.

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
  }
}
```

Device states:

- `idle`: ready for read-only requests.
- `busy`: processing another request.
- `awaiting_approval`: physical approval UI is active.
- `locked`: device requires local unlock before sensitive actions.
- `error`: device is running but cannot currently serve requests.

M1 Firmware may emit only `idle`, `busy`, and `awaiting_approval`. Other states
are reserved for later behavior.

`deviceId` is a Firmware-generated UUID stored in device-local persistent
storage. It must not be derived from MAC address, USB serial number, account
public key, or signing key.

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

M1 identification codes are four decimal digits. M1 identification display
duration must be a positive integer no greater than `30000` milliseconds.

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

## Connect

Gateway must connect before calling account or method requests.

The first connection from a Gateway should require physical approval on
Firmware. Firmware may remember an approved Gateway according to local policy,
but Gateway cannot assume approval.

Request:

```json
{
  "id": "req_002",
  "version": 1,
  "type": "connect",
  "client": {
    "name": "Agent-Q Gateway",
    "origin": "local"
  }
}
```

Response:

```json
{
  "id": "req_002",
  "version": 1,
  "type": "connect_result",
  "status": "approved",
  "session": {
    "id": "session_001"
  }
}
```

Possible connect statuses:

- `approved`
- `rejected`
- `requires_physical_approval`
- `timed_out`
- `error`

## Disconnect

Gateway can disconnect and end the active session.

After disconnect, Gateway must call `connect` again before calling
session-scoped requests.

Request:

```json
{
  "id": "req_003",
  "version": 1,
  "type": "disconnect",
  "sessionId": "session_001"
}
```

Response:

```json
{
  "id": "req_003",
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
capabilities.

Example methods:

- `propose_policy_update`
- `propose_key_generate`
- `propose_key_import`

Firmware must physically approve write methods before saving changes.
