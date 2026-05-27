# Agent-Q Communication Protocol

This document defines the communication contract between Agent-Q Gateway and
Agent-Q Firmware.

The protocol is intentionally small. It is inspired by wallet capability
discovery patterns, but it does not try to copy a full wallet standard.

## Scope

The protocol only needs enough structure for Gateway and Firmware to agree on:

- connection approval
- Firmware status
- supported chains and methods
- addresses and public keys

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

All messages should include:

- `id`: request correlation id
- `type`: message type
- `version`: protocol version

Example:

```json
{
  "id": "req_001",
  "version": 1,
  "type": "get_status"
}
```

## Session Flow

Protocol interaction has a clear start and end.

```text
get_status
  -> connect
    -> get_capabilities
    -> get_accounts
    -> call_method*
  -> disconnect
```

Flow rules:

- `get_status` can be called before a session exists.
- `connect` starts a session.
- The first `connect` from a Gateway should require physical approval.
- `get_capabilities`, `get_accounts`, and `call_method` require `sessionId`.
- `disconnect` ends the session.
- Firmware should reject session-scoped requests with an unknown or expired
  `sessionId`.
- Gateway should treat disconnect, timeout, transport close, or Firmware reboot
  as the end of the session.

## Status

Gateway can ask whether Firmware is available and ready.

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
  "status": "ready",
  "firmware": {
    "name": "Agent-Q Firmware",
    "target": "stackchan-cores3",
    "version": "0.0.0"
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

Gateway can ask which chains and methods the Firmware supports.

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
