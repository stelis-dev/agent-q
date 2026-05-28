# Agent-Q Gateway

Agent-Q Gateway is the local process that exposes MCP tools and communicates
with Agent-Q Firmware.

Gateway does not store signing keys and does not make signing or policy
decisions. Firmware is the signing authority.

## MCP Tools

Device discovery tools:

- `scan_devices`
- `identify_devices`
- `select_device`
- `get_device_status`

Device registry and connection-session tools:

- `list_devices`
- `set_device_metadata`
- `connect_device`
- `disconnect_device`

`scan_devices` records discovered candidates but does not save an active
device. `identify_devices` asks candidate devices to display short codes.
`select_device` saves the user-selected device as the default active device or
as the active device for a named routing purpose.

`list_devices` returns Gateway-local registry state, including labels, purpose
assignments, and any in-memory connection session. `set_device_metadata`
updates a device's human-readable label. `connect_device` opens a
communication session by sending a Firmware connect request that requires
physical approval. `disconnect_device` ends the runtime session.

## Boundaries

- `label` is Gateway-local human-readable metadata. It is not a security
  boundary and not device authority.
- `purpose` is Gateway-local routing selection. It is not Firmware policy. The
  purpose name `default` is reserved and cannot be assigned in
  `activeDeviceIdsByPurpose`; the default device lives in `activeDeviceId`.
- A connection session opens a communication channel between Gateway and
  Firmware. It is not signing approval.
- A connection session does not authorize signing.
- A connection session does not prove which agent or upstream user produced a
  request.
- Session ids are held in Gateway memory only and are never returned to MCP
  clients. A Gateway restart or explicit disconnect ends Gateway's view of the
  session; a Firmware reboot ends it on the device. A Gateway restart clears
  only the local record — Firmware cannot observe it and keeps its session
  until its TTL, a reboot, a disconnect, or replacement by a new approved
  connect.
- While Gateway holds a non-expired runtime session, `connect_device` returns
  it from local memory without contacting Firmware and without re-approval. This
  is a local optimization and does not re-verify with Firmware; a session
  Firmware has already dropped surfaces as `invalid_session` on the next
  disconnect or session-scoped call.
- Gateway evicts an expired runtime session lazily, on the next access after
  its local TTL passes, not on a timer. Firmware remains the session authority.
- Not yet implemented: signing, policy evaluation, account discovery, public
  key discovery, Admin Page, and chain-specific transaction logic.

## MCP Output Boundary

MCP clients and agents are untrusted request sources. Gateway limits what its
MCP output can contain, but it does **not** judge agent or prompt intent and
does **not** claim to detect prompt injection. Concretely:

- Secret material (signing keys, seeds, mnemonics) is never produced, and the
  Firmware session token (`sessionId`) is kept inside Gateway and never returned
  to clients.
- Error output carries a stable `{ code, message, retryable }`. The `message` is
  a fixed, code-derived string; raw OS, serial, or Firmware error text is not
  forwarded. Unknown error codes collapse to `gateway_error`.
- Device-supplied display strings (`firmwareName`, `hardware`,
  `firmwareVersion`) are untrusted text. They are reduced to bounded, printable
  text when parsed from the device, not used as a trust signal. `deviceId` is a
  bounded safe identifier; a device that sends an unsafe one is rejected.
- `label` is a local display name supplied by the user; it is rejected if it is
  empty, too long, or contains control characters.
- The display-text and identifier rules are defined once, in `src/safe-text.ts`,
  and enforced at every boundary that handles untrusted text: the device wire
  response, the stored on-disk registry (which may be hand-edited), and the MCP
  output schema. A stored device record whose `deviceId` is unsafe is dropped on
  load; its display strings and port hint are sanitized, an invalid `label` is
  reset to null, and a malformed timestamp is replaced, so the stored registry
  cannot carry control characters or unsafe identifiers into MCP output.
- The public error policy (`src/public-error.ts`) is the single source for what
  any output boundary may emit: an allowlisted error `code` with its canonical
  message. Gateway core deliberately throws a raw `GatewayError` whose `message`
  may carry OS, serial, or Firmware text; safety comes from the output boundary,
  not from core pre-sanitizing. The contract is therefore that **every output
  adapter must project errors through `public-error.ts` before returning or
  logging them**. The MCP adapter does this in one place — its `run()` wrapper
  for results and `logToolDiagnostic` for stderr — and any future adapter (CLI,
  Admin/web API) must do the same. Diagnostic logging goes to stderr (never
  stdout, the MCP channel) and carries only the allowlisted `code`, its canonical
  message, and `retryable`; raw device/OS/Firmware text is never written to a log,
  even sanitized. Operator-controlled local config (such as the config file path)
  is not untrusted request input and may be logged as-is.

This is output hygiene at an untrusted boundary, not intent detection. All
authority over what may be signed remains with Firmware policy.

## Commands

Requires Node.js 22 or newer.

Install dependencies:

```sh
npm install
```

Build:

```sh
npm run build
```

Test:

```sh
npm test
```

The automated tests use mocked Gateway drivers and do not exercise the live
`SerialPortUsbDriver` path. When hardware is available, run a manual USB smoke
check for `scan_devices`, `get_device_status`, `identify_devices`,
`display_signal`, `connect_device`, and `disconnect_device` after serial
transport changes.

Run the stdio MCP server:

```sh
node dist/bin/agent-q.js
```

The intended published command is `npx @stelis/agent-q`, but this package is
not published yet.
