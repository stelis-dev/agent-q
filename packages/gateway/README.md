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
- `get_capabilities`
- `get_accounts`
- `get_policy`
- `get_approval_history`
- `call_method`
- `propose_policy_update`

`scan_devices` records discovered candidates but does not save an active
device. `identify_devices` asks candidate devices to display short codes.
`select_device` saves the user-selected device as the default active device or
as the active device for a named routing purpose.

`list_devices` returns Gateway-local registry state, including labels, purpose
assignments, and any in-memory connection session. `set_device_metadata`
updates a device's human-readable label. `connect_device` opens a communication
session by sending a Firmware connect request that requires device-local
approval when Gateway does not already hold a valid RAM session for the device.
If Gateway already has a session, it validates that session with a
session-scoped read-only request and reuses it when Firmware accepts it. The
current StackChan CoreS3 target accepts `connect` only after persistent root
material and material-backed `provisioned` state exist. `disconnect_device` ends
the runtime session when one exists. `get_capabilities` and `get_accounts` are
read-only session-scoped tools. `call_method` is the shared method path; the current
runtime keeps unknown methods rejected and recognizes Sui `sign_transaction`
only for rejected policy-decision smoke. It is not signing support.
`get_policy` and `get_approval_history` are read-only session-scoped tools.
`propose_policy_update` is a session-scoped proposal path: Gateway and MCP do
not store, apply, or decide policy, and Firmware requires device-local approval
before committing a bounded reject-policy proposal.

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
  session. A live USB scan that no longer observes the device also clears
  Gateway's RAM session mirror for that device. A Firmware reboot ends the
  session on the device. A Gateway restart clears only the local record -
  Firmware cannot observe it and keeps its RAM session until target policy
  clears it, such as USB link loss, reboot, explicit disconnect, material-error
  cleanup, or replacement by a new approved connect.
- `connect_device` reuses an existing Gateway-local runtime session only after a
  Firmware session-scoped read-only request confirms that the session is still
  valid. Firmware remains the only authority that can issue a fresh session, and
  a fresh Firmware `connect` request still requires device-local approval.
- Not yet implemented: concrete signing methods, signing-request physical
  approval, full Admin policy editing beyond the current reject-policy proposal
  template, and chain-specific signing transaction logic beyond the current Sui
  policy-decision smoke.

## Admin Page

Gateway serves a local Admin Page for device discovery, connection, active
policy summary, approval history, and the current reject-policy proposal
template. The Admin Page is not a policy authority: it submits bounded requests
through Gateway core, and Firmware validates proposals, requires device-local
approval, commits policy, and records terminal results.

## Package Entrypoints

The package exposes two library entrypoints:

- `@stelis/agent-q` and `@stelis/agent-q/client` expose the device-facing
  Gateway core factory. This entrypoint does not import MCP or Admin adapters.
- `@stelis/agent-q/mcp` exposes the MCP adapter.

The `agent-q` binary starts one local Gateway process that shares Gateway core
state between stdio MCP tools and the local Admin Page. No provider package or
provider API is implemented yet.

## Gateway Output Boundary

MCP clients, agents, and Admin Page requests are untrusted request sources.
Gateway limits what its output can contain, but it does **not** judge agent or
prompt intent and does **not** claim to detect prompt injection. Concretely:

- Secret material (signing keys, seeds, recovery phrases, mnemonics) is never
  produced by Gateway and is never returned to MCP clients. The Firmware
  session token (`sessionId`) is kept inside Gateway and never returned to
  clients.
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
  logging them**. The MCP adapter does this in one place - its `run()` wrapper
  for results and `logToolDiagnostic` for stderr - and the Admin HTTP API uses
  the same public-error projection before returning JSON. Diagnostic logging
  goes to stderr (never stdout, the MCP channel) and carries only the
  allowlisted `code`, its canonical message, and `retryable`; raw
  device/OS/Firmware text is never written to a log, even sanitized.
  Operator-controlled local config (such as the config file path) is not
  untrusted request input and may be logged as-is.

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
`connect_device`, `get_capabilities`, `get_accounts`, `get_policy`,
`get_approval_history`, `call_method`, and `disconnect_device` after serial
transport changes. Policy-update smoke is a separate opt-in check that mutates
the device's active policy; run it only on a development device whose policy can
be changed. When more than one Agent-Q device is connected, set
`AGENTQ_HW_POLICY_UPDATE_DEVICE_ID` so the mutating smoke cannot select a device
by USB scan order.

Run the local Gateway:

```sh
node dist/bin/agent-q.js
```

The same process exposes stdio MCP tools and the local Admin Page, so Gateway
RAM session state is shared between MCP requests and Admin Page requests.

Use a different local Admin Page port:

```sh
node dist/bin/agent-q.js --port 8788
```

The intended published command is `npx @stelis/agent-q`, but this package is
not published yet.
