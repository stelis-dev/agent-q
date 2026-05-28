# Agent-Q Gateway

Agent-Q Gateway is the local process that exposes MCP tools and communicates
with Agent-Q Firmware.

M1 exposes only device discovery, identification, selection, and status tools:

- `scan_devices`
- `identify_devices`
- `select_device`
- `get_device_status`

`scan_devices` records discovered candidates but does not save an active device.
`identify_devices` asks candidate devices to display short codes. `select_device`
saves the user-selected device as active.

Gateway does not store signing keys and does not make signing or policy
decisions.

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
check for `scan_devices`, `get_device_status`, `identify_devices`, and
`display_signal` after serial transport changes.

Run the stdio MCP server:

```sh
node dist/bin/agent-q.js
```

The intended published command is `npx @stelis/agent-q`, but this package is
not published yet.
