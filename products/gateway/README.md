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

Run the stdio MCP server:

```sh
npx @stelis/agent-q
```
