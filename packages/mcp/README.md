# Agent-Q MCP

`@stelis/agent-q-mcp` provides the local Agent-Q MCP server, local Admin Page,
and `agent-q-sui-signer`.

Use this package when an MCP-capable agent needs to request signatures from an
Agent-Q device, or when a Sui CLI workflow needs an Agent-Q device as its
external signer.

Firmware remains the signing authority. MCP tools and CLI commands submit
requests; they do not store keys, apply policy, approve signing, or select the
device signing mode.

## Quick Start: MCP Server

Run the local MCP server:

```sh
agent-q
```

Typical agent flow:

```text
scan_devices
  -> identify_devices
  -> select_device
  -> connect_device
  -> get_capabilities
  -> get_accounts
  -> sign_transaction or sign_personal_message
  -> disconnect_device
```

Agents should treat every signing result as Firmware-authored device output.
They should not claim that a request was safe because the agent produced it, and
they should not infer user intent from a successful signature.

## Quick Start: Sui CLI External Signer

Register the Agent-Q signer with Sui CLI:

```sh
sui external-keys list-keys agent-q-sui-signer
sui external-keys add-existing "<KEY_ID>" agent-q-sui-signer
sui client switch --address <SUI_ADDRESS>
```

After that, normal Sui CLI commands that need the selected address can request
the signature from Agent-Q:

```sh
sui client transfer --object-id <OBJECT_ID> --to <TO_ADDRESS>
```

Sui CLI calls `agent-q-sui-signer` through its external signer JSON-RPC
stdin/stdout protocol. Agent-Q lists the Sui key from the connected device and
sends transaction signing requests to Firmware. The private key stays on the
device.

`agent-q-sui-signer` uses the active Sui CLI environment when it is `mainnet`,
`testnet`, `devnet`, or `localnet`. To set it explicitly:

```sh
agent-q-sui-signer configure --network testnet
```

For low-level scripts that already have unsigned transaction bytes:

```sh
agent-q-sui-signer --network testnet --tx-bytes <base64-unsigned-transaction>
```

## MCP Tools

- `scan_devices`
- `identify_devices`
- `select_device`
- `get_device_status`
- `list_devices`
- `set_device_metadata`
- `connect_device`
- `disconnect_device`
- `get_capabilities`
- `get_accounts`
- `policy_get`
- `get_approval_history`
- `sign_transaction`
- `sign_personal_message`
- `policy_propose`

`policy_propose` is a proposal path. MCP does not decide or commit policy.
Firmware validates the proposal, requires device-local approval, and commits
only supported policy records.

## Guidance For Agents

Call `get_capabilities` before signing. It tells the agent which signing methods
the connected device currently reports.

For signing:

- use `sign_transaction` for Sui transaction bytes;
- use `sign_personal_message` only when the device reports that method;
- keep `chain` as `"sui"` for the current implementation;
- keep `method` as `"sign_transaction"` or `"sign_personal_message"`;
- pass canonical base64 payloads;
- handle `policy_rejected`, `user_rejected`, `user_timed_out`, and
  `signing_failed` as terminal signing results;
- handle `not_connected`, `unsupported_chain`, `unsupported_method`,
  `unsupported_payload_size`, and `request_id_conflict` as request errors that
  need caller-side handling.

Do not:

- ask the user for private keys;
- ask the agent to choose policy mode or user-confirmation mode;
- treat client labels or purpose names as authorization facts;
- retry a changed signing request with the same explicit request id;
- submit broad or arbitrary chain payloads and assume Firmware will sign them.

## Signing Behavior

MCP exposes transaction signing through `sign_transaction` and user-mode
personal-message signing through `sign_personal_message`.

For Sui transaction signing, Firmware reads its device-local signing mode and
uses exactly one gate:

- policy mode evaluates the active Firmware policy;
- user mode shows device-local clear-signing review and requires local
  confirmation.

Personal-message signing is user-mode only in the current implementation.
Policy mode fails closed for `sign_personal_message`.

MCP accepts bounded signing route identifiers and delegates route
classification to the shared Client/host-process boundary. It does not maintain a
separate chain registry. Sui is currently the only executable chain.

## Admin Page

The `agent-q` binary also serves a local Admin Page through the same host process
core instance. The Admin Page supports device discovery, connection, active
policy readback, approval history, and the current policy proposal template.

The Admin Page is a host process capability. It is not a policy authority.

## Development

From the repository root:

```sh
npm --workspace @stelis/agent-q-mcp run build
npm --workspace @stelis/agent-q-mcp test
```
