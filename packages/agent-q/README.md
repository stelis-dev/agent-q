# Agent-Q Local Server

`@stelis/agent-q` provides the local Agent-Q server package.

It exposes MCP tools for AI agents, a local HTTP API for the Admin Page, and the
`agent-q-sui-signer` executable for Sui CLI external signer compatibility.

Use this package when an MCP-capable agent needs to request signatures from an
Agent-Q device, or when a Sui CLI workflow needs an Agent-Q device as its
external signer.

Firmware remains the signing authority. MCP tools and CLI commands submit
requests; they do not store keys, apply policy, approve signing, or select the
device signing mode.

## Terms Used Here

- **host process**: the local `agent-q` process. It exposes MCP stdio tools,
  the local HTTP API, and the Admin Page, and relays requests to Firmware.
- **Firmware**: the software running on the Agent-Q hardware device. Firmware is
  the signing and policy authority.
- **Admin Page**: the local web UI served by the host process. It is not a
  separate authority.
- **Sui CLI external signer**: an executable that Sui CLI starts from its
  keystore configuration when a registered address needs a signature. In this
  package the executable is `agent-q-sui-signer`.

## Quick Start: MCP

Run the local server as an MCP server:

```sh
npx -y @stelis/agent-q serve --request-connect
```

If installed globally, use `agent-q`.

Confirm the connection request on the device when the server starts. The server
can request a connection, but only Firmware can approve it on the device. After
approval, `agent-q` writes an operator-facing summary to stderr. The summary
includes the connected device id, public Sui address when available,
Firmware-reported signing mode when available, and supported signing methods
when available. Account information and capability information are read after
the device approves the connection; if either read fails, the server prints a
separate `Agent-Q accounts unavailable: ...` or
`Agent-Q capabilities unavailable: ...` line. This diagnostic output is not Sui
CLI key registration and is not signing authorization.

MCP client config example:

```json
{
  "mcpServers": {
    "agent-q": {
      "command": "npx",
      "args": ["-y", "@stelis/agent-q", "serve", "--request-connect"]
    }
  }
}
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

Sui CLI needs a one-time external key registration before normal
`sui client ...` commands can use Agent-Q. Running the Agent-Q server only opens
the local server and requests a device connection; it does not register the key
in Sui CLI.

Start the local Agent-Q server and confirm the connection request on the
device. With a global install:

```sh
npm install -g @stelis/agent-q
agent-q serve --request-connect
```

Without a global install:

```sh
npm exec --yes --package @stelis/agent-q -- agent-q serve --request-connect
```

After approval, the server writes an operator-facing summary to stderr. The
summary includes the connected device id, public Sui address when available,
Firmware-reported signing mode when available, and supported signing methods
when available. Account information and capability information are read after
the device approves the connection; if either read fails, the server prints a
separate `Agent-Q accounts unavailable: ...` or
`Agent-Q capabilities unavailable: ...` line. Use the public Sui address from
this summary as `<SUI_ADDRESS>` in the Sui CLI commands below.

In another terminal, register the Agent-Q key with Sui CLI once. This writes an
external signer entry to the Sui CLI keystore; it is not an environment
variable. Copy `<KEY_ID_FROM_LIST_KEYS>` from the `list-keys` output:

```sh
sui external-keys list-keys agent-q-sui-signer
sui external-keys add-existing "<KEY_ID_FROM_LIST_KEYS>" agent-q-sui-signer
sui client switch --address <SUI_ADDRESS>
```

After registration, keep `agent-q` running and use the registered address as the
Sui CLI sender. For example, pick a SUI coin and send SUI:

```sh
sui client gas <SUI_ADDRESS> --json
sui client pay-sui \
  --input-coins <SUI_COIN_OBJECT_ID> \
  --recipients <TO_ADDRESS> \
  --amounts <MIST_AMOUNT> \
  --gas-budget <GAS_BUDGET> \
  --sender <SUI_ADDRESS> \
  --json
```

Sui CLI calls `agent-q-sui-signer` through its external signer JSON-RPC
stdin/stdout protocol. It finds the external signer from its keystore
registration for the sender address, then runs `agent-q-sui-signer` by command
name. The signer must therefore be installed, linked, or otherwise available on
`PATH` whenever Sui CLI invokes it. The signer calls the local Agent-Q server,
and the server sends transaction signing requests to Firmware. The private key
stays on the device.

If you do not install the package globally, run both setup and Sui CLI commands
through `npm exec` so `agent-q-sui-signer` is on `PATH` for that command:

```sh
npm exec --yes --package @stelis/agent-q -- \
  sui external-keys list-keys agent-q-sui-signer
npm exec --yes --package @stelis/agent-q -- \
  sui external-keys add-existing "<KEY_ID_FROM_LIST_KEYS>" agent-q-sui-signer
```

Use the same `npm exec --yes --package @stelis/agent-q -- ...` wrapper for
subsequent `sui client ...` commands when the package is not globally installed.

`agent-q-sui-signer` uses the active Sui CLI environment when it is `mainnet`,
`testnet`, `devnet`, or `localnet`. To set it explicitly:

```sh
agent-q-sui-signer configure --network testnet
```

For low-level scripts that already have unsigned transaction bytes:

```sh
agent-q-sui-signer --network testnet --tx-bytes <base64-unsigned-transaction>
```

That low-level command also requires the local `agent-q` server to be running.

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
- ask the agent to choose policy authorization mode or user authorization mode;
- treat client labels or purpose names as authorization facts;
- retry a changed signing request with the same explicit request id;
- submit broad or arbitrary chain payloads and assume Firmware will sign them.

## Signing Behavior

The MCP API exposes transaction signing through `sign_transaction` and user-mode
personal-message signing through `sign_personal_message`.

For Sui transaction signing, Firmware reads its device-local signing mode and
uses exactly one gate:

- policy mode evaluates the active Firmware policy;
- user mode shows device-local offline facts review or an explicit
  blind-signing warning, then requires local confirmation.

Personal-message signing is user-mode only in the current implementation.
Policy mode fails closed for `sign_personal_message`.

The MCP API accepts bounded signing route identifiers and delegates route
classification to the shared core/host-process boundary. It does not maintain a
separate chain registry. Sui is currently the only executable chain.

## Admin Page

The `agent-q` binary also serves a local Admin Page through the same host process
core instance. The Admin Page supports device discovery, connection, active
policy readback, approval history, current-schema policy proposal editing, a
minimal Sui testnet policy template, and no policy-reset shortcut. Policy reset
is a Firmware-local Settings action.

The Admin Page is a host process capability. It is not a policy authority.

## Development

From the repository root:

```sh
npm --workspace @stelis/agent-q run build
npm --workspace @stelis/agent-q test
```
