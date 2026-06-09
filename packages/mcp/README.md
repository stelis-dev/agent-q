# Agent-Q MCP

`@stelis/agent-q-mcp` provides the local Agent-Q MCP server, CLI binary, and
local Admin Page.

It depends on `@stelis/agent-q-client` for device discovery, runtime sessions,
USB transport, protocol requests, and output validation. It does not depend on
`@stelis/agent-q-provider-sui`.

The MCP package is an adapter. It does not store signing keys, does not make
signing or policy decisions, and does not apply policy. Firmware remains the
authority for keys, policies, device-local approval, and policy commits.

MCP narrows the tool surface it offers to agents. That tool surface is not a
security boundary against code that deliberately imports broader client/Admin
entrypoints. Firmware must enforce all security-relevant state gates, policy
decisions, signing, persistence, and cleanup.

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

`policy_propose` is a proposal path. MCP does not decide or commit
policy; Firmware validates the proposal, requires device-local approval, and
commits only supported policy records.

MCP exposes transaction signing through the `sign_transaction` tool and
user-mode personal-message signing through `sign_personal_message`. Firmware
uses its device-local signing mode to select the policy or user authorization
gate for transaction signing: policy mode evaluates active policy and signs
after policy authorization, while user mode requires device-local confirmation.
Personal-message signing is user-mode only and fails closed in policy mode. The
tools return Firmware-authored `sign_result` values.
`get_capabilities`
reports the read-only current signing authorization mode for UX/display only;
the request never selects it. This is MCP adapter projection, not signing
authority.

MCP accepts bounded signing route identifiers and delegates route
classification to the shared Client/Gateway boundary. It does not maintain a
separate chain registry. Sui is currently the only executable chain;
unsupported chains and methods fail explicitly. MCP validates transport-safe
request shape but does not enforce the current Sui Firmware adapter's decoded
payload capacities.

The package also provides `agent-q-sui-sign`, a Sui offline-signing bridge that
submits the shared `sign_transaction` request and prints only a
Firmware-authored serialized signature to stdout. Diagnostics use stderr, and
the command performs best-effort session disconnect after a successful
connection. It is not an implementation of the Sui CLI JSON-RPC
external-signer protocol.

MCP tool inputs do not expose caller-controlled timing fields. Firmware-owned
device-local physical-input windows remain 30 seconds; Gateway uses fixed
internal transport budgets for PIN retry/lockout handling plus a
non-configurable margin.

## Admin Page

The `agent-q` binary serves a local Admin Page alongside stdio MCP tools through
one shared Gateway core instance. The Admin Page supports device discovery,
connection, active policy readback, approval history, and the current
policy proposal template.

The Admin Page is not a separate product and is not a policy authority.

## Development

From the repository root:

```sh
npm --workspace @stelis/agent-q-mcp run build
npm --workspace @stelis/agent-q-mcp test
```
