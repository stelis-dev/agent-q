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
- `sign_by_policy`
- `policy_propose`

`policy_propose` is a proposal path. MCP does not decide or commit
policy; Firmware validates the proposal, requires device-local approval, and
commits only supported policy records.

MCP exposes policy-authorized signing through the `sign_by_policy` tool. Its
tool set does not include provider-facing user-confirmed signing. Provider-facing
user signing capability metadata is removed from MCP `get_capabilities` runtime
output; the exported MCP tool output schema accepts policy-authorized signing
capability only. This is MCP adapter projection, not signing authority.

MCP tool inputs do not expose caller-controlled timing fields. Firmware-owned
device-local physical-input windows remain 30 seconds; Gateway uses fixed
internal transport budgets for PIN retry/lockout handling plus a
non-configurable margin.

## Admin Page

The `agent-q` binary serves a local Admin Page alongside stdio MCP tools through
one shared Gateway core instance. The Admin Page supports device discovery,
connection, active policy summary, approval history, and the current
policy proposal template.

The Admin Page is not a separate product and is not a policy authority.

## Development

From the repository root:

```sh
npm --workspace @stelis/agent-q-mcp run build
npm --workspace @stelis/agent-q-mcp test
```
