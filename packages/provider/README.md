# Agent-Q Provider

`@stelis/agent-q-provider` is the application-facing Agent-Q adapter package.

It exposes the current device discovery, device selection, connection,
read-only session data, and approval-history capabilities through a small
provider object.

The provider does not store signing keys and does not make policy decisions.
Agent-Q Firmware remains the authority for keys, policy evaluation,
device-local approval, signing, and active policy commits.

## Entrypoints

- `@stelis/agent-q-provider` exposes the provider factory and class.
- `@stelis/agent-q-provider/provider` exposes the same provider entrypoint.

## Current API

- `scanDevices`
- `identifyDevices`
- `selectDevice`
- `listDevices`
- `connectDevice`
- `disconnectDevice`
- `getCapabilities`
- `getAccounts`
- `getPolicy`
- `getApprovalHistory`

Policy update proposals are Admin/MCP capabilities and are not exposed by this
provider. Public signing methods are not implemented.

## Development

From the repository root:

```sh
npm --workspace @stelis/agent-q-provider run build
npm --workspace @stelis/agent-q-provider test
```
