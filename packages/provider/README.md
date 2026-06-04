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

Policy update proposals and provider-facing signing are not exposed by this
provider. Future signing activation must add a separate device-confirmed API
only after the Firmware USB dispatcher, client/provider parser/API, capability
advertisement, and current-tree hardware smoke are all complete.

Provider requests do not accept caller-controlled timing fields. Firmware-owned
device-local approval windows remain 30 seconds; Gateway uses fixed internal
transport budgets with a non-configurable margin so a valid terminal device
result can still be received at the end of that window.

## Development

From the repository root:

```sh
npm --workspace @stelis/agent-q-provider run build
npm --workspace @stelis/agent-q-provider test
```

No provider hardware signing smoke test is tracked while public provider
signing is inactive.
