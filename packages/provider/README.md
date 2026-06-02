# Agent-Q Provider

`@stelis/agent-q-provider` is the application-facing Agent-Q adapter package.

It exposes the current device discovery, device selection, connection,
read-only session data, approval-history, and policy-update proposal
capabilities through a small provider object.

This is not signing support. It does not sign transactions, does not expose a
wallet signing API, does not store signing keys, and does not make policy
decisions. Agent-Q Firmware remains the authority for keys, policy evaluation,
device-local approval, and active policy commits.

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
- `requestPolicyUpdate`

`requestPolicyUpdate` submits a bounded policy proposal to Firmware. Firmware
validates the proposal, requires device-local approval, commits the active
policy, and records the terminal result. It is not a direct policy setter.

## Signing Boundary

The current provider API has no signing method. Applications must not infer
signing availability from device discovery, connection, public accounts, or
policy summaries. Current StackChan CoreS3 capability responses report Sui
account identity with an empty `methods` list, and the provider does not expose
`call_method`.

## Development

From the repository root:

```sh
npm --workspace @stelis/agent-q-provider run build
npm --workspace @stelis/agent-q-provider test
```
