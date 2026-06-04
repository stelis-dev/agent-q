# Agent-Q Provider

`@stelis/agent-q-provider` is the application-facing Agent-Q adapter package.

It exposes the current device discovery, device selection, connection,
read-only session data, approval-history, and provider-facing
device-confirmed signing transport through a small provider object.

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
- `signByUser`

Policy update proposals and raw delegated `signByPolicy` access are not exposed by
this provider. Provider-facing signing uses only `signByUser`, which
passes a bounded request to Firmware for device-local review, local PIN
confirmation, required history, and signing. The provider does not decide
whether signing is allowed.

Provider requests do not accept caller-controlled timing fields. Firmware-owned
device-local physical-input windows remain 30 seconds; Gateway uses fixed
internal transport budgets for PIN retry/lockout handling plus a
non-configurable margin.

## Development

From the repository root:

```sh
npm --workspace @stelis/agent-q-provider run build
npm --workspace @stelis/agent-q-provider test
```

The current source tree tracks an opt-in hardware smoke test for
`provider-exposed-not-product-active` provider signing:

```sh
AGENTQ_HW_PROVIDER_SIGNATURE=1 \
AGENTQ_HW_PROVIDER_SIGNATURE_SCENARIO=positive \
AGENTQ_HW_PROVIDER_SIGNATURE_TX_BYTES=<base64> \
node --test test/hardware-provider-signature-smoke.test.mjs
```

Supported scenarios are `positive`, `reject`, `timeout`, and `disconnect`.
The `disconnect` scenario verifies transport session end, post-reconnect idle
status, fresh connection, capability recovery, and absence of new signature
confirmation or terminal history.
