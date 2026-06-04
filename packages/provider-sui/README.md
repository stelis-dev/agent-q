# Agent-Q Sui Provider

`@stelis/agent-q-provider-sui` is the Sui application-facing Agent-Q adapter
package.

It exposes current device discovery, device selection, connection, read-only
Sui account/capability data, and provider-facing device-confirmed Sui
`sign_transaction` transport through a small provider object.

The Sui provider does not store signing keys and does not make policy
decisions. Agent-Q Firmware remains the authority for keys, policy evaluation,
device-local approval, signing, and active policy commits.

This package is not yet a Sui Wallet Standard registration adapter. Mysten
dapp-kit discovers wallets through Wallet Standard wallet objects and Sui
features such as `sui:signTransaction`. Agent-Q's current Sui provider surface
is the pre-Wallet-Standard adapter that the next demo/Wallet Standard work
should wrap.

## Entrypoints

- `@stelis/agent-q-provider-sui` exposes the Sui provider factory and class.
- `@stelis/agent-q-provider-sui/provider-sui` exposes the same Sui provider
  entrypoint.

## Current API

- `scanDevices`
- `identifyDevices`
- `selectDevice`
- `listDevices`
- `connectDevice`
- `disconnectDevice`
- `getCapabilities`
- `getAccounts`
- `signByUser`

Policy update proposals and raw delegated `signByPolicy` access are not exposed
by this provider. Active policy summaries and approval history are also not
exposed through this dapp-facing provider surface; they remain on client,
MCP, and Admin management surfaces. Provider-facing signing uses only
`signByUser`, which passes a bounded request to Firmware for device-local
review, local PIN confirmation, required history, and signing. The provider
does not decide whether signing is allowed.

The current signing method is Sui `sign_transaction` only. Sui personal-message
signing and Wallet Standard registration are future work and must not be
described as implemented until their protocol, history, UI, and tests are
defined.

Provider requests do not accept caller-controlled timing fields. Firmware-owned
device-local physical-input windows remain 30 seconds; Gateway uses fixed
internal transport budgets for PIN retry/lockout handling plus a
non-configurable margin.

## Development

From the repository root:

```sh
npm --workspace @stelis/agent-q-provider-sui run build
npm --workspace @stelis/agent-q-provider-sui test
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
confirmation or terminal history. The smoke harness reads approval history
through its shared device client core for test evidence only; approval history
is not a provider-sui API.
