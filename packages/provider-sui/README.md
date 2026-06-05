# Agent-Q Sui Provider

`@stelis/agent-q-provider-sui` is the Sui application-facing Agent-Q adapter
package.

It exposes current device discovery, device selection, connection, read-only
Sui account/capability data, and provider-facing device-confirmed Sui
`sign_transaction` transport through a small provider object. It also exposes
an app-imported Sui Wallet Standard registration adapter for
`sui:signTransaction`.

The Sui provider does not store signing keys and does not make policy
decisions. Agent-Q Firmware remains the authority for keys, policy evaluation,
device-local approval, signing, and active policy commits.

Mysten dapp-kit discovers wallets through Wallet Standard wallet objects and
Sui features such as `sui:signTransaction`. Agent-Q provides a Wallet Standard
wallet object, a global registration helper, and a dapp-kit initializer helper.
Agent-Q is not a self-injecting browser wallet; applications import this
package and register the wallet during app initialization.

## Entrypoints

- `@stelis/agent-q-provider-sui` exposes the Sui provider factory and class.
- `@stelis/agent-q-provider-sui/provider-sui` exposes the same Sui provider
  entrypoint.
- `@stelis/agent-q-provider-sui/wallet-standard` exposes the Wallet Standard
  wallet object, registration helper, and dapp-kit initializer helper.

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
signing and transaction execution are not implemented and must not be
advertised until their protocol, history, UI, and tests are defined.

## Wallet Standard

The Wallet Standard adapter exposes the current Agent-Q-supported wallet
features only:

- `standard:connect`
- `standard:events`
- `standard:disconnect`
- `sui:signTransaction`

It does not expose `sui:signPersonalMessage`,
`sui:signAndExecuteTransaction`, Admin, policy update, `signByPolicy`, policy
reads, or approval-history reads.

Apps can register the wallet directly:

```ts
import { registerAgentQSuiWallet } from "@stelis/agent-q-provider-sui/wallet-standard";

const registration = registerAgentQSuiWallet({
  getClient(network) {
    return clients[network];
  },
  chains: ["sui:testnet"],
});

// Later, during teardown:
registration.unregister();
```

For dapp-kit, use the initializer helper before wallet UI is created:

```ts
import { createDAppKit } from "@mysten/dapp-kit-react";
import { createAgentQSuiWalletInitializer } from "@stelis/agent-q-provider-sui/wallet-standard";

export const dAppKit = createDAppKit({
  networks: ["testnet"],
  defaultNetwork: "testnet",
  createClient(network) {
    return clients[network];
  },
  walletInitializers: [createAgentQSuiWalletInitializer()],
});
```

The wallet signs through provider-sui `signByUser`, which sends
`sign_by_user` to Firmware. Firmware remains responsible for review, local PIN,
history, signing, and cleanup.

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
`provider-exposed-not-product-active` signing in the client package, where the
direct USB/Firmware boundary lives:

```sh
AGENTQ_HW_CLIENT_SIGN_BY_USER=1 \
AGENTQ_HW_CLIENT_SIGN_BY_USER_SCENARIO=positive \
AGENTQ_HW_CLIENT_SIGN_BY_USER_TX_BYTES=<base64> \
node --test packages/client/test/hardware-sign-api-smoke.test.mjs
```

Supported scenarios are `positive`, `reject`, `timeout`, and `disconnect`.
The `disconnect` scenario verifies transport session end, post-reconnect idle
status, fresh connection, capability recovery, and absence of new signature
confirmation or terminal history. Provider-sui package tests cover the
dapp-facing provider and Wallet Standard boundaries; approval history is not a
provider-sui API.
