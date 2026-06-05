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

The Wallet Standard entrypoint requires an injected provider implementation and
does not create a default provider internally. The repository's
`createAgentQSuiProvider()` factory is Node/Gateway-local and uses the device
client transport. Ordinary browser dapps need a provider-only browser runtime
that implements `AgentQSuiWalletProvider` before a runtime dapp-kit demo can be
considered product-real. Do not use the Wallet Standard adapter as evidence
that browser hardware signing has been verified.

The current package still depends on `@stelis/agent-q-client` because the root
provider factory is Node/Gateway-local. The `./wallet-standard` subpath must
remain runtime-separated from that Node transport. A future browser-safe
provider runtime must be injected into the Wallet Standard adapter and must
expose only the provider-facing methods described below.

This package narrows the dapp-facing API it presents. That is not a security
boundary against an application that deliberately imports
`@stelis/agent-q-client` or `@stelis/agent-q-client/admin` directly. Firmware
remains the authority that enforces state gates, device-local confirmation,
policy evaluation, signing, persistence, and cleanup.

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

The dapp-facing provider object does not include policy update proposals, raw
delegated `signByPolicy` access, active policy summaries, or approval history.
Those APIs remain on broader client, MCP, or Admin surfaces. This is API
projection for the provider audience, not a security claim that the same
application cannot import the client/Admin package directly. Provider-facing
signing uses only `signByUser`, which passes a bounded request to Firmware for
device-local review, local PIN confirmation, required history, and signing. The
provider does not decide whether signing is allowed.

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
import type { AgentQSuiWalletProvider } from "@stelis/agent-q-provider-sui/wallet-standard";

declare const provider: AgentQSuiWalletProvider;

const registration = registerAgentQSuiWallet({
  provider,
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
import type { AgentQSuiWalletProvider } from "@stelis/agent-q-provider-sui/wallet-standard";

declare const provider: AgentQSuiWalletProvider;

export const dAppKit = createDAppKit({
  networks: ["testnet"],
  defaultNetwork: "testnet",
  createClient(network) {
    return clients[network];
  },
  walletInitializers: [createAgentQSuiWalletInitializer({ provider })],
});
```

The wallet signs through provider-sui `signByUser`, which sends
`sign_by_user` to Firmware. Firmware remains responsible for review, local PIN,
history, signing, and cleanup.

See `packages/example-sui-dapp-kit/` for a minimal dapp-kit integration
skeleton. The example intentionally does not create a fake provider; it
registers Agent-Q only when a browser-safe provider is injected by the host page.

### Browser-Safe Provider Boundary

`AgentQSuiWalletProvider` is the current browser injection contract for the
Wallet Standard adapter. It is intentionally smaller than the Node-local
provider factory:

- `connectDevice`
- `disconnectDevice`
- `getAccounts`
- `signByUser`

The injected browser provider contract contains only the methods above. It must
not include Admin, policy update, active-policy reads, approval-history reads,
`signByPolicy`, `sign_by_policy`, raw session tokens, secrets, or
caller-controlled timing fields. That keeps the Wallet Standard adapter
provider-facing; Firmware remains the security authority. Any future browser
runtime must implement this provider-only injection contract instead of reusing
broader management surfaces.

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
