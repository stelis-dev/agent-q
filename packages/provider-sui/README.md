# Agent-Q Sui Provider

> Development status: Agent-Q is an active development project with
> hardware-tested Sui signing paths for CLI, MCP, and supported provider flows.
> The current StackChan CoreS3 Firmware path uses DEV_PROFILE material intended
> for development and demos, not real-asset custody. See the root README
> Current Status section for storage and profile limitations.

`@stelis/agent-q-provider-sui` is the Sui application-facing Agent-Q adapter
package.

It exposes current device discovery, device selection, connection, read-only
Sui account/capability data, and Sui `sign_transaction` /
`sign_personal_message` transport through a small provider object. Direct
provider methods also expose common Sui zkLogin credential preparation and
proposal. It also exposes an app-imported Sui Wallet Standard registration
adapter for the currently supported Sui signing features.

The Sui provider does not store signing material and does not make policy
decisions. Agent-Q Firmware remains the authority for signing material, policy
evaluation, device-local approval, signing, and active policy commits.

## Quick Start

Use this package when a Sui app should show an Agent-Q wallet and route signing
requests to an Agent-Q device.

For Wallet Standard / dapp-kit, register the wallet during app initialization:

```ts
import { createDAppKit } from "@mysten/dapp-kit-react";
import { createAgentQSuiWalletInitializer } from "@stelis/agent-q-provider-sui/wallet-standard";
import { createAgentQSuiBrowserProvider } from "@stelis/agent-q-provider-sui/browser";

const provider = createAgentQSuiBrowserProvider();

export const dAppKit = createDAppKit({
  networks: ["devnet"],
  defaultNetwork: "devnet",
  createClient(network) {
    return clients[network];
  },
  walletInitializers: [createAgentQSuiWalletInitializer({ provider })],
});
```

The app then uses normal Sui wallet flows. Agent-Q signs only after the device
accepts the request through its current policy or device-confirmation gate.

Mysten dapp-kit discovers wallets through Wallet Standard wallet objects and
Sui features such as `sui:signTransaction`. Agent-Q provides a Wallet Standard
wallet object, a global registration function, and a dapp-kit initializer.
Agent-Q is not a self-injecting browser wallet; applications import this
package and register the wallet during app initialization.

The Wallet Standard entrypoint requires an injected provider implementation and
does not create a default provider internally. The repository's
`createAgentQSuiProvider()` factory is Node/host-local and uses the device
client transport. Browser dapps can use the `./browser` subpath for a Web
Serial-based runtime that implements `AgentQSuiWalletProvider`. Browser
hardware signing is product-active only when the matching status entry in
`docs/IMPLEMENTATION_STATUS.md` says the source, docs, tests, build, hardware,
and visual evidence are complete.

The root provider factory is Node/host-local and uses `@stelis/agent-q-core`
device transport. The `./wallet-standard` subpath is runtime-separated from
that Node transport, and the `./browser` subpath uses the core package's
provider protocol projection for app-facing Web Serial requests. That
projection exact-validates provider requests at runtime and does not expose
Admin, policy read/update, approval-history, or retained-response recovery
request/response types. Browser retained-response recovery uses the full core
protocol's low-level `get_result` / `ack_result` primitives internally; direct
application use of those primitives is unsupported.

This package narrows the dapp-facing API it presents. That is not a security
boundary against an application that imports
`@stelis/agent-q-core` or broader `@stelis/agent-q` local-server APIs directly. Firmware
remains the authority that enforces state gates, device-local confirmation,
policy evaluation, signing, persistence, and cleanup.

## Entrypoints

- `@stelis/agent-q-provider-sui` exposes the Sui provider factory and class.
- `@stelis/agent-q-provider-sui/provider-sui` exposes the same Sui provider
  entrypoint.
- `@stelis/agent-q-provider-sui/wallet-standard` exposes the Wallet Standard
  wallet object, registration function, and dapp-kit initializer.
- `@stelis/agent-q-provider-sui/browser` exposes the browser-only Web
  Serial runtime used by direct provider methods and the Wallet Standard
  adapter.

## Current API

- `scanDevices`
- `identifyDevices`
- `selectDevice`
- `listDevices`
- `connectDevice`
- `disconnectDevice`
- `getCapabilities`
- `getAccounts`
- `credentialPrepare`
- `credentialPropose`
- `signTransaction`
- `signPersonalMessage`

`getCapabilities` may include Firmware-authored `credentials[]` metadata.
For Sui zkLogin, that metadata advertises only common credential preparation
and proposal availability. It is not a Wallet Standard feature, proof-clear
route, signer selector, or signing authorization selector.

The dapp-facing provider object does not include policy update proposals,
active policy readback, approval history, proof-clear APIs, signer selectors,
or any host-selected signing authorization API.
Those APIs remain on broader core, MCP, or Admin surfaces. This is API
projection for the provider audience, not a security claim that the same
application cannot import broader core or local-server APIs directly. Provider-facing
signing uses `signTransaction` for transaction bytes and `signPersonalMessage`
for bounded Sui personal-message bytes. `signTransaction` may internally use
Firmware-advertised same-session payload transfer when the transaction bytes do
not fit the inline transport form; that transfer primitive is not a separate dapp
API. Firmware uses its device-local signing mode to select the policy or user
authorization gate for transaction signing, and personal-message signing is
user-mode only. Firmware records required history and signs or rejects. The
provider does not decide whether signing is allowed and cannot select the
authorization mode.

`getAccounts` returns the raw Agent-Q Sui account projection. That projection
includes `sponsoredTransactions.acceptGasSponsor`, a read-only value from the
active account's device-local Firmware setting. It tells direct provider callers
whether Firmware may accept transactions where the parsed sender is the active
account and the parsed gas owner is a different sponsor. There is no provider,
Wallet Standard, host, or dapp setter for this setting.

`credentialPrepare` and `credentialPropose` send common `credential_prepare`
and `credential_propose` requests. Enoki, OAuth, JWT handling, prover calls,
salt services, and zkLogin address continuity are application or test-web
responsibilities; Agent-Q receives only the bounded credential proposal fields
accepted by Firmware.

The current signing methods are Sui `sign_transaction` and user-confirmed Sui
`sign_personal_message`. Transaction execution and policy-authorized personal
message signing are not implemented and must not be advertised.

Provider-sui remains a Sui-specific projection. It does not own a shared chain
router or registry; the common Core, host process, and Firmware boundaries enforce
the shared route contract.

## Wallet Standard

The Wallet Standard adapter exposes the current Agent-Q-supported wallet
methods only:

- `standard:connect`
- `standard:events`
- `standard:disconnect`
- `sui:signTransaction`
- `sui:signPersonalMessage`

Connected Wallet Standard accounts advertise only the features supported by
the live Firmware capability response for the current signing mode.
`sui:signPersonalMessage` is therefore an account feature only when Firmware
reports user-mode support for `sign_personal_message`.

It does not expose `sui:signAndExecuteTransaction`, deprecated
`sui:signMessage`, Admin, policy update, policy reads, approval-history reads,
Agent-Q credential setup features, proof-clear APIs, signer selectors, or a
host-selected authorization API.

Credential setup is available through direct provider methods, not through
Wallet Standard. The Wallet Standard wallet object does not expose
`agentq:credentialPrepare`, `agentq:credentialPropose`, `credential_prepare`,
`credential_propose`, or proof-clear features.

The raw Agent-Q account projection and Wallet Standard account object are
different shapes. Wallet Standard `ReadonlyWalletAccount` objects do not expose
`sponsoredTransactions` or `acceptGasSponsor`; those values are available only
from direct provider `getAccounts`.

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
  chains: ["sui:devnet"],
});

// During teardown:
registration.unregister();
```

For dapp-kit, register the initializer before wallet UI is created:

```ts
import { createDAppKit } from "@mysten/dapp-kit-react";
import { createAgentQSuiWalletInitializer } from "@stelis/agent-q-provider-sui/wallet-standard";
import type { AgentQSuiWalletProvider } from "@stelis/agent-q-provider-sui/wallet-standard";

declare const provider: AgentQSuiWalletProvider;

export const dAppKit = createDAppKit({
  networks: ["devnet"],
  defaultNetwork: "devnet",
  createClient(network) {
    return clients[network];
  },
  walletInitializers: [createAgentQSuiWalletInitializer({ provider })],
});
```

The wallet signs through provider-sui `signTransaction` and
`signPersonalMessage`, which send `sign_transaction` and
`sign_personal_message` to Firmware. Firmware remains responsible for selecting
the policy or user signing gate from its local signing mode, active policy
evaluation in policy mode, device-local user confirmation in user mode, history,
signing, and cleanup. Personal-message signing is user-mode only in the current
implementation.

See `packages/sample-sui-dapp-kit/` for a minimal dapp-kit integration
sample with transfer-signing and personal-message signing buttons. The sample
does not create or accept a fake provider; it creates the Web Serial-based
browser runtime so the Agent-Q wallet can stay visible before a
USB device is selected. If Web Serial is unavailable, the runtime fails closed
on connect/read/signing instead of hiding the wallet. The sample does not
expose policy reads, policy update proposals, approval history, Admin, MCP, or
a host-selected authorization API.

### Browser-Safe Provider Boundary

`AgentQSuiWalletProvider` is the current browser injection contract for the
Wallet Standard adapter. It is smaller than the Node-local
provider factory:

- `connectDevice`
- `disconnectDevice`
- `getCapabilities`
- `getAccounts`
- `signTransaction`
- `signPersonalMessage`

The injected browser provider contract contains only the methods above. It must
not include Admin, policy update, active-policy reads, approval-history reads,
host-selected authorization controls, raw session tokens, secrets, or
caller-controlled timing fields. That keeps the Wallet Standard adapter
dapp-facing; Firmware remains the security authority. "No policy surface" means
no policy management, policy reads, approval-history reads, Admin, MCP, or
policy editor surface. It does not mean policy authorization is impossible:
`sign_transaction` may still use Firmware's policy gate when the device-local
signing mode is `policy`. The provider and browser runtime cannot read, set, or
override that mode.

The `./browser` runtime also exposes direct provider `credentialPrepare` and
`credentialPropose` methods for test or application code that imports the
provider runtime directly. Those methods are not projected as Wallet Standard
features.

The `./browser` runtime is Web Serial based and browser-only. It can be created
before dapp-kit initializes so the Wallet Standard wallet can be registered
early, but it does not select a USB device or request Web Serial permission at
initialization time. Port acquisition happens inside `connectDevice()`: the
runtime first reuses a single already-granted Agent-Q Web Serial port when the
browser exposes one, and otherwise falls back to the browser's port picker where
a user gesture may be required. If Web Serial is unavailable, reads/signing fail
closed as `unavailable`. If Web Serial exists but no device session is
connected, they fail closed as `not_connected`.

Provider requests do not accept caller-controlled timing fields, custom serial
ports, raw transport injection, or baud-rate configuration. Firmware-owned
device-local physical-input windows remain 30 seconds. The browser runtime uses
the same fixed internal connect/signing budgets as the client core for PIN
retry/lockout handling plus a non-configurable margin, and keeps shorter
internal budgets for read/disconnect requests.

## Development

From the repository root:

```sh
npm --workspace @stelis/agent-q-provider-sui run build
npm --workspace @stelis/agent-q-provider-sui test
```

The current source tree tracks opt-in hardware smoke tests for signing in the
core package, where the direct USB/Firmware boundary lives:

```sh
AGENTQ_HW_CLIENT_SIGN_TRANSACTION_USER=1 \
AGENTQ_HW_CLIENT_SIGN_TRANSACTION_USER_SCENARIO=positive \
AGENTQ_HW_CLIENT_SIGN_TRANSACTION_USER_TX_BYTES=<base64> \
node --test packages/core/test/hardware-sign-api-smoke.test.mjs
```

Supported scenarios are `positive`, `reject`, `timeout`, and `disconnect`.
The `disconnect` scenario verifies transport session end, post-reconnect idle
status, fresh connection, capability recovery, and absence of new signature
confirmation or terminal history. Provider-sui package tests cover the
dapp-facing provider and Wallet Standard boundaries; approval history is not a
provider-sui API.
