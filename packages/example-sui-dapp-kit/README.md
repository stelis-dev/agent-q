# Agent-Q Sui dapp-kit Example

This example shows the intended Sui dapp-kit registration path for
`@stelis/agent-q-provider-sui`.

It is not hardware evidence and it is not a product-active signing claim. The
example does not create a fake provider, fake account, fake signature, or fake
device state. It registers the Agent-Q Wallet Standard wallet with an injected
browser-safe `AgentQSuiWalletProvider` when one is present, otherwise it creates
the package's Web Serial browser runtime when the browser supports Web Serial.

The current repository provider factory, `createAgentQSuiProvider()`, is
Node/Gateway-local and must not be used as a browser dapp provider.

## Run

This example depends on the repository workspace packages. From a fresh
checkout, install the root workspace dependencies first:

```sh
npm install
```

From the repository root:

```sh
npm run build:example-sui-dapp-kit
```

For local development, run `npm --workspace @stelis/agent-q-example-sui-dapp-kit
run dev` from the repository root.

If neither an injected provider nor Web Serial is available, the page shows
Agent-Q as unavailable. The Web Serial runtime can be created before dapp-kit
initialization, but it requests a USB device only when `connectDevice()` runs
from the dapp-kit connect flow. The runtime implements only the
`AgentQSuiWalletProvider` contract; broader management APIs are not part of this
dapp-facing example. That is example/provider API projection, not a security
barrier against direct imports of broader client/Admin entrypoints.

The example's Wallet Standard registration path includes `sui:signTransaction`
and `sui:signPersonalMessage` through the provider contract. It does not expose
raw Agent-Q protocol, client, or MCP signing requests, Admin, policy update,
policy reads, approval-history reads, deprecated `sui:signMessage`, or
`sui:signAndExecuteTransaction`.
