# Agent-Q Sui dapp-kit Example

This example shows the intended Sui dapp-kit registration path for
`@stelis/agent-q-provider-sui`.

It is not hardware evidence and it is not a product-active signing claim. The
example does not create a fake provider, fake account, fake signature, or fake
device state. It registers the Agent-Q Wallet Standard wallet only when an
external browser-safe `AgentQSuiWalletProvider` is injected before app startup.

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

Without an injected provider, the page shows Agent-Q as unavailable. A future
browser-safe provider runtime should set `window.agentQSuiProvider` before this
app imports `src/dapp-kit.ts`. That runtime must implement only the
`AgentQSuiWalletProvider` contract; broader management APIs are not part of this
dapp-facing example. That is example/provider API projection, not a security
barrier against direct imports of broader client/Admin entrypoints.

The example's Wallet Standard registration path includes `sui:signTransaction`
through the injected provider. It does not expose raw Agent-Q protocol, client,
or MCP `sign_transaction`, Admin, policy update, policy reads,
approval-history reads, `sui:signPersonalMessage`, or
`sui:signAndExecuteTransaction`.
