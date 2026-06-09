# Agent-Q Sui dapp-kit Example

This example shows the intended Sui dapp-kit registration path for
`@stelis/agent-q-provider-sui`. It includes browser signing actions for
self-transfer transaction signing and personal-message signing.

Use this example when you want to see how a Sui app registers the Agent-Q Wallet
Standard adapter and sends signing requests to an Agent-Q device.

It is not hardware evidence and it is not a product-active signing claim. The
example does not create a fake provider, fake account, fake signature, or fake
device state. It creates the package's Web Serial browser runtime and registers
the Agent-Q Wallet Standard wallet from that runtime.

The current repository provider factory, `createAgentQSuiProvider()`, is
Node/host-local and must not be used as a browser dapp provider.

## Quick Start

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

The Web Serial runtime is created before dapp-kit initialization so the
Agent-Q wallet remains visible in the connect modal for ordinary users. It
requests a USB device only when `connectDevice()` runs from the dapp-kit connect
flow. If Web Serial is unavailable, connect/read/signing fail closed as
`unavailable` instead of hiding the wallet. The runtime implements only the
`AgentQSuiWalletProvider` contract; broader management APIs are not part of this
dapp-facing example. That is example/provider API projection, not a security
barrier against direct imports of broader core or local-server APIs.

The example's Wallet Standard registration path includes `sui:signTransaction`
and `sui:signPersonalMessage` through the provider contract. It does not expose
raw Agent-Q protocol, client, or MCP signing requests, Admin, policy update,
policy reads, approval-history reads, deprecated `sui:signMessage`, or
`sui:signAndExecuteTransaction`.

The connect button filters the dapp-kit wallet modal to the Agent-Q wallet.
Signing actions also fail closed unless the current dapp-kit wallet is the
Agent-Q wallet, so the page cannot display Agent-Q signing expectations while a
different Sui wallet signs.

The transfer buttons build real devnet Sui transaction objects at click time,
ask dapp-kit to sign them through Agent-Q, and submit successfully signed
transactions to devnet with the current dapp-kit client. In both user and policy
mode they self-transfer 0.5 SUI or 1.25 SUI to the connected Agent-Q account so
the example does not spend test tokens to an external address.
Policy-rejected transfers are not executed because Agent-Q does not return a
signature for them. The example does not use fake txBytes.

The browser example does not read, set, or display policy configuration. In
policy signing mode it only shows transaction-signing actions and reports the
Firmware result. Policy setup and readback remain MCP/Admin workflows, not part
of this browser example.
