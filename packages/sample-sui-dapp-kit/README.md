# Agent-Q Sui dapp-kit Sample

> Development status: Agent-Q is an active development project with
> hardware-tested Sui signing paths for CLI, MCP, and supported provider flows.
> The current StackChan CoreS3 Firmware path uses DEV_PROFILE material intended
> for development and demos, not real-asset custody. See the root README
> Current Status section for storage and profile limitations.

This sample shows the current Sui dapp-kit registration path for
`@stelis/agent-q-provider-sui`. It includes browser signing actions for
self-transfer transaction signing and personal-message signing.

Use this sample when you want to see how a Sui app registers the Agent-Q Wallet
Standard adapter and sends signing requests to an Agent-Q device.

It is not hardware evidence and it is not a product-active signing claim. The
sample does not create a fake provider, fake account, fake signature, or fake
device state. It creates the package's Web Serial browser runtime and registers
the Agent-Q Wallet Standard wallet from that runtime.

The current repository provider factory, `createAgentQSuiProvider()`, is
Node/host-local and must not be used as a browser dapp provider.

## Quick Start

This sample depends on the repository workspace packages. From a fresh
checkout, install the root workspace dependencies first:

```sh
npm install
```

Build the sample from the repository root:

```sh
npm run build:sample-sui-dapp-kit
```

For local development, start the Vite server from the repository root:

```sh
npm --workspace @stelis/agent-q-sample-sui-dapp-kit run dev
```

Open the URL printed by Vite. With the default script, this is usually
`http://127.0.0.1:5173/` unless that port is already in use.

The Web Serial runtime is created before dapp-kit initialization so the
Agent-Q wallet remains visible in the connect modal for ordinary users. It
requests a USB device only when `connectDevice()` runs from the dapp-kit connect
flow. If Web Serial is unavailable, connect/read/signing fail closed as
`unavailable` instead of hiding the wallet. The runtime implements only the
`AgentQSuiWalletProvider` contract; broader management APIs are not part of this
dapp-facing sample. That is sample/provider API projection, not a security
barrier against direct imports of broader core or local-server APIs.

The sample's Wallet Standard registration path includes `sui:signTransaction`
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
the sample does not spend test tokens to an external address.
Policy-rejected transfers are not executed because Agent-Q does not return a
signature for them. The sample does not use fake txBytes.

When the device is in policy signing mode and the Admin Page has committed the
minimal Sui testnet policy template, the 0.5 SUI button is the intended pass
case and the 1.25 SUI button is the intended reject case. The page does not
evaluate policy locally; it shows the Firmware result.

The browser sample does not read, set, or display policy configuration. In
policy signing mode it only shows transaction-signing actions and reports the
Firmware result. Policy setup and readback remain MCP/Admin workflows, not part
of this browser sample.
