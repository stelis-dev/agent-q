import { DAppKitProvider, useCurrentAccount, useCurrentNetwork, useCurrentWallet } from "@mysten/dapp-kit-react";
import { ConnectButton } from "@mysten/dapp-kit-react/ui";
import { agentQProviderAvailable, dAppKit } from "./dapp-kit";
import "./style.css";

function WalletStatus() {
  const account = useCurrentAccount();
  const wallet = useCurrentWallet();
  const network = useCurrentNetwork();

  if (!agentQProviderAvailable) {
    return (
      <section className="panel warning">
        <h2>Agent-Q provider unavailable</h2>
        <p>
          This example does not create a fake provider. Inject a browser-safe
          Agent-Q provider before app startup to register the Agent-Q wallet.
        </p>
      </section>
    );
  }

  if (!account) {
    return (
      <section className="panel">
        <h2>No wallet connected</h2>
        <p>Use the dapp-kit connect button to select the Agent-Q Sui wallet.</p>
      </section>
    );
  }

  return (
    <section className="panel">
      <h2>Connected</h2>
      <dl>
        <dt>Wallet</dt>
        <dd>{wallet?.name ?? "Unknown"}</dd>
        <dt>Address</dt>
        <dd>{account.address}</dd>
        <dt>Network</dt>
        <dd>{network}</dd>
      </dl>
    </section>
  );
}

export function App() {
  return (
    <DAppKitProvider dAppKit={dAppKit}>
      <main>
        <header>
          <h1>Agent-Q Sui dapp-kit Example</h1>
          <ConnectButton />
        </header>
        <WalletStatus />
      </main>
    </DAppKitProvider>
  );
}
