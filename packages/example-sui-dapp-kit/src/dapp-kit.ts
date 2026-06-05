import { createDAppKit } from "@mysten/dapp-kit-react";
import { SuiGrpcClient } from "@mysten/sui/grpc";
import { createAgentQSuiWalletInitializer } from "@stelis/agent-q-provider-sui/wallet-standard";
import { createAgentQProvider } from "./provider";

const NETWORKS = ["testnet"] as const;
const GRPC_URLS: Record<(typeof NETWORKS)[number], string> = {
  testnet: "https://fullnode.testnet.sui.io:443",
};

const provider = createAgentQProvider();

export const agentQProviderAvailable = provider !== null;

export const dAppKit = createDAppKit({
  autoConnect: false,
  networks: NETWORKS,
  defaultNetwork: "testnet",
  enableBurnerWallet: false,
  slushWalletConfig: null,
  storage: null,
  createClient(network) {
    return new SuiGrpcClient({ network, baseUrl: GRPC_URLS[network] });
  },
  walletInitializers: provider === null
    ? []
    : [createAgentQSuiWalletInitializer({ provider })],
});

declare module "@mysten/dapp-kit-react" {
  interface Register {
    dAppKit: typeof dAppKit;
  }
}
