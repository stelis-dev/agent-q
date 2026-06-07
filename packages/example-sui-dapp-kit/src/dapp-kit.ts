import { createDAppKit } from "@mysten/dapp-kit-react";
import { SuiGrpcClient } from "@mysten/sui/grpc";
import { createAgentQSuiWalletInitializer } from "@stelis/agent-q-provider-sui/wallet-standard";
import { createAgentQProvider } from "./provider";

const NETWORKS = ["devnet"] as const;
const GRPC_URLS: Record<(typeof NETWORKS)[number], string> = {
  devnet: "https://fullnode.devnet.sui.io:443",
};

export const agentQProvider = createAgentQProvider();

export const dAppKit = createDAppKit({
  autoConnect: false,
  networks: NETWORKS,
  defaultNetwork: "devnet",
  enableBurnerWallet: false,
  slushWalletConfig: null,
  storage: null,
  createClient(network) {
    return new SuiGrpcClient({ network, baseUrl: GRPC_URLS[network] });
  },
  walletInitializers: agentQProvider === null
    ? []
    : [createAgentQSuiWalletInitializer({ provider: agentQProvider })],
});

declare module "@mysten/dapp-kit-react" {
  interface Register {
    dAppKit: typeof dAppKit;
  }
}
