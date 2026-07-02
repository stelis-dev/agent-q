import { createDAppKit } from "@mysten/dapp-kit-react";
import { SuiGrpcClient } from "@mysten/sui/grpc";
import { createSuiDeviceWalletInitializer } from "@stelis/agent-q-provider-sui/wallet-standard";
import { createDeviceProvider } from "./provider";

const NETWORKS = ["devnet"] as const;
const GRPC_URLS: Record<(typeof NETWORKS)[number], string> = {
  devnet: "https://fullnode.devnet.sui.io:443",
};

export const deviceProvider = createDeviceProvider();

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
  walletInitializers: deviceProvider === null
    ? []
    : [createSuiDeviceWalletInitializer({ provider: deviceProvider })],
});

declare module "@mysten/dapp-kit-react" {
  interface Register {
    dAppKit: typeof dAppKit;
  }
}
