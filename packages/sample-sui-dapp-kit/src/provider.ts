import type { SuiDeviceWalletProvider } from "@stelis/agent-q-provider-sui/wallet-standard";
import { createSuiBrowserDeviceProvider } from "@stelis/agent-q-provider-sui/browser";

export function createDeviceProvider(): SuiDeviceWalletProvider | null {
  if (typeof window === "undefined") {
    return null;
  }
  return createSuiBrowserDeviceProvider({
    clientName: "Agent-Q Sui dapp-kit Sample",
  });
}
