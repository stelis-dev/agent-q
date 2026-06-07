import type { AgentQSuiWalletProvider } from "@stelis/agent-q-provider-sui/wallet-standard";
import { createAgentQSuiBrowserProvider } from "@stelis/agent-q-provider-sui/browser";

export function createAgentQProvider(): AgentQSuiWalletProvider | null {
  if (typeof window === "undefined") {
    return null;
  }
  return createAgentQSuiBrowserProvider({
    gatewayName: "Agent-Q Sui dapp-kit Example",
  });
}
