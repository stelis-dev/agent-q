import type { AgentQSuiWalletProvider } from "@stelis/agent-q-provider-sui/wallet-standard";
import {
  createAgentQSuiBrowserProvider,
  isAgentQSuiBrowserProviderAvailable,
} from "@stelis/agent-q-provider-sui/browser";

declare global {
  interface Window {
    agentQSuiProvider?: AgentQSuiWalletProvider;
  }
}

export function getInjectedAgentQProvider(): AgentQSuiWalletProvider | null {
  if (typeof window === "undefined") {
    return null;
  }
  return window.agentQSuiProvider ?? null;
}

export function createAgentQProvider(): AgentQSuiWalletProvider | null {
  const injectedProvider = getInjectedAgentQProvider();
  if (injectedProvider !== null) {
    return injectedProvider;
  }
  if (!isAgentQSuiBrowserProviderAvailable()) {
    return null;
  }
  return createAgentQSuiBrowserProvider({
    gatewayName: "Agent-Q Sui dapp-kit Example",
  });
}
