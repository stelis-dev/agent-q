import type { AgentQSuiWalletProvider } from "@stelis/agent-q-provider-sui/wallet-standard";

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
