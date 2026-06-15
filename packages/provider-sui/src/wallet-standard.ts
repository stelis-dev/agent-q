import type { ClientWithCoreApi } from "@mysten/sui/client";
import { Ed25519PublicKey } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";
import { fromBase64, toBase64 } from "@mysten/sui/utils";
import {
  getWallets,
  ReadonlyWalletAccount,
  StandardConnect,
  StandardDisconnect,
  StandardEvents,
  SUI_CHAINS,
  SuiSignPersonalMessage,
  SuiSignTransaction,
  type IdentifierArray,
  type IdentifierString,
  type StandardConnectMethod,
  type StandardDisconnectMethod,
  type StandardEventsChangeProperties,
  type StandardEventsOnMethod,
  type SuiChain,
  type SuiSignPersonalMessageMethod,
  type SuiSignTransactionMethod,
  type Wallet,
  type WalletAccount,
} from "@mysten/wallet-standard";
import { ZkLoginPublicIdentifier } from "@mysten/sui/zklogin";
type AgentQSuiNetwork = "mainnet" | "testnet" | "devnet" | "localnet";

type DAppKitInitializerInput = {
  networks: readonly unknown[];
  getClient: (network?: AgentQSuiNetwork) => ClientWithCoreApi;
};

export type AgentQSuiWalletInitializer = {
  id: string;
  initialize(input: DAppKitInitializerInput): AgentQSuiWalletRegistration;
};

export interface AgentQSuiWalletOptions {
  provider: AgentQSuiWalletProvider;
  getClient: (network: AgentQSuiNetwork) => ClientWithCoreApi;
  deviceId?: string;
  purpose?: string;
  chains?: readonly SuiChain[];
  id?: string;
  name?: string;
  icon?: Wallet["icon"];
}

export type AgentQSuiWalletSuiAccount = {
  chain: "sui";
  address: string;
  publicKey: string;
} & (
  | {
      keyScheme: "ed25519";
      derivationPath: typeof SUI_DERIVATION_PATH;
    }
  | {
      keyScheme: "zklogin";
    }
);

export type AgentQSuiWalletGetAccountsResult = {
  source: string;
  deviceId?: unknown;
  accounts?: AgentQSuiWalletSuiAccount[];
};

export type AgentQSuiWalletGetCapabilitiesResult = {
  source?: unknown;
  deviceId?: unknown;
  capabilities?: unknown;
  signing?: unknown;
};

export type AgentQSuiWalletSignTransactionResult = {
  source: string;
  deviceId?: string;
  reason?: string;
  status?: string;
  authorization?: string;
  chain?: string;
  method?: string;
  signature?: string;
  messageBytes?: string;
  error?: {
    message?: string;
  };
};

export type AgentQSuiWalletProvider = {
  connectDevice(input?: {
    deviceId?: string;
    purpose?: string;
    clientName?: string;
  }): Promise<unknown>;
  disconnectDevice(input?: {
    deviceId?: string;
    purpose?: string;
  }): Promise<unknown>;
  getAccounts(input?: {
    deviceId?: string;
    purpose?: string;
  }): Promise<AgentQSuiWalletGetAccountsResult>;
  getCapabilities(input?: {
    deviceId?: string;
    purpose?: string;
  }): Promise<AgentQSuiWalletGetCapabilitiesResult>;
  signTransaction(input: {
    deviceId?: string;
    purpose?: string;
    chain: "sui";
    method: "sign_transaction";
    network: AgentQSuiNetwork;
    txBytes: string;
  }): Promise<AgentQSuiWalletSignTransactionResult>;
  signPersonalMessage(input: {
    deviceId?: string;
    purpose?: string;
    chain: "sui";
    method: "sign_personal_message";
    network: AgentQSuiNetwork;
    message: string;
  }): Promise<AgentQSuiWalletSignTransactionResult>;
};

export type AgentQSuiWalletRegistration = {
  wallet: AgentQSuiWallet;
  unregister: () => void;
};

export const AGENT_Q_SUI_WALLET_ID = "stelis:agent-q:sui";
export const AGENT_Q_SUI_WALLET_NAME = "Agent-Q";
const DEFAULT_WALLET_ICON =
  "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA1MzAgNTIwIiBmb250LWZhbWlseT0iSW50ZXIsIHNhbnMtc2VyaWYiPjxwYXRoIGQ9Ik0yMTYuOSAyOS40QzIxMS40IDMwLjMgMjA1LjggMzEuNyAyMDAuMCAzMy40QzE5NC4zIDM1LjIgMTg4LjQgMzcuNSAxODIuNCA0MC4wQzE3Ni4zIDQyLjUgMTY5LjkgNDUuNCAxNjMuOCA0OC4yQzE1Ny42IDUxLjEgMTUxLjYgNTQuMSAxNDUuNSA1Ny4xQzEzOS40IDYwLjAgMTMzLjMgNjMuMSAxMjcuMiA2Ni4xQzEyMS4xIDY5LjEgMTE1LjAgNzIuMSAxMDguOSA3NS4xQzEwMi45IDc4LjIgOTYuOCA4MS4yIDkwLjggODQuNEM4NC44IDg3LjYgNzguNyA5MC43IDcyLjkgOTQuM0M2Ny4yIDk3LjkgNjEuNCAxMDEuNSA1Ni4zIDEwNS44QzUxLjIgMTEwLjEgNDYuMyAxMTQuOCA0Mi4zIDEyMC4wQzM4LjMgMTI1LjIgMzQuOSAxMzEuMCAzMi4zIDEzNy4xQzI5LjYgMTQzLjIgMjcuOCAxNDkuOCAyNi40IDE1Ni41QzI1LjAgMTYzLjMgMjQuNCAxNzAuNCAyMy45IDE3Ny41QzIzLjMgMTg0LjYgMjMuMyAxOTEuOSAyMy4xIDE5OS4xQzIzLjAgMjA2LjQgMjMuMCAyMTMuOCAyMy4wIDIyMS4xQzIzLjAgMjI4LjQgMjMuMCAyMzUuOCAyMy4wIDI0My4xQzIzLjAgMjUwLjQgMjMuMCAyNTcuOCAyMy4wIDI2NS4xQzIzLjAgMjcyLjQgMjMuMCAyNzkuOCAyMy4wIDI4Ny4xQzIzLjAgMjk0LjQgMjMuMCAzMDEuOCAyMy4wIDMwOS4xQzIzLjAgMzE2LjQgMjMuMCAzMjMuOCAyMy4yIDMzMS4wQzIzLjQgMzM4LjIgMjMuNiAzNDUuNSAyNC4zIDM1Mi41QzI1LjAgMzU5LjYgMjUuOSAzNjYuNiAyNy40IDM3My4zQzI4LjkgMzgwLjAgMzAuOSAzODYuNiAzMy41IDM5Mi43QzM2LjIgMzk4LjkgMzkuNCA0MDQuOSA0My4yIDQxMC40QzQ3LjAgNDE1LjggNTEuNSA0MjEuMCA1Ni40IDQyNS41QzYxLjMgNDMwLjAgNjYuOCA0MzQuMCA3Mi41IDQzNy40Qzc4LjMgNDQwLjkgODQuNSA0NDMuNiA5MC43IDQ0Ni4xQzk3LjAgNDQ4LjYgMTAzLjYgNDUwLjUgMTEwLjIgNDUyLjNDMTE2LjcgNDU0LjIgMTIzLjQgNDU1LjggMTMwLjEgNDU3LjRDMTM2LjcgNDU5LjAgMTQzLjUgNDYwLjUgMTUwLjEgNDYyLjFDMTU2LjggNDYzLjYgMTYzLjUgNDY1LjIgMTcwLjIgNDY2LjhDMTc2LjkgNDY4LjMgMTgzLjYgNDY5LjkgMTkwLjMgNDcxLjRDMTk2LjkgNDczLjAgMjAzLjYgNDc0LjYgMjEwLjMgNDc2LjFDMjE3LjAgNDc3LjcgMjIzLjcgNDc5LjMgMjMwLjQgNDgwLjhDMjM3LjEgNDgyLjMgMjQzLjggNDgzLjkgMjUwLjUgNDg1LjRDMjU3LjIgNDg2LjggMjY0LjAgNDg4LjQgMjcwLjggNDg5LjVDMjc3LjYgNDkwLjcgMjg0LjQgNDkxLjkgMjkxLjMgNDkyLjVDMjk4LjEgNDkzLjEgMzA1LjAgNDkzLjQgMzExLjggNDkzLjBDMzE4LjUgNDkyLjYgMzI1LjMgNDkxLjcgMzMxLjggNDkwLjBDMzM4LjMgNDg4LjQgMzQ0LjcgNDg2LjAgMzUwLjggNDgzLjRDMzU3LjAgNDgwLjcgMzYzLjAgNDc3LjMgMzY4LjkgNDczLjhDMzc0LjggNDcwLjQgMzgwLjYgNDY2LjYgMzg2LjQgNDYyLjlDMzkyLjEgNDU5LjEgMzk3LjkgNDU1LjMgNDAzLjYgNDUxLjVDNDA5LjQgNDQ3LjcgNDE1LjIgNDQzLjkgNDIwLjkgNDQwLjBDNDI2LjYgNDM2LjIgNDMyLjQgNDMyLjQgNDM4LjEgNDI4LjRDNDQzLjcgNDI0LjQgNDQ5LjUgNDIwLjQgNDU0LjggNDE2LjFDNDYwLjEgNDExLjggNDY1LjUgNDA3LjMgNDcwLjEgNDAyLjRDNDc0LjggMzk3LjUgNDc5LjIgMzkyLjMgNDgyLjkgMzg2LjdDNDg2LjYgMzgxLjEgNDg5LjcgMzc1LjEgNDkyLjIgMzY4LjlDNDk0LjcgMzYyLjcgNDk2LjUgMzU2LjEgNDk3LjkgMzQ5LjRDNDk5LjQgMzQyLjYgNTAwLjEgMzM1LjYgNTAwLjggMzI4LjVDNTAxLjQgMzIxLjUgNTAxLjYgMzE0LjIgNTAxLjggMzA2LjlDNTAyLjAgMjk5LjcgNTAyLjAgMjkyLjQgNTAyLjAgMjg1LjBDNTAyLjAgMjc3LjcgNTAyLjAgMjcwLjQgNTAyLjAgMjYzLjBDNTAyLjAgMjU1LjcgNTAyLjAgMjQ4LjQgNTAyLjAgMjQxLjBDNTAyLjAgMjMzLjcgNTAyLjAgMjI2LjQgNTAyLjAgMjE5LjBDNTAyLjAgMjExLjcgNTAyLjAgMjA0LjQgNTAyLjAgMTk3LjBDNTAyLjAgMTg5LjcgNTAyLjEgMTgyLjMgNTAxLjkgMTc1LjFDNTAxLjcgMTY3LjggNTAxLjYgMTYwLjUgNTAxLjAgMTUzLjRDNTAwLjQgMTQ2LjQgNDk5LjcgMTM5LjMgNDk4LjIgMTMyLjZDNDk2LjggMTI1LjkgNDk0LjkgMTE5LjMgNDkyLjIgMTEzLjFDNDg5LjYgMTA2LjkgNDg2LjMgMTAxLjAgNDgyLjQgOTUuNkM0NzguNCA5MC4zIDQ3My44IDg1LjMgNDY4LjcgODEuMUM0NjMuNiA3Ni44IDQ1Ny45IDczLjIgNDUyLjAgNzAuMUM0NDYuMSA2Ny4wIDQzOS43IDY0LjYgNDMzLjMgNjIuNUM0MjYuOCA2MC40IDQyMC4xIDU4LjkgNDEzLjQgNTcuNEM0MDYuNyA1NS45IDM5OS45IDU0LjcgMzkzLjEgNTMuNEMzODYuMyA1Mi4xIDM3OS40IDUxLjAgMzcyLjUgNDkuOEMzNjUuNyA0OC42IDM1OC45IDQ3LjQgMzUyLjAgNDYuMkMzNDUuMiA0NS4xIDMzOC4zIDQzLjkgMzMxLjUgNDIuOEMzMjQuNiA0MS42IDMxNy44IDQwLjQgMzEwLjkgMzkuMkMzMDQuMSAzOC4wIDI5Ny4yIDM2LjkgMjkwLjQgMzUuN0MyODMuNSAzNC42IDI3Ni40IDMzLjMgMjY5LjggMzIuM0MyNjMuMiAzMS4zIDI1Ni44IDMwLjIgMjUwLjYgMjkuNkMyNDQuNCAyOC45IDIzOC41IDI4LjQgMjMyLjggMjguM0MyMjcuMiAyOC4zIDIyMi40IDI4LjYgMjE2LjkgMjkuNFoiIGZpbGw9IiNGQUZBRkEiIHN0cm9rZT0iIzNGM0YzRiIgc3Ryb2tlLXdpZHRoPSI4IiBzdHJva2UtbGluZWpvaW49InJvdW5kIiBzdHJva2UtbGluZWNhcD0icm91bmQiLz48cGF0aCBkPSJNNzQuNSAxNjQuOEM3MC4wIDE2NS44IDY1LjggMTY3LjYgNjEuOSAxNzAuNUM1OC4wIDE3My40IDUzLjcgMTc3LjYgNTAuOSAxODIuMUM0OC4xIDE4Ni43IDQ2LjMgMTkyLjIgNDUuMCAxOTcuOEM0My43IDIwMy4zIDQzLjYgMjA5LjQgNDMuMyAyMTUuNEM0Mi45IDIyMS40IDQzLjAgMjI3LjUgNDMuMCAyMzMuNkM0My4wIDIzOS43IDQzLjAgMjQ1LjggNDMuMCAyNTEuOUM0My4wIDI1OC4wIDQzLjAgMjY0LjEgNDMuMCAyNzAuMkM0My4wIDI3Ni4zIDQzLjAgMjgyLjQgNDMuMCAyODguNUM0My4wIDI5NC42IDQzLjAgMzAwLjcgNDMuMCAzMDYuOEM0My4wIDMxMi45IDQzLjAgMzE5LjAgNDMuMCAzMjUuMUM0My4wIDMzMS4yIDQyLjggMzM3LjQgNDMuMCAzNDMuNUM0My4yIDM0OS41IDQzLjMgMzU1LjUgNDQuMCAzNjEuM0M0NC44IDM2Ny4xIDQ1LjYgMzcyLjkgNDcuNCAzNzguM0M0OS4yIDM4My42IDUxLjcgMzg4LjkgNTQuOCAzOTMuNUM1OC4wIDM5OC4xIDYxLjkgNDAyLjQgNjYuMiA0MDUuOEM3MC42IDQwOS4zIDc1LjggNDEyLjAgODAuOSA0MTQuNEM4Ni4wIDQxNi43IDkxLjYgNDE4LjMgOTcuMCA0MTkuOUMxMDIuNSA0MjEuNSAxMDguMiA0MjIuNiAxMTMuOCA0MjMuOUMxMTkuNCA0MjUuMiAxMjUuMCA0MjYuNSAxMzAuNiA0MjcuN0MxMzYuMiA0MjkuMCAxNDEuOSA0MzAuMiAxNDcuNSA0MzEuNUMxNTMuMSA0MzIuNyAxNTguNyA0MzMuOSAxNjQuMyA0MzUuMkMxNjkuOSA0MzYuNSAxNzUuNSA0MzcuOSAxODEuMSA0MzkuMkMxODYuNyA0NDAuNSAxOTIuMyA0NDEuNyAxOTguMCA0NDIuOUMyMDMuNiA0NDQuMiAyMDkuMiA0NDUuNCAyMTQuOCA0NDYuN0MyMjAuNSA0NDcuOSAyMjYuMSA0NDkuMiAyMzEuNyA0NTAuM0MyMzcuNCA0NTEuNCAyNDMuMCA0NTIuOCAyNDguNiA0NTMuNEMyNTQuMiA0NTMuOSAyNjAuMSA0NTQuNSAyNjUuNSA0NTMuN0MyNzAuOSA0NTMuMCAyNzYuNCA0NTEuNCAyODEuMSA0NDguOUMyODUuNyA0NDYuNCAyOTAuMCA0NDIuNyAyOTMuMiA0MzguNUMyOTYuNCA0MzQuMiAyOTguNyA0MjguOSAzMDAuNCA0MjMuNUMzMDIuMSA0MTguMiAzMDIuNyA0MTIuMyAzMDMuMyA0MDYuNEMzMDMuOSA0MDAuNSAzMDMuOSAzOTQuNCAzMDQuMCAzODguNEMzMDQuMSAzODIuMyAzMDQuMCAzNzYuMiAzMDQuMCAzNzAuMUMzMDQuMCAzNjQuMCAzMDQuMCAzNTcuOSAzMDQuMCAzNTEuOEMzMDQuMCAzNDUuNyAzMDQuMCAzMzkuNSAzMDQuMCAzMzMuNEMzMDQuMCAzMjcuMyAzMDQuMCAzMjEuMiAzMDQuMCAzMTUuMUMzMDQuMCAzMDkuMCAzMDQuMCAzMDIuOSAzMDQuMCAyOTYuOEMzMDQuMCAyOTAuNyAzMDQuMCAyODQuNiAzMDQuMCAyNzguNUMzMDMuOSAyNzIuNCAzMDQuMSAyNjYuMyAzMDMuNiAyNjAuM0MzMDMuMiAyNTQuNCAzMDIuNiAyNDguNiAzMDEuMiAyNDMuMEMyOTkuOSAyMzcuNSAyOTguMSAyMzIuMCAyOTUuNSAyMjcuMUMyOTIuOCAyMjIuMiAyODkuMiAyMTcuNiAyODUuMyAyMTMuOEMyODEuMyAyMDkuOSAyNzYuNiAyMDYuNiAyNzEuNyAyMDMuOUMyNjYuOSAyMDEuMyAyNjEuMyAxOTkuNCAyNTUuOSAxOTcuN0MyNTAuNSAxOTYuMCAyNDQuOCAxOTQuOCAyMzkuMiAxOTMuNkMyMzMuNiAxOTIuMyAyMjcuOSAxOTEuNCAyMjIuMiAxOTAuMkMyMTYuNiAxODkuMCAyMTAuOSAxODcuOCAyMDUuMyAxODYuNkMxOTkuNiAxODUuNCAxOTMuOSAxODQuNCAxODguMyAxODMuMkMxODIuNiAxODIuMSAxNzcuMCAxODAuOSAxNzEuMyAxNzkuN0MxNjUuNiAxNzguNiAxNjAuMCAxNzcuNSAxNTQuMyAxNzYuNEMxNDguNiAxNzUuMiAxNDMuMCAxNzQuMSAxMzcuMyAxNzMuMEMxMzEuNiAxNzEuOCAxMjYuMCAxNzAuNyAxMjAuMyAxNjkuNkMxMTQuNiAxNjguNSAxMDguNCAxNjcuNCAxMDMuMSAxNjYuNUM5Ny45IDE2NS42IDkzLjQgMTY0LjQgODguNiAxNjQuMUM4My45IDE2My44IDc5LjAgMTYzLjcgNzQuNSAxNjQuOFoiIGZpbGw9IiM1MjUyNTIiLz48cGF0aCBkPSJNMTM4LjggMzQwLjZDMTM3LjMgMzQxLjUgMTM2LjEgMzQzLjEgMTM1LjkgMzQ0LjhDMTM1LjcgMzQ2LjQgMTM2LjQgMzQ4LjkgMTM3LjYgMzUwLjVDMTM4LjcgMzUyLjIgMTQwLjggMzUzLjggMTQyLjggMzU0LjlDMTQ0LjggMzU2LjEgMTQ3LjMgMzU2LjYgMTQ5LjYgMzU3LjJDMTUyLjAgMzU3LjggMTU0LjQgMzU4LjEgMTU2LjkgMzU4LjVDMTU5LjMgMzU4LjkgMTYxLjcgMzU5LjMgMTY0LjEgMzU5LjhDMTY2LjUgMzYwLjMgMTY4LjcgMzYxLjEgMTcxLjEgMzYxLjdDMTczLjQgMzYyLjMgMTc1LjggMzYyLjkgMTc4LjEgMzYzLjRDMTgwLjUgMzYzLjggMTgzLjAgMzY0LjIgMTg1LjQgMzY0LjZDMTg3LjggMzY1LjEgMTkwLjMgMzY1LjggMTkyLjYgMzY1LjlDMTk0LjkgMzY2LjEgMTk3LjUgMzY2LjAgMTk5LjMgMzY1LjRDMjAxLjIgMzY0LjggMjAzLjAgMzYzLjkgMjAzLjkgMzYyLjVDMjA0LjggMzYxLjEgMjA1LjEgMzU4LjYgMjA0LjcgMzU2LjlDMjA0LjMgMzU1LjIgMjAyLjggMzUzLjUgMjAxLjIgMzUyLjNDMTk5LjYgMzUxLjAgMTk3LjMgMzUwLjEgMTk1LjAgMzQ5LjRDMTkyLjggMzQ4LjYgMTkwLjMgMzQ4LjQgMTg3LjkgMzQ3LjlDMTg1LjUgMzQ3LjMgMTgzLjIgMzQ2LjggMTgwLjggMzQ2LjJDMTc4LjUgMzQ1LjYgMTc2LjIgMzQ0LjkgMTczLjggMzQ0LjRDMTcxLjQgMzQzLjggMTY5LjAgMzQzLjUgMTY2LjYgMzQzLjFDMTY0LjIgMzQyLjYgMTYxLjggMzQyLjIgMTU5LjQgMzQxLjhDMTU3LjAgMzQxLjMgMTU0LjUgMzQwLjkgMTUyLjEgMzQwLjRDMTQ5LjcgMzQwLjAgMTQ3LjIgMzM5LjEgMTQ1LjAgMzM5LjJDMTQyLjcgMzM5LjIgMTQwLjMgMzM5LjYgMTM4LjggMzQwLjZaIiBmaWxsPSIjRjBGMEYwIi8+PHBhdGggZD0iTTIxMC44IDI5Ny42QzIwOS42IDI5OC43IDIwOC44IDMwMC40IDIwOC44IDMwMi4xQzIwOC44IDMwMy45IDIwOS43IDMwNi4zIDIxMS4wIDMwNy45QzIxMi4yIDMwOS42IDIxNC4xIDMxMS4wIDIxNi4xIDMxMi4wQzIxOC4xIDMxMy4wIDIyMC43IDMxMy40IDIyMy4xIDMxMy45QzIyNS41IDMxNC40IDIyNy45IDMxNC43IDIzMC4zIDMxNS4yQzIzMi43IDMxNS42IDIzNS4yIDMxNi4xIDIzNy42IDMxNi41QzIzOS45IDMxNi44IDI0Mi41IDMxNy41IDI0NC42IDMxNy4zQzI0Ni43IDMxNy4xIDI0OC44IDMxNi4zIDI1MC4xIDMxNS4yQzI1MS4zIDMxNC4wIDI1Mi4zIDMxMi4wIDI1Mi4yIDMxMC4zQzI1Mi4xIDMwOC42IDI1MS4xIDMwNi41IDI0OS43IDMwNS4wQzI0OC40IDMwMy41IDI0Ni4yIDMwMi4zIDI0NC4yIDMwMS4zQzI0Mi4xIDMwMC4zIDIzOS42IDI5OS44IDIzNy4zIDI5OS4xQzIzNS4wIDI5OC40IDIzMi43IDI5Ny44IDIzMC4zIDI5Ny4zQzIyNy45IDI5Ni44IDIyNS40IDI5Ni4zIDIyMy4xIDI5Ni4wQzIyMC43IDI5NS43IDIxOC4xIDI5NS4xIDIxNi4xIDI5NS4zQzIxNC4wIDI5NS42IDIxMi4wIDI5Ni40IDIxMC44IDI5Ny42WiIgZmlsbD0iI0YwRjBGMCIvPjxwYXRoIGQ9Ik05Mi44IDI3Mi43QzkxLjUgMjczLjcgOTAuNyAyNzUuMyA5MC41IDI3Ny4wQzkwLjMgMjc4LjcgOTAuNyAyODEuMSA5MS43IDI4Mi44QzkyLjggMjg0LjUgOTQuNyAyODYuMSA5Ni42IDI4Ny4yQzk4LjUgMjg4LjMgMTAxLjAgMjg4LjkgMTAzLjMgMjg5LjVDMTA1LjYgMjkwLjEgMTA4LjEgMjkwLjQgMTEwLjUgMjkwLjhDMTEyLjkgMjkxLjMgMTE1LjQgMjkxLjggMTE3LjggMjkyLjFDMTIwLjIgMjkyLjQgMTIyLjggMjkzLjAgMTI1LjAgMjkyLjhDMTI3LjEgMjkyLjcgMTI5LjMgMjkyLjEgMTMwLjcgMjkxLjBDMTMyLjEgMjg5LjkgMTMzLjIgMjg4LjAgMTMzLjMgMjg2LjNDMTMzLjQgMjg0LjYgMTMyLjUgMjgyLjQgMTMxLjMgMjgwLjhDMTMwLjEgMjc5LjIgMTI4LjAgMjc3LjkgMTI2LjAgMjc2LjlDMTI0LjAgMjc1LjggMTIxLjUgMjc1LjIgMTE5LjIgMjc0LjZDMTE2LjkgMjczLjkgMTE0LjUgMjczLjQgMTEyLjEgMjcyLjlDMTA5LjcgMjcyLjUgMTA3LjIgMjcyLjAgMTA0LjkgMjcxLjdDMTAyLjYgMjcxLjMgMTAwLjMgMjcwLjggOTguMyAyNzAuOUM5Ni4zIDI3MS4xIDk0LjEgMjcxLjcgOTIuOCAyNzIuN1oiIGZpbGw9IiNGMEYwRjAiLz48cGF0aCBkPSJNNDI3LjcgMjU3LjVDNDI2LjYgMjU3LjcgNDI1LjcgMjU4LjAgNDI0LjYgMjU4LjVDNDIzLjYgMjU5LjAgNDIyLjQgMjU5LjcgNDIxLjQgMjYwLjRDNDIwLjMgMjYxLjAgNDE5LjIgMjYxLjcgNDE4LjMgMjYyLjVDNDE3LjMgMjYzLjMgNDE2LjQgMjY0LjIgNDE1LjUgMjY1LjFDNDE0LjYgMjY2LjAgNDEzLjcgMjY2LjggNDEyLjggMjY3LjhDNDEyLjAgMjY4LjcgNDExLjMgMjY5LjggNDEwLjUgMjcwLjhDNDA5LjcgMjcxLjggNDA4LjkgMjcyLjggNDA4LjIgMjczLjhDNDA3LjQgMjc0LjkgNDA2LjkgMjc2LjAgNDA2LjMgMjc3LjFDNDA1LjcgMjc4LjIgNDA1LjEgMjc5LjIgNDA0LjUgMjgwLjRDNDA0LjAgMjgxLjUgNDAzLjYgMjgyLjYgNDAzLjIgMjgzLjhDNDAyLjggMjg1LjAgNDAyLjQgMjg2LjEgNDAyLjAgMjg3LjNDNDAxLjYgMjg4LjUgNDAxLjMgMjg5LjcgNDAxLjAgMjkwLjlDNDAwLjcgMjkyLjEgNDAwLjMgMjkzLjMgNDAwLjAgMjk0LjVDMzk5LjcgMjk1LjcgMzk5LjMgMjk2LjggMzk5LjAgMjk4LjFDMzk4LjcgMjk5LjMgMzk4LjUgMzAwLjUgMzk4LjMgMzAxLjhDMzk4LjEgMzAzLjAgMzk3LjkgMzA0LjMgMzk3LjggMzA1LjZDMzk3LjggMzA2LjggMzk3LjggMzA4LjEgMzk3LjggMzA5LjNDMzk3LjggMzEwLjUgMzk3LjggMzExLjggMzk3LjggMzEzLjBDMzk3LjkgMzE0LjMgMzk3LjkgMzE1LjUgMzk4LjAgMzE2LjhDMzk4LjEgMzE4LjEgMzk4LjIgMzE5LjQgMzk4LjMgMzIwLjdDMzk4LjUgMzIxLjkgMzk4LjcgMzIzLjIgMzk5LjAgMzI0LjRDMzk5LjMgMzI1LjYgMzk5LjcgMzI2LjggNDAwLjEgMzI3LjlDNDAwLjYgMzI5LjEgNDAxLjAgMzMwLjIgNDAxLjYgMzMxLjNDNDAyLjMgMzMyLjQgNDAzLjAgMzMzLjQgNDAzLjggMzM0LjNDNDA0LjYgMzM1LjIgNDA1LjYgMzM2LjEgNDA2LjYgMzM2LjhDNDA3LjYgMzM3LjUgNDA4LjcgMzM4LjEgNDA5LjggMzM4LjZDNDExLjAgMzM5LjEgNDEyLjIgMzM5LjQgNDEzLjQgMzM5LjZDNDE0LjYgMzM5LjggNDE1LjkgMzM5LjggNDE3LjEgMzM5LjdDNDE4LjQgMzM5LjYgNDE5LjcgMzM5LjQgNDIwLjkgMzM5LjBDNDIyLjEgMzM4LjcgNDIzLjMgMzM4LjQgNDI0LjMgMzM3LjhDNDI1LjQgMzM3LjIgNDI2LjQgMzM2LjUgNDI3LjEgMzM1LjdDNDI3LjcgMzM0LjkgNDI4LjIgMzMzLjYgNDI4LjMgMzMyLjhDNDI4LjQgMzMxLjkgNDI4LjEgMzMwLjkgNDI3LjYgMzMwLjNDNDI3LjEgMzI5LjggNDI2LjIgMzI5LjQgNDI1LjMgMzI5LjRDNDI0LjQgMzI5LjMgNDIzLjIgMzI5LjggNDIyLjEgMzMwLjBDNDIwLjkgMzMwLjIgNDE5LjYgMzMwLjUgNDE4LjQgMzMwLjVDNDE3LjIgMzMwLjUgNDE2LjAgMzMwLjQgNDE0LjkgMzMwLjBDNDEzLjcgMzI5LjcgNDEyLjYgMzI5LjAgNDExLjYgMzI4LjNDNDEwLjYgMzI3LjUgNDA5LjggMzI2LjUgNDA5LjEgMzI1LjVDNDA4LjMgMzI0LjUgNDA3LjcgMzIzLjQgNDA3LjIgMzIyLjNDNDA2LjcgMzIxLjIgNDA2LjMgMzIwLjAgNDA1LjkgMzE4LjhDNDA1LjYgMzE3LjYgNDA1LjIgMzE2LjQgNDA0LjkgMzE1LjJDNDA0LjcgMzE0LjAgNDA0LjQgMzEyLjcgNDA0LjMgMzExLjVDNDA0LjIgMzEwLjIgNDA0LjMgMzA5LjAgNDA0LjMgMzA3LjdDNDA0LjQgMzA2LjUgNDA0LjUgMzA1LjIgNDA0LjcgMzAzLjlDNDA0LjggMzAyLjYgNDA1LjEgMzAxLjQgNDA1LjMgMzAwLjJDNDA1LjYgMjk4LjkgNDA1LjcgMjk3LjcgNDA2LjAgMjk2LjRDNDA2LjMgMjk1LjIgNDA2LjcgMjk0LjAgNDA3LjAgMjkyLjlDNDA3LjMgMjkxLjcgNDA3LjcgMjkwLjUgNDA4LjEgMjg5LjNDNDA4LjUgMjg4LjEgNDA4LjkgMjg3LjAgNDA5LjQgMjg1LjlDNDA5LjkgMjg0LjcgNDEwLjQgMjgzLjYgNDExLjAgMjgyLjVDNDExLjYgMjgxLjQgNDEyLjIgMjgwLjMgNDEyLjkgMjc5LjNDNDEzLjYgMjc4LjIgNDE0LjMgMjc3LjIgNDE1LjEgMjc2LjJDNDE1LjkgMjc1LjIgNDE2LjggMjc0LjIgNDE3LjcgMjczLjNDNDE4LjYgMjcyLjQgNDE5LjYgMjcxLjUgNDIwLjYgMjcwLjdDNDIxLjYgMjY5LjkgNDIyLjcgMjY5LjIgNDIzLjggMjY4LjZDNDI0LjkgMjY4LjAgNDI2LjAgMjY3LjQgNDI3LjIgMjY3LjFDNDI4LjMgMjY2LjggNDI5LjUgMjY2LjcgNDMwLjcgMjY2LjdDNDMxLjkgMjY2LjYgNDMzLjEgMjY2LjcgNDM0LjMgMjY3LjBDNDM1LjQgMjY3LjMgNDM2LjYgMjY3LjkgNDM3LjYgMjY4LjZDNDM4LjYgMjY5LjIgNDM5LjUgMjcwLjAgNDQwLjIgMjcxLjBDNDQxLjAgMjcxLjkgNDQxLjcgMjczLjAgNDQyLjMgMjc0LjFDNDQyLjkgMjc1LjIgNDQzLjMgMjc2LjMgNDQzLjcgMjc3LjVDNDQ0LjEgMjc4LjcgNDQ0LjQgMjc5LjkgNDQ0LjcgMjgxLjFDNDQ0LjkgMjgyLjMgNDQ0LjkgMjgzLjcgNDQ1LjAgMjg1LjBDNDQ1LjAgMjg2LjMgNDQ1LjAgMjg3LjYgNDQ1LjAgMjg5LjBDNDQ1LjAgMjkwLjMgNDQ0LjkgMjkxLjYgNDQ0LjggMjkyLjlDNDQ0LjcgMjk0LjIgNDQ0LjYgMjk1LjUgNDQ0LjQgMjk2LjdDNDQ0LjMgMjk4LjAgNDQ0LjAgMjk5LjIgNDQzLjggMzAwLjVDNDQzLjUgMzAxLjcgNDQzLjMgMzAyLjkgNDQzLjAgMzA0LjFDNDQyLjcgMzA1LjMgNDQyLjQgMzA2LjYgNDQxLjkgMzA3LjdDNDQxLjUgMzA4LjggNDQxLjAgMzEwLjIgNDQwLjQgMzExLjBDNDM5LjkgMzExLjcgNDM5LjMgMzEyLjEgNDM4LjUgMzEyLjJDNDM3LjggMzEyLjIgNDM2LjkgMzExLjggNDM2LjAgMzExLjVDNDM1LjEgMzExLjEgNDM0LjAgMzEwLjMgNDMzLjAgMzEwLjJDNDMyLjEgMzEwLjEgNDMxLjAgMzEwLjQgNDMwLjMgMzExLjBDNDI5LjYgMzExLjYgNDI4LjkgMzEyLjcgNDI4LjcgMzEzLjhDNDI4LjUgMzE0LjggNDI4LjYgMzE2LjEgNDI5LjAgMzE3LjJDNDI5LjMgMzE4LjMgNDMwLjAgMzE5LjQgNDMwLjggMzIwLjRDNDMxLjUgMzIxLjUgNDMyLjUgMzIyLjQgNDMzLjQgMzIzLjRDNDM0LjIgMzI0LjMgNDM1LjEgMzI1LjMgNDM2LjAgMzI2LjNDNDM2LjggMzI3LjMgNDM3LjcgMzI4LjIgNDM4LjUgMzI5LjJDNDM5LjQgMzMwLjIgNDQwLjAgMzMxLjQgNDQwLjkgMzMyLjFDNDQxLjggMzMyLjkgNDQzLjAgMzMzLjcgNDQzLjkgMzM0LjBDNDQ0LjkgMzM0LjIgNDQ1LjggMzM0LjIgNDQ2LjcgMzMzLjhDNDQ3LjUgMzMzLjQgNDQ4LjQgMzMyLjQgNDQ4LjkgMzMxLjRDNDQ5LjMgMzMwLjQgNDQ5LjQgMzI5LjEgNDQ5LjMgMzI4LjBDNDQ5LjIgMzI2LjkgNDQ4LjYgMzI1LjcgNDQ4LjEgMzI0LjdDNDQ3LjUgMzIzLjYgNDQ2LjQgMzIyLjcgNDQ1LjggMzIxLjdDNDQ1LjIgMzIwLjcgNDQ0LjcgMzE5LjcgNDQ0LjYgMzE4LjdDNDQ0LjUgMzE3LjcgNDQ0LjYgMzE2LjcgNDQ1LjAgMzE1LjZDNDQ1LjMgMzE0LjUgNDQ2LjEgMzEzLjQgNDQ2LjYgMzEyLjNDNDQ3LjEgMzExLjEgNDQ3LjUgMzEwLjAgNDQ3LjkgMzA4LjhDNDQ4LjMgMzA3LjYgNDQ4LjcgMzA2LjUgNDQ5LjAgMzA1LjNDNDQ5LjMgMzA0LjEgNDQ5LjcgMzAyLjkgNDUwLjAgMzAxLjdDNDUwLjMgMzAwLjQgNDUwLjUgMjk5LjIgNDUwLjYgMjk3LjlDNDUwLjggMjk2LjcgNDUwLjkgMjk1LjQgNDUxLjAgMjk0LjFDNDUxLjEgMjkyLjggNDUxLjIgMjkxLjUgNDUxLjMgMjkwLjJDNDUxLjQgMjg4LjkgNDUxLjYgMjg3LjYgNDUxLjcgMjg2LjRDNDUxLjcgMjg1LjEgNDUxLjcgMjgzLjkgNDUxLjcgMjgyLjZDNDUxLjYgMjgxLjQgNDUxLjUgMjgwLjAgNDUxLjMgMjc4LjhDNDUxLjIgMjc3LjUgNDUwLjkgMjc2LjMgNDUwLjcgMjc1LjFDNDUwLjQgMjczLjggNDUwLjMgMjcyLjUgNDQ5LjkgMjcxLjRDNDQ5LjYgMjcwLjIgNDQ5LjAgMjY5LjEgNDQ4LjUgMjY4LjBDNDQ4LjAgMjY2LjggNDQ3LjQgMjY1LjcgNDQ2LjcgMjY0LjdDNDQ2LjAgMjYzLjcgNDQ1LjIgMjYyLjcgNDQ0LjMgMjYxLjhDNDQzLjQgMjYwLjkgNDQyLjUgMjYwLjAgNDQxLjUgMjU5LjNDNDQwLjUgMjU4LjYgNDM5LjMgMjU4LjEgNDM4LjIgMjU3LjhDNDM3LjAgMjU3LjQgNDM1LjYgMjU3LjIgNDM0LjQgMjU3LjFDNDMzLjIgMjU3LjAgNDMyLjEgMjU2LjkgNDMxLjAgMjU3LjBDNDI5LjkgMjU3LjEgNDI4LjcgMjU3LjIgNDI3LjcgMjU3LjVaIiBmaWxsPSIjM0YzRjNGIiBvcGFjaXR5PSIwLjg1Ii8+PHBhdGggZD0iTTQzNy44IDE4Ny43QzQzNi44IDE4Ny45IDQzNS44IDE4OC4zIDQzNC44IDE4OC44QzQzMy43IDE4OS40IDQzMi42IDE5MC4xIDQzMS41IDE5MC43QzQzMC41IDE5MS4zIDQyOS4zIDE5MS44IDQyOC4yIDE5Mi40QzQyNy4yIDE5My4wIDQyNi4xIDE5My42IDQyNS4wIDE5NC4yQzQyMy45IDE5NC44IDQyMi44IDE5NS40IDQyMS43IDE5Ni4wQzQyMC43IDE5Ni42IDQxOS42IDE5Ny4zIDQxOC41IDE5Ny45QzQxNy40IDE5OC41IDQxNi4zIDE5OS4wIDQxNS4yIDE5OS42QzQxNC4xIDIwMC4yIDQxMy4wIDIwMC44IDQxMi4wIDIwMS40QzQxMC45IDIwMi4wIDQwOS44IDIwMi41IDQwOC43IDIwMy4xQzQwNy42IDIwMy43IDQwNi40IDIwNC4zIDQwNS41IDIwNS4wQzQwNC41IDIwNS43IDQwMy41IDIwNi41IDQwMi44IDIwNy4zQzQwMi4xIDIwOC4yIDQwMS41IDIwOS4yIDQwMS4zIDIxMC4yQzQwMS4yIDIxMS4xIDQwMS41IDIxMi4zIDQwMS45IDIxMi45QzQwMi40IDIxMy41IDQwMy4yIDIxMy44IDQwNC4xIDIxMy44QzQwNS4wIDIxMy45IDQwNi4yIDIxMy41IDQwNy4zIDIxMy4xQzQwOC40IDIxMi43IDQwOS41IDIxMi4wIDQxMC42IDIxMS41QzQxMS43IDIxMC45IDQxMi44IDIxMC40IDQxMy45IDIwOS44QzQxNS4wIDIwOS4yIDQxNi4xIDIwOC42IDQxNy4xIDIwOC4wQzQxOC4yIDIwNy4zIDQxOS4zIDIwNi43IDQyMC40IDIwNi4xQzQyMS40IDIwNS41IDQyMi41IDIwNC44IDQyMy42IDIwNC4yQzQyNC43IDIwMy42IDQyNS44IDIwMy4xIDQyNi45IDIwMi41QzQyOC4wIDIwMS45IDQyOS4wIDIwMS4zIDQzMC4xIDIwMC43QzQzMS4yIDIwMC4xIDQzMi40IDE5OS42IDQzMy40IDE5OS4wQzQzNC41IDE5OC40IDQzNS42IDE5Ny44IDQzNi43IDE5Ny4xQzQzNy43IDE5Ni41IDQzOC44IDE5NS45IDQzOS42IDE5NS4xQzQ0MC40IDE5NC4zIDQ0MS4zIDE5My4yIDQ0MS43IDE5Mi4zQzQ0Mi4xIDE5MS40IDQ0Mi4xIDE5MC40IDQ0MS45IDE4OS42QzQ0MS43IDE4OC44IDQ0MS4yIDE4OC4wIDQ0MC41IDE4Ny43QzQzOS44IDE4Ny40IDQzOC43IDE4Ny41IDQzNy44IDE4Ny43WiIgZmlsbD0iIzNGM0YzRiIgb3BhY2l0eT0iMC44NSIvPjwvc3ZnPg==" as Wallet["icon"];
const SUI_ADDRESS_PATTERN = /^0x[0-9a-fA-F]{64}$/;
const DEVICE_ID_PATTERN = /^[A-Za-z0-9_.-]{1,128}$/;
const UINT_DECIMAL_STRING_PATTERN = /^(0|[1-9][0-9]{0,19})$/;
const WALLET_PAYLOAD_DELIVERY_MIN_CHUNK_BYTES = 2048;
const SUI_ED25519_SIGNATURE_BYTES = 97;
const SUI_DERIVATION_PATH = "m/44'/784'/0'/0'/0'" as const;
const SUI_SIGNATURE_SCHEME_FLAG_ED25519 = 0x00;
const SUI_SIGNATURE_SCHEME_FLAG_ZKLOGIN = 0x05;
const SUI_SCHEME_PREFIXED_ED25519_PUBLIC_KEY_BYTES = 33;
const MIN_SUI_ZKLOGIN_PUBLIC_KEY_BYTES = 34;
const MAX_SUI_ZKLOGIN_PUBLIC_KEY_BYTES = 288;
// Keep bounded dapp-facing messages local so this subpath stays client-runtime free.
const SIGN_TRANSACTION_DAPP_ERROR_MESSAGES: Record<string, string> = {
  not_connected: "Agent-Q Sui wallet is not connected.",
  session_ended: "Agent-Q Sui wallet session ended before signing completed.",
  user_rejected: "The signing request was rejected on the device.",
  user_timed_out: "The signing request timed out on the device.",
  policy_rejected: "The signing request was rejected by device policy.",
  signing_failed: "The device could not produce a signature.",
};
const UNKNOWN_SIGN_TRANSACTION_DAPP_ERROR_MESSAGE = "Agent-Q signTransaction did not return a signed result.";
const UNKNOWN_SIGN_PERSONAL_MESSAGE_DAPP_ERROR_MESSAGE = "Agent-Q signPersonalMessage did not return a signed result.";

const CHAIN_TO_NETWORK: Record<SuiChain, AgentQSuiNetwork> = {
  "sui:mainnet": "mainnet",
  "sui:testnet": "testnet",
  "sui:devnet": "devnet",
  "sui:localnet": "localnet",
};

const NETWORK_TO_CHAIN: Record<AgentQSuiNetwork, SuiChain> = {
  mainnet: "sui:mainnet",
  testnet: "sui:testnet",
  devnet: "sui:devnet",
  localnet: "sui:localnet",
};

function isSuiChain(value: unknown): value is SuiChain {
  return typeof value === "string" && (SUI_CHAINS as readonly string[]).includes(value);
}

function chainToNetwork(chain: IdentifierString): AgentQSuiNetwork {
  if (!isSuiChain(chain)) {
    throw new Error(`Agent-Q Sui wallet does not support chain "${chain}".`);
  }
  return CHAIN_TO_NETWORK[chain];
}

function networkToChain(network: unknown): SuiChain {
  if (network !== "mainnet" && network !== "testnet" && network !== "devnet" && network !== "localnet") {
    throw new Error(`Agent-Q Sui wallet initializer received an unsupported network "${String(network)}".`);
  }
  return NETWORK_TO_CHAIN[network];
}

function networksToChains(networks: readonly unknown[]): SuiChain[] {
  if (!Array.isArray(networks) || networks.length === 0) {
    throw new Error("Agent-Q Sui wallet initializer requires at least one Sui network.");
  }
  return [...new Set(networks.map(networkToChain))];
}

function walletAccountFeaturesFromCapabilities(
  capabilities: AgentQSuiWalletGetCapabilitiesResult,
): Array<typeof SuiSignTransaction | typeof SuiSignPersonalMessage> {
  const message = "Agent-Q Sui wallet could not read supported signing methods.";
  requireExactKeys(capabilities, ["source", "deviceId", "capabilities", "signing"], message);
  if (
    capabilities.source !== "live" ||
    typeof capabilities.deviceId !== "string" ||
    !DEVICE_ID_PATTERN.test(capabilities.deviceId) ||
    !Array.isArray(capabilities.capabilities) ||
    capabilities.capabilities.length !== 1
  ) {
    throw new Error(message);
  }
  validateWalletCapabilityChain(capabilities.capabilities[0]);
  return validateWalletSigningCapabilities(capabilities.signing);
}

function toIdentifierArray(chains: readonly unknown[]): IdentifierArray {
  if (!Array.isArray(chains) || chains.length === 0) {
    throw new Error("Agent-Q Sui wallet requires at least one Sui chain.");
  }
  const suiChains: SuiChain[] = [];
  for (const chain of chains) {
    if (!isSuiChain(chain)) {
      throw new Error(`Agent-Q Sui wallet received an unsupported chain "${String(chain)}".`);
    }
    if (!suiChains.includes(chain)) {
      suiChains.push(chain);
    }
  }
  return suiChains as IdentifierArray;
}

function accountPublicKeyBytes(publicKey: string): Uint8Array {
  return decodeCanonicalBase64(publicKey);
}

function isSuiAddressForWalletAccountPublicKey(
  address: string,
  publicKey: string,
  expectedSchemeFlag: number,
  minBytes: number,
  maxBytes: number,
): boolean {
  try {
    const decoded = decodeCanonicalBase64(publicKey);
    if (decoded.length < minBytes || decoded.length > maxBytes || decoded[0] !== expectedSchemeFlag) {
      return false;
    }
    if (expectedSchemeFlag === SUI_SIGNATURE_SCHEME_FLAG_ED25519) {
      return new Ed25519PublicKey(decoded.slice(1)).toSuiAddress() === address;
    }
    if (expectedSchemeFlag === SUI_SIGNATURE_SCHEME_FLAG_ZKLOGIN) {
      return new ZkLoginPublicIdentifier(decoded.slice(1)).toSuiAddress() === address;
    }
    return false;
  } catch {
    return false;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireExactKeys(
  value: unknown,
  keys: readonly string[],
  errorMessage: string,
): asserts value is Record<string, unknown> {
  if (!isRecord(value)) {
    throw new Error(errorMessage);
  }
  const allowed = new Set(keys);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw new Error(errorMessage);
    }
  }
  for (const key of keys) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) {
      throw new Error(errorMessage);
    }
  }
}

function requireExactKeysWithOptional(
  value: unknown,
  requiredKeys: readonly string[],
  optionalKeys: readonly string[],
  errorMessage: string,
): asserts value is Record<string, unknown> {
  if (!isRecord(value)) {
    throw new Error(errorMessage);
  }
  const allowed = new Set([...requiredKeys, ...optionalKeys]);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw new Error(errorMessage);
    }
  }
  for (const key of requiredKeys) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) {
      throw new Error(errorMessage);
    }
  }
}

function decodeCanonicalBase64(value: unknown, expectedBytes?: number): Uint8Array {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("invalid_base64");
  }
  let bytes: Uint8Array;
  try {
    bytes = fromBase64(value);
  } catch {
    throw new Error("invalid_base64");
  }
  if ((expectedBytes !== undefined && bytes.length !== expectedBytes) || toBase64(bytes) !== value) {
    throw new Error("invalid_base64");
  }
  return bytes;
}

function validateWalletCapabilityAccount(value: unknown): void {
  const message = "Agent-Q Sui wallet could not read supported signing methods.";
  if (!isRecord(value)) {
    throw new Error(message);
  }
  if (value.keyScheme === "ed25519") {
    requireExactKeys(value, ["keyScheme", "derivationPath"], message);
    if (value.derivationPath !== SUI_DERIVATION_PATH) {
      throw new Error(message);
    }
    return;
  }
  if (value.keyScheme === "zklogin") {
    requireExactKeys(value, ["keyScheme"], message);
    return;
  }
  throw new Error(message);
}

function validateWalletCapabilityChain(value: unknown): void {
  const message = "Agent-Q Sui wallet could not read supported signing methods.";
  requireExactKeys(value, ["id", "accounts", "methods"], message);
  if (
    value.id !== "sui" ||
    !Array.isArray(value.accounts) ||
    value.accounts.length !== 1 ||
    !Array.isArray(value.methods) ||
    value.methods.length !== 0
  ) {
    throw new Error(message);
  }
  validateWalletCapabilityAccount(value.accounts[0]);
}

function validateWalletSigningCapabilities(value: unknown): Array<typeof SuiSignTransaction | typeof SuiSignPersonalMessage> {
  const message = "Agent-Q Sui wallet could not read supported signing methods.";
  requireExactKeys(value, ["authorization", "methods"], message);
  if ((value.authorization !== "user" && value.authorization !== "policy") || !Array.isArray(value.methods)) {
    throw new Error(message);
  }

  const seenMethods = new Set<string>();
  for (const method of value.methods) {
    requireExactKeysWithOptional(method, ["chain", "method"], ["payload"], message);
    const methodName = method.method;
    if (method.chain !== "sui" || (methodName !== "sign_transaction" && methodName !== "sign_personal_message")) {
      throw new Error(message);
    }
    if (method.payload !== undefined) {
      if (methodName !== "sign_transaction") {
        throw new Error(message);
      }
      validateWalletSigningPayloadCapability(method.payload, message);
    }
    if (seenMethods.has(methodName)) {
      throw new Error(message);
    }
    seenMethods.add(methodName);
  }

  if (value.authorization === "policy") {
    if (seenMethods.size !== 1 || !seenMethods.has("sign_transaction")) {
      throw new Error(message);
    }
    return [SuiSignTransaction];
  }

  if (
    seenMethods.size !== 2 ||
    !seenMethods.has("sign_transaction") ||
    !seenMethods.has("sign_personal_message")
  ) {
    throw new Error(message);
  }
  return [SuiSignTransaction, SuiSignPersonalMessage];
}

function validateWalletSigningPayloadCapability(value: unknown, message: string): void {
  requireExactKeys(value, ["kind", "inlineMaxBytes", "chunkMaxBytes", "payloadMaxBytes"], message);
  if (value.kind !== "transaction") {
    throw new Error(message);
  }
  parseWalletPayloadCapabilityUint(value.inlineMaxBytes, message);
  const chunkMaxBytes = parseWalletPayloadCapabilityUint(value.chunkMaxBytes, message);
  parseWalletPayloadCapabilityUint(value.payloadMaxBytes, message);
  if (chunkMaxBytes < WALLET_PAYLOAD_DELIVERY_MIN_CHUNK_BYTES) {
    throw new Error(message);
  }
}

function parseWalletPayloadCapabilityUint(value: unknown, message: string): number {
  if (typeof value !== "string" || !UINT_DECIMAL_STRING_PATTERN.test(value)) {
    throw new Error(message);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(message);
  }
  return parsed;
}

function validateWalletAccount(value: unknown): AgentQSuiWalletSuiAccount {
  const message = "Agent-Q Sui wallet could not read a connected Sui account.";
  if (!isRecord(value)) {
    throw new Error(message);
  }
  if (
    value.chain !== "sui" ||
    typeof value.address !== "string" ||
    !SUI_ADDRESS_PATTERN.test(value.address) ||
    typeof value.publicKey !== "string"
  ) {
    throw new Error(message);
  }

  const address = value.address.toLowerCase();
  if (value.keyScheme === "ed25519") {
    requireExactKeys(value, ["chain", "address", "publicKey", "keyScheme", "derivationPath"], message);
    if (
      value.derivationPath !== SUI_DERIVATION_PATH ||
      !isSuiAddressForWalletAccountPublicKey(
        address,
        value.publicKey,
        SUI_SIGNATURE_SCHEME_FLAG_ED25519,
        SUI_SCHEME_PREFIXED_ED25519_PUBLIC_KEY_BYTES,
        SUI_SCHEME_PREFIXED_ED25519_PUBLIC_KEY_BYTES,
      )
    ) {
      throw new Error(message);
    }
    return {
      chain: "sui",
      address,
      publicKey: value.publicKey,
      keyScheme: "ed25519",
      derivationPath: SUI_DERIVATION_PATH,
    };
  }

  if (value.keyScheme === "zklogin") {
    requireExactKeys(value, ["chain", "address", "publicKey", "keyScheme"], message);
    if (
      !isSuiAddressForWalletAccountPublicKey(
        address,
        value.publicKey,
        SUI_SIGNATURE_SCHEME_FLAG_ZKLOGIN,
        MIN_SUI_ZKLOGIN_PUBLIC_KEY_BYTES,
        MAX_SUI_ZKLOGIN_PUBLIC_KEY_BYTES,
      )
    ) {
      throw new Error(message);
    }
    return {
      chain: "sui",
      address,
      publicKey: value.publicKey,
      keyScheme: "zklogin",
    };
  }

  throw new Error(message);
}

function validateWalletAccountsResult(result: AgentQSuiWalletGetAccountsResult): AgentQSuiWalletSuiAccount[] {
  const message = "Agent-Q Sui wallet could not read a connected Sui account.";
  if (!isRecord(result) || result.source !== "live" || !Array.isArray(result.accounts)) {
    throw new Error(message);
  }
  const allowedKeys = new Set(["source", "deviceId", "accounts"]);
  for (const key of Object.keys(result)) {
    if (!allowedKeys.has(key)) {
      throw new Error(message);
    }
  }
  if (
    Object.prototype.hasOwnProperty.call(result, "deviceId") &&
    typeof (result as { deviceId?: unknown }).deviceId !== "string"
  ) {
    throw new Error(message);
  }
  return result.accounts.map(validateWalletAccount);
}

function validateSignedTransactionResult(result: AgentQSuiWalletSignTransactionResult): string {
  const message = UNKNOWN_SIGN_TRANSACTION_DAPP_ERROR_MESSAGE;
  requireExactKeys(result, ["source", "deviceId", "status", "authorization", "chain", "method", "signature"], message);
  if (
    result.source !== "live" ||
    typeof result.deviceId !== "string" ||
    result.status !== "signed" ||
    (result.authorization !== "user" && result.authorization !== "policy") ||
    result.chain !== "sui" ||
    result.method !== "sign_transaction" ||
    typeof result.signature !== "string"
  ) {
    throw errorForSignResult("unknown");
  }
  try {
    decodeCanonicalBase64(result.signature, SUI_ED25519_SIGNATURE_BYTES);
  } catch {
    throw errorForSignResult("missing_signature");
  }
  return result.signature;
}

function validateSignedPersonalMessageResult(
  result: AgentQSuiWalletSignTransactionResult,
  expectedMessageBytes: string,
): string {
  const message = UNKNOWN_SIGN_PERSONAL_MESSAGE_DAPP_ERROR_MESSAGE;
  requireExactKeys(result, ["source", "deviceId", "status", "authorization", "chain", "method", "signature", "messageBytes"], message);
  if (
    result.source !== "live" ||
    typeof result.deviceId !== "string" ||
    result.status !== "signed" ||
    result.authorization !== "user" ||
    result.chain !== "sui" ||
    result.method !== "sign_personal_message" ||
    result.messageBytes !== expectedMessageBytes ||
    typeof result.signature !== "string"
  ) {
    throw errorForSignResult("unknown", message);
  }
  try {
    decodeCanonicalBase64(result.signature, SUI_ED25519_SIGNATURE_BYTES);
  } catch {
    throw errorForSignResult("missing_signature", message);
  }
  return result.signature;
}

function errorForSignResult(
  status: string,
  unknownMessage = UNKNOWN_SIGN_TRANSACTION_DAPP_ERROR_MESSAGE,
): Error {
  return new Error(
    SIGN_TRANSACTION_DAPP_ERROR_MESSAGES[status] ?? unknownMessage,
  );
}

export class AgentQSuiWallet implements Wallet {
  readonly version = "1.0.0" as const;
  readonly id?: string;
  readonly name: string;
  readonly icon: Wallet["icon"];

  readonly #provider: AgentQSuiWalletProvider;
  readonly #getClient: (network: AgentQSuiNetwork) => ClientWithCoreApi;
  readonly #deviceScope: { deviceId?: string; purpose?: string };
  readonly #chains: IdentifierArray;
  readonly #eventHandlers = new Set<(properties: StandardEventsChangeProperties) => void>();
  #accounts: ReadonlyWalletAccount[] = [];

  constructor(options: AgentQSuiWalletOptions) {
    this.#provider = options.provider;
    this.#getClient = options.getClient;
    this.#deviceScope = {
      deviceId: options.deviceId,
      purpose: options.purpose,
    };
    this.#chains = toIdentifierArray(options.chains ?? SUI_CHAINS);
    this.id = options.id ?? AGENT_Q_SUI_WALLET_ID;
    this.name = options.name ?? AGENT_Q_SUI_WALLET_NAME;
    this.icon = options.icon ?? DEFAULT_WALLET_ICON;
  }

  get chains(): IdentifierArray {
    return this.#chains;
  }

  get accounts(): readonly ReadonlyWalletAccount[] {
    return this.#accounts;
  }

  get features(): Wallet["features"] {
    return {
      [StandardConnect]: {
        version: "1.0.0",
        connect: this.#connect,
      },
      [StandardDisconnect]: {
        version: "1.0.0",
        disconnect: this.#disconnect,
      },
      [StandardEvents]: {
        version: "1.0.0",
        on: this.#on,
      },
      [SuiSignTransaction]: {
        version: "2.0.0",
        signTransaction: this.#signTransaction,
      },
      [SuiSignPersonalMessage]: {
        version: "1.1.0",
        signPersonalMessage: this.#signPersonalMessage,
      },
    };
  }

  #connect: StandardConnectMethod = async (input = {}) => {
    if (input.silent && this.#accounts.length === 0) {
      return { accounts: [] };
    }
    if (this.#accounts.length === 0) {
      let connected = false;
      try {
        await this.#provider.connectDevice(this.#deviceScope);
        connected = true;
        const accounts = validateWalletAccountsResult(await this.#provider.getAccounts(this.#deviceScope));
        const accountFeatures = walletAccountFeaturesFromCapabilities(
          await this.#provider.getCapabilities(this.#deviceScope),
        );
        const nextAccounts = accounts
          .filter((account) => account.chain === "sui")
          .map((account) => new ReadonlyWalletAccount({
            address: account.address,
            publicKey: accountPublicKeyBytes(account.publicKey),
            chains: this.#chains,
            features: [...accountFeatures],
          }));
        if (nextAccounts.length === 0) {
          throw new Error("Agent-Q Sui wallet could not read a connected Sui account.");
        }
        this.#accounts = nextAccounts;
        this.#emit({ accounts: this.#accounts });
      } catch (error) {
        this.#accounts = [];
        if (connected) {
          try {
            await this.#provider.disconnectDevice(this.#deviceScope);
          } catch {
            // Keep the original connect failure as the caller-visible result.
          }
        }
        throw error;
      }
    }
    return { accounts: this.#accounts };
  };

  #disconnect: StandardDisconnectMethod = async () => {
    await this.#provider.disconnectDevice(this.#deviceScope);
    this.#accounts = [];
    this.#emit({ accounts: this.#accounts });
  };

  #on: StandardEventsOnMethod = (event, listener) => {
    if (event !== "change") {
      return () => {};
    }
    this.#eventHandlers.add(listener);
    return () => {
      this.#eventHandlers.delete(listener);
    };
  };

  #signTransaction: SuiSignTransactionMethod = async ({ transaction, account, chain, signal }) => {
    signal?.throwIfAborted();
    const activeAccount = this.#requireActiveAccount(account, chain, SuiSignTransaction);
    const network = chainToNetwork(chain);
    const parsedTransaction = Transaction.from(await transaction.toJSON());
    parsedTransaction.setSenderIfNotSet(activeAccount.address);
    const bytes = await parsedTransaction.build({ client: this.#getClient(network) });
    signal?.throwIfAborted();
    const txBytes = toBase64(bytes);
    const result = await this.#provider.signTransaction({
      ...this.#deviceScope,
      chain: "sui",
      method: "sign_transaction",
      network,
      txBytes,
    });
    if (result.source !== "live") {
      this.#clearAccounts();
      throw errorForSignResult(result.source);
    }
    if (result.status !== "signed") {
      throw errorForSignResult(result.status ?? "unknown");
    }
    const signature = validateSignedTransactionResult(result);
    return {
      bytes: txBytes,
      signature,
    };
  };

  #signPersonalMessage: SuiSignPersonalMessageMethod = async ({ message, account, chain }) => {
    const requestedChain = this.#resolvePersonalMessageChain(account, chain);
    this.#requireActiveAccount(account, requestedChain, SuiSignPersonalMessage);
    const network = chainToNetwork(requestedChain);
    const messageBytes = toBase64(message);
    const result = await this.#provider.signPersonalMessage({
      ...this.#deviceScope,
      chain: "sui",
      method: "sign_personal_message",
      network,
      message: messageBytes,
    });
    if (result.source !== "live") {
      this.#clearAccounts();
      throw errorForSignResult(result.source, UNKNOWN_SIGN_PERSONAL_MESSAGE_DAPP_ERROR_MESSAGE);
    }
    if (result.status !== "signed") {
      throw errorForSignResult(result.status ?? "unknown", UNKNOWN_SIGN_PERSONAL_MESSAGE_DAPP_ERROR_MESSAGE);
    }
    const signature = validateSignedPersonalMessageResult(result, messageBytes);
    return {
      bytes: messageBytes,
      signature,
    };
  };

  #resolvePersonalMessageChain(account: WalletAccount, chain?: IdentifierString): SuiChain {
    if (chain !== undefined) {
      if (!isSuiChain(chain)) {
        throw new Error("Agent-Q Sui wallet account does not support the requested signing feature.");
      }
      return chain;
    }
    for (const candidate of account.chains) {
      if (isSuiChain(candidate) && this.#chains.includes(candidate)) {
        return candidate;
      }
    }
    throw new Error("Agent-Q Sui wallet account does not support the requested signing feature.");
  }

  #requireActiveAccount(
    account: WalletAccount,
    chain: IdentifierString,
    feature: typeof SuiSignTransaction | typeof SuiSignPersonalMessage,
  ): ReadonlyWalletAccount {
    if (!isSuiChain(chain)) {
      throw new Error("Agent-Q Sui wallet account does not support the requested signing feature.");
    }
    const activeAccount = this.#accounts.find((candidate) => candidate.address === account.address);
    if (!activeAccount) {
      throw new Error("Agent-Q Sui wallet account is not connected.");
    }
    if (!activeAccount.chains.includes(chain) || !activeAccount.features.includes(feature)) {
      throw new Error("Agent-Q Sui wallet account does not support the requested signing feature.");
    }
    return activeAccount;
  }

  #clearAccounts(): void {
    if (this.#accounts.length === 0) {
      return;
    }
    this.#accounts = [];
    this.#emit({ accounts: this.#accounts });
  }

  #emit(properties: StandardEventsChangeProperties): void {
    for (const listener of this.#eventHandlers) {
      listener(properties);
    }
  }
}

export function createAgentQSuiWallet(options: AgentQSuiWalletOptions): AgentQSuiWallet {
  return new AgentQSuiWallet(options);
}

export function registerAgentQSuiWallet(options: AgentQSuiWalletOptions): AgentQSuiWalletRegistration {
  const wallet = createAgentQSuiWallet(options);
  const unregister = getWallets().register(wallet);
  return { wallet, unregister };
}

export function createAgentQSuiWalletInitializer(
  options: Omit<AgentQSuiWalletOptions, "chains" | "getClient">,
): AgentQSuiWalletInitializer {
  return {
    id: options.id ?? AGENT_Q_SUI_WALLET_ID,
    initialize({ networks, getClient }) {
      return registerAgentQSuiWallet({
        ...options,
        chains: networksToChains(networks),
        getClient: (network) => getClient(network),
      });
    },
  };
}
