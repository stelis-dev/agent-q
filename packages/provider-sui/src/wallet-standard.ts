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
  keyScheme: "ed25519";
  derivationPath: "m/44'/784'/0'/0'/0'";
};

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
    gatewayName?: string;
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
  "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgLTE5IDMyOSAzMjkiIGNvbG9yPSIjMjEyMTIxIj4KPHN0eWxlPgogIC8qIEV4dGVybmFsIG92ZXJyaWRlOiBzZXQgQ1NTIGNvbG9yIG9yIC0tYWdlbnQtKiBvbiB0aGUgcGFyZW50LgogICAgIC5yaW5nIHsgZmlsbDogY3VycmVudENvbG9yIH0gIC5maWxsIHsgZmlsbDogdmFyKC0tYWdlbnQtYmctY29sb3IsICNmZmYpIH0KICAgICB0ZXh0ICB7IGZpbGw6IGN1cnJlbnRDb2xvciB9ICovCjwvc3R5bGU+CjxwYXRoIGQ9Ik0zNS4wIDcxLjBDMjkuMCA3OS4yIDI1LjMgODcuMiAyMi4wIDk1LjBDMTguNyAxMDIuOCAxNi43IDExMC4wIDE1LjAgMTE4LjBDMTMuMyAxMjYuMCAxMi4yIDEzMy44IDEyLjAgMTQzLjBDMTEuOCAxNTIuMiAxMi4zIDE2My4zIDE0LjAgMTczLjBDMTUuNyAxODIuNyAxOS4yIDE5My41IDIyLjAgMjAxLjBDMjQuOCAyMDguNSAyNy4yIDIxMi4yIDMxLjAgMjE4LjBDMzQuOCAyMjMuOCAzOC44IDIyOS44IDQ1LjAgMjM2LjBDNTEuMiAyNDIuMiA1OS4zIDI0OS41IDY4LjAgMjU1LjBDNzYuNyAyNjAuNSA4Ny4zIDI2NS41IDk3LjAgMjY5LjBDMTA2LjcgMjcyLjUgMTE4LjIgMjc0LjUgMTI2LjAgMjc2LjBDMTMzLjggMjc3LjUgMTM0LjAgMjc3LjcgMTQ0LjAgMjc4LjBDMTU0LjAgMjc4LjMgMTc0LjUgMjc4LjcgMTg2LjAgMjc4LjBDMTk3LjUgMjc3LjMgMjAzLjAgMjc2LjUgMjEzLjAgMjc0LjBDMjIzLjAgMjcxLjUgMjM5LjcgMjY0LjggMjQ2LjAgMjYzLjBDMjUyLjMgMjYxLjIgMjQ3LjMgMjYyLjAgMjUxLjAgMjYzLjBDMjU0LjcgMjY0LjAgMjYyLjMgMjY4LjAgMjY4LjAgMjY5LjBDMjczLjcgMjcwLjAgMjc5LjUgMjcwLjAgMjg1LjAgMjY5LjBDMjkwLjUgMjY4LjAgMjk2LjcgMjY1LjcgMzAxLjAgMjYzLjBDMzA1LjMgMjYwLjMgMzA4LjcgMjU2LjIgMzExLjAgMjUzLjBDMzEzLjMgMjQ5LjggMzE0LjIgMjQ4LjAgMzE1LjAgMjQ0LjBDMzE1LjggMjQwLjAgMzE2LjMgMjMzLjIgMzE2LjAgMjI5LjBDMzE1LjcgMjI0LjggMzE1LjAgMjIyLjcgMzEzLjAgMjE5LjBDMzExLjAgMjE1LjMgMzA1LjcgMjA5LjcgMzA0LjAgMjA3LjBDMzAyLjMgMjA0LjMgMzAyLjAgMjA2LjMgMzAzLjAgMjAzLjBDMzA0LjAgMTk5LjcgMzA4LjAgMTk0LjIgMzEwLjAgMTg3LjBDMzEyLjAgMTc5LjggMzE0LjIgMTY4LjggMzE1LjAgMTYwLjBDMzE1LjggMTUxLjIgMzE1LjUgMTQxLjcgMzE1LjAgMTM0LjBDMzE0LjUgMTI2LjMgMzEzLjcgMTIwLjggMzEyLjAgMTE0LjBDMzEwLjMgMTA3LjIgMzA4LjcgMTAwLjggMzA1LjAgOTMuMEMzMDEuMyA4NS4yIDI5Ni4yIDc1LjIgMjkwLjAgNjcuMEMyODMuOCA1OC44IDI3My44IDQ5LjMgMjY4LjAgNDQuMEMyNjIuMiAzOC43IDI2MS4yIDM4LjUgMjU1LjAgMzUuMEMyNDguOCAzMS41IDIzOS43IDI2LjMgMjMxLjAgMjMuMEMyMjIuMyAxOS43IDIxMS44IDE2LjggMjAzLjAgMTUuMEMxOTQuMiAxMy4yIDE4OS43IDEyLjIgMTc4LjAgMTIuMEMxNjYuMyAxMS44IDE0Ni4zIDEyLjIgMTMzLjAgMTQuMEMxMTkuNyAxNS44IDEwNy43IDE5LjcgOTguMCAyMy4wQzg4LjMgMjYuMyA4MS43IDMwLjIgNzUuMCAzNC4wQzY4LjMgMzcuOCA2NC43IDM5LjggNTguMCA0Ni4wQzUxLjMgNTIuMiA0MS4wIDYyLjggMzUuMCA3MS4wWiIgZmlsbD0iI0ZGRkZGRiIgY2xhc3M9ImZpbGwiLz4KPHBhdGggZD0iTTM1LjAgNzEuMEMyOS4wIDc5LjIgMjUuMyA4Ny4yIDIyLjAgOTUuMEMxOC43IDEwMi44IDE2LjcgMTEwLjAgMTUuMCAxMTguMEMxMy4zIDEyNi4wIDEyLjIgMTMzLjggMTIuMCAxNDMuMEMxMS44IDE1Mi4yIDEyLjMgMTYzLjMgMTQuMCAxNzMuMEMxNS43IDE4Mi43IDE5LjIgMTkzLjUgMjIuMCAyMDEuMEMyNC44IDIwOC41IDI3LjIgMjEyLjIgMzEuMCAyMTguMEMzNC44IDIyMy44IDM4LjggMjI5LjggNDUuMCAyMzYuMEM1MS4yIDI0Mi4yIDU5LjMgMjQ5LjUgNjguMCAyNTUuMEM3Ni43IDI2MC41IDg3LjMgMjY1LjUgOTcuMCAyNjkuMEMxMDYuNyAyNzIuNSAxMTguMiAyNzQuNSAxMjYuMCAyNzYuMEMxMzMuOCAyNzcuNSAxMzQuMCAyNzcuNyAxNDQuMCAyNzguMEMxNTQuMCAyNzguMyAxNzQuNSAyNzguNyAxODYuMCAyNzguMEMxOTcuNSAyNzcuMyAyMDMuMCAyNzYuNSAyMTMuMCAyNzQuMEMyMjMuMCAyNzEuNSAyMzkuNyAyNjQuOCAyNDYuMCAyNjMuMEMyNTIuMyAyNjEuMiAyNDcuMyAyNjIuMCAyNTEuMCAyNjMuMEMyNTQuNyAyNjQuMCAyNjIuMyAyNjguMCAyNjguMCAyNjkuMEMyNzMuNyAyNzAuMCAyNzkuNSAyNzAuMCAyODUuMCAyNjkuMEMyOTAuNSAyNjguMCAyOTYuNyAyNjUuNyAzMDEuMCAyNjMuMEMzMDUuMyAyNjAuMyAzMDguNyAyNTYuMiAzMTEuMCAyNTMuMEMzMTMuMyAyNDkuOCAzMTQuMiAyNDguMCAzMTUuMCAyNDQuMEMzMTUuOCAyNDAuMCAzMTYuMyAyMzMuMiAzMTYuMCAyMjkuMEMzMTUuNyAyMjQuOCAzMTUuMCAyMjIuNyAzMTMuMCAyMTkuMEMzMTEuMCAyMTUuMyAzMDUuNyAyMDkuNyAzMDQuMCAyMDcuMEMzMDIuMyAyMDQuMyAzMDIuMCAyMDYuMyAzMDMuMCAyMDMuMEMzMDQuMCAxOTkuNyAzMDguMCAxOTQuMiAzMTAuMCAxODcuMEMzMTIuMCAxNzkuOCAzMTQuMiAxNjguOCAzMTUuMCAxNjAuMEMzMTUuOCAxNTEuMiAzMTUuNSAxNDEuNyAzMTUuMCAxMzQuMEMzMTQuNSAxMjYuMyAzMTMuNyAxMjAuOCAzMTIuMCAxMTQuMEMzMTAuMyAxMDcuMiAzMDguNyAxMDAuOCAzMDUuMCA5My4wQzMwMS4zIDg1LjIgMjk2LjIgNzUuMiAyOTAuMCA2Ny4wQzI4My44IDU4LjggMjczLjggNDkuMyAyNjguMCA0NC4wQzI2Mi4yIDM4LjcgMjYxLjIgMzguNSAyNTUuMCAzNS4wQzI0OC44IDMxLjUgMjM5LjcgMjYuMyAyMzEuMCAyMy4wQzIyMi4zIDE5LjcgMjExLjggMTYuOCAyMDMuMCAxNS4wQzE5NC4yIDEzLjIgMTg5LjcgMTIuMiAxNzguMCAxMi4wQzE2Ni4zIDExLjggMTQ2LjMgMTIuMiAxMzMuMCAxNC4wQzExOS43IDE1LjggMTA3LjcgMTkuNyA5OC4wIDIzLjBDODguMyAyNi4zIDgxLjcgMzAuMiA3NS4wIDM0LjBDNjguMyAzNy44IDY0LjcgMzkuOCA1OC4wIDQ2LjBDNTEuMyA1Mi4yIDQxLjAgNjIuOCAzNS4wIDcxLjBaIE00Mi4wIDc4LjBDNDYuNSA3MS44IDUzLjcgNjMuMCA2MC4wIDU3LjBDNjYuMyA1MS4wIDcyLjMgNDYuNSA4MC4wIDQyLjBDODcuNyAzNy41IDk3LjggMzMuMCAxMDYuMCAzMC4wQzExNC4yIDI3LjAgMTIyLjUgMjUuMyAxMjkuMCAyNC4wQzEzNS41IDIyLjcgMTM2LjAgMjIuMyAxNDUuMCAyMi4wQzE1NC4wIDIxLjcgMTc0LjAgMjEuNyAxODMuMCAyMi4wQzE5Mi4wIDIyLjMgMTkxLjUgMjIuMyAxOTkuMCAyNC4wQzIwNi41IDI1LjcgMjE5LjggMjkuMCAyMjguMCAzMi4wQzIzNi4yIDM1LjAgMjQxLjIgMzcuNyAyNDguMCA0Mi4wQzI1NC44IDQ2LjMgMjYzLjIgNTIuNyAyNjkuMCA1OC4wQzI3NC44IDYzLjMgMjc4LjMgNjcuMiAyODMuMCA3NC4wQzI4Ny43IDgwLjggMjk0LjAgOTIuOCAyOTcuMCA5OS4wQzMwMC4wIDEwNS4yIDI5OS43IDEwNS43IDMwMS4wIDExMS4wQzMwMi4zIDExNi4zIDMwNC4yIDEyNC4yIDMwNS4wIDEzMS4wQzMwNS44IDEzNy44IDMwNi4zIDE0NC41IDMwNi4wIDE1Mi4wQzMwNS43IDE1OS41IDMwNC4zIDE2OS4yIDMwMy4wIDE3Ni4wQzMwMS43IDE4Mi44IDI5OS43IDE4OC41IDI5OC4wIDE5My4wQzI5Ni4zIDE5Ny41IDI5My44IDIwMC41IDI5My4wIDIwMy4wQzI5Mi4yIDIwNS41IDI5MS4zIDIwNS4yIDI5My4wIDIwOC4wQzI5NC43IDIxMC44IDMwMC44IDIxNi44IDMwMy4wIDIyMC4wQzMwNS4yIDIyMy4yIDMwNS4zIDIyNC41IDMwNi4wIDIyNy4wQzMwNi43IDIyOS41IDMwNy41IDIzMS41IDMwNy4wIDIzNS4wQzMwNi41IDIzOC41IDMwNS4zIDI0NC4zIDMwMy4wIDI0OC4wQzMwMC43IDI1MS43IDI5Ni4zIDI1NS4wIDI5My4wIDI1Ny4wQzI4OS43IDI1OS4wIDI4Ni43IDI1OS41IDI4My4wIDI2MC4wQzI3OS4zIDI2MC41IDI3Ni44IDI2MS4yIDI3MS4wIDI2MC4wQzI2NS4yIDI1OC44IDI1OC4zIDI1Mi4yIDI0OC4wIDI1My4wQzIzNy43IDI1My44IDIyMi4yIDI2Mi4zIDIwOS4wIDI2NS4wQzE5NS44IDI2Ny43IDE4MC41IDI2OC41IDE2OS4wIDI2OS4wQzE1Ny41IDI2OS41IDE0OS4wIDI2OC44IDE0MC4wIDI2OC4wQzEzMS4wIDI2Ny4yIDEyMi44IDI2NS44IDExNS4wIDI2NC4wQzEwNy4yIDI2Mi4yIDk5LjMgMjU5LjUgOTMuMCAyNTcuMEM4Ni43IDI1NC41IDgyLjggMjUyLjcgNzcuMCAyNDkuMEM3MS4yIDI0NS4zIDYzLjUgMjM5LjggNTguMCAyMzUuMEM1Mi41IDIzMC4yIDQ4LjMgMjI1LjggNDQuMCAyMjAuMEMzOS43IDIxNC4yIDM1LjMgMjA3LjUgMzIuMCAyMDAuMEMyOC43IDE5Mi41IDI1LjcgMTgxLjcgMjQuMCAxNzUuMEMyMi4zIDE2OC4zIDIyLjMgMTY2LjcgMjIuMCAxNjAuMEMyMS43IDE1My4zIDIxLjcgMTQxLjMgMjIuMCAxMzUuMEMyMi4zIDEyOC43IDIyLjIgMTI4LjggMjQuMCAxMjIuMEMyNS44IDExNS4yIDMwLjAgMTAxLjMgMzMuMCA5NC4wQzM2LjAgODYuNyAzNy41IDg0LjIgNDIuMCA3OC4wWiIgZmlsbD0iIzIxMjEyMSIgY2xhc3M9InJpbmciIGZpbGwtcnVsZT0iZXZlbm9kZCIvPgo8dGV4dCB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBkb21pbmFudC1iYXNlbGluZT0iY2VudHJhbCIKICBmb250LWZhbWlseT0iSmV0QnJhaW5zIE1vbm8sIE5vdG8gU2FucyBNb25vLCBOb3RvIFNhbnMgSlAsIE5vdG8gU2FucyBLUiwgdWktbW9ub3NwYWNlLCBtb25vc3BhY2UiCiAgZm9udC13ZWlnaHQ9IjcwMCIgZm9udC1zaXplPSI4Ni42IiBsZXR0ZXItc3BhY2luZz0iLTIiIGZpbGw9IiMyMTIxMjEiPjx0c3BhbiB4PSIxMzguNSIgeT0iMTQ1LjUiPiZndDtfJmx0OzwvdHNwYW4+PC90ZXh0Pgo8L3N2Zz4=" as Wallet["icon"];
const SUI_DERIVATION_PATH = "m/44'/784'/0'/0'/0'";
const SUI_ADDRESS_PATTERN = /^0x[0-9a-fA-F]{64}$/;
const DEVICE_ID_PATTERN = /^[A-Za-z0-9_.-]{1,128}$/;
const ED25519_PUBLIC_KEY_BYTES = 32;
const SUI_ED25519_SIGNATURE_BYTES = 97;
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
  return decodeCanonicalBase64(publicKey, ED25519_PUBLIC_KEY_BYTES);
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

function decodeCanonicalBase64(value: unknown, expectedBytes: number): Uint8Array {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("invalid_base64");
  }
  let bytes: Uint8Array;
  try {
    bytes = fromBase64(value);
  } catch {
    throw new Error("invalid_base64");
  }
  if (bytes.length !== expectedBytes || toBase64(bytes) !== value) {
    throw new Error("invalid_base64");
  }
  return bytes;
}

function validateWalletCapabilityAccount(value: unknown): void {
  const message = "Agent-Q Sui wallet could not read supported signing methods.";
  requireExactKeys(value, ["keyScheme", "derivationPath"], message);
  if (value.keyScheme !== "ed25519" || value.derivationPath !== SUI_DERIVATION_PATH) {
    throw new Error(message);
  }
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
    requireExactKeys(method, ["chain", "method"], message);
    const methodName = method.method;
    if (method.chain !== "sui" || (methodName !== "sign_transaction" && methodName !== "sign_personal_message")) {
      throw new Error(message);
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

function validateWalletAccount(value: unknown): AgentQSuiWalletSuiAccount {
  const message = "Agent-Q Sui wallet could not read a connected Sui account.";
  requireExactKeys(value, ["chain", "address", "publicKey", "keyScheme", "derivationPath"], message);
  if (
    value.chain !== "sui" ||
    typeof value.address !== "string" ||
    !SUI_ADDRESS_PATTERN.test(value.address) ||
    typeof value.publicKey !== "string" ||
    value.keyScheme !== "ed25519" ||
    value.derivationPath !== SUI_DERIVATION_PATH
  ) {
    throw new Error(message);
  }

  let publicKeyBytes: Uint8Array;
  try {
    publicKeyBytes = decodeCanonicalBase64(value.publicKey, ED25519_PUBLIC_KEY_BYTES);
  } catch {
    throw new Error(message);
  }
  const publicKey = value.publicKey;
  const address = value.address.toLowerCase();
  if (new Ed25519PublicKey(publicKeyBytes).toSuiAddress() !== address) {
    throw new Error(message);
  }

  return {
    chain: "sui",
    address,
    publicKey,
    keyScheme: "ed25519",
    derivationPath: SUI_DERIVATION_PATH,
  };
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
