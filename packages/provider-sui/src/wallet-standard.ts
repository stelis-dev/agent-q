import type { ClientWithCoreApi } from "@mysten/sui/client";
import { Transaction } from "@mysten/sui/transactions";
import { fromBase64, toBase64 } from "@mysten/sui/utils";
import {
  getWallets,
  ReadonlyWalletAccount,
  StandardConnect,
  StandardDisconnect,
  StandardEvents,
  SUI_CHAINS,
  SuiSignTransaction,
  type IdentifierArray,
  type IdentifierString,
  type StandardConnectMethod,
  type StandardDisconnectMethod,
  type StandardEventsChangeProperties,
  type StandardEventsOnMethod,
  type SuiChain,
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
};

export type AgentQSuiWalletGetAccountsResult = {
  source: string;
  accounts?: AgentQSuiWalletSuiAccount[];
};

export type AgentQSuiWalletSignByUserResult = {
  source: string;
  status?: string;
  signature?: string;
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
  signByUser(input: {
    deviceId?: string;
    purpose?: string;
    chain: "sui";
    method: "sign_transaction";
    network: AgentQSuiNetwork;
    txBytes: string;
  }): Promise<AgentQSuiWalletSignByUserResult>;
};

export type AgentQSuiWalletRegistration = {
  wallet: AgentQSuiWallet;
  unregister: () => void;
};

const DEFAULT_WALLET_ID = "stelis:agent-q:sui";
const DEFAULT_WALLET_NAME = "Agent-Q Sui";
const DEFAULT_WALLET_ICON =
  "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIzMiIgaGVpZ2h0PSIzMiIgdmlld0JveD0iMCAwIDMyIDMyIj48cmVjdCB3aWR0aD0iMzIiIGhlaWdodD0iMzIiIHJ4PSI2IiBmaWxsPSIjMTExODI3Ii8+PHRleHQgeD0iMTYiIHk9IjIwIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjExIiBmb250LWZhbWlseT0iQXJpYWwsIHNhbnMtc2VyaWYiIGZpbGw9IiNmOGZhZmMiPkFRPC90ZXh0Pjwvc3ZnPg==" as Wallet["icon"];
// Keep bounded dapp-facing messages local so this subpath stays client-runtime free.
const SIGN_BY_USER_DAPP_ERROR_MESSAGES: Record<string, string> = {
  not_connected: "Agent-Q Sui wallet is not connected.",
  session_ended: "Agent-Q Sui wallet session ended before signing completed.",
  user_rejected: "The signing request was rejected on the device.",
  user_timed_out: "The signing request timed out on the device.",
  signing_failed: "The device could not produce a signature.",
};
const UNKNOWN_SIGN_BY_USER_DAPP_ERROR_MESSAGE = "Agent-Q signByUser did not return a signed result.";

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
  return fromBase64(publicKey);
}

function errorForSignResult(status: string): Error {
  return new Error(
    SIGN_BY_USER_DAPP_ERROR_MESSAGES[status] ?? UNKNOWN_SIGN_BY_USER_DAPP_ERROR_MESSAGE,
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
    this.id = options.id ?? DEFAULT_WALLET_ID;
    this.name = options.name ?? DEFAULT_WALLET_NAME;
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
        const accounts = await this.#provider.getAccounts(this.#deviceScope);
        if (accounts.source !== "live" || !Array.isArray(accounts.accounts) || accounts.accounts.length === 0) {
          throw new Error("Agent-Q Sui wallet could not read a connected Sui account.");
        }
        const nextAccounts = accounts.accounts
          .filter((account) => account.chain === "sui")
          .map((account) => new ReadonlyWalletAccount({
            address: account.address,
            publicKey: accountPublicKeyBytes(account.publicKey),
            chains: this.#chains,
            features: [SuiSignTransaction],
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
    const activeAccount = this.#requireActiveAccount(account, chain);
    const network = chainToNetwork(chain);
    const parsedTransaction = Transaction.from(await transaction.toJSON());
    parsedTransaction.setSenderIfNotSet(activeAccount.address);
    const bytes = await parsedTransaction.build({ client: this.#getClient(network) });
    signal?.throwIfAborted();
    const txBytes = toBase64(bytes);
    const result = await this.#provider.signByUser({
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
    const signature = result.signature;
    if (typeof signature !== "string" || signature.length === 0) {
      throw errorForSignResult("missing_signature");
    }
    return {
      bytes: txBytes,
      signature,
    };
  };

  #requireActiveAccount(account: WalletAccount, chain: IdentifierString): ReadonlyWalletAccount {
    if (!isSuiChain(chain)) {
      throw new Error("Agent-Q Sui wallet account does not support the requested signing feature.");
    }
    const activeAccount = this.#accounts.find((candidate) => candidate.address === account.address);
    if (!activeAccount) {
      throw new Error("Agent-Q Sui wallet account is not connected.");
    }
    if (!activeAccount.chains.includes(chain) || !activeAccount.features.includes(SuiSignTransaction)) {
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
    id: options.id ?? DEFAULT_WALLET_ID,
    initialize({ networks, getClient }) {
      return registerAgentQSuiWallet({
        ...options,
        chains: networksToChains(networks),
        getClient: (network) => getClient(network),
      });
    },
  };
}
