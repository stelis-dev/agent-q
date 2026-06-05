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

const DEFAULT_WALLET_ID = "stelis:agent-q:sui";
const DEFAULT_WALLET_NAME = "Agent-Q Sui";
const DEFAULT_WALLET_ICON =
  "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIzMiIgaGVpZ2h0PSIzMiIgdmlld0JveD0iMCAwIDMyIDMyIj48cmVjdCB3aWR0aD0iMzIiIGhlaWdodD0iMzIiIHJ4PSI2IiBmaWxsPSIjMTExODI3Ii8+PHRleHQgeD0iMTYiIHk9IjIwIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LXNpemU9IjExIiBmb250LWZhbWlseT0iQXJpYWwsIHNhbnMtc2VyaWYiIGZpbGw9IiNmOGZhZmMiPkFRPC90ZXh0Pjwvc3ZnPg==" as Wallet["icon"];
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
