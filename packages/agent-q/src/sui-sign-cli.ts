import type { AgentQCore } from "@stelis/agent-q-core";
import { toPublicErrorFromUnknown } from "@stelis/agent-q-core/adapter-internal";
import {
  SIGNING_OUTCOME_ERROR_MESSAGES,
  SUI_SCHEME_PREFIXED_ED25519_PUBLIC_KEY_BYTES,
  SUI_ED25519_SIGNATURE_BASE64_PATTERN,
  SUI_SIGNATURE_SCHEME_FLAG_ED25519,
  SUI_SIGN_TRANSACTION_NETWORKS,
  isSuiTransactionSignatureEnvelopeBase64,
  type Account,
  type SuiSignTransactionNetwork,
  validateSignTransactionParamsInput,
} from "@stelis/agent-q-core/protocol";

import {
  formatSuiExternalSignerJsonRpcError,
  formatSuiExternalSignerJsonRpcResult,
  parseSuiExternalSignerJsonRpcRequest,
  parseSuiExternalSignerKeysParams,
  parseSuiExternalSignerPublicKeyParams,
  parseSuiExternalSignerSignParams,
  type SuiExternalSignerJsonRpcRequest,
  type SuiExternalSignerPublicKeyResponse,
} from "./sui-external-signer-jsonrpc.js";

export const SUI_SIGN_CLI_HELP = `Agent-Q Sui CLI external signer

Usage:
  npm install -g @stelis/agent-q
  agent-q serve --request-connect
  # without a global install:
  npm exec --yes --package @stelis/agent-q -- agent-q serve --request-connect
  sui external-keys list-keys agent-q-sui-signer
  sui external-keys add-existing "<KEY_ID_FROM_LIST_KEYS>" agent-q-sui-signer
  sui client switch --address <SUI_ADDRESS>
  sui client gas <SUI_ADDRESS> --json
  sui client pay-sui \\
    --input-coins <SUI_COIN_OBJECT_ID> \\
    --recipients <TO_ADDRESS> \\
    --amounts <MIST_AMOUNT> \\
    --gas-budget <GAS_BUDGET> \\
    --sender <SUI_ADDRESS> \\
    --json

Advanced:
  agent-q-sui-signer configure --network <mainnet|testnet|devnet|localnet> [--device-id <id>] [--purpose <purpose>]
  agent-q-sui-signer --tx-bytes <base64> --network <mainnet|testnet|devnet|localnet> [--device-id <id>] [--purpose <purpose>]
  agent-q-sui-signer --help

Sui CLI calls this program as an external signer. Keep agent-q running while Sui
CLI uses the signer. agent-q-sui-signer must be on PATH when Sui CLI invokes it.
If @stelis/agent-q is not globally installed, run setup and Sui CLI commands
through: npm exec --yes --package @stelis/agent-q -- ...
The signer calls the local Agent-Q server, and the server sends signing requests
to Firmware. Signing material stays under Firmware control on the device.`;

export type SuiSignCliCore = Pick<
  AgentQCore,
  "connectDevice" | "disconnectDevice" | "getAccounts" | "signTransaction"
>;

export interface SuiSignCliDependencies {
  core: SuiSignCliCore;
  readStdin(): Promise<string>;
  writeStdout(text: string): Promise<void>;
  writeStderr(text: string): Promise<void>;
  loadConfig?(): Promise<SuiSignCliConfig>;
  saveConfig?(config: SuiSignCliConfig): Promise<void>;
}

interface SuiSignCliFailure {
  code: string;
  message: string;
  retryable?: boolean;
}

export interface SuiSignCliConfig {
  network?: SuiSignTransactionNetwork;
  deviceId?: string;
  purpose?: string;
}

const SUI_SIGN_CLI_VALUE_FLAGS = new Set(["--network", "--tx-bytes", "--device-id", "--purpose"]);
const SUI_SIGN_CLI_CONFIG_VALUE_FLAGS = new Set(["--network", "--device-id", "--purpose"]);

export async function runSuiSignCli(
  args: string[],
  dependencies: SuiSignCliDependencies,
): Promise<number> {
  if (args.includes("--help") || args.includes("-h")) {
    await dependencies.writeStdout(`${SUI_SIGN_CLI_HELP}\n`);
    return 0;
  }

  if (args.length === 1 && args[0] === "call") {
    return runSuiExternalSignerCall(dependencies);
  }

  if (args[0] === "configure") {
    return runConfigure(args.slice(1), dependencies);
  }

  const parsedFlags = parseCliFlags(args);
  if ("failure" in parsedFlags) {
    return writeFailure(dependencies, parsedFlags.failure);
  }

  const network = parsedFlags.values.get("--network");
  const deviceId = parsedFlags.values.get("--device-id");
  const purpose = parsedFlags.values.get("--purpose");
  let txBytes = parsedFlags.values.get("--tx-bytes");
  txBytes = txBytes === "-" ? (await dependencies.readStdin()).trim() : txBytes?.trim();

  if (txBytes === undefined || txBytes.length === 0) {
    return writeFailure(dependencies, {
      code: "invalid_params",
      message: "Provide the unsigned transaction with --tx-bytes <base64> or --tx-bytes -.",
    });
  }
  if (network === undefined) {
    return writeFailure(dependencies, {
      code: "invalid_params",
      message: "Provide --network <mainnet|testnet|devnet|localnet>.",
    });
  }

  let validatedParams: ReturnType<typeof validateSignTransactionParamsInput>;
  try {
    validatedParams = validateSignTransactionParamsInput({ network, txBytes }, "agent-q-sui-signer");
  } catch (error) {
    return writeFailure(dependencies, toPublicErrorFromUnknown(error));
  }

  let connected = false;
  let signatureProduced = false;
  let resultCode = 1;
  try {
    await dependencies.core.connectDevice({ deviceId, purpose });
    connected = true;

    try {
      const accounts = await dependencies.core.getAccounts({ deviceId, purpose });
      if (accounts.source === "live" && accounts.accounts.length > 0) {
        await dependencies.writeStderr(`device address: ${accounts.accounts[0].address}\n`);
      }
    } catch {
      // The address hint is optional and cannot block direct signing.
    }

    const result = await dependencies.core.signTransaction({
      deviceId,
      purpose,
      chain: "sui",
      method: "sign_transaction",
      network: validatedParams.network,
      txBytes: validatedParams.txBytes,
    });
    if (result.source !== "live") {
      resultCode = await writeFailure(dependencies, {
        code: result.source,
        message: `The device is ${result.source} (${result.reason}).`,
      });
      return resultCode;
    }
    if (result.status !== "signed") {
      resultCode = await writeFailure(dependencies, {
        code: result.status,
        message: SIGNING_OUTCOME_ERROR_MESSAGES[result.status],
      });
      return resultCode;
    }
    if (!isSuiTransactionSignatureEnvelopeBase64(result.signature)) {
      resultCode = await writeFailure(dependencies, {
        code: "invalid_response",
        message: "The device returned an unexpected signature shape.",
      });
      return resultCode;
    }

    await dependencies.writeStdout(`${result.signature}\n`);
    signatureProduced = true;
    resultCode = 0;
    return resultCode;
  } catch (error) {
    resultCode = await writeFailure(dependencies, toPublicErrorFromUnknown(error));
    return resultCode;
  } finally {
    if (connected) {
      try {
        await dependencies.core.disconnectDevice({ deviceId, purpose });
      } catch {
        await writeCleanupFailure(dependencies, signatureProduced);
      }
    }
  }
}

async function runConfigure(
  args: string[],
  dependencies: SuiSignCliDependencies,
): Promise<number> {
  if (dependencies.saveConfig === undefined) {
    return writeFailure(dependencies, {
      code: "invalid_params",
      message: "This installation cannot save signer configuration.",
    });
  }

  const parsedFlags = parseAllowedFlags(args, SUI_SIGN_CLI_CONFIG_VALUE_FLAGS);
  if ("failure" in parsedFlags) {
    return writeFailure(dependencies, parsedFlags.failure);
  }

  const networkInput = parsedFlags.values.get("--network");
  if (networkInput === undefined) {
    return writeFailure(dependencies, {
      code: "invalid_params",
      message: "Provide --network <mainnet|testnet|devnet|localnet>.",
    });
  }

  let network: SuiSignTransactionNetwork;
  try {
    network = validateNetwork(networkInput);
  } catch (error) {
    return writeFailure(dependencies, toPublicErrorFromUnknown(error));
  }

  const config: SuiSignCliConfig = {
    network,
    ...(parsedFlags.values.has("--device-id")
      ? { deviceId: parsedFlags.values.get("--device-id") }
      : {}),
    ...(parsedFlags.values.has("--purpose") ? { purpose: parsedFlags.values.get("--purpose") } : {}),
  };
  await dependencies.saveConfig(config);
  await dependencies.writeStdout("Agent-Q Sui signer configured.\n");
  return 0;
}

async function runSuiExternalSignerCall(dependencies: SuiSignCliDependencies): Promise<number> {
  let request: SuiExternalSignerJsonRpcRequest;
  try {
    request = parseSuiExternalSignerJsonRpcRequest(await dependencies.readStdin());
  } catch (error) {
    await writeJsonRpcError(dependencies, null, -32700, errorMessage(error));
    return 1;
  }

  try {
    switch (request.method) {
      case "keys": {
        parseSuiExternalSignerKeysParams(request.params);
        const accounts = await readDeviceAccounts(dependencies);
        await writeJsonRpcResult(dependencies, request.id, {
          keys: accounts.map(accountToPublicKeyResponse),
        });
        return 0;
      }
      case "public_key": {
        const params = parseSuiExternalSignerPublicKeyParams(request.params);
        const account = await findDeviceAccount(dependencies, params.keyId);
        await writeJsonRpcResult(dependencies, request.id, accountToPublicKeyResponse(account));
        return 0;
      }
      case "sign": {
        const params = parseSuiExternalSignerSignParams(request.params);
        const config = await loadSignerConfig(dependencies);
        const network = config.network;
        if (network === undefined) {
          throw new Error(
            "Sui network is not configured. Run `agent-q-sui-signer configure --network <network>`.",
          );
        }
        const result = await signWithDevice(dependencies, {
          deviceId: config.deviceId,
          purpose: config.purpose,
          network,
          txBytes: params.txBytes,
          expectedKeyId: params.keyId,
        });
        await writeJsonRpcResult(dependencies, request.id, { signature: result });
        return 0;
      }
      case "create_key":
      case "sign_hashed": {
        await writeJsonRpcError(
          dependencies,
          request.id,
          -32601,
          `${request.method} is not supported by agent-q-sui-signer.`,
        );
        return 1;
      }
      default: {
        await writeJsonRpcError(dependencies, request.id, -32601, "Method not found.");
        return 1;
      }
    }
  } catch (error) {
    await writeJsonRpcError(dependencies, request.id, 1, errorMessage(error));
    return 1;
  }
}

async function readDeviceAccounts(dependencies: SuiSignCliDependencies): Promise<Account[]> {
  const config = await loadSignerConfig(dependencies);
  let connected = false;
  try {
    await dependencies.core.connectDevice({ deviceId: config.deviceId, purpose: config.purpose });
    connected = true;
    const accounts = await dependencies.core.getAccounts({
      deviceId: config.deviceId,
      purpose: config.purpose,
    });
    if (accounts.source !== "live") {
      throw new Error(`The device is ${accounts.source} (${accounts.reason}).`);
    }
    return accounts.accounts;
  } finally {
    if (connected) {
      await dependencies.core.disconnectDevice({
        deviceId: config.deviceId,
        purpose: config.purpose,
      });
    }
  }
}

async function findDeviceAccount(
  dependencies: SuiSignCliDependencies,
  keyId: string,
): Promise<Account> {
  const accounts = await readDeviceAccounts(dependencies);
  const account = accounts.find(
    (entry) => entry.address === keyId || (entry.keyScheme === "ed25519" && entry.derivationPath === keyId),
  );
  if (account === undefined) {
    throw new Error("Requested key is not available on the Agent-Q device.");
  }
  return account;
}

async function signWithDevice(
  dependencies: SuiSignCliDependencies,
  input: {
    deviceId?: string;
    purpose?: string;
    network: SuiSignTransactionNetwork;
    txBytes: string;
    expectedKeyId: string;
  },
): Promise<string> {
  let connected = false;
  try {
    await dependencies.core.connectDevice({ deviceId: input.deviceId, purpose: input.purpose });
    connected = true;
    const accounts = await dependencies.core.getAccounts({
      deviceId: input.deviceId,
      purpose: input.purpose,
    });
    if (accounts.source !== "live") {
      throw new Error(`The device is ${accounts.source} (${accounts.reason}).`);
    }
    const account = accounts.accounts.find(
      (entry) =>
        entry.address === input.expectedKeyId ||
        (entry.keyScheme === "ed25519" && entry.derivationPath === input.expectedKeyId),
    );
    if (account === undefined) {
      throw new Error("Requested key is not available on the Agent-Q device.");
    }
    if (account.keyScheme !== "ed25519") {
      throw new Error(
        "Sui CLI external signer cannot use zkLogin active accounts because this Sui CLI external signer protocol parses signature responses as native single-key signatures.",
      );
    }

    const result = await dependencies.core.signTransaction({
      deviceId: input.deviceId,
      purpose: input.purpose,
      chain: "sui",
      method: "sign_transaction",
      network: input.network,
      txBytes: input.txBytes,
    });
    if (result.source !== "live") {
      throw new Error(`The device is ${result.source} (${result.reason}).`);
    }
    if (result.status !== "signed") {
      throw new Error(SIGNING_OUTCOME_ERROR_MESSAGES[result.status]);
    }
    if (!SUI_ED25519_SIGNATURE_BASE64_PATTERN.test(result.signature)) {
      throw new Error("The device returned an unexpected signature shape.");
    }
    return result.signature;
  } finally {
    if (connected) {
      await dependencies.core.disconnectDevice({ deviceId: input.deviceId, purpose: input.purpose });
    }
  }
}

async function loadSignerConfig(
  dependencies: SuiSignCliDependencies,
): Promise<SuiSignCliConfig> {
  return dependencies.loadConfig === undefined ? {} : dependencies.loadConfig();
}

function accountToPublicKeyResponse(account: {
  address: string;
  publicKey: string;
  keyScheme: string;
  derivationPath?: string;
}): SuiExternalSignerPublicKeyResponse {
  if (account.keyScheme !== "ed25519" || account.derivationPath === undefined) {
    throw new Error(
      "Sui CLI external signer cannot advertise zkLogin active accounts because this Sui CLI external signer protocol parses signature responses as native single-key signatures.",
    );
  }
  const schemePrefixedPublicKey = Buffer.from(account.publicKey, "base64");
  if (
    schemePrefixedPublicKey.length !== SUI_SCHEME_PREFIXED_ED25519_PUBLIC_KEY_BYTES ||
    schemePrefixedPublicKey[0] !== SUI_SIGNATURE_SCHEME_FLAG_ED25519 ||
    schemePrefixedPublicKey.toString("base64") !== account.publicKey
  ) {
    throw new Error("The device returned an unexpected public key shape.");
  }
  const rawPublicKey = Buffer.from(schemePrefixedPublicKey.subarray(1)).toString("base64");
  return {
    key_id: account.derivationPath,
    public_key: { Ed25519: rawPublicKey },
    sui_address: account.address,
  };
}

function validateNetwork(value: string): SuiSignTransactionNetwork {
  if (!SUI_SIGN_TRANSACTION_NETWORKS.includes(value as SuiSignTransactionNetwork)) {
    throw new Error("Unsupported Sui network.");
  }
  return value as SuiSignTransactionNetwork;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Agent-Q signer request failed.";
}

async function writeJsonRpcResult(
  dependencies: SuiSignCliDependencies,
  id: number,
  result: unknown,
): Promise<void> {
  await dependencies.writeStdout(formatSuiExternalSignerJsonRpcResult(id, result));
}

async function writeJsonRpcError(
  dependencies: SuiSignCliDependencies,
  id: number | null,
  code: number,
  message: string,
): Promise<void> {
  await dependencies.writeStdout(formatSuiExternalSignerJsonRpcError(id, code, message));
}

function parseCliFlags(args: string[]):
  | { values: Map<string, string> }
  | { failure: SuiSignCliFailure } {
  return parseAllowedFlags(args, SUI_SIGN_CLI_VALUE_FLAGS);
}

function parseAllowedFlags(
  args: string[],
  allowedFlags: Set<string>,
):
  | { values: Map<string, string> }
  | { failure: SuiSignCliFailure } {
  const values = new Map<string, string>();
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (!arg.startsWith("--")) {
      return {
        failure: {
          code: "invalid_params",
          message: `Unsupported argument: ${arg}. Use --help for usage.`,
        },
      };
    }

    const equalsIndex = arg.indexOf("=");
    const name = equalsIndex === -1 ? arg : arg.slice(0, equalsIndex);
    if (!allowedFlags.has(name)) {
      return {
        failure: {
          code: "invalid_params",
          message: `Unsupported flag: ${name}. Use --help for usage.`,
        },
      };
    }
    if (values.has(name)) {
      return {
        failure: {
          code: "invalid_params",
          message: `Duplicate flag: ${name}.`,
        },
      };
    }

    let value: string | undefined;
    if (equalsIndex === -1) {
      value = args[index + 1];
      const isStdinTxBytes = name === "--tx-bytes" && value === "-";
      if (value === undefined || (value.startsWith("-") && !isStdinTxBytes)) {
        return {
          failure: {
            code: "invalid_params",
            message: `Provide a value for ${name}.`,
          },
        };
      }
      index += 1;
    } else {
      value = arg.slice(equalsIndex + 1);
      if (value.length === 0) {
        return {
          failure: {
            code: "invalid_params",
            message: `Provide a value for ${name}.`,
          },
        };
      }
    }

    values.set(name, value);
  }
  return { values };
}

async function writeFailure(
  dependencies: SuiSignCliDependencies,
  failure: SuiSignCliFailure,
): Promise<number> {
  await dependencies.writeStderr(`${JSON.stringify(failure)}\n`);
  return 1;
}

async function writeCleanupFailure(
  dependencies: SuiSignCliDependencies,
  signatureProduced: boolean,
): Promise<void> {
  try {
    await dependencies.writeStderr(
      `${JSON.stringify({
        code: "unknown_error",
        message: signatureProduced
          ? "Agent-Q produced a signature but could not confirm session cleanup."
          : "Agent-Q could not confirm session cleanup.",
        retryable: true,
      })}\n`,
    );
  } catch {
    // Cleanup diagnostics must not overwrite the primary signing outcome.
  }
}
