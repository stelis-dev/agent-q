import type { GatewayCore } from "@stelis/agent-q-client/admin";
import { toGatewayError, toPublicError } from "@stelis/agent-q-client/adapter-internal";
import {
  SIGN_RESULT_ERROR_MESSAGES,
  SUI_ED25519_SIGNATURE_BASE64_PATTERN,
  validateSignTransactionParamsInput,
} from "@stelis/agent-q-client/protocol";

export const SUI_SIGN_CLI_HELP = `Agent-Q Sui offline-signing bridge

Usage:
  agent-q-sui-sign --tx-bytes <base64> --network <mainnet|testnet|devnet|localnet> [--device-id <id>] [--purpose <purpose>]
  <unsigned-tx-command> | agent-q-sui-sign --network <network> --tx-bytes -
  agent-q-sui-sign --help

Submits the shared Sui sign_transaction request and prints the Firmware-authored
serialized signature to stdout. Firmware remains the signing authority. This
command is not the Sui CLI JSON-RPC external-signer protocol.`;

export type SuiSignCliCore = Pick<
  GatewayCore,
  "connectDevice" | "disconnectDevice" | "getAccounts" | "signTransaction"
>;

export interface SuiSignCliDependencies {
  core: SuiSignCliCore;
  readStdin(): Promise<string>;
  writeStdout(text: string): Promise<void>;
  writeStderr(text: string): Promise<void>;
}

interface SuiSignCliFailure {
  code: string;
  message: string;
  retryable?: boolean;
}

export async function runSuiSignCli(
  args: string[],
  dependencies: SuiSignCliDependencies,
): Promise<number> {
  if (args.includes("--help") || args.includes("-h")) {
    await dependencies.writeStdout(`${SUI_SIGN_CLI_HELP}\n`);
    return 0;
  }

  const network = flagValue(args, "--network");
  const deviceId = flagValue(args, "--device-id");
  const purpose = flagValue(args, "--purpose");
  let txBytes = flagValue(args, "--tx-bytes");
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
    validatedParams = validateSignTransactionParamsInput({ network, txBytes }, "agent-q-sui-sign");
  } catch (error) {
    const gatewayError = toGatewayError(error);
    return writeFailure(dependencies, toPublicError(gatewayError.code, gatewayError.retryable));
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
      // The address hint is optional and cannot block signing.
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
        message: SIGN_RESULT_ERROR_MESSAGES[result.status],
      });
      return resultCode;
    }
    if (!SUI_ED25519_SIGNATURE_BASE64_PATTERN.test(result.signature)) {
      resultCode = await writeFailure(dependencies, {
        code: "protocol_error",
        message: "The device returned an unexpected signature shape.",
      });
      return resultCode;
    }

    await dependencies.writeStdout(`${result.signature}\n`);
    signatureProduced = true;
    resultCode = 0;
    return resultCode;
  } catch (error) {
    const gatewayError = toGatewayError(error);
    resultCode = await writeFailure(
      dependencies,
      toPublicError(gatewayError.code, gatewayError.retryable),
    );
    return resultCode;
  } finally {
    if (connected) {
      try {
        await dependencies.core.disconnectDevice({ deviceId, purpose });
      } catch {
        if (!signatureProduced) {
          await dependencies.writeStderr(
            `${JSON.stringify({
              code: "gateway_error",
              message: "Agent-Q could not confirm session cleanup.",
              retryable: true,
            })}\n`,
          );
        }
      }
    }
  }
}

function flagValue(args: string[], name: string): string | undefined {
  const index = args.indexOf(name);
  if (index === -1 || index + 1 >= args.length) {
    return undefined;
  }
  return args[index + 1];
}

async function writeFailure(
  dependencies: SuiSignCliDependencies,
  failure: SuiSignCliFailure,
): Promise<number> {
  await dependencies.writeStderr(`${JSON.stringify(failure)}\n`);
  return 1;
}
