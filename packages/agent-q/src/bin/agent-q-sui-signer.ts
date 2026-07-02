#!/usr/bin/env node
import {
  SUI_SIGN_TRANSACTION_NETWORKS,
  type SuiSignTransactionNetwork,
} from "@stelis/agent-q-core/protocol";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

import { runSuiSignCli, type SuiSignCliConfig } from "../sui-sign-cli.js";
import { createLocalServerSuiSignCliCore } from "../sui-signer-local-client.js";

process.exitCode = await runSuiSignCli(process.argv.slice(2), {
  core: createLocalServerSuiSignCliCore(),
  async readStdin() {
    process.stdin.setEncoding("utf8");
    return readOneJsonRpcObject();
  },
  writeStdout: (text) =>
    new Promise<void>((resolve, reject) => {
      process.stdout.write(text, (error) => {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      });
    }),
  writeStderr: (text) =>
    new Promise<void>((resolve, reject) => {
      process.stderr.write(text, (error) => {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      });
    }),
  loadConfig: loadSignerConfig,
  saveConfig: saveSignerConfig,
});

function readOneJsonRpcObject(): Promise<string> {
  return new Promise((resolve, reject) => {
    let buffer = "";
    let settled = false;

    const cleanup = (): void => {
      process.stdin.off("data", onData);
      process.stdin.off("end", onEnd);
      process.stdin.off("close", onEnd);
      process.stdin.off("error", onError);
      process.stdin.pause();
      process.stdin.destroy();
    };
    const finish = (value: string): void => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      resolve(value);
    };
    const onData = (chunk: string): void => {
      buffer += chunk;
      const newlineIndex = buffer.search(/\r?\n/);
      if (newlineIndex !== -1) {
        finish(buffer.slice(0, newlineIndex + 1));
        return;
      }
      const objectEnd = completeJsonObjectEnd(buffer);
      if (objectEnd !== -1) {
        finish(buffer.slice(0, objectEnd));
      }
    };
    const onEnd = (): void => finish(buffer);
    const onError = (error: Error): void => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      reject(error);
    };

    process.stdin.on("data", onData);
    process.stdin.once("end", onEnd);
    process.stdin.once("close", onEnd);
    process.stdin.once("error", onError);
    process.stdin.resume();
  });
}

function completeJsonObjectEnd(input: string): number {
  let depth = 0;
  let inString = false;
  let escaped = false;
  let started = false;

  for (let index = 0; index < input.length; index += 1) {
    const value = input[index]!;
    if (!started) {
      if (/\s/.test(value)) {
        continue;
      }
      if (value !== "{") {
        return -1;
      }
      started = true;
      depth = 1;
      continue;
    }

    if (inString) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (value === "\\") {
        escaped = true;
        continue;
      }
      if (value === "\"") {
        inString = false;
      }
      continue;
    }

    if (value === "\"") {
      inString = true;
      continue;
    }
    if (value === "{") {
      depth += 1;
      continue;
    }
    if (value === "}") {
      depth -= 1;
      if (depth === 0) {
        return index + 1;
      }
    }
  }

  return -1;
}

async function loadSignerConfig(): Promise<SuiSignCliConfig> {
  const config = await readSavedConfig();
  return {
    ...config,
    network: config.network ?? (await readSuiActiveEnvironment()),
  };
}

async function saveSignerConfig(config: SuiSignCliConfig): Promise<void> {
  const path = configPath();
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
}

async function readSavedConfig(): Promise<SuiSignCliConfig> {
  try {
    const parsed = JSON.parse(await readFile(configPath(), "utf8")) as unknown;
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      return {};
    }
    const value = parsed as Record<string, unknown>;
    return {
      ...(isSuiNetwork(value.network) ? { network: value.network } : {}),
      ...(typeof value.deviceId === "string" && value.deviceId.length > 0
        ? { deviceId: value.deviceId }
        : {}),
      ...(typeof value.purpose === "string" && value.purpose.length > 0
        ? { purpose: value.purpose }
        : {}),
    };
  } catch {
    return {};
  }
}

async function readSuiActiveEnvironment(): Promise<SuiSignTransactionNetwork | undefined> {
  try {
    const clientYaml = await readFile(join(homedir(), ".sui", "sui_config", "client.yaml"), "utf8");
    const match = clientYaml.match(/^active_env:\s*"?([A-Za-z0-9_-]+)"?\s*$/m);
    return match !== null && isSuiNetwork(match[1]) ? match[1] : undefined;
  } catch {
    return undefined;
  }
}

function configPath(): string {
  return join(homedir(), ".signing", "sui-signer.json");
}

function isSuiNetwork(value: unknown): value is SuiSignTransactionNetwork {
  return SUI_SIGN_TRANSACTION_NETWORKS.includes(value as SuiSignTransactionNetwork);
}
