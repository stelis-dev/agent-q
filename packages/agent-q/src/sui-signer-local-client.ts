import type {
  ConnectDeviceResult,
  DisconnectDeviceResult,
  GetAccountsResult,
  SignTransactionResult,
} from "@stelis/agent-q-core";
import { DeviceRequestError } from "@stelis/agent-q-core/adapter-internal";

import type { SuiSignCliCore } from "./sui-sign-cli.js";

export const DEFAULT_LOCAL_SERVER_URL = "http://127.0.0.1:8787";

const MAX_LOCAL_SERVER_RESPONSE_BYTES = 65536;

interface LocalApiSuccess {
  ok: true;
  result: unknown;
}

interface LocalApiFailure {
  ok: false;
  error: {
    code: string;
    message: string;
    retryable: boolean;
  };
}

type LocalApiResponse = LocalApiSuccess | LocalApiFailure;

export function createLocalServerSuiSignCliCore(options: {
  baseUrl?: string;
} = {}): SuiSignCliCore {
  return new LocalServerSuiSignCliCore(options.baseUrl ?? DEFAULT_LOCAL_SERVER_URL);
}

class LocalServerSuiSignCliCore implements SuiSignCliCore {
  readonly #baseUrl: string;

  constructor(baseUrl: string) {
    this.#baseUrl = baseUrl.replace(/\/+$/, "");
  }

  connectDevice(input: { deviceId?: string; purpose?: string }): Promise<ConnectDeviceResult> {
    return this.#post("/api/connect", input);
  }

  disconnectDevice(input: { deviceId?: string; purpose?: string }): Promise<DisconnectDeviceResult> {
    return this.#post("/api/disconnect", input);
  }

  getAccounts(input: { deviceId?: string; purpose?: string }): Promise<GetAccountsResult> {
    return this.#post("/api/get_accounts", input);
  }

  signTransaction(input: {
    deviceId?: string;
    purpose?: string;
    chain: string;
    method: string;
    network: unknown;
    txBytes: string;
  }): Promise<SignTransactionResult> {
    return this.#post("/api/sign_transaction", input);
  }

  async #post<T>(path: string, body: unknown): Promise<T> {
    let response: Response;
    try {
      response = await fetch(`${this.#baseUrl}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
    } catch {
      throw new DeviceRequestError(
        "local_server_unavailable",
        "Start the local Agent-Q server with `agent-q` before using this command.",
        true,
      );
    }

    const payload = parseLocalApiResponse(await readBoundedResponseText(response));
    if (!payload.ok) {
      throw new DeviceRequestError(payload.error.code, payload.error.message, payload.error.retryable);
    }
    return payload.result as T;
  }
}

async function readBoundedResponseText(response: Response): Promise<string> {
  const reader = response.body?.getReader();
  if (reader === undefined) {
    throw new DeviceRequestError("invalid_response", "Agent-Q local server response was empty.", true);
  }

  const decoder = new TextDecoder();
  let raw = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      raw += decoder.decode();
      return raw;
    }
    raw += decoder.decode(value, { stream: true });
    if (Buffer.byteLength(raw, "utf8") > MAX_LOCAL_SERVER_RESPONSE_BYTES) {
      throw new DeviceRequestError("invalid_response", "Agent-Q local server response was too large.", true);
    }
  }
}

function parseLocalApiResponse(raw: string): LocalApiResponse {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new DeviceRequestError("invalid_response", "Agent-Q local server response was not JSON.", true);
  }
  if (!isRecord(parsed) || typeof parsed.ok !== "boolean") {
    throw new DeviceRequestError("invalid_response", "Agent-Q local server response was malformed.", true);
  }
  if (parsed.ok) {
    return { ok: true, result: parsed.result };
  }
  if (!isRecord(parsed.error)) {
    throw new DeviceRequestError("invalid_response", "Agent-Q local server error was malformed.", true);
  }
  const { code, message, retryable } = parsed.error;
  if (typeof code !== "string" || typeof message !== "string" || typeof retryable !== "boolean") {
    throw new DeviceRequestError("invalid_response", "Agent-Q local server error was malformed.", true);
  }
  return { ok: false, error: { code, message, retryable } };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
