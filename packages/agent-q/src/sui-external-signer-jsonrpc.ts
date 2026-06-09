import {
  validateSignTransactionParamsInput,
} from "@stelis/agent-q-core/protocol";

export interface SuiExternalSignerJsonRpcRequest {
  jsonrpc: "2.0";
  method: string;
  params: unknown;
  id: number;
}

export interface SuiExternalSignerSignParams {
  keyId: string;
  txBytes: string;
}

export interface SuiExternalSignerPublicKeyParams {
  keyId: string;
}

export interface SuiExternalSignerPublicKeyResponse {
  key_id: string;
  public_key: { Ed25519: string };
  sui_address: string;
}

export function parseSuiExternalSignerJsonRpcRequest(
  input: string,
): SuiExternalSignerJsonRpcRequest {
  const firstLine = input.split(/\r?\n/, 1)[0]?.trim();
  if (firstLine === undefined || firstLine.length === 0) {
    throw new Error("JSON-RPC request is empty.");
  }
  const parsed = JSON.parse(firstLine) as unknown;
  if (!isRecord(parsed)) {
    throw new Error("JSON-RPC request must be an object.");
  }
  if (
    parsed.jsonrpc !== "2.0" ||
    typeof parsed.method !== "string" ||
    typeof parsed.id !== "number" ||
    !Number.isSafeInteger(parsed.id)
  ) {
    throw new Error("Invalid JSON-RPC request.");
  }
  return {
    jsonrpc: "2.0",
    method: parsed.method,
    params: parsed.params,
    id: parsed.id,
  };
}

export function parseSuiExternalSignerKeysParams(params: unknown): void {
  if (
    params === undefined ||
    params === null ||
    (Array.isArray(params) && params.length === 1 && params[0] === null)
  ) {
    return;
  }
  throw new Error("Invalid keys params.");
}

export function parseSuiExternalSignerPublicKeyParams(
  params: unknown,
): SuiExternalSignerPublicKeyParams {
  if (Array.isArray(params) && params.length === 1 && typeof params[0] === "string") {
    if (params[0].length === 0) {
      throw new Error("Invalid public_key params.");
    }
    return { keyId: params[0] };
  }
  if (!isRecord(params) || typeof params.key_id !== "string" || params.key_id.length === 0) {
    throw new Error("Invalid public_key params.");
  }
  return { keyId: params.key_id };
}

export function parseSuiExternalSignerSignParams(
  params: unknown,
): SuiExternalSignerSignParams {
  if (!isRecord(params) || typeof params.key_id !== "string" || typeof params.msg !== "string") {
    throw new Error("Invalid sign params.");
  }
  validateSignTransactionParamsInput({ network: "testnet", txBytes: params.msg }, "sign");
  return { keyId: params.key_id, txBytes: params.msg };
}

export function formatSuiExternalSignerJsonRpcResult(id: number, result: unknown): string {
  return `${JSON.stringify({ jsonrpc: "2.0", result, id })}\n`;
}

export function formatSuiExternalSignerJsonRpcError(
  id: number | null,
  code: number,
  message: string,
): string {
  return `${JSON.stringify({ jsonrpc: "2.0", error: { code, message }, id })}\n`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
