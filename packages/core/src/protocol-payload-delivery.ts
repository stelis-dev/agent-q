import { ProtocolError } from "./protocol-error.js";
import {
  HASH_ID_PATTERN,
  INVALID_ID_ERROR_CODE,
  MAX_RAW_PROTOCOL_JSON_BYTES,
  PROTOCOL_VERSION,
  asRecord,
  createRequestId,
  hasOnlyObjectKeys,
  isUint64DecimalString,
  requireOnlyKeys,
  utf8ByteLength,
  validateCanonicalBase64Syntax,
} from "./protocol-primitives.js";
import { PAYLOAD_DELIVERY_DEADLINE_CHUNK_BYTES } from "./transport-invariants.js";
import { isSafeRequestId, isSessionId } from "./safe-text.js";

export const PAYLOAD_REF_PATTERN = /^payload_[A-Za-z0-9_.-]{1,72}$/;
export const PAYLOAD_TRANSFER_ID_PATTERN = /^transfer_[A-Za-z0-9_.-]{1,72}$/;

export type PayloadTransferAction = "begin" | "chunk" | "finish" | "abort";

export interface PayloadTransferBeginRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "payload_transfer";
  action: "begin";
  sessionId: string;
  totalBytes: string;
  payloadDigest: string;
}

export interface PayloadTransferChunkRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "payload_transfer";
  action: "chunk";
  sessionId: string;
  transferId: string;
  offsetBytes: string;
  chunk: string;
}

export interface PayloadTransferFinishRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "payload_transfer";
  action: "finish";
  sessionId: string;
  transferId: string;
}

export interface PayloadTransferAbortRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "payload_transfer";
  action: "abort";
  sessionId: string;
  transferId: string;
}

export type PayloadTransferRequest =
  | PayloadTransferBeginRequest
  | PayloadTransferChunkRequest
  | PayloadTransferFinishRequest
  | PayloadTransferAbortRequest;

export interface PayloadTransferBeginResult {
  transferId: string;
  receivedBytes: string;
  chunkMaxBytes: string;
}

export interface PayloadTransferChunkResult {
  receivedBytes: string;
}

export interface PayloadTransferFinishResult {
  payloadRef: string;
}

export type PayloadTransferAbortResult = Record<string, never>;

export interface PayloadTransferSuccessResponse<TResult = unknown> {
  id?: string;
  version: typeof PROTOCOL_VERSION;
  success: true;
  result: TResult;
}

export interface PayloadTransferFailureResponse {
  id?: string;
  version: typeof PROTOCOL_VERSION;
  success: false;
  error: {
    code: string;
    message: string;
    retryable: boolean;
  };
}

export type PayloadTransferResponse<TResult = unknown> =
  | PayloadTransferSuccessResponse<TResult>
  | PayloadTransferFailureResponse;

export function makePayloadTransferBeginRequest(
  sessionId: string,
  params: { totalBytes: string; payloadDigest: string },
  id = createRequestId(),
): PayloadTransferBeginRequest {
  validateRequestId(id);
  validateSessionId(sessionId);
  const request: PayloadTransferBeginRequest = {
    id,
    version: PROTOCOL_VERSION,
    type: "payload_transfer",
    action: "begin",
    sessionId,
    totalBytes: validatePayloadSizeString(params.totalBytes, "payload_transfer begin totalBytes"),
    payloadDigest: validatePayloadDigest(params.payloadDigest, "payload_transfer begin payloadDigest"),
  };
  validateRawRequestSize(request, "payload_transfer begin");
  return request;
}

export function makePayloadTransferChunkRequest(
  sessionId: string,
  transferId: string,
  offsetBytes: string,
  chunk: string,
  id = createRequestId(),
): PayloadTransferChunkRequest {
  validateRequestId(id);
  validateSessionId(sessionId);
  const request: PayloadTransferChunkRequest = {
    id,
    version: PROTOCOL_VERSION,
    type: "payload_transfer",
    action: "chunk",
    sessionId,
    transferId: validateTransferId(transferId),
    offsetBytes: validatePayloadSizeString(offsetBytes, "payload_transfer chunk offsetBytes"),
    chunk: validateCanonicalBase64Syntax(chunk, MAX_RAW_PROTOCOL_JSON_BYTES, "payload_transfer chunk"),
  };
  validateRawRequestSize(request, "payload_transfer chunk");
  return request;
}

export function makePayloadTransferFinishRequest(
  sessionId: string,
  transferId: string,
  id = createRequestId(),
): PayloadTransferFinishRequest {
  validateRequestId(id);
  validateSessionId(sessionId);
  const request: PayloadTransferFinishRequest = {
    id,
    version: PROTOCOL_VERSION,
    type: "payload_transfer",
    action: "finish",
    sessionId,
    transferId: validateTransferId(transferId),
  };
  validateRawRequestSize(request, "payload_transfer finish");
  return request;
}

export function makePayloadTransferAbortRequest(
  sessionId: string,
  transferId: string,
  id = createRequestId(),
): PayloadTransferAbortRequest {
  validateRequestId(id);
  validateSessionId(sessionId);
  const request: PayloadTransferAbortRequest = {
    id,
    version: PROTOCOL_VERSION,
    type: "payload_transfer",
    action: "abort",
    sessionId,
    transferId: validateTransferId(transferId),
  };
  validateRawRequestSize(request, "payload_transfer abort");
  return request;
}

export function normalizePayloadTransferRequest(request: unknown): PayloadTransferRequest {
  const value = asRecord(request, "payload_transfer request");
  if (value.version !== PROTOCOL_VERSION || value.type !== "payload_transfer") {
    throw new ProtocolError("unsupported_version", "Unsupported payload_transfer request version.");
  }
  switch (value.action) {
    case "begin":
      requireOnlyKeys(
        value,
        ["id", "version", "type", "action", "sessionId", "totalBytes", "payloadDigest"],
        "payload_transfer begin request",
        "invalid_request",
      );
      return makePayloadTransferBeginRequest(
        value.sessionId as string,
        {
          totalBytes: value.totalBytes as string,
          payloadDigest: value.payloadDigest as string,
        },
        value.id as string,
      );
    case "chunk":
      requireOnlyKeys(
        value,
        ["id", "version", "type", "action", "sessionId", "transferId", "offsetBytes", "chunk"],
        "payload_transfer chunk request",
        "invalid_request",
      );
      return makePayloadTransferChunkRequest(
        value.sessionId as string,
        value.transferId as string,
        value.offsetBytes as string,
        value.chunk as string,
        value.id as string,
      );
    case "finish":
      requireOnlyKeys(
        value,
        ["id", "version", "type", "action", "sessionId", "transferId"],
        "payload_transfer finish request",
        "invalid_request",
      );
      return makePayloadTransferFinishRequest(
        value.sessionId as string,
        value.transferId as string,
        value.id as string,
      );
    case "abort":
      requireOnlyKeys(
        value,
        ["id", "version", "type", "action", "sessionId", "transferId"],
        "payload_transfer abort request",
        "invalid_request",
      );
      return makePayloadTransferAbortRequest(
        value.sessionId as string,
        value.transferId as string,
        value.id as string,
      );
    default:
      throw new ProtocolError("unsupported_method", "payload_transfer action is unsupported.");
  }
}

export function sanitizePayloadTransferBeginResult(value: unknown): PayloadTransferBeginResult {
  const result = asRecord(value, "payload_transfer begin result");
  requireOnlyKeys(result, ["transferId", "receivedBytes", "chunkMaxBytes"], "payload_transfer begin result", "invalid_response");
  return {
    transferId: validateTransferId(result.transferId, "invalid_response"),
    receivedBytes: validatePayloadSizeString(result.receivedBytes, "payload_transfer begin receivedBytes", "invalid_response"),
    chunkMaxBytes: validatePayloadChunkMaxBytesString(result.chunkMaxBytes, "payload_transfer begin chunkMaxBytes", "invalid_response"),
  };
}

export function sanitizePayloadTransferChunkResult(value: unknown): PayloadTransferChunkResult {
  const result = asRecord(value, "payload_transfer chunk result");
  requireOnlyKeys(result, ["receivedBytes"], "payload_transfer chunk result", "invalid_response");
  return {
    receivedBytes: validatePayloadSizeString(result.receivedBytes, "payload_transfer chunk receivedBytes", "invalid_response"),
  };
}

export function sanitizePayloadTransferFinishResult(value: unknown): PayloadTransferFinishResult {
  const result = asRecord(value, "payload_transfer finish result");
  requireOnlyKeys(result, ["payloadRef"], "payload_transfer finish result", "invalid_response");
  return {
    payloadRef: validatePayloadRef(result.payloadRef, "invalid_response"),
  };
}

export function sanitizePayloadTransferAbortResult(value: unknown): PayloadTransferAbortResult {
  const result = asRecord(value, "payload_transfer abort result");
  requireOnlyKeys(result, [], "payload_transfer abort result", "invalid_response");
  return {};
}

export function parsePayloadTransferResponse<TResult>(
  value: unknown,
  expectedId: string,
  resultParser: (result: unknown) => TResult,
): PayloadTransferResponse<TResult> {
  const response = asRecord(value, "payload_transfer response");
  if (!hasOnlyObjectKeys(response, ["id", "version", "success", "result", "error"])) {
    throw new ProtocolError("invalid_response", "payload_transfer response contains unsupported fields.");
  }
  if (Object.prototype.hasOwnProperty.call(response, "id") && response.id !== expectedId) {
    throw new ProtocolError("invalid_response", "payload_transfer response id does not match request.");
  }
  if (response.version !== PROTOCOL_VERSION) {
    throw new ProtocolError("unsupported_version", "Protocol version is not supported.");
  }
  if (response.success === true) {
    if (!Object.prototype.hasOwnProperty.call(response, "result")) {
      throw new ProtocolError("invalid_response", "payload_transfer success response result is required.");
    }
    return {
      ...(Object.prototype.hasOwnProperty.call(response, "id") ? { id: response.id as string } : {}),
      version: PROTOCOL_VERSION,
      success: true,
      result: resultParser(response.result),
    };
  }
  if (response.success === false) {
    const error = asRecord(response.error, "payload_transfer error");
    if (
      !hasOnlyObjectKeys(error, ["code", "message", "retryable"]) ||
      typeof error.code !== "string" ||
      typeof error.message !== "string" ||
      typeof error.retryable !== "boolean"
    ) {
      throw new ProtocolError("invalid_response", "payload_transfer error response is malformed.");
    }
    return {
      ...(Object.prototype.hasOwnProperty.call(response, "id") ? { id: response.id as string } : {}),
      version: PROTOCOL_VERSION,
      success: false,
      error: {
        code: error.code,
        message: error.message,
        retryable: error.retryable,
      },
    };
  }
  throw new ProtocolError("invalid_response", "payload_transfer response success flag is invalid.");
}

export function serializePayloadTransferRequest(request: PayloadTransferRequest): string {
  return `${JSON.stringify(normalizePayloadTransferRequest(request))}\n`;
}

function validateRequestId(id: string): void {
  if (!isSafeRequestId(id)) {
    throw new ProtocolError(INVALID_ID_ERROR_CODE, "Invalid request id.");
  }
}

function validateSessionId(sessionId: string): void {
  if (!isSessionId(sessionId)) {
    throw new ProtocolError("invalid_session", "Invalid sessionId.");
  }
}

function validateTransferId(value: unknown, errorCode = "invalid_params"): string {
  if (typeof value !== "string" || !PAYLOAD_TRANSFER_ID_PATTERN.test(value)) {
    throw new ProtocolError(errorCode, "Payload transfer id is invalid.");
  }
  return value;
}

function validatePayloadRef(value: unknown, errorCode = "invalid_params"): string {
  if (typeof value !== "string" || !PAYLOAD_REF_PATTERN.test(value)) {
    throw new ProtocolError(errorCode, "Payload reference is invalid.");
  }
  return value;
}

function validatePayloadDigest(value: unknown, label: string, errorCode = "invalid_params"): string {
  if (typeof value !== "string" || !HASH_ID_PATTERN.test(value)) {
    throw new ProtocolError(errorCode, `${label} is invalid.`);
  }
  return value;
}

function validatePayloadSizeString(value: unknown, label: string, errorCode = "invalid_params"): string {
  if (typeof value !== "string" || !isUint64DecimalString(value)) {
    throw new ProtocolError(errorCode, `${label} must be a uint decimal string.`);
  }
  return value;
}

function validatePayloadChunkMaxBytesString(value: unknown, label: string, errorCode = "invalid_params"): string {
  const normalized = validatePayloadSizeString(value, label, errorCode);
  const parsed = Number(normalized);
  if (!Number.isSafeInteger(parsed) || parsed < PAYLOAD_DELIVERY_DEADLINE_CHUNK_BYTES) {
    throw new ProtocolError(errorCode, `${label} is below the usable payload chunk size.`);
  }
  return normalized;
}

function validateRawRequestSize(request: PayloadTransferRequest, method: string): void {
  if (utf8ByteLength(JSON.stringify(request)) > MAX_RAW_PROTOCOL_JSON_BYTES) {
    throw new ProtocolError("invalid_params", `${method} request is too large for the runtime.`);
  }
}
