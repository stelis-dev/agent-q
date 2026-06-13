import { isSafeRequestId, isSessionId } from "./safe-text.js";
import { ProtocolError } from "./protocol-error.js";
import {
  HASH_ID_PATTERN,
  INVALID_ID_ERROR_CODE,
  MAX_RAW_PROTOCOL_JSON_BYTES,
  PROTOCOL_VERSION,
  SUI_SIGN_TRANSACTION_METHOD,
  asRecord,
  createRequestId,
  hasSecretPayloadKey,
  isRecord,
  isUint64DecimalString,
  rejectSecretPayload,
  requireOnlyKeys,
  utf8ByteLength,
  validateCanonicalBase64Syntax,
  validateSuiSignTransactionNetwork,
  type SuiSignTransactionNetwork,
} from "./protocol-primitives.js";
import { identifySignRoute } from "./protocol-sign-routes.js";
import { PAYLOAD_DELIVERY_DEADLINE_CHUNK_BYTES } from "./transport-invariants.js";

export const SIGNABLE_PAYLOAD_KIND_TRANSACTION = "transaction";
export const PAYLOAD_REF_PATTERN = /^payload_[A-Za-z0-9_.-]{1,72}$/;
export const PAYLOAD_UPLOAD_ID_PATTERN = /^upload_[A-Za-z0-9_.-]{1,72}$/;

export interface PayloadDeliveryCapability {
  kind: typeof SIGNABLE_PAYLOAD_KIND_TRANSACTION;
  inlineMaxBytes: string;
  chunkMaxBytes: string;
  payloadMaxBytes: string;
}

export interface PayloadDeliveryCapabilityLimits {
  inlineMaxBytes: number;
  chunkMaxBytes: number;
  payloadMaxBytes: number;
}

export interface PayloadUploadBeginRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "payload_upload_begin";
  sessionId: string;
  chain: string;
  method: string;
  payloadKind: typeof SIGNABLE_PAYLOAD_KIND_TRANSACTION;
  sizeBytes: string;
  payloadDigest: string;
}

export interface PayloadUploadChunkRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "payload_upload_chunk";
  sessionId: string;
  uploadId: string;
  offsetBytes: string;
  chunk: string;
}

export interface PayloadUploadFinishRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "payload_upload_finish";
  sessionId: string;
  uploadId: string;
}

export type PayloadUploadAbortTarget =
  | { uploadId: string; payloadRef?: never }
  | { payloadRef: string; uploadId?: never };

export type PayloadUploadAbortRequest = {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "payload_upload_abort";
  sessionId: string;
} & PayloadUploadAbortTarget;

export type PayloadUploadRequest =
  | PayloadUploadBeginRequest
  | PayloadUploadChunkRequest
  | PayloadUploadFinishRequest
  | PayloadUploadAbortRequest;

export interface PayloadUploadBeginResultResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "payload_upload_begin_result";
  uploadId: string;
  receivedBytes: string;
  chunkMaxBytes: string;
}

export interface PayloadUploadChunkResultResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "payload_upload_chunk_result";
  receivedBytes: string;
}

export interface PayloadUploadFinishResultResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "payload_upload_finish_result";
  payloadRef: string;
  chain: string;
  method: string;
  payloadKind: typeof SIGNABLE_PAYLOAD_KIND_TRANSACTION;
  sizeBytes: string;
  payloadDigest: string;
}

export interface PayloadUploadAbortResultResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "payload_upload_abort_result";
  status: "aborted";
}

export type PayloadUploadResponse =
  | PayloadUploadBeginResultResponse
  | PayloadUploadChunkResultResponse
  | PayloadUploadFinishResultResponse
  | PayloadUploadAbortResultResponse;

export interface StagedSignTransactionParams {
  network: SuiSignTransactionNetwork;
  payloadRef: string;
  payloadKind: typeof SIGNABLE_PAYLOAD_KIND_TRANSACTION;
  sizeBytes: string;
  payloadDigest: string;
}

export interface StagedSignTransactionRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: typeof SUI_SIGN_TRANSACTION_METHOD;
  sessionId: string;
  chain: string;
  method: typeof SUI_SIGN_TRANSACTION_METHOD;
  params: StagedSignTransactionParams;
}

export function makePayloadUploadBeginRequest(
  sessionId: string,
  chain: string,
  method: string,
  params: { payloadKind: typeof SIGNABLE_PAYLOAD_KIND_TRANSACTION; sizeBytes: string; payloadDigest: string },
  id = createRequestId(),
): PayloadUploadBeginRequest {
  validateRequestId(id);
  validateSessionId(sessionId);
  const route = identifySignRoute(SUI_SIGN_TRANSACTION_METHOD, chain, method);
  if (params.payloadKind !== SIGNABLE_PAYLOAD_KIND_TRANSACTION) {
    throw new ProtocolError("invalid_params", "Payload kind is unsupported.");
  }
  const request: PayloadUploadBeginRequest = {
    id,
    version: PROTOCOL_VERSION,
    type: "payload_upload_begin",
    sessionId,
    chain: route.chain,
    method: route.method,
    payloadKind: SIGNABLE_PAYLOAD_KIND_TRANSACTION,
    sizeBytes: validatePayloadSizeString(params.sizeBytes, "payload_upload_begin sizeBytes"),
    payloadDigest: validatePayloadDigest(params.payloadDigest, "payload_upload_begin payloadDigest"),
  };
  validateRawRequestSize(request, "payload_upload_begin");
  return request;
}

export function makePayloadUploadChunkRequest(
  sessionId: string,
  uploadId: string,
  offsetBytes: string,
  chunk: string,
  id = createRequestId(),
): PayloadUploadChunkRequest {
  validateRequestId(id);
  validateSessionId(sessionId);
  const request: PayloadUploadChunkRequest = {
    id,
    version: PROTOCOL_VERSION,
    type: "payload_upload_chunk",
    sessionId,
    uploadId: validateUploadId(uploadId),
    offsetBytes: validatePayloadSizeString(offsetBytes, "payload_upload_chunk offsetBytes"),
    chunk: validateCanonicalBase64Syntax(chunk, MAX_RAW_PROTOCOL_JSON_BYTES, "payload_upload_chunk chunk"),
  };
  validateRawRequestSize(request, "payload_upload_chunk");
  return request;
}

export function makePayloadUploadFinishRequest(
  sessionId: string,
  uploadId: string,
  id = createRequestId(),
): PayloadUploadFinishRequest {
  validateRequestId(id);
  validateSessionId(sessionId);
  const request: PayloadUploadFinishRequest = {
    id,
    version: PROTOCOL_VERSION,
    type: "payload_upload_finish",
    sessionId,
    uploadId: validateUploadId(uploadId),
  };
  validateRawRequestSize(request, "payload_upload_finish");
  return request;
}

export function makePayloadUploadAbortRequest(
  sessionId: string,
  target: PayloadUploadAbortTarget,
  id = createRequestId(),
): PayloadUploadAbortRequest {
  validateRequestId(id);
  validateSessionId(sessionId);
  const normalizedTarget = normalizeAbortTarget(target);
  const request: PayloadUploadAbortRequest = {
    id,
    version: PROTOCOL_VERSION,
    type: "payload_upload_abort",
    sessionId,
    ...normalizedTarget,
  };
  validateRawRequestSize(request, "payload_upload_abort");
  return request;
}

export function makeStagedSignTransactionRequest(
  sessionId: string,
  chain: string,
  method: string,
  params: StagedSignTransactionParams,
  id = createRequestId(),
): StagedSignTransactionRequest {
  validateRequestId(id);
  validateSessionId(sessionId);
  const route = identifySignRoute(SUI_SIGN_TRANSACTION_METHOD, chain, method);
  const normalizedParams = normalizeStagedSignTransactionParams(params);
  const request: StagedSignTransactionRequest = {
    id,
    version: PROTOCOL_VERSION,
    type: SUI_SIGN_TRANSACTION_METHOD,
    sessionId,
    chain: route.chain,
    method: route.method,
    params: normalizedParams,
  };
  validateRawRequestSize(request, "sign_transaction");
  return request;
}

export function normalizePayloadUploadRequest(request: unknown): PayloadUploadRequest {
  if (!isRecord(request)) {
    throw new ProtocolError("invalid_method", "Payload upload request must be an object.");
  }
  if (request.version !== PROTOCOL_VERSION) {
    throw new ProtocolError("unsupported_version", "Unsupported payload upload request version.");
  }
  switch (request.type) {
    case "payload_upload_begin":
      requireOnlyKeys(
        request,
        ["id", "version", "type", "sessionId", "chain", "method", "payloadKind", "sizeBytes", "payloadDigest"],
        "payload_upload_begin request",
      );
      return makePayloadUploadBeginRequest(
        request.sessionId as string,
        request.chain as string,
        request.method as string,
        {
          payloadKind: request.payloadKind as typeof SIGNABLE_PAYLOAD_KIND_TRANSACTION,
          sizeBytes: request.sizeBytes as string,
          payloadDigest: request.payloadDigest as string,
        },
        request.id as string,
      );
    case "payload_upload_chunk":
      requireOnlyKeys(
        request,
        ["id", "version", "type", "sessionId", "uploadId", "offsetBytes", "chunk"],
        "payload_upload_chunk request",
      );
      return makePayloadUploadChunkRequest(
        request.sessionId as string,
        request.uploadId as string,
        request.offsetBytes as string,
        request.chunk as string,
        request.id as string,
      );
    case "payload_upload_finish":
      requireOnlyKeys(
        request,
        ["id", "version", "type", "sessionId", "uploadId"],
        "payload_upload_finish request",
      );
      return makePayloadUploadFinishRequest(
        request.sessionId as string,
        request.uploadId as string,
        request.id as string,
      );
    case "payload_upload_abort":
      requireOnlyKeys(
        request,
        ["id", "version", "type", "sessionId", "uploadId", "payloadRef"],
        "payload_upload_abort request",
      );
      return makePayloadUploadAbortRequest(
        request.sessionId as string,
        normalizeAbortTarget(request),
        request.id as string,
      );
    default:
      throw new ProtocolError("invalid_method", "Payload upload request type is unsupported.");
  }
}

export function normalizeStagedSignTransactionParams(params: unknown): StagedSignTransactionParams {
  const value = asRecord(params, "sign_transaction params");
  rejectSecretPayload(value, "sign_transaction params");
  requireOnlyKeys(value, ["network", "payloadRef", "payloadKind", "sizeBytes", "payloadDigest"], "sign_transaction params");
  if (value.payloadKind !== SIGNABLE_PAYLOAD_KIND_TRANSACTION) {
    throw new ProtocolError("invalid_params", "sign_transaction payloadKind is unsupported.");
  }
  return {
    network: validateSuiSignTransactionNetwork(value.network),
    payloadRef: validatePayloadRef(value.payloadRef),
    payloadKind: SIGNABLE_PAYLOAD_KIND_TRANSACTION,
    sizeBytes: validatePayloadSizeString(value.sizeBytes, "sign_transaction sizeBytes"),
    payloadDigest: validatePayloadDigest(value.payloadDigest, "sign_transaction payloadDigest"),
  };
}

export function sanitizePayloadDeliveryCapability(value: unknown): PayloadDeliveryCapability {
  const entry = asRecord(value, "Payload delivery capability");
  if (hasSecretPayloadKey(entry)) {
    throw new ProtocolError("protocol_error", "Payload delivery capability must not include secret material.");
  }
  requireOnlyKeys(entry, ["kind", "inlineMaxBytes", "chunkMaxBytes", "payloadMaxBytes"], "Payload delivery capability");
  if (entry.kind !== SIGNABLE_PAYLOAD_KIND_TRANSACTION) {
    throw new ProtocolError("protocol_error", "Payload delivery capability kind is malformed.");
  }
  return {
    kind: SIGNABLE_PAYLOAD_KIND_TRANSACTION,
    inlineMaxBytes: validatePayloadSizeString(entry.inlineMaxBytes, "Payload delivery capability inlineMaxBytes", "protocol_error"),
    chunkMaxBytes: validatePayloadChunkMaxBytesString(entry.chunkMaxBytes, "Payload delivery capability chunkMaxBytes", "protocol_error"),
    payloadMaxBytes: validatePayloadSizeString(entry.payloadMaxBytes, "Payload delivery capability payloadMaxBytes", "protocol_error"),
  };
}

export function payloadDeliveryCapabilityLimits(value: unknown): PayloadDeliveryCapabilityLimits {
  const capability = sanitizePayloadDeliveryCapability(value);
  return {
    inlineMaxBytes: parsePayloadCapabilityInteger(capability.inlineMaxBytes, "inlineMaxBytes"),
    chunkMaxBytes: parsePayloadCapabilityInteger(capability.chunkMaxBytes, "chunkMaxBytes"),
    payloadMaxBytes: parsePayloadCapabilityInteger(capability.payloadMaxBytes, "payloadMaxBytes"),
  };
}

export function sanitizePayloadUploadResponse(value: Record<string, unknown>): PayloadUploadResponse {
  switch (value.type) {
    case "payload_upload_begin_result":
      requireOnlyKeys(value, ["id", "version", "type", "uploadId", "receivedBytes", "chunkMaxBytes"], "Payload upload begin response");
      if (typeof value.id !== "string" || value.version !== PROTOCOL_VERSION) {
        throw new ProtocolError("protocol_error", "Payload upload begin response is malformed.");
      }
      return {
        id: value.id,
        version: PROTOCOL_VERSION,
        type: "payload_upload_begin_result",
        uploadId: validateUploadId(value.uploadId, "protocol_error"),
        receivedBytes: validatePayloadSizeString(value.receivedBytes, "Payload upload begin response receivedBytes", "protocol_error"),
        chunkMaxBytes: validatePayloadChunkMaxBytesString(value.chunkMaxBytes, "Payload upload begin response chunkMaxBytes", "protocol_error"),
      };
    case "payload_upload_chunk_result":
      requireOnlyKeys(value, ["id", "version", "type", "receivedBytes"], "Payload upload chunk response");
      if (typeof value.id !== "string" || value.version !== PROTOCOL_VERSION) {
        throw new ProtocolError("protocol_error", "Payload upload chunk response is malformed.");
      }
      return {
        id: value.id,
        version: PROTOCOL_VERSION,
        type: "payload_upload_chunk_result",
        receivedBytes: validatePayloadSizeString(value.receivedBytes, "Payload upload chunk response receivedBytes", "protocol_error"),
      };
    case "payload_upload_finish_result":
      requireOnlyKeys(value, ["id", "version", "type", "payloadRef", "chain", "method", "payloadKind", "sizeBytes", "payloadDigest"], "Payload upload finish response");
      if (typeof value.id !== "string" || value.version !== PROTOCOL_VERSION) {
        throw new ProtocolError("protocol_error", "Payload upload finish response is malformed.");
      }
      assertPayloadUploadResponseRoute(value.chain, value.method);
      if (value.payloadKind !== SIGNABLE_PAYLOAD_KIND_TRANSACTION) {
        throw new ProtocolError("protocol_error", "Payload upload finish response payloadKind is malformed.");
      }
      return {
        id: value.id,
        version: PROTOCOL_VERSION,
        type: "payload_upload_finish_result",
        payloadRef: validatePayloadRef(value.payloadRef, "protocol_error"),
        chain: value.chain as string,
        method: value.method as typeof SUI_SIGN_TRANSACTION_METHOD,
        payloadKind: SIGNABLE_PAYLOAD_KIND_TRANSACTION,
        sizeBytes: validatePayloadSizeString(value.sizeBytes, "Payload upload finish response sizeBytes", "protocol_error"),
        payloadDigest: validatePayloadDigest(value.payloadDigest, "Payload upload finish response payloadDigest", "protocol_error"),
      };
    case "payload_upload_abort_result":
      requireOnlyKeys(value, ["id", "version", "type", "status"], "Payload upload abort response");
      if (typeof value.id !== "string" || value.version !== PROTOCOL_VERSION || value.status !== "aborted") {
        throw new ProtocolError("protocol_error", "Payload upload abort response is malformed.");
      }
      return {
        id: value.id,
        version: PROTOCOL_VERSION,
        type: "payload_upload_abort_result",
        status: "aborted",
      };
    default:
      throw new ProtocolError("protocol_error", "Payload upload response type is unsupported.");
  }
}

export function isPayloadUploadResponseType(value: unknown): boolean {
  return (
    value === "payload_upload_begin_result" ||
    value === "payload_upload_chunk_result" ||
    value === "payload_upload_finish_result" ||
    value === "payload_upload_abort_result"
  );
}

function normalizeAbortTarget(value: unknown): PayloadUploadAbortTarget {
  const target = asRecord(value, "payload_upload_abort target");
  const hasUploadId = target.uploadId !== undefined;
  const hasPayloadRef = target.payloadRef !== undefined;
  if (hasUploadId === hasPayloadRef) {
    throw new ProtocolError("invalid_params", "payload_upload_abort must target exactly one uploadId or payloadRef.");
  }
  return hasUploadId
    ? { uploadId: validateUploadId(target.uploadId) }
    : { payloadRef: validatePayloadRef(target.payloadRef) };
}

function assertPayloadUploadResponseRoute(chain: unknown, method: unknown): void {
  try {
    identifySignRoute(SUI_SIGN_TRANSACTION_METHOD, chain, method);
  } catch {
    throw new ProtocolError("protocol_error", "Payload upload finish response route is malformed.");
  }
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

function validateUploadId(value: unknown, errorCode = "invalid_params"): string {
  if (typeof value !== "string" || !PAYLOAD_UPLOAD_ID_PATTERN.test(value)) {
    throw new ProtocolError(errorCode, "Payload upload id is invalid.");
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
    throw new ProtocolError(errorCode, `${label} is below the usable staged payload chunk size.`);
  }
  return normalized;
}

function parsePayloadCapabilityInteger(value: string, label: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new ProtocolError("protocol_error", `Payload delivery capability ${label} is invalid.`);
  }
  return parsed;
}

function validateRawRequestSize(request: PayloadUploadRequest | StagedSignTransactionRequest, method: string): void {
  if (utf8ByteLength(JSON.stringify(request)) > MAX_RAW_PROTOCOL_JSON_BYTES) {
    throw new ProtocolError("invalid_params", `${method} request is too large for the runtime.`);
  }
}
