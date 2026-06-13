import { isSafeRequestId, isSessionId } from "./safe-text.js";
import { ProtocolError } from "./protocol-error.js";
import {
  INVALID_ID_ERROR_CODE,
  PROTOCOL_VERSION,
  isRecord,
  requireOnlyKeys,
} from "./protocol-primitives.js";

export interface GetResultRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "get_result";
  sessionId: string;
}

export interface AckResultRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "ack_result";
  sessionId: string;
}

export type RecoveryProtocolRequest = GetResultRequest | AckResultRequest;

export interface AckResultResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "ack_result";
  status: "acked";
}

// `id` is required and is not freshly generated: get_result/ack_result target a
// specific prior signing request's retained result by its original request id.
export function makeGetResultRequest(sessionId: string, id: string): GetResultRequest {
  validateRequestId(id);
  validateSessionId(sessionId);
  return { id, version: PROTOCOL_VERSION, type: "get_result", sessionId };
}

export function makeAckResultRequest(sessionId: string, id: string): AckResultRequest {
  validateRequestId(id);
  validateSessionId(sessionId);
  return { id, version: PROTOCOL_VERSION, type: "ack_result", sessionId };
}

export function normalizeRecoveryRequest(request: unknown): RecoveryProtocolRequest {
  if (!isRecord(request)) {
    throw new ProtocolError("invalid_method", "Recovery protocol request must be an object.");
  }
  if (request.version !== PROTOCOL_VERSION) {
    throw new ProtocolError("unsupported_version", "Unsupported recovery protocol request version.");
  }
  switch (request.type) {
    case "get_result":
      requireOnlyKeys(request, ["id", "version", "type", "sessionId"], "get_result request");
      return makeGetResultRequest(request.sessionId as string, request.id as string);
    case "ack_result":
      requireOnlyKeys(request, ["id", "version", "type", "sessionId"], "ack_result request");
      return makeAckResultRequest(request.sessionId as string, request.id as string);
    default:
      throw new ProtocolError("invalid_method", "Recovery protocol request type is unsupported.");
  }
}

export function sanitizeAckResultResponse(value: Record<string, unknown>): AckResultResponse {
  requireOnlyKeys(value, ["id", "version", "type", "status"], "Ack result response");
  if (
    typeof value.id !== "string" ||
    value.version !== PROTOCOL_VERSION ||
    value.type !== "ack_result" ||
    value.status !== "acked"
  ) {
    throw new ProtocolError("protocol_error", "Ack result response is malformed.");
  }
  return { id: value.id, version: PROTOCOL_VERSION, type: "ack_result", status: "acked" };
}

export function assertAckResultResponse(response: unknown): AckResultResponse {
  if (!isRecord(response)) {
    throw new ProtocolError("protocol_error", "Protocol response is not an object.");
  }
  if (response.type === "error") {
    const error = response.error;
    if (!isRecord(error) || typeof error.code !== "string" || typeof error.message !== "string") {
      throw new ProtocolError("protocol_error", "Protocol error response is malformed.");
    }
    throw new ProtocolError(error.code, error.message);
  }
  return sanitizeAckResultResponse(response);
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
