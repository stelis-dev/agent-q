import {
  parseDeviceResponse,
  type DeviceErrorCode,
  type DeviceResponse,
} from "./device-contract.js";
import {
  requestDevice,
  type DeviceRequestExecutor,
  type DeviceRequestInput,
} from "./device-request-transport.js";
import { ProtocolError } from "./protocol-error.js";
import { isRecord } from "./protocol-primitives.js";

export type RetainedSigningRequest = DeviceRequestInput & {
  readonly id: string;
  readonly sessionId: string;
  readonly method: "sign_transaction" | "sign_personal_message";
};

export type RetainedSigningAckStatus = "acked" | "failed" | "invalid_session";

export type RetainedSigningRecoveryOutcome<TResponse> =
  | { readonly status: "result"; readonly response: TResponse; readonly sessionInvalidatedByAck: boolean }
  | { readonly status: "session_invalidated" };

export interface RetainedSigningRecoveryOptions<TResponse, TRecoveryContext> {
  readonly request: RetainedSigningRequest;
  readonly deadlineMs: number;
  readonly execute: DeviceRequestExecutor;
  readonly assertSigningOutcome: (response: DeviceResponse) => TResponse;
  readonly digestPayload: (payloadBytes: Uint8Array) => string | Promise<string>;
  readonly encodeChunkBase64: (chunkBytes: Uint8Array) => string;
  readonly makeError: (code: DeviceErrorCode, message: string, retryable?: boolean) => Error;
  readonly errorCode: (error: unknown) => string | null;
  readonly requestMayHaveReachedFirmware: (error: unknown) => boolean;
  readonly markInvalidSession: <T>(value: T) => T;
  readonly recoveryDeadlineMs: (method: "get_result" | "ack_result") => number;
  readonly makeGetResultRequestId: () => string;
  readonly makeAckResultRequestId: () => string;
  readonly prepareRecovery: (originalError: unknown) => TRecoveryContext | null | Promise<TRecoveryContext | null>;
  readonly recoveryExecute: (context: TRecoveryContext) => DeviceRequestExecutor;
  readonly onDirectSuccess?: (response: TResponse) => void;
  readonly onRecoverySettled?: (context: TRecoveryContext, ack: RetainedSigningAckStatus) => void;
}

const RECOVERABLE_SIGNING_DELIVERY_CODES = new Set([
  "timeout",
  "transport_closed",
  "invalid_response",
  "handshake_failed",
]);

export async function requestSigningWithRetainedRecovery<TResponse, TRecoveryContext>(
  options: RetainedSigningRecoveryOptions<TResponse, TRecoveryContext>,
): Promise<RetainedSigningRecoveryOutcome<TResponse>> {
  try {
    const response = await requestDevice({
      request: options.request,
      deadlineMs: options.deadlineMs,
      execute: options.execute,
      assertResponse: options.assertSigningOutcome,
      digestPayload: options.digestPayload,
      encodeChunkBase64: options.encodeChunkBase64,
      makeError: options.makeError,
      errorCode: options.errorCode,
      onAbortInvalidSession: options.markInvalidSession,
    });
    options.onDirectSuccess?.(response);
    return { status: "result", response, sessionInvalidatedByAck: false };
  } catch (originalError) {
    if (!shouldAttemptRetainedRecovery(originalError, options)) {
      throw originalError;
    }
    let context: TRecoveryContext | null;
    try {
      context = await options.prepareRecovery(originalError);
    } catch {
      throw originalError;
    }
    if (context === null) {
      throw originalError;
    }
    return recoverRetainedSigningOutcome(options, context, originalError);
  }
}

export function assertAckResultDeviceResponse(response: DeviceResponse): void {
  const parsed = parseDeviceResponse(response, { expectedMethod: "ack_result" });
  if (parsed.success === false) {
    throw new ProtocolError(parsed.error.code, parsed.error.message);
  }
  if (parsed.id === undefined) {
    throw new ProtocolError("invalid_response", "Ack result id is required.");
  }
  if (!isRecord(parsed.result)) {
    throw new ProtocolError("invalid_response", "Ack result must be an object.");
  }
  if (Object.keys(parsed.result).length !== 0) {
    throw new ProtocolError("invalid_response", "Ack result is malformed.");
  }
}

async function recoverRetainedSigningOutcome<TResponse, TRecoveryContext>(
  options: RetainedSigningRecoveryOptions<TResponse, TRecoveryContext>,
  context: TRecoveryContext,
  originalError: unknown,
): Promise<RetainedSigningRecoveryOutcome<TResponse>> {
  let recovered: DeviceResponse;
  try {
    recovered = await requestDevice({
      request: {
        id: options.makeGetResultRequestId(),
        method: "get_result",
        sessionId: options.request.sessionId,
        payload: { retainedRequestId: options.request.id },
      },
      deadlineMs: options.recoveryDeadlineMs("get_result"),
      execute: options.recoveryExecute(context),
      assertResponse: (response) => response,
      digestPayload: options.digestPayload,
      encodeChunkBase64: options.encodeChunkBase64,
      makeError: options.makeError,
      errorCode: options.errorCode,
      onAbortInvalidSession: options.markInvalidSession,
    });
  } catch (error) {
    if (options.errorCode(error) === "invalid_session") {
      return { status: "session_invalidated" };
    }
    throw originalError;
  }

  if (recovered.success === false) {
    if (recovered.error.code === "invalid_session") {
      return { status: "session_invalidated" };
    }
    if (recovered.error.code === "unknown_request") {
      throw originalError;
    }
    const ack = await ackRetainedSigningOutcome(options, context);
    const error = options.makeError(recovered.error.code, recovered.error.message, recovered.error.retryable);
    if (ack === "invalid_session") {
      options.markInvalidSession(error);
    }
    options.onRecoverySettled?.(context, ack);
    throw error;
  }

  let response: TResponse;
  try {
    response = options.assertSigningOutcome(recovered);
  } catch {
    throw originalError;
  }
  const ack = await ackRetainedSigningOutcome(options, context);
  if (ack === "invalid_session") {
    options.markInvalidSession(response);
  }
  options.onRecoverySettled?.(context, ack);
  return { status: "result", response, sessionInvalidatedByAck: ack === "invalid_session" };
}

async function ackRetainedSigningOutcome<TResponse, TRecoveryContext>(
  options: RetainedSigningRecoveryOptions<TResponse, TRecoveryContext>,
  context: TRecoveryContext,
): Promise<RetainedSigningAckStatus> {
  try {
    await requestDevice({
      request: {
        id: options.makeAckResultRequestId(),
        method: "ack_result",
        sessionId: options.request.sessionId,
        payload: { retainedRequestId: options.request.id },
      },
      deadlineMs: options.recoveryDeadlineMs("ack_result"),
      execute: options.recoveryExecute(context),
      assertResponse: assertAckResultDeviceResponse,
      digestPayload: options.digestPayload,
      encodeChunkBase64: options.encodeChunkBase64,
      makeError: options.makeError,
      errorCode: options.errorCode,
      onAbortInvalidSession: options.markInvalidSession,
    });
    return "acked";
  } catch (error) {
    if (options.errorCode(error) === "invalid_session") {
      return "invalid_session";
    }
    return "failed";
  }
}

function shouldAttemptRetainedRecovery<TResponse, TRecoveryContext>(
  error: unknown,
  options: RetainedSigningRecoveryOptions<TResponse, TRecoveryContext>,
): boolean {
  if (!options.requestMayHaveReachedFirmware(error)) {
    return false;
  }
  const code = options.errorCode(error);
  return code !== null && RECOVERABLE_SIGNING_DELIVERY_CODES.has(code);
}
