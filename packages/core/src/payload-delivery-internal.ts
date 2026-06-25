import { ProtocolError } from "./protocol-error.js";
import { isDeviceErrorCode, type DeviceErrorCode } from "./device-contract.js";
import {
  makePayloadTransferAbortRequest,
  makePayloadTransferBeginRequest,
  makePayloadTransferChunkRequest,
  makePayloadTransferFinishRequest,
  parsePayloadTransferResponse,
  sanitizePayloadTransferAbortResult,
  sanitizePayloadTransferBeginResult,
  sanitizePayloadTransferChunkResult,
  sanitizePayloadTransferFinishResult,
  type PayloadTransferRequest,
} from "./protocol-payload-delivery.js";

export type PayloadTransferRequestExecutor = <TResult>(
  request: PayloadTransferRequest,
  assertResponse: (response: unknown) => TResult,
) => Promise<TResult>;

export interface WithTransferredPayloadOptions<TResult> {
  sessionId: string;
  payloadBytes: Uint8Array;
  chunkMaxBytes: number;
  payloadMaxBytes: number;
  executeTransferRequest: PayloadTransferRequestExecutor;
  digestPayload: (payloadBytes: Uint8Array) => string | Promise<string>;
  encodeChunkBase64: (chunkBytes: Uint8Array) => string;
  makeError: (code: DeviceErrorCode, message: string, retryable?: boolean) => Error;
  errorCode: (error: unknown) => string | null;
  onAbortInvalidSession?: (error: unknown) => void;
  consumeFinalizedPayload: (payloadRef: string) => Promise<TResult>;
}

export async function withTransferredPayload<TResult>(
  options: WithTransferredPayloadOptions<TResult>,
): Promise<TResult> {
  const payloadBytes = new Uint8Array(options.payloadBytes);
  if (payloadBytes.length > options.payloadMaxBytes) {
    throw options.makeError("payload_too_large", "Payload exceeds the current device payload capacity.", false);
  }
  if (!Number.isSafeInteger(options.chunkMaxBytes) || options.chunkMaxBytes <= 0) {
    throw options.makeError("invalid_response", "Device payload transfer chunk size is invalid.", true);
  }

  const payloadDigest = await options.digestPayload(payloadBytes);
  let transferId: string | null = null;
  try {
    const beginRequest = makePayloadTransferBeginRequest(options.sessionId, {
      totalBytes: String(payloadBytes.length),
      payloadDigest,
    });
    const begin = await options.executeTransferRequest(
      beginRequest,
      (response) => assertPayloadTransferSuccess(
        response,
        beginRequest.id,
        sanitizePayloadTransferBeginResult,
        options.makeError,
      ),
    );
    transferId = begin.transferId;
    if (begin.receivedBytes !== "0") {
      throw options.makeError("invalid_response", "Device payload transfer progress is inconsistent.", true);
    }

    const deviceChunkMaxBytes = Number(begin.chunkMaxBytes);
    const chunkMaxBytes = Math.min(options.chunkMaxBytes, deviceChunkMaxBytes);
    if (!Number.isSafeInteger(chunkMaxBytes) || chunkMaxBytes <= 0) {
      throw options.makeError("invalid_response", "Device payload transfer chunk size is invalid.", true);
    }

    let offset = 0;
    while (offset < payloadBytes.length) {
      const nextOffset = Math.min(offset + chunkMaxBytes, payloadBytes.length);
      const chunk = options.encodeChunkBase64(payloadBytes.subarray(offset, nextOffset));
      const chunkRequest = makePayloadTransferChunkRequest(options.sessionId, transferId, String(offset), chunk);
      const response = await options.executeTransferRequest(
        chunkRequest,
        (value) => assertPayloadTransferSuccess(
          value,
          chunkRequest.id,
          sanitizePayloadTransferChunkResult,
          options.makeError,
        ),
      );
      if (response.receivedBytes !== String(nextOffset)) {
        throw options.makeError("invalid_response", "Device payload transfer progress is inconsistent.", true);
      }
      offset = nextOffset;
    }

    const finishRequest = makePayloadTransferFinishRequest(options.sessionId, transferId);
    const finish = await options.executeTransferRequest(
      finishRequest,
      (response) => assertPayloadTransferSuccess(
        response,
        finishRequest.id,
        sanitizePayloadTransferFinishResult,
        options.makeError,
      ),
    );
    return await options.consumeFinalizedPayload(finish.payloadRef);
  } catch (error) {
    const abort = await abortPayloadTransferBestEffort(options, transferId);
    if (abort === "invalid_session") {
      options.onAbortInvalidSession?.(error);
    }
    throw error;
  }
}

type PayloadAbortOutcome = "none" | "aborted" | "failed" | "invalid_session";

async function abortPayloadTransferBestEffort(
  options: Pick<
    WithTransferredPayloadOptions<unknown>,
    "sessionId" | "executeTransferRequest" | "makeError" | "errorCode"
  >,
  transferId: string | null,
): Promise<PayloadAbortOutcome> {
  if (transferId === null) {
    return "none";
  }
  try {
    const abortRequest = makePayloadTransferAbortRequest(options.sessionId, transferId);
    await options.executeTransferRequest(
      abortRequest,
      (response) => assertPayloadTransferSuccess(
        response,
        abortRequest.id,
        sanitizePayloadTransferAbortResult,
        options.makeError,
      ),
    );
    return "aborted";
  } catch (error) {
    if (options.errorCode(error) === "invalid_session") {
      return "invalid_session";
    }
    return "failed";
  }
}

function assertPayloadTransferSuccess<TResult>(
  response: unknown,
  expectedId: string,
  resultParser: (result: unknown) => TResult,
  makeError: (code: DeviceErrorCode, message: string, retryable?: boolean) => Error,
): TResult {
  let parsed;
  try {
    parsed = parsePayloadTransferResponse(response, expectedId, resultParser);
  } catch (error) {
    if (error instanceof ProtocolError) {
      throw makeError(isDeviceErrorCode(error.code) ? error.code : "unknown_error", error.message, false);
    }
    throw error;
  }
  if (parsed.success === false) {
    throw makeError(
      isDeviceErrorCode(parsed.error.code) ? parsed.error.code : "unknown_error",
      parsed.error.message,
      parsed.error.retryable,
    );
  }
  return parsed.result;
}
