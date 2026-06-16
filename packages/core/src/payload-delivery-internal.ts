import { ProtocolError } from "./protocol-error.js";
import {
  SIGNABLE_PAYLOAD_KIND_TRANSACTION,
  makePayloadUploadAbortRequest,
  makePayloadUploadBeginRequest,
  makePayloadUploadChunkRequest,
  makePayloadUploadFinishRequest,
  payloadDeliveryCapabilityLimits,
  type PayloadDeliveryCapability,
  type PayloadUploadBeginResultResponse,
  type PayloadUploadChunkResultResponse,
  type PayloadUploadFinishResultResponse,
  type PayloadUploadRequest,
  type PayloadUploadResponse,
} from "./protocol-payload-delivery.js";

export interface UploadedSignablePayloadDescriptor {
  payloadRef: string;
  chain: string;
  method: string;
  payloadKind: typeof SIGNABLE_PAYLOAD_KIND_TRANSACTION;
  sizeBytes: string;
  payloadDigest: string;
}

export type PayloadDeliveryRequestExecutor = <TResponse extends PayloadUploadResponse>(
  request: PayloadUploadRequest,
  assertResponse: (response: unknown) => TResponse,
) => Promise<TResponse>;

export interface WithUploadedSignablePayloadOptions<TResult> {
  sessionId: string;
  chain: string;
  method: string;
  payloadKind: typeof SIGNABLE_PAYLOAD_KIND_TRANSACTION;
  payloadBytes: Uint8Array;
  capability: PayloadDeliveryCapability;
  executeUploadRequest: PayloadDeliveryRequestExecutor;
  digestPayload: (payloadBytes: Uint8Array) => string | Promise<string>;
  encodeChunkBase64: (chunkBytes: Uint8Array) => string;
  makeError: (code: string, message: string) => Error;
  errorCode: (error: unknown) => string | null;
  onAbortInvalidSession?: (error: unknown) => void;
  consumeFinalizedPayload: (descriptor: UploadedSignablePayloadDescriptor) => Promise<TResult>;
}

export async function withUploadedSignablePayload<TResult>(
  options: WithUploadedSignablePayloadOptions<TResult>,
): Promise<TResult> {
  if (options.payloadKind !== SIGNABLE_PAYLOAD_KIND_TRANSACTION) {
    throw options.makeError("protocol_error", "Payload kind is unsupported.");
  }
  const payloadBytes = new Uint8Array(options.payloadBytes);
  const limits = parseCapabilityLimits(options.capability, options.makeError);
  if (payloadBytes.length > limits.payloadMaxBytes) {
    throw options.makeError(
      "unsupported_payload_size",
      "Transaction payload exceeds the device payload capability.",
    );
  }

  const payloadDigest = await options.digestPayload(payloadBytes);
  let uploadId: string | null = null;
  let payloadRef: string | null = null;
  try {
    const begin = await options.executeUploadRequest(
      makePayloadUploadBeginRequest(options.sessionId, options.chain, options.method, {
        payloadKind: options.payloadKind,
        sizeBytes: String(payloadBytes.length),
        payloadDigest,
      }),
      (response) => assertPayloadUploadBeginResultResponse(response, options.makeError),
    );
    uploadId = begin.uploadId;
    if (begin.receivedBytes !== "0") {
      throw options.makeError("protocol_error", "Firmware payload upload progress is inconsistent.");
    }
    const beginChunkMaxBytes = Number(begin.chunkMaxBytes);
    const chunkMaxBytes = Math.min(limits.chunkMaxBytes, beginChunkMaxBytes);
    if (!Number.isSafeInteger(chunkMaxBytes) || chunkMaxBytes <= 0) {
      throw options.makeError("protocol_error", "Firmware payload chunk capability is invalid.");
    }

    let offset = 0;
    while (offset < payloadBytes.length) {
      const nextOffset = Math.min(offset + chunkMaxBytes, payloadBytes.length);
      const chunk = options.encodeChunkBase64(payloadBytes.subarray(offset, nextOffset));
      const response = await options.executeUploadRequest(
        makePayloadUploadChunkRequest(options.sessionId, uploadId, String(offset), chunk),
        (value) => assertPayloadUploadChunkResultResponse(value, options.makeError),
      );
      if (response.receivedBytes !== String(nextOffset)) {
        throw options.makeError("protocol_error", "Firmware payload upload progress is inconsistent.");
      }
      offset = nextOffset;
    }

    const finish = await options.executeUploadRequest(
      makePayloadUploadFinishRequest(options.sessionId, uploadId),
      (response) => assertPayloadUploadFinishResultResponse(response, options.makeError),
    );
    payloadRef = finish.payloadRef;
    if (
      finish.chain !== options.chain ||
      finish.method !== options.method ||
      finish.payloadKind !== options.payloadKind ||
      finish.sizeBytes !== String(payloadBytes.length) ||
      finish.payloadDigest !== payloadDigest
    ) {
      throw options.makeError("protocol_error", "Firmware payload descriptor does not match the uploaded payload.");
    }

    return await options.consumeFinalizedPayload({
      payloadRef,
      chain: finish.chain,
      method: finish.method,
      payloadKind: finish.payloadKind,
      sizeBytes: finish.sizeBytes,
      payloadDigest: finish.payloadDigest,
    });
  } catch (error) {
    const abort = await abortPayloadDeliveryBestEffort(options, { uploadId, payloadRef });
    if (abort === "invalid_session") {
      options.onAbortInvalidSession?.(error);
    }
    throw error;
  }
}

type PayloadAbortOutcome = "none" | "aborted" | "failed" | "invalid_session";

async function abortPayloadDeliveryBestEffort(
  options: Pick<
    WithUploadedSignablePayloadOptions<unknown>,
    "sessionId" | "executeUploadRequest" | "makeError" | "errorCode"
  >,
  target: { uploadId: string | null; payloadRef: string | null },
): Promise<PayloadAbortOutcome> {
  if (target.payloadRef === null && target.uploadId === null) {
    return "none";
  }
  try {
    if (target.payloadRef !== null) {
      await options.executeUploadRequest(
        makePayloadUploadAbortRequest(options.sessionId, { payloadRef: target.payloadRef }),
        (response) => assertPayloadUploadAbortResultResponse(response, options.makeError),
      );
    } else if (target.uploadId !== null) {
      await options.executeUploadRequest(
        makePayloadUploadAbortRequest(options.sessionId, { uploadId: target.uploadId }),
        (response) => assertPayloadUploadAbortResultResponse(response, options.makeError),
      );
    }
    return "aborted";
  } catch (error) {
    if (options.errorCode(error) === "invalid_session") {
      return "invalid_session";
    }
    return "failed";
  }
}

function parseCapabilityLimits(
  capability: PayloadDeliveryCapability,
  makeError: (code: string, message: string) => Error,
): ReturnType<typeof payloadDeliveryCapabilityLimits> {
  try {
    return payloadDeliveryCapabilityLimits(capability);
  } catch (error) {
    if (error instanceof ProtocolError) {
      throw makeError("protocol_error", error.message);
    }
    throw error;
  }
}

function assertPayloadUploadBeginResultResponse(
  response: unknown,
  makeError: (code: string, message: string) => Error,
): PayloadUploadBeginResultResponse {
  return assertPayloadUploadResponseType(response, "payload_upload_begin_result", makeError);
}

function assertPayloadUploadChunkResultResponse(
  response: unknown,
  makeError: (code: string, message: string) => Error,
): PayloadUploadChunkResultResponse {
  return assertPayloadUploadResponseType(response, "payload_upload_chunk_result", makeError);
}

function assertPayloadUploadFinishResultResponse(
  response: unknown,
  makeError: (code: string, message: string) => Error,
): PayloadUploadFinishResultResponse {
  return assertPayloadUploadResponseType(response, "payload_upload_finish_result", makeError);
}

function assertPayloadUploadAbortResultResponse(
  response: unknown,
  makeError: (code: string, message: string) => Error,
): Extract<PayloadUploadResponse, { type: "payload_upload_abort_result" }> {
  return assertPayloadUploadResponseType(response, "payload_upload_abort_result", makeError);
}

function assertPayloadUploadResponseType<TType extends PayloadUploadResponse["type"]>(
  response: unknown,
  type: TType,
  makeError: (code: string, message: string) => Error,
): Extract<PayloadUploadResponse, { type: TType }> {
  if (!isRecord(response)) {
    throw makeError("protocol_error", "Payload upload response must be an object.");
  }
  if (response.type === "error") {
    const error = isRecord(response.error) ? response.error : {};
    const code = typeof error.code === "string" ? error.code : "protocol_error";
    const message = typeof error.message === "string" ? error.message : "Payload upload request failed.";
    throw makeError(code, message);
  }
  if (response.type !== type) {
    throw makeError("protocol_error", `Protocol response type is not ${type}.`);
  }
  return response as unknown as Extract<PayloadUploadResponse, { type: TType }>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
