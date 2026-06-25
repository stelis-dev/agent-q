import {
  makeDeviceRequest,
  parseDeviceResponse,
  serializeDeviceRequest,
  type DeviceResponse,
  type DeviceErrorCode,
  type DeviceMethod,
} from "./device-contract.js";
import { serializePayloadTransferRequest } from "./protocol-payload-delivery.js";
import { MAX_RAW_PROTOCOL_JSON_BYTES } from "./protocol-primitives.js";
import {
  INTERNAL_USB_DEADLINE_MS,
  PAYLOAD_DELIVERY_DEADLINE_CHUNK_BYTES,
  PAYLOAD_TRANSFER_MAX_BYTES,
} from "./transport-invariants.js";
import { withTransferredPayload } from "./payload-delivery-internal.js";

export interface DeviceRequestInput {
  id?: string;
  method: DeviceMethod;
  sessionId?: string;
  payload?: unknown;
}

export type DeviceRequestExecutor = <TResponse>(
  requestLine: string,
  expectedId: string,
  requestLabel: string,
  deadlineMs: number,
  assertResponse: (response: unknown) => TResponse,
) => Promise<TResponse>;

export interface RequestDeviceOptions<TResponse> {
  request: DeviceRequestInput;
  deadlineMs: number;
  execute: DeviceRequestExecutor;
  assertResponse: (response: DeviceResponse) => TResponse;
  digestPayload: (payloadBytes: Uint8Array) => string | Promise<string>;
  encodeChunkBase64: (chunkBytes: Uint8Array) => string;
  makeError: (code: DeviceErrorCode, message: string, retryable?: boolean) => Error;
  errorCode: (error: unknown) => string | null;
  onAbortInvalidSession?: (error: unknown) => void;
}

export async function requestDevice<TResponse>(
  options: RequestDeviceOptions<TResponse>,
): Promise<TResponse> {
  const request = makeDeviceRequest(options.request);
  const requestLine = serializeDeviceRequest(request);
  if (deviceRequestLineFitsDirectFrame(requestLine)) {
    return options.execute(requestLine, request.id, request.method, options.deadlineMs, (response) =>
      options.assertResponse(parseDeviceResponse(response, {
        expectedId: request.id,
        expectedMethod: request.method,
      })),
    );
  }

  if (!Object.prototype.hasOwnProperty.call(request, "payload") || request.sessionId === undefined) {
    throw options.makeError("payload_too_large", "Payload exceeds the current device payload capacity.", false);
  }

  const payloadJson = JSON.stringify(request.payload);
  if (payloadJson === undefined) {
    throw options.makeError("invalid_params", "Device request payload is not JSON serializable.", false);
  }
  const payloadBytes = new TextEncoder().encode(payloadJson);
  return withTransferredPayload({
    sessionId: request.sessionId,
    payloadBytes,
    chunkMaxBytes: PAYLOAD_DELIVERY_DEADLINE_CHUNK_BYTES,
    payloadMaxBytes: PAYLOAD_TRANSFER_MAX_BYTES,
    executeTransferRequest: (transferRequest, assertTransferResponse) =>
      options.execute(
        serializePayloadTransferRequest(transferRequest),
        transferRequest.id,
        request.method,
        INTERNAL_USB_DEADLINE_MS,
        assertTransferResponse,
      ),
    digestPayload: options.digestPayload,
    encodeChunkBase64: options.encodeChunkBase64,
    makeError: options.makeError,
    errorCode: options.errorCode,
    onAbortInvalidSession: options.onAbortInvalidSession,
    consumeFinalizedPayload: (payloadRef) => {
      const payloadRefRequest = makeDeviceRequest({
        id: request.id,
        method: request.method,
        sessionId: request.sessionId,
        payload: { payloadRef },
      });
      const payloadRefLine = serializeDeviceRequest(payloadRefRequest);
      if (!deviceRequestLineFitsDirectFrame(payloadRefLine)) {
        throw options.makeError(
          "internal_output_error",
          "Device payload reference request is too large.",
          false,
        );
      }
      return options.execute(payloadRefLine, payloadRefRequest.id, payloadRefRequest.method, options.deadlineMs, (response) =>
        options.assertResponse(parseDeviceResponse(response, {
          expectedId: payloadRefRequest.id,
          expectedMethod: payloadRefRequest.method,
        })),
      );
    },
  });
}

function deviceRequestLineFitsDirectFrame(requestLine: string): boolean {
  return new TextEncoder().encode(requestLine).length <= MAX_RAW_PROTOCOL_JSON_BYTES;
}
