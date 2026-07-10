import { gcm } from "@noble/ciphers/aes.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import type { DeviceResponse } from "./device-contract.js";
import {
  requestDevice,
  type DeviceRequestExecutor,
  type DeviceRequestInput,
} from "./device-request-transport.js";
import { DeviceRequestError } from "./errors.js";
import { ProtocolError } from "./protocol-error.js";
import { parseJsonLine } from "./protocol.js";
import { createRequestId } from "./protocol-primitives.js";
import {
  requestSigningWithRetainedRecovery,
  type RetainedSigningRecoveryOutcome,
  type RetainedSigningRequest,
} from "./retained-signing-recovery-internal.js";
import { markFirmwareSessionInvalidated } from "./session-invalidation-internal.js";

export const LOCAL_TRANSPORT_SCHEME = "aqlt:1?";
export const LOCAL_TRANSPORT_KIND_BLE = "ble";
export const LOCAL_TRANSPORT_BLE_SERVICE_UUID = "a6e31d1051a14f7a9b0a0a1c00000001";
export const LOCAL_TRANSPORT_CONTROL_CHARACTERISTIC_UUID =
  "a6e31d1051a14f7a9b0a0a1c00000002";
export const LOCAL_TRANSPORT_DATA_CHARACTERISTIC_UUID =
  "a6e31d1051a14f7a9b0a0a1c00000003";
export const LOCAL_TRANSPORT_PAIRING_EXPIRY_SECONDS = 120;
export const LOCAL_TRANSPORT_HANDSHAKE_READY_SIGNAL = 0x01;
export const LOCAL_TRANSPORT_FRAME_TYPE_PROTOCOL_LINE_FRAGMENT = 0x01;
export const LOCAL_TRANSPORT_FRAME_TYPE_CLOSE = 0x02;
export const LOCAL_TRANSPORT_FRAME_FLAG_LAST = 0x01;
export const LOCAL_TRANSPORT_DIRECTION_GATEWAY_TO_DEVICE = 0x01;
export const LOCAL_TRANSPORT_DIRECTION_DEVICE_TO_GATEWAY = 0x02;
export const LOCAL_TRANSPORT_KEY_BYTES = 32;
export const LOCAL_TRANSPORT_TAG_BYTES = 16;
export const LOCAL_TRANSPORT_FRAME_HEADER_BYTES = 10;
export const LOCAL_TRANSPORT_MAX_ENCRYPTED_FRAME_PAYLOAD_BYTES = 480;
export const LOCAL_TRANSPORT_MIN_ENCRYPTED_FRAME_PAYLOAD_BYTES = 20;
export const LOCAL_TRANSPORT_HANDSHAKE_TIMEOUT_MS = 10_000;
export const LOCAL_TRANSPORT_RESPONSE_TIMEOUT_MS = 185_000;
export const LOCAL_TRANSPORT_CARRIER_CLEANUP_TIMEOUT_MS = 5_000;

const PROTOCOL_NAME = ascii("Noise_XX_25519_AESGCM_SHA256");
const PAIRING_PROLOGUE_PREFIX = ascii("Agent-Q local transport pairing v1\0");
const FRAME_AAD_LABEL = ascii("Agent-Q local transport frame v1\0");
const NONCE_BYTES = 12;
const MESSAGE2_BYTES = 32 + 32 + LOCAL_TRANSPORT_TAG_BYTES + 8 + LOCAL_TRANSPORT_TAG_BYTES;
const MESSAGE3_BYTES = 32 + LOCAL_TRANSPORT_TAG_BYTES + LOCAL_TRANSPORT_TAG_BYTES;
const REQUEST_LINE_CAP = 4096;
const RESPONSE_LINE_CAP = 16 * 1024;
const LOCAL_TRANSPORT_REQUEST_MAY_HAVE_REACHED_FIRMWARE = Symbol(
  "localTransport.requestMayHaveReachedFirmware",
);

export interface LocalTransportOpticalPayload {
  raw: string;
  kind: "ble";
  serviceUuid: string;
  controlCharacteristicUuid: string;
  dataCharacteristicUuid: string;
  identityFingerprint: Uint8Array;
  nonce: Uint8Array;
  expiresInSeconds: number;
}

export interface LocalTransportNoiseKeys {
  gatewayToDevice: Uint8Array;
  deviceToGateway: Uint8Array;
}

export interface LocalTransportPlainFrame {
  type: number;
  flags: number;
  sequence: number;
  totalLen: number;
  payload: Uint8Array;
}

export interface LocalTransportProtocolSessionOptions {
  keys: LocalTransportNoiseKeys;
  encryptedFramePayloadBytes: number;
  defaultResponseTimeoutMs: number;
  cleanupTimeoutMs: number;
  writeData(data: Uint8Array): Promise<void>;
  addDataListener(listener: (data: Uint8Array) => void): void;
  removeDataListener(listener: (data: Uint8Array) => void): void;
  onCarrierClosed(listener: () => void): () => void;
  closeCarrier(): Promise<void>;
}

export interface LocalTransportProtocolSessionLike {
  execute: DeviceRequestExecutor;
  request<TResponse>(
    request: DeviceRequestInput,
    deadlineMs: number,
    assertResponse: (response: DeviceResponse) => TResponse,
  ): Promise<TResponse>;
  requestSigning<TResponse>(
    request: RetainedSigningRequest,
    deadlineMs: number,
    assertResponse: (response: DeviceResponse) => TResponse,
  ): Promise<RetainedSigningRecoveryOutcome<TResponse>>;
  close(): Promise<void>;
}

export interface LocalTransportControlWaiter {
  promise: Promise<Uint8Array>;
  cancel(error: DeviceRequestError): void;
}

export interface OpenLocalTransportProtocolSessionOptions
  extends Omit<LocalTransportProtocolSessionOptions, "keys"> {
  opticalPayload: LocalTransportOpticalPayload;
  handshakeTimeoutMs: number;
  beginControlWait(label: string, timeoutMs: number): LocalTransportControlWaiter;
  writeControl(data: Uint8Array): Promise<void>;
}

export function parseLocalTransportOpticalPayload(payload: string): LocalTransportOpticalPayload {
  if (typeof payload !== "string" || payload.length > 128 || !payload.startsWith(LOCAL_TRANSPORT_SCHEME)) {
    throw new DeviceRequestError("invalid_params", "Local transport optical payload is invalid.", false);
  }
  const match = /^aqlt:1\?k=([^&]+)&svc=([0-9a-f]{32})&idfp=([0-9a-f]{16})&non=([0-9a-f]{16})&exp=([1-9][0-9]*)$/.exec(payload);
  if (match === null) {
    throw new DeviceRequestError("invalid_params", "Local transport optical payload format is invalid.", false);
  }
  const [, kind, serviceUuid, idfpHex, nonceHex, expires] = match;
  if (kind !== LOCAL_TRANSPORT_KIND_BLE) {
    throw new DeviceRequestError("unsupported_transport", "Local transport kind is not supported.", false);
  }
  if (serviceUuid !== LOCAL_TRANSPORT_BLE_SERVICE_UUID) {
    throw new DeviceRequestError("unsupported_transport", "Local transport endpoint is not supported.", false);
  }
  const expiresInSeconds = Number(expires);
  if (expiresInSeconds !== LOCAL_TRANSPORT_PAIRING_EXPIRY_SECONDS) {
    throw new DeviceRequestError("invalid_params", "Local transport expiry is invalid.", false);
  }
  return {
    raw: payload,
    kind: LOCAL_TRANSPORT_KIND_BLE,
    serviceUuid: LOCAL_TRANSPORT_BLE_SERVICE_UUID,
    controlCharacteristicUuid: LOCAL_TRANSPORT_CONTROL_CHARACTERISTIC_UUID,
    dataCharacteristicUuid: LOCAL_TRANSPORT_DATA_CHARACTERISTIC_UUID,
    identityFingerprint: hexToBytes(idfpHex!),
    nonce: hexToBytes(nonceHex!),
    expiresInSeconds,
  };
}

export async function openLocalTransportProtocolSession(
  options: OpenLocalTransportProtocolSessionOptions,
): Promise<LocalTransportProtocolSessionLike> {
  return openLocalTransportProtocolSessionWithRandomSource(
    options,
    secureLocalTransportRandomBytes,
  );
}

/** @internal Core-owned deterministic seam; not exported by a package subpath. */
export async function openLocalTransportProtocolSessionWithRandomSource(
  options: OpenLocalTransportProtocolSessionOptions,
  randomBytes: (length: number) => Uint8Array,
): Promise<LocalTransportProtocolSessionLike> {
  const noise = new LocalTransportNoiseXxInitiator({
    opticalPayload: options.opticalPayload.raw,
    randomBytes,
  });
  let keys: LocalTransportNoiseKeys | null = null;
  try {
    const message2Waiter = options.beginControlWait(
      "handshake message 2",
      options.handshakeTimeoutMs,
    );
    void message2Waiter.promise.catch(noop);
    let message2: Uint8Array;
    try {
      await runLocalTransportOperation(
        "handshake message 1 write",
        options.handshakeTimeoutMs,
        () => options.writeControl(noise.message1()),
      );
      message2 = await message2Waiter.promise;
    } catch (error) {
      message2Waiter.cancel(mapLocalTransportProtocolError(error));
      await message2Waiter.promise.catch(noop);
      throw error;
    }

    const prepared = noise.readMessage2AndPrepareMessage3(
      message2,
      options.opticalPayload.identityFingerprint,
    );
    keys = prepared.keys;
    const readyWaiter = options.beginControlWait(
      "handshake ready indication",
      options.handshakeTimeoutMs,
    );
    void readyWaiter.promise.catch(noop);
    let ready: Uint8Array;
    try {
      await runLocalTransportOperation(
        "handshake message 3 write",
        options.handshakeTimeoutMs,
        () => options.writeControl(prepared.message3),
      );
      ready = await readyWaiter.promise;
    } catch (error) {
      readyWaiter.cancel(mapLocalTransportProtocolError(error));
      await readyWaiter.promise.catch(noop);
      throw error;
    } finally {
      prepared.message3.fill(0);
    }
    if (ready.length !== 1 || ready[0] !== LOCAL_TRANSPORT_HANDSHAKE_READY_SIGNAL) {
      throw new DeviceRequestError(
        "handshake_failed",
        "Local transport handshake ready signal is invalid.",
        true,
      );
    }

    const sessionKeys = keys;
    const session = new LocalTransportProtocolSession({
      keys: sessionKeys,
      encryptedFramePayloadBytes: options.encryptedFramePayloadBytes,
      defaultResponseTimeoutMs: options.defaultResponseTimeoutMs,
      cleanupTimeoutMs: options.cleanupTimeoutMs,
      writeData: options.writeData,
      addDataListener: options.addDataListener,
      removeDataListener: options.removeDataListener,
      onCarrierClosed: options.onCarrierClosed,
      closeCarrier: options.closeCarrier,
    });
    keys = null;
    return session;
  } finally {
    noise.wipe();
    keys?.gatewayToDevice.fill(0);
    keys?.deviceToGateway.fill(0);
  }
}

export class LocalTransportNoiseXxInitiator {
  #h = new Uint8Array(32);
  #ck: Uint8Array;
  #k: Uint8Array | null = null;
  #n = 0n;
  readonly #e: Uint8Array;
  readonly #ePub: Uint8Array;
  readonly #s: Uint8Array;
  readonly #sPub: Uint8Array;

  constructor(options: {
    opticalPayload: string;
    randomBytes: (length: number) => Uint8Array;
  }) {
    this.#h.set(PROTOCOL_NAME);
    this.#ck = this.#h.slice();
    this.#mixHash(concatBytes(PAIRING_PROLOGUE_PREFIX, ascii(options.opticalPayload)));
    let e: Uint8Array | null = null;
    let ePub: Uint8Array | null = null;
    let s: Uint8Array | null = null;
    let sPub: Uint8Array | null = null;
    try {
      e = takeSecret(options.randomBytes(LOCAL_TRANSPORT_KEY_BYTES), "gateway ephemeral secret");
      ePub = x25519Public(e);
      s = takeSecret(options.randomBytes(LOCAL_TRANSPORT_KEY_BYTES), "gateway static secret");
      sPub = x25519Public(s);
    } catch (error) {
      e?.fill(0);
      ePub?.fill(0);
      s?.fill(0);
      sPub?.fill(0);
      this.#h.fill(0);
      this.#ck.fill(0);
      throw error;
    }
    this.#e = e;
    this.#ePub = ePub;
    this.#s = s;
    this.#sPub = sPub;
  }

  message1(): Uint8Array {
    this.#mixHash(this.#ePub);
    return this.#ePub.slice();
  }

  readMessage2AndPrepareMessage3(
    message2: Uint8Array,
    expectedIdfp: Uint8Array,
  ): { message3: Uint8Array; keys: LocalTransportNoiseKeys } {
    if (message2.length !== MESSAGE2_BYTES) {
      throw new DeviceRequestError("handshake_failed", "Local transport handshake message length is invalid.", true);
    }
    let offset = 0;
    const deviceEphemeral = message2.slice(offset, offset + LOCAL_TRANSPORT_KEY_BYTES);
    offset += LOCAL_TRANSPORT_KEY_BYTES;
    this.#mixHash(deviceEphemeral);
    this.#mixKey(x25519Shared(this.#e, deviceEphemeral));

    const encryptedDeviceStatic = message2.subarray(
      offset,
      offset + LOCAL_TRANSPORT_KEY_BYTES + LOCAL_TRANSPORT_TAG_BYTES,
    );
    offset += LOCAL_TRANSPORT_KEY_BYTES + LOCAL_TRANSPORT_TAG_BYTES;
    const deviceStatic = this.#decryptAndHash(encryptedDeviceStatic);
    this.#mixKey(x25519Shared(this.#e, deviceStatic));

    const encryptedIdfp = message2.subarray(offset, offset + 8 + LOCAL_TRANSPORT_TAG_BYTES);
    offset += 8 + LOCAL_TRANSPORT_TAG_BYTES;
    if (offset !== message2.length) {
      throw new DeviceRequestError("handshake_failed", "Local transport handshake parse failed.", true);
    }
    const idfpEcho = this.#decryptAndHash(encryptedIdfp);
    const computedIdfp = sha256(deviceStatic).subarray(0, 8);
    if (!equalBytes(idfpEcho, computedIdfp) || !equalBytes(idfpEcho, expectedIdfp)) {
      throw new DeviceRequestError("handshake_failed", "Local transport identity binding failed.", true);
    }

    const encryptedStatic = this.#encryptAndHash(this.#sPub);
    this.#mixKey(x25519Shared(this.#s, deviceEphemeral));
    const finalTag = this.#encryptAndHash(new Uint8Array());
    const message3 = concatBytes(encryptedStatic, finalTag);
    if (message3.length !== MESSAGE3_BYTES) {
      throw new DeviceRequestError("internal_output_error", "Local transport handshake output is invalid.", false);
    }
    const [gatewayToDevice, deviceToGateway] = hkdf2(this.#ck, new Uint8Array());
    return { message3, keys: { gatewayToDevice, deviceToGateway } };
  }

  wipe(): void {
    this.#h.fill(0);
    this.#ck.fill(0);
    this.#k?.fill(0);
    this.#e.fill(0);
    this.#ePub.fill(0);
    this.#s.fill(0);
    this.#sPub.fill(0);
    this.#k = null;
    this.#n = 0n;
  }

  #mixHash(data: Uint8Array): void {
    const previous = this.#h;
    this.#h = sha256(concatBytes(previous, data));
    previous.fill(0);
  }

  #mixKey(ikm: Uint8Array): void {
    const previousCk = this.#ck;
    const previousK = this.#k;
    try {
      const [nextCk, tempK] = hkdf2(previousCk, ikm);
      this.#ck = nextCk;
      this.#k = tempK;
      this.#n = 0n;
      previousCk.fill(0);
      previousK?.fill(0);
    } finally {
      ikm.fill(0);
    }
  }

  #encryptAndHash(plaintext: Uint8Array): Uint8Array {
    const output = this.#k === null
      ? plaintext.slice()
      : aesGcmEncrypt(this.#k, noiseNonce(this.#n++), this.#h, plaintext);
    this.#mixHash(output);
    return output;
  }

  #decryptAndHash(input: Uint8Array): Uint8Array {
    let plaintext: Uint8Array;
    try {
      plaintext = this.#k === null
        ? input.slice()
        : aesGcmDecrypt(this.#k, noiseNonce(this.#n++), this.#h, input);
    } catch {
      throw new DeviceRequestError("handshake_failed", "Local transport handshake authentication failed.", true);
    }
    this.#mixHash(input);
    return plaintext;
  }
}

export function encodeLocalTransportPlainFrame(
  type: number,
  flags: number,
  sequence: number,
  totalLen: number,
  payload: Uint8Array,
): Uint8Array {
  if (!Number.isInteger(sequence) || sequence < 0 || sequence > 0xffff ||
      !Number.isInteger(totalLen) || totalLen < 1 || totalLen > 0xffff_ffff ||
      payload.length > 0xffff) {
    throw new DeviceRequestError("transport_error", "Local transport frame fields are invalid.", true);
  }
  const output = new Uint8Array(LOCAL_TRANSPORT_FRAME_HEADER_BYTES + payload.length);
  const view = new DataView(output.buffer, output.byteOffset, output.byteLength);
  output[0] = type;
  output[1] = flags;
  view.setUint16(2, sequence, false);
  view.setUint32(4, totalLen, false);
  view.setUint16(8, payload.length, false);
  output.set(payload, LOCAL_TRANSPORT_FRAME_HEADER_BYTES);
  return output;
}

export function encryptLocalTransportFrame(
  key: Uint8Array,
  direction: number,
  counter: bigint,
  plainFrame: Uint8Array,
): Uint8Array {
  return aesGcmEncrypt(key, frameNonce(counter), frameAad(direction, counter), plainFrame);
}

export function decryptLocalTransportFrame(
  key: Uint8Array,
  direction: number,
  counter: bigint,
  encryptedFrame: Uint8Array,
): LocalTransportPlainFrame {
  let plain: Uint8Array;
  try {
    plain = aesGcmDecrypt(key, frameNonce(counter), frameAad(direction, counter), encryptedFrame);
  } catch {
    throw new DeviceRequestError("transport_error", "Local transport frame authentication failed.", true);
  }
  return decodeLocalTransportPlainFrame(plain);
}

export function localTransportSha256Digest(value: Uint8Array): string {
  return `sha256:${bytesToHex(sha256(value))}`;
}

export class LocalTransportProtocolSession implements LocalTransportProtocolSessionLike {
  readonly #keys: LocalTransportNoiseKeys;
  readonly #encryptedFramePayloadBytes: number;
  readonly #defaultResponseTimeoutMs: number;
  readonly #cleanupTimeoutMs: number;
  readonly #writeData: (data: Uint8Array) => Promise<void>;
  readonly #addDataListener: (listener: (data: Uint8Array) => void) => void;
  readonly #removeDataListener: (listener: (data: Uint8Array) => void) => void;
  readonly #closeCarrier: () => Promise<void>;
  readonly #removeCarrierClosedListener: () => void;
  #txCounter = 0n;
  #rxCounter = 0n;
  #transactionTail: Promise<void> = Promise.resolve();
  #activeResponseCancel: ((error: DeviceRequestError) => void) | null = null;
  #closed = false;
  #carrierReleased = false;
  #cleanupPromise: Promise<void> | null = null;

  readonly execute: DeviceRequestExecutor = async (
    requestLine,
    expectedId,
    requestLabel,
    deadlineMs,
    assertResponse,
  ) => {
    if (this.#closed) {
      throw new DeviceRequestError("transport_closed", "Local transport session is closed.", true);
    }
    const requestTimeoutMs = boundedTimeoutMs(deadlineMs, this.#defaultResponseTimeoutMs);
    const requestDeadlineMs = Date.now() + requestTimeoutMs;
    const waiter = this.#waitForResponse(expectedId, requestLabel, requestTimeoutMs);
    void waiter.promise.catch(noop);
    let requestWritten = false;
    let responseReceived = false;
    try {
      await this.#writeRequestLine(requestLine, requestDeadlineMs);
      requestWritten = true;
      const responseLine = await waiter.promise;
      responseReceived = true;
      return assertResponse(parseJsonLine(responseLine));
    } catch (error) {
      const mapped = mapLocalTransportProtocolError(error);
      if (requestWritten && !responseReceived) {
        markLocalTransportRequestMayHaveReachedFirmware(mapped);
      }
      waiter.cancel(mapped);
      await waiter.promise.catch(noop);
      const canReplaySigningResponse =
        requestWritten &&
        !responseReceived &&
        mapped.code === "timeout" &&
        isSigningMethod(requestLabel);
      if (!canReplaySigningResponse) {
        void this.close();
      }
      throw mapped;
    }
  };

  constructor(options: LocalTransportProtocolSessionOptions) {
    this.#keys = {
      gatewayToDevice: options.keys.gatewayToDevice,
      deviceToGateway: options.keys.deviceToGateway,
    };
    this.#encryptedFramePayloadBytes = options.encryptedFramePayloadBytes;
    this.#defaultResponseTimeoutMs = options.defaultResponseTimeoutMs;
    this.#cleanupTimeoutMs = options.cleanupTimeoutMs;
    this.#writeData = options.writeData;
    this.#addDataListener = options.addDataListener;
    this.#removeDataListener = options.removeDataListener;
    this.#closeCarrier = options.closeCarrier;
    this.#removeCarrierClosedListener = options.onCarrierClosed(() => {
      this.#markClosed(new DeviceRequestError("transport_closed", "Local transport disconnected.", true));
      void this.#releaseCarrierOnce();
    });
  }

  async request<TResponse>(
    input: DeviceRequestInput,
    deadlineMs: number,
    assertResponse: (response: DeviceResponse) => TResponse,
  ): Promise<TResponse> {
    const stableRequest = isSigningMethod(input.method) && input.id === undefined
      ? { ...input, id: createRequestId() }
      : input;
    return this.#enqueueRequest(deadlineMs, async (remainingMs) => {
      if (!isSigningMethod(stableRequest.method)) {
        return this.#requestUnlocked(stableRequest, remainingMs, assertResponse);
      }
      if (stableRequest.id === undefined || stableRequest.sessionId === undefined) {
        throw new DeviceRequestError(
          "invalid_params",
          "Local transport signing requires a request id and session id.",
          false,
        );
      }
      const outcome = await this.#requestSigningUnlocked(
        stableRequest as RetainedSigningRequest,
        remainingMs,
        assertResponse,
      );
      if (outcome.status === "session_invalidated") {
        throw new DeviceRequestError(
          "invalid_session",
          "Session is missing, expired, or does not match.",
          false,
        );
      }
      if (outcome.sessionInvalidatedByAck) {
        markFirmwareSessionInvalidated(outcome.response);
      }
      return outcome.response;
    });
  }

  async requestSigning<TResponse>(
    request: RetainedSigningRequest,
    deadlineMs: number,
    assertResponse: (response: DeviceResponse) => TResponse,
  ): Promise<RetainedSigningRecoveryOutcome<TResponse>> {
    return this.#enqueueRequest(
      deadlineMs,
      (remainingMs) => this.#requestSigningUnlocked(request, remainingMs, assertResponse),
    );
  }

  #enqueueRequest<TResponse>(
    deadlineMs: number,
    operation: (remainingMs: number) => Promise<TResponse>,
  ): Promise<TResponse> {
    const absoluteDeadlineMs = Date.now() + Math.max(0, deadlineMs);
    const previous = this.#transactionTail;
    const run = previous.then(async () => {
      const remainingMs = absoluteDeadlineMs - Date.now();
      if (remainingMs <= 0) {
        throw new DeviceRequestError("timeout", "Local transport request expired before execution.", true);
      }
      if (this.#closed) {
        throw new DeviceRequestError("transport_closed", "Local transport session is closed.", true);
      }
      return operation(remainingMs);
    });
    this.#transactionTail = run.then(noop, noop);
    return run;
  }

  #requestUnlocked<TResponse>(
    request: DeviceRequestInput,
    deadlineMs: number,
    assertResponse: (response: DeviceResponse) => TResponse,
  ): Promise<TResponse> {
    return requestDevice({
      request,
      deadlineMs,
      execute: this.execute,
      assertResponse,
      digestPayload: localTransportSha256Digest,
      encodeChunkBase64: encodeBase64,
      makeError: (code, message, retryable = false) =>
        new DeviceRequestError(code, message, retryable),
      errorCode: localTransportErrorCode,
    });
  }

  #requestSigningUnlocked<TResponse>(
    request: RetainedSigningRequest,
    deadlineMs: number,
    assertResponse: (response: DeviceResponse) => TResponse,
  ): Promise<RetainedSigningRecoveryOutcome<TResponse>> {
    return requestSigningWithRetainedRecovery<TResponse, LocalTransportProtocolSession>({
      request,
      deadlineMs,
      execute: this.execute,
      assertSigningOutcome: assertResponse,
      digestPayload: localTransportSha256Digest,
      encodeChunkBase64: encodeBase64,
      makeError: (code, message, retryable = false) =>
        new DeviceRequestError(code, message, retryable),
      errorCode: localTransportErrorCode,
      requestMayHaveReachedFirmware: localTransportRequestMayHaveReachedFirmware,
      markInvalidSession: markFirmwareSessionInvalidated,
      recoveryDeadlineMs: () => this.#cleanupTimeoutMs,
      makeGetResultRequestId: createRequestId,
      makeAckResultRequestId: createRequestId,
      prepareRecovery: () => this.#closed ? null : this,
      recoveryExecute: (session) => session.execute,
    });
  }

  async close(): Promise<void> {
    if (this.#cleanupPromise !== null) {
      return this.#cleanupPromise;
    }
    this.#cleanupPromise = (async () => {
      const cleanupDeadlineMs = Date.now() + this.#cleanupTimeoutMs;
      let encryptedClose: Uint8Array | null = null;
      if (!this.#closed) {
        try {
          const closeFrame = encodeLocalTransportPlainFrame(
            LOCAL_TRANSPORT_FRAME_TYPE_CLOSE,
            LOCAL_TRANSPORT_FRAME_FLAG_LAST,
            0,
            1,
            new Uint8Array(),
          );
          encryptedClose = encryptLocalTransportFrame(
            this.#keys.gatewayToDevice,
            LOCAL_TRANSPORT_DIRECTION_GATEWAY_TO_DEVICE,
            this.#txCounter,
            closeFrame,
          );
          this.#txCounter += 1n;
        } catch {
          encryptedClose = null;
        }
      }
      this.#markClosed(new DeviceRequestError("transport_closed", "Local transport session was closed.", true));
      if (encryptedClose !== null) {
        try {
          await runLocalTransportOperation(
            "close frame write",
            remainingTimeoutMs(cleanupDeadlineMs),
            () => this.#writeData(encryptedClose!),
          );
        } catch {
          // Carrier release below remains the fail-closed cleanup path.
        } finally {
          encryptedClose.fill(0);
        }
      }
      await runLocalTransportOperation(
        "carrier cleanup",
        remainingTimeoutMs(cleanupDeadlineMs),
        () => this.#releaseCarrierOnce(),
      ).catch(noop);
    })();
    return this.#cleanupPromise;
  }

  async #writeRequestLine(requestLine: string, requestDeadlineMs: number): Promise<void> {
    const requestBytes = new TextEncoder().encode(requestLine);
    if (requestBytes.length < 1 || requestBytes.length > REQUEST_LINE_CAP) {
      throw new DeviceRequestError("payload_too_large", "Local transport request line is too large.", false);
    }
    let offset = 0;
    let sequence = 0;
    while (offset < requestBytes.length) {
      const payload = requestBytes.subarray(
        offset,
        Math.min(requestBytes.length, offset + this.#encryptedFramePayloadBytes),
      );
      offset += payload.length;
      const plainFrame = encodeLocalTransportPlainFrame(
        LOCAL_TRANSPORT_FRAME_TYPE_PROTOCOL_LINE_FRAGMENT,
        offset === requestBytes.length ? LOCAL_TRANSPORT_FRAME_FLAG_LAST : 0,
        sequence,
        requestBytes.length,
        payload,
      );
      sequence += 1;
      const encrypted = encryptLocalTransportFrame(
        this.#keys.gatewayToDevice,
        LOCAL_TRANSPORT_DIRECTION_GATEWAY_TO_DEVICE,
        this.#txCounter,
        plainFrame,
      );
      this.#txCounter += 1n;
      try {
        const remainingMs = requestDeadlineMs - Date.now();
        if (remainingMs <= 0) {
          throw new DeviceRequestError(
            "timeout",
            "Local transport request expired while writing.",
            true,
          );
        }
        await runLocalTransportOperation(
          "request frame write",
          remainingMs,
          () => this.#writeData(encrypted),
        );
      } finally {
        encrypted.fill(0);
      }
    }
  }

  #waitForResponse(expectedId: string, label: string, deadlineMs: number): {
    promise: Promise<string>;
    cancel: (error: DeviceRequestError) => void;
  } {
    const responseChunks: Uint8Array[] = [];
    let responseTotal: number | null = null;
    let nextSequence = 0;
    let received = 0;
    const timeoutMs = boundedTimeoutMs(deadlineMs, this.#defaultResponseTimeoutMs);
    let settled = false;
    let cancel = (_error: DeviceRequestError): void => {};
    const promise = new Promise<string>((resolve, reject) => {
      const cleanup = (): void => {
        clearTimeout(timer);
        this.#removeDataListener(onData);
        if (this.#activeResponseCancel === cancel) {
          this.#activeResponseCancel = null;
        }
      };
      const fail = (error: DeviceRequestError): void => {
        if (settled) {
          return;
        }
        settled = true;
        cleanup();
        reject(error);
      };
      cancel = fail;
      const onData = (chunk: Uint8Array): void => {
        if (settled) {
          return;
        }
        try {
          const frame = decryptLocalTransportFrame(
            this.#keys.deviceToGateway,
            LOCAL_TRANSPORT_DIRECTION_DEVICE_TO_GATEWAY,
            this.#rxCounter,
            chunk,
          );
          this.#rxCounter += 1n;
          if (frame.type !== LOCAL_TRANSPORT_FRAME_TYPE_PROTOCOL_LINE_FRAGMENT) {
            throw new DeviceRequestError("transport_error", "Unexpected local transport response frame.", true);
          }
          if (frame.sequence !== nextSequence) {
            throw new DeviceRequestError("transport_error", "Local transport response sequence mismatch.", true);
          }
          nextSequence += 1;
          if (responseTotal === null) {
            responseTotal = frame.totalLen;
            if (responseTotal < 1 || responseTotal > RESPONSE_LINE_CAP) {
              throw new DeviceRequestError("invalid_response", "Local transport response length is invalid.", true);
            }
          } else if (responseTotal !== frame.totalLen) {
            throw new DeviceRequestError("invalid_response", "Local transport response length changed.", true);
          }
          responseChunks.push(frame.payload);
          received += frame.payload.length;
          if (received > responseTotal) {
            throw new DeviceRequestError("invalid_response", "Local transport response exceeds declared length.", true);
          }
          if ((frame.flags & LOCAL_TRANSPORT_FRAME_FLAG_LAST) === 0) {
            return;
          }
          if (received !== responseTotal) {
            throw new DeviceRequestError("invalid_response", "Local transport response is incomplete.", true);
          }
          let responseLine: string;
          try {
            responseLine = new TextDecoder("utf-8", { fatal: true }).decode(concatBytes(...responseChunks));
          } catch {
            throw new DeviceRequestError("invalid_response", "Local transport response is not valid UTF-8.", true);
          }
          const parsed = parseJsonLine(responseLine);
          if (isResponseForAnotherRequest(parsed, expectedId)) {
            responseChunks.length = 0;
            responseTotal = null;
            nextSequence = 0;
            received = 0;
            return;
          }
          settled = true;
          cleanup();
          resolve(responseLine);
        } catch (error) {
          fail(mapLocalTransportProtocolError(error));
        }
      };
      const timer = setTimeout(() => {
        fail(new DeviceRequestError("timeout", `Timed out waiting for ${label} local transport response.`, true));
      }, timeoutMs);
      this.#addDataListener(onData);
      this.#activeResponseCancel = cancel;
    });
    return { promise, cancel: (error) => cancel(error) };
  }

  #markClosed(error: DeviceRequestError): void {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    this.#activeResponseCancel?.(error);
    this.#keys.gatewayToDevice.fill(0);
    this.#keys.deviceToGateway.fill(0);
  }

  async #releaseCarrierOnce(): Promise<void> {
    if (this.#carrierReleased) {
      return;
    }
    this.#carrierReleased = true;
    this.#removeCarrierClosedListener();
    await this.#closeCarrier();
  }
}

function decodeLocalTransportPlainFrame(plain: Uint8Array): LocalTransportPlainFrame {
  if (plain.length < LOCAL_TRANSPORT_FRAME_HEADER_BYTES) {
    throw new DeviceRequestError("transport_error", "Local transport frame is too short.", true);
  }
  const view = new DataView(plain.buffer, plain.byteOffset, plain.byteLength);
  const type = plain[0] ?? 0;
  const flags = plain[1] ?? 0;
  const sequence = view.getUint16(2, false);
  const totalLen = view.getUint32(4, false);
  const payloadLen = view.getUint16(8, false);
  if (plain.length !== LOCAL_TRANSPORT_FRAME_HEADER_BYTES + payloadLen) {
    throw new DeviceRequestError("transport_error", "Local transport frame length mismatch.", true);
  }
  if (type !== LOCAL_TRANSPORT_FRAME_TYPE_PROTOCOL_LINE_FRAGMENT &&
      type !== LOCAL_TRANSPORT_FRAME_TYPE_CLOSE) {
    throw new DeviceRequestError("transport_error", "Local transport frame type is invalid.", true);
  }
  if ((flags & ~LOCAL_TRANSPORT_FRAME_FLAG_LAST) !== 0 ||
      payloadLen > totalLen ||
      totalLen === 0) {
    throw new DeviceRequestError("transport_error", "Local transport frame fields are invalid.", true);
  }
  return {
    type,
    flags,
    sequence,
    totalLen,
    payload: plain.slice(LOCAL_TRANSPORT_FRAME_HEADER_BYTES),
  };
}

function hkdf2(salt: Uint8Array, ikm: Uint8Array): [Uint8Array, Uint8Array] {
  const tempKey = hmac(sha256, salt, ikm);
  try {
    const out1 = hmac(sha256, tempKey, Uint8Array.of(0x01));
    const out2 = hmac(sha256, tempKey, concatBytes(out1, Uint8Array.of(0x02)));
    return [out1, out2];
  } finally {
    tempKey.fill(0);
  }
}

function aesGcmEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  return gcm(key, nonce, aad).encrypt(plaintext);
}

function aesGcmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  if (ciphertext.length < LOCAL_TRANSPORT_TAG_BYTES) {
    throw new Error("ciphertext too short");
  }
  return gcm(key, nonce, aad).decrypt(ciphertext);
}

function x25519Public(secret: Uint8Array): Uint8Array {
  return x25519.getPublicKey(secret);
}

function x25519Shared(secret: Uint8Array, publicKey: Uint8Array): Uint8Array {
  const shared = x25519.getSharedSecret(secret, publicKey);
  if (shared.every((byte) => byte === 0)) {
    shared.fill(0);
    throw new DeviceRequestError("handshake_failed", "X25519 shared secret is invalid.", true);
  }
  return shared;
}

function noiseNonce(counter: bigint): Uint8Array {
  const nonce = new Uint8Array(NONCE_BYTES);
  new DataView(nonce.buffer).setBigUint64(4, counter, false);
  return nonce;
}

function frameNonce(counter: bigint): Uint8Array {
  return noiseNonce(counter);
}

function frameAad(direction: number, counter: bigint): Uint8Array {
  const counterBytes = new Uint8Array(8);
  new DataView(counterBytes.buffer).setBigUint64(0, counter, false);
  return concatBytes(FRAME_AAD_LABEL, Uint8Array.of(direction), counterBytes);
}

function takeSecret(secret: Uint8Array, label: string): Uint8Array {
  if (!(secret instanceof Uint8Array) || secret.length !== LOCAL_TRANSPORT_KEY_BYTES) {
    if (secret instanceof Uint8Array) {
      secret.fill(0);
    }
    throw new DeviceRequestError("invalid_params", `${label} must be 32 bytes.`, false);
  }
  return secret;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function ascii(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function hexToBytes(value: string): Uint8Array {
  const output = new Uint8Array(value.length / 2);
  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return output;
}

function bytesToHex(value: Uint8Array): string {
  let output = "";
  for (const byte of value) {
    output += byte.toString(16).padStart(2, "0");
  }
  return output;
}

function encodeBase64(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function secureLocalTransportRandomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length <= 0 || globalThis.crypto === undefined ||
      typeof globalThis.crypto.getRandomValues !== "function") {
    throw new DeviceRequestError(
      "unsupported_transport",
      "A secure random source is unavailable for local transport.",
      false,
    );
  }
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

function boundedTimeoutMs(deadlineMs: number, defaultTimeoutMs: number): number {
  if (!Number.isFinite(deadlineMs) || deadlineMs <= 0) {
    return defaultTimeoutMs;
  }
  return Math.max(1, Math.min(Math.trunc(deadlineMs), defaultTimeoutMs));
}

function remainingTimeoutMs(deadlineMs: number): number {
  return Math.max(1, deadlineMs - Date.now());
}

export function runLocalTransportOperation<T>(
  label: string,
  timeoutMs: number,
  operation: () => Promise<T>,
  onLateSuccess?: (value: T) => void | Promise<void>,
): Promise<T> {
  const boundedMs = Number.isFinite(timeoutMs) && timeoutMs > 0
    ? Math.max(1, Math.trunc(timeoutMs))
    : 1;
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) {
        return;
      }
      settled = true;
      reject(new DeviceRequestError(
        "timeout",
        `Timed out during local transport ${label}.`,
        true,
      ));
    }, boundedMs);
    Promise.resolve()
      .then(operation)
      .then(
        (value) => {
          if (settled) {
            if (onLateSuccess !== undefined) {
              Promise.resolve(onLateSuccess(value)).catch(noop);
            }
            return;
          }
          settled = true;
          clearTimeout(timer);
          resolve(value);
        },
        (error: unknown) => {
          if (settled) {
            return;
          }
          settled = true;
          clearTimeout(timer);
          reject(error);
        },
      );
  });
}

function localTransportErrorCode(error: unknown): string | null {
  return error instanceof DeviceRequestError ? error.code : null;
}

function isSigningMethod(method: string): method is "sign_transaction" | "sign_personal_message" {
  return method === "sign_transaction" || method === "sign_personal_message";
}

function isResponseForAnotherRequest(value: unknown, expectedId: string): boolean {
  return typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    typeof (value as { id?: unknown }).id === "string" &&
    (value as { id: string }).id !== expectedId;
}

function markLocalTransportRequestMayHaveReachedFirmware<T>(error: T): T {
  if ((typeof error === "object" && error !== null) || typeof error === "function") {
    try {
      Object.defineProperty(error, LOCAL_TRANSPORT_REQUEST_MAY_HAVE_REACHED_FIRMWARE, {
        value: true,
        configurable: true,
      });
    } catch {
      // Some Error-like objects may be non-extensible; leave them untagged.
    }
  }
  return error;
}

function localTransportRequestMayHaveReachedFirmware(error: unknown): boolean {
  return Boolean(
    error !== null &&
      (typeof error === "object" || typeof error === "function") &&
      (error as { [LOCAL_TRANSPORT_REQUEST_MAY_HAVE_REACHED_FIRMWARE]?: boolean })[
        LOCAL_TRANSPORT_REQUEST_MAY_HAVE_REACHED_FIRMWARE
      ],
  );
}

function mapLocalTransportProtocolError(error: unknown): DeviceRequestError {
  if (error instanceof DeviceRequestError) {
    return error;
  }
  if (error instanceof ProtocolError) {
    return new DeviceRequestError(error.code, error.message, error.code === "timeout");
  }
  return new DeviceRequestError(
    "transport_error",
    "Local transport failed before a valid device response.",
    true,
  );
}

function noop(): void {}
