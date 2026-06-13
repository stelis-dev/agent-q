import {
  assertAccountsResponse,
  assertCapabilitiesResponse,
  assertConnectResponse,
  assertDisconnectResponse,
  assertSignResultResponse,
  AGENT_Q_USB_PRODUCT_ID_NUMBER,
  AGENT_Q_USB_VENDOR_ID_NUMBER,
  consumeProtocolResponseChunk,
  DEFAULT_AGENT_Q_USB_BAUD_RATE,
  INTERNAL_CONNECT_DEADLINE_MS,
  INTERNAL_DISCONNECT_DEADLINE_MS,
  INTERNAL_SIGN_PERSONAL_MESSAGE_DEADLINE_MS,
  INTERNAL_SIGN_TRANSACTION_DEADLINE_MS,
  INTERNAL_USB_DEADLINE_MS,
  PAYLOAD_DELIVERY_DEADLINE_CHUNK_BYTES,
  makeConnectRequest,
  makeDisconnectRequest,
  makeGetAccountsRequest,
  makeGetCapabilitiesRequest,
  makeSignPersonalMessageRequest,
  makeSignTransactionRequest,
  ProtocolError,
  validateSignTransactionParams,
  type AccountsResponse,
  type CapabilitiesResponse,
  type ConnectResponse,
  type DisconnectResponse,
  type ProviderProtocolRequest,
  type ProviderProtocolResponse,
  type SignResultResponse,
  type SignTransactionParams,
  type SigningPayloadCapability,
} from "@stelis/agent-q-core/provider-protocol";
import {
  assertAckResultResponse,
  makeAckResultRequest,
  makeGetResultRequest,
  makePayloadUploadAbortRequest,
  makePayloadUploadBeginRequest,
  makePayloadUploadChunkRequest,
  makePayloadUploadFinishRequest,
  makeStagedSignTransactionRequest,
  payloadDeliveryCapabilityLimits,
  parseJsonLine,
  parseProtocolResponse,
  serializeRequest,
  SIGNABLE_PAYLOAD_KIND_TRANSACTION,
  type PayloadUploadAbortResultResponse,
  type PayloadUploadBeginResultResponse,
  type PayloadUploadChunkResultResponse,
  type PayloadUploadFinishResultResponse,
  type ProtocolRequest,
  type ProtocolResponse,
} from "@stelis/agent-q-core/protocol";
import type {
  AgentQSuiWalletGetAccountsResult,
  AgentQSuiWalletGetCapabilitiesResult,
  AgentQSuiWalletProvider,
  AgentQSuiWalletSignTransactionResult,
} from "./wallet-standard.js";

const DEFAULT_CLIENT_NAME = "Agent-Q Sui dapp";

// Web Serial cleanup (reader.cancel / port.close) can hang indefinitely when the
// device physically disconnects or resets mid-request. Cap each cleanup step so a
// hung transport can never wedge the request promise (which would otherwise leave
// the dapp waiting forever and the cached port unusable for reconnect).
const CLEANUP_STEP_TIMEOUT_MS = 1500;

type BrowserSerialPort = {
  open(options: { baudRate: number }): Promise<void>;
  close(): Promise<void>;
  readable: ReadableStream<Uint8Array> | null;
  writable: WritableStream<Uint8Array> | null;
};

type BrowserSerial = {
  requestPort(options?: { filters?: Array<{ usbVendorId?: number; usbProductId?: number }> }): Promise<BrowserSerialPort>;
};

export interface AgentQSuiBrowserProviderOptions {
  clientName?: string;
}

type BrowserSession = {
  deviceId: string;
  sessionId: string;
  sessionTtlMs: number;
  connectedAt: string;
  device: Extract<ConnectResponse, { status: "approved" }>["device"];
  epoch: number;
};

type BrowserSignRequest = Extract<
  ProtocolRequest,
  { type: "sign_transaction" | "sign_personal_message" }
>;
type BrowserWriteReachability = "not_started" | "started";
type BrowserPortLease = {
  canceled: boolean;
  abandoned: boolean;
  writeReachability: BrowserWriteReachability;
  stalePortLease?: BrowserStalePortLease;
};
type BrowserStalePortCleanup = {
  promise: Promise<void>;
  abandonedReason?: string;
  release(): void;
  abandon(reason: string): void;
};
type BrowserStalePortLease = {
  port: BrowserSerialPort;
  release(): void;
  abandon(reason: string): void;
};
type BrowserTransportTeardownReason =
  | "physical_disconnect"
  | "explicit_disconnect"
  | "dispose"
  | "session_ended"
  | "device_mismatch"
  | "transport_reset";
type BrowserTransportTeardownEvent = {
  generation: number;
  reason: BrowserTransportTeardownReason;
  deviceId?: string;
  sessionId?: string;
  sessionEpoch?: number;
};
type BrowserSessionSnapshot = {
  deviceId: string;
  sessionId: string;
  epoch: number;
  generation: number;
};
type BrowserBufferedRecoveryOutcome =
  | { status: "not_recovered" }
  | { status: "session_invalidated" }
  | { status: "recovered"; response: SignResultResponse; ack: "acked" | "failed" | "invalid_session" };
type BrowserSignRecoveryOutcome =
  | { status: "result"; response: SignResultResponse; sessionInvalidatedByAck: boolean }
  | { status: "session_invalidated" };
type BrowserPayloadAbortOutcome = "none" | "aborted" | "failed" | "invalid_session";

const PROVIDER_REQUEST_MAY_HAVE_REACHED_FIRMWARE = Symbol("agent-q.providerRequestMayHaveReachedFirmware");
const BROWSER_FIRMWARE_SESSION_INVALIDATED = Symbol("agent-q.browserFirmwareSessionInvalidated");
const RECOVERABLE_PROVIDER_SIGN_DELIVERY_CODES = new Set([
  "timeout",
  "transport_closed",
  "protocol_error",
  "invalid_json",
]);

export class AgentQSuiBrowserProviderError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "AgentQSuiBrowserProviderError";
    this.code = code;
  }
}

export class AgentQSuiBrowserProvider implements AgentQSuiWalletProvider {
  readonly #requestPort: () => Promise<BrowserSerialPort>;
  readonly #clientName: string;
  #port: BrowserSerialPort | null;
  #session: BrowserSession | null = null;
  #nextSessionEpoch = 1;
  #stalePortCleanups = new WeakMap<BrowserSerialPort, BrowserStalePortCleanup>();
  #transportTeardownEvent: BrowserTransportTeardownEvent | null = null;

  // Every Web Serial port operation runs through this single-slot queue so
  // concurrent callers never open the same port at once. Web Serial throws when
  // open() is called on an already-open port, so two in-flight requests would
  // otherwise collide; each request waits for the previous one to settle.
  #requestQueue: Promise<unknown> = Promise.resolve();
  // Bumped whenever the cached transport is torn down (physical disconnect or a
  // session-ended error). A request still queued when this changes rejects
  // instead of re-prompting the browser for a now-dead port.
  #transportGeneration = 0;

  #disconnectListener: ((event: { target?: unknown }) => void) | null = null;

  constructor(options: AgentQSuiBrowserProviderOptions = {}) {
    this.#port = null;
    this.#requestPort = defaultRequestPort();
    this.#clientName = options.clientName ?? DEFAULT_CLIENT_NAME;
    this.#registerDisconnectListener();
  }

  async connectDevice(input: {
    deviceId?: string;
    purpose?: string;
    clientName?: string;
  } = {}): Promise<unknown> {
    if (this.#session !== null && targetMatches(input.deviceId, this.#session.deviceId)) {
      const snapshot = this.#sessionSnapshot(this.#session);
      try {
        await this.#request(makeGetCapabilitiesRequest(this.#session.sessionId), assertCapabilitiesResponse);
        return this.#connectOutput(this.#session);
      } catch (error) {
        const ended = this.#clearIfSessionEnded(error, snapshot);
        if (ended === null) {
          throw error;
        }
      }
    }

    let response: ConnectResponse;
    try {
      response = await this.#exchange(
        makeConnectRequest(input.clientName ?? this.#clientName),
        assertConnectResponse,
        INTERNAL_CONNECT_DEADLINE_MS,
      );
    } catch (error) {
      if (isSessionEndedError(error)) {
        this.#clearSessionAndPort("session_ended");
      }
      throw error;
    }
    if (response.status === "rejected") {
      throw new AgentQSuiBrowserProviderError(response.error.code, response.error.message);
    }
    if (input.deviceId !== undefined && response.device.deviceId !== input.deviceId) {
      try {
        await this.#exchange(
          makeDisconnectRequest(response.sessionId),
          assertDisconnectResponse,
          INTERNAL_DISCONNECT_DEADLINE_MS,
        );
      } catch {
        // Best-effort cleanup for a session this provider will not retain.
      } finally {
        this.#clearSessionAndPort("device_mismatch");
      }
      throw new AgentQSuiBrowserProviderError("device_mismatch", "Connected Agent-Q device did not match the requested deviceId.");
    }
    this.#session = {
      deviceId: response.device.deviceId,
      sessionId: response.sessionId,
      sessionTtlMs: response.sessionTtlMs,
      connectedAt: new Date().toISOString(),
      device: response.device,
      epoch: this.#nextSessionEpoch++,
    };
    this.#transportTeardownEvent = null;
    return this.#connectOutput(this.#session);
  }

  async disconnectDevice(input: {
    deviceId?: string;
    purpose?: string;
  } = {}): Promise<unknown> {
    const session = this.#matchingSession(input.deviceId);
    if (session === null) {
      return this.#inactiveResult(input.deviceId);
    }
    try {
      await this.#request(makeDisconnectRequest(session.sessionId), assertDisconnectResponse);
    } catch (error) {
      if (isSessionEndedError(error)) {
        return { source: "session_ended", deviceId: session.deviceId, reason: errorCode(error) ?? "session_ended" };
      }
      throw error;
    } finally {
      // A user-requested disconnect is a full transport teardown: invalidate any
      // queued requests (generation bump) and release the port, not just the session.
      this.#clearSessionAndPort("explicit_disconnect");
    }
    return { source: "disconnected", deviceId: session.deviceId, reason: "firmware_confirmed" };
  }

  async getCapabilities(input: {
    deviceId?: string;
    purpose?: string;
  } = {}): Promise<AgentQSuiWalletGetCapabilitiesResult> {
    const session = this.#matchingSession(input.deviceId);
    if (session === null) {
      return this.#inactiveResult(input.deviceId);
    }
    const snapshot = this.#sessionSnapshot(session);
    try {
      const response = await this.#request(makeGetCapabilitiesRequest(session.sessionId), assertCapabilitiesResponse);
      return {
        source: "live",
        deviceId: session.deviceId,
        capabilities: response.chains,
        ...(response.signing === undefined ? {} : { signing: response.signing }),
      };
    } catch (error) {
      const ended = this.#clearIfSessionEnded(error, snapshot);
      if (ended !== null) {
        return ended;
      }
      throw error;
    }
  }

  async getAccounts(input: {
    deviceId?: string;
    purpose?: string;
  } = {}): Promise<AgentQSuiWalletGetAccountsResult> {
    const session = this.#matchingSession(input.deviceId);
    if (session === null) {
      return this.#inactiveResult(input.deviceId);
    }
    const snapshot = this.#sessionSnapshot(session);
    try {
      const response = await this.#request(makeGetAccountsRequest(session.sessionId), assertAccountsResponse);
      return { source: "live", deviceId: session.deviceId, accounts: response.accounts as AgentQSuiWalletGetAccountsResult["accounts"] };
    } catch (error) {
      const ended = this.#clearIfSessionEnded(error, snapshot);
      if (ended !== null) {
        return ended;
      }
      throw error;
    }
  }

  async signTransaction(input: {
    deviceId?: string;
    purpose?: string;
    chain: "sui";
    method: "sign_transaction";
    network: "mainnet" | "testnet" | "devnet" | "localnet";
    txBytes: string;
    // Optional stable request id for idempotent retries. Reuse it only for the
    // same signing request; while a retained result is buffered, a different
    // request using the same id fails with request_id_conflict.
    requestId?: string;
  }): Promise<AgentQSuiWalletSignTransactionResult> {
    const session = this.#matchingSession(input.deviceId);
    if (session === null) {
      return this.#inactiveResult(input.deviceId);
    }
    const snapshot = this.#sessionSnapshot(session);
    const params = validateSignTransactionParams({
      network: input.network,
      txBytes: input.txBytes,
    });
    try {
      const outcome = await this.#signTransactionWithDelivery(
        session,
        input.chain,
        input.method,
        params,
        input.requestId,
      );
      if (outcome.status === "session_invalidated") {
        this.#clearCurrentSessionIfSnapshotMatches(snapshot, "session_ended");
        return { source: "session_ended", deviceId: session.deviceId, reason: "invalid_session" };
      }
      const result = toLiveSignResult(session.deviceId, outcome.response);
      if (outcome.sessionInvalidatedByAck) {
        this.#clearCurrentSessionIfSnapshotMatches(snapshot, "session_ended");
      }
      return result;
    } catch (error) {
      this.#clearIfFirmwareInvalidatedSideEffect(error, snapshot);
      const ended = this.#clearIfFirmwareInvalidated(error, snapshot);
      if (ended !== null) {
        return ended;
      }
      throw error;
    }
  }

  async signPersonalMessage(input: {
    deviceId?: string;
    purpose?: string;
    chain: "sui";
    method: "sign_personal_message";
    network: "mainnet" | "testnet" | "devnet" | "localnet";
    message: string;
    // Optional stable request id for idempotent retries. Reuse it only for the
    // same signing request; while a retained result is buffered, a different
    // request using the same id fails with request_id_conflict.
    requestId?: string;
  }): Promise<AgentQSuiWalletSignTransactionResult> {
    const session = this.#matchingSession(input.deviceId);
    if (session === null) {
      return this.#inactiveResult(input.deviceId);
    }
    const snapshot = this.#sessionSnapshot(session);
    const signRequest = makeSignPersonalMessageRequest(session.sessionId, input.chain, input.method, {
      network: input.network,
      message: input.message,
    }, input.requestId);
    try {
      const outcome = await this.#signWithRecovery(signRequest, session);
      if (outcome.status === "session_invalidated") {
        this.#clearCurrentSessionIfSnapshotMatches(snapshot, "session_ended");
        return { source: "session_ended", deviceId: session.deviceId, reason: "invalid_session" };
      }
      const result = toLiveSignResult(session.deviceId, outcome.response);
      if (outcome.sessionInvalidatedByAck) {
        this.#clearCurrentSessionIfSnapshotMatches(snapshot, "session_ended");
      }
      return result;
    } catch (error) {
      this.#clearIfFirmwareInvalidatedSideEffect(error, snapshot);
      const ended = this.#clearIfFirmwareInvalidated(error, snapshot);
      if (ended !== null) {
        return ended;
      }
      throw error;
    }
  }

  async #getPort(absoluteDeadlineMs: number): Promise<BrowserSerialPort> {
    if (this.#port !== null) {
      await this.#waitForStalePortCleanup(this.#port, absoluteDeadlineMs);
      return this.#port;
    }
    const port = await this.#requestPort();
    await this.#waitForStalePortCleanup(port, absoluteDeadlineMs);
    this.#port = port;
    return port;
  }

  #clearPort(): void {
    const staleLease = this.#abandonPort();
    if (staleLease === null) {
      return;
    }
    if (staleLease.port.readable === null) {
      staleLease.release();
      return;
    }
    // Persistent port: close it on clear. Fire-and-forget so disconnect/dispose stay
    // synchronous; a dead port's close may never settle. The stale-port gate is
    // released only when cleanup actually settles before its cap.
    void settleCleanupStep(staleLease.port.close(), "port.close").then((completed) => {
      if (completed) {
        staleLease.release();
      } else {
        staleLease.abandon("port.close cleanup did not complete");
      }
    });
  }

  #abandonPort(): BrowserStalePortLease | null {
    const port = this.#port;
    this.#port = null;
    if (port === null) {
      return null;
    }
    let resolveCleanup!: () => void;
    const cleanup: BrowserStalePortCleanup = {
      promise: new Promise<void>((resolve) => {
        resolveCleanup = resolve;
      }),
      release: () => {
        if (this.#stalePortCleanups.get(port) === cleanup) {
          this.#stalePortCleanups.delete(port);
        }
        resolveCleanup();
      },
      abandon: (reason: string) => {
        cleanup.abandonedReason = reason;
        resolveCleanup();
      },
    };
    this.#stalePortCleanups.set(port, cleanup);
    return { port, release: cleanup.release, abandon: cleanup.abandon };
  }

  async #waitForStalePortCleanup(port: BrowserSerialPort, absoluteDeadlineMs: number): Promise<void> {
    const cleanup = this.#stalePortCleanups.get(port);
    if (cleanup === undefined) {
      return;
    }
    if (cleanup.abandonedReason !== undefined) {
      throw new AgentQSuiBrowserProviderError(
        "transport_closed",
        `The selected Web Serial port was abandoned after timed-out cleanup: ${cleanup.abandonedReason}.`,
      );
    }
    let timer: ReturnType<typeof setTimeout> | null = null;
    try {
      await Promise.race([
        cleanup.promise,
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => {
            reject(new AgentQSuiBrowserProviderError(
              "transport_closed",
              "The selected Web Serial port is still cleaning up from a timed-out request.",
            ));
          }, Math.max(0, absoluteDeadlineMs - Date.now()));
        }),
      ]);
    } finally {
      if (timer !== null) {
        clearTimeout(timer);
      }
    }
    if (cleanup.abandonedReason !== undefined) {
      throw new AgentQSuiBrowserProviderError(
        "transport_closed",
        `The selected Web Serial port was abandoned after timed-out cleanup: ${cleanup.abandonedReason}.`,
      );
    }
  }

  #clearSessionAndPort(reason: BrowserTransportTeardownReason = "transport_reset"): void {
    const session = this.#session;
    const generation = this.#transportGeneration;
    this.#transportGeneration += 1;
    this.#transportTeardownEvent = {
      generation,
      reason,
      deviceId: session?.deviceId,
      sessionId: session?.sessionId,
      sessionEpoch: session?.epoch,
    };
    this.#session = null;
    this.#clearPort();
  }

  // Observe physical Web Serial disconnects (cable removal or a Firmware reboot
  // that re-enumerates the device). Without this, a disconnect while idle leaves
  // a stale cached port, so the next reconnect reuses the dead port and never
  // re-prompts the browser port-selection menu.
  #registerDisconnectListener(): void {
    const serial = defaultSerial() as
      | (BrowserSerial & { addEventListener?: (type: string, listener: (event: { target?: unknown }) => void) => void })
      | null;
    if (serial === null || typeof serial.addEventListener !== "function") {
      return;
    }
    const listener = (event: { target?: unknown }): void => {
      if (this.#port !== null && event.target !== undefined && event.target !== this.#port) {
        return;
      }
      if (this.#port === null && this.#session === null) {
        return;
      }
      console.warn("[agent-q] Web Serial device disconnected; clearing cached port and session.");
      this.#clearSessionAndPort("physical_disconnect");
    };
    this.#disconnectListener = listener;
    serial.addEventListener("disconnect", listener);
  }

  dispose(): void {
    const serial = defaultSerial() as
      | (BrowserSerial & { removeEventListener?: (type: string, listener: (event: { target?: unknown }) => void) => void })
      | null;
    if (this.#disconnectListener !== null && serial !== null && typeof serial.removeEventListener === "function") {
      serial.removeEventListener("disconnect", this.#disconnectListener);
    }
    this.#disconnectListener = null;
    this.#clearSessionAndPort("dispose");
  }

  async #request<TResponse extends ProviderProtocolResponse>(
    request: ProviderProtocolRequest,
    assertResponse: (response: ProviderProtocolResponse) => TResponse,
  ): Promise<TResponse> {
    return this.#exchange(request, assertResponse, deadlineForProviderRequest(request));
  }

  #signTransactionWithDelivery(
    session: BrowserSession,
    chain: "sui",
    method: "sign_transaction",
    params: SignTransactionParams,
    requestId: string | undefined,
  ): Promise<BrowserSignRecoveryOutcome> {
    const generation = this.#transportGeneration;
    const absoluteDeadlineMs = Date.now() + deadlineForProviderSignTransactionDelivery(params.txBytes);
    const payloadBytes = decodeCanonicalBase64Payload(params.txBytes);
    return this.#enqueue(async () => {
      this.#assertTransportLive(generation);
      const port = await this.#getPort(absoluteDeadlineMs);
      this.#assertTransportLive(generation);
      const capabilities = await requestOverBrowserSerial(
        port,
        makeGetCapabilitiesRequest(session.sessionId),
        (response) => assertCapabilitiesResponse(response as ProviderProtocolResponse),
        remainingProviderDeadline(absoluteDeadlineMs, INTERNAL_USB_DEADLINE_MS),
        () => this.#abandonPort(),
      );
      const payloadCapability = findSignTransactionPayloadCapability(capabilities, chain, method);
      if (shouldUseInlineSignRequest(payloadBytes.length, payloadCapability)) {
        const request = makeInlineSignTransactionRequest(
          session.sessionId,
          chain,
          method,
          params,
          requestId,
          payloadCapability,
        );
        return this.#signWithRecoveryQueued(request, session, generation, absoluteDeadlineMs);
      }
      if (payloadCapability === null) {
        throw new AgentQSuiBrowserProviderError(
          "unsupported_payload_size",
          "Firmware does not advertise staged payload delivery for this signing method.",
        );
      }
      return this.#uploadAndSignTransaction(
        session,
        chain,
        method,
        params,
        requestId,
        payloadBytes,
        payloadCapability,
        generation,
        absoluteDeadlineMs,
      );
    });
  }

  async #uploadAndSignTransaction(
    session: BrowserSession,
    chain: "sui",
    method: "sign_transaction",
    params: SignTransactionParams,
    requestId: string | undefined,
    payloadBytes: Uint8Array,
    capability: SigningPayloadCapability,
    generation: number,
    absoluteDeadlineMs: number,
  ): Promise<BrowserSignRecoveryOutcome> {
    const limits = parsePayloadCapabilityLimits(capability);
    if (payloadBytes.length > limits.payloadMaxBytes) {
      throw new AgentQSuiBrowserProviderError(
        "unsupported_payload_size",
        "Transaction payload exceeds the device payload capability.",
      );
    }
    const payloadDigest = await sha256PayloadDigest(payloadBytes);
    let uploadId: string | null = null;
    let payloadRef: string | null = null;
    try {
      let port = await this.#getPort(absoluteDeadlineMs);
      this.#assertTransportLive(generation);
      const begin = await requestOverBrowserSerial(
        port,
        makePayloadUploadBeginRequest(session.sessionId, chain, method, {
          payloadKind: SIGNABLE_PAYLOAD_KIND_TRANSACTION,
          sizeBytes: String(payloadBytes.length),
          payloadDigest,
        }),
        assertPayloadUploadBeginResultResponse,
        remainingProviderDeadline(absoluteDeadlineMs, INTERNAL_USB_DEADLINE_MS),
        () => this.#abandonPort(),
      );
      uploadId = begin.uploadId;
      const beginChunkMaxBytes = Number(begin.chunkMaxBytes);
      const chunkMaxBytes = Math.min(limits.chunkMaxBytes, beginChunkMaxBytes);
      let offset = 0;
      while (offset < payloadBytes.length) {
        const nextOffset = Math.min(offset + chunkMaxBytes, payloadBytes.length);
        const chunk = encodeBase64(payloadBytes.subarray(offset, nextOffset));
        port = await this.#getPort(absoluteDeadlineMs);
        this.#assertTransportLive(generation);
        const response = await requestOverBrowserSerial(
          port,
          makePayloadUploadChunkRequest(session.sessionId, uploadId, String(offset), chunk),
          assertPayloadUploadChunkResultResponse,
          remainingProviderDeadline(absoluteDeadlineMs, INTERNAL_USB_DEADLINE_MS),
          () => this.#abandonPort(),
        );
        if (response.receivedBytes !== String(nextOffset)) {
          throw new AgentQSuiBrowserProviderError("protocol_error", "Firmware payload upload progress is inconsistent.");
        }
        offset = nextOffset;
      }
      port = await this.#getPort(absoluteDeadlineMs);
      this.#assertTransportLive(generation);
      const finish = await requestOverBrowserSerial(
        port,
        makePayloadUploadFinishRequest(session.sessionId, uploadId),
        assertPayloadUploadFinishResultResponse,
        remainingProviderDeadline(absoluteDeadlineMs, INTERNAL_USB_DEADLINE_MS),
        () => this.#abandonPort(),
      );
      payloadRef = finish.payloadRef;
      if (
        finish.chain !== chain ||
        finish.method !== method ||
        finish.payloadKind !== SIGNABLE_PAYLOAD_KIND_TRANSACTION ||
        finish.sizeBytes !== String(payloadBytes.length) ||
        finish.payloadDigest !== payloadDigest
      ) {
        throw new AgentQSuiBrowserProviderError("protocol_error", "Firmware payload descriptor does not match the uploaded payload.");
      }
      const request = makeStagedSignTransactionRequest(session.sessionId, chain, method, {
        network: params.network,
        payloadRef,
        payloadKind: finish.payloadKind,
        sizeBytes: finish.sizeBytes,
        payloadDigest: finish.payloadDigest,
      }, requestId);
      return await this.#signWithRecoveryQueued(request, session, generation, absoluteDeadlineMs);
    } catch (error) {
      const abort = await this.#abortPayloadDeliveryBestEffort(session.sessionId, { uploadId, payloadRef }, absoluteDeadlineMs);
      if (abort === "invalid_session") {
        markBrowserFirmwareSessionInvalidated(error);
      }
      throw error;
    }
  }

  #signWithRecovery(request: BrowserSignRequest, session: BrowserSession): Promise<BrowserSignRecoveryOutcome> {
    const generation = this.#transportGeneration;
    const absoluteDeadlineMs = Date.now() + deadlineForProviderSigningTransaction(request);
    return this.#enqueue(async () => this.#signWithRecoveryQueued(request, session, generation, absoluteDeadlineMs));
  }

  async #signWithRecoveryQueued(
    request: BrowserSignRequest,
    session: BrowserSession,
    generation: number,
    absoluteDeadlineMs: number,
  ): Promise<BrowserSignRecoveryOutcome> {
    this.#assertTransportLive(generation);
    const port = await this.#getPort(absoluteDeadlineMs);
    this.#assertTransportLive(generation);
    try {
      const response = await requestOverBrowserSerial(
        port,
        request,
        (response) => assertSignResultResponse(response as ProviderProtocolResponse),
        remainingProviderDeadline(absoluteDeadlineMs, deadlineForProviderRequest(request)),
        () => this.#abandonPort(),
      );
      this.#restoreCapturedSessionAfterPhysicalDisconnect(generation, session, port);
      return { status: "result", response, sessionInvalidatedByAck: false };
    } catch (error) {
      if (!shouldAttemptProviderSignResultRecovery(error)) {
        throw error;
      }
      if (!this.#canAttemptRecoveryAfterTeardown(generation, session)) {
        throw error;
      }
      try {
        const recoveryPort = await this.#getPort(absoluteDeadlineMs);
        const recovery = await this.#tryRecoverBufferedSignResult(
          recoveryPort,
          request.sessionId,
          request.id,
          absoluteDeadlineMs,
        );
        if (recovery.status === "session_invalidated") {
          return { status: "session_invalidated" };
        }
        if (recovery.status === "recovered") {
          if (recovery.ack !== "invalid_session") {
            this.#restoreCapturedSessionAfterPhysicalDisconnect(generation, session, recoveryPort);
          }
          return {
            status: "result",
            response: recovery.response,
            sessionInvalidatedByAck: recovery.ack === "invalid_session",
          };
        }
      } catch {
        // Recovery transport setup/read failures preserve the original signing
        // delivery error. Firmware invalid_session remains visible if it is the
        // original sign response error.
      }
      throw error;
    }
  }

  async #abortPayloadDeliveryBestEffort(
    sessionId: string,
    target: { uploadId: string | null; payloadRef: string | null },
    absoluteDeadlineMs: number,
  ): Promise<BrowserPayloadAbortOutcome> {
    if (target.uploadId === null && target.payloadRef === null) {
      return "none";
    }
    try {
      if (target.payloadRef !== null) {
        const port = await this.#getPort(absoluteDeadlineMs);
        await requestOverBrowserSerial(
          port,
          makePayloadUploadAbortRequest(sessionId, { payloadRef: target.payloadRef }),
          assertPayloadUploadAbortResultResponse,
          remainingProviderDeadline(absoluteDeadlineMs, INTERNAL_USB_DEADLINE_MS),
          () => this.#abandonPort(),
        );
      } else if (target.uploadId !== null) {
        const port = await this.#getPort(absoluteDeadlineMs);
        await requestOverBrowserSerial(
          port,
          makePayloadUploadAbortRequest(sessionId, { uploadId: target.uploadId }),
          assertPayloadUploadAbortResultResponse,
          remainingProviderDeadline(absoluteDeadlineMs, INTERNAL_USB_DEADLINE_MS),
          () => this.#abandonPort(),
        );
      }
      return "aborted";
    } catch (error) {
      if (errorCode(error) === "invalid_session") {
        return "invalid_session";
      }
      // Best-effort cleanup must not replace the upload/signing failure.
      return "failed";
    }
  }

  async #tryRecoverBufferedSignResult(
    port: BrowserSerialPort,
    sessionId: string,
    requestId: string,
    absoluteDeadlineMs: number,
  ): Promise<BrowserBufferedRecoveryOutcome> {
    let recovered: SignResultResponse;
    try {
      recovered = await requestOverBrowserSerial(
        port,
        makeGetResultRequest(sessionId, requestId),
        (response) => assertSignResultResponse(response as ProviderProtocolResponse),
        remainingProviderDeadline(absoluteDeadlineMs, INTERNAL_USB_DEADLINE_MS),
        () => this.#abandonPort(),
      );
    } catch (error) {
      if (errorCode(error) === "invalid_session") {
        return { status: "session_invalidated" };
      }
      return { status: "not_recovered" };
    }
    const ack = await this.#releaseRecoveredSignResult(port, sessionId, requestId, absoluteDeadlineMs);
    return { status: "recovered", response: recovered, ack };
  }

  async #releaseRecoveredSignResult(
    port: BrowserSerialPort,
    sessionId: string,
    requestId: string,
    absoluteDeadlineMs: number,
  ): Promise<"acked" | "failed" | "invalid_session"> {
    try {
      await requestOverBrowserSerial(
        port,
        makeAckResultRequest(sessionId, requestId),
        assertAckResultResponse,
        remainingProviderDeadline(absoluteDeadlineMs, INTERNAL_USB_DEADLINE_MS),
        () => this.#abandonPort(),
      );
      return "acked";
    } catch (error) {
      if (errorCode(error) === "invalid_session") {
        return "invalid_session";
      }
      // Best-effort cleanup: a failed ack must not turn a recovered sign_result
      // into a caller-visible failure, but it still runs inside the queued
      // signing transaction so later requests cannot overtake cleanup.
      return "failed";
    }
  }

  #canAttemptRecoveryAfterTeardown(generation: number, session: BrowserSession): boolean {
    return this.#transportGeneration === generation ||
      this.#teardownMatches(generation, session, "physical_disconnect");
  }

  #restoreCapturedSessionAfterPhysicalDisconnect(
    generation: number,
    session: BrowserSession,
    port: BrowserSerialPort,
  ): void {
    if (
      this.#transportGeneration === generation ||
      !this.#teardownMatches(generation, session, "physical_disconnect")
    ) {
      return;
    }
    this.#session = session;
    this.#port = port;
    this.#transportTeardownEvent = null;
  }

  #teardownMatches(
    generation: number,
    session: BrowserSession,
    reason: BrowserTransportTeardownReason,
  ): boolean {
    const event = this.#transportTeardownEvent;
    return event !== null &&
      event.generation === generation &&
      event.reason === reason &&
      event.deviceId === session.deviceId &&
      event.sessionId === session.sessionId &&
      event.sessionEpoch === session.epoch;
  }

  #assertTransportLive(generation: number): void {
    if (this.#transportGeneration !== generation) {
      throw new AgentQSuiBrowserProviderError(
        "transport_closed",
        "The device transport was torn down before this request could run.",
      );
    }
  }

  // Serialize one write -> read cycle against the persistent port. Concurrent
  // callers queue behind each other instead of racing on the same port. A teardown
  // observed while this request was queued or while #getPort() was re-prompting
  // rejects it here rather than running over a torn-down transport.
  #exchange<TResponse extends ProviderProtocolResponse>(
    request: ProviderProtocolRequest,
    assertResponse: (response: ProviderProtocolResponse) => TResponse,
    deadlineMs: number,
  ): Promise<TResponse> {
    const generation = this.#transportGeneration;
    const absoluteDeadlineMs = Date.now() + deadlineMs;
    return this.#enqueue(async () => {
      this.#assertTransportLive(generation);
      const port = await this.#getPort(absoluteDeadlineMs);
      // Re-check after the (possibly awaited) port acquisition: a disconnect observed
      // while #getPort() was re-prompting bumps the generation, so this request must
      // not run over or reopen a transport that was torn down in that window.
      this.#assertTransportLive(generation);
      return requestOverBrowserSerial(
        port,
        request,
        (response) => assertResponse(response as ProviderProtocolResponse),
        remainingProviderDeadline(absoluteDeadlineMs, deadlineMs),
        () => this.#abandonPort(),
      );
    });
  }

  #enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const run = this.#requestQueue.then(operation, operation);
    // Continue the chain past either outcome, and swallow the settled value so a
    // failed request never surfaces as an unhandled rejection on the queue tail.
    this.#requestQueue = run.then(noop, noop);
    return run;
  }

  #matchingSession(deviceId: string | undefined): BrowserSession | null {
    if (this.#session === null || !targetMatches(deviceId, this.#session.deviceId)) {
      return null;
    }
    return this.#session;
  }

  #sessionSnapshot(session: BrowserSession): BrowserSessionSnapshot {
    return {
      deviceId: session.deviceId,
      sessionId: session.sessionId,
      epoch: session.epoch,
      generation: this.#transportGeneration,
    };
  }

  #currentSessionMatches(snapshot: BrowserSessionSnapshot): boolean {
    return this.#session !== null &&
      this.#session.deviceId === snapshot.deviceId &&
      this.#session.sessionId === snapshot.sessionId &&
      this.#session.epoch === snapshot.epoch;
  }

  #clearCurrentSessionIfSnapshotMatches(
    snapshot: BrowserSessionSnapshot,
    reason: BrowserTransportTeardownReason,
  ): boolean {
    if (!this.#currentSessionMatches(snapshot)) {
      return false;
    }
    this.#clearSessionAndPort(reason);
    return true;
  }

  #inactiveResult(deviceId: string | undefined): { source: "not_connected" | "unavailable"; deviceId: string; reason: string } {
    if (!isAgentQSuiBrowserProviderAvailable()) {
      return { source: "unavailable", deviceId: deviceId ?? "browser", reason: "unsupported_transport" };
    }
    return { source: "not_connected", deviceId: deviceId ?? this.#session?.deviceId ?? "browser", reason: "not_connected" };
  }

  #clearIfSessionEnded(
    error: unknown,
    snapshot: BrowserSessionSnapshot,
  ): { source: "session_ended"; deviceId: string; reason: string } | null {
    if (!isSessionEndedError(error)) {
      return null;
    }
    const code = errorCode(error);
    if (code === "invalid_session") {
      this.#clearCurrentSessionIfSnapshotMatches(snapshot, "session_ended");
    } else if (this.#transportGeneration === snapshot.generation) {
      this.#clearCurrentSessionIfSnapshotMatches(snapshot, "session_ended");
    }
    return { source: "session_ended", deviceId: snapshot.deviceId, reason: code ?? "session_ended" };
  }

  #clearIfFirmwareInvalidated(
    error: unknown,
    snapshot: BrowserSessionSnapshot,
  ): { source: "session_ended"; deviceId: string; reason: string } | null {
    if (errorCode(error) !== "invalid_session") {
      return null;
    }
    this.#clearCurrentSessionIfSnapshotMatches(snapshot, "session_ended");
    return { source: "session_ended", deviceId: snapshot.deviceId, reason: "invalid_session" };
  }

  #clearIfFirmwareInvalidatedSideEffect(
    error: unknown,
    snapshot: BrowserSessionSnapshot,
  ): boolean {
    if (!consumeBrowserFirmwareSessionInvalidated(error)) {
      return false;
    }
    this.#clearCurrentSessionIfSnapshotMatches(snapshot, "session_ended");
    return true;
  }

  #connectOutput(session: BrowserSession): unknown {
    return {
      source: "connected",
      deviceId: session.deviceId,
      sessionTtlMs: session.sessionTtlMs,
      connectedAt: session.connectedAt,
      device: session.device,
    };
  }
}

export function isAgentQSuiBrowserProviderAvailable(): boolean {
  return defaultSerial() !== null;
}

export function createAgentQSuiBrowserProvider(options: AgentQSuiBrowserProviderOptions = {}): AgentQSuiBrowserProvider {
  return new AgentQSuiBrowserProvider(options);
}

function defaultSerial(): BrowserSerial | null {
  return (globalThis as { navigator?: { serial?: BrowserSerial } }).navigator?.serial ?? null;
}

function defaultRequestPort(): () => Promise<BrowserSerialPort> {
  return async () => {
    const serial = defaultSerial();
    if (serial === null) {
      throw new AgentQSuiBrowserProviderError("unsupported_transport", "Web Serial is not available in this browser.");
    }
    return serial.requestPort({
      filters: [{ usbVendorId: AGENT_Q_USB_VENDOR_ID_NUMBER, usbProductId: AGENT_Q_USB_PRODUCT_ID_NUMBER }],
    });
  };
}

function noop(): void {}

function deadlineForProviderSigningTransaction(request: BrowserSignRequest): number {
  return deadlineForProviderRequest(request) + INTERNAL_USB_DEADLINE_MS * 2;
}

function deadlineForProviderSignTransactionDelivery(txBytes: string): number {
  const decodedBytes = estimateBase64DecodedBytes(txBytes);
  const chunkCount = Math.ceil(decodedBytes / PAYLOAD_DELIVERY_DEADLINE_CHUNK_BYTES);
  return INTERNAL_SIGN_TRANSACTION_DEADLINE_MS + INTERNAL_USB_DEADLINE_MS * (chunkCount + 5);
}

function remainingProviderDeadline(absoluteDeadlineMs: number, phaseDeadlineMs: number): number {
  const remainingMs = absoluteDeadlineMs - Date.now();
  if (remainingMs <= 0) {
    throw markProviderRequestDidNotReachFirmware(
      new AgentQSuiBrowserProviderError("timeout", "The device request expired before it reached Firmware."),
    );
  }
  return Math.min(phaseDeadlineMs, remainingMs);
}

function markProviderRequestDidNotReachFirmware<T>(error: T): T {
  return tagProviderRequestReachability(error, false);
}

function markProviderRequestMayHaveReachedFirmware<T>(error: T): T {
  return tagProviderRequestReachability(error, true);
}

function markBrowserFirmwareSessionInvalidated<T>(value: T): T {
  if ((typeof value === "object" && value !== null) || typeof value === "function") {
    try {
      Object.defineProperty(value, BROWSER_FIRMWARE_SESSION_INVALIDATED, {
        value: true,
        configurable: true,
      });
    } catch {
      // Some browser errors may be non-extensible; leave them untagged.
    }
  }
  return value;
}

function consumeBrowserFirmwareSessionInvalidated(value: unknown): boolean {
  if (
    value === null ||
    (typeof value !== "object" && typeof value !== "function") ||
    (value as { [BROWSER_FIRMWARE_SESSION_INVALIDATED]?: boolean })[
      BROWSER_FIRMWARE_SESSION_INVALIDATED
    ] !== true
  ) {
    return false;
  }
  try {
    delete (value as { [BROWSER_FIRMWARE_SESSION_INVALIDATED]?: boolean })[
      BROWSER_FIRMWARE_SESSION_INVALIDATED
    ];
  } catch {
    // Metadata is non-public and non-enumerable; failure to delete is harmless.
  }
  return true;
}

function tagProviderRequestReachability<T>(error: T, mayHaveReachedFirmware: boolean): T {
  if ((typeof error === "object" && error !== null) || typeof error === "function") {
    try {
      Object.defineProperty(error, PROVIDER_REQUEST_MAY_HAVE_REACHED_FIRMWARE, {
        value: mayHaveReachedFirmware,
        configurable: true,
      });
    } catch {
      // Some browser errors may be non-extensible; leave them untagged.
    }
  }
  return error;
}

function providerRequestMayHaveReachedFirmware(error: unknown): boolean {
  return Boolean(
    error !== null &&
      (typeof error === "object" || typeof error === "function") &&
      (error as { [PROVIDER_REQUEST_MAY_HAVE_REACHED_FIRMWARE]?: boolean })[
        PROVIDER_REQUEST_MAY_HAVE_REACHED_FIRMWARE
      ],
  );
}

function shouldAttemptProviderSignResultRecovery(error: unknown): boolean {
  if (!providerRequestMayHaveReachedFirmware(error)) {
    return false;
  }
  const code = errorCode(error);
  return code !== null && RECOVERABLE_PROVIDER_SIGN_DELIVERY_CODES.has(code);
}

function findSignTransactionPayloadCapability(
  capabilities: CapabilitiesResponse,
  chain: "sui",
  method: "sign_transaction",
): SigningPayloadCapability | null {
  const entry = capabilities.signing?.methods.find((candidate) =>
    candidate.chain === chain && candidate.method === method
  );
  return entry?.payload ?? null;
}

function makeInlineSignTransactionRequest(
  sessionId: string,
  chain: "sui",
  method: "sign_transaction",
  params: SignTransactionParams,
  requestId: string | undefined,
  capability: SigningPayloadCapability | null,
): BrowserSignRequest {
  try {
    return makeSignTransactionRequest(sessionId, chain, method, params, requestId);
  } catch (error) {
    if (
      capability === null &&
      error instanceof ProtocolError &&
      error.code === "invalid_params" &&
      error.message.includes("too large")
    ) {
      throw new AgentQSuiBrowserProviderError(
        "unsupported_payload_size",
        "Firmware does not advertise staged payload delivery for this signing method.",
      );
    }
    throw error;
  }
}

function shouldUseInlineSignRequest(
  payloadSize: number,
  capability: SigningPayloadCapability | null,
): boolean {
  if (capability === null) {
    return true;
  }
  return payloadSize <= parsePayloadCapabilityLimits(capability).inlineMaxBytes;
}

function parsePayloadCapabilityLimits(capability: SigningPayloadCapability): ReturnType<typeof payloadDeliveryCapabilityLimits> {
  try {
    return payloadDeliveryCapabilityLimits(capability);
  } catch (error) {
    if (error instanceof ProtocolError) {
      throw new AgentQSuiBrowserProviderError("protocol_error", error.message);
    }
    throw error;
  }
}

function decodeCanonicalBase64Payload(value: string): Uint8Array {
  const binary = globalThis.atob(value);
  const output = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; ++index) {
    output[index] = binary.charCodeAt(index);
  }
  return output;
}

function encodeBase64(value: Uint8Array): string {
  let binary = "";
  for (let index = 0; index < value.length; ++index) {
    binary += String.fromCharCode(value[index] ?? 0);
  }
  return globalThis.btoa(binary);
}

async function sha256PayloadDigest(value: Uint8Array): Promise<string> {
  const copy = new Uint8Array(value.length);
  copy.set(value);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", copy.buffer);
  return `sha256:${hexBytes(new Uint8Array(digest))}`;
}

function hexBytes(value: Uint8Array): string {
  let output = "";
  for (const byte of value) {
    output += byte.toString(16).padStart(2, "0");
  }
  return output;
}

function estimateBase64DecodedBytes(value: string): number {
  if (value.length === 0) {
    return 0;
  }
  let padding = 0;
  if (value.endsWith("==")) {
    padding = 2;
  } else if (value.endsWith("=")) {
    padding = 1;
  }
  return Math.max(0, Math.floor(value.length / 4) * 3 - padding);
}

function assertPayloadUploadBeginResultResponse(
  response: ProtocolResponse,
): PayloadUploadBeginResultResponse {
  return assertPayloadUploadResponseType(response, "payload_upload_begin_result");
}

function assertPayloadUploadChunkResultResponse(
  response: ProtocolResponse,
): PayloadUploadChunkResultResponse {
  return assertPayloadUploadResponseType(response, "payload_upload_chunk_result");
}

function assertPayloadUploadFinishResultResponse(
  response: ProtocolResponse,
): PayloadUploadFinishResultResponse {
  return assertPayloadUploadResponseType(response, "payload_upload_finish_result");
}

function assertPayloadUploadAbortResultResponse(
  response: ProtocolResponse,
): PayloadUploadAbortResultResponse {
  return assertPayloadUploadResponseType(response, "payload_upload_abort_result");
}

function assertPayloadUploadResponseType<TType extends ProtocolResponse["type"]>(
  response: ProtocolResponse,
  type: TType,
): Extract<ProtocolResponse, { type: TType }> {
  if (response.type === "error") {
    throw new AgentQSuiBrowserProviderError(response.error.code, response.error.message);
  }
  if (response.type !== type) {
    throw new AgentQSuiBrowserProviderError("protocol_error", `Protocol response type is not ${type}.`);
  }
  return response as Extract<ProtocolResponse, { type: TType }>;
}

// Await a best-effort transport-cleanup step, but never block longer than
// CLEANUP_STEP_TIMEOUT_MS. A hung reader.cancel()/port.close() on a disconnected
// device is abandoned (its rejection is swallowed) so the request still settles.
async function settleCleanupStep(operation: Promise<unknown> | undefined, label: string): Promise<boolean> {
  if (operation === undefined) {
    return true;
  }
  let timer: ReturnType<typeof setTimeout> | null = null;
  const guarded = operation.then(() => true, () => false);
  const timeout = new Promise<false>((resolve) => {
    timer = setTimeout(() => {
      console.warn(
        `[agent-q] Web Serial cleanup '${label}' did not complete within ${CLEANUP_STEP_TIMEOUT_MS}ms; abandoning it.`,
      );
      resolve(false);
    }, CLEANUP_STEP_TIMEOUT_MS);
  });
  try {
    return await Promise.race([guarded, timeout]);
  } finally {
    if (timer !== null) {
      clearTimeout(timer);
    }
  }
}

function remainingBrowserLeaseMs(
  lease: BrowserPortLease,
  absoluteDeadlineMs: number,
  message: string,
): number {
  if (lease.canceled) {
    throw markProviderRequestDidNotReachFirmware(new AgentQSuiBrowserProviderError("timeout", message));
  }
  const remainingMs = absoluteDeadlineMs - Date.now();
  if (remainingMs <= 0) {
    lease.canceled = true;
    throw tagProviderRequestReachability(
      new AgentQSuiBrowserProviderError("timeout", message),
      lease.writeReachability === "started",
    );
  }
  return remainingMs;
}

async function openBrowserPortWithinLease(
  port: BrowserSerialPort,
  lease: BrowserPortLease,
  absoluteDeadlineMs: number,
  abandonPort: () => BrowserStalePortLease | null,
): Promise<void> {
  const remainingOpenMs = remainingBrowserLeaseMs(
    lease,
    absoluteDeadlineMs,
    "The device request expired while opening the Web Serial port.",
  );
  const open = port.open({ baudRate: DEFAULT_AGENT_Q_USB_BAUD_RATE });
  let timer: ReturnType<typeof setTimeout> | null = null;
  open.then(() => {
    if (lease.canceled) {
      void settleCleanupStep(port.close(), "late port.open close-only cleanup").then((completed) => {
        if (completed) {
          lease.stalePortLease?.release();
        } else {
          lease.stalePortLease?.abandon("late port.open cleanup did not complete");
        }
      });
    }
  }, () => {
    if (lease.canceled) {
      lease.stalePortLease?.release();
    }
  });
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      lease.canceled = true;
      lease.abandoned = true;
      lease.stalePortLease = abandonPort() ?? undefined;
      reject(markProviderRequestDidNotReachFirmware(
        new AgentQSuiBrowserProviderError("timeout", "The device request expired while opening the Web Serial port."),
      ));
    }, remainingOpenMs);
  });
  try {
    await Promise.race([open, timeout]);
  } catch (error) {
    throw markProviderRequestDidNotReachFirmware(error);
  } finally {
    if (timer !== null) {
      clearTimeout(timer);
    }
  }
}

async function writeBrowserRequestWithinLease(
  writer: WritableStreamDefaultWriter<Uint8Array>,
  request: ProtocolRequest,
  lease: BrowserPortLease,
  absoluteDeadlineMs: number,
  abandonPort: () => BrowserStalePortLease | null,
): Promise<void> {
  remainingBrowserLeaseMs(
    lease,
    absoluteDeadlineMs,
    "The device request expired before it reached Firmware.",
  );
  lease.writeReachability = "started";
  const write = writer.write(new TextEncoder().encode(serializeRequest(request)));
  let timer: ReturnType<typeof setTimeout> | null = null;
  write.catch(() => undefined);
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      lease.canceled = true;
      lease.abandoned = true;
      lease.stalePortLease = abandonPort() ?? undefined;
      reject(markProviderRequestMayHaveReachedFirmware(
        new AgentQSuiBrowserProviderError("timeout", "Timed out writing to Firmware."),
      ));
    }, Math.max(0, absoluteDeadlineMs - Date.now()));
  });
  try {
    await Promise.race([write, timeout]);
  } catch (error) {
    throw markProviderRequestMayHaveReachedFirmware(error);
  } finally {
    if (timer !== null) {
      clearTimeout(timer);
    }
  }
}

async function requestOverBrowserSerial<TResponse>(
  port: BrowserSerialPort,
  request: ProtocolRequest,
  assertResponse: (response: ProtocolResponse) => TResponse,
  deadlineMs: number,
  abandonPort: () => BrowserStalePortLease | null,
): Promise<TResponse> {
  const absoluteDeadlineMs = Date.now() + Math.max(0, deadlineMs);
  const lease: BrowserPortLease = {
    canceled: false,
    abandoned: false,
    writeReachability: "not_started",
  };
  // Persistent port: open once and reuse it across serialized requests (the request
  // queue guarantees one at a time). open() is idempotent here — a port a prior request
  // left open is reused; only a prior error or a disconnect leaves it closed.
  if (port.readable === null || port.writable === null) {
    await openBrowserPortWithinLease(port, lease, absoluteDeadlineMs, abandonPort);
  }
  let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  let writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  let timeout: ReturnType<typeof setTimeout> | null = null;
  let succeeded = false;
  try {
    if (port.readable === null || port.writable === null) {
      throw markProviderRequestDidNotReachFirmware(
        new AgentQSuiBrowserProviderError("transport_closed", "Web Serial port is not readable or writable."),
      );
    }
    reader = port.readable.getReader();
    writer = port.writable.getWriter();
    await writeBrowserRequestWithinLease(writer, request, lease, absoluteDeadlineMs, abandonPort);
    writer.releaseLock();
    writer = null;

    const response = readMatchingResponse(reader, request.id, assertResponse);
    // If the deadline wins the race below, the read is cancelled in `finally` and
    // this promise rejects after it has already lost. Attach a no-op catch so that
    // late rejection is not reported as an unhandled promise rejection.
    void response.catch(() => undefined);
    const deadline = new Promise<never>((_, reject) => {
      timeout = setTimeout(() => {
        lease.canceled = true;
        lease.abandoned = true;
        lease.stalePortLease = abandonPort() ?? undefined;
        console.warn(`[agent-q] No Firmware response for '${request.type}' within ${deadlineMs}ms; treating link as lost.`);
        reject(markProviderRequestMayHaveReachedFirmware(
          new AgentQSuiBrowserProviderError("timeout", "Timed out waiting for Firmware response."),
        ));
      }, Math.max(0, absoluteDeadlineMs - Date.now()));
    });
    const result = await Promise.race([response, deadline]);
    succeeded = true;
    return result;
  } catch (error) {
    throw tagProviderRequestReachability(error, lease.writeReachability === "started");
  } finally {
    if (timeout !== null) {
      clearTimeout(timeout);
    }
    if (writer !== null) {
      try {
        writer.releaseLock();
      } catch {
        // Writer may already be released.
      }
    }
    if (reader !== null) {
      if (!succeeded) {
        // Error or timeout: the read may still be pending; cancel it before releasing.
        await settleCleanupStep(reader.cancel(), "reader.cancel");
      }
      try {
        reader.releaseLock();
      } catch {
        // Reader may still be settling after a timed-out cancel.
      }
    }
    if (!succeeded) {
      // Close on failure so the next request reopens a clean transport; a successful
      // request leaves the port open for reuse.
      lease.stalePortLease ??= abandonPort() ?? undefined;
      const completed = await settleCleanupStep(port.close(), "port.close");
      if (completed) {
        lease.stalePortLease?.release();
      } else {
        lease.stalePortLease?.abandon("port.close cleanup did not complete");
      }
    }
  }
}

async function readMatchingResponse<TResponse>(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  expectedId: string,
  assertResponse: (response: ProtocolResponse) => TResponse,
): Promise<TResponse> {
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) {
      throw new AgentQSuiBrowserProviderError("transport_closed", "The device connection was closed.");
    }
    let lines: string[];
    try {
      const consumed = consumeProtocolResponseChunk(buffer, decoder.decode(value, { stream: true }));
      buffer = consumed.buffer;
      lines = consumed.lines;
    } catch (error) {
      if (error instanceof ProtocolError) {
        throw new AgentQSuiBrowserProviderError(error.code, error.message);
      }
      throw error;
    }
    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (line.length === 0 || !line.startsWith("{")) {
        continue;
      }
      const parsed = tryParseMatchingResponseLine(line, expectedId, assertResponse);
      if (parsed !== undefined) {
        return parsed;
      }
    }
  }
}

function deadlineForProviderRequest(request: Pick<ProtocolRequest, "type">): number {
  switch (request.type) {
    case "connect":
      return INTERNAL_CONNECT_DEADLINE_MS;
    case "disconnect":
      return INTERNAL_DISCONNECT_DEADLINE_MS;
    case "sign_transaction":
      return INTERNAL_SIGN_TRANSACTION_DEADLINE_MS;
    case "sign_personal_message":
      return INTERNAL_SIGN_PERSONAL_MESSAGE_DEADLINE_MS;
    case "get_capabilities":
    case "get_accounts":
      return INTERNAL_USB_DEADLINE_MS;
  }
  throw new AgentQSuiBrowserProviderError("internal_error", "Provider request deadline is not defined.");
}

function tryParseMatchingResponseLine<TResponse>(
  line: string,
  expectedId: string,
  assertResponse: (response: ProtocolResponse) => TResponse,
): TResponse | undefined {
  let parsed: unknown;
  try {
    parsed = parseJsonLine(line);
  } catch {
    return undefined;
  }
  if (!isRecord(parsed)) {
    return undefined;
  }
  if (parsed.id !== expectedId) {
    if (parsed.id === undefined && parsed.type === "error") {
      const response = parseProtocolResponse(line);
      if (response.type === "error") {
        throw new AgentQSuiBrowserProviderError(response.error.code, response.error.message);
      }
    }
    return undefined;
  }
  try {
    return assertResponse(parseProtocolResponse(line, expectedId));
  } catch (error) {
    if (error instanceof ProtocolError) {
      throw new AgentQSuiBrowserProviderError(error.code, error.message);
    }
    throw error;
  }
}

function targetMatches(requestedDeviceId: string | undefined, sessionDeviceId: string): boolean {
  return requestedDeviceId === undefined || requestedDeviceId === sessionDeviceId;
}

function isSessionEndedError(error: unknown): boolean {
  const code = errorCode(error);
  return code === "invalid_session" || code === "transport_closed" || code === "timeout";
}

function errorCode(error: unknown): string | null {
  if (error instanceof ProtocolError || error instanceof AgentQSuiBrowserProviderError) {
    return error.code;
  }
  return null;
}

function toLiveSignResult(deviceId: string, response: SignResultResponse): AgentQSuiWalletSignTransactionResult {
  if (response.status === "signed") {
    return {
      source: "live",
      deviceId,
      status: "signed",
      authorization: response.authorization,
      chain: response.chain,
      method: response.method,
      signature: response.signature,
      ...(response.method === "sign_personal_message" ? { messageBytes: response.messageBytes } : {}),
    };
  }
  if (response.status === "policy_rejected") {
    return {
      source: "live",
      deviceId,
      status: "policy_rejected",
      authorization: "policy",
      error: response.error,
    };
  }
  return {
    source: "live",
    deviceId,
    status: response.status,
    authorization: response.authorization,
    error: response.error,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
