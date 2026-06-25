import {
  AGENT_Q_USB_PRODUCT_ID_NUMBER,
  AGENT_Q_USB_VENDOR_ID_NUMBER,
  consumeDeviceResponseLineChunk,
  DEFAULT_AGENT_Q_USB_BAUD_RATE,
  INTERNAL_CONNECT_DEADLINE_MS,
  INTERNAL_DISCONNECT_DEADLINE_MS,
  INTERNAL_SIGN_PERSONAL_MESSAGE_DEADLINE_MS,
  INTERNAL_SIGN_TRANSACTION_DEADLINE_MS,
  INTERNAL_USB_DEADLINE_MS,
  PAYLOAD_DELIVERY_DEADLINE_CHUNK_BYTES,
  ProtocolError,
  createRequestId,
  validateSignTransactionParams,
  type ConnectResult,
  type SigningOutcome,
  type SignTransactionParams,
} from "@stelis/agent-q-core/provider-protocol";
import {
  assertAccountsResult,
  assertCapabilitiesResult,
  assertConnectResult,
  assertDisconnectResult,
  assertCredentialPreparationResponse,
  assertCredentialProposalOutcomeResponse,
  assertSigningOutcome,
  isClientName,
  parseJsonLine,
  parseDeviceResponse,
  validateCredentialPrepareInput,
  validateCredentialProposeInput,
  type DeviceResponse,
} from "@stelis/agent-q-core/protocol";
import {
  requestDevice,
  type DeviceRequestInput,
} from "@stelis/agent-q-core/device-request-internal";
import type {
  AgentQSuiWalletGetAccountsResult,
  AgentQSuiWalletGetCapabilitiesResult,
  AgentQSuiWalletProvider,
  AgentQSuiWalletSignTransactionResult,
} from "./wallet-standard.js";
import type {
  CredentialPrepareInput,
  CredentialPreparation,
  CredentialProposeInput,
  CredentialProposalOutcome,
} from "./provider-sui.js";

const DEFAULT_CLIENT_NAME = "Agent-Q Sui dapp";

// Web Serial cleanup (reader.cancel / port.close) can hang indefinitely when the
// device physically disconnects or resets mid-request. Cap each cleanup step so a
// hung transport can never wedge the request promise (which would otherwise leave
// the dapp waiting forever and the cached port unusable for reconnect).
const CLEANUP_STEP_TIMEOUT_MS = 1500;

type BrowserSerialPort = {
  open(options: { baudRate: number }): Promise<void>;
  close(): Promise<void>;
  getInfo?(): { usbVendorId?: number; usbProductId?: number };
  readable: ReadableStream<Uint8Array> | null;
  writable: WritableStream<Uint8Array> | null;
};

type BrowserSerial = {
  getPorts?(): Promise<BrowserSerialPort[]>;
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
  device: ConnectResult["device"];
  epoch: number;
};

type BrowserSignRequest = DeviceRequestInput & {
  readonly id: string;
  readonly sessionId: string;
  readonly method: "sign_transaction" | "sign_personal_message";
};
type BrowserDeviceRequest = DeviceRequestInput;
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
  | { status: "recovered"; response: SigningOutcome; ack: "acked" | "failed" | "invalid_session" }
  | { status: "recovered_error"; error: AgentQSuiBrowserProviderError; ack: "acked" | "failed" | "invalid_session" };
type BrowserSignRecoveryOutcome =
  | { status: "result"; response: SigningOutcome; sessionInvalidatedByAck: boolean }
  | { status: "session_invalidated" };

const PROVIDER_REQUEST_MAY_HAVE_REACHED_FIRMWARE = Symbol("agent-q.providerRequestMayHaveReachedFirmware");
const BROWSER_FIRMWARE_SESSION_INVALIDATED = Symbol("agent-q.browserFirmwareSessionInvalidated");
const RECOVERABLE_PROVIDER_SIGN_DELIVERY_CODES = new Set([
  "timeout",
  "transport_closed",
  "invalid_response",
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
        await this.#request(
          { method: "get_capabilities", sessionId: this.#session.sessionId },
          assertCapabilitiesResult,
        );
        return this.#connectOutput(this.#session);
      } catch (error) {
        const ended = this.#clearIfSessionEnded(error, snapshot);
        if (ended === null) {
          throw error;
        }
      }
    }

    let response: ConnectResult;
    try {
      response = await this.#request(
        connectDeviceRequestInput(input.clientName ?? this.#clientName),
        assertConnectResult,
      );
    } catch (error) {
      if (isSessionEndedError(error)) {
        this.#clearSessionAndPort("session_ended");
      }
      throw error;
    }
    if (input.deviceId !== undefined && response.device.deviceId !== input.deviceId) {
      try {
        await this.#request(
          { method: "disconnect", sessionId: response.sessionId },
          assertDisconnectResult,
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
      await this.#request(
        { method: "disconnect", sessionId: session.sessionId },
        assertDisconnectResult,
      );
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
      const response = await this.#request(
        { method: "get_capabilities", sessionId: session.sessionId },
        assertCapabilitiesResult,
      );
      return {
        source: "live",
        deviceId: session.deviceId,
        capabilities: response.chains,
        ...(response.signing === undefined ? {} : { signing: response.signing }),
        ...(response.credentials === undefined ? {} : { credentials: response.credentials }),
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
      const response = await this.#request(
        { method: "get_accounts", sessionId: session.sessionId },
        assertAccountsResult,
      );
      return { source: "live", deviceId: session.deviceId, accounts: response.accounts as AgentQSuiWalletGetAccountsResult["accounts"] };
    } catch (error) {
      const ended = this.#clearIfSessionEnded(error, snapshot);
      if (ended !== null) {
        return ended;
      }
      throw error;
    }
  }

  async credentialPrepare(input: CredentialPrepareInput): Promise<CredentialPreparation> {
    const session = this.#matchingSession(input.deviceId);
    if (session === null) {
      return this.#inactiveCredentialResult(input.deviceId);
    }
    const snapshot = this.#sessionSnapshot(session);
    const payload = validateCredentialPrepareInput({
      chain: input.chain,
      credential: input.credential,
    });
    const request: BrowserDeviceRequest = {
      method: "credential_prepare",
      sessionId: session.sessionId,
      payload,
    };
    try {
      const response = await this.#request(
        request,
        assertCredentialPreparationResponse,
      );
      return {
        source: "live",
        deviceId: session.deviceId,
        chain: response.chain,
        credential: response.credential,
        preparation: response.preparation,
      };
    } catch (error) {
      const ended = this.#clearIfSessionEnded(error, snapshot);
      if (ended !== null) {
        return toCredentialSessionEndedResult(ended);
      }
      throw error;
    }
  }

  async credentialPropose(input: CredentialProposeInput): Promise<CredentialProposalOutcome> {
    const session = this.#matchingSession(input.deviceId);
    if (session === null) {
      return this.#inactiveCredentialResult(input.deviceId);
    }
    const snapshot = this.#sessionSnapshot(session);
    const payload = validateCredentialProposeInput({
      chain: input.chain,
      credential: input.credential,
      network: input.network,
      address: input.address,
      publicKey: input.publicKey,
      maxEpoch: input.maxEpoch,
      inputs: input.inputs,
    });
    const request: BrowserDeviceRequest = {
      method: "credential_propose",
      sessionId: session.sessionId,
      payload,
    };
    try {
      const response = await this.#request(
        request,
        assertCredentialProposalOutcomeResponse,
      );
      const result: CredentialProposalOutcome = {
        source: "live",
        deviceId: session.deviceId,
        status: response.status,
        reasonCode: response.reasonCode,
        sessionEnded: response.sessionEnded,
      };
      if (response.sessionEnded) {
        this.#clearCurrentSessionIfSnapshotMatches(snapshot, "session_ended");
      }
      return result;
    } catch (error) {
      const ended = this.#clearIfSessionEnded(error, snapshot);
      if (ended !== null) {
        return toCredentialSessionEndedResult(ended);
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
    // same signing request; while a retained response is buffered, a different
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
      const result = toLiveSigningOutcome(session.deviceId, outcome.response);
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
    // same signing request; while a retained response is buffered, a different
    // request using the same id fails with request_id_conflict.
    requestId?: string;
  }): Promise<AgentQSuiWalletSignTransactionResult> {
    const session = this.#matchingSession(input.deviceId);
    if (session === null) {
      return this.#inactiveResult(input.deviceId);
    }
    const snapshot = this.#sessionSnapshot(session);
    const signRequest: BrowserSignRequest = {
      id: input.requestId ?? createRequestId(),
      method: input.method,
      sessionId: session.sessionId,
      payload: {
        chain: input.chain,
        network: input.network,
        message: input.message,
      },
    };
    try {
      const outcome = await this.#signWithRecovery(signRequest, session);
      if (outcome.status === "session_invalidated") {
        this.#clearCurrentSessionIfSnapshotMatches(snapshot, "session_ended");
        return { source: "session_ended", deviceId: session.deviceId, reason: "invalid_session" };
      }
      const result = toLiveSigningOutcome(session.deviceId, outcome.response);
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

  async #request<TResponse>(
    request: BrowserDeviceRequest,
    assertResponse: (response: DeviceResponse) => TResponse,
  ): Promise<TResponse> {
    const generation = this.#transportGeneration;
    const phaseDeadlineMs = deadlineForProviderRequest(request);
    const absoluteDeadlineMs = Date.now() + phaseDeadlineMs;
    return this.#enqueue(async () => {
      this.#assertTransportLive(generation);
      return this.#requestDeviceQueued(request, assertResponse, generation, absoluteDeadlineMs, phaseDeadlineMs);
    });
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
    return this.#enqueue(async () => {
      this.#assertTransportLive(generation);
      const request: BrowserSignRequest = {
        id: requestId ?? createRequestId(),
        method,
        sessionId: session.sessionId,
        payload: {
          chain,
          network: params.network,
          txBytes: params.txBytes,
        },
      };
      return this.#signWithRecoveryQueued(request, session, generation, absoluteDeadlineMs);
    });
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
    try {
      const response = await this.#requestDeviceQueued(
        request,
        assertSigningOutcome,
        generation,
        absoluteDeadlineMs,
        deadlineForProviderSigningTransaction(request),
      );
      const port = this.#port;
      if (port === null) {
        throw new AgentQSuiBrowserProviderError("transport_closed", "Web Serial port is not available.");
      }
      this.#restoreCapturedSessionAfterPhysicalDisconnect(generation, session, port);
      return { status: "result", response, sessionInvalidatedByAck: false };
    } catch (error) {
      if (!shouldAttemptProviderSigningOutcomeRecovery(error)) {
        throw error;
      }
      if (!this.#canAttemptRecoveryAfterTeardown(generation, session)) {
        throw error;
      }
      let recoveryPort: BrowserSerialPort;
      let recovery: BrowserBufferedRecoveryOutcome;
      try {
        recoveryPort = await this.#getPort(absoluteDeadlineMs);
        recovery = await this.#tryRecoverBufferedSigningOutcome(
          recoveryPort,
          request.sessionId,
          request.id,
          absoluteDeadlineMs,
        );
      } catch {
        // Recovery transport setup/read failures preserve the original signing
        // delivery error. Firmware invalid_session remains visible if it is the
        // original signing response error.
        throw error;
      }
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
      if (recovery.status === "recovered_error") {
        if (recovery.ack !== "invalid_session") {
          this.#restoreCapturedSessionAfterPhysicalDisconnect(generation, session, recoveryPort);
        } else {
          markBrowserFirmwareSessionInvalidated(recovery.error);
        }
        throw recovery.error;
      }
      throw error;
    }
  }

  async #requestDeviceQueued<TResponse>(
    request: BrowserDeviceRequest,
    assertResponse: (response: DeviceResponse) => TResponse,
    generation: number,
    absoluteDeadlineMs: number,
    phaseDeadlineMs: number,
  ): Promise<TResponse> {
    return requestDevice({
      request,
      deadlineMs: phaseDeadlineMs,
      execute: async (requestLine, expectedId, requestLabel, wireDeadlineMs, assertWireResponse) => {
        const port = await this.#getPort(absoluteDeadlineMs);
        this.#assertTransportLive(generation);
        return requestOverBrowserSerial(
          port,
          requestLine,
          expectedId,
          requestLabel,
          (response) => assertWireResponse(response),
          remainingProviderDeadline(absoluteDeadlineMs, wireDeadlineMs),
          () => this.#abandonPort(),
        );
      },
      assertResponse,
      digestPayload: (bytes) => sha256PayloadDigest(bytes),
      encodeChunkBase64: (bytes) => encodeBase64(bytes),
      makeError: (code, message, retryable = false) => new AgentQSuiBrowserProviderError(code, message),
      errorCode,
      onAbortInvalidSession: markBrowserFirmwareSessionInvalidated,
    });
  }

  async #tryRecoverBufferedSigningOutcome(
    port: BrowserSerialPort,
    sessionId: string,
    requestId: string,
    absoluteDeadlineMs: number,
  ): Promise<BrowserBufferedRecoveryOutcome> {
    let recovered: DeviceResponse;
    try {
      recovered = await requestDevice({
        request: {
          id: requestId,
          method: "get_result",
          sessionId,
          payload: { retainedRequestId: requestId },
        },
        deadlineMs: remainingProviderDeadline(absoluteDeadlineMs, INTERNAL_USB_DEADLINE_MS),
        execute: async (requestLine, expectedId, requestLabel, wireDeadlineMs, assertWireResponse) =>
          requestOverBrowserSerial(
            port,
            requestLine,
            expectedId,
            requestLabel,
            assertWireResponse,
            remainingProviderDeadline(absoluteDeadlineMs, wireDeadlineMs),
            () => this.#abandonPort(),
          ),
        assertResponse: (response) => response,
        digestPayload: (bytes) => sha256PayloadDigest(bytes),
        encodeChunkBase64: (bytes) => encodeBase64(bytes),
        makeError: (code, message) => new AgentQSuiBrowserProviderError(code, message),
        errorCode,
        onAbortInvalidSession: markBrowserFirmwareSessionInvalidated,
      });
    } catch (error) {
      if (errorCode(error) === "invalid_session") {
        return { status: "session_invalidated" };
      }
      return { status: "not_recovered" };
    }
    if (recovered.success === false) {
      if (recovered.error.code === "invalid_session") {
        return { status: "session_invalidated" };
      }
      if (recovered.error.code === "unknown_request") {
        return { status: "not_recovered" };
      }
      const ack = await this.#releaseRecoveredSigningOutcome(port, sessionId, requestId, absoluteDeadlineMs);
      return {
        status: "recovered_error",
        error: new AgentQSuiBrowserProviderError(recovered.error.code, recovered.error.message),
        ack,
      };
    }
    const response = assertSigningOutcome(recovered);
    const ack = await this.#releaseRecoveredSigningOutcome(port, sessionId, requestId, absoluteDeadlineMs);
    return { status: "recovered", response, ack };
  }

  async #releaseRecoveredSigningOutcome(
    port: BrowserSerialPort,
    sessionId: string,
    requestId: string,
    absoluteDeadlineMs: number,
  ): Promise<"acked" | "failed" | "invalid_session"> {
    try {
      await requestDevice({
        request: {
          id: requestId,
          method: "ack_result",
          sessionId,
          payload: { retainedRequestId: requestId },
        },
        deadlineMs: remainingProviderDeadline(absoluteDeadlineMs, INTERNAL_USB_DEADLINE_MS),
        execute: async (requestLine, expectedId, requestLabel, wireDeadlineMs, assertWireResponse) =>
          requestOverBrowserSerial(
            port,
            requestLine,
            expectedId,
            requestLabel,
            assertWireResponse,
            remainingProviderDeadline(absoluteDeadlineMs, wireDeadlineMs),
            () => this.#abandonPort(),
          ),
        assertResponse: assertAckResultDeviceResponse,
        digestPayload: (bytes) => sha256PayloadDigest(bytes),
        encodeChunkBase64: (bytes) => encodeBase64(bytes),
        makeError: (code, message) => new AgentQSuiBrowserProviderError(code, message),
        errorCode,
        onAbortInvalidSession: markBrowserFirmwareSessionInvalidated,
      });
      return "acked";
    } catch (error) {
      if (errorCode(error) === "invalid_session") {
        return "invalid_session";
      }
      // Best-effort cleanup: a failed ack must not turn a recovered signing outcome
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

  #inactiveCredentialResult(deviceId: string | undefined): Extract<CredentialPreparation, { source: "not_connected" }> {
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
    const grantedPort = await findSingleGrantedAgentQPort(serial);
    if (grantedPort !== null) {
      return grantedPort;
    }
    return serial.requestPort({
      filters: [{ usbVendorId: AGENT_Q_USB_VENDOR_ID_NUMBER, usbProductId: AGENT_Q_USB_PRODUCT_ID_NUMBER }],
    });
  };
}

function noop(): void {}

async function findSingleGrantedAgentQPort(serial: BrowserSerial): Promise<BrowserSerialPort | null> {
  if (typeof serial.getPorts !== "function") {
    return null;
  }
  let grantedPorts: BrowserSerialPort[];
  try {
    grantedPorts = await serial.getPorts();
  } catch {
    return null;
  }
  const agentQPorts = grantedPorts.filter(isAgentQSerialPort);
  return agentQPorts.length === 1 ? agentQPorts[0] : null;
}

function isAgentQSerialPort(port: BrowserSerialPort): boolean {
  if (typeof port.getInfo !== "function") {
    return false;
  }
  const info = port.getInfo();
  return info.usbVendorId === AGENT_Q_USB_VENDOR_ID_NUMBER &&
    info.usbProductId === AGENT_Q_USB_PRODUCT_ID_NUMBER;
}

function deadlineForProviderSigningTransaction(request: BrowserSignRequest): number {
  const methodDeadline = request.method === "sign_personal_message"
    ? INTERNAL_SIGN_PERSONAL_MESSAGE_DEADLINE_MS
    : INTERNAL_SIGN_TRANSACTION_DEADLINE_MS;
  return methodDeadline + INTERNAL_USB_DEADLINE_MS * 2;
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

function shouldAttemptProviderSigningOutcomeRecovery(error: unknown): boolean {
  if (!providerRequestMayHaveReachedFirmware(error)) {
    return false;
  }
  const code = errorCode(error);
  return code !== null && RECOVERABLE_PROVIDER_SIGN_DELIVERY_CODES.has(code);
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
  requestLine: string,
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
  const write = writer.write(new TextEncoder().encode(requestLine));
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
  requestLine: string,
  expectedId: string,
  requestLabel: string,
  assertResponse: (response: unknown) => TResponse,
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
    await writeBrowserRequestWithinLease(writer, requestLine, lease, absoluteDeadlineMs, abandonPort);
    writer.releaseLock();
    writer = null;

    const response = readMatchingResponse(reader, expectedId, assertResponse);
    // If the deadline wins the race below, the read is cancelled in `finally` and
    // this promise rejects after it has already lost. Attach a no-op catch so that
    // late rejection is not reported as an unhandled promise rejection.
    void response.catch(() => undefined);
    const deadline = new Promise<never>((_, reject) => {
      timeout = setTimeout(() => {
        lease.canceled = true;
        lease.abandoned = true;
        lease.stalePortLease = abandonPort() ?? undefined;
        console.warn(`[agent-q] No Firmware response for '${requestLabel}' within ${deadlineMs}ms; treating link as lost.`);
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
  assertResponse: (response: unknown) => TResponse,
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
      const consumed = consumeDeviceResponseLineChunk(buffer, decoder.decode(value, { stream: true }));
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
      if (parsed.matched) {
        return parsed.value;
      }
    }
  }
}

function deadlineForProviderRequest(request: Pick<BrowserDeviceRequest, "method">): number {
  switch (request.method) {
    case "connect":
      return INTERNAL_CONNECT_DEADLINE_MS;
    case "disconnect":
      return INTERNAL_DISCONNECT_DEADLINE_MS;
    case "sign_transaction":
      return INTERNAL_SIGN_TRANSACTION_DEADLINE_MS;
    case "sign_personal_message":
      return INTERNAL_SIGN_PERSONAL_MESSAGE_DEADLINE_MS;
    case "credential_prepare":
      return INTERNAL_USB_DEADLINE_MS;
    case "credential_propose":
      return INTERNAL_SIGN_TRANSACTION_DEADLINE_MS;
    case "get_capabilities":
    case "get_accounts":
    case "get_result":
    case "ack_result":
      return INTERNAL_USB_DEADLINE_MS;
  }
  throw new AgentQSuiBrowserProviderError("unknown_error", "Provider request deadline is not defined.");
}

function connectDeviceRequestInput(clientName: string): BrowserDeviceRequest {
  if (!isClientName(clientName)) {
    throw new AgentQSuiBrowserProviderError(
      "invalid_params",
      "clientName must be 1-64 printable ASCII characters.",
    );
  }
  return { method: "connect", payload: { clientName } };
}

function tryParseMatchingResponseLine<TResponse>(
  line: string,
  expectedId: string,
  assertResponse: (response: unknown) => TResponse,
): { matched: true; value: TResponse } | { matched: false } {
  let parsed: unknown;
  try {
    parsed = parseJsonLine(line);
  } catch {
    return { matched: false };
  }
  if (!isRecord(parsed)) {
    return { matched: false };
  }
  if (parsed.id !== expectedId) {
    if (parsed.id === undefined && parsed.success === false) {
      const response = parseDeviceResponse(parsed);
      if (response.success === false) {
        throw new AgentQSuiBrowserProviderError(response.error.code, response.error.message);
      }
    }
    return { matched: false };
  }
  try {
    return { matched: true, value: assertResponse(parsed) };
  } catch (error) {
    if (error instanceof ProtocolError) {
      throw new AgentQSuiBrowserProviderError(error.code, error.message);
    }
    throw error;
  }
}

function assertAckResultDeviceResponse(response: DeviceResponse): void {
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
  const keys = Object.keys(parsed.result);
  if (keys.length !== 0) {
    throw new ProtocolError("invalid_response", "Ack result is malformed.");
  }
}

function targetMatches(requestedDeviceId: string | undefined, sessionDeviceId: string): boolean {
  return requestedDeviceId === undefined || requestedDeviceId === sessionDeviceId;
}

function toCredentialSessionEndedResult(
  value: { source: "session_ended"; deviceId: string; reason: string },
): Extract<CredentialPreparation, { source: "session_ended" }> {
  const reason = value.reason === "transport_closed" ? "transport_unavailable" : value.reason;
  if (reason === "invalid_session" || reason === "timeout" || reason === "transport_unavailable") {
    return { source: "session_ended", deviceId: value.deviceId, reason };
  }
  return { source: "session_ended", deviceId: value.deviceId, reason: "transport_unavailable" };
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

function toLiveSigningOutcome(deviceId: string, response: SigningOutcome): AgentQSuiWalletSignTransactionResult {
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
