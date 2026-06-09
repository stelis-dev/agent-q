import {
  assertAccountsResponse,
  assertAckResultResponse,
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
  makeConnectRequest,
  makeDisconnectRequest,
  makeGetAccountsRequest,
  makeGetCapabilitiesRequest,
  makeGetResultRequest,
  makeAckResultRequest,
  makeSignPersonalMessageRequest,
  makeSignTransactionRequest,
  parseJsonLine,
  parseProviderProtocolResponse,
  ProtocolError,
  serializeProviderProtocolRequest,
  type AccountsResponse,
  type CapabilitiesResponse,
  type ConnectResponse,
  type DisconnectResponse,
  type ProviderProtocolRequest,
  type ProviderProtocolResponse,
  type SignResultResponse,
} from "@stelis/agent-q-core/provider-protocol";
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
};

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

  // Every Web Serial port operation runs through this single-slot queue so
  // concurrent callers never open the same port at once. Web Serial throws when
  // open() is called on an already-open port, so two in-flight requests would
  // otherwise collide; each request now waits for the previous one to settle.
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
      try {
        await this.#request(makeGetCapabilitiesRequest(this.#session.sessionId), assertCapabilitiesResponse);
        return this.#connectOutput(this.#session);
      } catch (error) {
        if (!isSessionEndedError(error)) {
          throw error;
        }
        this.#clearSessionAndPort();
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
        this.#clearSessionAndPort();
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
        this.#clearSessionAndPort();
      }
      throw new AgentQSuiBrowserProviderError("device_mismatch", "Connected Agent-Q device did not match the requested deviceId.");
    }
    this.#session = {
      deviceId: response.device.deviceId,
      sessionId: response.sessionId,
      sessionTtlMs: response.sessionTtlMs,
      connectedAt: new Date().toISOString(),
      device: response.device,
    };
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
      this.#clearSessionAndPort();
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
    try {
      const response = await this.#request(makeGetCapabilitiesRequest(session.sessionId), assertCapabilitiesResponse);
      return {
        source: "live",
        deviceId: session.deviceId,
        capabilities: response.chains,
        ...(response.signing === undefined ? {} : { signing: response.signing }),
      };
    } catch (error) {
      const ended = this.#clearIfSessionEnded(error, session.deviceId);
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
    try {
      const response = await this.#request(makeGetAccountsRequest(session.sessionId), assertAccountsResponse);
      return { source: "live", deviceId: session.deviceId, accounts: response.accounts as AgentQSuiWalletGetAccountsResult["accounts"] };
    } catch (error) {
      const ended = this.#clearIfSessionEnded(error, session.deviceId);
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
    // Optional stable request id for idempotent retries. The caller owns id uniqueness:
    // reuse it only to retry the same request, which returns the already-authorized result
    // instead of signing twice. Reusing an id for a different request returns that prior
    // (already-authorized) result, never an unauthorized one.
    requestId?: string;
  }): Promise<AgentQSuiWalletSignTransactionResult> {
    const session = this.#matchingSession(input.deviceId);
    if (session === null) {
      return this.#inactiveResult(input.deviceId);
    }
    const signRequest = makeSignTransactionRequest(session.sessionId, input.chain, input.method, {
      network: input.network,
      txBytes: input.txBytes,
    }, input.requestId);
    try {
      const response = await this.#request(signRequest, assertSignResultResponse);
      return toLiveSignResult(session.deviceId, response);
    } catch (error) {
      // W4: the request may have been signed but its response was lost in transit. Fetch
      // the buffered result by id before surfacing the error.
      const recovered = await this.#tryRecoverBufferedSignResult(session.sessionId, signRequest.id);
      if (recovered !== null) {
        return toLiveSignResult(session.deviceId, recovered);
      }
      const ended = this.#clearIfSessionEnded(error, session.deviceId);
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
    // Optional stable request id for idempotent retries. The caller owns id uniqueness:
    // reuse it only to retry the same request, which returns the already-authorized result
    // instead of signing twice. Reusing an id for a different request returns that prior
    // (already-authorized) result, never an unauthorized one.
    requestId?: string;
  }): Promise<AgentQSuiWalletSignTransactionResult> {
    const session = this.#matchingSession(input.deviceId);
    if (session === null) {
      return this.#inactiveResult(input.deviceId);
    }
    const signRequest = makeSignPersonalMessageRequest(session.sessionId, input.chain, input.method, {
      network: input.network,
      message: input.message,
    }, input.requestId);
    try {
      const response = await this.#request(signRequest, assertSignResultResponse);
      return toLiveSignResult(session.deviceId, response);
    } catch (error) {
      // W4: the request may have been signed but its response was lost in transit. Fetch
      // the buffered result by id before surfacing the error.
      const recovered = await this.#tryRecoverBufferedSignResult(session.sessionId, signRequest.id);
      if (recovered !== null) {
        return toLiveSignResult(session.deviceId, recovered);
      }
      const ended = this.#clearIfSessionEnded(error, session.deviceId);
      if (ended !== null) {
        return ended;
      }
      throw error;
    }
  }

  // W4: best-effort recovery of a buffered signing result whose response was lost in
  // transit. Returns null when the device has no buffered result for this id (it never
  // signed, or the session ended and the buffer cleared), so the caller surfaces the
  // original error.
  async #tryRecoverBufferedSignResult(sessionId: string, requestId: string) {
    // Only recover over a still-open transport. If the port was already cleared (a real
    // disconnect), re-acquiring it here would surprise the user with a port picker, so
    // leave the original error to surface. The device holds the session through a short
    // grace window, so a transient drop that kept the port open still recovers here.
    if (this.#port === null) {
      return null;
    }
    try {
      const recovered = await this.#request(makeGetResultRequest(sessionId, requestId), assertSignResultResponse);
      // Best-effort release: now that we hold the result, tell the device to drop its
      // buffered copy. A separate serialized request, fire-and-forget — a failed ack
      // leaves cleanup to the device's LRU and session-clear, so it never turns a
      // successful buffered-result fetch into a failure.
      void this.#request(makeAckResultRequest(sessionId, requestId), assertAckResultResponse).catch(() => undefined);
      return recovered;
    } catch {
      return null;
    }
  }

  async #getPort(): Promise<BrowserSerialPort> {
    this.#port ??= await this.#requestPort();
    return this.#port;
  }

  #clearPort(): void {
    const port = this.#port;
    this.#port = null;
    if (port !== null && port.readable !== null) {
      // Persistent port: close it on clear. Fire-and-forget so disconnect/dispose stay
      // synchronous; a dead port's close may never settle.
      void settleCleanupStep(port.close(), "port.close");
    }
  }

  #clearSessionAndPort(): void {
    this.#transportGeneration += 1;
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
      this.#clearSessionAndPort();
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
    this.#clearSessionAndPort();
  }

  async #request<TResponse extends ProviderProtocolResponse>(
    request: ProviderProtocolRequest,
    assertResponse: (response: ProviderProtocolResponse) => TResponse,
  ): Promise<TResponse> {
    return this.#exchange(request, assertResponse, deadlineForProviderRequest(request));
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
    return this.#enqueue(async () => {
      this.#assertTransportLive(generation);
      const port = await this.#getPort();
      // Re-check after the (possibly awaited) port acquisition: a disconnect observed
      // while #getPort() was re-prompting bumps the generation, so this request must
      // not run over or reopen a transport that was torn down in that window.
      this.#assertTransportLive(generation);
      return requestOverBrowserSerial(port, request, assertResponse, deadlineMs);
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

  #inactiveResult(deviceId: string | undefined): { source: "not_connected" | "unavailable"; deviceId: string; reason: string } {
    if (!isAgentQSuiBrowserProviderAvailable()) {
      return { source: "unavailable", deviceId: deviceId ?? "browser", reason: "unsupported_transport" };
    }
    return { source: "not_connected", deviceId: deviceId ?? this.#session?.deviceId ?? "browser", reason: "not_connected" };
  }

  #clearIfSessionEnded(error: unknown, deviceId: string): { source: "session_ended"; deviceId: string; reason: string } | null {
    if (!isSessionEndedError(error)) {
      return null;
    }
    this.#clearSessionAndPort();
    return { source: "session_ended", deviceId, reason: errorCode(error) ?? "session_ended" };
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

// Await a best-effort transport-cleanup step, but never block longer than
// CLEANUP_STEP_TIMEOUT_MS. A hung reader.cancel()/port.close() on a disconnected
// device is abandoned (its rejection is swallowed) so the request still settles.
async function settleCleanupStep(operation: Promise<unknown> | undefined, label: string): Promise<void> {
  if (operation === undefined) {
    return;
  }
  const guarded = operation.catch(() => undefined);
  let timer: ReturnType<typeof setTimeout> | null = null;
  const timeout = new Promise<void>((resolve) => {
    timer = setTimeout(() => {
      console.warn(
        `[agent-q] Web Serial cleanup '${label}' did not complete within ${CLEANUP_STEP_TIMEOUT_MS}ms; abandoning it.`,
      );
      resolve();
    }, CLEANUP_STEP_TIMEOUT_MS);
  });
  try {
    await Promise.race([guarded, timeout]);
  } finally {
    if (timer !== null) {
      clearTimeout(timer);
    }
  }
}

async function requestOverBrowserSerial<TResponse extends ProviderProtocolResponse>(
  port: BrowserSerialPort,
  request: ProviderProtocolRequest,
  assertResponse: (response: ProviderProtocolResponse) => TResponse,
  deadlineMs: number,
): Promise<TResponse> {
  // Persistent port: open once and reuse it across serialized requests (the request
  // queue guarantees one at a time). open() is idempotent here — a port a prior request
  // left open is reused; only a prior error or a disconnect leaves it closed.
  if (port.readable === null || port.writable === null) {
    await port.open({ baudRate: DEFAULT_AGENT_Q_USB_BAUD_RATE });
  }
  let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  let writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  let timeout: ReturnType<typeof setTimeout> | null = null;
  let succeeded = false;
  try {
    if (port.readable === null || port.writable === null) {
      throw new AgentQSuiBrowserProviderError("transport_closed", "Web Serial port is not readable or writable.");
    }
    reader = port.readable.getReader();
    writer = port.writable.getWriter();
    await writer.write(new TextEncoder().encode(serializeProviderProtocolRequest(request)));
    writer.releaseLock();
    writer = null;

    const response = readMatchingResponse(reader, request.id, assertResponse);
    // If the deadline wins the race below, the read is cancelled in `finally` and
    // this promise rejects after it has already lost. Attach a no-op catch so that
    // late rejection is not reported as an unhandled promise rejection.
    void response.catch(() => undefined);
    const deadline = new Promise<never>((_, reject) => {
      timeout = setTimeout(() => {
        console.warn(`[agent-q] No Firmware response for '${request.type}' within ${deadlineMs}ms; treating link as lost.`);
        reject(new AgentQSuiBrowserProviderError("timeout", "Timed out waiting for Firmware response."));
      }, deadlineMs);
    });
    const result = await Promise.race([response, deadline]);
    succeeded = true;
    return result;
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
      await settleCleanupStep(port.close(), "port.close");
    }
  }
}

async function readMatchingResponse<TResponse extends ProviderProtocolResponse>(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  expectedId: string,
  assertResponse: (response: ProviderProtocolResponse) => TResponse,
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

function deadlineForProviderRequest(request: ProviderProtocolRequest): number {
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
    case "get_result":
    case "ack_result":
      return INTERNAL_USB_DEADLINE_MS;
  }
}

function tryParseMatchingResponseLine<TResponse extends ProviderProtocolResponse>(
  line: string,
  expectedId: string,
  assertResponse: (response: ProviderProtocolResponse) => TResponse,
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
      const response = parseProviderProtocolResponse(line);
      if (response.type === "error") {
        throw new AgentQSuiBrowserProviderError(response.error.code, response.error.message);
      }
    }
    return undefined;
  }
  try {
    return assertResponse(parseProviderProtocolResponse(line, expectedId));
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
