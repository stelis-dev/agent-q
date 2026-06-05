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
  makeConnectRequest,
  makeDisconnectRequest,
  makeGetAccountsRequest,
  makeGetCapabilitiesRequest,
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
} from "@stelis/agent-q-client/provider-protocol";
import type {
  AgentQSuiWalletGetAccountsResult,
  AgentQSuiWalletGetCapabilitiesResult,
  AgentQSuiWalletProvider,
  AgentQSuiWalletSignTransactionResult,
} from "./wallet-standard.js";

const DEFAULT_GATEWAY_NAME = "Agent-Q Sui dapp";

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
  gatewayName?: string;
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
  readonly #gatewayName: string;
  #port: BrowserSerialPort | null;
  #session: BrowserSession | null = null;

  constructor(options: AgentQSuiBrowserProviderOptions = {}) {
    this.#port = null;
    this.#requestPort = defaultRequestPort();
    this.#gatewayName = options.gatewayName ?? DEFAULT_GATEWAY_NAME;
  }

  async connectDevice(input: {
    deviceId?: string;
    purpose?: string;
    gatewayName?: string;
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

    const port = await this.#getPort();
    let response: ConnectResponse;
    try {
      response = await requestOverBrowserSerial(
        port,
        makeConnectRequest(input.gatewayName ?? this.#gatewayName),
        assertConnectResponse,
        INTERNAL_CONNECT_DEADLINE_MS,
      );
    } catch (error) {
      if (isSessionEndedError(error)) {
        this.#clearPort();
      }
      throw error;
    }
    if (response.status === "rejected") {
      throw new AgentQSuiBrowserProviderError(response.error.code, response.error.message);
    }
    if (input.deviceId !== undefined && response.device.deviceId !== input.deviceId) {
      try {
        await disconnectApprovedMismatchedSession(port, response.sessionId);
      } finally {
        this.#clearPort();
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
      const ended = this.#clearIfSessionEnded(error, session.deviceId);
      if (ended !== null) {
        return ended;
      }
      throw error;
    } finally {
      this.#session = null;
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
  }): Promise<AgentQSuiWalletSignTransactionResult> {
    const session = this.#matchingSession(input.deviceId);
    if (session === null) {
      return this.#inactiveResult(input.deviceId);
    }
    try {
      const response = await this.#request(
        makeSignTransactionRequest(session.sessionId, input.chain, input.method, {
          network: input.network,
          txBytes: input.txBytes,
        }),
        assertSignResultResponse,
      );
      return toLiveSignResult(session.deviceId, response);
    } catch (error) {
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
  }): Promise<AgentQSuiWalletSignTransactionResult> {
    const session = this.#matchingSession(input.deviceId);
    if (session === null) {
      return this.#inactiveResult(input.deviceId);
    }
    try {
      const response = await this.#request(
        makeSignPersonalMessageRequest(session.sessionId, input.chain, input.method, {
          network: input.network,
          message: input.message,
        }),
        assertSignResultResponse,
      );
      return toLiveSignResult(session.deviceId, response);
    } catch (error) {
      const ended = this.#clearIfSessionEnded(error, session.deviceId);
      if (ended !== null) {
        return ended;
      }
      throw error;
    }
  }

  async #getPort(): Promise<BrowserSerialPort> {
    this.#port ??= await this.#requestPort();
    return this.#port;
  }

  #clearPort(): void {
    this.#port = null;
  }

  #clearSessionAndPort(): void {
    this.#session = null;
    this.#clearPort();
  }

  async #request<TResponse extends ProviderProtocolResponse>(
    request: ProviderProtocolRequest,
    assertResponse: (response: ProviderProtocolResponse) => TResponse,
  ): Promise<TResponse> {
    return requestOverBrowserSerial(
      await this.#getPort(),
      request,
      assertResponse,
      deadlineForProviderRequest(request),
    );
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

async function disconnectApprovedMismatchedSession(port: BrowserSerialPort, sessionId: string): Promise<void> {
  try {
    await requestOverBrowserSerial(
      port,
      makeDisconnectRequest(sessionId),
      assertDisconnectResponse,
      INTERNAL_DISCONNECT_DEADLINE_MS,
    );
  } catch {
    // Best-effort cleanup for a session this provider will not retain.
  }
}

async function requestOverBrowserSerial<TResponse extends ProviderProtocolResponse>(
  port: BrowserSerialPort,
  request: ProviderProtocolRequest,
  assertResponse: (response: ProviderProtocolResponse) => TResponse,
  deadlineMs: number,
): Promise<TResponse> {
  await port.open({ baudRate: DEFAULT_AGENT_Q_USB_BAUD_RATE });
  let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  let writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  let timeout: ReturnType<typeof setTimeout> | null = null;
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
    const deadline = new Promise<never>((_, reject) => {
      timeout = setTimeout(
        () => reject(new AgentQSuiBrowserProviderError("timeout", "Timed out waiting for Firmware response.")),
        deadlineMs,
      );
    });
    return await Promise.race([response, deadline]);
  } finally {
    if (timeout !== null) {
      clearTimeout(timeout);
    }
    if (writer !== null) {
      writer.releaseLock();
    }
    if (reader !== null) {
      try {
        await reader.cancel();
      } catch {
        // Best-effort transport cleanup; preserve the original request result.
      }
      reader.releaseLock();
    }
    try {
      await port.close();
    } catch {
      // Best-effort transport cleanup; preserve the original request result.
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
