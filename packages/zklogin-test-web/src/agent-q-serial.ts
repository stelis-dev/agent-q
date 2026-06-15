import {
  CREDENTIAL_PREPARE_OPERATION,
  CREDENTIAL_PROPOSE_OPERATION,
  SUI_CHAIN_ID,
  SUI_SIGN_TRANSACTION_METHOD,
  SUI_ZKLOGIN_CREDENTIAL,
  assertAccountsResponse,
  assertCapabilitiesResponse,
  assertConnectResponse,
  assertCredentialPrepareResultResponse,
  assertCredentialProposeResultResponse,
  assertDisconnectResponse,
  assertSignResultResponse,
  consumeProtocolResponseChunk,
  makeConnectRequest,
  makeCredentialPrepareRequest,
  makeCredentialProposeRequest,
  makeDisconnectRequest,
  makeGetAccountsRequest,
  makeGetCapabilitiesRequest,
  makeSignTransactionRequest,
  parseJsonLine,
  parseProtocolResponse,
  serializeRequest,
  type AccountsResponse,
  type CapabilitiesResponse,
  type ConnectApprovedResponse,
  type CredentialPrepareResultResponse,
  type CredentialProposeParams,
  type CredentialProposeResultResponse,
  type ProtocolRequest,
  type ProtocolResponse,
  type SignResultResponse,
  type SuiSignTransactionNetwork,
} from "@stelis/agent-q-core/protocol";
import {
  AGENT_Q_USB_PRODUCT_ID_NUMBER,
  AGENT_Q_USB_VENDOR_ID_NUMBER,
  DEFAULT_AGENT_Q_USB_BAUD_RATE,
  INTERNAL_CONNECT_DEADLINE_MS,
  INTERNAL_DISCONNECT_DEADLINE_MS,
  INTERNAL_SIGN_TRANSACTION_DEADLINE_MS,
  INTERNAL_USB_DEADLINE_MS,
} from "@stelis/agent-q-core/provider-protocol";

const CLIENT_NAME = "Agent-Q zkLogin test web";

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

export type AgentQConnectedSession = {
  deviceId: string;
  sessionId: string;
  sessionTtlMs: number;
  connectedAt: string;
  device: ConnectApprovedResponse["device"];
};

export class AgentQSerialError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "AgentQSerialError";
    this.code = code;
  }
}

export function isWebSerialAvailable(): boolean {
  return serialApi() !== null;
}

export class AgentQSerialClient {
  #port: BrowserSerialPort | null = null;
  #session: AgentQConnectedSession | null = null;
  #queue: Promise<unknown> = Promise.resolve();

  get session(): AgentQConnectedSession | null {
    return this.#session;
  }

  clearSession(): void {
    this.#session = null;
  }

  async connect(): Promise<AgentQConnectedSession> {
    const response = await this.#exchange(
      makeConnectRequest(CLIENT_NAME),
      assertConnectResponse,
      INTERNAL_CONNECT_DEADLINE_MS,
    );
    if (response.status === "rejected") {
      throw new AgentQSerialError(response.error.code, response.error.message);
    }
    const session: AgentQConnectedSession = {
      deviceId: response.device.deviceId,
      sessionId: response.sessionId,
      sessionTtlMs: response.sessionTtlMs,
      connectedAt: new Date().toISOString(),
      device: response.device,
    };
    this.#session = session;
    return session;
  }

  async disconnect(): Promise<void> {
    const session = this.#requireSession();
    try {
      await this.#exchange(
        makeDisconnectRequest(session.sessionId),
        assertDisconnectResponse,
        INTERNAL_DISCONNECT_DEADLINE_MS,
      );
    } finally {
      this.#session = null;
      await this.#closePort();
    }
  }

  async getCapabilities(): Promise<CapabilitiesResponse> {
    const session = this.#requireSession();
    return this.#exchange(
      makeGetCapabilitiesRequest(session.sessionId),
      assertCapabilitiesResponse,
      INTERNAL_USB_DEADLINE_MS,
    );
  }

  async getAccounts(): Promise<AccountsResponse> {
    const session = this.#requireSession();
    return this.#exchange(
      makeGetAccountsRequest(session.sessionId),
      assertAccountsResponse,
      INTERNAL_USB_DEADLINE_MS,
    );
  }

  async credentialPrepare(): Promise<CredentialPrepareResultResponse> {
    const session = this.#requireSession();
    return this.#exchange(
      makeCredentialPrepareRequest(session.sessionId, {
        chain: SUI_CHAIN_ID,
        credential: SUI_ZKLOGIN_CREDENTIAL,
      }),
      assertCredentialPrepareResultResponse,
      INTERNAL_USB_DEADLINE_MS,
    );
  }

  async credentialPropose(params: CredentialProposeParams): Promise<CredentialProposeResultResponse> {
    const session = this.#requireSession();
    return this.#exchange(
      makeCredentialProposeRequest(session.sessionId, params),
      assertCredentialProposeResultResponse,
      INTERNAL_SIGN_TRANSACTION_DEADLINE_MS,
    );
  }

  async signTransaction(input: {
    network: SuiSignTransactionNetwork;
    txBytes: string;
  }): Promise<SignResultResponse> {
    const session = this.#requireSession();
    return this.#exchange(
      makeSignTransactionRequest(session.sessionId, SUI_CHAIN_ID, SUI_SIGN_TRANSACTION_METHOD, input),
      assertSignResultResponse,
      INTERNAL_SIGN_TRANSACTION_DEADLINE_MS,
    );
  }

  async dispose(): Promise<void> {
    this.#session = null;
    await this.#closePort();
  }

  #requireSession(): AgentQConnectedSession {
    if (this.#session === null) {
      throw new AgentQSerialError("not_connected", "Connect to an Agent-Q device first.");
    }
    return this.#session;
  }

  async #exchange<TResponse>(
    request: ProtocolRequest,
    assertResponse: (response: ProtocolResponse) => TResponse,
    deadlineMs: number,
  ): Promise<TResponse> {
    const run = this.#queue.then(
      () => this.#exchangeNow(request, assertResponse, deadlineMs),
      () => this.#exchangeNow(request, assertResponse, deadlineMs),
    );
    this.#queue = run.then(noop, noop);
    return run;
  }

  async #exchangeNow<TResponse>(
    request: ProtocolRequest,
    assertResponse: (response: ProtocolResponse) => TResponse,
    deadlineMs: number,
  ): Promise<TResponse> {
    const port = await this.#getPort();
    if (port.readable === null || port.writable === null) {
      await port.open({ baudRate: DEFAULT_AGENT_Q_USB_BAUD_RATE });
    }
    if (port.readable === null || port.writable === null) {
      throw new AgentQSerialError("transport_closed", "Web Serial port is not readable or writable.");
    }

    let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
    let writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
    let timeout: ReturnType<typeof setTimeout> | null = null;
    let succeeded = false;
    try {
      reader = port.readable.getReader();
      writer = port.writable.getWriter();
      await writer.write(new TextEncoder().encode(serializeRequest(request)));
      writer.releaseLock();
      writer = null;

      const read = readMatchingResponse(reader, request.id, assertResponse);
      void read.catch(() => undefined);
      const deadline = new Promise<never>((_, reject) => {
        timeout = setTimeout(() => {
          reject(new AgentQSerialError("timeout", `Timed out waiting for '${request.type}'.`));
        }, deadlineMs);
      });
      const result = await Promise.race([read, deadline]);
      succeeded = true;
      return result;
    } finally {
      if (timeout !== null) {
        clearTimeout(timeout);
      }
      if (writer !== null) {
        writer.releaseLock();
      }
      if (reader !== null) {
        if (!succeeded) {
          await reader.cancel().catch(() => undefined);
        }
        reader.releaseLock();
      }
      if (!succeeded) {
        await this.#closePort();
      }
    }
  }

  async #getPort(): Promise<BrowserSerialPort> {
    if (this.#port !== null) {
      return this.#port;
    }
    const serial = serialApi();
    if (serial === null) {
      throw new AgentQSerialError("unsupported_transport", "Web Serial is unavailable in this browser.");
    }
    this.#port = await serial.requestPort({
      filters: [{
        usbVendorId: AGENT_Q_USB_VENDOR_ID_NUMBER,
        usbProductId: AGENT_Q_USB_PRODUCT_ID_NUMBER,
      }],
    });
    return this.#port;
  }

  async #closePort(): Promise<void> {
    const port = this.#port;
    this.#port = null;
    if (port === null || port.readable === null) {
      return;
    }
    await port.close().catch(() => undefined);
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
      throw new AgentQSerialError("transport_closed", "The device connection was closed.");
    }
    const consumed = consumeProtocolResponseChunk(buffer, decoder.decode(value, { stream: true }));
    buffer = consumed.buffer;
    for (const rawLine of consumed.lines) {
      const line = rawLine.trim();
      if (line.length === 0 || !line.startsWith("{")) {
        continue;
      }
      const response = tryParseMatchingResponseLine(line, expectedId, assertResponse);
      if (response !== undefined) {
        return response;
      }
    }
  }
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
      return assertResponse(parseProtocolResponse(line));
    }
    return undefined;
  }
  return assertResponse(parseProtocolResponse(line, expectedId));
}

function serialApi(): BrowserSerial | null {
  const candidate = (globalThis.navigator as Navigator & { serial?: BrowserSerial }).serial;
  if (candidate === undefined || typeof candidate.requestPort !== "function") {
    return null;
  }
  return candidate;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function noop(): void {}

export const AGENT_Q_ZKLOGIN_TEST_ALLOWED_OPERATIONS = [
  "connect",
  "get_capabilities",
  "get_accounts",
  CREDENTIAL_PREPARE_OPERATION,
  CREDENTIAL_PROPOSE_OPERATION,
  SUI_SIGN_TRANSACTION_METHOD,
  "disconnect",
] as const;
