import { SerialPort } from "serialport";
import { existsSync } from "node:fs";
import { AgentQError } from "./errors.js";
import {
  assertAccountsResponse,
  assertApprovalHistoryResponse,
  assertCapabilitiesResponse,
  assertPolicyProposeResultResponse,
  assertPolicyResponse,
  assertSignResultResponse,
  assertConnectResponse,
  assertDisconnectResponse,
  assertIdentifyDeviceResponse,
  assertStatusResponse,
  makeConnectRequest,
  makeDisconnectRequest,
  makeGetCapabilitiesRequest,
  makeGetAccountsRequest,
  makeGetApprovalHistoryRequest,
  makePolicyProposeRequest,
  makeIdentifyDeviceRequest,
  makePolicyGetRequest,
  makeGetStatusRequest,
  consumeProtocolResponseChunk,
  parseJsonLine,
  parseProtocolResponse,
  ProtocolError,
  serializeRequest,
  type AccountsResponse,
  type ApprovalHistoryResponse,
  type CapabilitiesResponse,
  type ConnectResponse,
  type DisconnectResponse,
  type IdentifyDeviceResponse,
  type PolicyProposeResultResponse,
  type PolicyResponse,
  type ProtocolRequest,
  type ProtocolResponse,
  type SignPersonalMessageRequest,
  type SignResultResponse,
  type SignPersonalMessageParams,
  type SignTransactionRequest,
  type SignTransactionParams,
  type SupportedSignRoute,
  type StatusResponse,
} from "./protocol.js";
import {
  assertAckResultResponse,
  makeAckResultRequest,
  makeGetResultRequest,
} from "./protocol-recovery.js";
import {
  makeSignPersonalMessageRequest,
  makeSignTransactionRequest,
} from "./provider-protocol.js";
import {
  AGENT_Q_USB_PRODUCT_ID,
  AGENT_Q_USB_VENDOR_ID,
  DEFAULT_AGENT_Q_USB_BAUD_RATE,
  INTERNAL_USB_DEADLINE_MS,
} from "./transport-invariants.js";

export { AGENT_Q_USB_PRODUCT_ID, AGENT_Q_USB_VENDOR_ID, INTERNAL_USB_DEADLINE_MS };

export type UnavailableReason =
  | "timeout"
  | "port_not_found"
  | "port_in_use"
  | "port_permission_denied"
  | "handshake_failed"
  | "incompatible_version"
  | "transport_closed";

export interface PortInfo {
  path: string;
  manufacturer?: string;
  serialNumber?: string;
  pnpId?: string;
  locationId?: string;
  productId?: string;
  vendorId?: string;
}

export interface UsbStatusResult {
  portPath: string;
  protocolResponse: StatusResponse;
}

export interface UsbStatusFailure {
  portPath: string;
  unavailableReason: UnavailableReason;
  firmwareErrorCode?: string;
}

export interface UsbStatusScanResult {
  ports: PortInfo[];
  devices: UsbStatusResult[];
  failures: UsbStatusFailure[];
}

export type UsbProtocolRequestExecutor = <TResponse extends ProtocolResponse>(
  request: ProtocolRequest,
  deadlineMs: number,
  assertResponse: (response: ProtocolResponse) => TResponse,
) => Promise<TResponse>;

type SignProtocolRequest = SignTransactionRequest | SignPersonalMessageRequest;
export type PortTransactionContext = {
  request: UsbProtocolRequestExecutor;
};
type SerialPortOptions = {
  path: string;
  baudRate: number;
  hupcl: boolean;
  autoOpen: boolean;
};
type SerialPortLike = {
  readonly isOpen: boolean;
  open(callback: (error?: Error | null) => void): void;
  flush(callback: (error?: Error | null) => void): void;
  write(data: string, callback: (error?: Error | null) => void): void;
  drain(callback: (error?: Error | null) => void): void;
  close(callback: (error?: Error | null) => void): void;
  on(event: "data", listener: (chunk: Buffer) => void): void;
  on(event: "error", listener: (error: Error) => void): void;
  on(event: "close", listener: () => void): void;
  off(event: "data", listener: (chunk: Buffer) => void): void;
  off(event: "error", listener: (error: Error) => void): void;
  off(event: "close", listener: () => void): void;
};
type SerialPortFactory = (options: SerialPortOptions) => SerialPortLike;
type WriteReachability = "not_started" | "started";
type PortLease = {
  portPath: string;
  canceled: boolean;
  writeReachability: WriteReachability;
  quarantineToken?: symbol;
  cleanupPromise?: Promise<void>;
};
type PortQuarantine = {
  token: symbol;
  reason: string;
  released: Promise<void>;
  release(): void;
};
type SignRecoveryOutcome =
  | { status: "not_recovered" }
  | { status: "recovered"; result: SignResultResponse };
type AckRecoveryOutcome = "acked" | "failed" | "invalid_session";

const REQUEST_MAY_HAVE_REACHED_FIRMWARE = Symbol("agent-q.requestMayHaveReachedFirmware");
const FIRMWARE_SESSION_INVALIDATED = Symbol("agent-q.firmwareSessionInvalidated");
const portTransactions = new Map<string, Promise<void>>();
const portQuarantines = new Map<string, PortQuarantine>();
const USB_CLEANUP_STEP_TIMEOUT_MS = 1500;
const defaultSerialPortFactory: SerialPortFactory = (options) => new SerialPort(options);
let serialPortFactory: SerialPortFactory = defaultSerialPortFactory;

const RECOVERABLE_SIGN_DELIVERY_CODES = new Set([
  "timeout",
  "transport_closed",
  "protocol_error",
  "invalid_json",
  "handshake_failed",
]);

/** @internal Test-only injection point for transport lease tests. */
export function setSerialPortFactoryForTest(factory: SerialPortFactory | null): void {
  serialPortFactory = factory ?? defaultSerialPortFactory;
}

// Transport contract: each call should resolve or reject within its internal
// deadline. AgentQCore wraps the driver in deadlineEnforcingDriver, so a driver
// that ignores the deadline argument still cannot exceed the budget. listPorts
// has no deadline argument and is bounded by the shared scan deadline in
// scanUsbDeviceStatuses.
export interface UsbSerialDriver {
  listPorts(): Promise<PortInfo[]>;
  requestStatus(portPath: string, deadlineMs: number): Promise<StatusResponse>;
  identifyDevice(
    portPath: string,
    code: string,
    deadlineMs: number,
  ): Promise<IdentifyDeviceResponse>;
  connectDevice(
    portPath: string,
    clientName: string,
    deadlineMs: number,
  ): Promise<ConnectResponse>;
  disconnectDevice(
    portPath: string,
    sessionId: string,
    deadlineMs: number,
  ): Promise<DisconnectResponse>;
  getCapabilities(
    portPath: string,
    sessionId: string,
    deadlineMs: number,
  ): Promise<CapabilitiesResponse>;
  getAccounts(
    portPath: string,
    sessionId: string,
    deadlineMs: number,
  ): Promise<AccountsResponse>;
  policyGet(
    portPath: string,
    sessionId: string,
    deadlineMs: number,
  ): Promise<PolicyResponse>;
  getApprovalHistory(
    portPath: string,
    sessionId: string,
    params: { limit?: number; beforeSeq?: string },
    deadlineMs: number,
  ): Promise<ApprovalHistoryResponse>;
  policyPropose(
    portPath: string,
    sessionId: string,
    policy: Record<string, unknown>,
    deadlineMs: number,
  ): Promise<PolicyProposeResultResponse>;
  signTransaction(
    portPath: string,
    sessionId: string,
    route: Extract<SupportedSignRoute, { operation: "sign_transaction" }>,
    params: SignTransactionParams,
    deadlineMs: number,
  ): Promise<SignResultResponse>;
  signPersonalMessage(
    portPath: string,
    sessionId: string,
    route: Extract<SupportedSignRoute, { operation: "sign_personal_message" }>,
    params: SignPersonalMessageParams,
    deadlineMs: number,
  ): Promise<SignResultResponse>;
}

export class SerialPortUsbDriver implements UsbSerialDriver {
  async listPorts(): Promise<PortInfo[]> {
    return (await SerialPort.list()).map((port) => ({
      ...port,
      path: resolveUsbCalloutPath(port.path),
    }));
  }

  async requestStatus(portPath: string, deadlineMs: number): Promise<StatusResponse> {
    return requestStatusOverSerial(portPath, deadlineMs);
  }

  async identifyDevice(
    portPath: string,
    code: string,
    deadlineMs: number,
  ): Promise<IdentifyDeviceResponse> {
    return identifyDeviceOverSerial(portPath, code, deadlineMs);
  }

  async connectDevice(
    portPath: string,
    clientName: string,
    deadlineMs: number,
  ): Promise<ConnectResponse> {
    return connectDeviceOverSerial(portPath, clientName, deadlineMs);
  }

  async disconnectDevice(
    portPath: string,
    sessionId: string,
    deadlineMs: number,
  ): Promise<DisconnectResponse> {
    return disconnectDeviceOverSerial(portPath, sessionId, deadlineMs);
  }

  async getCapabilities(
    portPath: string,
    sessionId: string,
    deadlineMs: number,
  ): Promise<CapabilitiesResponse> {
    return getCapabilitiesOverSerial(portPath, sessionId, deadlineMs);
  }

  async getAccounts(
    portPath: string,
    sessionId: string,
    deadlineMs: number,
  ): Promise<AccountsResponse> {
    return getAccountsOverSerial(portPath, sessionId, deadlineMs);
  }

  async policyGet(
    portPath: string,
    sessionId: string,
    deadlineMs: number,
  ): Promise<PolicyResponse> {
    return policyGetOverSerial(portPath, sessionId, deadlineMs);
  }

  async getApprovalHistory(
    portPath: string,
    sessionId: string,
    params: { limit?: number; beforeSeq?: string },
    deadlineMs: number,
  ): Promise<ApprovalHistoryResponse> {
    return getApprovalHistoryOverSerial(portPath, sessionId, params, deadlineMs);
  }

  async policyPropose(
    portPath: string,
    sessionId: string,
    policy: Record<string, unknown>,
    deadlineMs: number,
  ): Promise<PolicyProposeResultResponse> {
    return policyProposeOverSerial(portPath, sessionId, policy, deadlineMs);
  }

  async signTransaction(
    portPath: string,
    sessionId: string,
    route: Extract<SupportedSignRoute, { operation: "sign_transaction" }>,
    params: SignTransactionParams,
    deadlineMs: number,
  ): Promise<SignResultResponse> {
    return signTransactionOverSerial(portPath, sessionId, route, params, deadlineMs);
  }

  async signPersonalMessage(
    portPath: string,
    sessionId: string,
    route: Extract<SupportedSignRoute, { operation: "sign_personal_message" }>,
    params: SignPersonalMessageParams,
    deadlineMs: number,
  ): Promise<SignResultResponse> {
    return signPersonalMessageOverSerial(portPath, sessionId, route, params, deadlineMs);
  }
}

export function resolveUsbCalloutPath(
  path: string,
  platform = process.platform,
  pathExists: (path: string) => boolean = existsSync,
): string {
  if (platform !== "darwin" || !path.startsWith("/dev/tty.")) {
    return path;
  }
  const calloutPath = `/dev/cu.${path.slice("/dev/tty.".length)}`;
  return pathExists(calloutPath) ? calloutPath : path;
}

export function validateInternalDeadlineMs(value: unknown): number {
  if (value === undefined) {
    return INTERNAL_USB_DEADLINE_MS;
  }
  if (!Number.isInteger(value) || typeof value !== "number" || value <= 0) {
    throw new AgentQError("agent_q_error", "Internal USB deadline is invalid.", false);
  }
  if (value > INTERNAL_USB_DEADLINE_MS) {
    throw new AgentQError("agent_q_error", "Internal USB deadline is invalid.", false);
  }
  return value;
}

export function isLikelyAgentQUsbPort(port: PortInfo): boolean {
  const vendorId = normalizeUsbId(port.vendorId);
  const productId = normalizeUsbId(port.productId);

  const manufacturer = port.manufacturer?.toLowerCase() ?? "";
  const pnpId = port.pnpId?.toLowerCase() ?? "";
  const serialNumber = port.serialNumber ?? "";
  const hasLikelyDescriptor =
    manufacturer.includes("espressif") || pnpId.includes("303a") || pnpId.includes("esp");
  const hasUsbSerialPath = /(^|[/\\])(cu|tty)\.usbmodem/i.test(port.path);
  const hasDeviceSerial = serialNumber.length > 0;

  if (vendorId.length > 0 || productId.length > 0) {
    if (vendorId !== AGENT_Q_USB_VENDOR_ID || productId !== AGENT_Q_USB_PRODUCT_ID) {
      return false;
    }
    return manufacturer.length === 0 && pnpId.length === 0 ? true : hasLikelyDescriptor;
  }

  return hasLikelyDescriptor && hasUsbSerialPath && hasDeviceSerial;
}

export async function scanUsbDevices(
  driver: UsbSerialDriver,
  deadlineMs = INTERNAL_USB_DEADLINE_MS,
): Promise<UsbStatusResult[]> {
  return (await scanUsbDeviceStatuses(driver, deadlineMs)).devices;
}

// Enforce a host-side deadline on a transport call so a slow or uncooperative
// driver — one that ignores its deadline argument, or a stuck listPorts() — cannot
// push the scan past its budget. A genuine rejection from `work` propagates
// UNCHANGED, so callers can still tell an enumeration/transport error apart from
// "no device present"; swallowing the error (returning []) would conflate the two.
function raceDeadline<T>(work: Promise<T>, remainingMs: number, timeoutMessage: string): Promise<T> {
  // Swallow only a LATE rejection from the losing branch to avoid an unhandled
  // rejection; an early rejection still propagates through the race below.
  work.catch(() => {});
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<T>((_resolve, reject) => {
    timer = setTimeout(
      () => reject(new AgentQError("timeout", timeoutMessage, true)),
      Math.max(0, remainingMs),
    );
  });
  return Promise.race([work, timeout]).finally(() => clearTimeout(timer));
}

function deadlineExpiredBeforeWriteError(message: string): AgentQError {
  return markRequestDidNotReachFirmware(new AgentQError("timeout", message, true));
}

// Single enforcement boundary for the transport deadline contract. Wrapping a
// driver here races every deadline-bearing call against its own deadline argument,
// so a driver that ignores the argument still cannot exceed the budget. Applied
// once in AgentQCore, this bounds deadline-bearing calls in one place instead
// of relying on each call site to remember to race.
// listPorts has no deadline argument and is bounded by the shared scan deadline in
// scanUsbDeviceStatuses.
export function deadlineEnforcingDriver(driver: UsbSerialDriver): UsbSerialDriver {
  return {
    listPorts: () => driver.listPorts(),
    requestStatus: (portPath, deadlineMs) =>
      raceDeadline(
        driver.requestStatus(portPath, deadlineMs),
        deadlineMs,
        "USB status handshake exceeded its timeout.",
      ),
    identifyDevice: (portPath, code, deadlineMs) =>
      raceDeadline(
        driver.identifyDevice(portPath, code, deadlineMs),
        deadlineMs,
        "USB identify exceeded its timeout.",
      ),
    connectDevice: (portPath, clientName, deadlineMs) =>
      raceDeadline(
        driver.connectDevice(portPath, clientName, deadlineMs),
        deadlineMs,
        "USB connect exceeded its timeout.",
      ),
    disconnectDevice: (portPath, sessionId, deadlineMs) =>
      raceDeadline(
        driver.disconnectDevice(portPath, sessionId, deadlineMs),
        deadlineMs,
        "USB disconnect exceeded its timeout.",
      ),
    getCapabilities: (portPath, sessionId, deadlineMs) =>
      raceDeadline(
        driver.getCapabilities(portPath, sessionId, deadlineMs),
        deadlineMs,
        "USB get capabilities exceeded its timeout.",
      ),
    getAccounts: (portPath, sessionId, deadlineMs) =>
      raceDeadline(
        driver.getAccounts(portPath, sessionId, deadlineMs),
        deadlineMs,
        "USB get accounts exceeded its timeout.",
      ),
    policyGet: (portPath, sessionId, deadlineMs) =>
      raceDeadline(
        driver.policyGet(portPath, sessionId, deadlineMs),
        deadlineMs,
        "USB policy_get exceeded its timeout.",
      ),
    getApprovalHistory: (portPath, sessionId, params, deadlineMs) =>
      raceDeadline(
        driver.getApprovalHistory(portPath, sessionId, params, deadlineMs),
        deadlineMs,
        "USB get approval history exceeded its timeout.",
      ),
    policyPropose: (portPath, sessionId, policy, deadlineMs) =>
      raceDeadline(
        driver.policyPropose(portPath, sessionId, policy, deadlineMs),
        deadlineMs,
        "USB policy_propose exceeded its timeout.",
      ),
    signTransaction: (portPath, sessionId, route, params, deadlineMs) =>
      raceDeadline(
        driver.signTransaction(portPath, sessionId, route, params, deadlineMs),
        deadlineWithSignRecovery(deadlineMs),
        "USB sign_transaction exceeded its timeout.",
      ),
    signPersonalMessage: (portPath, sessionId, route, params, deadlineMs) =>
      raceDeadline(
        driver.signPersonalMessage(portPath, sessionId, route, params, deadlineMs),
        deadlineWithSignRecovery(deadlineMs),
        "USB sign_personal_message exceeded its timeout.",
      ),
  };
}

function deadlineWithSignRecovery(deadlineMs: number): number {
  return deadlineMs + INTERNAL_USB_DEADLINE_MS * 2;
}

/** @internal */
export function markRequestMayHaveReachedFirmware<T>(error: T): T {
  return tagRequestReachability(error, true);
}

function markFirmwareSessionInvalidated<T>(value: T): T {
  if ((typeof value === "object" && value !== null) || typeof value === "function") {
    try {
      Object.defineProperty(value, FIRMWARE_SESSION_INVALIDATED, {
        value: true,
        configurable: true,
      });
    } catch {
      // Some Error-like or response-like objects may be non-extensible.
    }
  }
  return value;
}

/** @internal Package-private side channel consumed by AgentQCore before projection. */
export function consumeFirmwareSessionInvalidated(value: unknown): boolean {
  if (
    value === null ||
    (typeof value !== "object" && typeof value !== "function") ||
    (value as { [FIRMWARE_SESSION_INVALIDATED]?: boolean })[FIRMWARE_SESSION_INVALIDATED] !== true
  ) {
    return false;
  }
  try {
    delete (value as { [FIRMWARE_SESSION_INVALIDATED]?: boolean })[FIRMWARE_SESSION_INVALIDATED];
  } catch {
    // Metadata is non-public and non-enumerable; failure to delete is harmless.
  }
  return true;
}

function markRequestDidNotReachFirmware<T>(error: T): T {
  return tagRequestReachability(error, false);
}

function tagRequestReachability<T>(error: T, mayHaveReachedFirmware: boolean): T {
  if ((typeof error === "object" && error !== null) || typeof error === "function") {
    try {
      Object.defineProperty(error, REQUEST_MAY_HAVE_REACHED_FIRMWARE, {
        value: mayHaveReachedFirmware,
        configurable: true,
      });
    } catch {
      // Some host errors may be non-extensible; leave them untagged.
    }
  }
  return error;
}

function requestMayHaveReachedFirmware(error: unknown): boolean {
  return Boolean(
    error !== null &&
      (typeof error === "object" || typeof error === "function") &&
      (error as { [REQUEST_MAY_HAVE_REACHED_FIRMWARE]?: boolean })[REQUEST_MAY_HAVE_REACHED_FIRMWARE],
  );
}

function errorCode(error: unknown): string | null {
  if (error instanceof AgentQError || error instanceof ProtocolError) {
    return error.code;
  }
  return null;
}

/** @internal Shared per-port transaction queue for multi-request USB invariants. */
export function withSerialPortTransaction<T>(
  portPath: string,
  deadlineMs: number,
  operation: (context: PortTransactionContext) => Promise<T>,
): Promise<T> {
  const absoluteDeadlineMs = Date.now() + Math.max(0, deadlineMs);
  const previous = portTransactions.get(portPath) ?? Promise.resolve();
  const run = previous.then(async () => {
    ensureTransactionDeadline(
      absoluteDeadlineMs,
      "USB request expired before it reached Firmware.",
    );
    await waitForPortPathAvailability(portPath, absoluteDeadlineMs);
    const context: PortTransactionContext = {
      request: async (request, requestDeadlineMs, assertResponse) => {
        const remainingMs = ensureTransactionDeadline(
          absoluteDeadlineMs,
          "USB request expired before it reached Firmware.",
        );
        await waitForPortPathAvailability(portPath, absoluteDeadlineMs);
        return requestOverSerialUnlocked(
          portPath,
          request,
          Math.min(requestDeadlineMs, remainingMs),
          assertResponse,
        );
      },
    };
    return operation(context);
  });
  const tail = run.then(noop, noop);
  portTransactions.set(portPath, tail);
  tail.then(() => {
    if (portTransactions.get(portPath) === tail) {
      portTransactions.delete(portPath);
    }
  });
  return run;
}

function ensureTransactionDeadline(absoluteDeadlineMs: number, message: string): number {
  const remainingMs = absoluteDeadlineMs - Date.now();
  if (remainingMs <= 0) {
    throw deadlineExpiredBeforeWriteError(message);
  }
  return remainingMs;
}

function noop(): void {}

function ensurePortPathNotQuarantined(portPath: string): void {
  const quarantine = portQuarantines.get(portPath);
  if (quarantine !== undefined) {
    throw new AgentQError(
      "port_in_use",
      `USB port is waiting for timed-out transport cleanup: ${quarantine.reason}`,
      true,
    );
  }
}

async function waitForPortPathAvailability(portPath: string, absoluteDeadlineMs: number): Promise<void> {
  const quarantine = portQuarantines.get(portPath);
  if (quarantine === undefined) {
    return;
  }
  const remainingMs = absoluteDeadlineMs - Date.now();
  if (remainingMs <= 0) {
    ensurePortPathNotQuarantined(portPath);
  }
  let timer: ReturnType<typeof setTimeout> | null = null;
  try {
    await Promise.race([
      quarantine.released,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          reject(new AgentQError(
            "port_in_use",
            `USB port is waiting for timed-out transport cleanup: ${quarantine.reason}`,
            true,
          ));
        }, remainingMs);
      }),
    ]);
  } finally {
    if (timer !== null) {
      clearTimeout(timer);
    }
  }
  ensurePortPathNotQuarantined(portPath);
}

function quarantinePortPath(lease: PortLease, reason: string): symbol {
  if (lease.quarantineToken !== undefined) {
    return lease.quarantineToken;
  }
  const token = Symbol(`agent-q.port-quarantine:${lease.portPath}`);
  let release!: () => void;
  const released = new Promise<void>((resolve) => {
    release = resolve;
  });
  lease.quarantineToken = token;
  portQuarantines.set(lease.portPath, { token, reason, released, release });
  return token;
}

function releasePortPathQuarantine(portPath: string, token: symbol | undefined): void {
  if (token === undefined) {
    return;
  }
  const quarantine = portQuarantines.get(portPath);
  if (quarantine?.token === token) {
    portQuarantines.delete(portPath);
    quarantine.release();
  }
}

export async function scanUsbDeviceStatuses(
  driver: UsbSerialDriver,
  deadlineMs = INTERNAL_USB_DEADLINE_MS,
  now: () => number = () => Date.now(),
): Promise<UsbStatusScanResult> {
  // deadlineMs is a total wall-clock budget for the whole scan, not a per-candidate
  // limit. Port enumeration AND every handshake draw from one shared deadline, so
  // a slow listPorts() or many candidates cannot push the call past deadlineMs.
  // `now` is injectable so the deadline is deterministically testable.
  const totalDeadlineMs = validateInternalDeadlineMs(deadlineMs);
  const deadline = now() + totalDeadlineMs;
  // Enumeration is bounded by the deadline but its errors propagate (a failed
  // listPorts is not the same as "no devices"; the caller maps it).
  const ports = await raceDeadline(
    driver.listPorts(),
    deadline - now(),
    "USB port enumeration exceeded the scan deadline.",
  );
  const candidates = ports.filter(isLikelyAgentQUsbPort);
  const results: UsbStatusResult[] = [];
  const failures: UsbStatusFailure[] = [];

  for (const candidate of candidates) {
    const remainingMs = deadline - now();
    if (remainingMs <= 0) {
      // Budget exhausted before this candidate was reached.
      failures.push({
        portPath: candidate.path,
        unavailableReason: "timeout",
      });
      continue;
    }
    try {
      // scanUsbDeviceStatuses OWNS the total scan budget, so it bounds each
      // handshake itself by the time remaining until the deadline. A raw/direct
      // caller is therefore safe even without the AgentQCore driver wrapper; the
      // wrapper adds the same bound for Core's non-scan transport calls and the
      // overlap on this path is harmless (same timeout, whichever fires first).
      const protocolResponse = await raceDeadline(
        driver.requestStatus(candidate.path, remainingMs),
        remainingMs,
        "USB status handshake exceeded the scan deadline.",
      );
      results.push({
        portPath: candidate.path,
        protocolResponse,
      });
    } catch (error) {
      failures.push({
        portPath: candidate.path,
        unavailableReason: mapErrorToUnavailableReason(error),
        firmwareErrorCode: getFirmwareErrorCode(error),
      });
      // Scan only reports confirmed Agent-Q devices. Callers can use failures
      // to explain why a known device is not live.
    }
  }

  return {
    ports,
    devices: results,
    failures,
  };
}

export function mapErrorToUnavailableReason(error: unknown): UnavailableReason {
  if (error instanceof AgentQError) {
    if (isUnavailableReason(error.code)) {
      return error.code;
    }
    if (error.code === "unsupported_version" || error.code === "incompatible_version") {
      return "incompatible_version";
    }
    if (error.code === "timeout") {
      return "timeout";
    }
  }
  if (error instanceof ProtocolError) {
    if (error.code === "unsupported_version" || error.code === "incompatible_version") {
      return "incompatible_version";
    }
    return "handshake_failed";
  }
  const serialReason = classifySerialUnavailableReason(error);
  if (serialReason !== null) {
    return serialReason;
  }
  return "handshake_failed";
}

async function requestStatusOverSerial(portPath: string, deadlineMs: number): Promise<StatusResponse> {
  const request = makeGetStatusRequest();
  return requestOverSerial(portPath, request, deadlineMs, (response) => assertStatusResponse(response));
}

async function identifyDeviceOverSerial(
  portPath: string,
  code: string,
  deadlineMs: number,
): Promise<IdentifyDeviceResponse> {
  const request = makeIdentifyDeviceRequest(code);
  return requestOverSerial(portPath, request, deadlineMs, (response) => assertIdentifyDeviceResponse(response));
}

async function connectDeviceOverSerial(
  portPath: string,
  clientName: string,
  deadlineMs: number,
): Promise<ConnectResponse> {
  const request = makeConnectRequest(clientName);
  return requestOverSerial(portPath, request, deadlineMs, (response) => assertConnectResponse(response));
}

async function disconnectDeviceOverSerial(
  portPath: string,
  sessionId: string,
  deadlineMs: number,
): Promise<DisconnectResponse> {
  const request = makeDisconnectRequest(sessionId);
  return requestOverSerial(portPath, request, deadlineMs, (response) => assertDisconnectResponse(response));
}

async function getCapabilitiesOverSerial(
  portPath: string,
  sessionId: string,
  deadlineMs: number,
): Promise<CapabilitiesResponse> {
  const request = makeGetCapabilitiesRequest(sessionId);
  return requestOverSerial(portPath, request, deadlineMs, (response) => assertCapabilitiesResponse(response));
}

async function getAccountsOverSerial(
  portPath: string,
  sessionId: string,
  deadlineMs: number,
): Promise<AccountsResponse> {
  const request = makeGetAccountsRequest(sessionId);
  return requestOverSerial(portPath, request, deadlineMs, (response) => assertAccountsResponse(response));
}

async function policyGetOverSerial(
  portPath: string,
  sessionId: string,
  deadlineMs: number,
): Promise<PolicyResponse> {
  const request = makePolicyGetRequest(sessionId);
  return requestOverSerial(portPath, request, deadlineMs, (response) => assertPolicyResponse(response));
}

async function getApprovalHistoryOverSerial(
  portPath: string,
  sessionId: string,
  params: { limit?: number; beforeSeq?: string },
  deadlineMs: number,
): Promise<ApprovalHistoryResponse> {
  const request = makeGetApprovalHistoryRequest(sessionId, params);
  return requestOverSerial(portPath, request, deadlineMs, (response) => assertApprovalHistoryResponse(response));
}

async function policyProposeOverSerial(
  portPath: string,
  sessionId: string,
  policy: Record<string, unknown>,
  deadlineMs: number,
): Promise<PolicyProposeResultResponse> {
  const request = makePolicyProposeRequest(sessionId, policy);
  return requestOverSerial(portPath, request, deadlineMs, (response) => assertPolicyProposeResultResponse(response));
}

async function signTransactionOverSerial(
  portPath: string,
  sessionId: string,
  route: Extract<SupportedSignRoute, { operation: "sign_transaction" }>,
  params: SignTransactionParams,
  deadlineMs: number,
): Promise<SignResultResponse> {
  const request = makeSignTransactionRequest(sessionId, route.chain, route.method, params);
  return withSerialPortTransaction(portPath, deadlineWithSignRecovery(deadlineMs), (transaction) =>
    requestSignResultWithRecovery(request, deadlineMs, transaction.request),
  );
}

async function signPersonalMessageOverSerial(
  portPath: string,
  sessionId: string,
  route: Extract<SupportedSignRoute, { operation: "sign_personal_message" }>,
  params: SignPersonalMessageParams,
  deadlineMs: number,
): Promise<SignResultResponse> {
  const request = makeSignPersonalMessageRequest(sessionId, route.chain, route.method, params);
  return withSerialPortTransaction(portPath, deadlineWithSignRecovery(deadlineMs), (transaction) =>
    requestSignResultWithRecovery(request, deadlineMs, transaction.request),
  );
}

/** @internal Shared signing-result delivery invariant for the Node USB path. */
export async function requestSignResultWithRecovery(
  request: SignProtocolRequest,
  deadlineMs: number,
  executor: UsbProtocolRequestExecutor,
): Promise<SignResultResponse> {
  try {
    return await executor(request, deadlineMs, (response) => assertSignResultResponse(response));
  } catch (error) {
    if (!shouldAttemptSignResultRecovery(error)) {
      throw error;
    }
    const recovery = await tryRecoverSignResult(request.sessionId, request.id, executor);
    if (recovery.status === "recovered") {
      return recovery.result;
    }
    throw error;
  }
}

async function tryRecoverSignResult(
  sessionId: string,
  requestId: string,
  executor: UsbProtocolRequestExecutor,
): Promise<SignRecoveryOutcome> {
  let recovered: SignResultResponse;
  try {
    recovered = await executor(
      makeGetResultRequest(sessionId, requestId),
      INTERNAL_USB_DEADLINE_MS,
      (response) => assertSignResultResponse(response),
    );
  } catch (error) {
    if (errorCode(error) === "invalid_session") {
      throw error;
    }
    return { status: "not_recovered" };
  }
  const ack = await releaseRecoveredSignResult(sessionId, requestId, executor);
  if (ack === "invalid_session") {
    markFirmwareSessionInvalidated(recovered);
  }
  return { status: "recovered", result: recovered };
}

async function releaseRecoveredSignResult(
  sessionId: string,
  requestId: string,
  executor: UsbProtocolRequestExecutor,
): Promise<AckRecoveryOutcome> {
  try {
    await executor(
      makeAckResultRequest(sessionId, requestId),
      INTERNAL_USB_DEADLINE_MS,
      (response) => assertAckResultResponse(response),
    );
    return "acked";
  } catch (error) {
    if (errorCode(error) === "invalid_session") {
      return "invalid_session";
    }
    // Best-effort cleanup: a failed ack must not turn a recovered sign_result
    // into a caller-visible failure.
    return "failed";
  }
}

function shouldAttemptSignResultRecovery(error: unknown): boolean {
  if (!requestMayHaveReachedFirmware(error)) {
    return false;
  }
  const code = errorCode(error);
  return code !== null && RECOVERABLE_SIGN_DELIVERY_CODES.has(code);
}

async function requestOverSerial<TResponse extends ProtocolResponse>(
  portPath: string,
  request: ProtocolRequest,
  deadlineMs: number,
  assertResponse: (response: ProtocolResponse) => TResponse,
): Promise<TResponse> {
  return withSerialPortTransaction(portPath, deadlineMs, (transaction) =>
    transaction.request(request, deadlineMs, assertResponse),
  );
}

async function requestOverSerialUnlocked<TResponse extends ProtocolResponse>(
  portPath: string,
  request: ProtocolRequest,
  deadlineMs: number,
  assertResponse: (response: ProtocolResponse) => TResponse,
): Promise<TResponse> {
  const absoluteDeadlineMs = Date.now() + Math.max(0, deadlineMs);
  const lease: PortLease = {
    portPath,
    canceled: false,
    writeReachability: "not_started",
  };
  const port = serialPortFactory({
    path: portPath,
    baudRate: DEFAULT_AGENT_Q_USB_BAUD_RATE,
    // The host opens a short-lived serial connection for each protocol call.
    // Dropping DTR on every close resets ESP32-S3 USB Serial/JTAG devices
    // between scan and connect, so keep the line state stable across closes.
    hupcl: false,
    autoOpen: false,
  });

  if (deadlineMs <= 0) {
    throw deadlineExpiredBeforeWriteError("USB request expired before it reached Firmware.");
  }

  try {
    await openPortWithinLease(port, lease, absoluteDeadlineMs);
    await flushPortWithinLease(port, lease, absoluteDeadlineMs);
  } catch (error) {
    await ensureLeaseCleanup(port, lease, "pre-write port.close");
    throw markRequestDidNotReachFirmware(error);
  }

  try {
    ensureLeaseCanStartSideEffect(lease, absoluteDeadlineMs);
    return await new Promise<TResponse>((resolve, reject) => {
      let settled = false;
      let buffer = "";
      const timer = setTimeout(() => {
        lease.canceled = true;
        settle(() =>
          reject(tagRequestReachability(
            new AgentQError("timeout", "Timed out waiting for Firmware response.", true),
            lease.writeReachability === "started",
          )),
        );
      }, Math.max(0, absoluteDeadlineMs - Date.now()));

      const settle = (complete: () => void): void => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);
        port.off("data", onData);
        port.off("error", onError);
        port.off("close", onClose);
        complete();
      };

      const onError = (error: Error): void => {
        settle(() => reject(tagRequestReachability(mapSerialOpenError(error), lease.writeReachability === "started")));
      };

      const onClose = (): void => {
        settle(() =>
          reject(tagRequestReachability(
            new AgentQError("transport_closed", "USB serial transport closed.", true),
            lease.writeReachability === "started",
          )),
        );
      };

      const onData = (chunk: Buffer): void => {
        let lines: string[];
        try {
          const consumed = consumeProtocolResponseChunk(buffer, chunk.toString("utf8"));
          buffer = consumed.buffer;
          lines = consumed.lines;
        } catch (error) {
          settle(() => reject(markRequestMayHaveReachedFirmware(toAgentQProtocolError(error))));
          return;
        }

        for (const rawLine of lines) {
          const line = rawLine.trim();
          if (line.length === 0 || !line.startsWith("{")) {
            continue;
          }

          let parsed: TResponse | undefined;
          try {
            parsed = tryParseMatchingResponseLine(line, request.id, assertResponse);
          } catch (error) {
            settle(() => reject(markRequestMayHaveReachedFirmware(error)));
            return;
          }
          if (parsed !== undefined) {
            settle(() => resolve(parsed));
            return;
          }
        }
      };

      port.on("data", onData);
      port.on("error", onError);
      port.on("close", onClose);
      lease.writeReachability = "started";
      port.write(serializeRequest(request), (error) => {
        if (settled || lease.canceled) {
          return;
        }
        if (error) {
          settle(() => reject(markRequestMayHaveReachedFirmware(mapSerialOpenError(error))));
          return;
        }
        port.drain((drainError) => {
          if (settled || lease.canceled) {
            return;
          }
          if (drainError) {
            settle(() => reject(markRequestMayHaveReachedFirmware(mapSerialOpenError(drainError))));
          }
        });
      });
    });
  } finally {
    await ensureLeaseCleanup(port, lease, "port.close");
  }
}

function toAgentQProtocolError(error: unknown): unknown {
  if (error instanceof ProtocolError) {
    return new AgentQError(error.code, error.message, error.code === "timeout");
  }
  return error;
}

/** @internal Exported for focused protocol-line tests; not part of Agent-Q's public API. */
export function tryParseMatchingResponseLine<TResponse extends ProtocolResponse>(
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
        throw new AgentQError(
          response.error.code,
          response.error.message,
          isRetryableIdlessFirmwareError(response.error.code),
        );
      }
    }
    return undefined;
  }

  try {
    return assertResponse(parseProtocolResponse(line, expectedId));
  } catch (error) {
    if (error instanceof ProtocolError) {
      throw new AgentQError(error.code, error.message, error.code === "timeout");
    }
    throw error;
  }
}

function ensureLeaseCanStartSideEffect(lease: PortLease, absoluteDeadlineMs: number): void {
  if (lease.canceled) {
    throw markRequestDidNotReachFirmware(
      new AgentQError("timeout", "USB request lease was canceled before it reached Firmware.", true),
    );
  }
  ensureTransactionDeadline(
    absoluteDeadlineMs,
    "USB request expired before it reached Firmware.",
  );
}

function remainingLeaseMs(lease: PortLease, absoluteDeadlineMs: number, message: string): number {
  if (lease.canceled) {
    throw markRequestDidNotReachFirmware(new AgentQError("timeout", message, true));
  }
  return ensureTransactionDeadline(absoluteDeadlineMs, message);
}

function openPortWithinLease(
  port: SerialPortLike,
  lease: PortLease,
  absoluteDeadlineMs: number,
): Promise<void> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timeoutMs = remainingLeaseMs(
      lease,
      absoluteDeadlineMs,
      "USB request expired while opening the serial port.",
    );
    const timeout = setTimeout(() => {
      if (settled) {
        return;
      }
      settled = true;
      lease.canceled = true;
      quarantinePortPath(lease, "serial port open timed out");
      reject(deadlineExpiredBeforeWriteError("USB request expired while opening the serial port."));
    }, timeoutMs);

    port.open((error) => {
      if (settled) {
        if (!error) {
          void ensureLeaseCleanup(port, lease, "late port.open close-only cleanup");
        } else {
          releasePortPathQuarantine(lease.portPath, lease.quarantineToken);
        }
        return;
      }
      settled = true;
      clearTimeout(timeout);
      if (error) {
        reject(mapSerialOpenError(error));
        return;
      }
      if (lease.canceled) {
        void ensureLeaseCleanup(port, lease, "canceled port.open close-only cleanup");
        reject(deadlineExpiredBeforeWriteError("USB request lease was canceled before it reached Firmware."));
        return;
      }
      resolve();
    });
  });
}

function flushPortWithinLease(
  port: SerialPortLike,
  lease: PortLease,
  absoluteDeadlineMs: number,
): Promise<void> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timeoutMs = remainingLeaseMs(
      lease,
      absoluteDeadlineMs,
      "USB request expired while preparing the serial port.",
    );
    const timeout = setTimeout(() => {
      if (settled) {
        return;
      }
      settled = true;
      lease.canceled = true;
      quarantinePortPath(lease, "serial port flush timed out");
      void ensureLeaseCleanup(port, lease, "timed-out port.flush close-only cleanup");
      reject(deadlineExpiredBeforeWriteError("USB request expired while preparing the serial port."));
    }, timeoutMs);

    port.flush((error) => {
      if (settled) {
        void ensureLeaseCleanup(port, lease, "late port.flush close-only cleanup");
        return;
      }
      settled = true;
      clearTimeout(timeout);
      if (error) {
        reject(mapSerialOpenError(error));
        return;
      }
      if (lease.canceled) {
        void ensureLeaseCleanup(port, lease, "canceled port.flush close-only cleanup");
        reject(deadlineExpiredBeforeWriteError("USB request lease was canceled before it reached Firmware."));
        return;
      }
      resolve();
    });
  });
}

function ensureLeaseCleanup(
  port: SerialPortLike,
  lease: PortLease,
  label: string,
): Promise<void> {
  if (!port.isOpen) {
    return Promise.resolve();
  }
  if (lease.cleanupPromise === undefined) {
    lease.cleanupPromise = closePortBestEffort(port, lease, label);
  }
  return lease.cleanupPromise;
}

function closePortBestEffort(
  port: SerialPortLike,
  lease: PortLease,
  label: string,
): Promise<void> {
  if (!port.isOpen) {
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    let settled = false;
    const timeout = setTimeout(() => {
      if (settled) {
        return;
      }
      settled = true;
      quarantinePortPath(lease, `${label} timed out`);
      resolve();
    }, USB_CLEANUP_STEP_TIMEOUT_MS);
    port.close((error) => {
      if (settled) {
        if (!error) {
          releasePortPathQuarantine(lease.portPath, lease.quarantineToken);
        }
        return;
      }
      settled = true;
      clearTimeout(timeout);
      if (error) {
        quarantinePortPath(lease, `${label} failed`);
      } else {
        releasePortPathQuarantine(lease.portPath, lease.quarantineToken);
      }
      resolve();
    });
  });
}

function mapSerialOpenError(error: Error): AgentQError {
  const message = error.message || "USB serial transport failed.";
  const reason = classifySerialUnavailableReason(error);
  if (reason !== null) {
    return new AgentQError(reason, message, true);
  }
  return new AgentQError("handshake_failed", message, true);
}

function classifySerialUnavailableReason(error: unknown): UnavailableReason | null {
  const message = error instanceof Error ? error.message : "";
  const code = isRecord(error) && typeof error.code === "string" ? error.code : "";
  const text = `${code} ${message}`;

  if (/\b(?:eacces|eperm)\b|operation not permitted|permission denied|access denied/i.test(text)) {
    return "port_permission_denied";
  }
  if (/busy|resource busy|in use/i.test(text)) {
    return "port_in_use";
  }
  if (/not found|cannot open|no such file|\benoent\b/i.test(text)) {
    return "port_not_found";
  }
  if (/closed|disconnect/i.test(text)) {
    return "transport_closed";
  }
  return null;
}

function normalizeUsbId(value: string | undefined): string {
  if (value === undefined || value.length === 0) {
    return "";
  }
  return value.toLowerCase().replace(/^0x/, "").padStart(4, "0");
}

function isUnavailableReason(value: string): value is UnavailableReason {
  return (
    value === "timeout" ||
    value === "port_not_found" ||
    value === "port_in_use" ||
    value === "port_permission_denied" ||
    value === "handshake_failed" ||
    value === "incompatible_version" ||
    value === "transport_closed"
  );
}

function isRetryableIdlessFirmwareError(code: string): boolean {
  // Current Firmware does not emit id-less transient errors. Keep this narrow
  // because these errors cannot be correlated to a request id.
  return code === "busy" || code === "timeout";
}

function getFirmwareErrorCode(error: unknown): string | undefined {
  if (error instanceof AgentQError && !isUnavailableReason(error.code)) {
    return error.code;
  }
  if (error instanceof ProtocolError) {
    return error.code;
  }
  return undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
