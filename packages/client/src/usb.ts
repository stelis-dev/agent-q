import { SerialPort } from "serialport";
import { existsSync } from "node:fs";
import { GatewayError } from "./errors.js";
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
  type SignResultResponse,
  type SignPersonalMessageParams,
  type SignTransactionParams,
  type SupportedSignRoute,
  type StatusResponse,
} from "./protocol.js";
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

// Transport contract: each call should resolve or reject within its internal
// deadline. GatewayCore wraps the driver in deadlineEnforcingDriver, so a driver
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
    gatewayName: string,
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
    gatewayName: string,
    deadlineMs: number,
  ): Promise<ConnectResponse> {
    return connectDeviceOverSerial(portPath, gatewayName, deadlineMs);
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
    throw new GatewayError("gateway_error", "Internal USB deadline is invalid.", false);
  }
  if (value > INTERNAL_USB_DEADLINE_MS) {
    throw new GatewayError("gateway_error", "Internal USB deadline is invalid.", false);
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

// Enforce a Gateway-side deadline on a transport call so a slow or uncooperative
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
      () => reject(new GatewayError("timeout", timeoutMessage, true)),
      Math.max(0, remainingMs),
    );
  });
  return Promise.race([work, timeout]).finally(() => clearTimeout(timer));
}

// Single enforcement boundary for the transport deadline contract. Wrapping a
// driver here races every deadline-bearing call against its own deadline argument,
// so a driver that ignores the argument still cannot exceed the budget. Applied
// once in GatewayCore, this bounds deadline-bearing calls in one place instead
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
    connectDevice: (portPath, gatewayName, deadlineMs) =>
      raceDeadline(
        driver.connectDevice(portPath, gatewayName, deadlineMs),
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
        deadlineMs,
        "USB sign_transaction exceeded its timeout.",
      ),
    signPersonalMessage: (portPath, sessionId, route, params, deadlineMs) =>
      raceDeadline(
        driver.signPersonalMessage(portPath, sessionId, route, params, deadlineMs),
        deadlineMs,
        "USB sign_personal_message exceeded its timeout.",
      ),
  };
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
      // caller is therefore safe even without the GatewayCore driver wrapper; the
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
      // to explain why a previously known device is not live now.
    }
  }

  return {
    ports,
    devices: results,
    failures,
  };
}

export function mapErrorToUnavailableReason(error: unknown): UnavailableReason {
  if (error instanceof GatewayError) {
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
  gatewayName: string,
  deadlineMs: number,
): Promise<ConnectResponse> {
  const request = makeConnectRequest(gatewayName);
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
  return requestOverSerial(portPath, request, deadlineMs, (response) => assertSignResultResponse(response));
}

async function signPersonalMessageOverSerial(
  portPath: string,
  sessionId: string,
  route: Extract<SupportedSignRoute, { operation: "sign_personal_message" }>,
  params: SignPersonalMessageParams,
  deadlineMs: number,
): Promise<SignResultResponse> {
  const request = makeSignPersonalMessageRequest(sessionId, route.chain, route.method, params);
  return requestOverSerial(portPath, request, deadlineMs, (response) => assertSignResultResponse(response));
}

async function requestOverSerial<TResponse extends ProtocolResponse>(
  portPath: string,
  request: ProtocolRequest,
  deadlineMs: number,
  assertResponse: (response: ProtocolResponse) => TResponse,
): Promise<TResponse> {
  const port = new SerialPort({
    path: portPath,
    baudRate: DEFAULT_AGENT_Q_USB_BAUD_RATE,
    autoOpen: false,
  });

  await openPort(port);

  try {
    // Flush discards only OS-side serial buffers. Bytes already in transit on
    // the USB wire may still arrive after this call.
    await flushPort(port);
    return await new Promise<TResponse>((resolve, reject) => {
      let settled = false;
      let buffer = "";
      const timer = setTimeout(() => {
        settle(() => reject(new GatewayError("timeout", "Timed out waiting for Firmware response.", true)));
      }, deadlineMs);

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
        settle(() => reject(mapSerialOpenError(error)));
      };

      const onClose = (): void => {
        settle(() => reject(new GatewayError("transport_closed", "USB serial transport closed.", true)));
      };

      const onData = (chunk: Buffer): void => {
        let lines: string[];
        try {
          const consumed = consumeProtocolResponseChunk(buffer, chunk.toString("utf8"));
          buffer = consumed.buffer;
          lines = consumed.lines;
        } catch (error) {
          settle(() => reject(toGatewayProtocolError(error)));
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
            settle(() => reject(error));
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
      port.write(serializeRequest(request), (error) => {
        if (error) {
          settle(() => reject(mapSerialOpenError(error)));
          return;
        }
        port.drain((drainError) => {
          if (drainError) {
            settle(() => reject(mapSerialOpenError(drainError)));
          }
        });
      });
    });
  } finally {
    await closePort(port);
  }
}

function toGatewayProtocolError(error: unknown): unknown {
  if (error instanceof ProtocolError) {
    return new GatewayError(error.code, error.message, error.code === "timeout");
  }
  return error;
}

/** @internal Exported for focused protocol-line tests; not part of Gateway's public API. */
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
        throw new GatewayError(
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
      throw new GatewayError(error.code, error.message, error.code === "timeout");
    }
    throw error;
  }
}

function openPort(port: SerialPort): Promise<void> {
  return new Promise((resolve, reject) => {
    port.open((error) => {
      if (error) {
        reject(mapSerialOpenError(error));
        return;
      }
      resolve();
    });
  });
}

function flushPort(port: SerialPort): Promise<void> {
  return new Promise((resolve, reject) => {
    port.flush((error) => {
      if (error) {
        reject(mapSerialOpenError(error));
        return;
      }
      resolve();
    });
  });
}

function closePort(port: SerialPort): Promise<void> {
  if (!port.isOpen) {
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    port.close(() => resolve());
  });
}

function mapSerialOpenError(error: Error): GatewayError {
  const message = error.message || "USB serial transport failed.";
  const reason = classifySerialUnavailableReason(error);
  if (reason !== null) {
    return new GatewayError(reason, message, true);
  }
  return new GatewayError("handshake_failed", message, true);
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
  if (error instanceof GatewayError && !isUnavailableReason(error.code)) {
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
