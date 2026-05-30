import { SerialPort } from "serialport";
import { existsSync } from "node:fs";
import { GatewayError } from "./errors.js";
import {
  assertAccountsResponse,
  assertCapabilitiesResponse,
  assertMethodResultResponse,
  assertPolicyResponse,
  assertConnectResponse,
  assertDisconnectResponse,
  assertIdentifyDeviceResponse,
  assertStatusResponse,
  makeCallMethodRequest,
  makeConnectRequest,
  makeDisconnectRequest,
  makeGetCapabilitiesRequest,
  makeGetAccountsRequest,
  makeIdentifyDeviceRequest,
  makeGetPolicyRequest,
  makeGetStatusRequest,
  parseJsonLine,
  parseProtocolResponse,
  ProtocolError,
  serializeRequest,
  type AccountsResponse,
  type CapabilitiesResponse,
  type ConnectResponse,
  type DisconnectResponse,
  type IdentifyDeviceResponse,
  type MethodResultResponse,
  type PolicyResponse,
  type ProtocolRequest,
  type ProtocolResponse,
  type StatusResponse,
} from "./protocol.js";

export const DEFAULT_SCAN_TIMEOUT_MS = 2000;
export const MAX_SCAN_TIMEOUT_MS = 10000;
export const AGENT_Q_USB_VENDOR_ID = "303a";
export const AGENT_Q_USB_PRODUCT_ID = "1001";

export type UnavailableReason =
  | "timeout"
  | "port_not_found"
  | "port_in_use"
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

// Transport contract: each call should resolve or reject within its timeout
// argument. Gateway does not rely on that alone — GatewayCore wraps the driver in
// deadlineEnforcingDriver, which races every timeout-bearing call against its own
// timeout argument, so a driver that ignores it still cannot exceed the budget.
// listPorts has no timeout argument and is bounded by the shared scan deadline in
// scanUsbDeviceStatuses. A new timeout-bearing method must be added to the wrapper.
export interface UsbSerialDriver {
  listPorts(): Promise<PortInfo[]>;
  requestStatus(portPath: string, timeoutMs: number): Promise<StatusResponse>;
  identifyDevice(
    portPath: string,
    code: string,
    timeoutMs: number,
    durationMs: number,
  ): Promise<IdentifyDeviceResponse>;
  connectDevice(
    portPath: string,
    gatewayName: string,
    timeoutMs: number,
    approvalTimeoutMs: number,
  ): Promise<ConnectResponse>;
  disconnectDevice(
    portPath: string,
    sessionId: string,
    timeoutMs: number,
  ): Promise<DisconnectResponse>;
  getCapabilities(
    portPath: string,
    sessionId: string,
    timeoutMs: number,
  ): Promise<CapabilitiesResponse>;
  getAccounts(
    portPath: string,
    sessionId: string,
    timeoutMs: number,
  ): Promise<AccountsResponse>;
  getPolicy(
    portPath: string,
    sessionId: string,
    timeoutMs: number,
  ): Promise<PolicyResponse>;
  callMethod(
    portPath: string,
    sessionId: string,
    chain: string,
    method: string,
    params: Record<string, unknown>,
    timeoutMs: number,
  ): Promise<MethodResultResponse>;
}

export class SerialPortUsbDriver implements UsbSerialDriver {
  async listPorts(): Promise<PortInfo[]> {
    return (await SerialPort.list()).map((port) => ({
      ...port,
      path: resolveUsbCalloutPath(port.path),
    }));
  }

  async requestStatus(portPath: string, timeoutMs: number): Promise<StatusResponse> {
    return requestStatusOverSerial(portPath, timeoutMs);
  }

  async identifyDevice(
    portPath: string,
    code: string,
    timeoutMs: number,
    durationMs: number,
  ): Promise<IdentifyDeviceResponse> {
    return identifyDeviceOverSerial(portPath, code, timeoutMs, durationMs);
  }

  async connectDevice(
    portPath: string,
    gatewayName: string,
    timeoutMs: number,
    approvalTimeoutMs: number,
  ): Promise<ConnectResponse> {
    return connectDeviceOverSerial(portPath, gatewayName, timeoutMs, approvalTimeoutMs);
  }

  async disconnectDevice(
    portPath: string,
    sessionId: string,
    timeoutMs: number,
  ): Promise<DisconnectResponse> {
    return disconnectDeviceOverSerial(portPath, sessionId, timeoutMs);
  }

  async getCapabilities(
    portPath: string,
    sessionId: string,
    timeoutMs: number,
  ): Promise<CapabilitiesResponse> {
    return getCapabilitiesOverSerial(portPath, sessionId, timeoutMs);
  }

  async getAccounts(
    portPath: string,
    sessionId: string,
    timeoutMs: number,
  ): Promise<AccountsResponse> {
    return getAccountsOverSerial(portPath, sessionId, timeoutMs);
  }

  async getPolicy(
    portPath: string,
    sessionId: string,
    timeoutMs: number,
  ): Promise<PolicyResponse> {
    return getPolicyOverSerial(portPath, sessionId, timeoutMs);
  }

  async callMethod(
    portPath: string,
    sessionId: string,
    chain: string,
    method: string,
    params: Record<string, unknown>,
    timeoutMs: number,
  ): Promise<MethodResultResponse> {
    return callMethodOverSerial(portPath, sessionId, chain, method, params, timeoutMs);
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

export function validateTimeoutMs(value: unknown): number {
  if (value === undefined) {
    return DEFAULT_SCAN_TIMEOUT_MS;
  }
  if (!Number.isInteger(value) || typeof value !== "number" || value <= 0) {
    throw new GatewayError("invalid_timeout", "timeoutMs must be a positive integer.", false);
  }
  if (value > MAX_SCAN_TIMEOUT_MS) {
    throw new GatewayError("invalid_timeout", `timeoutMs must be <= ${MAX_SCAN_TIMEOUT_MS}.`, false);
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
  timeoutMs = DEFAULT_SCAN_TIMEOUT_MS,
): Promise<UsbStatusResult[]> {
  return (await scanUsbDeviceStatuses(driver, timeoutMs)).devices;
}

// Enforce a Gateway-side deadline on a transport call so a slow or uncooperative
// driver — one that ignores its timeout argument, or a stuck listPorts() — cannot
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

// Single enforcement boundary for the transport timeout contract. Wrapping a
// driver here races every timeout-bearing call against its own timeout argument,
// so a driver that ignores the argument still cannot exceed the budget. Applied
// once in GatewayCore, this bounds every present and future timeout-bearing call
// in one place instead of relying on each call site to remember to race.
// listPorts has no timeout argument and is bounded by the shared scan deadline in
// scanUsbDeviceStatuses.
export function deadlineEnforcingDriver(driver: UsbSerialDriver): UsbSerialDriver {
  return {
    listPorts: () => driver.listPorts(),
    requestStatus: (portPath, timeoutMs) =>
      raceDeadline(
        driver.requestStatus(portPath, timeoutMs),
        timeoutMs,
        "USB status handshake exceeded its timeout.",
      ),
    identifyDevice: (portPath, code, timeoutMs, durationMs) =>
      raceDeadline(
        driver.identifyDevice(portPath, code, timeoutMs, durationMs),
        timeoutMs,
        "USB identify exceeded its timeout.",
      ),
    connectDevice: (portPath, gatewayName, timeoutMs, approvalTimeoutMs) =>
      raceDeadline(
        driver.connectDevice(portPath, gatewayName, timeoutMs, approvalTimeoutMs),
        timeoutMs,
        "USB connect exceeded its timeout.",
      ),
    disconnectDevice: (portPath, sessionId, timeoutMs) =>
      raceDeadline(
        driver.disconnectDevice(portPath, sessionId, timeoutMs),
        timeoutMs,
        "USB disconnect exceeded its timeout.",
      ),
    getCapabilities: (portPath, sessionId, timeoutMs) =>
      raceDeadline(
        driver.getCapabilities(portPath, sessionId, timeoutMs),
        timeoutMs,
        "USB get capabilities exceeded its timeout.",
      ),
    getAccounts: (portPath, sessionId, timeoutMs) =>
      raceDeadline(
        driver.getAccounts(portPath, sessionId, timeoutMs),
        timeoutMs,
        "USB get accounts exceeded its timeout.",
      ),
    getPolicy: (portPath, sessionId, timeoutMs) =>
      raceDeadline(
        driver.getPolicy(portPath, sessionId, timeoutMs),
        timeoutMs,
        "USB get policy exceeded its timeout.",
      ),
    callMethod: (portPath, sessionId, chain, method, params, timeoutMs) =>
      raceDeadline(
        driver.callMethod(portPath, sessionId, chain, method, params, timeoutMs),
        timeoutMs,
        "USB call_method exceeded its timeout.",
      ),
  };
}

export async function scanUsbDeviceStatuses(
  driver: UsbSerialDriver,
  timeoutMs = DEFAULT_SCAN_TIMEOUT_MS,
  now: () => number = () => Date.now(),
): Promise<UsbStatusScanResult> {
  // timeoutMs is a total wall-clock budget for the whole scan, not a per-candidate
  // limit. Port enumeration AND every handshake draw from one shared deadline, so
  // a slow listPorts() or many candidates cannot push the call past timeoutMs.
  // `now` is injectable so the deadline is deterministically testable.
  const totalTimeoutMs = validateTimeoutMs(timeoutMs);
  const deadline = now() + totalTimeoutMs;
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
  return "handshake_failed";
}

async function requestStatusOverSerial(portPath: string, timeoutMs: number): Promise<StatusResponse> {
  const request = makeGetStatusRequest();
  return requestOverSerial(portPath, request, timeoutMs, (response) => assertStatusResponse(response));
}

async function identifyDeviceOverSerial(
  portPath: string,
  code: string,
  timeoutMs: number,
  durationMs: number,
): Promise<IdentifyDeviceResponse> {
  const request = makeIdentifyDeviceRequest(code, durationMs);
  return requestOverSerial(portPath, request, timeoutMs, (response) => assertIdentifyDeviceResponse(response));
}

async function connectDeviceOverSerial(
  portPath: string,
  gatewayName: string,
  timeoutMs: number,
  approvalTimeoutMs: number,
): Promise<ConnectResponse> {
  const request = makeConnectRequest(gatewayName, approvalTimeoutMs);
  return requestOverSerial(portPath, request, timeoutMs, (response) => assertConnectResponse(response));
}

async function disconnectDeviceOverSerial(
  portPath: string,
  sessionId: string,
  timeoutMs: number,
): Promise<DisconnectResponse> {
  const request = makeDisconnectRequest(sessionId);
  return requestOverSerial(portPath, request, timeoutMs, (response) => assertDisconnectResponse(response));
}

async function getCapabilitiesOverSerial(
  portPath: string,
  sessionId: string,
  timeoutMs: number,
): Promise<CapabilitiesResponse> {
  const request = makeGetCapabilitiesRequest(sessionId);
  return requestOverSerial(portPath, request, timeoutMs, (response) => assertCapabilitiesResponse(response));
}

async function getAccountsOverSerial(
  portPath: string,
  sessionId: string,
  timeoutMs: number,
): Promise<AccountsResponse> {
  const request = makeGetAccountsRequest(sessionId);
  return requestOverSerial(portPath, request, timeoutMs, (response) => assertAccountsResponse(response));
}

async function getPolicyOverSerial(
  portPath: string,
  sessionId: string,
  timeoutMs: number,
): Promise<PolicyResponse> {
  const request = makeGetPolicyRequest(sessionId);
  return requestOverSerial(portPath, request, timeoutMs, (response) => assertPolicyResponse(response));
}

async function callMethodOverSerial(
  portPath: string,
  sessionId: string,
  chain: string,
  method: string,
  params: Record<string, unknown>,
  timeoutMs: number,
): Promise<MethodResultResponse> {
  const request = makeCallMethodRequest(sessionId, chain, method, params);
  return requestOverSerial(portPath, request, timeoutMs, (response) => assertMethodResultResponse(response));
}

async function requestOverSerial<TResponse extends ProtocolResponse>(
  portPath: string,
  request: ProtocolRequest,
  timeoutMs: number,
  assertResponse: (response: ProtocolResponse) => TResponse,
): Promise<TResponse> {
  const port = new SerialPort({
    path: portPath,
    baudRate: 115200,
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
      }, timeoutMs);

      const settle = (complete: () => void): void => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);
        port.off("data", onData);
        port.off("error", onError);
        complete();
      };

      const onError = (error: Error): void => {
        settle(() => reject(mapSerialOpenError(error)));
      };

      const onData = (chunk: Buffer): void => {
        buffer += chunk.toString("utf8");
        while (buffer.includes("\n")) {
          const index = buffer.indexOf("\n");
          const line = buffer.slice(0, index).trim();
          buffer = buffer.slice(index + 1);
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
  if (/busy|access denied|resource busy|permission/i.test(message)) {
    return new GatewayError("port_in_use", message, true);
  }
  if (/not found|cannot open|no such file/i.test(message)) {
    return new GatewayError("port_not_found", message, true);
  }
  if (/closed|disconnect/i.test(message)) {
    return new GatewayError("transport_closed", message, true);
  }
  return new GatewayError("handshake_failed", message, true);
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
    value === "handshake_failed" ||
    value === "incompatible_version" ||
    value === "transport_closed"
  );
}

function isRetryableIdlessFirmwareError(code: string): boolean {
  // Current Firmware does not emit id-less transient errors. Keep this narrow
  // for future transient codes that cannot be correlated to a request id.
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
