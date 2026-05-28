import { SerialPort } from "serialport";
import { GatewayError } from "./errors.js";
import {
  assertIdentifyDeviceResponse,
  assertStatusResponse,
  makeIdentifyDeviceRequest,
  makeGetStatusRequest,
  parseJsonLine,
  parseProtocolResponse,
  ProtocolError,
  serializeRequest,
  type IdentifyDeviceResponse,
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

export interface UsbSerialDriver {
  listPorts(): Promise<PortInfo[]>;
  requestStatus(portPath: string, timeoutMs: number): Promise<StatusResponse>;
  identifyDevice(
    portPath: string,
    code: string,
    timeoutMs: number,
    durationMs: number,
  ): Promise<IdentifyDeviceResponse>;
}

export class SerialPortUsbDriver implements UsbSerialDriver {
  async listPorts(): Promise<PortInfo[]> {
    return SerialPort.list();
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
  const hasLikelyDescriptor =
    manufacturer.includes("espressif") || pnpId.includes("303a") || pnpId.includes("esp");
  const hasUsbSerialPath = /(^|[/\\])(cu|tty)\.usbmodem/i.test(port.path);

  if (vendorId.length > 0 || productId.length > 0) {
    if (vendorId !== AGENT_Q_USB_VENDOR_ID || productId !== AGENT_Q_USB_PRODUCT_ID) {
      return false;
    }
    return manufacturer.length === 0 && pnpId.length === 0 ? true : hasLikelyDescriptor;
  }

  return hasLikelyDescriptor && hasUsbSerialPath;
}

export async function scanUsbDevices(
  driver: UsbSerialDriver,
  timeoutMs = DEFAULT_SCAN_TIMEOUT_MS,
): Promise<UsbStatusResult[]> {
  const normalizedTimeoutMs = validateTimeoutMs(timeoutMs);
  const ports = await driver.listPorts();
  const candidates = ports.filter(isLikelyAgentQUsbPort);
  const results: UsbStatusResult[] = [];

  for (const candidate of candidates) {
    try {
      const protocolResponse = await driver.requestStatus(candidate.path, normalizedTimeoutMs);
      results.push({
        portPath: candidate.path,
        protocolResponse,
      });
    } catch {
      // Scan only reports confirmed Agent-Q devices. Callers can surface cached
      // status for known devices when a direct status request fails.
    }
  }

  return results;
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

function tryParseMatchingResponseLine<TResponse extends ProtocolResponse>(
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

  if (!isRecord(parsed) || parsed.id !== expectedId) {
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
