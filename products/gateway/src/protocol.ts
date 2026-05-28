import { randomBytes } from "node:crypto";

export const PROTOCOL_VERSION = 1;
export const REQUEST_ID_PATTERN = /^[A-Za-z0-9_.-]{1,79}$/;

export type DeviceState = "idle" | "busy" | "awaiting_approval" | "locked" | "error";

export interface DeviceStatus {
  deviceId: string;
  state: DeviceState;
  firmwareName: string;
  hardware: string;
  firmwareVersion: string;
}

export interface GetStatusRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "get_status";
}

export interface IdentifyDeviceRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "identify_device";
  params: {
    code: string;
    durationMs: number;
  };
}

export type ProtocolRequest = GetStatusRequest | IdentifyDeviceRequest;

export interface StatusResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "status";
  device: DeviceStatus;
}

export interface IdentifyDeviceResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "identify_device_result";
  status: "displayed";
  code: string;
  device: DeviceStatus;
}

export interface ProtocolErrorResponse {
  id?: string;
  version: typeof PROTOCOL_VERSION;
  type: "error";
  error: {
    code: string;
    message: string;
  };
}

export type ProtocolResponse = StatusResponse | IdentifyDeviceResponse | ProtocolErrorResponse;

export class ProtocolError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "ProtocolError";
    this.code = code;
  }
}

export function isSafeRequestId(value: unknown): value is string {
  return typeof value === "string" && REQUEST_ID_PATTERN.test(value);
}

export function createRequestId(): string {
  return `req_${randomBytes(12).toString("hex")}`;
}

export function makeGetStatusRequest(id = createRequestId()): GetStatusRequest {
  if (!isSafeRequestId(id)) {
    throw new ProtocolError("invalid_id", "Invalid request id.");
  }
  return {
    id,
    version: PROTOCOL_VERSION,
    type: "get_status",
  };
}

export function makeIdentifyDeviceRequest(
  code: string,
  durationMs: number,
  id = createRequestId(),
): IdentifyDeviceRequest {
  if (!isSafeRequestId(id)) {
    throw new ProtocolError("invalid_id", "Invalid request id.");
  }
  if (!isIdentificationCode(code)) {
    throw new ProtocolError("invalid_code", "Invalid identification code.");
  }
  if (!Number.isInteger(durationMs) || durationMs <= 0 || durationMs > 30000) {
    throw new ProtocolError("invalid_duration", "Invalid identification duration.");
  }
  return {
    id,
    version: PROTOCOL_VERSION,
    type: "identify_device",
    params: {
      code,
      durationMs,
    },
  };
}

export function createIdentificationCode(): string {
  return (randomBytes(2).readUInt16BE(0) % 10000).toString().padStart(4, "0");
}

export function serializeRequest(request: ProtocolRequest): string {
  return `${JSON.stringify(request)}\n`;
}

export function parseJsonLine(line: string): unknown {
  try {
    return JSON.parse(line);
  } catch {
    throw new ProtocolError("invalid_json", "Invalid JSON response.");
  }
}

export function parseProtocolResponse(line: string, expectedId?: string): ProtocolResponse {
  const value = parseJsonLine(line);
  if (!isRecord(value)) {
    throw new ProtocolError("protocol_error", "Protocol response must be an object.");
  }

  if (value.version !== PROTOCOL_VERSION) {
    throw new ProtocolError("incompatible_version", "Unsupported protocol response version.");
  }

  if (expectedId !== undefined && value.id !== expectedId) {
    throw new ProtocolError("protocol_error", "Protocol response id does not match request id.");
  }

  if (value.type === "error") {
    const error = value.error;
    if (!isRecord(error) || typeof error.code !== "string" || typeof error.message !== "string") {
      throw new ProtocolError("protocol_error", "Protocol error response is malformed.");
    }
    return {
      id: typeof value.id === "string" ? value.id : undefined,
      version: PROTOCOL_VERSION,
      type: "error",
      error: {
        code: error.code,
        message: error.message,
      },
    };
  }

  if (value.type === "status") {
    const device = value.device;
    if (!isDeviceStatus(device)) {
      throw new ProtocolError("protocol_error", "Status response device object is malformed.");
    }
    if (typeof value.id !== "string") {
      throw new ProtocolError("protocol_error", "Status response id is malformed.");
    }

    return {
      id: value.id,
      version: PROTOCOL_VERSION,
      type: "status",
      device,
    };
  }

  if (value.type === "identify_device_result") {
    const device = value.device;
    if (!isDeviceStatus(device)) {
      throw new ProtocolError("protocol_error", "Identify response device object is malformed.");
    }
    if (typeof value.id !== "string" || value.status !== "displayed" || !isIdentificationCode(value.code)) {
      throw new ProtocolError("protocol_error", "Identify response is malformed.");
    }

    return {
      id: value.id,
      version: PROTOCOL_VERSION,
      type: "identify_device_result",
      status: "displayed",
      code: value.code,
      device,
    };
  }

  throw new ProtocolError("protocol_error", "Protocol response type is unsupported.");
}

export function assertStatusResponse(response: ProtocolResponse): StatusResponse {
  if (response.type === "error") {
    throw new ProtocolError(response.error.code, response.error.message);
  }
  if (response.type !== "status") {
    throw new ProtocolError("protocol_error", "Protocol response type is not status.");
  }
  return response;
}

export function assertIdentifyDeviceResponse(response: ProtocolResponse): IdentifyDeviceResponse {
  if (response.type === "error") {
    throw new ProtocolError(response.error.code, response.error.message);
  }
  if (response.type !== "identify_device_result") {
    throw new ProtocolError("protocol_error", "Protocol response type is not identify_device_result.");
  }
  return response;
}

function isDeviceStatus(value: unknown): value is DeviceStatus {
  if (!isRecord(value)) {
    return false;
  }
  return (
    typeof value.deviceId === "string" &&
    isDeviceState(value.state) &&
    typeof value.firmwareName === "string" &&
    typeof value.hardware === "string" &&
    typeof value.firmwareVersion === "string"
  );
}

function isDeviceState(value: unknown): value is DeviceState {
  return (
    value === "idle" ||
    value === "busy" ||
    value === "awaiting_approval" ||
    value === "locked" ||
    value === "error"
  );
}

function isIdentificationCode(value: unknown): value is string {
  return typeof value === "string" && /^[0-9]{4}$/.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
