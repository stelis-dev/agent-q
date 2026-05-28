import { randomBytes } from "node:crypto";

export const PROTOCOL_VERSION = 1;
export const REQUEST_ID_PATTERN = /^[A-Za-z0-9_.-]{1,79}$/;
export const SESSION_ID_PATTERN = /^session_[0-9a-f]{1,128}$/;
export const GATEWAY_NAME_PATTERN = /^[\x20-\x7E]{1,64}$/;
export const MAX_APPROVAL_TIMEOUT_MS = 60000;
export const DEFAULT_APPROVAL_TIMEOUT_MS = 30000;

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

export interface ConnectRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "connect";
  params: {
    gatewayName: string;
    approvalTimeoutMs: number;
  };
}

export interface DisconnectRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "disconnect";
  sessionId: string;
}

export type ProtocolRequest =
  | GetStatusRequest
  | IdentifyDeviceRequest
  | ConnectRequest
  | DisconnectRequest;

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

export interface ConnectApprovedResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "connect_result";
  status: "approved";
  sessionId: string;
  sessionTtlMs: number;
  device: DeviceStatus;
}

export interface ConnectRejectedResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "connect_result";
  status: "rejected";
  error: {
    code: string;
    message: string;
  };
}

export type ConnectResponse = ConnectApprovedResponse | ConnectRejectedResponse;

export interface DisconnectResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "disconnect_result";
  status: "disconnected";
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

export type ProtocolResponse =
  | StatusResponse
  | IdentifyDeviceResponse
  | ConnectResponse
  | DisconnectResponse
  | ProtocolErrorResponse;

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

export function makeConnectRequest(
  gatewayName: string,
  approvalTimeoutMs: number = DEFAULT_APPROVAL_TIMEOUT_MS,
  id = createRequestId(),
): ConnectRequest {
  if (!isSafeRequestId(id)) {
    throw new ProtocolError("invalid_id", "Invalid request id.");
  }
  if (!isGatewayName(gatewayName)) {
    throw new ProtocolError(
      "invalid_gateway_name",
      "gatewayName must be 1-64 printable ASCII characters.",
    );
  }
  if (
    !Number.isInteger(approvalTimeoutMs) ||
    approvalTimeoutMs <= 0 ||
    approvalTimeoutMs > MAX_APPROVAL_TIMEOUT_MS
  ) {
    throw new ProtocolError(
      "invalid_approval_timeout",
      `approvalTimeoutMs must be a positive integer <= ${MAX_APPROVAL_TIMEOUT_MS}.`,
    );
  }
  return {
    id,
    version: PROTOCOL_VERSION,
    type: "connect",
    params: {
      gatewayName,
      approvalTimeoutMs,
    },
  };
}

export function makeDisconnectRequest(sessionId: string, id = createRequestId()): DisconnectRequest {
  if (!isSafeRequestId(id)) {
    throw new ProtocolError("invalid_id", "Invalid request id.");
  }
  if (!isSessionId(sessionId)) {
    throw new ProtocolError("invalid_session", "Invalid sessionId.");
  }
  return {
    id,
    version: PROTOCOL_VERSION,
    type: "disconnect",
    sessionId,
  };
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

  if (value.type === "connect_result") {
    if (typeof value.id !== "string") {
      throw new ProtocolError("protocol_error", "Connect response id is malformed.");
    }

    if (value.status === "approved") {
      const device = value.device;
      if (!isDeviceStatus(device)) {
        throw new ProtocolError("protocol_error", "Connect response device object is malformed.");
      }
      if (!isSessionId(value.sessionId)) {
        throw new ProtocolError("protocol_error", "Connect response sessionId is malformed.");
      }
      if (
        typeof value.sessionTtlMs !== "number" ||
        !Number.isInteger(value.sessionTtlMs) ||
        value.sessionTtlMs <= 0
      ) {
        throw new ProtocolError("protocol_error", "Connect response sessionTtlMs is malformed.");
      }
      return {
        id: value.id,
        version: PROTOCOL_VERSION,
        type: "connect_result",
        status: "approved",
        sessionId: value.sessionId,
        sessionTtlMs: value.sessionTtlMs,
        device,
      };
    }

    if (value.status === "rejected") {
      const error = value.error;
      if (!isRecord(error) || typeof error.code !== "string" || typeof error.message !== "string") {
        throw new ProtocolError("protocol_error", "Connect rejected response error object is malformed.");
      }
      return {
        id: value.id,
        version: PROTOCOL_VERSION,
        type: "connect_result",
        status: "rejected",
        error: {
          code: error.code,
          message: error.message,
        },
      };
    }

    throw new ProtocolError("protocol_error", "Connect response status is unsupported.");
  }

  if (value.type === "disconnect_result") {
    if (typeof value.id !== "string" || value.status !== "disconnected") {
      throw new ProtocolError("protocol_error", "Disconnect response is malformed.");
    }
    return {
      id: value.id,
      version: PROTOCOL_VERSION,
      type: "disconnect_result",
      status: "disconnected",
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

export function assertConnectResponse(response: ProtocolResponse): ConnectResponse {
  if (response.type === "error") {
    throw new ProtocolError(response.error.code, response.error.message);
  }
  if (response.type !== "connect_result") {
    throw new ProtocolError("protocol_error", "Protocol response type is not connect_result.");
  }
  return response;
}

export function assertDisconnectResponse(response: ProtocolResponse): DisconnectResponse {
  if (response.type === "error") {
    throw new ProtocolError(response.error.code, response.error.message);
  }
  if (response.type !== "disconnect_result") {
    throw new ProtocolError("protocol_error", "Protocol response type is not disconnect_result.");
  }
  return response;
}

export function isSessionId(value: unknown): value is string {
  return typeof value === "string" && SESSION_ID_PATTERN.test(value);
}

export function isGatewayName(value: unknown): value is string {
  return typeof value === "string" && GATEWAY_NAME_PATTERN.test(value);
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
