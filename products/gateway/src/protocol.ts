import { randomBytes } from "node:crypto";
import {
  IDENTIFICATION_CODE_PATTERN,
  MAX_FIRMWARE_NAME_LENGTH,
  MAX_FIRMWARE_VERSION_LENGTH,
  MAX_HARDWARE_ID_LENGTH,
  isDeviceState,
  isGatewayName,
  isProvisioningState,
  isSafeDeviceId,
  isSafeRequestId,
  isSessionId,
  sanitizeDisplayText,
  type DeviceState,
  type ProvisioningState,
} from "./safe-text.js";

// These boundary helpers are defined once in safe-text.ts (the single source of
// truth) and re-exported here because protocol.ts is the wire-ingress boundary
// that applies them; existing importers and tests resolve them via protocol.ts.
export { isGatewayName, isSafeDeviceId, isSafeRequestId, isSessionId, sanitizeDisplayText };
export type { DeviceState, ProvisioningState };

export const PROTOCOL_VERSION = 1;
export const MAX_APPROVAL_TIMEOUT_MS = 60000;
export const DEFAULT_APPROVAL_TIMEOUT_MS = 30000;
export const MAX_PROVISIONING_APPROVAL_TIMEOUT_MS = MAX_APPROVAL_TIMEOUT_MS;
export const DEFAULT_PROVISIONING_APPROVAL_TIMEOUT_MS = DEFAULT_APPROVAL_TIMEOUT_MS;
// sessionTtlMs is a uint32 millisecond counter on the wire (see the firmware's
// kSessionTtlMs). A value outside that range cannot come from a conformant
// device, so the wire boundary rejects it as malformed. Bounding it here also
// keeps Gateway's session-expiry arithmetic (connectedAt + sessionTtlMs) far
// inside the representable Date range, so recording a session can never throw a
// RangeError after the connect was physically approved.
export const MAX_SESSION_TTL_MS = 4_294_967_295;

export interface DeviceStatus {
  deviceId: string;
  state: DeviceState;
  firmwareName: string;
  hardware: string;
  firmwareVersion: string;
}

export interface ProvisioningStatus {
  state: ProvisioningState;
}

export interface DeviceStatusSnapshot {
  device: DeviceStatus;
  provisioning: ProvisioningStatus;
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

export interface StartProvisioningRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "start_provisioning";
  params: {
    approvalTimeoutMs: number;
  };
}

export interface CancelProvisioningRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "cancel_provisioning";
  params: {
    approvalTimeoutMs: number;
  };
}

export type ProtocolRequest =
  | GetStatusRequest
  | IdentifyDeviceRequest
  | ConnectRequest
  | DisconnectRequest
  | StartProvisioningRequest
  | CancelProvisioningRequest;

export interface StatusResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "status";
  device: DeviceStatus;
  provisioning: ProvisioningStatus;
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

export interface ProvisioningResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "provisioning_result";
  status: "started" | "canceled";
  provisioning: ProvisioningStatus;
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
  | ProvisioningResponse
  | ProtocolErrorResponse;

export class ProtocolError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "ProtocolError";
    this.code = code;
  }
}

export function createRequestId(): string {
  return `req_${randomBytes(12).toString("hex")}`;
}

export function makeGetStatusRequest(id = createRequestId()): GetStatusRequest {
  validateRequestId(id);
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
  validateRequestId(id);
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
  validateRequestId(id);
  if (!isGatewayName(gatewayName)) {
    throw new ProtocolError(
      "invalid_gateway_name",
      "gatewayName must be 1-64 printable ASCII characters.",
    );
  }
  validateApprovalTimeoutMs(approvalTimeoutMs);
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
  validateRequestId(id);
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

export function makeStartProvisioningRequest(
  approvalTimeoutMs: number = DEFAULT_PROVISIONING_APPROVAL_TIMEOUT_MS,
  id = createRequestId(),
): StartProvisioningRequest {
  validateRequestId(id);
  validateApprovalTimeoutMs(approvalTimeoutMs);
  return {
    id,
    version: PROTOCOL_VERSION,
    type: "start_provisioning",
    params: {
      approvalTimeoutMs,
    },
  };
}

export function makeCancelProvisioningRequest(
  approvalTimeoutMs: number = DEFAULT_PROVISIONING_APPROVAL_TIMEOUT_MS,
  id = createRequestId(),
): CancelProvisioningRequest {
  validateRequestId(id);
  validateApprovalTimeoutMs(approvalTimeoutMs);
  return {
    id,
    version: PROTOCOL_VERSION,
    type: "cancel_provisioning",
    params: {
      approvalTimeoutMs,
    },
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
    const device = sanitizeDeviceStatus(value.device);
    if (device === null) {
      throw new ProtocolError("protocol_error", "Status response device object is malformed.");
    }
    const provisioning = sanitizeProvisioningStatus(value.provisioning);
    if (provisioning === null) {
      throw new ProtocolError("protocol_error", "Status response provisioning object is malformed.");
    }
    if (typeof value.id !== "string") {
      throw new ProtocolError("protocol_error", "Status response id is malformed.");
    }

    return {
      id: value.id,
      version: PROTOCOL_VERSION,
      type: "status",
      device,
      provisioning,
    };
  }

  if (value.type === "identify_device_result") {
    const device = sanitizeDeviceStatus(value.device);
    if (device === null) {
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
      const device = sanitizeDeviceStatus(value.device);
      if (device === null) {
        throw new ProtocolError("protocol_error", "Connect response device object is malformed.");
      }
      if (!isSessionId(value.sessionId)) {
        throw new ProtocolError("protocol_error", "Connect response sessionId is malformed.");
      }
      if (
        typeof value.sessionTtlMs !== "number" ||
        !Number.isInteger(value.sessionTtlMs) ||
        value.sessionTtlMs <= 0 ||
        value.sessionTtlMs > MAX_SESSION_TTL_MS
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

  if (value.type === "provisioning_result") {
    if (typeof value.id !== "string" || (value.status !== "started" && value.status !== "canceled")) {
      throw new ProtocolError("protocol_error", "Provisioning response is malformed.");
    }
    const provisioning = sanitizeProvisioningStatus(value.provisioning);
    if (provisioning === null) {
      throw new ProtocolError("protocol_error", "Provisioning response state is malformed.");
    }
    const expectedState = value.status === "started" ? "provisioning" : "unprovisioned";
    if (provisioning.state !== expectedState) {
      throw new ProtocolError("protocol_error", "Provisioning response status and state disagree.");
    }
    return {
      id: value.id,
      version: PROTOCOL_VERSION,
      type: "provisioning_result",
      status: value.status,
      provisioning,
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

export function assertProvisioningResponse(response: ProtocolResponse): ProvisioningResponse {
  if (response.type === "error") {
    throw new ProtocolError(response.error.code, response.error.message);
  }
  if (response.type !== "provisioning_result") {
    throw new ProtocolError("protocol_error", "Protocol response type is not provisioning_result.");
  }
  return response;
}

// Reduce an untrusted wire or stored device object to a safe DeviceStatus, or
// null when its identity fields are unusable. deviceId and state are REJECTED
// when malformed (returns null); the display strings are sanitized to bounded
// printable ASCII. Shared by the wire boundary (above) and the disk boundary
// (config.ts) so both apply the identical policy.
export function sanitizeDeviceStatus(value: unknown): DeviceStatus | null {
  if (!isRecord(value) || !isSafeDeviceId(value.deviceId) || !isDeviceState(value.state)) {
    return null;
  }
  return {
    deviceId: value.deviceId,
    state: value.state,
    firmwareName: sanitizeDisplayText(value.firmwareName, MAX_FIRMWARE_NAME_LENGTH),
    hardware: sanitizeDisplayText(value.hardware, MAX_HARDWARE_ID_LENGTH),
    firmwareVersion: sanitizeDisplayText(value.firmwareVersion, MAX_FIRMWARE_VERSION_LENGTH),
  };
}

export function sanitizeProvisioningStatus(value: unknown): ProvisioningStatus | null {
  if (!isRecord(value) || !isProvisioningState(value.state)) {
    return null;
  }
  return { state: value.state };
}

export function sanitizeDeviceStatusSnapshot(value: unknown): DeviceStatusSnapshot | null {
  if (!isRecord(value)) {
    return null;
  }
  const device = sanitizeDeviceStatus(value.device);
  const provisioning = sanitizeProvisioningStatus(value.provisioning);
  if (device === null || provisioning === null) {
    return null;
  }
  return { device, provisioning };
}

function isIdentificationCode(value: unknown): value is string {
  return typeof value === "string" && IDENTIFICATION_CODE_PATTERN.test(value);
}

function validateRequestId(id: string): void {
  if (!isSafeRequestId(id)) {
    throw new ProtocolError("invalid_id", "Invalid request id.");
  }
}

function validateApprovalTimeoutMs(approvalTimeoutMs: number): void {
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
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
