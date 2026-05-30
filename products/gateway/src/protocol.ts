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
// sessionTtlMs is a uint32 millisecond counter on the wire. A value outside
// that range cannot come from a conformant device, so the wire boundary rejects
// it as malformed. Bounding it here also keeps Gateway's session-expiry
// arithmetic (connectedAt + sessionTtlMs) far inside the representable Date
// range, so recording a session can never throw a RangeError after the connect
// was physically approved.
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

export interface GetCapabilitiesRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "get_capabilities";
  sessionId: string;
}

export interface GetAccountsRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "get_accounts";
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

export interface ConfirmRecoveryPhraseBackupRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "confirm_recovery_phrase_backup";
  params: {
    approvalTimeoutMs: number;
  };
}

export interface FactoryResetRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "factory_reset";
  params: {
    approvalTimeoutMs: number;
  };
}

export type ProtocolRequest =
  | GetStatusRequest
  | IdentifyDeviceRequest
  | ConnectRequest
  | DisconnectRequest
  | GetCapabilitiesRequest
  | GetAccountsRequest
  | StartProvisioningRequest
  | CancelProvisioningRequest
  | ConfirmRecoveryPhraseBackupRequest
  | FactoryResetRequest;

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

export interface CapabilityAccount {
  keyScheme: string;
  derivationPath: string;
}

export interface CapabilityChain {
  id: string;
  accounts: CapabilityAccount[];
  methods: string[];
}

export interface CapabilitiesResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "capabilities";
  chains: CapabilityChain[];
}

// Public account identity only. Never carries mnemonic, seed, entropy, or any
// private/signing key material. publicKey is the raw 32-byte Ed25519 key as
// base64; the scheme is reported separately as keyScheme. The shape is
// chain-agnostic so future chains are added as additional accounts[] entries.
export interface Account {
  chain: string;
  address: string;
  publicKey: string;
  keyScheme: string;
  derivationPath: string;
}

export interface AccountsResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "accounts";
  accounts: Account[];
}

export interface ProvisioningResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "provisioning_result";
  status: "canceled";
  provisioning: ProvisioningStatus;
}

export interface RecoveryPhraseResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "recovery_phrase_result";
  status: "displayed" | "confirmed";
  provisioning: ProvisioningStatus;
}

export interface FactoryResetResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "factory_reset_result";
  status: "reset";
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
  | CapabilitiesResponse
  | AccountsResponse
  | ProvisioningResponse
  | RecoveryPhraseResponse
  | FactoryResetResponse
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

export function makeGetCapabilitiesRequest(
  sessionId: string,
  id = createRequestId(),
): GetCapabilitiesRequest {
  validateRequestId(id);
  if (!isSessionId(sessionId)) {
    throw new ProtocolError("invalid_session", "Invalid sessionId.");
  }
  return {
    id,
    version: PROTOCOL_VERSION,
    type: "get_capabilities",
    sessionId,
  };
}

export function makeGetAccountsRequest(sessionId: string, id = createRequestId()): GetAccountsRequest {
  validateRequestId(id);
  if (!isSessionId(sessionId)) {
    throw new ProtocolError("invalid_session", "Invalid sessionId.");
  }
  return {
    id,
    version: PROTOCOL_VERSION,
    type: "get_accounts",
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

export function makeConfirmRecoveryPhraseBackupRequest(
  approvalTimeoutMs: number = DEFAULT_PROVISIONING_APPROVAL_TIMEOUT_MS,
  id = createRequestId(),
): ConfirmRecoveryPhraseBackupRequest {
  validateRequestId(id);
  validateApprovalTimeoutMs(approvalTimeoutMs);
  return {
    id,
    version: PROTOCOL_VERSION,
    type: "confirm_recovery_phrase_backup",
    params: {
      approvalTimeoutMs,
    },
  };
}

export function makeFactoryResetRequest(
  approvalTimeoutMs: number = DEFAULT_PROVISIONING_APPROVAL_TIMEOUT_MS,
  id = createRequestId(),
): FactoryResetRequest {
  validateRequestId(id);
  validateApprovalTimeoutMs(approvalTimeoutMs);
  return {
    id,
    version: PROTOCOL_VERSION,
    type: "factory_reset",
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

  if (value.type === "capabilities") {
    if (typeof value.id !== "string") {
      throw new ProtocolError("protocol_error", "Capabilities response id is malformed.");
    }
    if (hasSecretPayloadKey(value)) {
      throw new ProtocolError("protocol_error", "Capabilities response must not include secret material.");
    }
    if (!hasOnlyObjectKeys(value, ["id", "version", "type", "chains"])) {
      throw new ProtocolError("protocol_error", "Capabilities response contains unsupported fields.");
    }
    if (!Array.isArray(value.chains)) {
      throw new ProtocolError("protocol_error", "Capabilities response chains must be an array.");
    }
    if (value.chains.length !== MAX_CAPABILITY_CHAINS) {
      throw new ProtocolError("protocol_error", "Capabilities response has an unsupported chain count.");
    }
    return {
      id: value.id,
      version: PROTOCOL_VERSION,
      type: "capabilities",
      chains: value.chains.map((entry) => sanitizeCapabilityChain(entry)),
    };
  }

  if (value.type === "provisioning_result") {
    if (typeof value.id !== "string" || value.status !== "canceled") {
      throw new ProtocolError("protocol_error", "Provisioning response is malformed.");
    }
    const provisioning = sanitizeProvisioningStatus(value.provisioning);
    if (provisioning === null) {
      throw new ProtocolError("protocol_error", "Provisioning response state is malformed.");
    }
    if (provisioning.state !== "unprovisioned") {
      throw new ProtocolError("protocol_error", "Provisioning cancellation response requires unprovisioned state.");
    }
    return {
      id: value.id,
      version: PROTOCOL_VERSION,
      type: "provisioning_result",
      status: value.status,
      provisioning,
    };
  }

  if (value.type === "recovery_phrase_result") {
    if (
      typeof value.id !== "string" ||
      (value.status !== "displayed" && value.status !== "confirmed")
    ) {
      throw new ProtocolError("protocol_error", "Recovery phrase response is malformed.");
    }
    if (hasSecretPayloadKey(value)) {
      throw new ProtocolError("protocol_error", "Recovery phrase response must not include secret material.");
    }
    if (!hasOnlyObjectKeys(value, ["id", "version", "type", "status", "provisioning"])) {
      throw new ProtocolError("protocol_error", "Recovery phrase response contains unsupported fields.");
    }
    if (!isRecord(value.provisioning) || !hasOnlyObjectKeys(value.provisioning, ["state"])) {
      throw new ProtocolError("protocol_error", "Recovery phrase response state is malformed.");
    }
    const provisioning = sanitizeProvisioningStatus(value.provisioning);
    if (provisioning === null) {
      throw new ProtocolError("protocol_error", "Recovery phrase response state is malformed.");
    }
    const expectedState = value.status === "displayed" ? "unprovisioned" : "provisioned";
    if (provisioning.state !== expectedState) {
      throw new ProtocolError("protocol_error", "Recovery phrase response status and state disagree.");
    }
    return {
      id: value.id,
      version: PROTOCOL_VERSION,
      type: "recovery_phrase_result",
      status: value.status,
      provisioning,
    };
  }

  if (value.type === "factory_reset_result") {
    if (typeof value.id !== "string" || value.status !== "reset") {
      throw new ProtocolError("protocol_error", "Factory reset response is malformed.");
    }
    if (!hasOnlyObjectKeys(value, ["id", "version", "type", "status", "provisioning"])) {
      throw new ProtocolError("protocol_error", "Factory reset response contains unsupported fields.");
    }
    if (!isRecord(value.provisioning) || !hasOnlyObjectKeys(value.provisioning, ["state"])) {
      throw new ProtocolError("protocol_error", "Factory reset response state is malformed.");
    }
    const provisioning = sanitizeProvisioningStatus(value.provisioning);
    if (provisioning === null) {
      throw new ProtocolError("protocol_error", "Factory reset response state is malformed.");
    }
    if (provisioning.state !== "unprovisioned") {
      throw new ProtocolError("protocol_error", "Factory reset response requires unprovisioned state.");
    }
    return {
      id: value.id,
      version: PROTOCOL_VERSION,
      type: "factory_reset_result",
      status: "reset",
      provisioning,
    };
  }

  if (value.type === "accounts") {
    if (typeof value.id !== "string") {
      throw new ProtocolError("protocol_error", "Accounts response id is malformed.");
    }
    if (hasSecretPayloadKey(value)) {
      throw new ProtocolError("protocol_error", "Accounts response must not include secret material.");
    }
    if (!hasOnlyObjectKeys(value, ["id", "version", "type", "accounts"])) {
      throw new ProtocolError("protocol_error", "Accounts response contains unsupported fields.");
    }
    if (!Array.isArray(value.accounts)) {
      throw new ProtocolError("protocol_error", "Accounts response accounts must be an array.");
    }
    if (value.accounts.length !== MAX_ACCOUNTS_PER_RESPONSE) {
      throw new ProtocolError("protocol_error", "Accounts response has an unsupported account count.");
    }
    return {
      id: value.id,
      version: PROTOCOL_VERSION,
      type: "accounts",
      accounts: value.accounts.map((entry) => sanitizeAccount(entry)),
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

export function assertCapabilitiesResponse(response: ProtocolResponse): CapabilitiesResponse {
  if (response.type === "error") {
    throw new ProtocolError(response.error.code, response.error.message);
  }
  if (response.type !== "capabilities") {
    throw new ProtocolError("protocol_error", "Protocol response type is not capabilities.");
  }
  return response;
}

export function assertAccountsResponse(response: ProtocolResponse): AccountsResponse {
  if (response.type === "error") {
    throw new ProtocolError(response.error.code, response.error.message);
  }
  if (response.type !== "accounts") {
    throw new ProtocolError("protocol_error", "Protocol response type is not accounts.");
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

export function assertRecoveryPhraseResponse(response: ProtocolResponse): RecoveryPhraseResponse {
  if (response.type === "error") {
    throw new ProtocolError(response.error.code, response.error.message);
  }
  if (response.type !== "recovery_phrase_result") {
    throw new ProtocolError("protocol_error", "Protocol response type is not recovery_phrase_result.");
  }
  return response;
}

export function assertFactoryResetResponse(response: ProtocolResponse): FactoryResetResponse {
  if (response.type === "error") {
    throw new ProtocolError(response.error.code, response.error.message);
  }
  if (response.type !== "factory_reset_result") {
    throw new ProtocolError("protocol_error", "Protocol response type is not factory_reset_result.");
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

export const SUI_ADDRESS_PATTERN = /^0x[0-9a-f]{64}$/;
// Raw 32-byte Ed25519 public key as base64 is exactly 43 payload chars + one "=".
export const ED25519_PUBLIC_KEY_BASE64_PATTERN = /^[A-Za-z0-9+/]{43}=$/;
export const SUI_DERIVATION_PATH = "m/44'/784'/0'/0'/0'";
export const MAX_CAPABILITY_CHAINS = 1;
export const MAX_CAPABILITY_ACCOUNTS_PER_CHAIN = 1;
// The current target implements exactly one account (Sui Ed25519 account 0). Bound
// the accounts array so a buggy or spoofed device cannot inflate the MCP result or
// imply multi-account support that does not exist. Raise this as more accounts or
// chains are actually implemented.
export const MAX_ACCOUNTS_PER_RESPONSE = 1;
export const FORBIDDEN_SECRET_FIELD_NAMES = [
  "entropy",
  "mnemonic",
  "phrase",
  "prefixes",
  "privateKey",
  "private_key",
  "privateMaterial",
  "private_material",
  "recoveryPhrase",
  "recovery_phrase",
  "rootEntropy",
  "root_entropy",
  "rootMaterial",
  "root_material",
  "secret",
  "seed",
  "signingKey",
  "signing_key",
  "words",
] as const;
const FORBIDDEN_SECRET_FIELD_NAME_SET = new Set(
  FORBIDDEN_SECRET_FIELD_NAMES.map((fieldName) => fieldName.toLowerCase()),
);

const U64_MASK = (1n << 64n) - 1n;
const BLAKE2B_BLOCK_BYTES = 128;
const BLAKE2B_256_BYTES = 32;
const BLAKE2B_IV = [
  0x6a09e667f3bcc908n,
  0xbb67ae8584caa73bn,
  0x3c6ef372fe94f82bn,
  0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n,
  0x9b05688c2b3e6c1fn,
  0x1f83d9abfb41bd6bn,
  0x5be0cd19137e2179n,
] as const;
const BLAKE2B_SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
] as const;

function add64(...values: bigint[]): bigint {
  return values.reduce((sum, value) => (sum + value) & U64_MASK, 0n);
}

function rotr64(value: bigint, shift: number): bigint {
  return ((value >> BigInt(shift)) | (value << BigInt(64 - shift))) & U64_MASK;
}

function readU64Le(input: Uint8Array, offset: number): bigint {
  let value = 0n;
  for (let index = 0; index < 8; ++index) {
    value |= BigInt(input[offset + index] ?? 0) << BigInt(index * 8);
  }
  return value;
}

function writeU64Le(output: Uint8Array, offset: number, value: bigint): void {
  for (let index = 0; index < 8; ++index) {
    output[offset + index] = Number((value >> BigInt(index * 8)) & 0xffn);
  }
}

function blake2bCompress(h: bigint[], block: Uint8Array, bytesCompressed: bigint, isLast: boolean): void {
  const m = Array.from({ length: 16 }, (_, index) => readU64Le(block, index * 8));
  const v = [...h, ...BLAKE2B_IV];
  v[12] ^= bytesCompressed & U64_MASK;
  v[13] ^= bytesCompressed >> 64n;
  if (isLast) {
    v[14] ^= U64_MASK;
  }

  const g = (a: number, b: number, c: number, d: number, x: number, y: number) => {
    v[a] = add64(v[a], v[b], m[x]);
    v[d] = rotr64(v[d] ^ v[a], 32);
    v[c] = add64(v[c], v[d]);
    v[b] = rotr64(v[b] ^ v[c], 24);
    v[a] = add64(v[a], v[b], m[y]);
    v[d] = rotr64(v[d] ^ v[a], 16);
    v[c] = add64(v[c], v[d]);
    v[b] = rotr64(v[b] ^ v[c], 63);
  };

  for (let round = 0; round < 12; ++round) {
    const sigma = BLAKE2B_SIGMA[round % BLAKE2B_SIGMA.length];
    g(0, 4, 8, 12, sigma[0], sigma[1]);
    g(1, 5, 9, 13, sigma[2], sigma[3]);
    g(2, 6, 10, 14, sigma[4], sigma[5]);
    g(3, 7, 11, 15, sigma[6], sigma[7]);
    g(0, 5, 10, 15, sigma[8], sigma[9]);
    g(1, 6, 11, 12, sigma[10], sigma[11]);
    g(2, 7, 8, 13, sigma[12], sigma[13]);
    g(3, 4, 9, 14, sigma[14], sigma[15]);
  }

  for (let index = 0; index < h.length; ++index) {
    h[index] = (h[index] ^ v[index] ^ v[index + 8]) & U64_MASK;
  }
}

function blake2b256(input: Uint8Array): Uint8Array {
  const h = [...BLAKE2B_IV];
  h[0] ^= 0x01010000n ^ BigInt(BLAKE2B_256_BYTES);

  let offset = 0;
  let bytesCompressed = 0n;
  while (offset + BLAKE2B_BLOCK_BYTES < input.length) {
    bytesCompressed += BigInt(BLAKE2B_BLOCK_BYTES);
    blake2bCompress(h, input.subarray(offset, offset + BLAKE2B_BLOCK_BYTES), bytesCompressed, false);
    offset += BLAKE2B_BLOCK_BYTES;
  }

  const finalBlock = new Uint8Array(BLAKE2B_BLOCK_BYTES);
  const remaining = input.subarray(offset);
  finalBlock.set(remaining);
  bytesCompressed += BigInt(remaining.length);
  blake2bCompress(h, finalBlock, bytesCompressed, true);

  const digest = new Uint8Array(BLAKE2B_256_BYTES);
  for (let index = 0; index < BLAKE2B_256_BYTES / 8; ++index) {
    writeU64Le(digest, index * 8, h[index]);
  }
  return digest;
}

function hexLower(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function deriveSuiAddressFromPublicKey(publicKeyBase64: string): string | null {
  const publicKey = Buffer.from(publicKeyBase64, "base64");
  if (publicKey.length !== 32 || publicKey.toString("base64") !== publicKeyBase64) {
    return null;
  }

  const addressInput = new Uint8Array(33);
  addressInput[0] = 0x00; // Sui Ed25519 scheme flag.
  addressInput.set(publicKey, 1);
  return `0x${hexLower(blake2b256(addressInput))}`;
}

export function isSuiAddressForPublicKey(address: string, publicKeyBase64: string): boolean {
  if (!SUI_ADDRESS_PATTERN.test(address) || !ED25519_PUBLIC_KEY_BASE64_PATTERN.test(publicKeyBase64)) {
    return false;
  }
  const expectedAddress = deriveSuiAddressFromPublicKey(publicKeyBase64);
  return expectedAddress !== null && address === expectedAddress;
}

function sanitizeCapabilityAccount(value: unknown): CapabilityAccount {
  if (!isRecord(value)) {
    throw new ProtocolError("protocol_error", "Capability account entry is malformed.");
  }
  if (hasSecretPayloadKey(value)) {
    throw new ProtocolError("protocol_error", "Capability account entry must not include secret material.");
  }
  if (!hasOnlyObjectKeys(value, ["keyScheme", "derivationPath"])) {
    throw new ProtocolError("protocol_error", "Capability account entry contains unsupported fields.");
  }
  if (value.keyScheme !== "ed25519") {
    throw new ProtocolError("protocol_error", "Capability account keyScheme is unsupported.");
  }
  if (value.derivationPath !== SUI_DERIVATION_PATH) {
    throw new ProtocolError("protocol_error", "Capability account derivationPath is unsupported.");
  }
  return {
    keyScheme: value.keyScheme,
    derivationPath: value.derivationPath,
  };
}

function sanitizeCapabilityChain(value: unknown): CapabilityChain {
  if (!isRecord(value)) {
    throw new ProtocolError("protocol_error", "Capability chain entry is malformed.");
  }
  if (hasSecretPayloadKey(value)) {
    throw new ProtocolError("protocol_error", "Capability chain entry must not include secret material.");
  }
  if (!hasOnlyObjectKeys(value, ["id", "accounts", "methods"])) {
    throw new ProtocolError("protocol_error", "Capability chain entry contains unsupported fields.");
  }
  if (value.id !== "sui") {
    throw new ProtocolError("protocol_error", "Capability chain is unsupported.");
  }
  if (!Array.isArray(value.accounts)) {
    throw new ProtocolError("protocol_error", "Capability accounts must be an array.");
  }
  if (value.accounts.length !== MAX_CAPABILITY_ACCOUNTS_PER_CHAIN) {
    throw new ProtocolError("protocol_error", "Capability account count is unsupported.");
  }
  if (!Array.isArray(value.methods)) {
    throw new ProtocolError("protocol_error", "Capability methods must be an array.");
  }
  if (value.methods.length !== 0) {
    throw new ProtocolError("protocol_error", "Capability method is unsupported.");
  }
  return {
    id: "sui",
    accounts: value.accounts.map((entry) => sanitizeCapabilityAccount(entry)),
    methods: [],
  };
}

// Reduce an untrusted account entry to a safe Account or throw. Enforces the Sui
// Ed25519 account-0 shape, rejects any secret-like or unexpected field, and
// rejects unknown chains rather than passing them through, so an unsupported
// chain never looks supported. Extend per chain as more chains are implemented.
function sanitizeAccount(value: unknown): Account {
  if (!isRecord(value)) {
    throw new ProtocolError("protocol_error", "Account entry is malformed.");
  }
  if (hasSecretPayloadKey(value)) {
    throw new ProtocolError("protocol_error", "Account entry must not include secret material.");
  }
  if (!hasOnlyObjectKeys(value, ["chain", "address", "publicKey", "keyScheme", "derivationPath"])) {
    throw new ProtocolError("protocol_error", "Account entry contains unsupported fields.");
  }
  if (value.chain !== "sui") {
    throw new ProtocolError("protocol_error", "Account chain is unsupported.");
  }
  if (typeof value.address !== "string" || !SUI_ADDRESS_PATTERN.test(value.address)) {
    throw new ProtocolError("protocol_error", "Account address is malformed.");
  }
  if (typeof value.publicKey !== "string" || !ED25519_PUBLIC_KEY_BASE64_PATTERN.test(value.publicKey)) {
    throw new ProtocolError("protocol_error", "Account publicKey is malformed.");
  }
  if (!isSuiAddressForPublicKey(value.address, value.publicKey)) {
    throw new ProtocolError("protocol_error", "Account address does not match publicKey.");
  }
  if (value.keyScheme !== "ed25519") {
    throw new ProtocolError("protocol_error", "Account keyScheme is unsupported.");
  }
  if (value.derivationPath !== SUI_DERIVATION_PATH) {
    throw new ProtocolError("protocol_error", "Account derivationPath is unsupported.");
  }
  return {
    chain: value.chain,
    address: value.address,
    publicKey: value.publicKey,
    keyScheme: value.keyScheme,
    derivationPath: value.derivationPath,
  };
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

function hasSecretPayloadKey(value: unknown): boolean {
  if (Array.isArray(value)) {
    return value.some((item) => hasSecretPayloadKey(item));
  }
  if (!isRecord(value)) {
    return false;
  }
  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN_SECRET_FIELD_NAME_SET.has(key.toLowerCase())) {
      return true;
    }
    if (hasSecretPayloadKey(child)) {
      return true;
    }
  }
  return false;
}

function hasOnlyObjectKeys(value: Record<string, unknown>, allowedKeys: readonly string[]): boolean {
  return Object.keys(value).every((key) => allowedKeys.includes(key));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
