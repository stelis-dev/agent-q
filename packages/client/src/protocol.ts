import { Buffer } from "node:buffer";
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
// sessionTtlMs is uint32 wire metadata. Gateway does not use it as the session
// authority; it is bounded here only to reject malformed Firmware responses.
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
  };
}

export interface ConnectRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "connect";
  params: {
    gatewayName: string;
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

export interface GetPolicyRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "get_policy";
  sessionId: string;
}

export interface GetApprovalHistoryRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "get_approval_history";
  sessionId: string;
  params: {
    limit: number;
    beforeSeq?: string;
  };
}

export interface CallMethodRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "call_method";
  sessionId: string;
  chain: string;
  method: string;
  params: Record<string, unknown>;
}

export interface ProposePolicyUpdateRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "call_method";
  sessionId: string;
  methodNamespace: "admin";
  method: "propose_policy_update";
  params: {
    policy: Record<string, unknown>;
  };
}

export interface RequestSignatureParams {
  chain: typeof SUI_CHAIN_ID;
  method: typeof SUI_SIGN_TRANSACTION_METHOD;
  network: SuiSignTransactionNetwork;
  txBytes: string;
}

export interface RequestSignatureRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "request_signature";
  sessionId: string;
  params: RequestSignatureParams;
}

export type ProtocolRequest =
  | GetStatusRequest
  | IdentifyDeviceRequest
  | ConnectRequest
  | DisconnectRequest
  | GetCapabilitiesRequest
  | GetAccountsRequest
  | GetPolicyRequest
  | GetApprovalHistoryRequest
  | CallMethodRequest
  | ProposePolicyUpdateRequest
  | RequestSignatureRequest;

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

export interface SignatureRequestCapability {
  chain: typeof SUI_CHAIN_ID;
  method: typeof SUI_SIGN_TRANSACTION_METHOD;
}

export interface CapabilitiesResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "capabilities";
  chains: CapabilityChain[];
  signatureRequests?: SignatureRequestCapability[];
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

export interface PolicySummary {
  schema: string;
  policyId: string;
  defaultAction: "reject";
  ruleCount: number;
}

export interface PolicyResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "policy";
  policy: PolicySummary;
}

export type ApprovalHistoryDecisionKind = "policy_rejected";

export type ApprovalHistoryConfirmationKind = "none" | "policy" | "local_pin";

export type SignatureRequestHistoryRecordKind = "confirmation" | "terminal";

export type SignatureRequestHistoryTerminalResult =
  | "signed"
  | "rejected"
  | "timed_out"
  | "signing_failed";

export type ApprovalHistoryPolicyUpdateResult =
  | "applied"
  | "rejected"
  | "timed_out"
  | "storage_error";

export type ApprovalHistoryHighestAction = "reject";

interface ApprovalHistoryRecordBase {
  seq: string;
  uptimeMs: string;
  timeSource: "uptime";
  eventKind: "method_decision" | "policy_update" | "signature_request";
  reasonCode: string;
}

export interface MethodDecisionApprovalHistoryRecord extends ApprovalHistoryRecordBase {
  eventKind: "method_decision";
  decisionKind: ApprovalHistoryDecisionKind;
  confirmationKind: ApprovalHistoryConfirmationKind;
  chain: string;
  method: string;
  payloadDigest?: string;
  policyHash?: string;
  ruleRef?: string;
}

export interface PolicyUpdateApprovalHistoryRecord extends ApprovalHistoryRecordBase {
  eventKind: "policy_update";
  result: ApprovalHistoryPolicyUpdateResult;
  policyHash: string;
  ruleCount: number;
  highestAction: ApprovalHistoryHighestAction;
}

export interface SignatureRequestApprovalHistoryRecord extends ApprovalHistoryRecordBase {
  eventKind: "signature_request";
  recordKind: SignatureRequestHistoryRecordKind;
  chain: string;
  method: string;
  payloadDigest: string;
  confirmationKind?: "local_pin";
  terminalResult?: SignatureRequestHistoryTerminalResult;
}

export type ApprovalHistoryRecord =
  | MethodDecisionApprovalHistoryRecord
  | PolicyUpdateApprovalHistoryRecord
  | SignatureRequestApprovalHistoryRecord;

export interface ApprovalHistoryResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "approval_history";
  records: ApprovalHistoryRecord[];
  hasMore: boolean;
}

export type PolicyUpdateResultStatus =
  | "applied"
  | "rejected"
  | "timed_out"
  | "invalid_policy"
  | "ui_error"
  | "storage_error"
  | "consistency_error";

export interface PolicyUpdateResultPolicySummary {
  policyHash: string;
  ruleCount: number;
  highestAction: ApprovalHistoryHighestAction;
}

export interface PolicyUpdateResultResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "policy_update_result";
  status: PolicyUpdateResultStatus;
  reasonCode: string;
  policy?: PolicyUpdateResultPolicySummary;
}

export interface MethodResultRejectedResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "method_result";
  status: "rejected";
  error: {
    code: MethodResultErrorCode;
    message: string;
  };
}

export type MethodResultResponse = MethodResultRejectedResponse;

export type SignatureResultStatus = "signed" | "rejected" | "timed_out" | "failed";
export type SignatureResultReasonCode =
  | "device_confirmed"
  | "device_rejected"
  | "device_timed_out"
  | "signing_failed";

export interface SignatureResultSignedResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "signature_result";
  status: "signed";
  reasonCode: "device_confirmed";
  chain: typeof SUI_CHAIN_ID;
  method: typeof SUI_SIGN_TRANSACTION_METHOD;
  signature: string;
}

export interface SignatureResultTerminalResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "signature_result";
  status: Exclude<SignatureResultStatus, "signed">;
  reasonCode: Exclude<SignatureResultReasonCode, "device_confirmed">;
  error: {
    code: Exclude<SignatureResultReasonCode, "device_confirmed">;
    message: string;
  };
}

export type SignatureResultResponse =
  | SignatureResultSignedResponse
  | SignatureResultTerminalResponse;

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
  | PolicyResponse
  | ApprovalHistoryResponse
  | PolicyUpdateResultResponse
  | MethodResultResponse
  | SignatureResultResponse
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

export function makeIdentifyDeviceRequest(code: string, id = createRequestId()): IdentifyDeviceRequest {
  validateRequestId(id);
  if (!isIdentificationCode(code)) {
    throw new ProtocolError("invalid_code", "Invalid identification code.");
  }
  return {
    id,
    version: PROTOCOL_VERSION,
    type: "identify_device",
    params: {
      code,
    },
  };
}

export function createIdentificationCode(): string {
  return (randomBytes(2).readUInt16BE(0) % 10000).toString().padStart(4, "0");
}

export function makeConnectRequest(
  gatewayName: string,
  id = createRequestId(),
): ConnectRequest {
  validateRequestId(id);
  if (!isGatewayName(gatewayName)) {
    throw new ProtocolError(
      "invalid_gateway_name",
      "gatewayName must be 1-64 printable ASCII characters.",
    );
  }
  return {
    id,
    version: PROTOCOL_VERSION,
    type: "connect",
    params: {
      gatewayName,
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

export function makeGetPolicyRequest(sessionId: string, id = createRequestId()): GetPolicyRequest {
  validateRequestId(id);
  if (!isSessionId(sessionId)) {
    throw new ProtocolError("invalid_session", "Invalid sessionId.");
  }
  return {
    id,
    version: PROTOCOL_VERSION,
    type: "get_policy",
    sessionId,
  };
}

export function makeGetApprovalHistoryRequest(
  sessionId: string,
  params: { limit?: number; beforeSeq?: string } = {},
  id = createRequestId(),
): GetApprovalHistoryRequest {
  validateRequestId(id);
  if (!isSessionId(sessionId)) {
    throw new ProtocolError("invalid_session", "Invalid sessionId.");
  }
  const normalizedParams = validateApprovalHistoryInput(params);
  return {
    id,
    version: PROTOCOL_VERSION,
    type: "get_approval_history",
    sessionId,
    params: normalizedParams,
  };
}

export function makeCallMethodRequest(
  sessionId: string,
  chain: string,
  method: string,
  params: Record<string, unknown> = {},
  id = createRequestId(),
): CallMethodRequest {
  validateRequestId(id);
  if (!isSessionId(sessionId)) {
    throw new ProtocolError("invalid_session", "Invalid sessionId.");
  }
  validateCallMethodInput(chain, method, params);
  return {
    id,
    version: PROTOCOL_VERSION,
    type: "call_method",
    sessionId,
    chain,
    method,
    params,
  };
}

export function makeProposePolicyUpdateRequest(
  sessionId: string,
  policy: Record<string, unknown>,
  id = createRequestId(),
): ProposePolicyUpdateRequest {
  validateRequestId(id);
  if (!isSessionId(sessionId)) {
    throw new ProtocolError("invalid_session", "Invalid sessionId.");
  }
  validatePolicyUpdateProposalInput(policy);
  const request: ProposePolicyUpdateRequest = {
    id,
    version: PROTOCOL_VERSION,
    type: "call_method",
    sessionId,
    methodNamespace: "admin",
    method: "propose_policy_update",
    params: {
      policy,
    },
  };
  if (Buffer.byteLength(JSON.stringify(request), "utf8") > MAX_POLICY_UPDATE_REQUEST_JSON_BYTES) {
    throw new ProtocolError("invalid_params", "policy update request is too large for the runtime.");
  }
  return request;
}

export function makeRequestSignatureRequest(
  sessionId: string,
  params: unknown,
  id = createRequestId(),
): RequestSignatureRequest {
  validateRequestId(id);
  if (!isSessionId(sessionId)) {
    throw new ProtocolError("invalid_session", "Invalid sessionId.");
  }
  const normalizedParams = validateRequestSignatureInput(params);
  const request: RequestSignatureRequest = {
    id,
    version: PROTOCOL_VERSION,
    type: "request_signature",
    sessionId,
    params: normalizedParams,
  };
  if (Buffer.byteLength(JSON.stringify(request), "utf8") > MAX_RAW_PROTOCOL_JSON_BYTES) {
    throw new ProtocolError("invalid_params", "request_signature request is too large for the runtime.");
  }
  return request;
}

export function validateProposePolicyUpdateRequestInput(
  sessionId: string,
  policy: Record<string, unknown>,
): void {
  makeProposePolicyUpdateRequest(sessionId, policy, "req_000000000000000000000000");
}

export function validateRequestSignatureInput(params: unknown): RequestSignatureParams {
  if (!isRecord(params) || Array.isArray(params)) {
    throw new ProtocolError("invalid_params", "request_signature params must be an object.");
  }
  if (hasSecretPayloadKey(params)) {
    throw new ProtocolError("invalid_params", "request_signature params must not include secret material.");
  }
  if (!hasOnlyObjectKeys(params, ["chain", "method", "network", "txBytes"])) {
    throw new ProtocolError("invalid_params", "request_signature params contain unsupported fields.");
  }
  if (params.chain !== SUI_CHAIN_ID || params.method !== SUI_SIGN_TRANSACTION_METHOD) {
    throw new ProtocolError("invalid_method", "request_signature method is unsupported.");
  }
  return {
    chain: SUI_CHAIN_ID,
    method: SUI_SIGN_TRANSACTION_METHOD,
    network: validateSuiSignTransactionNetwork(params.network),
    txBytes: validateSuiSignTransactionTxBytes(params.txBytes),
  };
}

export function validateCallMethodInput(
  chain: unknown,
  method: unknown,
  params: unknown,
): asserts params is Record<string, unknown> {
  if (!isCallMethodChain(chain)) {
    throw new ProtocolError("invalid_method", "Invalid call_method chain.");
  }
  if (!isCallMethodName(method)) {
    throw new ProtocolError("invalid_method", "Invalid call_method method.");
  }
  validateCallMethodParams(params);
  if (chain === SUI_CHAIN_ID && method === SUI_SIGN_TRANSACTION_METHOD) {
    validateSuiSignTransactionParams(params);
  }
}

export function validatePolicyUpdateProposalInput(policy: unknown): asserts policy is Record<string, unknown> {
  if (!isRecord(policy) || Array.isArray(policy)) {
    throw new ProtocolError("invalid_params", "policy update proposal must be an object.");
  }
  if (hasSecretPayloadKey(policy)) {
    throw new ProtocolError("invalid_params", "policy update proposal must not include secret material.");
  }
  let serialized: string | undefined;
  try {
    serialized = JSON.stringify(policy);
  } catch {
    throw new ProtocolError("invalid_params", "policy update proposal must be JSON serializable.");
  }
  if (serialized === undefined) {
    throw new ProtocolError("invalid_params", "policy update proposal must be JSON serializable.");
  }
}

export function validateApprovalHistoryInput(
  params: { limit?: number; beforeSeq?: string } = {},
): { limit: number; beforeSeq?: string } {
  const limit = params.limit ?? MAX_APPROVAL_HISTORY_RECORDS;
  if (!Number.isInteger(limit) || limit <= 0 || limit > MAX_APPROVAL_HISTORY_RECORDS) {
    throw new ProtocolError("invalid_params", "approval history limit is invalid.");
  }
  if (params.beforeSeq !== undefined && !isUint64DecimalString(params.beforeSeq)) {
    throw new ProtocolError("invalid_params", "approval history beforeSeq is invalid.");
  }
  return params.beforeSeq === undefined ? { limit } : { limit, beforeSeq: params.beforeSeq };
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
    if (!hasOnlyObjectKeys(value, ["id", "version", "type", "chains", "signatureRequests"])) {
      throw new ProtocolError("protocol_error", "Capabilities response contains unsupported fields.");
    }
    if (!Array.isArray(value.chains)) {
      throw new ProtocolError("protocol_error", "Capabilities response chains must be an array.");
    }
    if (value.chains.length !== MAX_CAPABILITY_CHAINS) {
      throw new ProtocolError("protocol_error", "Capabilities response has an unsupported chain count.");
    }
    const signatureRequests = sanitizeSignatureRequestCapabilities(value.signatureRequests);
    return {
      id: value.id,
      version: PROTOCOL_VERSION,
      type: "capabilities",
      chains: value.chains.map((entry) => sanitizeCapabilityChain(entry)),
      ...(signatureRequests === undefined ? {} : { signatureRequests }),
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

  if (value.type === "policy") {
    if (typeof value.id !== "string") {
      throw new ProtocolError("protocol_error", "Policy response id is malformed.");
    }
    if (hasSecretPayloadKey(value)) {
      throw new ProtocolError("protocol_error", "Policy response must not include secret material.");
    }
    if (!hasOnlyObjectKeys(value, ["id", "version", "type", "policy"])) {
      throw new ProtocolError("protocol_error", "Policy response contains unsupported fields.");
    }
    const policy = sanitizePolicySummary(value.policy);
    if (policy === null) {
      throw new ProtocolError("protocol_error", "Policy response policy object is malformed.");
    }
    return {
      id: value.id,
      version: PROTOCOL_VERSION,
      type: "policy",
      policy,
    };
  }

  if (value.type === "approval_history") {
    if (typeof value.id !== "string") {
      throw new ProtocolError("protocol_error", "Approval history response id is malformed.");
    }
    if (hasSecretPayloadKey(value)) {
      throw new ProtocolError("protocol_error", "Approval history response must not include secret material.");
    }
    if (!hasOnlyObjectKeys(value, ["id", "version", "type", "records", "hasMore"])) {
      throw new ProtocolError("protocol_error", "Approval history response contains unsupported fields.");
    }
    if (!Array.isArray(value.records) || value.records.length > MAX_APPROVAL_HISTORY_RECORDS) {
      throw new ProtocolError("protocol_error", "Approval history response records are malformed.");
    }
    if (typeof value.hasMore !== "boolean") {
      throw new ProtocolError("protocol_error", "Approval history response hasMore is malformed.");
    }
    return {
      id: value.id,
      version: PROTOCOL_VERSION,
      type: "approval_history",
      records: value.records.map((entry) => sanitizeApprovalHistoryRecord(entry)),
      hasMore: value.hasMore,
    };
  }

  if (value.type === "policy_update_result") {
    if (typeof value.id !== "string") {
      throw new ProtocolError("protocol_error", "Policy update result id is malformed.");
    }
    if (hasSecretPayloadKey(value)) {
      throw new ProtocolError("protocol_error", "Policy update result must not include secret material.");
    }
    if (!hasOnlyObjectKeys(value, ["id", "version", "type", "status", "reasonCode", "policy"])) {
      throw new ProtocolError("protocol_error", "Policy update result contains unsupported fields.");
    }
    if (
      !POLICY_UPDATE_RESULT_STATUSES.includes(value.status as PolicyUpdateResultStatus) ||
      typeof value.reasonCode !== "string" ||
      !APPROVAL_HISTORY_REASON_CODE_PATTERN.test(value.reasonCode)
    ) {
      throw new ProtocolError("protocol_error", "Policy update result is malformed.");
    }
    const policy = sanitizePolicyUpdateResultPolicy(value.policy);
    if (value.status === "invalid_policy") {
      if (policy !== undefined) {
        throw new ProtocolError("protocol_error", "Invalid policy result must not include policy metadata.");
      }
    } else if (policy === undefined) {
      throw new ProtocolError("protocol_error", "Policy update result policy metadata is malformed.");
    }
    return {
      id: value.id,
      version: PROTOCOL_VERSION,
      type: "policy_update_result",
      status: value.status as PolicyUpdateResultStatus,
      reasonCode: value.reasonCode,
      ...(policy !== undefined ? { policy } : {}),
    };
  }

  if (value.type === "method_result") {
    if (typeof value.id !== "string" || typeof value.status !== "string") {
      throw new ProtocolError("protocol_error", "Method result response is malformed.");
    }
    if (hasSecretPayloadKey(value)) {
      throw new ProtocolError("protocol_error", "Method result response must not include secret material.");
    }

    if (value.status !== "rejected") {
      throw new ProtocolError("protocol_error", "Method result response is malformed.");
    }
    if (!hasOnlyObjectKeys(value, ["id", "version", "type", "status", "error"])) {
      throw new ProtocolError("protocol_error", "Method result response contains unsupported fields.");
    }
    const error = value.error;
    if (!isRecord(error) || !hasOnlyObjectKeys(error, ["code", "message"])) {
      throw new ProtocolError("protocol_error", "Method result error is malformed.");
    }
    const errorMessage = methodResultErrorMessage(error.code);
    if (errorMessage === undefined || error.message !== errorMessage) {
      throw new ProtocolError("protocol_error", "Method result error is malformed.");
    }
    return {
      id: value.id,
      version: PROTOCOL_VERSION,
      type: "method_result",
      status: "rejected",
      error: {
        code: error.code as MethodResultErrorCode,
        message: errorMessage,
      },
    };
  }

  if (value.type === "signature_result") {
    return sanitizeSignatureResultResponse(value);
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

export function assertPolicyResponse(response: ProtocolResponse): PolicyResponse {
  if (response.type === "error") {
    throw new ProtocolError(response.error.code, response.error.message);
  }
  if (response.type !== "policy") {
    throw new ProtocolError("protocol_error", "Protocol response type is not policy.");
  }
  return response;
}

export function assertApprovalHistoryResponse(response: ProtocolResponse): ApprovalHistoryResponse {
  if (response.type === "error") {
    throw new ProtocolError(response.error.code, response.error.message);
  }
  if (response.type !== "approval_history") {
    throw new ProtocolError("protocol_error", "Protocol response type is not approval_history.");
  }
  return response;
}

export function assertPolicyUpdateResultResponse(response: ProtocolResponse): PolicyUpdateResultResponse {
  if (response.type === "error") {
    throw new ProtocolError(response.error.code, response.error.message);
  }
  if (response.type !== "policy_update_result") {
    throw new ProtocolError("protocol_error", "Protocol response type is not policy_update_result.");
  }
  return response;
}

export function assertMethodResultResponse(response: ProtocolResponse): MethodResultResponse {
  if (response.type === "error") {
    throw new ProtocolError(response.error.code, response.error.message);
  }
  if (response.type !== "method_result") {
    throw new ProtocolError("protocol_error", "Protocol response type is not method_result.");
  }
  return response;
}

export function assertSignatureResultResponse(response: ProtocolResponse): SignatureResultResponse {
  if (response.type === "error") {
    throw new ProtocolError(response.error.code, response.error.message);
  }
  if (response.type !== "signature_result") {
    throw new ProtocolError("protocol_error", "Protocol response type is not signature_result.");
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

export function isCallMethodChain(value: unknown): value is string {
  return typeof value === "string" && CALL_METHOD_CHAIN_PATTERN.test(value);
}

export function isCallMethodName(value: unknown): value is string {
  return typeof value === "string" && CALL_METHOD_NAME_PATTERN.test(value);
}

export function isUint64DecimalString(value: unknown): value is string {
  if (typeof value !== "string" || !UINT_DECIMAL_STRING_PATTERN.test(value)) {
    return false;
  }
  return value.length < UINT64_MAX_DECIMAL.length ||
    (value.length === UINT64_MAX_DECIMAL.length && value <= UINT64_MAX_DECIMAL);
}

export const SUI_ADDRESS_PATTERN = /^0x[0-9a-f]{64}$/;
// Raw 32-byte Ed25519 public key as base64 is exactly 43 payload chars + one "=".
export const ED25519_PUBLIC_KEY_BASE64_PATTERN = /^[A-Za-z0-9+/]{43}=$/;
// Sui Ed25519 signatures are scheme flag + 64-byte signature + 32-byte public key.
export const SUI_ED25519_SIGNATURE_BASE64_PATTERN = /^[A-Za-z0-9+/]{130}==$/;
export const SUI_DERIVATION_PATH = "m/44'/784'/0'/0'/0'";
export const MAX_CAPABILITY_CHAINS = 1;
export const MAX_CAPABILITY_ACCOUNTS_PER_CHAIN = 1;
export const MAX_SIGNATURE_REQUEST_CAPABILITIES = 1;
// The current target implements exactly one account (Sui Ed25519 account 0). Bound
// the accounts array so a buggy or spoofed device cannot inflate the MCP result or
// imply multi-account support that does not exist. Raise this as more accounts or
// chains are actually implemented.
export const MAX_ACCOUNTS_PER_RESPONSE = 1;
export const AGENT_Q_POLICY_SCHEMA = "agentq.policy.v0";
export const POLICY_ID_PATTERN = /^sha256:[0-9a-f]{64}$/;
export const MAX_POLICY_RULE_COUNT = 16;
export const MAX_APPROVAL_HISTORY_RECORDS = 4;
export const UINT_DECIMAL_STRING_PATTERN = /^(0|[1-9][0-9]{0,19})$/;
const UINT64_MAX_DECIMAL = "18446744073709551615";
export const APPROVAL_HISTORY_REASON_CODE_PATTERN = /^[a-z][a-z0-9_]{0,31}$/;
export const APPROVAL_HISTORY_RULE_REF_PATTERN = /^[a-z][a-z0-9_.:/-]{0,31}$/;
export const APPROVAL_HISTORY_DECISION_KINDS = [
  "policy_rejected",
] as const;
export const APPROVAL_HISTORY_CONFIRMATION_KINDS = [
  "none",
  "policy",
  "local_pin",
] as const;
export const SIGNATURE_REQUEST_HISTORY_RECORD_KINDS = [
  "confirmation",
  "terminal",
] as const;
export const SIGNATURE_REQUEST_HISTORY_TERMINAL_RESULTS = [
  "signed",
  "rejected",
  "timed_out",
  "signing_failed",
] as const;
export const APPROVAL_HISTORY_POLICY_UPDATE_RESULTS = [
  "applied",
  "rejected",
  "timed_out",
  "storage_error",
] as const;
export const APPROVAL_HISTORY_HIGHEST_ACTIONS = ["reject"] as const;
export const POLICY_UPDATE_RESULT_STATUSES = [
  "applied",
  "rejected",
  "timed_out",
  "invalid_policy",
  "ui_error",
  "storage_error",
  "consistency_error",
] as const;
export const CALL_METHOD_CHAIN_PATTERN = /^[a-z][a-z0-9_.-]{0,31}$/;
export const CALL_METHOD_NAME_PATTERN = /^[a-z][a-z0-9_.-]{0,63}$/;
// The method runtime keeps request bodies bounded by the current Firmware JSONL
// input buffer. Specific methods can add stricter semantic limits inside this cap.
export const MAX_CALL_METHOD_PARAMS_JSON_BYTES = 600;
export const MAX_RAW_PROTOCOL_JSON_BYTES = 4096;
export const MAX_POLICY_UPDATE_REQUEST_JSON_BYTES = 4096;
export const SUI_CHAIN_ID = "sui";
export const SUI_SIGN_TRANSACTION_METHOD = "sign_transaction";
export const SUI_SIGN_TRANSACTION_NETWORKS = ["mainnet", "testnet", "devnet", "localnet"] as const;
export type SuiSignTransactionNetwork = (typeof SUI_SIGN_TRANSACTION_NETWORKS)[number];
export const MAX_SUI_SIGN_TRANSACTION_TX_BYTES = 384;
export const MAX_SUI_SIGN_TRANSACTION_TX_BYTES_BASE64_CHARS = 512;
const BASE64_CANONICAL_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
export const UNSUPPORTED_METHOD_MESSAGE = "Method is not supported.";
export const METHOD_RESULT_ERROR_MESSAGES = {
  unsupported_method: UNSUPPORTED_METHOD_MESSAGE,
  policy_rejected: "The request was rejected by device policy.",
  malformed_transaction: "Transaction bytes are malformed.",
  unsupported_transaction: "Transaction shape is not supported.",
  policy_error: "Active policy is unavailable.",
} as const;
export type MethodResultErrorCode = keyof typeof METHOD_RESULT_ERROR_MESSAGES;
export const SIGNATURE_RESULT_ERROR_MESSAGES = {
  device_rejected: "The signing request was rejected on the device.",
  device_timed_out: "The signing request timed out on the device.",
  signing_failed: "The device could not produce a signature.",
} as const;
export type SignatureResultErrorCode = keyof typeof SIGNATURE_RESULT_ERROR_MESSAGES;
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

function sanitizeSignatureRequestCapabilities(value: unknown): SignatureRequestCapability[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!Array.isArray(value)) {
    throw new ProtocolError("protocol_error", "Signature request capabilities must be an array.");
  }
  if (value.length !== MAX_SIGNATURE_REQUEST_CAPABILITIES) {
    throw new ProtocolError("protocol_error", "Signature request capability count is unsupported.");
  }
  return value.map((entry) => {
    if (!isRecord(entry)) {
      throw new ProtocolError("protocol_error", "Signature request capability entry is malformed.");
    }
    if (hasSecretPayloadKey(entry)) {
      throw new ProtocolError("protocol_error", "Signature request capability entry must not include secret material.");
    }
    if (!hasOnlyObjectKeys(entry, ["chain", "method"])) {
      throw new ProtocolError("protocol_error", "Signature request capability entry contains unsupported fields.");
    }
    if (entry.chain !== SUI_CHAIN_ID || entry.method !== SUI_SIGN_TRANSACTION_METHOD) {
      throw new ProtocolError("protocol_error", "Signature request capability is unsupported.");
    }
    return {
      chain: SUI_CHAIN_ID,
      method: SUI_SIGN_TRANSACTION_METHOD,
    };
  });
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

function sanitizePolicySummary(value: unknown): PolicySummary | null {
  if (!isRecord(value)) {
    return null;
  }
  if (hasSecretPayloadKey(value)) {
    throw new ProtocolError("protocol_error", "Policy summary must not include secret material.");
  }
  if (!hasOnlyObjectKeys(value, ["schema", "policyId", "defaultAction", "ruleCount"])) {
    throw new ProtocolError("protocol_error", "Policy summary contains unsupported fields.");
  }
  if (
    value.schema !== AGENT_Q_POLICY_SCHEMA ||
    typeof value.policyId !== "string" ||
    !POLICY_ID_PATTERN.test(value.policyId) ||
    value.defaultAction !== "reject" ||
    typeof value.ruleCount !== "number" ||
    !Number.isInteger(value.ruleCount) ||
    value.ruleCount < 0 ||
    value.ruleCount > MAX_POLICY_RULE_COUNT
  ) {
    return null;
  }
  return {
    schema: value.schema,
    policyId: value.policyId,
    defaultAction: value.defaultAction,
    ruleCount: value.ruleCount,
  };
}

function sanitizePolicyUpdateResultPolicy(value: unknown): PolicyUpdateResultPolicySummary | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!isRecord(value)) {
    throw new ProtocolError("protocol_error", "Policy update result policy metadata is malformed.");
  }
  if (hasSecretPayloadKey(value)) {
    throw new ProtocolError("protocol_error", "Policy update result policy metadata must not include secret material.");
  }
  if (!hasOnlyObjectKeys(value, ["policyHash", "ruleCount", "highestAction"])) {
    throw new ProtocolError("protocol_error", "Policy update result policy metadata contains unsupported fields.");
  }
  if (
    typeof value.policyHash !== "string" ||
    !POLICY_ID_PATTERN.test(value.policyHash) ||
    typeof value.ruleCount !== "number" ||
    !Number.isInteger(value.ruleCount) ||
    value.ruleCount < 0 ||
    value.ruleCount > MAX_POLICY_RULE_COUNT ||
    !APPROVAL_HISTORY_HIGHEST_ACTIONS.includes(value.highestAction as ApprovalHistoryHighestAction)
  ) {
    throw new ProtocolError("protocol_error", "Policy update result policy metadata is malformed.");
  }
  return {
    policyHash: value.policyHash,
    ruleCount: value.ruleCount,
    highestAction: value.highestAction as ApprovalHistoryHighestAction,
  };
}

function sanitizeApprovalHistoryRecord(value: unknown): ApprovalHistoryRecord {
  if (!isRecord(value)) {
    throw new ProtocolError("protocol_error", "Approval history record is malformed.");
  }
  if (hasSecretPayloadKey(value)) {
    throw new ProtocolError("protocol_error", "Approval history record must not include secret material.");
  }
  const allowedKeys = [
    "seq",
    "uptimeMs",
    "timeSource",
    "eventKind",
    "decisionKind",
    "confirmationKind",
    "chain",
    "method",
    "reasonCode",
    "payloadDigest",
    "policyHash",
    "ruleRef",
    "result",
    "ruleCount",
    "highestAction",
    "recordKind",
    "terminalResult",
  ];
  if (!hasOnlyObjectKeys(value, allowedKeys)) {
    throw new ProtocolError("protocol_error", "Approval history record contains unsupported fields.");
  }
  if (
    typeof value.seq !== "string" ||
    !isUint64DecimalString(value.seq) ||
    typeof value.uptimeMs !== "string" ||
    !isUint64DecimalString(value.uptimeMs) ||
    value.timeSource !== "uptime" ||
    typeof value.reasonCode !== "string" ||
    !APPROVAL_HISTORY_REASON_CODE_PATTERN.test(value.reasonCode)
  ) {
    throw new ProtocolError("protocol_error", "Approval history record is malformed.");
  }

  if (value.eventKind === "policy_update") {
    if (
      value.decisionKind !== undefined ||
      value.confirmationKind !== undefined ||
      value.chain !== undefined ||
      value.method !== undefined ||
      value.payloadDigest !== undefined ||
      value.ruleRef !== undefined ||
      value.recordKind !== undefined ||
      value.terminalResult !== undefined ||
      !APPROVAL_HISTORY_POLICY_UPDATE_RESULTS.includes(value.result as ApprovalHistoryPolicyUpdateResult) ||
      typeof value.policyHash !== "string" ||
      !POLICY_ID_PATTERN.test(value.policyHash) ||
      typeof value.ruleCount !== "number" ||
      !Number.isInteger(value.ruleCount) ||
      value.ruleCount < 0 ||
      value.ruleCount > MAX_POLICY_RULE_COUNT ||
      !APPROVAL_HISTORY_HIGHEST_ACTIONS.includes(value.highestAction as ApprovalHistoryHighestAction)
    ) {
      throw new ProtocolError("protocol_error", "Approval history policy update record is malformed.");
    }
    return {
      seq: value.seq,
      uptimeMs: value.uptimeMs,
      timeSource: "uptime",
      eventKind: "policy_update",
      reasonCode: value.reasonCode,
      result: value.result as ApprovalHistoryPolicyUpdateResult,
      policyHash: value.policyHash,
      ruleCount: value.ruleCount,
      highestAction: value.highestAction as ApprovalHistoryHighestAction,
    };
  }

  if (value.eventKind === "signature_request") {
    if (
      value.decisionKind !== undefined ||
      value.result !== undefined ||
      value.ruleCount !== undefined ||
      value.highestAction !== undefined ||
      value.policyHash !== undefined ||
      value.ruleRef !== undefined ||
      !SIGNATURE_REQUEST_HISTORY_RECORD_KINDS.includes(value.recordKind as SignatureRequestHistoryRecordKind) ||
      !isCallMethodChain(value.chain) ||
      !isCallMethodName(value.method) ||
      typeof value.payloadDigest !== "string" ||
      !POLICY_ID_PATTERN.test(value.payloadDigest)
    ) {
      throw new ProtocolError("protocol_error", "Approval history signature request record is malformed.");
    }
    if (value.recordKind === "confirmation") {
      if (
        value.confirmationKind !== "local_pin" ||
        value.terminalResult !== undefined
      ) {
        throw new ProtocolError("protocol_error", "Approval history signature request record is malformed.");
      }
      return {
        seq: value.seq,
        uptimeMs: value.uptimeMs,
        timeSource: "uptime",
        eventKind: "signature_request",
        reasonCode: value.reasonCode,
        recordKind: "confirmation",
        confirmationKind: "local_pin",
        chain: value.chain,
        method: value.method,
        payloadDigest: value.payloadDigest,
      };
    }
    if (
      value.confirmationKind !== undefined ||
      !SIGNATURE_REQUEST_HISTORY_TERMINAL_RESULTS.includes(
        value.terminalResult as SignatureRequestHistoryTerminalResult,
      )
    ) {
      throw new ProtocolError("protocol_error", "Approval history signature request record is malformed.");
    }
    return {
      seq: value.seq,
      uptimeMs: value.uptimeMs,
      timeSource: "uptime",
      eventKind: "signature_request",
      reasonCode: value.reasonCode,
      recordKind: "terminal",
      terminalResult: value.terminalResult as SignatureRequestHistoryTerminalResult,
      chain: value.chain,
      method: value.method,
      payloadDigest: value.payloadDigest,
    };
  }

  if (
    value.eventKind !== "method_decision" ||
    value.result !== undefined ||
    value.ruleCount !== undefined ||
    value.highestAction !== undefined ||
    value.recordKind !== undefined ||
    value.terminalResult !== undefined ||
    !APPROVAL_HISTORY_DECISION_KINDS.includes(value.decisionKind as ApprovalHistoryDecisionKind) ||
    value.confirmationKind !== "policy" ||
    !isCallMethodChain(value.chain) ||
    !isCallMethodName(value.method)
  ) {
    throw new ProtocolError("protocol_error", "Approval history record is malformed.");
  }
  if (
    value.payloadDigest !== undefined &&
    (typeof value.payloadDigest !== "string" || !POLICY_ID_PATTERN.test(value.payloadDigest))
  ) {
    throw new ProtocolError("protocol_error", "Approval history payloadDigest is malformed.");
  }
  if (
    value.policyHash !== undefined &&
    (typeof value.policyHash !== "string" || !POLICY_ID_PATTERN.test(value.policyHash))
  ) {
    throw new ProtocolError("protocol_error", "Approval history policyHash is malformed.");
  }
  if (
    value.ruleRef !== undefined &&
    (typeof value.ruleRef !== "string" || !APPROVAL_HISTORY_RULE_REF_PATTERN.test(value.ruleRef))
  ) {
    throw new ProtocolError("protocol_error", "Approval history ruleRef is malformed.");
  }
  return {
    seq: value.seq,
    uptimeMs: value.uptimeMs,
    timeSource: "uptime",
    eventKind: "method_decision",
    reasonCode: value.reasonCode,
    decisionKind: value.decisionKind as ApprovalHistoryDecisionKind,
    confirmationKind: value.confirmationKind as ApprovalHistoryConfirmationKind,
    chain: value.chain,
    method: value.method,
    ...(value.payloadDigest === undefined ? {} : { payloadDigest: value.payloadDigest }),
    ...(value.policyHash === undefined ? {} : { policyHash: value.policyHash }),
    ...(value.ruleRef === undefined ? {} : { ruleRef: value.ruleRef }),
  };
}

function validateCallMethodParams(params: unknown): asserts params is Record<string, unknown> {
  if (!isRecord(params) || Array.isArray(params)) {
    throw new ProtocolError("invalid_params", "call_method params must be an object.");
  }
  if (hasSecretPayloadKey(params)) {
    throw new ProtocolError("invalid_params", "call_method params must not include secret material.");
  }
  let serialized: string | undefined;
  try {
    serialized = JSON.stringify(params);
  } catch {
    throw new ProtocolError("invalid_params", "call_method params must be JSON serializable.");
  }
  if (serialized === undefined || Buffer.byteLength(serialized, "utf8") > MAX_CALL_METHOD_PARAMS_JSON_BYTES) {
    throw new ProtocolError("invalid_params", "call_method params are too large for the runtime.");
  }
}

function validateSuiSignTransactionParams(params: Record<string, unknown>): void {
  if (!hasOnlyObjectKeys(params, ["network", "txBytes"])) {
    throw new ProtocolError("invalid_params", "sui/sign_transaction params contain unsupported fields.");
  }
  validateSuiSignTransactionNetwork(params.network);
  validateSuiSignTransactionTxBytes(params.txBytes);
}

function validateSuiSignTransactionNetwork(value: unknown): SuiSignTransactionNetwork {
  if (!SUI_SIGN_TRANSACTION_NETWORKS.includes(value as SuiSignTransactionNetwork)) {
    throw new ProtocolError("invalid_params", "sui/sign_transaction network is unsupported.");
  }
  return value as SuiSignTransactionNetwork;
}

function validateSuiSignTransactionTxBytes(value: unknown): string {
  if (typeof value !== "string") {
    throw new ProtocolError("invalid_params", "sui/sign_transaction txBytes must be base64.");
  }
  if (
    value.length === 0 ||
    value.length > MAX_SUI_SIGN_TRANSACTION_TX_BYTES_BASE64_CHARS ||
    !BASE64_CANONICAL_PATTERN.test(value)
  ) {
    throw new ProtocolError("invalid_params", "sui/sign_transaction txBytes must be canonical base64.");
  }
  const decoded = Buffer.from(value, "base64");
  if (
    decoded.length === 0 ||
    decoded.length > MAX_SUI_SIGN_TRANSACTION_TX_BYTES ||
    decoded.toString("base64") !== value
  ) {
    throw new ProtocolError("invalid_params", "sui/sign_transaction txBytes are outside the supported size.");
  }
  return value;
}

function methodResultErrorMessage(code: unknown): string | undefined {
  if (typeof code !== "string" || !(code in METHOD_RESULT_ERROR_MESSAGES)) {
    return undefined;
  }
  return METHOD_RESULT_ERROR_MESSAGES[code as MethodResultErrorCode];
}

function signatureResultErrorMessage(code: unknown): string | undefined {
  if (typeof code !== "string" || !(code in SIGNATURE_RESULT_ERROR_MESSAGES)) {
    return undefined;
  }
  return SIGNATURE_RESULT_ERROR_MESSAGES[code as SignatureResultErrorCode];
}

function sanitizeSignatureResultResponse(value: Record<string, unknown>): SignatureResultResponse {
  if (typeof value.id !== "string" || typeof value.status !== "string") {
    throw new ProtocolError("protocol_error", "Signature result response is malformed.");
  }
  if (hasSecretPayloadKey(value)) {
    throw new ProtocolError("protocol_error", "Signature result response must not include secret material.");
  }

  if (value.status === "signed") {
    if (!hasOnlyObjectKeys(value, ["id", "version", "type", "status", "reasonCode", "chain", "method", "signature"])) {
      throw new ProtocolError("protocol_error", "Signature result response contains unsupported fields.");
    }
    if (
      value.reasonCode !== "device_confirmed" ||
      value.chain !== SUI_CHAIN_ID ||
      value.method !== SUI_SIGN_TRANSACTION_METHOD ||
      typeof value.signature !== "string" ||
      !SUI_ED25519_SIGNATURE_BASE64_PATTERN.test(value.signature)
    ) {
      throw new ProtocolError("protocol_error", "Signature result response is malformed.");
    }
    return {
      id: value.id,
      version: PROTOCOL_VERSION,
      type: "signature_result",
      status: "signed",
      reasonCode: "device_confirmed",
      chain: SUI_CHAIN_ID,
      method: SUI_SIGN_TRANSACTION_METHOD,
      signature: value.signature,
    };
  }

  if (value.status === "rejected" || value.status === "timed_out" || value.status === "failed") {
    if (!hasOnlyObjectKeys(value, ["id", "version", "type", "status", "reasonCode", "error"])) {
      throw new ProtocolError("protocol_error", "Signature result response contains unsupported fields.");
    }
    const error = value.error;
    if (!isRecord(error) || !hasOnlyObjectKeys(error, ["code", "message"])) {
      throw new ProtocolError("protocol_error", "Signature result error is malformed.");
    }
    const expectedReason: SignatureResultErrorCode =
      value.status === "rejected"
        ? "device_rejected"
        : value.status === "timed_out"
          ? "device_timed_out"
          : "signing_failed";
    const expectedMessage = SIGNATURE_RESULT_ERROR_MESSAGES[expectedReason];
    if (
      value.reasonCode !== expectedReason ||
      error.code !== expectedReason ||
      error.message !== expectedMessage
    ) {
      throw new ProtocolError("protocol_error", "Signature result error is malformed.");
    }
    return {
      id: value.id,
      version: PROTOCOL_VERSION,
      type: "signature_result",
      status: value.status,
      reasonCode: expectedReason,
      error: {
        code: expectedReason,
        message: expectedMessage,
      },
    };
  }

  throw new ProtocolError("protocol_error", "Signature result status is unsupported.");
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
