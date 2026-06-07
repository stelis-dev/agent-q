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
import {
  makeConnectRequest as makeProviderConnectRequest,
  makeDisconnectRequest as makeProviderDisconnectRequest,
  makeGetAccountsRequest as makeProviderGetAccountsRequest,
  makeGetCapabilitiesRequest as makeProviderGetCapabilitiesRequest,
  makeSignPersonalMessageRequest as makeProviderSignPersonalMessageRequest,
  makeSignTransactionRequest as makeProviderSignTransactionRequest,
  parseProviderProtocolResponse as parseProviderProtocolResponseCore,
  validateSignPersonalMessageInput as validateProviderSignPersonalMessageInput,
  validateSignTransactionInput as validateProviderSignTransactionInput,
  type Account,
  type AccountsResponse,
  type CapabilitiesResponse,
  type CapabilityAccount,
  type CapabilityChain,
  type ConnectApprovedResponse,
  type ConnectRejectedResponse,
  type ConnectRequest,
  type ConnectResponse,
  type DisconnectRequest,
  type DisconnectResponse,
  type GetAccountsRequest,
  type GetCapabilitiesRequest,
  type ProtocolErrorResponse,
  type SignPersonalMessageParams,
  type SignPersonalMessageRequest,
  type SignPersonalMessageSignedResponse,
  type SignResultAuthorization,
  type SignResultPolicyRejectedResponse,
  type SignResultResponse,
  type SignResultSignedResponse,
  type SignResultSigningFailedResponse,
  type SignResultStatus,
  type SignResultUserRejectedResponse,
  type SignTransactionParams,
  type SignTransactionRequest,
  type SignTransactionSignedResponse,
  type SigningCapabilities,
  type SigningCapabilityEntry,
} from "./provider-protocol.js";
import { ProtocolError } from "./protocol-error.js";
import {
  AGENT_Q_POLICY_SCHEMA,
  APPROVAL_HISTORY_HIGHEST_ACTIONS,
  APPROVAL_HISTORY_POLICY_UPDATE_RESULTS,
  APPROVAL_HISTORY_REASON_CODE_PATTERN,
  APPROVAL_HISTORY_RULE_REF_PATTERN,
  MAX_APPROVAL_HISTORY_RECORDS,
  MAX_POLICY_CHAIN_ID_LENGTH,
  MAX_POLICY_CRITERION_VALUES,
  MAX_POLICY_FIELD_ID_LENGTH,
  MAX_POLICY_METHOD_LENGTH,
  MAX_POLICY_RULE_CRITERIA,
  MAX_POLICY_RULE_COUNT,
  MAX_POLICY_RULE_ID_LENGTH,
  MAX_POLICY_UPDATE_REQUEST_JSON_BYTES,
  MAX_POLICY_VALUE_LENGTH,
  POLICY_ACTIONS,
  POLICY_FIELD_ID_PATTERN,
  POLICY_ID_PATTERN,
  POLICY_IDENTIFIER_PATTERN,
  POLICY_OPERATORS,
  POLICY_PROPOSE_RESULT_STATUSES,
  POLICY_RULE_ID_PATTERN,
  SIGNING_HISTORY_RECORD_KINDS,
  SIGNING_HISTORY_TERMINAL_RESULTS,
  SIGN_CHAIN_PATTERN,
  SIGN_METHOD_PATTERN,
  UINT_DECIMAL_STRING_PATTERN,
} from "./protocol-management-primitives.js";
import {
  ED25519_PUBLIC_KEY_BASE64_PATTERN,
  FORBIDDEN_SECRET_FIELD_NAMES,
  MAX_ACCOUNTS_PER_RESPONSE,
  MAX_CAPABILITY_ACCOUNTS_PER_CHAIN,
  MAX_CAPABILITY_CHAINS,
  MAX_PROTOCOL_RESPONSE_LINE_BYTES,
  MAX_RAW_PROTOCOL_JSON_BYTES,
  MAX_SESSION_TTL_MS,
  MAX_SIGNING_CAPABILITIES,
  MAX_SUI_SIGN_PERSONAL_MESSAGE_BASE64_CHARS,
  MAX_SUI_SIGN_PERSONAL_MESSAGE_BYTES,
  MAX_SUI_SIGN_TRANSACTION_TX_BYTES,
  MAX_SUI_SIGN_TRANSACTION_TX_BYTES_BASE64_CHARS,
  PROTOCOL_VERSION,
  SIGN_RESULT_ERROR_MESSAGES,
  SUI_ADDRESS_PATTERN,
  SUI_CHAIN_ID,
  SUI_DERIVATION_PATH,
  SUI_ED25519_SIGNATURE_BASE64_PATTERN,
  SUI_SIGN_PERSONAL_MESSAGE_METHOD,
  SUI_SIGN_TRANSACTION_METHOD,
  SUI_SIGN_TRANSACTION_NETWORKS,
  UNSUPPORTED_METHOD_MESSAGE,
  consumeProtocolResponseChunk,
  createRequestId,
  hasOnlyObjectKeys,
  hasSecretPayloadKey,
  isRecord,
  isSuiAddressForPublicKey,
  randomBytesPortable,
  utf8ByteLength,
  type SignResultErrorCode,
  type SuiSignMethod,
  type SuiSignTransactionNetwork,
} from "./protocol-primitives.js";

// These boundary functions are defined once in safe-text.ts (the single source of
// truth) and re-exported here because protocol.ts is the wire-ingress boundary
// that applies them; existing importers and tests resolve them via protocol.ts.
export { isGatewayName, isSafeDeviceId, isSafeRequestId, isSessionId, sanitizeDisplayText };
export {
  AGENT_Q_POLICY_SCHEMA,
  APPROVAL_HISTORY_HIGHEST_ACTIONS,
  APPROVAL_HISTORY_POLICY_UPDATE_RESULTS,
  APPROVAL_HISTORY_REASON_CODE_PATTERN,
  APPROVAL_HISTORY_RULE_REF_PATTERN,
  ED25519_PUBLIC_KEY_BASE64_PATTERN,
  FORBIDDEN_SECRET_FIELD_NAMES,
  MAX_ACCOUNTS_PER_RESPONSE,
  MAX_APPROVAL_HISTORY_RECORDS,
  MAX_CAPABILITY_ACCOUNTS_PER_CHAIN,
  MAX_CAPABILITY_CHAINS,
  MAX_POLICY_CHAIN_ID_LENGTH,
  MAX_POLICY_CRITERION_VALUES,
  MAX_POLICY_FIELD_ID_LENGTH,
  MAX_POLICY_METHOD_LENGTH,
  MAX_POLICY_RULE_CRITERIA,
  MAX_POLICY_RULE_COUNT,
  MAX_POLICY_RULE_ID_LENGTH,
  MAX_POLICY_UPDATE_REQUEST_JSON_BYTES,
  MAX_POLICY_VALUE_LENGTH,
  MAX_PROTOCOL_RESPONSE_LINE_BYTES,
  MAX_RAW_PROTOCOL_JSON_BYTES,
  MAX_SESSION_TTL_MS,
  MAX_SIGNING_CAPABILITIES,
  MAX_SUI_SIGN_PERSONAL_MESSAGE_BASE64_CHARS,
  MAX_SUI_SIGN_PERSONAL_MESSAGE_BYTES,
  MAX_SUI_SIGN_TRANSACTION_TX_BYTES,
  MAX_SUI_SIGN_TRANSACTION_TX_BYTES_BASE64_CHARS,
  POLICY_ACTIONS,
  POLICY_FIELD_ID_PATTERN,
  POLICY_ID_PATTERN,
  POLICY_IDENTIFIER_PATTERN,
  POLICY_OPERATORS,
  POLICY_PROPOSE_RESULT_STATUSES,
  POLICY_RULE_ID_PATTERN,
  PROTOCOL_VERSION,
  SIGNING_HISTORY_RECORD_KINDS,
  SIGNING_HISTORY_TERMINAL_RESULTS,
  SIGN_CHAIN_PATTERN,
  SIGN_METHOD_PATTERN,
  SIGN_RESULT_ERROR_MESSAGES,
  SUI_ADDRESS_PATTERN,
  SUI_CHAIN_ID,
  SUI_DERIVATION_PATH,
  SUI_ED25519_SIGNATURE_BASE64_PATTERN,
  SUI_SIGN_PERSONAL_MESSAGE_METHOD,
  SUI_SIGN_TRANSACTION_METHOD,
  SUI_SIGN_TRANSACTION_NETWORKS,
  UINT_DECIMAL_STRING_PATTERN,
  UNSUPPORTED_METHOD_MESSAGE,
  consumeProtocolResponseChunk,
  createRequestId,
  isSuiAddressForPublicKey,
};
export { ProtocolError };
export type { DeviceState, ProvisioningState, SignResultErrorCode, SuiSignMethod, SuiSignTransactionNetwork };
export type {
  Account,
  AccountsResponse,
  CapabilitiesResponse,
  CapabilityAccount,
  CapabilityChain,
  ConnectApprovedResponse,
  ConnectRejectedResponse,
  ConnectRequest,
  ConnectResponse,
  DisconnectRequest,
  DisconnectResponse,
  GetAccountsRequest,
  GetCapabilitiesRequest,
  ProtocolErrorResponse,
  SignPersonalMessageParams,
  SignPersonalMessageRequest,
  SignPersonalMessageSignedResponse,
  SignResultAuthorization,
  SignResultPolicyRejectedResponse,
  SignResultResponse,
  SignResultSignedResponse,
  SignResultSigningFailedResponse,
  SignResultStatus,
  SignResultUserRejectedResponse,
  SignTransactionParams,
  SignTransactionRequest,
  SignTransactionSignedResponse,
  SigningCapabilities,
  SigningCapabilityEntry,
} from "./provider-protocol.js";

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

export interface PolicyGetRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "policy_get";
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

export interface PolicyProposeRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "policy_propose";
  sessionId: string;
  params: {
    policy: Record<string, unknown>;
  };
}

export type ProtocolRequest =
  | GetStatusRequest
  | IdentifyDeviceRequest
  | ConnectRequest
  | DisconnectRequest
  | GetCapabilitiesRequest
  | GetAccountsRequest
  | PolicyGetRequest
  | GetApprovalHistoryRequest
  | PolicyProposeRequest
  | SignTransactionRequest
  | SignPersonalMessageRequest;

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

export type PolicyAction = "reject" | "sign";
export type PolicyOperator = "eq" | "in" | "lte";

export interface PolicyCriterion {
  field: string;
  op: PolicyOperator;
  value?: string;
  values?: string[];
}

export interface PolicyRule {
  id: string;
  chain: string;
  method: string;
  action: PolicyAction;
  criteria: PolicyCriterion[];
}

export interface PolicyDocument {
  schema: string;
  policyId: string;
  defaultAction: PolicyAction;
  ruleCount: number;
  rules: PolicyRule[];
}

export interface PolicyResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "policy";
  policy: PolicyDocument;
}

export type SigningHistoryRecordKind = "confirmation" | "terminal";

export type SigningHistoryTerminalResult =
  | "signed"
  | "user_rejected"
  | "user_timed_out"
  | "policy_rejected"
  | "signing_failed";

export type ApprovalHistoryPolicyUpdateResult =
  | "applied"
  | "rejected"
  | "timed_out"
  | "storage_error";

export type ApprovalHistoryHighestAction = PolicyAction;

interface ApprovalHistoryRecordBase {
  seq: string;
  uptimeMs: string;
  timeSource: "uptime";
  eventKind: "policy_update" | "signing";
  reasonCode: string;
}

export interface PolicyUpdateApprovalHistoryRecord extends ApprovalHistoryRecordBase {
  eventKind: "policy_update";
  result: ApprovalHistoryPolicyUpdateResult;
  policyHash: string;
  ruleCount: number;
  highestAction: ApprovalHistoryHighestAction;
}

export interface SigningApprovalHistoryRecord extends ApprovalHistoryRecordBase {
  eventKind: "signing";
  recordKind: SigningHistoryRecordKind;
  authorization: "user" | "policy";
  chain: string;
  method: string;
  payloadDigest: string;
  confirmationKind?: "local_pin" | "physical_confirm" | "policy";
  policyHash?: string;
  ruleRef?: string;
  terminalResult?: SigningHistoryTerminalResult;
}

export type ApprovalHistoryRecord =
  | PolicyUpdateApprovalHistoryRecord
  | SigningApprovalHistoryRecord;

export interface ApprovalHistoryResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "approval_history";
  records: ApprovalHistoryRecord[];
  hasMore: boolean;
}

export type PolicyProposeResultStatus =
  | "applied"
  | "rejected"
  | "timed_out"
  | "invalid_policy"
  | "ui_error"
  | "storage_error"
  | "consistency_error";

export interface PolicyProposeResultPolicySummary {
  policyHash: string;
  ruleCount: number;
  highestAction: ApprovalHistoryHighestAction;
}

export interface PolicyProposeResultResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "policy_propose_result";
  status: PolicyProposeResultStatus;
  reasonCode: string;
  policy?: PolicyProposeResultPolicySummary;
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
  | PolicyProposeResultResponse
  | SignResultResponse
  | ProtocolErrorResponse;

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
  const bytes = randomBytesPortable(2);
  return ((((bytes[0] ?? 0) << 8) | (bytes[1] ?? 0)) % 10000).toString().padStart(4, "0");
}

export const makeConnectRequest = makeProviderConnectRequest;
export const makeDisconnectRequest = makeProviderDisconnectRequest;
export const makeGetCapabilitiesRequest = makeProviderGetCapabilitiesRequest;
export const makeGetAccountsRequest = makeProviderGetAccountsRequest;

export function makePolicyGetRequest(sessionId: string, id = createRequestId()): PolicyGetRequest {
  validateRequestId(id);
  if (!isSessionId(sessionId)) {
    throw new ProtocolError("invalid_session", "Invalid sessionId.");
  }
  return {
    id,
    version: PROTOCOL_VERSION,
    type: "policy_get",
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

export function makePolicyProposeRequest(
  sessionId: string,
  policy: Record<string, unknown>,
  id = createRequestId(),
): PolicyProposeRequest {
  validateRequestId(id);
  if (!isSessionId(sessionId)) {
    throw new ProtocolError("invalid_session", "Invalid sessionId.");
  }
  validatePolicyProposeInput(policy);
  const request: PolicyProposeRequest = {
    id,
    version: PROTOCOL_VERSION,
    type: "policy_propose",
    sessionId,
    params: {
      policy,
    },
  };
  if (utf8ByteLength(JSON.stringify(request)) > MAX_POLICY_UPDATE_REQUEST_JSON_BYTES) {
    throw new ProtocolError("invalid_params", "policy_propose request is too large for the runtime.");
  }
  return request;
}

export const makeSignTransactionRequest = makeProviderSignTransactionRequest;
export const makeSignPersonalMessageRequest = makeProviderSignPersonalMessageRequest;

export function validatePolicyProposeRequestInput(
  sessionId: string,
  policy: Record<string, unknown>,
): void {
  makePolicyProposeRequest(sessionId, policy, "req_000000000000000000000000");
}

export function validateSignRequestInput(
  chain: unknown,
  method: unknown,
  params: unknown,
  requestType = "sign",
): SignTransactionParams {
  return validateProviderSignTransactionInput(chain, method, params, requestType);
}

export function validateSignPersonalMessageRequestInput(
  chain: unknown,
  method: unknown,
  params: unknown,
  requestType = "sign_personal_message",
): SignPersonalMessageParams {
  return validateProviderSignPersonalMessageInput(chain, method, params, requestType);
}

export function validatePolicyProposeInput(policy: unknown): asserts policy is Record<string, unknown> {
  if (!isRecord(policy) || Array.isArray(policy)) {
    throw new ProtocolError("invalid_params", "policy_propose policy must be an object.");
  }
  if (hasSecretPayloadKey(policy)) {
    throw new ProtocolError("invalid_params", "policy_propose policy must not include secret material.");
  }
  let serialized: string | undefined;
  try {
    serialized = JSON.stringify(policy);
  } catch {
    throw new ProtocolError("invalid_params", "policy_propose policy must be JSON serializable.");
  }
  if (serialized === undefined) {
    throw new ProtocolError("invalid_params", "policy_propose policy must be JSON serializable.");
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

  if (isProviderProtocolResponseType(value.type)) {
    return parseProviderProtocolResponse(line, expectedId);
  }

  if (value.type === "status") {
    if (!hasOnlyObjectKeys(value, ["id", "version", "type", "device", "provisioning"])) {
      throw new ProtocolError("protocol_error", "Status response contains unsupported fields.");
    }
    requireWireDeviceStatusShape(value.device, "Status response device object");
    requireWireProvisioningStatusShape(value.provisioning, "Status response provisioning object");
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
    if (!hasOnlyObjectKeys(value, ["id", "version", "type", "status", "code", "device"])) {
      throw new ProtocolError("protocol_error", "Identify response contains unsupported fields.");
    }
    requireWireDeviceStatusShape(value.device, "Identify response device object");
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
    const policy = sanitizeCurrentPolicyDocument(value.policy);
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

  if (value.type === "policy_propose_result") {
    if (typeof value.id !== "string") {
      throw new ProtocolError("protocol_error", "policy_propose_result id is malformed.");
    }
    if (hasSecretPayloadKey(value)) {
      throw new ProtocolError("protocol_error", "policy_propose_result must not include secret material.");
    }
    if (!hasOnlyObjectKeys(value, ["id", "version", "type", "status", "reasonCode", "policy"])) {
      throw new ProtocolError("protocol_error", "policy_propose_result contains unsupported fields.");
    }
    if (
      !POLICY_PROPOSE_RESULT_STATUSES.includes(value.status as PolicyProposeResultStatus) ||
      typeof value.reasonCode !== "string" ||
      !APPROVAL_HISTORY_REASON_CODE_PATTERN.test(value.reasonCode)
    ) {
      throw new ProtocolError("protocol_error", "policy_propose_result is malformed.");
    }
    const policy = sanitizePolicyProposeResultPolicy(value.policy);
    if (value.status === "invalid_policy") {
      if (policy !== undefined) {
        throw new ProtocolError("protocol_error", "Invalid policy result must not include policy metadata.");
      }
    } else if (policy === undefined) {
      throw new ProtocolError("protocol_error", "policy_propose_result policy metadata is malformed.");
    }
    return {
      id: value.id,
      version: PROTOCOL_VERSION,
      type: "policy_propose_result",
      status: value.status as PolicyProposeResultStatus,
      reasonCode: value.reasonCode,
      ...(policy !== undefined ? { policy } : {}),
    };
  }

  throw new ProtocolError("protocol_error", "Protocol response type is unsupported.");
}

export function parseProviderProtocolResponse(line: string, expectedId?: string): ProtocolResponse {
  return parseProviderProtocolResponseCore(line, expectedId) as ProtocolResponse;
}

function isProviderProtocolResponseType(value: unknown): boolean {
  return (
    value === "error" ||
    value === "connect_result" ||
    value === "disconnect_result" ||
    value === "capabilities" ||
    value === "accounts" ||
    value === "sign_result"
  );
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

export function assertPolicyProposeResultResponse(response: ProtocolResponse): PolicyProposeResultResponse {
  if (response.type === "error") {
    throw new ProtocolError(response.error.code, response.error.message);
  }
  if (response.type !== "policy_propose_result") {
    throw new ProtocolError("protocol_error", "Protocol response type is not policy_propose_result.");
  }
  return response;
}

export function assertSignResultResponse(response: ProtocolResponse): SignResultResponse {
  if (response.type === "error") {
    throw new ProtocolError(response.error.code, response.error.message);
  }
  if (response.type !== "sign_result") {
    throw new ProtocolError("protocol_error", "Protocol response type is not sign_result.");
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

export function isSignChain(value: unknown): value is string {
  return typeof value === "string" && SIGN_CHAIN_PATTERN.test(value);
}

export function isSignMethod(value: unknown): value is string {
  return typeof value === "string" && SIGN_METHOD_PATTERN.test(value);
}

export function isUint64DecimalString(value: unknown): value is string {
  if (typeof value !== "string" || !UINT_DECIMAL_STRING_PATTERN.test(value)) {
    return false;
  }
  return value.length < UINT64_MAX_DECIMAL.length ||
    (value.length === UINT64_MAX_DECIMAL.length && value <= UINT64_MAX_DECIMAL);
}

const UINT64_MAX_DECIMAL = "18446744073709551615";

function isBoundedPolicyString(value: unknown, maxLength: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength;
}

function isPolicyIdentifierString(value: unknown, maxLength: number): value is string {
  return isBoundedPolicyString(value, maxLength) && POLICY_IDENTIFIER_PATTERN.test(value);
}

type PolicyValueType = "string" | "u64_decimal";

interface PolicyFieldDescriptor {
  type: PolicyValueType;
  allowEq: boolean;
  allowIn: boolean;
  allowLte: boolean;
}

const COMMON_POLICY_FIELDS: Record<string, PolicyFieldDescriptor> = {
  "common.chain": { type: "string", allowEq: true, allowIn: true, allowLte: false },
  "common.method": { type: "string", allowEq: true, allowIn: true, allowLte: false },
  "common.intent": { type: "string", allowEq: true, allowIn: true, allowLte: false },
};

const SUI_SIGN_TRANSACTION_POLICY_FIELDS: Record<string, PolicyFieldDescriptor> = {
  "sui.command_shape": { type: "string", allowEq: true, allowIn: true, allowLte: false },
  "sui.sender_address": { type: "string", allowEq: true, allowIn: true, allowLte: false },
  "sui.recipient_address": { type: "string", allowEq: true, allowIn: true, allowLte: false },
  "sui.coin_type": { type: "string", allowEq: true, allowIn: true, allowLte: false },
  "sui.amount_raw": { type: "u64_decimal", allowEq: true, allowIn: false, allowLte: true },
  "sui.gas_budget": { type: "u64_decimal", allowEq: true, allowIn: false, allowLte: true },
  "sui.gas_price": { type: "u64_decimal", allowEq: true, allowIn: false, allowLte: true },
};

function policyRuleHasSupportedMethod(rule: Pick<PolicyRule, "chain" | "method">): boolean {
  return rule.chain === SUI_CHAIN_ID && rule.method === SUI_SIGN_TRANSACTION_METHOD;
}

function findPolicyFieldDescriptor(rule: Pick<PolicyRule, "chain" | "method">, field: string): PolicyFieldDescriptor | null {
  if (!policyRuleHasSupportedMethod(rule)) {
    return null;
  }
  return COMMON_POLICY_FIELDS[field] ?? SUI_SIGN_TRANSACTION_POLICY_FIELDS[field] ?? null;
}

function policyOperatorAllowed(descriptor: PolicyFieldDescriptor, op: PolicyOperator): boolean {
  switch (op) {
    case "eq":
      return descriptor.allowEq;
    case "in":
      return descriptor.allowIn;
    case "lte":
      return descriptor.allowLte;
  }
}

function policyCriterionMatchesDescriptor(
  rule: Pick<PolicyRule, "chain" | "method">,
  criterion: PolicyCriterion,
): boolean {
  const descriptor = findPolicyFieldDescriptor(rule, criterion.field);
  if (descriptor === null || !policyOperatorAllowed(descriptor, criterion.op)) {
    return false;
  }
  if (criterion.op === "in") {
    if (criterion.values === undefined || criterion.value !== undefined) {
      return false;
    }
    return descriptor.type !== "u64_decimal" ||
      criterion.values.every((value) => isUint64DecimalString(value));
  }
  if (criterion.value === undefined || criterion.values !== undefined) {
    return false;
  }
  return descriptor.type !== "u64_decimal" || isUint64DecimalString(criterion.value);
}

function policyCriterionEq(criterion: PolicyCriterion, field: string, value: string): boolean {
  return criterion.field === field &&
    criterion.op === "eq" &&
    criterion.value === value;
}

function policyCriterionLte(criterion: PolicyCriterion, field: string): boolean {
  return criterion.field === field &&
    criterion.op === "lte" &&
    criterion.value !== undefined &&
    isUint64DecimalString(criterion.value);
}

function policyRecipientIsBounded(criterion: PolicyCriterion): boolean {
  if (criterion.field !== "sui.recipient_address") {
    return false;
  }
  if (criterion.op === "eq") {
    return criterion.value !== undefined && criterion.value.length > 0;
  }
  return criterion.op === "in" &&
    criterion.values !== undefined &&
    criterion.values.length === 1;
}

function policySignRuleIsBounded(rule: PolicyRule): boolean {
  if (rule.action !== "sign") {
    return true;
  }
  if (rule.chain !== SUI_CHAIN_ID ||
      rule.method !== SUI_SIGN_TRANSACTION_METHOD ||
      rule.criteria.length === 0) {
    return false;
  }

  let hasIntent = false;
  let hasShape = false;
  let hasAsset = false;
  let hasRecipient = false;
  let hasAmountBound = false;
  let hasGasBudgetBound = false;
  let hasGasPriceBound = false;
  for (const criterion of rule.criteria) {
    hasIntent = hasIntent || policyCriterionEq(criterion, "common.intent", "single_asset_transfer");
    hasShape = hasShape || policyCriterionEq(criterion, "sui.command_shape", "restricted_transfer");
    hasAsset = hasAsset || policyCriterionEq(criterion, "sui.coin_type", "0x2::sui::SUI");
    hasRecipient = hasRecipient || policyRecipientIsBounded(criterion);
    hasAmountBound = hasAmountBound || policyCriterionLte(criterion, "sui.amount_raw");
    hasGasBudgetBound = hasGasBudgetBound || policyCriterionLte(criterion, "sui.gas_budget");
    hasGasPriceBound = hasGasPriceBound || policyCriterionLte(criterion, "sui.gas_price");
  }
  return hasIntent &&
    hasShape &&
    hasAsset &&
    hasRecipient &&
    hasAmountBound &&
    hasGasBudgetBound &&
    hasGasPriceBound;
}

function sanitizePolicyCriterion(value: unknown): PolicyCriterion | null {
  if (!isRecord(value)) {
    return null;
  }
  if (hasSecretPayloadKey(value)) {
    throw new ProtocolError("protocol_error", "Policy criterion must not include secret material.");
  }
  if (!isBoundedPolicyString(value.field, MAX_POLICY_FIELD_ID_LENGTH) ||
      !POLICY_FIELD_ID_PATTERN.test(value.field) ||
      typeof value.op !== "string" ||
      !POLICY_OPERATORS.includes(value.op as PolicyOperator)) {
    return null;
  }

  const op = value.op as PolicyOperator;
  if (op === "in") {
    if (!hasOnlyObjectKeys(value, ["field", "op", "values"])) {
      throw new ProtocolError("protocol_error", "Policy criterion contains unsupported fields.");
    }
    if (!Array.isArray(value.values) ||
        value.values.length === 0 ||
        value.values.length > MAX_POLICY_CRITERION_VALUES ||
        !value.values.every((item) => isBoundedPolicyString(item, MAX_POLICY_VALUE_LENGTH))) {
      return null;
    }
    return {
      field: value.field,
      op,
      values: [...value.values],
    };
  }

  if (!hasOnlyObjectKeys(value, ["field", "op", "value"])) {
    throw new ProtocolError("protocol_error", "Policy criterion contains unsupported fields.");
  }
  if (!isBoundedPolicyString(value.value, MAX_POLICY_VALUE_LENGTH)) {
    return null;
  }
  return {
    field: value.field,
    op,
    value: value.value,
  };
}

function sanitizePolicyRule(value: unknown): PolicyRule | null {
  if (!isRecord(value)) {
    return null;
  }
  if (hasSecretPayloadKey(value)) {
    throw new ProtocolError("protocol_error", "Policy rule must not include secret material.");
  }
  if (!hasOnlyObjectKeys(value, ["id", "chain", "method", "action", "criteria"])) {
    throw new ProtocolError("protocol_error", "Policy rule contains unsupported fields.");
  }
  if (
    !isBoundedPolicyString(value.id, MAX_POLICY_RULE_ID_LENGTH) ||
    !POLICY_RULE_ID_PATTERN.test(value.id) ||
    !isPolicyIdentifierString(value.chain, MAX_POLICY_CHAIN_ID_LENGTH) ||
    !isPolicyIdentifierString(value.method, MAX_POLICY_METHOD_LENGTH) ||
    typeof value.action !== "string" ||
    !POLICY_ACTIONS.includes(value.action as PolicyAction) ||
    !Array.isArray(value.criteria) ||
    value.criteria.length > MAX_POLICY_RULE_CRITERIA
  ) {
    return null;
  }

  const criteria = value.criteria.map((criterion) => sanitizePolicyCriterion(criterion));
  if (criteria.some((criterion) => criterion === null)) {
    return null;
  }
  const rule = {
    id: value.id,
    chain: value.chain,
    method: value.method,
    action: value.action as PolicyAction,
    criteria: criteria as PolicyCriterion[],
  };
  if (!policyRuleHasSupportedMethod(rule) ||
      !rule.criteria.every((criterion) => policyCriterionMatchesDescriptor(rule, criterion)) ||
      !policySignRuleIsBounded(rule)) {
    return null;
  }
  return rule;
}

export function sanitizeCurrentPolicyDocument(value: unknown): PolicyDocument | null {
  if (!isRecord(value)) {
    return null;
  }
  if (hasSecretPayloadKey(value)) {
    throw new ProtocolError("protocol_error", "Policy document must not include secret material.");
  }
  if (!hasOnlyObjectKeys(value, ["schema", "policyId", "defaultAction", "ruleCount", "rules"])) {
    throw new ProtocolError("protocol_error", "Policy document contains unsupported fields.");
  }
  if (
    value.schema !== AGENT_Q_POLICY_SCHEMA ||
    typeof value.policyId !== "string" ||
    !POLICY_ID_PATTERN.test(value.policyId) ||
    value.defaultAction !== "reject" ||
    typeof value.ruleCount !== "number" ||
    !Number.isInteger(value.ruleCount) ||
    value.ruleCount < 0 ||
    value.ruleCount > MAX_POLICY_RULE_COUNT ||
    !Array.isArray(value.rules) ||
    value.rules.length !== value.ruleCount
  ) {
    return null;
  }
  const rules = value.rules.map((rule) => sanitizePolicyRule(rule));
  if (rules.some((rule) => rule === null)) {
    return null;
  }
  const signRuleCount = rules.filter((rule) => rule?.action === "sign").length;
  if (signRuleCount > 1) {
    return null;
  }
  return {
    schema: value.schema,
    policyId: value.policyId,
    defaultAction: value.defaultAction,
    ruleCount: value.ruleCount,
    rules: rules as PolicyRule[],
  };
}

function sanitizePolicyProposeResultPolicy(value: unknown): PolicyProposeResultPolicySummary | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!isRecord(value)) {
    throw new ProtocolError("protocol_error", "policy_propose_result policy metadata is malformed.");
  }
  if (hasSecretPayloadKey(value)) {
    throw new ProtocolError("protocol_error", "policy_propose_result policy metadata must not include secret material.");
  }
  if (!hasOnlyObjectKeys(value, ["policyHash", "ruleCount", "highestAction"])) {
    throw new ProtocolError("protocol_error", "policy_propose_result policy metadata contains unsupported fields.");
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
    throw new ProtocolError("protocol_error", "policy_propose_result policy metadata is malformed.");
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
    "confirmationKind",
    "authorization",
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

  if (value.eventKind === "signing") {
    if (
      value.result !== undefined ||
      value.ruleCount !== undefined ||
      value.highestAction !== undefined ||
      !SIGNING_HISTORY_RECORD_KINDS.includes(value.recordKind as SigningHistoryRecordKind) ||
      (value.authorization !== "user" && value.authorization !== "policy") ||
      !isSignChain(value.chain) ||
      !isSignMethod(value.method) ||
      typeof value.payloadDigest !== "string" ||
      !POLICY_ID_PATTERN.test(value.payloadDigest)
    ) {
      throw new ProtocolError("protocol_error", "Approval history signing record is malformed.");
    }
    if (value.recordKind === "confirmation") {
      if (value.terminalResult !== undefined) {
        throw new ProtocolError("protocol_error", "Approval history signing record is malformed.");
      }
      if (value.authorization === "user") {
        if (
          (value.confirmationKind !== "local_pin" &&
            value.confirmationKind !== "physical_confirm") ||
          value.policyHash !== undefined ||
          value.ruleRef !== undefined
        ) {
          throw new ProtocolError("protocol_error", "Approval history signing record is malformed.");
        }
        return {
          seq: value.seq,
          uptimeMs: value.uptimeMs,
          timeSource: "uptime",
          eventKind: "signing",
          reasonCode: value.reasonCode,
          recordKind: "confirmation",
          authorization: "user",
          confirmationKind: value.confirmationKind,
          chain: value.chain,
          method: value.method,
          payloadDigest: value.payloadDigest,
        };
      }
      if (
        value.confirmationKind !== "policy" ||
        typeof value.policyHash !== "string" ||
        !POLICY_ID_PATTERN.test(value.policyHash) ||
        typeof value.ruleRef !== "string" ||
        !APPROVAL_HISTORY_RULE_REF_PATTERN.test(value.ruleRef)
      ) {
        throw new ProtocolError("protocol_error", "Approval history signing policy metadata is malformed.");
      }
      return {
        seq: value.seq,
        uptimeMs: value.uptimeMs,
        timeSource: "uptime",
        eventKind: "signing",
        reasonCode: value.reasonCode,
        recordKind: "confirmation",
        authorization: "policy",
        confirmationKind: "policy",
        chain: value.chain,
        method: value.method,
        payloadDigest: value.payloadDigest,
        policyHash: value.policyHash,
        ruleRef: value.ruleRef,
      };
    }
    if (
      value.confirmationKind !== undefined ||
      !SIGNING_HISTORY_TERMINAL_RESULTS.includes(
        value.terminalResult as SigningHistoryTerminalResult,
      )
    ) {
      throw new ProtocolError("protocol_error", "Approval history signing record is malformed.");
    }
    const terminalResult = value.terminalResult as SigningHistoryTerminalResult;
    if (value.authorization === "policy") {
      if (
        !["signed", "policy_rejected", "signing_failed"].includes(terminalResult) ||
        typeof value.policyHash !== "string" ||
        !POLICY_ID_PATTERN.test(value.policyHash) ||
        typeof value.ruleRef !== "string" ||
        !APPROVAL_HISTORY_RULE_REF_PATTERN.test(value.ruleRef)
      ) {
        throw new ProtocolError("protocol_error", "Approval history signing policy metadata is malformed.");
      }
    } else if (
      !["signed", "user_rejected", "user_timed_out", "signing_failed"].includes(terminalResult) ||
      value.policyHash !== undefined ||
      value.ruleRef !== undefined
    ) {
      throw new ProtocolError("protocol_error", "Approval history signing policy metadata is malformed.");
    }
    return {
      seq: value.seq,
      uptimeMs: value.uptimeMs,
      timeSource: "uptime",
      eventKind: "signing",
      reasonCode: value.reasonCode,
      recordKind: "terminal",
      authorization: value.authorization as "user" | "policy",
      terminalResult,
      chain: value.chain,
      method: value.method,
      payloadDigest: value.payloadDigest,
      ...(value.authorization === "policy" ? {
        policyHash: value.policyHash as string,
        ruleRef: value.ruleRef as string,
      } : {}),
    };
  }

  throw new ProtocolError("protocol_error", "Approval history record is malformed.");
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

function requireWireDeviceStatusShape(value: unknown, label: string): void {
  if (
    !isRecord(value) ||
    !hasOnlyObjectKeys(value, ["deviceId", "state", "firmwareName", "hardware", "firmwareVersion"])
  ) {
    throw new ProtocolError("protocol_error", `${label} contains unsupported fields.`);
  }
}

function requireWireProvisioningStatusShape(value: unknown, label: string): void {
  if (!isRecord(value) || !hasOnlyObjectKeys(value, ["state"])) {
    throw new ProtocolError("protocol_error", `${label} contains unsupported fields.`);
  }
}
