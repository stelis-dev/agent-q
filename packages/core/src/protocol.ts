import {
  IDENTIFICATION_CODE_PATTERN,
  MAX_FIRMWARE_NAME_LENGTH,
  MAX_FIRMWARE_VERSION_LENGTH,
  MAX_HARDWARE_ID_LENGTH,
  isDeviceState,
  isClientName,
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
  parseProviderProtocolResponse as parseProviderProtocolResponseCore,
  validateSignPersonalMessageParams as validateProviderSignPersonalMessageParams,
  validateSignPersonalMessageInput as validateProviderSignPersonalMessageInput,
  validateSignTransactionParams as validateProviderSignTransactionParams,
  validateSignTransactionInput as validateProviderSignTransactionInput,
  type Account,
  type AccountsResponse,
  type CapabilitiesResponse,
  type CapabilityAccount,
  type CapabilityChain,
  type CredentialCapability,
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
  type SignOperationType,
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
  type SupportedSignRoute,
  type SigningCapabilities,
  type SigningCapabilityEntry,
} from "./provider-protocol.js";
import {
  sanitizeAckResultResponse,
  type AckResultRequest,
  type AckResultResponse,
  type GetResultRequest,
} from "./protocol-recovery.js";
import {
  isPayloadUploadResponseType,
  sanitizePayloadUploadResponse,
  type PayloadDeliveryCapability,
  type PayloadUploadAbortRequest,
  type PayloadUploadAbortResultResponse,
  type PayloadUploadBeginRequest,
  type PayloadUploadBeginResultResponse,
  type PayloadUploadChunkRequest,
  type PayloadUploadChunkResultResponse,
  type PayloadUploadFinishRequest,
  type PayloadUploadFinishResultResponse,
  type PayloadUploadRequest,
  type PayloadUploadResponse,
  type StagedSignTransactionParams,
  type StagedSignTransactionRequest,
} from "./protocol-payload-delivery.js";
import { ProtocolError } from "./protocol-error.js";
import {
  AGENT_Q_POLICY_SCHEMA,
  APPROVAL_HISTORY_HIGHEST_ACTIONS,
  APPROVAL_HISTORY_POLICY_UPDATE_RESULTS,
  APPROVAL_HISTORY_REASON_CODE_PATTERN,
  APPROVAL_HISTORY_RULE_REF_PATTERN,
  MAX_POLICY_BLOCKCHAIN_LENGTH,
  MAX_POLICY_BLOCKCHAINS,
  MAX_POLICY_CONDITION_VALUES,
  MAX_POLICY_CONDITIONS_PER_POLICY,
  MAX_APPROVAL_HISTORY_RECORDS,
  MAX_POLICY_FIELD_ID_LENGTH,
  MAX_POLICY_ID_LENGTH,
  MAX_POLICY_NETWORK_LENGTH,
  MAX_POLICY_NETWORKS_PER_BLOCKCHAIN,
  MAX_POLICY_POLICIES_PER_NETWORK,
  MAX_POLICY_TOTAL_CONDITIONS,
  MAX_POLICY_TOTAL_NETWORKS,
  MAX_POLICY_TOTAL_POLICIES,
  MAX_POLICY_UPDATE_REQUEST_JSON_BYTES,
  MAX_POLICY_VALUE_LENGTH,
  POLICY_ACTIONS,
  POLICY_ENTRY_ID_PATTERN,
  POLICY_FIELD_ID_PATTERN,
  POLICY_ID_PATTERN,
  POLICY_OPERATORS,
  POLICY_PROPOSE_RESULT_STATUSES,
  SIGNING_HISTORY_RECORD_KINDS,
  SIGNING_HISTORY_TERMINAL_RESULTS,
  SIGN_CHAIN_PATTERN,
  SIGN_METHOD_PATTERN,
  UINT_DECIMAL_STRING_PATTERN,
} from "./protocol-management-primitives.js";
import {
  CREDENTIAL_PREPARE_OPERATION,
  CREDENTIAL_PROPOSE_OPERATION,
  ED25519_PUBLIC_KEY_BASE64_PATTERN,
  FORBIDDEN_SECRET_FIELD_NAMES,
  MAX_ACCOUNTS_PER_RESPONSE,
  MAX_CAPABILITY_ACCOUNTS_PER_CHAIN,
  MAX_CAPABILITY_CHAINS,
  MAX_CREDENTIAL_CAPABILITIES,
  MAX_PROTOCOL_RESPONSE_LINE_BYTES,
  MAX_RAW_PROTOCOL_JSON_BYTES,
  MAX_SESSION_TTL_MS,
  MAX_SIGN_RESULT_PAYLOAD_BASE64_CHARS,
  MAX_SIGNING_CAPABILITIES,
  MAX_SUI_SIGN_PERSONAL_MESSAGE_BASE64_CHARS,
  MAX_SUI_SIGN_PERSONAL_MESSAGE_BYTES,
  MAX_SUI_SIGN_TRANSACTION_TX_BYTES,
  MAX_SUI_SIGN_TRANSACTION_TX_BYTES_BASE64_CHARS,
  MAX_SUI_ZKLOGIN_HEADER_BASE64_CHARS,
  MAX_SUI_ZKLOGIN_ISS_BASE64_CHARS,
  MAX_SUI_ZKLOGIN_PUBLIC_KEY_BYTES,
  MIN_SUI_ZKLOGIN_PUBLIC_KEY_BYTES,
  PROTOCOL_VERSION,
  SIGN_RESULT_ERROR_MESSAGES,
  SUI_ADDRESS_PATTERN,
  SUI_CHAIN_ID,
  SUI_DERIVATION_PATH,
  SUI_ED25519_SIGNATURE_BASE64_PATTERN,
  SUI_SCHEME_PREFIXED_ED25519_PUBLIC_KEY_BYTES,
  SUI_SIGNATURE_SCHEME_FLAG_ED25519,
  SUI_SIGNATURE_SCHEME_FLAG_ZKLOGIN,
  SUI_SIGN_PERSONAL_MESSAGE_METHOD,
  SUI_SIGN_TRANSACTION_METHOD,
  SUI_SIGN_TRANSACTION_NETWORKS,
  SUI_ZKLOGIN_BASE64URL_NO_PADDING_PATTERN,
  SUI_ZKLOGIN_CREDENTIAL,
  SUI_ZKLOGIN_PROOF_POINT_DECIMAL_PATTERN,
  UNSUPPORTED_METHOD_MESSAGE,
  consumeProtocolResponseChunk,
  createRequestId,
  decodeCanonicalBase64,
  hasOnlyObjectKeys,
  hasSecretPayloadKey,
  isUint64DecimalString,
  isUint256DecimalString,
  isRecord,
  isSuiAddressForPublicKey,
  isSuiAddressForSchemePrefixedPublicKey,
  randomBytesPortable,
  utf8ByteLength,
  type SignResultErrorCode,
  type SuiSignMethod,
  type SuiSignTransactionNetwork,
} from "./protocol-primitives.js";

// These boundary functions are defined once in safe-text.ts (the single source of
// truth) and re-exported here because protocol.ts is the wire-ingress boundary
// that applies them; existing importers and tests resolve them via protocol.ts.
export { isClientName, isSafeDeviceId, isSafeRequestId, isSessionId, sanitizeDisplayText };
export {
  AGENT_Q_POLICY_SCHEMA,
  APPROVAL_HISTORY_HIGHEST_ACTIONS,
  APPROVAL_HISTORY_POLICY_UPDATE_RESULTS,
  APPROVAL_HISTORY_REASON_CODE_PATTERN,
  APPROVAL_HISTORY_RULE_REF_PATTERN,
  CREDENTIAL_PREPARE_OPERATION,
  CREDENTIAL_PROPOSE_OPERATION,
  ED25519_PUBLIC_KEY_BASE64_PATTERN,
  FORBIDDEN_SECRET_FIELD_NAMES,
  MAX_ACCOUNTS_PER_RESPONSE,
  MAX_APPROVAL_HISTORY_RECORDS,
  MAX_CAPABILITY_ACCOUNTS_PER_CHAIN,
  MAX_CAPABILITY_CHAINS,
  MAX_CREDENTIAL_CAPABILITIES,
  MAX_POLICY_BLOCKCHAIN_LENGTH,
  MAX_POLICY_BLOCKCHAINS,
  MAX_POLICY_CONDITION_VALUES,
  MAX_POLICY_CONDITIONS_PER_POLICY,
  MAX_POLICY_FIELD_ID_LENGTH,
  MAX_POLICY_ID_LENGTH,
  MAX_POLICY_NETWORK_LENGTH,
  MAX_POLICY_NETWORKS_PER_BLOCKCHAIN,
  MAX_POLICY_POLICIES_PER_NETWORK,
  MAX_POLICY_TOTAL_CONDITIONS,
  MAX_POLICY_TOTAL_NETWORKS,
  MAX_POLICY_TOTAL_POLICIES,
  MAX_POLICY_UPDATE_REQUEST_JSON_BYTES,
  MAX_POLICY_VALUE_LENGTH,
  MAX_PROTOCOL_RESPONSE_LINE_BYTES,
  MAX_RAW_PROTOCOL_JSON_BYTES,
  MAX_SESSION_TTL_MS,
  MAX_SIGN_RESULT_PAYLOAD_BASE64_CHARS,
  MAX_SIGNING_CAPABILITIES,
  MAX_SUI_SIGN_PERSONAL_MESSAGE_BASE64_CHARS,
  MAX_SUI_SIGN_PERSONAL_MESSAGE_BYTES,
  MAX_SUI_SIGN_TRANSACTION_TX_BYTES,
  MAX_SUI_SIGN_TRANSACTION_TX_BYTES_BASE64_CHARS,
  MAX_SUI_ZKLOGIN_HEADER_BASE64_CHARS,
  MAX_SUI_ZKLOGIN_ISS_BASE64_CHARS,
  MAX_SUI_ZKLOGIN_PUBLIC_KEY_BYTES,
  MIN_SUI_ZKLOGIN_PUBLIC_KEY_BYTES,
  POLICY_ACTIONS,
  POLICY_ENTRY_ID_PATTERN,
  POLICY_FIELD_ID_PATTERN,
  POLICY_ID_PATTERN,
  POLICY_OPERATORS,
  POLICY_PROPOSE_RESULT_STATUSES,
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
  SUI_SCHEME_PREFIXED_ED25519_PUBLIC_KEY_BYTES,
  SUI_SIGNATURE_SCHEME_FLAG_ED25519,
  SUI_SIGNATURE_SCHEME_FLAG_ZKLOGIN,
  SUI_SIGN_PERSONAL_MESSAGE_METHOD,
  SUI_SIGN_TRANSACTION_METHOD,
  SUI_SIGN_TRANSACTION_NETWORKS,
  SUI_ZKLOGIN_BASE64URL_NO_PADDING_PATTERN,
  SUI_ZKLOGIN_CREDENTIAL,
  SUI_ZKLOGIN_PROOF_POINT_DECIMAL_PATTERN,
  UINT_DECIMAL_STRING_PATTERN,
  UNSUPPORTED_METHOD_MESSAGE,
  consumeProtocolResponseChunk,
  createRequestId,
  isUint64DecimalString,
  isUint256DecimalString,
  isSuiAddressForPublicKey,
  isSuiAddressForSchemePrefixedPublicKey,
};
export { ProtocolError };
export type { DeviceState, ProvisioningState, SignResultErrorCode, SuiSignMethod, SuiSignTransactionNetwork };
export type {
  Account,
  AccountsResponse,
  CapabilitiesResponse,
  CapabilityAccount,
  CapabilityChain,
  CredentialCapability,
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
  SignOperationType,
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
  SupportedSignRoute,
  SigningCapabilities,
  SigningCapabilityEntry,
} from "./provider-protocol.js";
export type {
  AckResultRequest,
  AckResultResponse,
  GetResultRequest,
} from "./protocol-recovery.js";
export type {
  PayloadDeliveryCapability,
  PayloadDeliveryCapabilityLimits,
  PayloadUploadAbortRequest,
  PayloadUploadAbortResultResponse,
  PayloadUploadBeginRequest,
  PayloadUploadBeginResultResponse,
  PayloadUploadChunkRequest,
  PayloadUploadChunkResultResponse,
  PayloadUploadFinishRequest,
  PayloadUploadFinishResultResponse,
  PayloadUploadRequest,
  PayloadUploadResponse,
  StagedSignTransactionParams,
  StagedSignTransactionRequest,
} from "./protocol-payload-delivery.js";
export {
  assertAckResultResponse,
  makeAckResultRequest,
  makeGetResultRequest,
} from "./protocol-recovery.js";
export {
  PAYLOAD_REF_PATTERN,
  PAYLOAD_UPLOAD_ID_PATTERN,
  SIGNABLE_PAYLOAD_KIND_TRANSACTION,
  makePayloadUploadAbortRequest,
  makePayloadUploadBeginRequest,
  makePayloadUploadChunkRequest,
  makePayloadUploadFinishRequest,
  makeStagedSignTransactionRequest,
  normalizePayloadUploadRequest,
  normalizeStagedSignTransactionParams,
  payloadDeliveryCapabilityLimits,
  sanitizePayloadDeliveryCapability,
  sanitizePayloadUploadResponse,
} from "./protocol-payload-delivery.js";
// Signing request builders and route identification are owned by
// provider-protocol because provider adapters and the full protocol share the
// same top-level signing methods. The full protocol entrypoint re-exports the
// same current-route builders instead of wrapping or reclassifying the route.
export {
  identifySignRoute,
  makeSignPersonalMessageRequest,
  makeSignTransactionRequest,
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

export interface CredentialPrepareRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: typeof CREDENTIAL_PREPARE_OPERATION;
  sessionId: string;
  params: {
    chain: typeof SUI_CHAIN_ID;
    credential: typeof SUI_ZKLOGIN_CREDENTIAL;
  };
}

export interface ZkLoginSignatureInputsDto {
  proofPoints: {
    a: [string, string, string];
    b: [[string, string], [string, string], [string, string]];
    c: [string, string, string];
  };
  issBase64Details: {
    value: string;
    indexMod4: 0 | 1 | 2;
  };
  headerBase64: string;
  addressSeed: string;
}

export interface CredentialProposeParams {
  chain: typeof SUI_CHAIN_ID;
  credential: typeof SUI_ZKLOGIN_CREDENTIAL;
  network: SuiSignTransactionNetwork;
  address: string;
  publicKey: string;
  maxEpoch: string;
  inputs: ZkLoginSignatureInputsDto;
}

export interface CredentialProposeRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: typeof CREDENTIAL_PROPOSE_OPERATION;
  sessionId: string;
  params: CredentialProposeParams;
}

export type ProtocolRequest =
  | GetStatusRequest
  | IdentifyDeviceRequest
  | ConnectRequest
  | DisconnectRequest
  | GetCapabilitiesRequest
  | GetAccountsRequest
  | GetResultRequest
  | AckResultRequest
  | PayloadUploadRequest
  | PolicyGetRequest
  | GetApprovalHistoryRequest
  | PolicyProposeRequest
  | CredentialPrepareRequest
  | CredentialProposeRequest
  | StagedSignTransactionRequest
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
export type PolicyOperator =
  | "eq"
  | "in"
  | "not_in"
  | "lte"
  | "contains"
  | "not_contains"
  | "all_in"
  | "none_in";

export interface PolicyCondition {
  field: string;
  op: PolicyOperator;
  where?: {
    type: string;
  };
  value?: string;
  values?: string[];
}

export interface PolicyEntry {
  id: string;
  action: PolicyAction;
  conditions: PolicyCondition[];
}

export interface PolicyNetworkScope {
  network: string;
  policies: PolicyEntry[];
}

export interface PolicyBlockchainScope {
  blockchain: string;
  networks: PolicyNetworkScope[];
}

export interface PolicyDocument {
  schema: string;
  policyId: string;
  defaultAction: PolicyAction;
  blockchainCount: number;
  networkCount: number;
  policyCount: number;
  conditionCount: number;
  blockchains: PolicyBlockchainScope[];
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
  policyCount: number;
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
  blockchainCount: number;
  networkCount: number;
  policyCount: number;
  conditionCount: number;
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

export interface CredentialPrepareResultResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "credential_prepare_result";
  status: "prepared";
  chain: typeof SUI_CHAIN_ID;
  credential: typeof SUI_ZKLOGIN_CREDENTIAL;
  preparation: {
    publicKey: string;
    keyScheme: "ed25519";
    address: string;
  };
}

export type CredentialProposeResultStatus =
  | "activated"
  | "rejected"
  | "timed_out"
  | "invalid_proof"
  | "ui_error"
  | "storage_error"
  | "consistency_error";

export const CREDENTIAL_PROPOSE_RESULT_STATUSES = [
  "activated",
  "rejected",
  "timed_out",
  "invalid_proof",
  "ui_error",
  "storage_error",
  "consistency_error",
] as const;

export interface CredentialProposeResultResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "credential_propose_result";
  status: CredentialProposeResultStatus;
  reasonCode: string;
  sessionEnded: boolean;
}

export type ProtocolResponse =
  | StatusResponse
  | IdentifyDeviceResponse
  | ConnectResponse
  | DisconnectResponse
  | AckResultResponse
  | PayloadUploadResponse
  | CapabilitiesResponse
  | AccountsResponse
  | PolicyResponse
  | ApprovalHistoryResponse
  | PolicyProposeResultResponse
  | CredentialPrepareResultResponse
  | CredentialProposeResultResponse
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

export function makeCredentialPrepareRequest(
  sessionId: string,
  params: unknown,
  id = createRequestId(),
): CredentialPrepareRequest {
  validateRequestId(id);
  if (!isSessionId(sessionId)) {
    throw new ProtocolError("invalid_session", "Invalid sessionId.");
  }
  const normalizedParams = validateCredentialPrepareInput(params);
  const request: CredentialPrepareRequest = {
    id,
    version: PROTOCOL_VERSION,
    type: CREDENTIAL_PREPARE_OPERATION,
    sessionId,
    params: normalizedParams,
  };
  if (utf8ByteLength(JSON.stringify(request)) > MAX_RAW_PROTOCOL_JSON_BYTES) {
    throw new ProtocolError("invalid_params", "credential_prepare request is too large for the runtime.");
  }
  return request;
}

export function makeCredentialProposeRequest(
  sessionId: string,
  params: unknown,
  id = createRequestId(),
): CredentialProposeRequest {
  validateRequestId(id);
  if (!isSessionId(sessionId)) {
    throw new ProtocolError("invalid_session", "Invalid sessionId.");
  }
  const normalizedParams = validateCredentialProposeInput(params);
  const request: CredentialProposeRequest = {
    id,
    version: PROTOCOL_VERSION,
    type: CREDENTIAL_PROPOSE_OPERATION,
    sessionId,
    params: normalizedParams,
  };
  if (utf8ByteLength(JSON.stringify(request)) > MAX_POLICY_UPDATE_REQUEST_JSON_BYTES) {
    throw new ProtocolError("invalid_params", "credential_propose request is too large for the runtime.");
  }
  return request;
}

export function validatePolicyProposeRequestInput(
  sessionId: string,
  policy: Record<string, unknown>,
): void {
  makePolicyProposeRequest(sessionId, policy, "req_000000000000000000000000");
}

export function validateCredentialPrepareRequestInput(
  sessionId: string,
  params: unknown,
): void {
  makeCredentialPrepareRequest(sessionId, params, "req_000000000000000000000000");
}

export function validateCredentialProposeRequestInput(
  sessionId: string,
  params: unknown,
): void {
  makeCredentialProposeRequest(sessionId, params, "req_000000000000000000000000");
}

export function validateSignRequestInput(
  chain: unknown,
  method: unknown,
  params: unknown,
  requestType = "sign",
): SignTransactionParams {
  return validateProviderSignTransactionInput(chain, method, params, requestType);
}

export function validateSignTransactionParamsInput(
  params: unknown,
  requestType = "sign_transaction",
): SignTransactionParams {
  return validateProviderSignTransactionParams(params, requestType);
}

export function validateSignPersonalMessageRequestInput(
  chain: unknown,
  method: unknown,
  params: unknown,
  requestType = "sign_personal_message",
): SignPersonalMessageParams {
  return validateProviderSignPersonalMessageInput(chain, method, params, requestType);
}

export function validateSignPersonalMessageParamsInput(
  params: unknown,
  requestType = "sign_personal_message",
): SignPersonalMessageParams {
  return validateProviderSignPersonalMessageParams(params, requestType);
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

export function validateCredentialPrepareInput(params: unknown): CredentialPrepareRequest["params"] {
  const value = credentialParamsObject(params, "credential_prepare params");
  requireCredentialInputKeys(value, ["chain", "credential"], "credential_prepare params");
  if (value.chain !== SUI_CHAIN_ID || value.credential !== SUI_ZKLOGIN_CREDENTIAL) {
    throw new ProtocolError("invalid_params", "credential_prepare credential is unsupported.");
  }
  return { chain: SUI_CHAIN_ID, credential: SUI_ZKLOGIN_CREDENTIAL };
}

export function validateCredentialProposeInput(params: unknown): CredentialProposeParams {
  const value = credentialParamsObject(params, "credential_propose params");
  requireCredentialInputKeys(
    value,
    ["chain", "credential", "network", "address", "publicKey", "maxEpoch", "inputs"],
    "credential_propose params",
  );
  if (value.chain !== SUI_CHAIN_ID || value.credential !== SUI_ZKLOGIN_CREDENTIAL) {
    throw new ProtocolError("invalid_params", "credential_propose credential is unsupported.");
  }
  if (!SUI_SIGN_TRANSACTION_NETWORKS.includes(value.network as SuiSignTransactionNetwork)) {
    throw new ProtocolError("invalid_params", "credential_propose network is unsupported.");
  }
  if (typeof value.address !== "string" || !SUI_ADDRESS_PATTERN.test(value.address)) {
    throw new ProtocolError("invalid_params", "credential_propose address is invalid.");
  }
  const publicKey = validateCredentialPublicKey(
    value.publicKey,
    SUI_SIGNATURE_SCHEME_FLAG_ZKLOGIN,
    MIN_SUI_ZKLOGIN_PUBLIC_KEY_BYTES,
    MAX_SUI_ZKLOGIN_PUBLIC_KEY_BYTES,
    "credential_propose publicKey",
  );
  if (
    !isSuiAddressForSchemePrefixedPublicKey(
      value.address,
      publicKey,
      SUI_SIGNATURE_SCHEME_FLAG_ZKLOGIN,
      MIN_SUI_ZKLOGIN_PUBLIC_KEY_BYTES,
      MAX_SUI_ZKLOGIN_PUBLIC_KEY_BYTES,
    )
  ) {
    throw new ProtocolError("invalid_params", "credential_propose publicKey does not match address.");
  }
  if (!isUint64DecimalString(value.maxEpoch)) {
    throw new ProtocolError("invalid_params", "credential_propose maxEpoch is invalid.");
  }
  const inputs = validateZkLoginSignatureInputs(value.inputs);
  return {
    chain: SUI_CHAIN_ID,
    credential: SUI_ZKLOGIN_CREDENTIAL,
    network: value.network as SuiSignTransactionNetwork,
    address: value.address,
    publicKey,
    maxEpoch: value.maxEpoch,
    inputs,
  };
}

function credentialParamsObject(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new ProtocolError("invalid_params", `${label} must be an object.`);
  }
  return value;
}

function requireCredentialInputKeys(
  value: Record<string, unknown>,
  allowedKeys: readonly string[],
  label: string,
): void {
  if (!hasOnlyObjectKeys(value, allowedKeys)) {
    throw new ProtocolError("invalid_params", `${label} contains unsupported fields.`);
  }
}

function validateCredentialPublicKey(
  value: unknown,
  expectedSchemeFlag: number,
  minDecodedBytes: number,
  maxDecodedBytes: number,
  label: string,
): string {
  if (typeof value !== "string") {
    throw new ProtocolError("invalid_params", `${label} must be base64.`);
  }
  if (value.length === 0 || value.length > Math.ceil(maxDecodedBytes / 3) * 4) {
    throw new ProtocolError("invalid_params", `${label} is invalid.`);
  }
  const decoded = decodeCanonicalBase64(value);
  if (
    decoded === null ||
    decoded.length < minDecodedBytes ||
    decoded.length > maxDecodedBytes ||
    decoded[0] !== expectedSchemeFlag
  ) {
    throw new ProtocolError("invalid_params", `${label} is invalid.`);
  }
  if (expectedSchemeFlag === SUI_SIGNATURE_SCHEME_FLAG_ZKLOGIN && !zkLoginPublicIdentifierShapeValid(decoded)) {
    throw new ProtocolError("invalid_params", `${label} is invalid.`);
  }
  return value;
}

function zkLoginPublicIdentifierShapeValid(decoded: Uint8Array): boolean {
  if (decoded.length < MIN_SUI_ZKLOGIN_PUBLIC_KEY_BYTES || decoded[0] !== SUI_SIGNATURE_SCHEME_FLAG_ZKLOGIN) {
    return false;
  }
  const issuerLength = decoded[1] ?? 0;
  return decoded.length === 2 + issuerLength + 32;
}

function validateZkLoginSignatureInputs(value: unknown): ZkLoginSignatureInputsDto {
  const inputs = credentialParamsObject(value, "credential_propose inputs");
  requireCredentialInputKeys(
    inputs,
    ["proofPoints", "issBase64Details", "headerBase64", "addressSeed"],
    "credential_propose inputs",
  );
  const proofPoints = validateZkLoginProofPoints(inputs.proofPoints);
  const issBase64Details = validateIssBase64Details(inputs.issBase64Details);
  const headerBase64 = validateBase64UrlNoPadding(
    inputs.headerBase64,
    MAX_SUI_ZKLOGIN_HEADER_BASE64_CHARS,
    "credential_propose headerBase64",
  );
  if (!isUint256DecimalString(inputs.addressSeed)) {
    throw new ProtocolError("invalid_params", "credential_propose addressSeed is invalid.");
  }
  return {
    proofPoints,
    issBase64Details,
    headerBase64,
    addressSeed: inputs.addressSeed,
  };
}

function validateZkLoginProofPoints(value: unknown): ZkLoginSignatureInputsDto["proofPoints"] {
  const proofPoints = credentialParamsObject(value, "credential_propose proofPoints");
  requireCredentialInputKeys(proofPoints, ["a", "b", "c"], "credential_propose proofPoints");
  return {
    a: validateProofPointVector(proofPoints.a, 3, "credential_propose proofPoints.a") as [string, string, string],
    b: validateProofPointMatrix(proofPoints.b),
    c: validateProofPointVector(proofPoints.c, 3, "credential_propose proofPoints.c") as [string, string, string],
  };
}

function validateProofPointMatrix(value: unknown): [[string, string], [string, string], [string, string]] {
  if (!Array.isArray(value) || value.length !== 3) {
    throw new ProtocolError("invalid_params", "credential_propose proofPoints.b is invalid.");
  }
  return value.map((row, index) =>
    validateProofPointVector(row, 2, `credential_propose proofPoints.b[${index}]`) as [string, string],
  ) as [[string, string], [string, string], [string, string]];
}

function validateProofPointVector(value: unknown, expectedLength: number, label: string): string[] {
  if (!Array.isArray(value) || value.length !== expectedLength) {
    throw new ProtocolError("invalid_params", `${label} is invalid.`);
  }
  return value.map((entry) => validateProofPointDecimal(entry, label));
}

function validateProofPointDecimal(value: unknown, label: string): string {
  if (typeof value !== "string" || !SUI_ZKLOGIN_PROOF_POINT_DECIMAL_PATTERN.test(value)) {
    throw new ProtocolError("invalid_params", `${label} contains an invalid proof point.`);
  }
  return value;
}

function validateIssBase64Details(value: unknown): ZkLoginSignatureInputsDto["issBase64Details"] {
  const details = credentialParamsObject(value, "credential_propose issBase64Details");
  requireCredentialInputKeys(details, ["value", "indexMod4"], "credential_propose issBase64Details");
  const base64Value = validateBase64UrlNoPadding(
    details.value,
    MAX_SUI_ZKLOGIN_ISS_BASE64_CHARS,
    "credential_propose issBase64Details.value",
  );
  if (details.indexMod4 !== 0 && details.indexMod4 !== 1 && details.indexMod4 !== 2) {
    throw new ProtocolError("invalid_params", "credential_propose issBase64Details.indexMod4 is invalid.");
  }
  return { value: base64Value, indexMod4: details.indexMod4 };
}

function validateBase64UrlNoPadding(value: unknown, maxChars: number, label: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maxChars ||
    !SUI_ZKLOGIN_BASE64URL_NO_PADDING_PATTERN.test(value)
  ) {
    throw new ProtocolError("invalid_params", `${label} is invalid.`);
  }
  return value;
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

  if (value.type === "ack_result") {
    return sanitizeAckResultResponse(value);
  }

  if (isPayloadUploadResponseType(value.type)) {
    return sanitizePayloadUploadResponse(value);
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

  if (value.type === "credential_prepare_result") {
    if (typeof value.id !== "string") {
      throw new ProtocolError("protocol_error", "credential_prepare_result id is malformed.");
    }
    if (hasSecretPayloadKey(value)) {
      throw new ProtocolError("protocol_error", "credential_prepare_result must not include secret material.");
    }
    if (!hasOnlyObjectKeys(value, ["id", "version", "type", "status", "chain", "credential", "preparation"])) {
      throw new ProtocolError("protocol_error", "credential_prepare_result contains unsupported fields.");
    }
    const preparation = sanitizeCredentialPreparation(value.preparation);
    if (
      value.status !== "prepared" ||
      value.chain !== SUI_CHAIN_ID ||
      value.credential !== SUI_ZKLOGIN_CREDENTIAL ||
      preparation === null
    ) {
      throw new ProtocolError("protocol_error", "credential_prepare_result is malformed.");
    }
    return {
      id: value.id,
      version: PROTOCOL_VERSION,
      type: "credential_prepare_result",
      status: "prepared",
      chain: SUI_CHAIN_ID,
      credential: SUI_ZKLOGIN_CREDENTIAL,
      preparation,
    };
  }

  if (value.type === "credential_propose_result") {
    if (typeof value.id !== "string") {
      throw new ProtocolError("protocol_error", "credential_propose_result id is malformed.");
    }
    if (hasSecretPayloadKey(value)) {
      throw new ProtocolError("protocol_error", "credential_propose_result must not include secret material.");
    }
    if (!hasOnlyObjectKeys(value, ["id", "version", "type", "status", "reasonCode", "sessionEnded"])) {
      throw new ProtocolError("protocol_error", "credential_propose_result contains unsupported fields.");
    }
    if (
      !CREDENTIAL_PROPOSE_RESULT_STATUSES.includes(value.status as CredentialProposeResultStatus) ||
      typeof value.reasonCode !== "string" ||
      !APPROVAL_HISTORY_REASON_CODE_PATTERN.test(value.reasonCode) ||
      typeof value.sessionEnded !== "boolean"
    ) {
      throw new ProtocolError("protocol_error", "credential_propose_result is malformed.");
    }
    return {
      id: value.id,
      version: PROTOCOL_VERSION,
      type: "credential_propose_result",
      status: value.status as CredentialProposeResultStatus,
      reasonCode: value.reasonCode,
      sessionEnded: value.sessionEnded,
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

export function assertCredentialPrepareResultResponse(response: ProtocolResponse): CredentialPrepareResultResponse {
  if (response.type === "error") {
    throw new ProtocolError(response.error.code, response.error.message);
  }
  if (response.type !== "credential_prepare_result") {
    throw new ProtocolError("protocol_error", "Protocol response type is not credential_prepare_result.");
  }
  return response;
}

export function assertCredentialProposeResultResponse(response: ProtocolResponse): CredentialProposeResultResponse {
  if (response.type === "error") {
    throw new ProtocolError(response.error.code, response.error.message);
  }
  if (response.type !== "credential_propose_result") {
    throw new ProtocolError("protocol_error", "Protocol response type is not credential_propose_result.");
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

function sanitizeCredentialPreparation(value: unknown): CredentialPrepareResultResponse["preparation"] | null {
  if (!isRecord(value) || hasSecretPayloadKey(value)) {
    return null;
  }
  if (!hasOnlyObjectKeys(value, ["publicKey", "keyScheme", "address"])) {
    return null;
  }
  if (
    value.keyScheme !== "ed25519" ||
    typeof value.address !== "string" ||
    !SUI_ADDRESS_PATTERN.test(value.address) ||
    typeof value.publicKey !== "string"
  ) {
    return null;
  }
  const decoded = decodeCanonicalBase64(value.publicKey);
  if (
    decoded === null ||
    decoded.length !== SUI_SCHEME_PREFIXED_ED25519_PUBLIC_KEY_BYTES ||
    decoded[0] !== SUI_SIGNATURE_SCHEME_FLAG_ED25519 ||
    !isSuiAddressForSchemePrefixedPublicKey(
      value.address,
      value.publicKey,
      SUI_SIGNATURE_SCHEME_FLAG_ED25519,
      SUI_SCHEME_PREFIXED_ED25519_PUBLIC_KEY_BYTES,
      SUI_SCHEME_PREFIXED_ED25519_PUBLIC_KEY_BYTES,
    )
  ) {
    return null;
  }
  return {
    publicKey: value.publicKey,
    keyScheme: "ed25519",
    address: value.address,
  };
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

function isBoundedPolicyString(value: unknown, maxLength: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength;
}

function isSupportedPolicyBlockchain(value: unknown): value is string {
  return value === SUI_CHAIN_ID;
}

function isSupportedPolicyNetwork(value: unknown): value is string {
  return typeof value === "string" &&
    SUI_SIGN_TRANSACTION_NETWORKS.includes(value as SuiSignTransactionNetwork);
}

type PolicyValueKind = "string" | "u64_decimal" | "bool_string";

interface CurrentPolicyFieldDescriptor {
  type: PolicyValueKind;
  operators: readonly PolicyOperator[];
  whereType?: "required";
}

const CURRENT_POLICY_FIELD_DESCRIPTORS: Record<string, CurrentPolicyFieldDescriptor> = {
  "sui.gas_budget_raw": { type: "u64_decimal", operators: ["eq", "lte"] },
  "sui.gas_price_raw": { type: "u64_decimal", operators: ["eq", "lte"] },
  "sui.gas_owner": { type: "string", operators: ["eq", "in", "not_in"] },
  "sui.sponsored": { type: "bool_string", operators: ["eq"] },
  "sui.command_count": { type: "u64_decimal", operators: ["eq", "lte"] },
  "sui.command_kinds": { type: "string", operators: ["contains", "not_contains", "all_in", "none_in"] },
  "sui.move_call_packages": { type: "string", operators: ["contains", "not_contains", "all_in", "none_in"] },
  "sui.move_call_modules": { type: "string", operators: ["contains", "not_contains", "all_in", "none_in"] },
  "sui.move_call_functions": { type: "string", operators: ["contains", "not_contains", "all_in", "none_in"] },
  "sui.publish_present": { type: "bool_string", operators: ["eq"] },
  "sui.upgrade_present": { type: "bool_string", operators: ["eq"] },
  "sui.recipient_addresses": { type: "string", operators: ["contains", "not_contains", "all_in", "none_in"] },
  "sui.pure_address_arguments": { type: "string", operators: ["contains", "not_contains", "none_in"] },
  "sui.token_sources.type": { type: "string", operators: ["eq", "in", "not_in"] },
  "sui.token_sources.source": { type: "string", operators: ["eq", "in"] },
  "sui.token_sources.amount_raw": { type: "u64_decimal", operators: ["eq", "lte"] },
  "sui.token_totals_by_type.amount_raw": { type: "u64_decimal", operators: ["eq", "lte"], whereType: "required" },
  "sui.token_unknown_amount_present": { type: "bool_string", operators: ["eq"] },
};

function policyOperatorUsesValueList(op: PolicyOperator): boolean {
  return op === "in" || op === "not_in" || op === "all_in" || op === "none_in";
}

function policyConditionValueValid(type: PolicyValueKind, value: unknown): value is string {
  if (!isBoundedPolicyString(value, MAX_POLICY_VALUE_LENGTH)) {
    return false;
  }
  if (type === "u64_decimal") {
    return isUint64DecimalString(value);
  }
  if (type === "bool_string") {
    return value === "true" || value === "false";
  }
  return true;
}

function policyConditionTypeSelectorValid(value: unknown): value is string {
  return isBoundedPolicyString(value, MAX_POLICY_VALUE_LENGTH) && value.includes("::");
}

function sanitizePolicyConditionWhere(value: unknown): { type: string } | null {
  if (!isRecord(value)) {
    return null;
  }
  if (hasSecretPayloadKey(value)) {
    throw new ProtocolError("protocol_error", "Policy condition selector must not include secret material.");
  }
  if (!hasOnlyObjectKeys(value, ["type"])) {
    throw new ProtocolError("protocol_error", "Policy condition selector contains unsupported fields.");
  }
  if (!policyConditionTypeSelectorValid(value.type)) {
    return null;
  }
  return { type: value.type };
}

function sanitizePolicyCondition(value: unknown): PolicyCondition | null {
  if (!isRecord(value)) {
    return null;
  }
  if (hasSecretPayloadKey(value)) {
    throw new ProtocolError("protocol_error", "Policy condition must not include secret material.");
  }
  if (!isBoundedPolicyString(value.field, MAX_POLICY_FIELD_ID_LENGTH) ||
      !POLICY_FIELD_ID_PATTERN.test(value.field) ||
      typeof value.op !== "string" ||
      !POLICY_OPERATORS.includes(value.op as PolicyOperator)) {
    return null;
  }

  const op = value.op as PolicyOperator;
  const descriptor = CURRENT_POLICY_FIELD_DESCRIPTORS[value.field];
  if (descriptor === undefined || !descriptor.operators.includes(op)) {
    return null;
  }
  const hasWhere = Object.prototype.hasOwnProperty.call(value, "where");
  if (hasWhere && descriptor.whereType !== "required") {
    return null;
  }
  let where: { type: string } | undefined;
  if (hasWhere) {
    const parsedWhere = sanitizePolicyConditionWhere(value.where);
    if (parsedWhere === null) {
      return null;
    }
    where = parsedWhere;
  }
  if (descriptor.whereType === "required" && where === undefined) {
    return null;
  }
  if (policyOperatorUsesValueList(op)) {
    const allowedKeys = descriptor.whereType === "required"
      ? ["field", "op", "where", "values"]
      : ["field", "op", "values"];
    if (!hasOnlyObjectKeys(value, allowedKeys)) {
      throw new ProtocolError("protocol_error", "Policy condition contains unsupported fields.");
    }
    if (!Array.isArray(value.values) ||
        value.values.length === 0 ||
        value.values.length > MAX_POLICY_CONDITION_VALUES ||
        !value.values.every((item) => policyConditionValueValid(descriptor.type, item))) {
      return null;
    }
    const output: PolicyCondition = {
      field: value.field,
      op,
      values: [...value.values],
    };
    if (where !== undefined) {
      output.where = where;
    }
    return output;
  }

  const allowedKeys = descriptor.whereType === "required"
    ? ["field", "op", "where", "value"]
    : ["field", "op", "value"];
  if (!hasOnlyObjectKeys(value, allowedKeys)) {
    throw new ProtocolError("protocol_error", "Policy condition contains unsupported fields.");
  }
  if (!policyConditionValueValid(descriptor.type, value.value)) {
    return null;
  }
  const output: PolicyCondition = {
    field: value.field,
    op,
    value: value.value,
  };
  if (where !== undefined) {
    output.where = where;
  }
  return output;
}

function sanitizePolicyEntry(value: unknown): PolicyEntry | null {
  if (!isRecord(value)) {
    return null;
  }
  if (hasSecretPayloadKey(value)) {
    throw new ProtocolError("protocol_error", "Policy entry must not include secret material.");
  }
  if (!hasOnlyObjectKeys(value, ["id", "action", "conditions"])) {
    throw new ProtocolError("protocol_error", "Policy entry contains unsupported fields.");
  }
  if (
    !isBoundedPolicyString(value.id, MAX_POLICY_ID_LENGTH) ||
    !POLICY_ENTRY_ID_PATTERN.test(value.id) ||
    typeof value.action !== "string" ||
    !POLICY_ACTIONS.includes(value.action as PolicyAction) ||
    !Array.isArray(value.conditions) ||
    value.conditions.length > MAX_POLICY_CONDITIONS_PER_POLICY ||
    (value.action === "sign" && value.conditions.length === 0)
  ) {
    return null;
  }

  const conditions = value.conditions.map((condition) => sanitizePolicyCondition(condition));
  if (conditions.some((condition) => condition === null)) {
    return null;
  }
  return {
    id: value.id,
    action: value.action as PolicyAction,
    conditions: conditions as PolicyCondition[],
  };
}

function sanitizePolicyNetworkScope(value: unknown): PolicyNetworkScope | null {
  if (!isRecord(value)) {
    return null;
  }
  if (hasSecretPayloadKey(value)) {
    throw new ProtocolError("protocol_error", "Policy network scope must not include secret material.");
  }
  if (!hasOnlyObjectKeys(value, ["network", "policies"])) {
    throw new ProtocolError("protocol_error", "Policy network scope contains unsupported fields.");
  }
  if (!isBoundedPolicyString(value.network, MAX_POLICY_NETWORK_LENGTH) ||
      !isSupportedPolicyNetwork(value.network) ||
      !Array.isArray(value.policies) ||
      value.policies.length > MAX_POLICY_POLICIES_PER_NETWORK) {
    return null;
  }
  const policies = value.policies.map((policy) => sanitizePolicyEntry(policy));
  if (policies.some((policy) => policy === null)) {
    return null;
  }
  const policyIds = new Set((policies as PolicyEntry[]).map((policy) => policy.id));
  if (policyIds.size !== policies.length) {
    return null;
  }
  return {
    network: value.network,
    policies: policies as PolicyEntry[],
  };
}

function sanitizePolicyBlockchainScope(value: unknown): PolicyBlockchainScope | null {
  if (!isRecord(value)) {
    return null;
  }
  if (hasSecretPayloadKey(value)) {
    throw new ProtocolError("protocol_error", "Policy blockchain scope must not include secret material.");
  }
  if (!hasOnlyObjectKeys(value, ["blockchain", "networks"])) {
    throw new ProtocolError("protocol_error", "Policy blockchain scope contains unsupported fields.");
  }
  if (!isBoundedPolicyString(value.blockchain, MAX_POLICY_BLOCKCHAIN_LENGTH) ||
      !isSupportedPolicyBlockchain(value.blockchain) ||
      !Array.isArray(value.networks) ||
      value.networks.length > MAX_POLICY_NETWORKS_PER_BLOCKCHAIN) {
    return null;
  }
  const networks = value.networks.map((network) => sanitizePolicyNetworkScope(network));
  if (networks.some((network) => network === null)) {
    return null;
  }
  const networkIds = new Set((networks as PolicyNetworkScope[]).map((network) => network.network));
  if (networkIds.size !== networks.length) {
    return null;
  }
  return {
    blockchain: value.blockchain,
    networks: networks as PolicyNetworkScope[],
  };
}

export function sanitizeCurrentPolicyDocument(value: unknown): PolicyDocument | null {
  if (!isRecord(value)) {
    return null;
  }
  if (hasSecretPayloadKey(value)) {
    throw new ProtocolError("protocol_error", "Policy document must not include secret material.");
  }
  if (!hasOnlyObjectKeys(value, [
    "schema",
    "policyId",
    "defaultAction",
    "blockchainCount",
    "networkCount",
    "policyCount",
    "conditionCount",
    "blockchains",
  ])) {
    throw new ProtocolError("protocol_error", "Policy document contains unsupported fields.");
  }
  if (
    value.schema !== AGENT_Q_POLICY_SCHEMA ||
    typeof value.policyId !== "string" ||
    !POLICY_ID_PATTERN.test(value.policyId) ||
    value.defaultAction !== "reject" ||
    typeof value.blockchainCount !== "number" ||
    !Number.isInteger(value.blockchainCount) ||
    value.blockchainCount < 0 ||
    value.blockchainCount > MAX_POLICY_BLOCKCHAINS ||
    typeof value.networkCount !== "number" ||
    !Number.isInteger(value.networkCount) ||
    value.networkCount < 0 ||
    value.networkCount > MAX_POLICY_TOTAL_NETWORKS ||
    typeof value.policyCount !== "number" ||
    !Number.isInteger(value.policyCount) ||
    value.policyCount < 0 ||
    value.policyCount > MAX_POLICY_TOTAL_POLICIES ||
    typeof value.conditionCount !== "number" ||
    !Number.isInteger(value.conditionCount) ||
    value.conditionCount < 0 ||
    value.conditionCount > MAX_POLICY_TOTAL_CONDITIONS ||
    !Array.isArray(value.blockchains) ||
    value.blockchains.length !== value.blockchainCount
  ) {
    return null;
  }
  const blockchains = value.blockchains.map((blockchain) => sanitizePolicyBlockchainScope(blockchain));
  if (blockchains.some((blockchain) => blockchain === null)) {
    return null;
  }
  const blockchainIds = new Set((blockchains as PolicyBlockchainScope[]).map((blockchain) => blockchain.blockchain));
  if (blockchainIds.size !== blockchains.length) {
    return null;
  }
  const networkCount = (blockchains as PolicyBlockchainScope[])
    .reduce((sum, blockchain) => sum + blockchain.networks.length, 0);
  const policyCount = (blockchains as PolicyBlockchainScope[])
    .reduce((sum, blockchain) => sum + blockchain.networks
      .reduce((networkSum, network) => networkSum + network.policies.length, 0), 0);
  const conditionCount = (blockchains as PolicyBlockchainScope[])
    .reduce((sum, blockchain) => sum + blockchain.networks
      .reduce((networkSum, network) => networkSum + network.policies
        .reduce((policySum, policy) => policySum + policy.conditions.length, 0), 0), 0);
  if (
    networkCount !== value.networkCount ||
    policyCount !== value.policyCount ||
    conditionCount !== value.conditionCount
  ) {
    return null;
  }
  return {
    schema: value.schema,
    policyId: value.policyId,
    defaultAction: value.defaultAction,
    blockchainCount: value.blockchainCount,
    networkCount: value.networkCount,
    policyCount: value.policyCount,
    conditionCount: value.conditionCount,
    blockchains: blockchains as PolicyBlockchainScope[],
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
  if (!hasOnlyObjectKeys(value, [
    "policyHash",
    "blockchainCount",
    "networkCount",
    "policyCount",
    "conditionCount",
    "highestAction",
  ])) {
    throw new ProtocolError("protocol_error", "policy_propose_result policy metadata contains unsupported fields.");
  }
  if (
    typeof value.policyHash !== "string" ||
    !POLICY_ID_PATTERN.test(value.policyHash) ||
    typeof value.blockchainCount !== "number" ||
    !Number.isInteger(value.blockchainCount) ||
    value.blockchainCount < 0 ||
    value.blockchainCount > MAX_POLICY_BLOCKCHAINS ||
    typeof value.networkCount !== "number" ||
    !Number.isInteger(value.networkCount) ||
    value.networkCount < 0 ||
    value.networkCount > MAX_POLICY_TOTAL_NETWORKS ||
    typeof value.policyCount !== "number" ||
    !Number.isInteger(value.policyCount) ||
    value.policyCount < 0 ||
    value.policyCount > MAX_POLICY_TOTAL_POLICIES ||
    typeof value.conditionCount !== "number" ||
    !Number.isInteger(value.conditionCount) ||
    value.conditionCount < 0 ||
    value.conditionCount > MAX_POLICY_TOTAL_CONDITIONS ||
    !APPROVAL_HISTORY_HIGHEST_ACTIONS.includes(value.highestAction as ApprovalHistoryHighestAction)
  ) {
    throw new ProtocolError("protocol_error", "policy_propose_result policy metadata is malformed.");
  }
  return {
    policyHash: value.policyHash,
    blockchainCount: value.blockchainCount,
    networkCount: value.networkCount,
    policyCount: value.policyCount,
    conditionCount: value.conditionCount,
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
    "policyCount",
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
      typeof value.policyCount !== "number" ||
      !Number.isInteger(value.policyCount) ||
      value.policyCount < 0 ||
      value.policyCount > MAX_POLICY_TOTAL_POLICIES ||
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
      policyCount: value.policyCount,
      highestAction: value.highestAction as ApprovalHistoryHighestAction,
    };
  }

  if (value.eventKind === "signing") {
    if (
      value.result !== undefined ||
      value.policyCount !== undefined ||
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
