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
  validateSignPersonalMessageParams as validateProviderSignPersonalMessageParams,
  validateSignPersonalMessageInput as validateProviderSignPersonalMessageInput,
  validateSignTransactionParams as validateProviderSignTransactionParams,
  validateSignTransactionInput as validateProviderSignTransactionInput,
  type Account,
  type AccountsResult,
  type CapabilitiesResult,
  type CapabilityChain,
  type ConnectResult,
  type CredentialCapability,
  type DisconnectResult,
  type SignPersonalMessageParams,
  type SigningOutcome,
  type SignTransactionParams,
  type SigningCapabilities,
} from "./provider-protocol.js";
import { ProtocolError } from "./protocol-error.js";
import {
  makeDeviceError,
  parseDeviceResponse,
  SIGNING_OUTCOME_ERROR_MESSAGES,
  type DeviceResponse,
  type DeviceMethod,
  type SigningOutcomeErrorCode,
} from "./device-contract.js";
import {
  SIGNING_POLICY_SCHEMA,
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
  POLICY_PROPOSAL_OUTCOME_STATUSES,
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
  MAX_SIGNING_OUTCOME_PAYLOAD_BASE64_CHARS,
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
  SUI_ADDRESS_PATTERN,
  SUI_CHAIN_ID,
  SUI_DERIVATION_PATH,
  SUI_ED25519_SIGNATURE_BYTES,
  SUI_ED25519_SIGNATURE_BASE64_PATTERN,
  SUI_SIGNATURE_ENVELOPE_MAX_BYTES,
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
  consumeDeviceResponseLineChunk,
  createRequestId,
  decodeCanonicalBase64,
  hasOnlyObjectKeys,
  hasSecretPayloadKey,
  isUint64DecimalString,
  isUint256DecimalString,
  isRecord,
  isSuiPersonalMessageSignatureBase64,
  isSuiAddressForPublicKey,
  isSuiAddressForSchemePrefixedPublicKey,
  isSuiTransactionSignatureEnvelopeBase64,
  randomBytesPortable,
  utf8ByteLength,
  validateCanonicalBase64Syntax,
  type SuiSignMethod,
  type SuiSignTransactionNetwork,
} from "./protocol-primitives.js";

// These boundary functions are defined once in safe-text.ts (the single source of
// truth) and re-exported here because protocol.ts is the wire-ingress boundary
// that applies them; existing importers and tests resolve them via protocol.ts.
export { isClientName, isSafeDeviceId, isSafeRequestId, isSessionId, sanitizeDisplayText };
export {
  SIGNING_POLICY_SCHEMA,
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
  MAX_SIGNING_OUTCOME_PAYLOAD_BASE64_CHARS,
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
  POLICY_PROPOSAL_OUTCOME_STATUSES,
  PROTOCOL_VERSION,
  SIGNING_HISTORY_RECORD_KINDS,
  SIGNING_HISTORY_TERMINAL_RESULTS,
  SIGN_CHAIN_PATTERN,
  SIGN_METHOD_PATTERN,
  SIGNING_OUTCOME_ERROR_MESSAGES,
  SUI_ADDRESS_PATTERN,
  SUI_CHAIN_ID,
  SUI_DERIVATION_PATH,
  SUI_ED25519_SIGNATURE_BYTES,
  SUI_ED25519_SIGNATURE_BASE64_PATTERN,
  SUI_SIGNATURE_ENVELOPE_MAX_BYTES,
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
  consumeDeviceResponseLineChunk,
  createRequestId,
  isUint64DecimalString,
  isUint256DecimalString,
  isSuiPersonalMessageSignatureBase64,
  isSuiAddressForPublicKey,
  isSuiAddressForSchemePrefixedPublicKey,
  isSuiTransactionSignatureEnvelopeBase64,
  makeDeviceError,
  parseDeviceResponse,
};
export { ProtocolError };
export type { DeviceMethod, DeviceResponse, DeviceState, ProvisioningState, SigningOutcomeErrorCode, SuiSignMethod, SuiSignTransactionNetwork };
export type {
  Account,
  AccountsResult,
  CapabilitiesResult,
  CapabilityAccount,
  CapabilityChain,
  CredentialCapability,
  ConnectResult,
  DisconnectResult,
  SignPersonalMessageParams,
  SignOperationType,
  SigningOutcomeAuthorization,
  SigningOutcome,
  SignPersonalMessageSignedResult,
  SigningOutcomePolicyRejected,
  SigningOutcomeSigned,
  SigningOutcomeSigningFailed,
  SigningOutcomeStatus,
  SigningOutcomeUserRejected,
  SignTransactionParams,
  SignTransactionSignedResult,
  SupportedSignRoute,
  SigningCapabilities,
  SigningCapabilityEntry,
} from "./provider-protocol.js";
export { identifySignRoute } from "./provider-protocol.js";

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

export interface CredentialPrepareParams {
  chain: typeof SUI_CHAIN_ID;
  credential: typeof SUI_ZKLOGIN_CREDENTIAL;
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

export interface StatusResponse {
  device: DeviceStatus;
  provisioning: ProvisioningStatus;
}

export interface IdentifyDeviceResponse {
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
  records: ApprovalHistoryRecord[];
  hasMore: boolean;
}

export type PolicyProposalOutcomeStatus =
  | "applied"
  | "rejected"
  | "timed_out"
  | "invalid_policy"
  | "ui_error"
  | "storage_error"
  | "consistency_error";

export interface PolicyProposalOutcomePolicySummary {
  policyHash: string;
  blockchainCount: number;
  networkCount: number;
  policyCount: number;
  conditionCount: number;
  highestAction: ApprovalHistoryHighestAction;
}

export interface PolicyProposalOutcomeResponse {
  status: PolicyProposalOutcomeStatus;
  reasonCode: string;
  policy?: PolicyProposalOutcomePolicySummary;
}

export interface CredentialPreparationResponse {
  chain: typeof SUI_CHAIN_ID;
  credential: typeof SUI_ZKLOGIN_CREDENTIAL;
  preparation: {
    publicKey: string;
    keyScheme: "ed25519";
    address: string;
  };
}

export type CredentialProposalOutcomeStatus =
  | "activated"
  | "rejected"
  | "timed_out"
  | "invalid_proof"
  | "ui_error"
  | "storage_error"
  | "consistency_error";

export const CREDENTIAL_PROPOSAL_OUTCOME_STATUSES = [
  "activated",
  "rejected",
  "timed_out",
  "invalid_proof",
  "ui_error",
  "storage_error",
  "consistency_error",
] as const;

export interface CredentialProposalOutcomeResponse {
  status: CredentialProposalOutcomeStatus;
  reasonCode: string;
  sessionEnded: boolean;
}

export function createIdentificationCode(): string {
  const bytes = randomBytesPortable(2);
  return ((((bytes[0] ?? 0) << 8) | (bytes[1] ?? 0)) % 10000).toString().padStart(4, "0");
}

export function validatePolicyProposeRequestInput(
  sessionId: string,
  policy: Record<string, unknown>,
): void {
  if (!isSessionId(sessionId)) {
    throw new ProtocolError("invalid_session", "Invalid sessionId.");
  }
  validatePolicyProposeInput(policy);
}

export function validateCredentialPrepareRequestInput(
  sessionId: string,
  params: unknown,
): void {
  if (!isSessionId(sessionId)) {
    throw new ProtocolError("invalid_session", "Invalid sessionId.");
  }
  validateCredentialPrepareInput(params);
}

export function validateCredentialProposeRequestInput(
  sessionId: string,
  params: unknown,
): void {
  if (!isSessionId(sessionId)) {
    throw new ProtocolError("invalid_session", "Invalid sessionId.");
  }
  validateCredentialProposeInput(params);
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

export function validateCredentialPrepareInput(params: unknown): CredentialPrepareParams {
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

export function parseJsonLine(line: string): unknown {
  try {
    return JSON.parse(line);
  } catch {
    throw new ProtocolError("invalid_response", "Invalid JSON response.");
  }
}

function asResultObject(value: unknown): Record<string, unknown> {
  if (!isRecord(value) || Array.isArray(value)) {
    throw new ProtocolError("invalid_response", "Device result must be an object.");
  }
  return value;
}

function assertDeviceResultObject(
  response: DeviceResponse,
  method: DeviceMethod,
  label: string,
): Record<string, unknown> {
  const parsed = parseDeviceResponse(response, { expectedMethod: method });
  if (parsed.success === false) {
    throw new ProtocolError(parsed.error.code, parsed.error.message);
  }
  if (parsed.id === undefined) {
    throw new ProtocolError("invalid_response", `${label} id is required.`);
  }
  return asResultObject(parsed.result);
}

function requireResultKeys(
  result: Record<string, unknown>,
  keys: readonly string[],
  label: string,
): void {
  if (hasSecretPayloadKey(result)) {
    throw new ProtocolError("invalid_response", `${label} must not include secret material.`);
  }
  if (!hasOnlyObjectKeys(result, keys)) {
    throw new ProtocolError("invalid_response", `${label} contains unsupported fields.`);
  }
}

export function assertStatusResponse(response: DeviceResponse): StatusResponse {
  const result = assertDeviceResultObject(response, "get_status", "Status result");
  requireResultKeys(result, ["device", "provisioning"], "Status result");
  requireWireDeviceStatusShape(result.device, "Status result device object");
  requireWireProvisioningStatusShape(result.provisioning, "Status result provisioning object");
  const device = sanitizeDeviceStatus(result.device);
  const provisioning = sanitizeProvisioningStatus(result.provisioning);
  if (device === null || provisioning === null) {
    throw new ProtocolError("invalid_response", "Status result is malformed.");
  }
  return { device, provisioning };
}

export function assertIdentifyDeviceResponse(response: DeviceResponse): IdentifyDeviceResponse {
  const result = assertDeviceResultObject(response, "identify_device", "Identify result");
  requireResultKeys(result, ["code", "device"], "Identify result");
  requireWireDeviceStatusShape(result.device, "Identify result device object");
  const device = sanitizeDeviceStatus(result.device);
  if (device === null || !isIdentificationCode(result.code)) {
    throw new ProtocolError("invalid_response", "Identify result is malformed.");
  }
  return { code: result.code, device };
}

export function assertConnectResult(response: DeviceResponse): ConnectResult {
  const result = assertDeviceResultObject(response, "connect", "Connect result");
  requireResultKeys(result, ["sessionId", "sessionTtlMs", "device"], "Connect result");
  requireWireDeviceStatusShape(result.device, "Connect result device object");
  const device = sanitizeDeviceStatus(result.device);
  if (
    device === null ||
    !isSessionId(result.sessionId) ||
    typeof result.sessionTtlMs !== "number" ||
    !Number.isInteger(result.sessionTtlMs) ||
    result.sessionTtlMs <= 0 ||
    result.sessionTtlMs > MAX_SESSION_TTL_MS
  ) {
    throw new ProtocolError("invalid_response", "Connect result is malformed.");
  }
  return { sessionId: result.sessionId, sessionTtlMs: result.sessionTtlMs, device };
}

export function assertDisconnectResult(response: DeviceResponse): DisconnectResult {
  const result = assertDeviceResultObject(response, "disconnect", "Disconnect result");
  requireResultKeys(result, [], "Disconnect result");
  return {};
}

export function assertCapabilitiesResult(response: DeviceResponse): CapabilitiesResult {
  const result = assertDeviceResultObject(response, "get_capabilities", "Capabilities result");
  requireResultKeys(result, ["chains", "signing", "credentials"], "Capabilities result");
  if (!Array.isArray(result.chains)) {
    throw new ProtocolError("invalid_response", "Capabilities result is malformed.");
  }
  return {
    chains: result.chains as CapabilityChain[],
    ...(result.signing === undefined ? {} : { signing: result.signing as SigningCapabilities }),
    ...(result.credentials === undefined ? {} : { credentials: result.credentials as CredentialCapability[] }),
  };
}

export function assertAccountsResult(response: DeviceResponse): AccountsResult {
  const result = assertDeviceResultObject(response, "get_accounts", "Accounts result");
  requireResultKeys(result, ["accounts"], "Accounts result");
  if (!Array.isArray(result.accounts)) {
    throw new ProtocolError("invalid_response", "Accounts result is malformed.");
  }
  return { accounts: result.accounts as Account[] };
}

export function assertPolicyResponse(response: DeviceResponse): PolicyResponse {
  const result = assertDeviceResultObject(response, "policy_get", "Policy result");
  requireResultKeys(result, ["policy"], "Policy result");
  const policy = sanitizeCurrentPolicyDocument(result.policy);
  if (policy === null) {
    throw new ProtocolError("invalid_response", "Policy result is malformed.");
  }
  return { policy };
}

export function assertApprovalHistoryResponse(response: DeviceResponse): ApprovalHistoryResponse {
  const result = assertDeviceResultObject(response, "get_approval_history", "Approval history result");
  requireResultKeys(result, ["records", "hasMore"], "Approval history result");
  if (!Array.isArray(result.records) || result.records.length > MAX_APPROVAL_HISTORY_RECORDS || typeof result.hasMore !== "boolean") {
    throw new ProtocolError("invalid_response", "Approval history result is malformed.");
  }
  return {
    records: result.records.map((entry) => sanitizeApprovalHistoryRecord(entry)),
    hasMore: result.hasMore,
  };
}

export function assertPolicyProposalOutcomeResponse(response: DeviceResponse): PolicyProposalOutcomeResponse {
  const result = assertDeviceResultObject(response, "policy_propose", "Policy proposal outcome");
  requireResultKeys(result, ["status", "reasonCode", "policy"], "Policy proposal outcome");
  if (
    !POLICY_PROPOSAL_OUTCOME_STATUSES.includes(result.status as PolicyProposalOutcomeStatus) ||
    typeof result.reasonCode !== "string" ||
    !APPROVAL_HISTORY_REASON_CODE_PATTERN.test(result.reasonCode)
  ) {
    throw new ProtocolError("invalid_response", "Policy proposal outcome is malformed.");
  }
  const policy = sanitizePolicyProposalOutcomePolicy(result.policy);
  if (result.status === "invalid_policy") {
    if (policy !== undefined) {
      throw new ProtocolError("invalid_response", "Invalid policy result must not include policy metadata.");
    }
  } else if (policy === undefined) {
    throw new ProtocolError("invalid_response", "Policy proposal outcome policy metadata is malformed.");
  }
  return {
    status: result.status as PolicyProposalOutcomeStatus,
    reasonCode: result.reasonCode,
    ...(policy !== undefined ? { policy } : {}),
  };
}

export function assertCredentialPreparationResponse(response: DeviceResponse): CredentialPreparationResponse {
  const result = assertDeviceResultObject(response, "credential_prepare", "Credential preparation response");
  requireResultKeys(result, ["chain", "credential", "preparation"], "Credential preparation response");
  const preparation = sanitizeCredentialPreparation(result.preparation);
  if (
    result.chain !== SUI_CHAIN_ID ||
    result.credential !== SUI_ZKLOGIN_CREDENTIAL ||
    preparation === null
  ) {
    throw new ProtocolError("invalid_response", "Credential preparation response is malformed.");
  }
  return {
    chain: SUI_CHAIN_ID,
    credential: SUI_ZKLOGIN_CREDENTIAL,
    preparation,
  };
}

export function assertCredentialProposalOutcomeResponse(response: DeviceResponse): CredentialProposalOutcomeResponse {
  const result = assertDeviceResultObject(response, "credential_propose", "Credential proposal outcome");
  requireResultKeys(result, ["status", "reasonCode", "sessionEnded"], "Credential proposal outcome");
  if (
    !CREDENTIAL_PROPOSAL_OUTCOME_STATUSES.includes(result.status as CredentialProposalOutcomeStatus) ||
    typeof result.reasonCode !== "string" ||
    !APPROVAL_HISTORY_REASON_CODE_PATTERN.test(result.reasonCode) ||
    typeof result.sessionEnded !== "boolean"
  ) {
    throw new ProtocolError("invalid_response", "Credential proposal outcome is malformed.");
  }
  return {
    status: result.status as CredentialProposalOutcomeStatus,
    reasonCode: result.reasonCode,
    sessionEnded: result.sessionEnded,
  };
}

export function assertSigningOutcome(response: DeviceResponse): SigningOutcome {
  const parsed = parseDeviceResponse(response);
  if (parsed.success === false) {
    throw new ProtocolError(parsed.error.code, parsed.error.message);
  }
  if (parsed.id === undefined) {
    throw new ProtocolError("invalid_response", "Signing outcome id is required.");
  }
  if (
    parsed.method !== "sign_transaction" &&
    parsed.method !== "sign_personal_message" &&
    parsed.method !== "get_result"
  ) {
    throw new ProtocolError("invalid_response", "Signing outcome method is malformed.");
  }
  const id = parsed.id;
  const result = asResultObject(parsed.result);
  requireResultKeys(result, ["authorization", "chain", "method", "signature", "messageBytes"], "Signing outcome");
  if (
    (result.authorization !== "user" && result.authorization !== "policy") ||
    result.chain !== SUI_CHAIN_ID ||
    typeof result.signature !== "string"
  ) {
    throw new ProtocolError("invalid_response", "Signing outcome is malformed.");
  }
  if (result.method === SUI_SIGN_TRANSACTION_METHOD) {
    if (result.messageBytes !== undefined || !isSuiTransactionSignatureEnvelopeBase64(result.signature)) {
      throw new ProtocolError("invalid_response", "Signing outcome is malformed.");
    }
    return {
      authorization: result.authorization,
      status: "signed",
      chain: SUI_CHAIN_ID,
      method: SUI_SIGN_TRANSACTION_METHOD,
      signature: result.signature,
    };
  }
  if (result.method === SUI_SIGN_PERSONAL_MESSAGE_METHOD) {
    if (result.authorization !== "user" || !isSuiPersonalMessageSignatureBase64(result.signature)) {
      throw new ProtocolError("invalid_response", "Signing outcome is malformed.");
    }
    const messageBytes = validateCanonicalBase64Syntax(
      result.messageBytes,
      MAX_SIGNING_OUTCOME_PAYLOAD_BASE64_CHARS,
      "sui/sign_personal_message messageBytes",
      "invalid_response",
    );
    return {
      authorization: "user",
      status: "signed",
      chain: SUI_CHAIN_ID,
      method: SUI_SIGN_PERSONAL_MESSAGE_METHOD,
      signature: result.signature,
      messageBytes,
    };
  }
  throw new ProtocolError("invalid_response", "Signing outcome is malformed.");
}

function sanitizeCredentialPreparation(value: unknown): CredentialPreparationResponse["preparation"] | null {
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
    throw new ProtocolError("invalid_response", "Policy condition selector must not include secret material.");
  }
  if (!hasOnlyObjectKeys(value, ["type"])) {
    throw new ProtocolError("invalid_response", "Policy condition selector contains unsupported fields.");
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
    throw new ProtocolError("invalid_response", "Policy condition must not include secret material.");
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
      throw new ProtocolError("invalid_response", "Policy condition contains unsupported fields.");
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
    throw new ProtocolError("invalid_response", "Policy condition contains unsupported fields.");
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
    throw new ProtocolError("invalid_response", "Policy entry must not include secret material.");
  }
  if (!hasOnlyObjectKeys(value, ["id", "action", "conditions"])) {
    throw new ProtocolError("invalid_response", "Policy entry contains unsupported fields.");
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
    throw new ProtocolError("invalid_response", "Policy network scope must not include secret material.");
  }
  if (!hasOnlyObjectKeys(value, ["network", "policies"])) {
    throw new ProtocolError("invalid_response", "Policy network scope contains unsupported fields.");
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
    throw new ProtocolError("invalid_response", "Policy blockchain scope must not include secret material.");
  }
  if (!hasOnlyObjectKeys(value, ["blockchain", "networks"])) {
    throw new ProtocolError("invalid_response", "Policy blockchain scope contains unsupported fields.");
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
    throw new ProtocolError("invalid_response", "Policy document must not include secret material.");
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
    throw new ProtocolError("invalid_response", "Policy document contains unsupported fields.");
  }
  if (
    value.schema !== SIGNING_POLICY_SCHEMA ||
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

function sanitizePolicyProposalOutcomePolicy(value: unknown): PolicyProposalOutcomePolicySummary | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!isRecord(value)) {
    throw new ProtocolError("invalid_response", "policy proposal outcome policy metadata is malformed.");
  }
  if (hasSecretPayloadKey(value)) {
    throw new ProtocolError("invalid_response", "policy proposal outcome policy metadata must not include secret material.");
  }
  if (!hasOnlyObjectKeys(value, [
    "policyHash",
    "blockchainCount",
    "networkCount",
    "policyCount",
    "conditionCount",
    "highestAction",
  ])) {
    throw new ProtocolError("invalid_response", "policy proposal outcome policy metadata contains unsupported fields.");
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
    throw new ProtocolError("invalid_response", "policy proposal outcome policy metadata is malformed.");
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
    throw new ProtocolError("invalid_response", "Approval history record is malformed.");
  }
  if (hasSecretPayloadKey(value)) {
    throw new ProtocolError("invalid_response", "Approval history record must not include secret material.");
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
    throw new ProtocolError("invalid_response", "Approval history record contains unsupported fields.");
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
    throw new ProtocolError("invalid_response", "Approval history record is malformed.");
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
      throw new ProtocolError("invalid_response", "Approval history policy update record is malformed.");
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
      throw new ProtocolError("invalid_response", "Approval history signing record is malformed.");
    }
    if (value.recordKind === "confirmation") {
      if (value.terminalResult !== undefined) {
        throw new ProtocolError("invalid_response", "Approval history signing record is malformed.");
      }
      if (value.authorization === "user") {
        if (
          (value.confirmationKind !== "local_pin" &&
            value.confirmationKind !== "physical_confirm") ||
          value.policyHash !== undefined ||
          value.ruleRef !== undefined
        ) {
          throw new ProtocolError("invalid_response", "Approval history signing record is malformed.");
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
        throw new ProtocolError("invalid_response", "Approval history signing policy metadata is malformed.");
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
      throw new ProtocolError("invalid_response", "Approval history signing record is malformed.");
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
        throw new ProtocolError("invalid_response", "Approval history signing policy metadata is malformed.");
      }
    } else if (
      !["signed", "user_rejected", "user_timed_out", "signing_failed"].includes(terminalResult) ||
      value.policyHash !== undefined ||
      value.ruleRef !== undefined
    ) {
      throw new ProtocolError("invalid_response", "Approval history signing policy metadata is malformed.");
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

  throw new ProtocolError("invalid_response", "Approval history record is malformed.");
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
    throw new ProtocolError("invalid_request", "Invalid request id.");
  }
}

function requireWireDeviceStatusShape(value: unknown, label: string): void {
  if (
    !isRecord(value) ||
    !hasOnlyObjectKeys(value, ["deviceId", "state", "firmwareName", "hardware", "firmwareVersion"])
  ) {
    throw new ProtocolError("invalid_response", `${label} contains unsupported fields.`);
  }
}

function requireWireProvisioningStatusShape(value: unknown, label: string): void {
  if (!isRecord(value) || !hasOnlyObjectKeys(value, ["state"])) {
    throw new ProtocolError("invalid_response", `${label} contains unsupported fields.`);
  }
}
