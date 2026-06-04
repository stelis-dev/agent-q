import * as z from "zod/v4";
import {
  CALL_METHOD_SESSION_ENDED_REASONS,
  DISCONNECT_ENDED_REASONS,
  DISCONNECT_REASONS,
  GET_ACCOUNTS_SESSION_ENDED_REASONS,
  GET_APPROVAL_HISTORY_SESSION_ENDED_REASONS,
  GET_CAPABILITIES_SESSION_ENDED_REASONS,
  GET_POLICY_SESSION_ENDED_REASONS,
  PROPOSE_POLICY_UPDATE_SESSION_ENDED_REASONS,
  REQUEST_SIGNATURE_SESSION_ENDED_REASONS,
} from "./core.js";
import { PUBLIC_ERROR_MESSAGES } from "./public-error.js";
import {
  CALL_METHOD_CHAIN_PATTERN,
  CALL_METHOD_NAME_PATTERN,
  ED25519_PUBLIC_KEY_BASE64_PATTERN,
  AGENT_Q_POLICY_SCHEMA,
  APPROVAL_HISTORY_CONFIRMATION_KINDS,
  APPROVAL_HISTORY_DECISION_KINDS,
  APPROVAL_HISTORY_HIGHEST_ACTIONS,
  APPROVAL_HISTORY_POLICY_UPDATE_RESULTS,
  APPROVAL_HISTORY_REASON_CODE_PATTERN,
  APPROVAL_HISTORY_RULE_REF_PATTERN,
  MAX_ACCOUNTS_PER_RESPONSE,
  MAX_APPROVAL_HISTORY_RECORDS,
  MAX_CAPABILITY_ACCOUNTS_PER_CHAIN,
  MAX_CAPABILITY_CHAINS,
  MAX_POLICY_RULE_COUNT,
  METHOD_RESULT_ERROR_MESSAGES,
  POLICY_ID_PATTERN,
  POLICY_UPDATE_RESULT_STATUSES,
  SIGNATURE_REQUEST_HISTORY_TERMINAL_RESULTS,
  SIGNATURE_RESULT_ERROR_MESSAGES,
  SUI_ADDRESS_PATTERN,
  SUI_DERIVATION_PATH,
  SUI_ED25519_SIGNATURE_BASE64_PATTERN,
  UINT_DECIMAL_STRING_PATTERN,
  isUint64DecimalString,
  isSuiAddressForPublicKey,
} from "./protocol.js";
import {
  DEVICE_ID_PATTERN,
  DEVICE_STATES,
  GATEWAY_NAME_PATTERN,
  IDENTIFICATION_CODE_PATTERN,
  ISO_TIMESTAMP_PATTERN,
  MAX_FIRMWARE_NAME_LENGTH,
  MAX_FIRMWARE_VERSION_LENGTH,
  MAX_HARDWARE_ID_LENGTH,
  MAX_LABEL_LENGTH,
  MAX_PORT_HINT_LENGTH,
  PRINTABLE_ASCII_ONLY,
  PURPOSE_PATTERN,
  PROVISIONING_STATES,
  REQUEST_ID_PATTERN,
  isValidLabel,
  isValidPurpose,
} from "./safe-text.js";

// Mirrors public-error.ts exactly: the code must be an allowlisted public code
// and the message must be that code's canonical string. This keeps Gateway
// egress schemas in lockstep with the runtime.
export const publicErrorShape = z
  .object({
    code: z.string(),
    message: z.string(),
    retryable: z.boolean(),
  })
  .refine((value) => PUBLIC_ERROR_MESSAGES[value.code] === value.message, {
    message: "error must be a canonical public error (allowlisted code with its matching message)",
  });

export const safeDeviceIdShape = z.string().regex(DEVICE_ID_PATTERN);
export const requestIdShape = z.string().regex(REQUEST_ID_PATTERN);
export const identificationCodeShape = z.string().regex(IDENTIFICATION_CODE_PATTERN);
export const displayTextShape = (maxLength: number) => z.string().regex(PRINTABLE_ASCII_ONLY).max(maxLength);
export const portHintShape = displayTextShape(MAX_PORT_HINT_LENGTH);
export const isoInstantShape = z
  .string()
  .regex(ISO_TIMESTAMP_PATTERN)
  .refine((value) => Number.isFinite(Date.parse(value)));
export const safePurposeShape = z.string().regex(PURPOSE_PATTERN).refine((value) => isValidPurpose(value));
export const safeLabelShape = z.string().min(1).max(MAX_LABEL_LENGTH).refine((value) => isValidLabel(value));

export const deviceShape = z.object({
  deviceId: safeDeviceIdShape,
  state: z.enum(DEVICE_STATES),
  firmwareName: displayTextShape(MAX_FIRMWARE_NAME_LENGTH),
  hardware: displayTextShape(MAX_HARDWARE_ID_LENGTH),
  firmwareVersion: displayTextShape(MAX_FIRMWARE_VERSION_LENGTH),
});
export const provisioningShape = z.object({
  state: z.enum(PROVISIONING_STATES),
});
export const deviceStatusSnapshotShape = z.object({
  device: deviceShape,
  provisioning: provisioningShape,
});

export const statusResponseShape = z.object({
  id: requestIdShape,
  version: z.literal(1),
  type: z.literal("status"),
  device: deviceShape,
  provisioning: provisioningShape,
});

export const identifyResponseShape = z.object({
  id: requestIdShape,
  version: z.literal(1),
  type: z.literal("identify_device_result"),
  status: z.literal("displayed"),
  code: identificationCodeShape,
  device: deviceShape,
});

export const liveStatusShape = z.object({
  source: z.literal("live"),
  connected: z.literal(true),
  portPath: portHintShape,
  protocolResponse: statusResponseShape,
});

export const identifiedDeviceShape = z.object({
  source: z.literal("live"),
  connected: z.literal(true),
  portPath: portHintShape,
  status: z.literal("displayed"),
  code: identificationCodeShape,
  protocolResponse: identifyResponseShape,
});

export const failedIdentificationShape = z.object({
  source: z.literal("error"),
  connected: z.literal(false),
  portPath: portHintShape,
  deviceId: safeDeviceIdShape,
  status: z.literal("error"),
  error: publicErrorShape,
});

export const errorToolResultShape = z.object({
  source: z.literal("error"),
  connected: z.literal(false),
  error: publicErrorShape,
});

export const runtimeSessionShape = z.object({
  sessionTtlMs: z.number().int().positive(),
  connectedAt: isoInstantShape,
});

export const deviceListEntryShape = z.object({
  deviceId: safeDeviceIdShape,
  transport: z.literal("usb"),
  lastPortHint: portHintShape,
  lastSeenAt: isoInstantShape,
  label: safeLabelShape.nullable(),
  lastStatus: deviceStatusSnapshotShape,
  assignedPurposes: z.array(safePurposeShape),
  isDefaultActive: z.boolean(),
  runtimeSession: runtimeSessionShape.nullable(),
});

const unavailableReasonShape = z.enum([
  "timeout",
  "port_not_found",
  "port_in_use",
  "port_permission_denied",
  "handshake_failed",
  "incompatible_version",
  "transport_closed",
]);
const scanDeviceFailureShape = z.object({
  source: z.literal("error"),
  connected: z.literal(false),
  portPath: portHintShape,
  unavailableReason: unavailableReasonShape,
  firmwareErrorCode: z
    .string()
    .refine((code) => Object.prototype.hasOwnProperty.call(PUBLIC_ERROR_MESSAGES, code))
    .optional(),
});
export const scanDevicesSuccessOutputShape = z.object({
  source: z.literal("live"),
  devices: z.array(liveStatusShape),
  failures: z.array(scanDeviceFailureShape),
  activeDeviceId: safeDeviceIdShape.nullable(),
});
export const scanDevicesToolOutputShape = z.discriminatedUnion("source", [
  scanDevicesSuccessOutputShape,
  errorToolResultShape,
]);

export const identifyDevicesSuccessOutputShape = z.object({
  source: z.literal("live"),
  devices: z.array(z.discriminatedUnion("source", [identifiedDeviceShape, failedIdentificationShape])),
  activeDeviceId: safeDeviceIdShape.nullable(),
});
export const identifyDevicesToolOutputShape = z.discriminatedUnion("source", [
  identifyDevicesSuccessOutputShape,
  errorToolResultShape,
]);

export const selectDeviceSuccessOutputShape = z.object({
  source: z.literal("selected"),
  activeDeviceId: safeDeviceIdShape,
  purpose: safePurposeShape.nullable(),
  device: deviceShape,
});
export const selectDeviceToolOutputShape = z.discriminatedUnion("source", [
  selectDeviceSuccessOutputShape,
  errorToolResultShape,
]);

export const listDevicesSuccessOutputShape = z.object({
  source: z.literal("list"),
  devices: z.array(deviceListEntryShape),
  activeDeviceId: safeDeviceIdShape.nullable(),
  activeDeviceIdsByPurpose: z.record(safePurposeShape, safeDeviceIdShape),
});
export const listDevicesToolOutputShape = z.discriminatedUnion("source", [
  listDevicesSuccessOutputShape,
  errorToolResultShape,
]);

export const setDeviceMetadataSuccessOutputShape = z.object({
  source: z.literal("metadata"),
  deviceId: safeDeviceIdShape,
  label: safeLabelShape.nullable(),
});
export const setDeviceMetadataToolOutputShape = z.discriminatedUnion("source", [
  setDeviceMetadataSuccessOutputShape,
  errorToolResultShape,
]);

export const connectDeviceSuccessOutputShape = z.object({
  source: z.literal("connected"),
  deviceId: safeDeviceIdShape,
  sessionTtlMs: z.number().int().positive(),
  connectedAt: isoInstantShape,
  device: deviceShape,
});
export const connectDeviceToolOutputShape = z.discriminatedUnion("source", [
  connectDeviceSuccessOutputShape,
  errorToolResultShape,
]);

export const disconnectDeviceSuccessOutputShape = z
  .object({
    source: z.enum(["disconnected", "not_connected"]),
    deviceId: safeDeviceIdShape,
    reason: z.enum(DISCONNECT_REASONS),
  })
  .refine(
    (result) =>
      (result.source === "not_connected" && result.reason === "not_connected") ||
      (result.source === "disconnected" &&
        DISCONNECT_ENDED_REASONS.includes(result.reason as (typeof DISCONNECT_ENDED_REASONS)[number])),
    { message: "disconnect source and reason disagree" },
  );
export const disconnectDeviceToolOutputShape = z.discriminatedUnion("source", [
  disconnectDeviceSuccessOutputShape,
  errorToolResultShape,
]);

const capabilityAccountShape = z.object({
  keyScheme: z.literal("ed25519"),
  derivationPath: z.literal(SUI_DERIVATION_PATH),
});
const capabilityChainShape = z.object({
  id: z.literal("sui"),
  accounts: z.array(capabilityAccountShape).length(MAX_CAPABILITY_ACCOUNTS_PER_CHAIN),
  methods: z.array(z.never()).length(0),
});
const signatureRequestCapabilityShape = z.object({
  chain: z.literal("sui"),
  method: z.literal("sign_transaction"),
});
const liveCapabilitiesOutputShape = z.object({
  source: z.literal("live"),
  deviceId: safeDeviceIdShape,
  capabilities: z.array(capabilityChainShape).length(MAX_CAPABILITY_CHAINS),
  signatureRequests: z.array(signatureRequestCapabilityShape).length(1).optional(),
});
const notConnectedCapabilitiesOutputShape = z.object({
  source: z.literal("not_connected"),
  deviceId: safeDeviceIdShape,
  reason: z.literal("not_connected"),
});
const sessionEndedCapabilitiesOutputShape = z.object({
  source: z.literal("session_ended"),
  deviceId: safeDeviceIdShape,
  reason: z.enum(GET_CAPABILITIES_SESSION_ENDED_REASONS),
});
export const getCapabilitiesSuccessOutputShape = z.discriminatedUnion("source", [
  liveCapabilitiesOutputShape,
  notConnectedCapabilitiesOutputShape,
  sessionEndedCapabilitiesOutputShape,
]);
export const getCapabilitiesToolOutputShape = z.discriminatedUnion("source", [
  liveCapabilitiesOutputShape,
  notConnectedCapabilitiesOutputShape,
  sessionEndedCapabilitiesOutputShape,
  errorToolResultShape,
]);

const accountShape = z.object({
  chain: z.literal("sui"),
  address: z.string().regex(SUI_ADDRESS_PATTERN),
  publicKey: z.string().regex(ED25519_PUBLIC_KEY_BASE64_PATTERN),
  keyScheme: z.literal("ed25519"),
  derivationPath: z.literal(SUI_DERIVATION_PATH),
}).refine((account) => isSuiAddressForPublicKey(account.address, account.publicKey), {
  message: "Sui address must match publicKey",
});
const liveAccountsOutputShape = z.object({
  source: z.literal("live"),
  deviceId: safeDeviceIdShape,
  accounts: z.array(accountShape).length(MAX_ACCOUNTS_PER_RESPONSE),
});
const notConnectedAccountsOutputShape = z.object({
  source: z.literal("not_connected"),
  deviceId: safeDeviceIdShape,
  reason: z.literal("not_connected"),
});
const sessionEndedAccountsOutputShape = z.object({
  source: z.literal("session_ended"),
  deviceId: safeDeviceIdShape,
  reason: z.enum(GET_ACCOUNTS_SESSION_ENDED_REASONS),
});
export const getAccountsSuccessOutputShape = z.discriminatedUnion("source", [
  liveAccountsOutputShape,
  notConnectedAccountsOutputShape,
  sessionEndedAccountsOutputShape,
]);
export const getAccountsToolOutputShape = z.discriminatedUnion("source", [
  liveAccountsOutputShape,
  notConnectedAccountsOutputShape,
  sessionEndedAccountsOutputShape,
  errorToolResultShape,
]);

const policySummaryShape = z.object({
  schema: z.literal(AGENT_Q_POLICY_SCHEMA),
  policyId: z.string().regex(POLICY_ID_PATTERN),
  defaultAction: z.literal("reject"),
  ruleCount: z.number().int().min(0).max(MAX_POLICY_RULE_COUNT),
});
const livePolicyOutputShape = z.object({
  source: z.literal("live"),
  deviceId: safeDeviceIdShape,
  policy: policySummaryShape,
});
const notConnectedPolicyOutputShape = z.object({
  source: z.literal("not_connected"),
  deviceId: safeDeviceIdShape,
  reason: z.literal("not_connected"),
});
const sessionEndedPolicyOutputShape = z.object({
  source: z.literal("session_ended"),
  deviceId: safeDeviceIdShape,
  reason: z.enum(GET_POLICY_SESSION_ENDED_REASONS),
});
export const getPolicySuccessOutputShape = z.discriminatedUnion("source", [
  livePolicyOutputShape,
  notConnectedPolicyOutputShape,
  sessionEndedPolicyOutputShape,
]);
export const getPolicyToolOutputShape = z.discriminatedUnion("source", [
  livePolicyOutputShape,
  notConnectedPolicyOutputShape,
  sessionEndedPolicyOutputShape,
  errorToolResultShape,
]);

const approvalHistoryRecordShape = z.object({
  seq: z.string().regex(UINT_DECIMAL_STRING_PATTERN).refine((value) => isUint64DecimalString(value)),
  uptimeMs: z.string().regex(UINT_DECIMAL_STRING_PATTERN).refine((value) => isUint64DecimalString(value)),
  timeSource: z.literal("uptime"),
  reasonCode: z.string().regex(APPROVAL_HISTORY_REASON_CODE_PATTERN),
});
const methodDecisionApprovalHistoryRecordShape = approvalHistoryRecordShape.extend({
  eventKind: z.literal("method_decision"),
  decisionKind: z.enum(APPROVAL_HISTORY_DECISION_KINDS),
  confirmationKind: z.enum(APPROVAL_HISTORY_CONFIRMATION_KINDS),
  chain: z.string().regex(CALL_METHOD_CHAIN_PATTERN),
  method: z.string().regex(CALL_METHOD_NAME_PATTERN),
  payloadDigest: z.string().regex(POLICY_ID_PATTERN).optional(),
  policyHash: z.string().regex(POLICY_ID_PATTERN).optional(),
  ruleRef: z.string().regex(APPROVAL_HISTORY_RULE_REF_PATTERN).optional(),
});
const policyUpdateApprovalHistoryRecordShape = approvalHistoryRecordShape.extend({
  eventKind: z.literal("policy_update"),
  result: z.enum(APPROVAL_HISTORY_POLICY_UPDATE_RESULTS),
  policyHash: z.string().regex(POLICY_ID_PATTERN),
  ruleCount: z.number().int().min(0).max(MAX_POLICY_RULE_COUNT),
  highestAction: z.enum(APPROVAL_HISTORY_HIGHEST_ACTIONS),
});
const signatureRequestConfirmationApprovalHistoryRecordShape = approvalHistoryRecordShape.extend({
  eventKind: z.literal("signature_request"),
  recordKind: z.literal("confirmation"),
  confirmationKind: z.literal("local_pin"),
  chain: z.string().regex(CALL_METHOD_CHAIN_PATTERN),
  method: z.string().regex(CALL_METHOD_NAME_PATTERN),
  payloadDigest: z.string().regex(POLICY_ID_PATTERN),
});
const signatureRequestTerminalApprovalHistoryRecordShape = approvalHistoryRecordShape.extend({
  eventKind: z.literal("signature_request"),
  recordKind: z.literal("terminal"),
  terminalResult: z.enum(SIGNATURE_REQUEST_HISTORY_TERMINAL_RESULTS),
  chain: z.string().regex(CALL_METHOD_CHAIN_PATTERN),
  method: z.string().regex(CALL_METHOD_NAME_PATTERN),
  payloadDigest: z.string().regex(POLICY_ID_PATTERN),
});
const approvalHistoryRecordOutputShape = z.union([
  methodDecisionApprovalHistoryRecordShape,
  policyUpdateApprovalHistoryRecordShape,
  signatureRequestConfirmationApprovalHistoryRecordShape,
  signatureRequestTerminalApprovalHistoryRecordShape,
]);
const liveApprovalHistoryOutputShape = z.object({
  source: z.literal("live"),
  deviceId: safeDeviceIdShape,
  records: z.array(approvalHistoryRecordOutputShape).max(MAX_APPROVAL_HISTORY_RECORDS),
  hasMore: z.boolean(),
});
const notConnectedApprovalHistoryOutputShape = z.object({
  source: z.literal("not_connected"),
  deviceId: safeDeviceIdShape,
  reason: z.literal("not_connected"),
});
const sessionEndedApprovalHistoryOutputShape = z.object({
  source: z.literal("session_ended"),
  deviceId: safeDeviceIdShape,
  reason: z.enum(GET_APPROVAL_HISTORY_SESSION_ENDED_REASONS),
});
export const getApprovalHistorySuccessOutputShape = z.discriminatedUnion("source", [
  liveApprovalHistoryOutputShape,
  notConnectedApprovalHistoryOutputShape,
  sessionEndedApprovalHistoryOutputShape,
]);
export const getApprovalHistoryToolOutputShape = z.discriminatedUnion("source", [
  liveApprovalHistoryOutputShape,
  notConnectedApprovalHistoryOutputShape,
  sessionEndedApprovalHistoryOutputShape,
  errorToolResultShape,
]);

const methodResultErrorShape = z.object({
  code: z.enum(Object.keys(METHOD_RESULT_ERROR_MESSAGES) as [keyof typeof METHOD_RESULT_ERROR_MESSAGES, ...Array<keyof typeof METHOD_RESULT_ERROR_MESSAGES>]),
  message: z.enum(Object.values(METHOD_RESULT_ERROR_MESSAGES) as [string, ...string[]]),
}).refine((error) => error.message === METHOD_RESULT_ERROR_MESSAGES[error.code], {
  message: "Method result error message must match its code.",
});
const liveCallMethodRejectedOutputShape = z.object({
  source: z.literal("live"),
  deviceId: safeDeviceIdShape,
  status: z.literal("rejected"),
  error: methodResultErrorShape,
});
const notConnectedCallMethodOutputShape = z.object({
  source: z.literal("not_connected"),
  deviceId: safeDeviceIdShape,
  reason: z.literal("not_connected"),
});
const sessionEndedCallMethodOutputShape = z.object({
  source: z.literal("session_ended"),
  deviceId: safeDeviceIdShape,
  reason: z.enum(CALL_METHOD_SESSION_ENDED_REASONS),
});
export const callMethodSuccessOutputShape = z.union([
  liveCallMethodRejectedOutputShape,
  notConnectedCallMethodOutputShape,
  sessionEndedCallMethodOutputShape,
]);
export const callMethodToolOutputShape = z.union([
  liveCallMethodRejectedOutputShape,
  notConnectedCallMethodOutputShape,
  sessionEndedCallMethodOutputShape,
  errorToolResultShape,
]);

const signatureResultErrorShape = z.object({
  code: z.enum(Object.keys(SIGNATURE_RESULT_ERROR_MESSAGES) as [keyof typeof SIGNATURE_RESULT_ERROR_MESSAGES, ...Array<keyof typeof SIGNATURE_RESULT_ERROR_MESSAGES>]),
  message: z.enum(Object.values(SIGNATURE_RESULT_ERROR_MESSAGES) as [string, ...string[]]),
}).refine((error) => error.message === SIGNATURE_RESULT_ERROR_MESSAGES[error.code], {
  message: "Signature result error message must match its code.",
});
const liveRequestSignatureSignedOutputShape = z.object({
  source: z.literal("live"),
  deviceId: safeDeviceIdShape,
  status: z.literal("signed"),
  reasonCode: z.literal("device_confirmed"),
  chain: z.literal("sui"),
  method: z.literal("sign_transaction"),
  signature: z.string().regex(SUI_ED25519_SIGNATURE_BASE64_PATTERN),
});
const liveRequestSignatureTerminalOutputShape = z.discriminatedUnion("status", [
  z.object({
    source: z.literal("live"),
    deviceId: safeDeviceIdShape,
    status: z.literal("rejected"),
    reasonCode: z.literal("device_rejected"),
    error: signatureResultErrorShape.refine((error) => error.code === "device_rejected", {
      message: "Rejected signature result error code must be device_rejected.",
    }),
  }),
  z.object({
    source: z.literal("live"),
    deviceId: safeDeviceIdShape,
    status: z.literal("timed_out"),
    reasonCode: z.literal("device_timed_out"),
    error: signatureResultErrorShape.refine((error) => error.code === "device_timed_out", {
      message: "Timed-out signature result error code must be device_timed_out.",
    }),
  }),
  z.object({
    source: z.literal("live"),
    deviceId: safeDeviceIdShape,
    status: z.literal("failed"),
    reasonCode: z.literal("signing_failed"),
    error: signatureResultErrorShape.refine((error) => error.code === "signing_failed", {
      message: "Failed signature result error code must be signing_failed.",
    }),
  }),
]);
const notConnectedRequestSignatureOutputShape = z.object({
  source: z.literal("not_connected"),
  deviceId: safeDeviceIdShape,
  reason: z.literal("not_connected"),
});
const sessionEndedRequestSignatureOutputShape = z.object({
  source: z.literal("session_ended"),
  deviceId: safeDeviceIdShape,
  reason: z.enum(REQUEST_SIGNATURE_SESSION_ENDED_REASONS),
});
export const requestSignatureSuccessOutputShape = z.union([
  liveRequestSignatureSignedOutputShape,
  liveRequestSignatureTerminalOutputShape,
  notConnectedRequestSignatureOutputShape,
  sessionEndedRequestSignatureOutputShape,
]);
export const requestSignatureToolOutputShape = z.union([
  liveRequestSignatureSignedOutputShape,
  liveRequestSignatureTerminalOutputShape,
  notConnectedRequestSignatureOutputShape,
  sessionEndedRequestSignatureOutputShape,
  errorToolResultShape,
]);

const policyUpdateResultPolicyShape = z.object({
  policyHash: z.string().regex(POLICY_ID_PATTERN),
  ruleCount: z.number().int().min(0).max(MAX_POLICY_RULE_COUNT),
  highestAction: z.enum(APPROVAL_HISTORY_HIGHEST_ACTIONS),
});
const liveProposePolicyUpdateOutputShape = z
  .object({
    source: z.literal("live"),
    deviceId: safeDeviceIdShape,
    status: z.enum(POLICY_UPDATE_RESULT_STATUSES),
    reasonCode: z.string().regex(APPROVAL_HISTORY_REASON_CODE_PATTERN),
    policy: policyUpdateResultPolicyShape.optional(),
  })
  .refine((value) => (value.status === "invalid_policy") === (value.policy === undefined), {
    message: "invalid_policy omits policy metadata; other policy update results include it",
  });
const notConnectedProposePolicyUpdateOutputShape = z.object({
  source: z.literal("not_connected"),
  deviceId: safeDeviceIdShape,
  reason: z.literal("not_connected"),
});
const sessionEndedProposePolicyUpdateOutputShape = z.object({
  source: z.literal("session_ended"),
  deviceId: safeDeviceIdShape,
  reason: z.enum(PROPOSE_POLICY_UPDATE_SESSION_ENDED_REASONS),
});
export const proposePolicyUpdateSuccessOutputShape = z.discriminatedUnion("source", [
  liveProposePolicyUpdateOutputShape,
  notConnectedProposePolicyUpdateOutputShape,
  sessionEndedProposePolicyUpdateOutputShape,
]);
export const proposePolicyUpdateToolOutputShape = z.discriminatedUnion("source", [
  liveProposePolicyUpdateOutputShape,
  notConnectedProposePolicyUpdateOutputShape,
  sessionEndedProposePolicyUpdateOutputShape,
  errorToolResultShape,
]);

const cachedDeviceStatusOutputShape = z.object({
  source: z.literal("cached"),
  connected: z.literal(false),
  statusObservedAt: isoInstantShape,
  unavailableReason: unavailableReasonShape,
  firmwareErrorCode: z
    .string()
    .refine((code) => Object.prototype.hasOwnProperty.call(PUBLIC_ERROR_MESSAGES, code))
    .optional(),
  cachedStatus: deviceStatusSnapshotShape,
});
export const getDeviceStatusSuccessOutputShape = z.discriminatedUnion("source", [
  liveStatusShape,
  cachedDeviceStatusOutputShape,
]);
export const getDeviceStatusToolOutputShape = z.discriminatedUnion("source", [
  liveStatusShape,
  cachedDeviceStatusOutputShape,
  errorToolResultShape,
]);

export const gatewaySuccessOutputSchemas = {
  scanDevices: scanDevicesSuccessOutputShape,
  identifyDevices: identifyDevicesSuccessOutputShape,
  selectDevice: selectDeviceSuccessOutputShape,
  getDeviceStatus: getDeviceStatusSuccessOutputShape,
  listDevices: listDevicesSuccessOutputShape,
  setDeviceMetadata: setDeviceMetadataSuccessOutputShape,
  connectDevice: connectDeviceSuccessOutputShape,
  disconnectDevice: disconnectDeviceSuccessOutputShape,
  getCapabilities: getCapabilitiesSuccessOutputShape,
  getAccounts: getAccountsSuccessOutputShape,
  getPolicy: getPolicySuccessOutputShape,
  getApprovalHistory: getApprovalHistorySuccessOutputShape,
  callMethod: callMethodSuccessOutputShape,
  requestSignature: requestSignatureSuccessOutputShape,
  proposePolicyUpdate: proposePolicyUpdateSuccessOutputShape,
} as const;
