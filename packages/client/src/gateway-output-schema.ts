import * as z from "zod/v4";
import {
  DISCONNECT_ENDED_REASONS,
  DISCONNECT_REASONS,
  GET_ACCOUNTS_SESSION_ENDED_REASONS,
  GET_APPROVAL_HISTORY_SESSION_ENDED_REASONS,
  GET_CAPABILITIES_SESSION_ENDED_REASONS,
  POLICY_PROPOSE_SESSION_ENDED_REASONS,
  POLICY_GET_SESSION_ENDED_REASONS,
  SIGN_TRANSACTION_SESSION_ENDED_REASONS,
} from "./core.js";
import { PUBLIC_ERROR_MESSAGES } from "./public-error.js";
import {
  ED25519_PUBLIC_KEY_BASE64_PATTERN,
  AGENT_Q_POLICY_SCHEMA,
  APPROVAL_HISTORY_HIGHEST_ACTIONS,
  APPROVAL_HISTORY_POLICY_UPDATE_RESULTS,
  APPROVAL_HISTORY_REASON_CODE_PATTERN,
  APPROVAL_HISTORY_RULE_REF_PATTERN,
  MAX_ACCOUNTS_PER_RESPONSE,
  MAX_APPROVAL_HISTORY_RECORDS,
  MAX_CAPABILITY_ACCOUNTS_PER_CHAIN,
  MAX_CAPABILITY_CHAINS,
  MAX_POLICY_RULE_COUNT,
  POLICY_ID_PATTERN,
  POLICY_PROPOSE_RESULT_STATUSES,
  SIGN_CHAIN_PATTERN,
  SIGN_METHOD_PATTERN,
  SIGNING_HISTORY_TERMINAL_RESULTS,
  SIGN_RESULT_ERROR_MESSAGES,
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
}).strict();
const capabilityChainShape = z.object({
  id: z.literal("sui"),
  accounts: z.array(capabilityAccountShape).length(MAX_CAPABILITY_ACCOUNTS_PER_CHAIN),
  methods: z.array(z.never()).length(0),
}).strict();
const signingCapabilityEntryShape = z.object({
  chain: z.literal("sui"),
  method: z.literal("sign_transaction"),
}).strict();
const signingCapabilitiesShape = z.object({
  authorization: z.enum(["user", "policy"]),
  methods: z.array(signingCapabilityEntryShape).length(1),
}).strict();
const liveCapabilitiesOutputShape = z.object({
  source: z.literal("live"),
  deviceId: safeDeviceIdShape,
  capabilities: z.array(capabilityChainShape).length(MAX_CAPABILITY_CHAINS),
  signing: signingCapabilitiesShape.optional(),
}).strict();
const liveProviderCapabilitiesOutputShape = z.object({
  source: z.literal("live"),
  deviceId: safeDeviceIdShape,
  capabilities: z.array(capabilityChainShape).length(MAX_CAPABILITY_CHAINS),
  signing: signingCapabilitiesShape.optional(),
}).strict();
const liveMcpCapabilitiesOutputShape = z.object({
  source: z.literal("live"),
  deviceId: safeDeviceIdShape,
  capabilities: z.array(capabilityChainShape).length(MAX_CAPABILITY_CHAINS),
  signing: signingCapabilitiesShape.optional(),
}).strict();
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
export const providerGetCapabilitiesSuccessOutputShape = z.discriminatedUnion("source", [
  liveProviderCapabilitiesOutputShape,
  notConnectedCapabilitiesOutputShape,
  sessionEndedCapabilitiesOutputShape,
]);
export const providerGetCapabilitiesToolOutputShape = z.discriminatedUnion("source", [
  liveProviderCapabilitiesOutputShape,
  notConnectedCapabilitiesOutputShape,
  sessionEndedCapabilitiesOutputShape,
  errorToolResultShape,
]);
export const mcpGetCapabilitiesSuccessOutputShape = z.discriminatedUnion("source", [
  liveMcpCapabilitiesOutputShape,
  notConnectedCapabilitiesOutputShape,
  sessionEndedCapabilitiesOutputShape,
]);
export const mcpGetCapabilitiesToolOutputShape = z.discriminatedUnion("source", [
  liveMcpCapabilitiesOutputShape,
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
  reason: z.enum(POLICY_GET_SESSION_ENDED_REASONS),
});
export const policyGetSuccessOutputShape = z.discriminatedUnion("source", [
  livePolicyOutputShape,
  notConnectedPolicyOutputShape,
  sessionEndedPolicyOutputShape,
]);
export const policyGetToolOutputShape = z.discriminatedUnion("source", [
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
const policyUpdateApprovalHistoryRecordShape = approvalHistoryRecordShape.extend({
  eventKind: z.literal("policy_update"),
  result: z.enum(APPROVAL_HISTORY_POLICY_UPDATE_RESULTS),
  policyHash: z.string().regex(POLICY_ID_PATTERN),
  ruleCount: z.number().int().min(0).max(MAX_POLICY_RULE_COUNT),
  highestAction: z.enum(APPROVAL_HISTORY_HIGHEST_ACTIONS),
});
const signingUserConfirmationApprovalHistoryRecordShape = approvalHistoryRecordShape.extend({
  eventKind: z.literal("signing"),
  recordKind: z.literal("confirmation"),
  authorization: z.literal("user"),
  confirmationKind: z.literal("local_pin"),
  chain: z.string().regex(SIGN_CHAIN_PATTERN),
  method: z.string().regex(SIGN_METHOD_PATTERN),
  payloadDigest: z.string().regex(POLICY_ID_PATTERN),
});
const signingPolicyConfirmationApprovalHistoryRecordShape = approvalHistoryRecordShape.extend({
  eventKind: z.literal("signing"),
  recordKind: z.literal("confirmation"),
  authorization: z.literal("policy"),
  confirmationKind: z.literal("policy"),
  chain: z.string().regex(SIGN_CHAIN_PATTERN),
  method: z.string().regex(SIGN_METHOD_PATTERN),
  payloadDigest: z.string().regex(POLICY_ID_PATTERN),
  policyHash: z.string().regex(POLICY_ID_PATTERN),
  ruleRef: z.string().regex(APPROVAL_HISTORY_RULE_REF_PATTERN),
});
const signingTerminalApprovalHistoryRecordShape = approvalHistoryRecordShape.extend({
  eventKind: z.literal("signing"),
  recordKind: z.literal("terminal"),
  authorization: z.enum(["user", "policy"]),
  terminalResult: z.enum(SIGNING_HISTORY_TERMINAL_RESULTS),
  chain: z.string().regex(SIGN_CHAIN_PATTERN),
  method: z.string().regex(SIGN_METHOD_PATTERN),
  payloadDigest: z.string().regex(POLICY_ID_PATTERN),
  policyHash: z.string().regex(POLICY_ID_PATTERN).optional(),
  ruleRef: z.string().regex(APPROVAL_HISTORY_RULE_REF_PATTERN).optional(),
}).refine((value) => {
  const hasPolicyMetadata = value.policyHash !== undefined && value.ruleRef !== undefined;
  if (value.authorization === "policy") {
    return (
      hasPolicyMetadata &&
      ["signed", "policy_rejected", "signing_failed"].includes(value.terminalResult)
    );
  }
  return (
    value.policyHash === undefined &&
    value.ruleRef === undefined &&
    ["signed", "user_rejected", "user_timed_out", "signing_failed"].includes(value.terminalResult)
  );
}, { message: "signing policy metadata must match authorization" });
const approvalHistoryRecordOutputShape = z.union([
  policyUpdateApprovalHistoryRecordShape,
  signingUserConfirmationApprovalHistoryRecordShape,
  signingPolicyConfirmationApprovalHistoryRecordShape,
  signingTerminalApprovalHistoryRecordShape,
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

const signResultErrorShape = z.object({
  code: z.enum(Object.keys(SIGN_RESULT_ERROR_MESSAGES) as [keyof typeof SIGN_RESULT_ERROR_MESSAGES, ...Array<keyof typeof SIGN_RESULT_ERROR_MESSAGES>]),
  message: z.enum(Object.values(SIGN_RESULT_ERROR_MESSAGES) as [string, ...string[]]),
}).refine((error) => error.message === SIGN_RESULT_ERROR_MESSAGES[error.code], {
  message: "Sign result error message must match its code.",
});
const liveUserSignSignedOutputShape = z.object({
  source: z.literal("live"),
  deviceId: safeDeviceIdShape,
  status: z.literal("signed"),
  authorization: z.literal("user"),
  chain: z.literal("sui"),
  method: z.literal("sign_transaction"),
  signature: z.string().regex(SUI_ED25519_SIGNATURE_BASE64_PATTERN),
});
const livePolicySignSignedOutputShape = liveUserSignSignedOutputShape.extend({
  authorization: z.literal("policy"),
});
const liveUserSignTerminalOutputShape = z.discriminatedUnion("status", [
  z.object({
    source: z.literal("live"),
    deviceId: safeDeviceIdShape,
    status: z.literal("user_rejected"),
    authorization: z.literal("user"),
    error: signResultErrorShape.refine((error) => error.code === "user_rejected", {
      message: "User-rejected sign result error code must be user_rejected.",
    }),
  }),
  z.object({
    source: z.literal("live"),
    deviceId: safeDeviceIdShape,
    status: z.literal("user_timed_out"),
    authorization: z.literal("user"),
    error: signResultErrorShape.refine((error) => error.code === "user_timed_out", {
      message: "Timed-out sign result error code must be user_timed_out.",
    }),
  }),
  z.object({
    source: z.literal("live"),
    deviceId: safeDeviceIdShape,
    status: z.literal("signing_failed"),
    authorization: z.literal("user"),
    error: signResultErrorShape.refine((error) => error.code === "signing_failed", {
      message: "Failed sign result error code must be signing_failed.",
    }),
  }),
]);
const livePolicySignTerminalOutputShape = z.discriminatedUnion("status", [
  z.object({
    source: z.literal("live"),
    deviceId: safeDeviceIdShape,
    status: z.literal("policy_rejected"),
    authorization: z.literal("policy"),
    policyHash: z.string().regex(POLICY_ID_PATTERN),
    ruleRef: z.string().regex(APPROVAL_HISTORY_RULE_REF_PATTERN),
    error: signResultErrorShape.refine((error) => error.code === "policy_rejected", {
      message: "Policy-rejected sign result error code must be policy_rejected.",
    }),
  }),
  z.object({
    source: z.literal("live"),
    deviceId: safeDeviceIdShape,
    status: z.literal("signing_failed"),
    authorization: z.literal("policy"),
    error: signResultErrorShape.refine((error) => error.code === "signing_failed", {
      message: "Failed sign result error code must be signing_failed.",
    }),
  }),
]);
const notConnectedSignOutputShape = z.object({
  source: z.literal("not_connected"),
  deviceId: safeDeviceIdShape,
  reason: z.literal("not_connected"),
});
const sessionEndedSignTransactionOutputShape = z.object({
  source: z.literal("session_ended"),
  deviceId: safeDeviceIdShape,
  reason: z.enum(SIGN_TRANSACTION_SESSION_ENDED_REASONS),
});
export const signTransactionSuccessOutputShape = z.union([
  liveUserSignSignedOutputShape,
  livePolicySignSignedOutputShape,
  liveUserSignTerminalOutputShape,
  livePolicySignTerminalOutputShape,
  notConnectedSignOutputShape,
  sessionEndedSignTransactionOutputShape,
]);
export const signTransactionToolOutputShape = z.union([
  liveUserSignSignedOutputShape,
  livePolicySignSignedOutputShape,
  liveUserSignTerminalOutputShape,
  livePolicySignTerminalOutputShape,
  notConnectedSignOutputShape,
  sessionEndedSignTransactionOutputShape,
  errorToolResultShape,
]);

const policyProposeResultPolicyShape = z.object({
  policyHash: z.string().regex(POLICY_ID_PATTERN),
  ruleCount: z.number().int().min(0).max(MAX_POLICY_RULE_COUNT),
  highestAction: z.enum(APPROVAL_HISTORY_HIGHEST_ACTIONS),
});
const livePolicyProposeOutputShape = z
  .object({
    source: z.literal("live"),
    deviceId: safeDeviceIdShape,
    status: z.enum(POLICY_PROPOSE_RESULT_STATUSES),
    reasonCode: z.string().regex(APPROVAL_HISTORY_REASON_CODE_PATTERN),
    policy: policyProposeResultPolicyShape.optional(),
  })
  .refine((value) => (value.status === "invalid_policy") === (value.policy === undefined), {
    message: "invalid_policy omits policy metadata; other policy_propose_result statuses include it",
  });
const notConnectedPolicyProposeOutputShape = z.object({
  source: z.literal("not_connected"),
  deviceId: safeDeviceIdShape,
  reason: z.literal("not_connected"),
});
const sessionEndedPolicyProposeOutputShape = z.object({
  source: z.literal("session_ended"),
  deviceId: safeDeviceIdShape,
  reason: z.enum(POLICY_PROPOSE_SESSION_ENDED_REASONS),
});
export const policyProposeSuccessOutputShape = z.discriminatedUnion("source", [
  livePolicyProposeOutputShape,
  notConnectedPolicyProposeOutputShape,
  sessionEndedPolicyProposeOutputShape,
]);
export const policyProposeToolOutputShape = z.discriminatedUnion("source", [
  livePolicyProposeOutputShape,
  notConnectedPolicyProposeOutputShape,
  sessionEndedPolicyProposeOutputShape,
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
  policyGet: policyGetSuccessOutputShape,
  getApprovalHistory: getApprovalHistorySuccessOutputShape,
  signTransaction: signTransactionSuccessOutputShape,
  policyPropose: policyProposeSuccessOutputShape,
} as const;
