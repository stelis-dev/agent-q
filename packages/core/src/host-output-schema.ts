import { Buffer } from "node:buffer";
import * as z from "zod/v4";
import {
  DISCONNECT_ENDED_REASONS,
  DISCONNECT_REASONS,
  GET_ACCOUNTS_SESSION_ENDED_REASONS,
  GET_APPROVAL_HISTORY_SESSION_ENDED_REASONS,
  GET_CAPABILITIES_SESSION_ENDED_REASONS,
  POLICY_PROPOSE_SESSION_ENDED_REASONS,
  POLICY_GET_SESSION_ENDED_REASONS,
  SIGN_PERSONAL_MESSAGE_SESSION_ENDED_REASONS,
  SIGN_TRANSACTION_SESSION_ENDED_REASONS,
} from "./core.js";
import {
  SIGNING_OUTCOME_ERROR_MESSAGES,
} from "./device-contract.js";
import { PUBLIC_ERROR_MESSAGES, toPublicError } from "./public-error.js";
import {
  APPROVAL_HISTORY_HIGHEST_ACTIONS,
  APPROVAL_HISTORY_POLICY_UPDATE_RESULTS,
  APPROVAL_HISTORY_REASON_CODE_PATTERN,
  APPROVAL_HISTORY_RULE_REF_PATTERN,
  CREDENTIAL_PREPARE_OPERATION,
  CREDENTIAL_PROPOSE_OPERATION,
  CREDENTIAL_PROPOSAL_OUTCOME_STATUSES,
  MAX_ACCOUNTS_PER_RESPONSE,
  MAX_APPROVAL_HISTORY_RECORDS,
  MAX_CAPABILITY_ACCOUNTS_PER_CHAIN,
  MAX_CAPABILITY_CHAINS,
  MAX_CREDENTIAL_CAPABILITIES,
  MAX_SIGNING_OUTCOME_PAYLOAD_BASE64_CHARS,
  MAX_POLICY_BLOCKCHAINS,
  MAX_POLICY_TOTAL_CONDITIONS,
  MAX_POLICY_TOTAL_NETWORKS,
  MAX_POLICY_TOTAL_POLICIES,
  POLICY_ID_PATTERN,
  POLICY_PROPOSAL_OUTCOME_STATUSES,
  SIGN_CHAIN_PATTERN,
  SIGN_METHOD_PATTERN,
  SIGNING_HISTORY_TERMINAL_RESULTS,
  SUI_CHAIN_ID,
  SUI_ADDRESS_PATTERN,
  SUI_DERIVATION_PATH,
  SUI_SCHEME_PREFIXED_ED25519_PUBLIC_KEY_BYTES,
  SUI_SIGNATURE_SCHEME_FLAG_ED25519,
  SUI_SIGNATURE_SCHEME_FLAG_ZKLOGIN,
  SUI_SIGN_PERSONAL_MESSAGE_METHOD,
  SUI_SIGN_TRANSACTION_METHOD,
  SUI_ZKLOGIN_CREDENTIAL,
  MIN_SUI_ZKLOGIN_PUBLIC_KEY_BYTES,
  MAX_SUI_ZKLOGIN_PUBLIC_KEY_BYTES,
  UINT_DECIMAL_STRING_PATTERN,
  isUint64DecimalString,
  isSuiPersonalMessageSignatureBase64,
  isSuiAddressForSchemePrefixedPublicKey,
  isSuiTransactionSignatureEnvelopeBase64,
  sanitizeCurrentPolicyDocument,
} from "./protocol.js";
import {
  DEVICE_ID_PATTERN,
  DEVICE_STATES,
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

// Mirrors the DeviceErrorCode projection exactly: code, message, and retryable
// must all come from the same canonical error row.
export const publicErrorShape = z
  .object({
    code: z.string(),
    message: z.string(),
    retryable: z.boolean(),
  })
  .strict()
  .refine((value) => {
    const canonical = toPublicError(value.code);
    return canonical.code === value.code &&
      canonical.message === value.message &&
      canonical.retryable === value.retryable;
  }, {
    message: "error must be a canonical public error row",
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
}).strict();
export const provisioningShape = z.object({
  state: z.enum(PROVISIONING_STATES),
}).strict();
export const deviceStatusSnapshotShape = z.object({
  device: deviceShape,
  provisioning: provisioningShape,
}).strict();

export const statusResponseShape = z.object({
  device: deviceShape,
  provisioning: provisioningShape,
}).strict();

export const identifyResponseShape = z.object({
  code: identificationCodeShape,
  device: deviceShape,
}).strict();

export const liveStatusShape = z.object({
  source: z.literal("live"),
  connected: z.literal(true),
  portPath: portHintShape,
  status: statusResponseShape,
}).strict();

export const identifiedDeviceShape = z.object({
  source: z.literal("live"),
  connected: z.literal(true),
  portPath: portHintShape,
  code: identificationCodeShape,
  device: deviceShape,
}).strict();

export const failedIdentificationShape = z.object({
  source: z.literal("error"),
  connected: z.literal(false),
  portPath: portHintShape,
  deviceId: safeDeviceIdShape,
  status: z.literal("error"),
  error: publicErrorShape,
}).strict();

export const errorToolResultShape = z.object({
  source: z.literal("error"),
  connected: z.literal(false),
  error: publicErrorShape,
}).strict();

export const runtimeSessionShape = z.object({
  sessionTtlMs: z.number().int().positive(),
  connectedAt: isoInstantShape,
}).strict();

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
}).strict();

const unavailableReasonShape = z.enum([
  "timeout",
  "port_not_found",
  "port_in_use",
  "port_permission_denied",
  "handshake_failed",
  "unsupported_version",
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
}).strict();
export const scanDevicesSuccessOutputShape = z.object({
  source: z.literal("live"),
  devices: z.array(liveStatusShape),
  failures: z.array(scanDeviceFailureShape),
  activeDeviceId: safeDeviceIdShape.nullable(),
}).strict();
export const scanDevicesToolOutputShape = z.discriminatedUnion("source", [
  scanDevicesSuccessOutputShape,
  errorToolResultShape,
]);

export const identifyDevicesSuccessOutputShape = z.object({
  source: z.literal("live"),
  devices: z.array(z.discriminatedUnion("source", [identifiedDeviceShape, failedIdentificationShape])),
  activeDeviceId: safeDeviceIdShape.nullable(),
}).strict();
export const identifyDevicesToolOutputShape = z.discriminatedUnion("source", [
  identifyDevicesSuccessOutputShape,
  errorToolResultShape,
]);

export const selectDeviceSuccessOutputShape = z.object({
  source: z.literal("selected"),
  activeDeviceId: safeDeviceIdShape,
  purpose: safePurposeShape.nullable(),
  device: deviceShape,
}).strict();
export const selectDeviceToolOutputShape = z.discriminatedUnion("source", [
  selectDeviceSuccessOutputShape,
  errorToolResultShape,
]);

export const listDevicesSuccessOutputShape = z.object({
  source: z.literal("list"),
  devices: z.array(deviceListEntryShape),
  activeDeviceId: safeDeviceIdShape.nullable(),
  activeDeviceIdsByPurpose: z.record(safePurposeShape, safeDeviceIdShape),
}).strict();
export const listDevicesToolOutputShape = z.discriminatedUnion("source", [
  listDevicesSuccessOutputShape,
  errorToolResultShape,
]);

export const setDeviceMetadataSuccessOutputShape = z.object({
  source: z.literal("metadata"),
  deviceId: safeDeviceIdShape,
  label: safeLabelShape.nullable(),
}).strict();
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
}).strict();
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
  .strict()
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

const nativeCapabilityAccountShape = z.object({
  keyScheme: z.literal("ed25519"),
  derivationPath: z.literal(SUI_DERIVATION_PATH),
}).strict();
const zkLoginCapabilityAccountShape = z.object({
  keyScheme: z.literal("zklogin"),
}).strict();
const capabilityAccountShape = z.discriminatedUnion("keyScheme", [
  nativeCapabilityAccountShape,
  zkLoginCapabilityAccountShape,
]);
const capabilityChainShape = z.object({
  id: z.literal("sui"),
  accounts: z.array(capabilityAccountShape).length(MAX_CAPABILITY_ACCOUNTS_PER_CHAIN),
  methods: z.array(z.never()).length(0),
}).strict();
const signingCapabilityEntryShape = z.object({
  chain: z.literal("sui"),
  method: z.enum([SUI_SIGN_TRANSACTION_METHOD, SUI_SIGN_PERSONAL_MESSAGE_METHOD]),
}).strict();
const signingCapabilitiesShape = z
  .object({
    authorization: z.enum(["user", "policy"]),
    methods: z.array(signingCapabilityEntryShape).min(1).max(2),
  })
  .strict()
  .refine((value) => {
    const methods = new Set(value.methods.map((entry) => entry.method));
    if (methods.size !== value.methods.length) {
      return false;
    }
    if (value.authorization === "policy") {
      return methods.size === 1 && methods.has(SUI_SIGN_TRANSACTION_METHOD);
    }
    return (
      methods.size === 2 &&
      methods.has(SUI_SIGN_TRANSACTION_METHOD) &&
      methods.has(SUI_SIGN_PERSONAL_MESSAGE_METHOD)
    );
  }, { message: "signing methods must match authorization mode" });
const credentialCapabilityShape = z.object({
  chain: z.literal(SUI_CHAIN_ID),
  credential: z.literal(SUI_ZKLOGIN_CREDENTIAL),
  operations: z.tuple([
    z.literal(CREDENTIAL_PREPARE_OPERATION),
    z.literal(CREDENTIAL_PROPOSE_OPERATION),
  ]),
}).strict();
const credentialCapabilitiesShape = z.array(credentialCapabilityShape).length(MAX_CREDENTIAL_CAPABILITIES);
const liveCapabilitiesOutputShape = z.object({
  source: z.literal("live"),
  deviceId: safeDeviceIdShape,
  capabilities: z.array(capabilityChainShape).length(MAX_CAPABILITY_CHAINS),
  signing: signingCapabilitiesShape.optional(),
  credentials: credentialCapabilitiesShape.optional(),
}).strict();
const liveProviderCapabilitiesOutputShape = z.object({
  source: z.literal("live"),
  deviceId: safeDeviceIdShape,
  capabilities: z.array(capabilityChainShape).length(MAX_CAPABILITY_CHAINS),
  signing: signingCapabilitiesShape.optional(),
  credentials: credentialCapabilitiesShape.optional(),
}).strict();
const liveMcpCapabilitiesOutputShape = z.object({
  source: z.literal("live"),
  deviceId: safeDeviceIdShape,
  capabilities: z.array(capabilityChainShape).length(MAX_CAPABILITY_CHAINS),
  signing: signingCapabilitiesShape.optional(),
  credentials: credentialCapabilitiesShape.optional(),
}).strict();
const notConnectedCapabilitiesOutputShape = z.object({
  source: z.literal("not_connected"),
  deviceId: safeDeviceIdShape,
  reason: z.literal("not_connected"),
}).strict();
const sessionEndedCapabilitiesOutputShape = z.object({
  source: z.literal("session_ended"),
  deviceId: safeDeviceIdShape,
  reason: z.enum(GET_CAPABILITIES_SESSION_ENDED_REASONS),
}).strict();
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

const accountSponsoredTransactionsShape = z.object({
  acceptGasSponsor: z.boolean(),
}).strict();
const nativeAccountShape = z.object({
  chain: z.literal("sui"),
  address: z.string().regex(SUI_ADDRESS_PATTERN),
  publicKey: z.string(),
  keyScheme: z.literal("ed25519"),
  derivationPath: z.literal(SUI_DERIVATION_PATH),
  sponsoredTransactions: accountSponsoredTransactionsShape,
}).strict().refine((account) => isSuiAddressForSchemePrefixedPublicKey(
  account.address,
  account.publicKey,
  SUI_SIGNATURE_SCHEME_FLAG_ED25519,
  SUI_SCHEME_PREFIXED_ED25519_PUBLIC_KEY_BYTES,
  SUI_SCHEME_PREFIXED_ED25519_PUBLIC_KEY_BYTES,
), {
  message: "Sui address must match publicKey",
});
const zkLoginAccountShape = z.object({
  chain: z.literal("sui"),
  address: z.string().regex(SUI_ADDRESS_PATTERN),
  publicKey: z.string(),
  keyScheme: z.literal("zklogin"),
  sponsoredTransactions: accountSponsoredTransactionsShape,
}).strict().refine((account) => isSuiAddressForSchemePrefixedPublicKey(
  account.address,
  account.publicKey,
  SUI_SIGNATURE_SCHEME_FLAG_ZKLOGIN,
  MIN_SUI_ZKLOGIN_PUBLIC_KEY_BYTES,
  MAX_SUI_ZKLOGIN_PUBLIC_KEY_BYTES,
), {
  message: "Sui address must match publicKey",
});
const accountShape = z.discriminatedUnion("keyScheme", [
  nativeAccountShape,
  zkLoginAccountShape,
]);
const liveAccountsOutputShape = z.object({
  source: z.literal("live"),
  deviceId: safeDeviceIdShape,
  accounts: z.array(accountShape).length(MAX_ACCOUNTS_PER_RESPONSE),
}).strict();
const notConnectedAccountsOutputShape = z.object({
  source: z.literal("not_connected"),
  deviceId: safeDeviceIdShape,
  reason: z.literal("not_connected"),
}).strict();
const sessionEndedAccountsOutputShape = z.object({
  source: z.literal("session_ended"),
  deviceId: safeDeviceIdShape,
  reason: z.enum(GET_ACCOUNTS_SESSION_ENDED_REASONS),
}).strict();
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

const policyDocumentShape = z.custom((value) => {
  try {
    return sanitizeCurrentPolicyDocument(value) !== null;
  } catch {
    return false;
  }
}, {
  message: "policy must match the current active policy document schema",
});
const livePolicyOutputShape = z.object({
  source: z.literal("live"),
  deviceId: safeDeviceIdShape,
  policy: policyDocumentShape,
}).strict();
const notConnectedPolicyOutputShape = z.object({
  source: z.literal("not_connected"),
  deviceId: safeDeviceIdShape,
  reason: z.literal("not_connected"),
}).strict();
const sessionEndedPolicyOutputShape = z.object({
  source: z.literal("session_ended"),
  deviceId: safeDeviceIdShape,
  reason: z.enum(POLICY_GET_SESSION_ENDED_REASONS),
}).strict();
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
}).strict();
const policyUpdateApprovalHistoryRecordShape = approvalHistoryRecordShape.extend({
  eventKind: z.literal("policy_update"),
  result: z.enum(APPROVAL_HISTORY_POLICY_UPDATE_RESULTS),
  policyHash: z.string().regex(POLICY_ID_PATTERN),
  policyCount: z.number().int().min(0).max(MAX_POLICY_TOTAL_POLICIES),
  highestAction: z.enum(APPROVAL_HISTORY_HIGHEST_ACTIONS),
}).strict();
const signingUserConfirmationApprovalHistoryRecordShape = approvalHistoryRecordShape.extend({
  eventKind: z.literal("signing"),
  recordKind: z.literal("confirmation"),
  authorization: z.literal("user"),
  confirmationKind: z.enum(["local_pin", "physical_confirm"]),
  chain: z.string().regex(SIGN_CHAIN_PATTERN),
  method: z.string().regex(SIGN_METHOD_PATTERN),
  payloadDigest: z.string().regex(POLICY_ID_PATTERN),
}).strict();
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
}).strict();
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
}).strict().refine((value) => {
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
}).strict();
const notConnectedApprovalHistoryOutputShape = z.object({
  source: z.literal("not_connected"),
  deviceId: safeDeviceIdShape,
  reason: z.literal("not_connected"),
}).strict();
const sessionEndedApprovalHistoryOutputShape = z.object({
  source: z.literal("session_ended"),
  deviceId: safeDeviceIdShape,
  reason: z.enum(GET_APPROVAL_HISTORY_SESSION_ENDED_REASONS),
}).strict();
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
  code: z.enum(Object.keys(SIGNING_OUTCOME_ERROR_MESSAGES) as [keyof typeof SIGNING_OUTCOME_ERROR_MESSAGES, ...Array<keyof typeof SIGNING_OUTCOME_ERROR_MESSAGES>]),
  message: z.enum(Object.values(SIGNING_OUTCOME_ERROR_MESSAGES) as [string, ...string[]]),
}).strict().refine((error) => error.message === SIGNING_OUTCOME_ERROR_MESSAGES[error.code], {
  message: "Signing outcome error message must match its code.",
});
const canonicalBase64Shape = z
  .string()
  .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/);
const personalMessageBytesShape = canonicalBase64Shape
  .min(1)
  .max(MAX_SIGNING_OUTCOME_PAYLOAD_BASE64_CHARS)
  .refine((value) => {
    const decoded = Buffer.from(value, "base64");
    return (
      decoded.length > 0 &&
      decoded.toString("base64") === value
    );
  }, {
    message: "messageBytes must be canonical base64",
  });
const liveUserSignSignedOutputShape = z.object({
  source: z.literal("live"),
  deviceId: safeDeviceIdShape,
  status: z.literal("signed"),
  authorization: z.literal("user"),
  chain: z.literal("sui"),
  method: z.literal(SUI_SIGN_TRANSACTION_METHOD),
  signature: z.string().refine(isSuiTransactionSignatureEnvelopeBase64),
}).strict();
const livePolicySignSignedOutputShape = liveUserSignSignedOutputShape.extend({
  authorization: z.literal("policy"),
}).strict();
const liveUserSignPersonalMessageSignedOutputShape = z.object({
  source: z.literal("live"),
  deviceId: safeDeviceIdShape,
  status: z.literal("signed"),
  authorization: z.literal("user"),
  chain: z.literal("sui"),
  method: z.literal(SUI_SIGN_PERSONAL_MESSAGE_METHOD),
  signature: z.string().refine(isSuiPersonalMessageSignatureBase64),
  messageBytes: personalMessageBytesShape,
}).strict();
const liveUserSignTerminalOutputShape = z.discriminatedUnion("status", [
  z.object({
    source: z.literal("live"),
    deviceId: safeDeviceIdShape,
    status: z.literal("user_rejected"),
    authorization: z.literal("user"),
    error: signResultErrorShape.refine((error) => error.code === "user_rejected", {
      message: "User-rejected signing outcome error code must be user_rejected.",
    }),
  }).strict(),
  z.object({
    source: z.literal("live"),
    deviceId: safeDeviceIdShape,
    status: z.literal("user_timed_out"),
    authorization: z.literal("user"),
    error: signResultErrorShape.refine((error) => error.code === "user_timed_out", {
      message: "Timed-out signing outcome error code must be user_timed_out.",
    }),
  }).strict(),
  z.object({
    source: z.literal("live"),
    deviceId: safeDeviceIdShape,
    status: z.literal("signing_failed"),
    authorization: z.literal("user"),
    error: signResultErrorShape.refine((error) => error.code === "signing_failed", {
      message: "Failed signing outcome error code must be signing_failed.",
    }),
  }).strict(),
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
      message: "Policy-rejected signing outcome error code must be policy_rejected.",
    }),
  }).strict(),
  z.object({
    source: z.literal("live"),
    deviceId: safeDeviceIdShape,
    status: z.literal("signing_failed"),
    authorization: z.literal("policy"),
    error: signResultErrorShape.refine((error) => error.code === "signing_failed", {
      message: "Failed signing outcome error code must be signing_failed.",
    }),
  }).strict(),
]);
const notConnectedSignOutputShape = z.object({
  source: z.literal("not_connected"),
  deviceId: safeDeviceIdShape,
  reason: z.literal("not_connected"),
}).strict();
const sessionEndedSignTransactionOutputShape = z.object({
  source: z.literal("session_ended"),
  deviceId: safeDeviceIdShape,
  reason: z.enum(SIGN_TRANSACTION_SESSION_ENDED_REASONS),
}).strict();
const sessionEndedSignPersonalMessageOutputShape = z.object({
  source: z.literal("session_ended"),
  deviceId: safeDeviceIdShape,
  reason: z.enum(SIGN_PERSONAL_MESSAGE_SESSION_ENDED_REASONS),
}).strict();
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
export const signPersonalMessageSuccessOutputShape = z.union([
  liveUserSignPersonalMessageSignedOutputShape,
  liveUserSignTerminalOutputShape,
  notConnectedSignOutputShape,
  sessionEndedSignPersonalMessageOutputShape,
]);
export const signPersonalMessageToolOutputShape = z.union([
  liveUserSignPersonalMessageSignedOutputShape,
  liveUserSignTerminalOutputShape,
  notConnectedSignOutputShape,
  sessionEndedSignPersonalMessageOutputShape,
  errorToolResultShape,
]);

const policyProposeResultPolicyShape = z.object({
  policyHash: z.string().regex(POLICY_ID_PATTERN),
  blockchainCount: z.number().int().min(0).max(MAX_POLICY_BLOCKCHAINS),
  networkCount: z.number().int().min(0).max(MAX_POLICY_TOTAL_NETWORKS),
  policyCount: z.number().int().min(0).max(MAX_POLICY_TOTAL_POLICIES),
  conditionCount: z.number().int().min(0).max(MAX_POLICY_TOTAL_CONDITIONS),
  highestAction: z.enum(APPROVAL_HISTORY_HIGHEST_ACTIONS),
}).strict();
const livePolicyProposeOutputShape = z
  .object({
    source: z.literal("live"),
    deviceId: safeDeviceIdShape,
    status: z.enum(POLICY_PROPOSAL_OUTCOME_STATUSES),
    reasonCode: z.string().regex(APPROVAL_HISTORY_REASON_CODE_PATTERN),
    policy: policyProposeResultPolicyShape.optional(),
  })
  .strict()
  .refine((value) => (value.status === "invalid_policy") === (value.policy === undefined), {
    message: "invalid_policy omits policy metadata; other policy proposal outcome statuses include it",
  });
const notConnectedPolicyProposeOutputShape = z.object({
  source: z.literal("not_connected"),
  deviceId: safeDeviceIdShape,
  reason: z.literal("not_connected"),
}).strict();
const sessionEndedPolicyProposeOutputShape = z.object({
  source: z.literal("session_ended"),
  deviceId: safeDeviceIdShape,
  reason: z.enum(POLICY_PROPOSE_SESSION_ENDED_REASONS),
}).strict();
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

const credentialPreparationShape = z.object({
  address: z.string().regex(SUI_ADDRESS_PATTERN),
  publicKey: z.string(),
  keyScheme: z.literal("ed25519"),
}).strict().refine((preparation) => isSuiAddressForSchemePrefixedPublicKey(
  preparation.address,
  preparation.publicKey,
  SUI_SIGNATURE_SCHEME_FLAG_ED25519,
  SUI_SCHEME_PREFIXED_ED25519_PUBLIC_KEY_BYTES,
  SUI_SCHEME_PREFIXED_ED25519_PUBLIC_KEY_BYTES,
), {
  message: "Sui preparation address must match publicKey",
});
const liveCredentialPrepareOutputShape = z.object({
  source: z.literal("live"),
  deviceId: safeDeviceIdShape,
  chain: z.literal(SUI_CHAIN_ID),
  credential: z.literal(SUI_ZKLOGIN_CREDENTIAL),
  preparation: credentialPreparationShape,
}).strict();
const liveCredentialProposeOutputShape = z.object({
  source: z.literal("live"),
  deviceId: safeDeviceIdShape,
  status: z.enum(CREDENTIAL_PROPOSAL_OUTCOME_STATUSES),
  reasonCode: z.string().regex(APPROVAL_HISTORY_REASON_CODE_PATTERN),
  sessionEnded: z.boolean(),
}).strict();
const notConnectedCredentialOutputShape = z.object({
  source: z.literal("not_connected"),
  deviceId: safeDeviceIdShape,
  reason: z.literal("not_connected"),
}).strict();
const sessionEndedCredentialOutputShape = z.object({
  source: z.literal("session_ended"),
  deviceId: safeDeviceIdShape,
  reason: z.enum(GET_ACCOUNTS_SESSION_ENDED_REASONS),
}).strict();
export const credentialPrepareSuccessOutputShape = z.discriminatedUnion("source", [
  liveCredentialPrepareOutputShape,
  notConnectedCredentialOutputShape,
  sessionEndedCredentialOutputShape,
]);
export const credentialPrepareToolOutputShape = z.discriminatedUnion("source", [
  liveCredentialPrepareOutputShape,
  notConnectedCredentialOutputShape,
  sessionEndedCredentialOutputShape,
  errorToolResultShape,
]);
export const credentialProposeSuccessOutputShape = z.discriminatedUnion("source", [
  liveCredentialProposeOutputShape,
  notConnectedCredentialOutputShape,
  sessionEndedCredentialOutputShape,
]);
export const credentialProposeToolOutputShape = z.discriminatedUnion("source", [
  liveCredentialProposeOutputShape,
  notConnectedCredentialOutputShape,
  sessionEndedCredentialOutputShape,
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
}).strict();
export const getDeviceStatusSuccessOutputShape = z.discriminatedUnion("source", [
  liveStatusShape,
  cachedDeviceStatusOutputShape,
]);
export const getDeviceStatusToolOutputShape = z.discriminatedUnion("source", [
  liveStatusShape,
  cachedDeviceStatusOutputShape,
  errorToolResultShape,
]);

export const hostSuccessOutputSchemas = {
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
  signPersonalMessage: signPersonalMessageSuccessOutputShape,
  policyPropose: policyProposeSuccessOutputShape,
  credentialPrepare: credentialPrepareSuccessOutputShape,
  credentialPropose: credentialProposeSuccessOutputShape,
} as const;
