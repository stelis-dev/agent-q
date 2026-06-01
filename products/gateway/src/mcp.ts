import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as z from "zod/v4";
import { ConfigStore } from "./config.js";
import {
  CALL_METHOD_SESSION_ENDED_REASONS,
  DISCONNECT_ENDED_REASONS,
  DISCONNECT_REASONS,
  GET_ACCOUNTS_SESSION_ENDED_REASONS,
  GET_APPROVAL_HISTORY_SESSION_ENDED_REASONS,
  GET_CAPABILITIES_SESSION_ENDED_REASONS,
  GET_POLICY_SESSION_ENDED_REASONS,
  GatewayCore,
  MAX_IDENTIFY_DURATION_MS,
  type ConnectDeviceResult,
  type CallMethodResult,
  type DeviceListResult,
  type DeviceStatusToolResult,
  type DisconnectDeviceResult,
  type GetAccountsResult,
  type GetApprovalHistoryResult,
  type GetCapabilitiesResult,
  type GetPolicyResult,
  type SetDeviceMetadataResult,
} from "./core.js";
import { GatewayError, toGatewayError } from "./errors.js";
import { PUBLIC_ERROR_MESSAGES, normalizeErrorCode, toPublicError } from "./public-error.js";
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
  MAX_APPROVAL_TIMEOUT_MS,
  MAX_POLICY_RULE_COUNT,
  METHOD_RESULT_ERROR_MESSAGES,
  POLICY_ID_PATTERN,
  SUI_ADDRESS_PATTERN,
  SUI_DERIVATION_PATH,
  UINT_DECIMAL_STRING_PATTERN,
  isUint64DecimalString,
  isSuiAddressForPublicKey,
} from "./protocol.js";
import { SerialPortUsbDriver, MAX_SCAN_TIMEOUT_MS } from "./usb.js";
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
// and the message must be that code's canonical string. This keeps the EXPORTED
// tool schema in lockstep with the runtime — the declared contract can no longer
// say a raw `message: "session_LEAK..."` is valid tool output.
const publicErrorShape = z
  .object({
    code: z.string(),
    message: z.string(),
    retryable: z.boolean(),
  })
  .refine((value) => PUBLIC_ERROR_MESSAGES[value.code] === value.message, {
    message: "error must be a canonical public error (allowlisted code with its matching message)",
  });

// Shared, SoT-derived field shapes. Every untrusted string field in every MCP
// output schema composes from these, so the egress boundary enforces exactly the
// same policy as the wire (protocol.ts) and disk (config.ts) boundaries. Format
// constraints use regex/max so they also surface in the published JSON Schema;
// only semantics JSON Schema cannot express (reserved/prototype-sensitive purpose
// names, real-calendar dates) are layered on with refine.
const safeDeviceIdShape = z.string().regex(DEVICE_ID_PATTERN);
const requestIdShape = z.string().regex(REQUEST_ID_PATTERN);
const identificationCodeShape = z.string().regex(IDENTIFICATION_CODE_PATTERN);
const displayTextShape = (maxLength: number) => z.string().regex(PRINTABLE_ASCII_ONLY).max(maxLength);
const portHintShape = displayTextShape(MAX_PORT_HINT_LENGTH);
const isoInstantShape = z
  .string()
  .regex(ISO_TIMESTAMP_PATTERN)
  .refine((value) => Number.isFinite(Date.parse(value)));
const safePurposeShape = z.string().regex(PURPOSE_PATTERN).refine((value) => isValidPurpose(value));
const safeLabelShape = z.string().min(1).max(MAX_LABEL_LENGTH).refine((value) => isValidLabel(value));

// The device shape is part of the egress tripwire: deviceId, state, and the
// bounded printable-ASCII display strings must already satisfy the safe-text
// policy by the time a result reaches here (the wire and disk boundaries
// sanitize them). If anything ever slips through, run() fails the result closed
// as internal_output_error rather than leaking it.
const deviceShape = z.object({
  deviceId: safeDeviceIdShape,
  state: z.enum(DEVICE_STATES),
  firmwareName: displayTextShape(MAX_FIRMWARE_NAME_LENGTH),
  hardware: displayTextShape(MAX_HARDWARE_ID_LENGTH),
  firmwareVersion: displayTextShape(MAX_FIRMWARE_VERSION_LENGTH),
});
const provisioningShape = z.object({
  state: z.enum(PROVISIONING_STATES),
});
const deviceStatusSnapshotShape = z.object({
  device: deviceShape,
  provisioning: provisioningShape,
});

const statusResponseShape = z.object({
  id: requestIdShape,
  version: z.literal(1),
  type: z.literal("status"),
  device: deviceShape,
  provisioning: provisioningShape,
});

const identifyResponseShape = z.object({
  id: requestIdShape,
  version: z.literal(1),
  type: z.literal("identify_device_result"),
  status: z.literal("displayed"),
  code: identificationCodeShape,
  device: deviceShape,
});

const liveStatusShape = z.object({
  source: z.literal("live"),
  connected: z.literal(true),
  portPath: portHintShape,
  protocolResponse: statusResponseShape,
});

const identifiedDeviceShape = z.object({
  source: z.literal("live"),
  connected: z.literal(true),
  portPath: portHintShape,
  status: z.literal("displayed"),
  code: identificationCodeShape,
  protocolResponse: identifyResponseShape,
});

const failedIdentificationShape = z.object({
  source: z.literal("error"),
  connected: z.literal(false),
  portPath: portHintShape,
  deviceId: safeDeviceIdShape,
  status: z.literal("error"),
  error: publicErrorShape,
});

const errorToolResultShape = z.object({
  source: z.literal("error"),
  connected: z.literal(false),
  error: publicErrorShape,
});

// sessionId is a Firmware-issued token held only inside Gateway. It is never
// exposed to MCP clients, which are untrusted request sources.
const runtimeSessionShape = z.object({
  sessionTtlMs: z.number().int().positive(),
  connectedAt: isoInstantShape,
  expiresAt: isoInstantShape,
});

const deviceListEntryShape = z.object({
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

// Two schemas per tool, kept deliberately separate:
//  - `*SuccessOutputShape`: a single object schema for the success result. This
//    is what we register with the MCP SDK as `outputSchema`. The SDK only
//    models object/raw-shape output schemas, and it skips output validation for
//    error results (`isError: true`), so errors do not belong in this schema.
//  - `*ToolOutputShape`: the success | error discriminated union, used only by
//    Gateway-side tests to validate the full result contract.
const scanDevicesSuccessOutputShape = z.object({
  source: z.literal("live"),
  devices: z.array(liveStatusShape),
  activeDeviceId: safeDeviceIdShape.nullable(),
});
const scanDevicesToolOutputShape = z.discriminatedUnion("source", [
  scanDevicesSuccessOutputShape,
  errorToolResultShape,
]);

const identifyDevicesSuccessOutputShape = z.object({
  source: z.literal("live"),
  devices: z.array(z.discriminatedUnion("source", [identifiedDeviceShape, failedIdentificationShape])),
  activeDeviceId: safeDeviceIdShape.nullable(),
});
const identifyDevicesToolOutputShape = z.discriminatedUnion("source", [
  identifyDevicesSuccessOutputShape,
  errorToolResultShape,
]);

const selectDeviceSuccessOutputShape = z.object({
  source: z.literal("selected"),
  activeDeviceId: safeDeviceIdShape,
  purpose: safePurposeShape.nullable(),
  device: deviceShape,
});
const selectDeviceToolOutputShape = z.discriminatedUnion("source", [
  selectDeviceSuccessOutputShape,
  errorToolResultShape,
]);

const listDevicesSuccessOutputShape = z.object({
  source: z.literal("list"),
  devices: z.array(deviceListEntryShape),
  activeDeviceId: safeDeviceIdShape.nullable(),
  activeDeviceIdsByPurpose: z.record(safePurposeShape, safeDeviceIdShape),
});
const listDevicesToolOutputShape = z.discriminatedUnion("source", [
  listDevicesSuccessOutputShape,
  errorToolResultShape,
]);

const setDeviceMetadataSuccessOutputShape = z.object({
  source: z.literal("metadata"),
  deviceId: safeDeviceIdShape,
  label: safeLabelShape.nullable(),
});
const setDeviceMetadataToolOutputShape = z.discriminatedUnion("source", [
  setDeviceMetadataSuccessOutputShape,
  errorToolResultShape,
]);

const connectDeviceSuccessOutputShape = z.object({
  source: z.literal("connected"),
  deviceId: safeDeviceIdShape,
  sessionTtlMs: z.number().int().positive(),
  connectedAt: isoInstantShape,
  expiresAt: isoInstantShape,
  device: deviceShape,
});
const connectDeviceToolOutputShape = z.discriminatedUnion("source", [
  connectDeviceSuccessOutputShape,
  errorToolResultShape,
]);

const disconnectDeviceSuccessOutputShape = z
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
const disconnectDeviceToolOutputShape = z.discriminatedUnion("source", [
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
const liveCapabilitiesOutputShape = z.object({
  source: z.literal("live"),
  deviceId: safeDeviceIdShape,
  capabilities: z.array(capabilityChainShape).length(MAX_CAPABILITY_CHAINS),
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
const getCapabilitiesSuccessOutputShape = z.discriminatedUnion("source", [
  liveCapabilitiesOutputShape,
  notConnectedCapabilitiesOutputShape,
  sessionEndedCapabilitiesOutputShape,
]);
const getCapabilitiesToolOutputShape = z.discriminatedUnion("source", [
  liveCapabilitiesOutputShape,
  notConnectedCapabilitiesOutputShape,
  sessionEndedCapabilitiesOutputShape,
  errorToolResultShape,
]);

// Public account identity only. sessionId and any private/signing material are
// never part of this shape, so they cannot reach an MCP client.
const accountShape = z.object({
  chain: z.literal("sui"),
  address: z.string().regex(SUI_ADDRESS_PATTERN),
  publicKey: z.string().regex(ED25519_PUBLIC_KEY_BASE64_PATTERN),
  keyScheme: z.literal("ed25519"),
  derivationPath: z.literal(SUI_DERIVATION_PATH),
}).refine((account) => isSuiAddressForPublicKey(account.address, account.publicKey), {
  message: "Sui address must match publicKey",
});
// State-specific shapes so the run() egress guard cannot pass an unreachable
// result: `live` must carry accounts (and no reason); `not_connected` /
// `session_ended` must carry only a reason (no accounts). Like get_device_status,
// the success is a discriminated union, so this tool is registered without an SDK
// outputSchema and sanitized at the run() boundary instead.
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
const getAccountsSuccessOutputShape = z.discriminatedUnion("source", [
  liveAccountsOutputShape,
  notConnectedAccountsOutputShape,
  sessionEndedAccountsOutputShape,
]);
const getAccountsToolOutputShape = z.discriminatedUnion("source", [
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
const getPolicySuccessOutputShape = z.discriminatedUnion("source", [
  livePolicyOutputShape,
  notConnectedPolicyOutputShape,
  sessionEndedPolicyOutputShape,
]);
const getPolicyToolOutputShape = z.discriminatedUnion("source", [
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
const approvalHistoryRecordOutputShape = z.discriminatedUnion("eventKind", [
  methodDecisionApprovalHistoryRecordShape,
  policyUpdateApprovalHistoryRecordShape,
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
const getApprovalHistorySuccessOutputShape = z.discriminatedUnion("source", [
  liveApprovalHistoryOutputShape,
  notConnectedApprovalHistoryOutputShape,
  sessionEndedApprovalHistoryOutputShape,
]);
const getApprovalHistoryToolOutputShape = z.discriminatedUnion("source", [
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
const liveCallMethodOutputShape = z.object({
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
const callMethodSuccessOutputShape = z.discriminatedUnion("source", [
  liveCallMethodOutputShape,
  notConnectedCallMethodOutputShape,
  sessionEndedCallMethodOutputShape,
]);
const callMethodToolOutputShape = z.discriminatedUnion("source", [
  liveCallMethodOutputShape,
  notConnectedCallMethodOutputShape,
  sessionEndedCallMethodOutputShape,
  errorToolResultShape,
]);

// get_device_status success is itself a live | cached union, which the SDK
// output-schema model cannot represent, so this tool is the one registered
// without an SDK outputSchema. The success union is still used at the run()
// boundary to sanitize output; the error variant must NOT be part of the
// success sanitizer (an error-shaped result must surface as isError, never as a
// sanitized success). The full tool union is used only by Gateway-side tests.
const cachedDeviceStatusOutputShape = z.object({
  source: z.literal("cached"),
  connected: z.literal(false),
  statusObservedAt: isoInstantShape,
  unavailableReason: z.enum([
    "timeout",
    "port_not_found",
    "port_in_use",
    "handshake_failed",
    "incompatible_version",
    "transport_closed",
  ]),
  // Constrained to an allowlisted public code; sanitizeGetDeviceStatusResult
  // normalizes any unknown/raw code to gateway_error before this schema runs.
  firmwareErrorCode: z
    .string()
    .refine((code) => Object.prototype.hasOwnProperty.call(PUBLIC_ERROR_MESSAGES, code))
    .optional(),
  cachedStatus: deviceStatusSnapshotShape,
});
const getDeviceStatusSuccessOutputShape = z.discriminatedUnion("source", [
  liveStatusShape,
  cachedDeviceStatusOutputShape,
]);
const getDeviceStatusToolOutputShape = z.discriminatedUnion("source", [
  liveStatusShape,
  cachedDeviceStatusOutputShape,
  errorToolResultShape,
]);

// Input purpose uses the same SoT predicate as egress, so reserved ("default")
// and prototype-sensitive ("__proto__"/"prototype"/"constructor") names are
// rejected at the request boundary as well as in storage and output.
const purposeSchema = z.string().regex(PURPOSE_PATTERN).refine((value) => isValidPurpose(value), {
  message: "purpose must be 1-32 characters of [A-Za-z0-9_.-] and not a reserved or prototype-sensitive name.",
});

// Shared discovery timeout. It is a TOTAL wall-clock budget for USB discovery
// (port enumeration + status handshakes), documented so callers don't read it as
// a per-port limit or as the device approval wait (connect_device's approval
// uses approvalTimeoutMs separately).
const scanTimeoutSchema = z
  .number()
  .int()
  .positive()
  .max(MAX_SCAN_TIMEOUT_MS)
  .describe(
    "Total wall-clock budget in ms for USB discovery (port enumeration and status handshakes). Not the device approval wait.",
  )
  .optional();

export const gatewayToolDefinitions = {
  scanDevices: {
    name: "scan_devices",
    title: "Scan devices",
    description:
      "Find USB-connected Agent-Q Firmware devices by writing a status handshake to candidate USB serial ports.",
    inputSchema: {
      timeoutMs: scanTimeoutSchema,
    },
    outputSchema: scanDevicesToolOutputShape,
    successOutputSchema: scanDevicesSuccessOutputShape,
  },
  identifyDevices: {
    name: "identify_devices",
    title: "Identify devices",
    description:
      "Ask discovered Agent-Q Firmware devices to display short identification codes. Writes a status handshake to candidate USB serial ports before sending the identify request.",
    inputSchema: {
      timeoutMs: scanTimeoutSchema,
      durationMs: z.number().int().positive().max(MAX_IDENTIFY_DURATION_MS).optional(),
    },
    outputSchema: identifyDevicesToolOutputShape,
    successOutputSchema: identifyDevicesSuccessOutputShape,
  },
  selectDevice: {
    name: "select_device",
    title: "Select device",
    description:
      "Set a previously discovered Agent-Q Firmware device as the default active device, or as the active device for a named routing purpose. 'purpose' is local Gateway routing metadata, not security policy. Updates local Gateway state only; does not contact Firmware.",
    inputSchema: {
      deviceId: z.string().regex(DEVICE_ID_PATTERN),
      purpose: purposeSchema.optional(),
    },
    outputSchema: selectDeviceToolOutputShape,
    successOutputSchema: selectDeviceSuccessOutputShape,
  },
  getDeviceStatus: {
    name: "get_device_status",
    title: "Get device status",
    description:
      "Read live or cached status for a known Agent-Q Firmware device by writing a status handshake to candidate USB serial ports. Resolves the device by deviceId, by purpose, or by the default active device.",
    inputSchema: {
      deviceId: z.string().regex(DEVICE_ID_PATTERN).optional(),
      purpose: purposeSchema.optional(),
      timeoutMs: scanTimeoutSchema,
    },
    // outputSchema (full union) is for Gateway-side tests only; it is not
    // registered with the SDK. successOutputSchema (live | cached) is the
    // runtime sanitize boundary used by run().
    outputSchema: getDeviceStatusToolOutputShape,
    successOutputSchema: getDeviceStatusSuccessOutputShape,
  },
  listDevices: {
    name: "list_devices",
    title: "List devices",
    description:
      "List Agent-Q Firmware devices known to Gateway, including Gateway-local label, purpose routing assignments, and any in-memory connection session metadata. Reads from local Gateway state only; does not contact Firmware.",
    inputSchema: {},
    outputSchema: listDevicesToolOutputShape,
    successOutputSchema: listDevicesSuccessOutputShape,
  },
  setDeviceMetadata: {
    name: "set_device_metadata",
    title: "Set device metadata",
    description:
      "Set Gateway-local metadata for a known Agent-Q Firmware device. 'label' is human-readable Gateway-local metadata, not a security boundary and not device authority. Pass null to clear the label. Updates local Gateway state only; does not contact Firmware.",
    inputSchema: {
      deviceId: z.string().regex(DEVICE_ID_PATTERN),
      label: z.union([z.string().max(MAX_LABEL_LENGTH).refine((value) => isValidLabel(value)), z.null()]),
    },
    outputSchema: setDeviceMetadataToolOutputShape,
    successOutputSchema: setDeviceMetadataSuccessOutputShape,
  },
  connectDevice: {
    name: "connect_device",
    title: "Connect device",
    description:
      "Open a communication session with a known Agent-Q Firmware device. Resolves the target device by deviceId, by purpose, or by the default active device. Sends a connect request that requires Firmware-owned device-local approval. Writes a status handshake to candidate USB serial ports while locating the device. Connect is not signing approval and does not authorize signing. Session is held in Gateway memory only.",
    inputSchema: {
      deviceId: z.string().regex(DEVICE_ID_PATTERN).optional(),
      purpose: purposeSchema.optional(),
      gatewayName: z.string().regex(GATEWAY_NAME_PATTERN).optional(),
      approvalTimeoutMs: z.number().int().positive().max(MAX_APPROVAL_TIMEOUT_MS).optional(),
      timeoutMs: scanTimeoutSchema,
    },
    outputSchema: connectDeviceToolOutputShape,
    successOutputSchema: connectDeviceSuccessOutputShape,
  },
  disconnectDevice: {
    name: "disconnect_device",
    title: "Disconnect device",
    description:
      "End a previously approved Agent-Q Firmware session. Resolves the target device by deviceId, by purpose, or by the default active device. Returns 'not_connected' without contacting Firmware when there is no Gateway runtime session. Writes a status handshake to candidate USB serial ports when locating the device. Disconnect does not require physical approval.",
    inputSchema: {
      deviceId: z.string().regex(DEVICE_ID_PATTERN).optional(),
      purpose: purposeSchema.optional(),
      timeoutMs: scanTimeoutSchema,
    },
    outputSchema: disconnectDeviceToolOutputShape,
    successOutputSchema: disconnectDeviceSuccessOutputShape,
  },
  getCapabilities: {
    name: "get_capabilities",
    title: "Get capabilities",
    description:
      "Read Firmware-authored supported chains, public account schemes, and currently implemented methods over an approved session. Resolves the target device by deviceId, by purpose, or by the default active device. Requires a prior connect_device approval; returns 'not_connected' without contacting Firmware when there is no Gateway runtime session. Current StackChan CoreS3 capabilities report Sui Ed25519 account identity with no signing methods.",
    inputSchema: {
      deviceId: z.string().regex(DEVICE_ID_PATTERN).optional(),
      purpose: purposeSchema.optional(),
      timeoutMs: scanTimeoutSchema,
    },
    outputSchema: getCapabilitiesToolOutputShape,
    successOutputSchema: getCapabilitiesSuccessOutputShape,
  },
  getAccounts: {
    name: "get_accounts",
    title: "Get accounts",
    description:
      "List the public accounts (chain, address, public key) held by a provisioned Agent-Q Firmware device over an approved session. Resolves the target device by deviceId, by purpose, or by the default active device. Requires a prior connect_device approval; returns 'not_connected' without contacting Firmware when there is no Gateway runtime session. Read-only: no signing, no private material, and no session id is ever returned.",
    inputSchema: {
      deviceId: z.string().regex(DEVICE_ID_PATTERN).optional(),
      purpose: purposeSchema.optional(),
      timeoutMs: scanTimeoutSchema,
    },
    outputSchema: getAccountsToolOutputShape,
    successOutputSchema: getAccountsSuccessOutputShape,
  },
  getPolicy: {
    name: "get_policy",
    title: "Get policy",
    description:
      "Read the Firmware-owned active policy summary over an approved session. Resolves the target device by deviceId, by purpose, or by the default active device. Requires a prior connect_device approval; returns 'not_connected' without contacting Firmware when there is no Gateway runtime session. Read-only: no policy update, no signing, no private material, and no session id is ever returned.",
    inputSchema: {
      deviceId: z.string().regex(DEVICE_ID_PATTERN).optional(),
      purpose: purposeSchema.optional(),
      timeoutMs: scanTimeoutSchema,
    },
    outputSchema: getPolicyToolOutputShape,
    successOutputSchema: getPolicySuccessOutputShape,
  },
  getApprovalHistory: {
    name: "get_approval_history",
    title: "Get approval history",
    description:
      "Read a bounded page of Firmware-owned approval and method-decision history over an approved session. This is not on-chain history and is read-only: no raw requests, session ids, private material, PINs, gateway names, or full policy documents are returned.",
    inputSchema: {
      deviceId: z.string().regex(DEVICE_ID_PATTERN).optional(),
      purpose: purposeSchema.optional(),
      limit: z.number().int().positive().max(MAX_APPROVAL_HISTORY_RECORDS).optional(),
      beforeSeq: z.string().regex(UINT_DECIMAL_STRING_PATTERN).refine((value) => isUint64DecimalString(value)).optional(),
      timeoutMs: scanTimeoutSchema,
    },
    outputSchema: getApprovalHistoryToolOutputShape,
    successOutputSchema: getApprovalHistorySuccessOutputShape,
  },
  callMethod: {
    name: "call_method",
    title: "Call method",
    description:
      "Send a session-scoped method request through the shared Agent-Q protocol path. Resolves the target device by deviceId, by purpose, or by the default active device. Requires a prior connect_device approval; returns 'not_connected' without contacting Firmware when there is no Gateway runtime session. This is not signing support: current StackChan CoreS3 capabilities advertise no callable methods, unknown methods are rejected, and Sui sign_transaction is recognized only for rejected policy-decision smoke.",
    inputSchema: {
      deviceId: z.string().regex(DEVICE_ID_PATTERN).optional(),
      purpose: purposeSchema.optional(),
      chain: z.string().regex(CALL_METHOD_CHAIN_PATTERN),
      method: z.string().regex(CALL_METHOD_NAME_PATTERN),
      params: z.object({}).passthrough().optional(),
      timeoutMs: scanTimeoutSchema,
    },
    outputSchema: callMethodToolOutputShape,
    successOutputSchema: callMethodSuccessOutputShape,
  },
} as const;

export function createGatewayMcpServer(core = createDefaultGatewayCore()): McpServer {
  const server = new McpServer({
    name: "agent-q-gateway",
    version: "0.0.0",
  });

  // run() is the single MCP output boundary. It sanitizes every result so that
  // structuredContent and the text mirror only ever carry schema-approved
  // fields, and so that error output never echoes a raw (possibly
  // device/OS-originated) message back to the untrusted client.
  //
  //   work succeeds       -> successSchema.parse() strips unknown fields
  //   work throws         -> canonical public error keyed by error code
  //   sanitize fails      -> fixed internal_output_error (never the raw ZodError)
  const run = async (
    successSchema: { parse: (raw: unknown) => object },
    work: () => Promise<unknown>,
  ) => {
    let raw: unknown;
    try {
      raw = await work();
    } catch (error) {
      const gatewayError = toGatewayError(error);
      logToolDiagnostic("gateway_tool_error", gatewayError.code, gatewayError.retryable);
      return withStructuredContent(toPublicErrorToolResult(gatewayError), true);
    }

    let sanitized: object;
    try {
      sanitized = successSchema.parse(raw);
    } catch {
      // An unsanitizable success is an internal contract bug. Surface a fixed
      // generic error instead of the raw value or the ZodError details.
      logToolDiagnostic("gateway_output_sanitize_failed", "internal_output_error", false);
      return withStructuredContent(
        toPublicErrorToolResult(new GatewayError("internal_output_error", "", false)),
        true,
      );
    }
    return withStructuredContent(sanitized);
  };

  // For the tools below the registered SDK outputSchema is the success-only
  // object shape. Error results carry `isError: true`, for which the SDK skips
  // output validation, so the error variant is intentionally absent there.
  server.registerTool(
    gatewayToolDefinitions.scanDevices.name,
    {
      title: gatewayToolDefinitions.scanDevices.title,
      description: gatewayToolDefinitions.scanDevices.description,
      inputSchema: gatewayToolDefinitions.scanDevices.inputSchema,
      outputSchema: gatewayToolDefinitions.scanDevices.successOutputSchema,
    },
    async ({ timeoutMs }) =>
      run(gatewayToolDefinitions.scanDevices.successOutputSchema, () => core.scanDevices({ timeoutMs })),
  );

  server.registerTool(
    gatewayToolDefinitions.identifyDevices.name,
    {
      title: gatewayToolDefinitions.identifyDevices.title,
      description: gatewayToolDefinitions.identifyDevices.description,
      inputSchema: gatewayToolDefinitions.identifyDevices.inputSchema,
      outputSchema: gatewayToolDefinitions.identifyDevices.successOutputSchema,
    },
    async ({ timeoutMs, durationMs }) =>
      run({ parse: sanitizeIdentifyDevicesResult }, () => core.identifyDevices({ timeoutMs, durationMs })),
  );

  server.registerTool(
    gatewayToolDefinitions.selectDevice.name,
    {
      title: gatewayToolDefinitions.selectDevice.title,
      description: gatewayToolDefinitions.selectDevice.description,
      inputSchema: gatewayToolDefinitions.selectDevice.inputSchema,
      outputSchema: gatewayToolDefinitions.selectDevice.successOutputSchema,
    },
    async ({ deviceId, purpose }) =>
      run(gatewayToolDefinitions.selectDevice.successOutputSchema, () => core.selectDevice({ deviceId, purpose })),
  );

  // get_device_status is the one tool without a registered SDK outputSchema
  // (success is a live | cached union). It is still sanitized at run() using
  // its success-only union, so an error-shaped result cannot leak as a success.
  server.registerTool(
    gatewayToolDefinitions.getDeviceStatus.name,
    {
      title: gatewayToolDefinitions.getDeviceStatus.title,
      description: gatewayToolDefinitions.getDeviceStatus.description,
      inputSchema: gatewayToolDefinitions.getDeviceStatus.inputSchema,
    },
    async ({ deviceId, purpose, timeoutMs }) =>
      run({ parse: sanitizeGetDeviceStatusResult }, () =>
        core.getDeviceStatus({ deviceId, purpose, timeoutMs }),
      ),
  );

  server.registerTool(
    gatewayToolDefinitions.listDevices.name,
    {
      title: gatewayToolDefinitions.listDevices.title,
      description: gatewayToolDefinitions.listDevices.description,
      inputSchema: gatewayToolDefinitions.listDevices.inputSchema,
      outputSchema: gatewayToolDefinitions.listDevices.successOutputSchema,
    },
    async () => run(gatewayToolDefinitions.listDevices.successOutputSchema, () => core.listDevices()),
  );

  server.registerTool(
    gatewayToolDefinitions.setDeviceMetadata.name,
    {
      title: gatewayToolDefinitions.setDeviceMetadata.title,
      description: gatewayToolDefinitions.setDeviceMetadata.description,
      inputSchema: gatewayToolDefinitions.setDeviceMetadata.inputSchema,
      outputSchema: gatewayToolDefinitions.setDeviceMetadata.successOutputSchema,
    },
    async ({ deviceId, label }) =>
      run(gatewayToolDefinitions.setDeviceMetadata.successOutputSchema, () =>
        core.setDeviceMetadata({ deviceId, label }),
      ),
  );

  server.registerTool(
    gatewayToolDefinitions.connectDevice.name,
    {
      title: gatewayToolDefinitions.connectDevice.title,
      description: gatewayToolDefinitions.connectDevice.description,
      inputSchema: gatewayToolDefinitions.connectDevice.inputSchema,
      outputSchema: gatewayToolDefinitions.connectDevice.successOutputSchema,
    },
    async ({ deviceId, purpose, gatewayName, approvalTimeoutMs, timeoutMs }) =>
      run(gatewayToolDefinitions.connectDevice.successOutputSchema, () =>
        core.connectDevice({ deviceId, purpose, gatewayName, approvalTimeoutMs, timeoutMs }),
      ),
  );

  server.registerTool(
    gatewayToolDefinitions.disconnectDevice.name,
    {
      title: gatewayToolDefinitions.disconnectDevice.title,
      description: gatewayToolDefinitions.disconnectDevice.description,
      inputSchema: gatewayToolDefinitions.disconnectDevice.inputSchema,
      outputSchema: gatewayToolDefinitions.disconnectDevice.successOutputSchema,
    },
    async ({ deviceId, purpose, timeoutMs }) =>
      run(gatewayToolDefinitions.disconnectDevice.successOutputSchema, () =>
        core.disconnectDevice({ deviceId, purpose, timeoutMs }),
      ),
  );

  server.registerTool(
    gatewayToolDefinitions.getCapabilities.name,
    {
      title: gatewayToolDefinitions.getCapabilities.title,
      description: gatewayToolDefinitions.getCapabilities.description,
      inputSchema: gatewayToolDefinitions.getCapabilities.inputSchema,
      // Success is a discriminated union (live | not_connected | session_ended),
      // which the SDK outputSchema model cannot represent; it is sanitized at the
      // run() boundary below instead.
    },
    async ({ deviceId, purpose, timeoutMs }) =>
      run(gatewayToolDefinitions.getCapabilities.successOutputSchema, () =>
        core.getCapabilities({ deviceId, purpose, timeoutMs }),
      ),
  );

  server.registerTool(
    gatewayToolDefinitions.getAccounts.name,
    {
      title: gatewayToolDefinitions.getAccounts.title,
      description: gatewayToolDefinitions.getAccounts.description,
      inputSchema: gatewayToolDefinitions.getAccounts.inputSchema,
      // Success is a discriminated union (live | not_connected | session_ended),
      // which the SDK outputSchema model cannot represent; it is sanitized at the
      // run() boundary below instead.
    },
    async ({ deviceId, purpose, timeoutMs }) =>
      run(gatewayToolDefinitions.getAccounts.successOutputSchema, () =>
        core.getAccounts({ deviceId, purpose, timeoutMs }),
      ),
  );

  server.registerTool(
    gatewayToolDefinitions.getPolicy.name,
    {
      title: gatewayToolDefinitions.getPolicy.title,
      description: gatewayToolDefinitions.getPolicy.description,
      inputSchema: gatewayToolDefinitions.getPolicy.inputSchema,
      // Success is a discriminated union (live | not_connected | session_ended),
      // which the SDK outputSchema model cannot represent; it is sanitized at the
      // run() boundary below instead.
    },
    async ({ deviceId, purpose, timeoutMs }) =>
      run(gatewayToolDefinitions.getPolicy.successOutputSchema, () =>
        core.getPolicy({ deviceId, purpose, timeoutMs }),
      ),
  );

  server.registerTool(
    gatewayToolDefinitions.getApprovalHistory.name,
    {
      title: gatewayToolDefinitions.getApprovalHistory.title,
      description: gatewayToolDefinitions.getApprovalHistory.description,
      inputSchema: gatewayToolDefinitions.getApprovalHistory.inputSchema,
      // Success is a discriminated union (live | not_connected | session_ended),
      // which the SDK outputSchema model cannot represent; it is sanitized at the
      // run() boundary below instead.
    },
    async ({ deviceId, purpose, limit, beforeSeq, timeoutMs }) =>
      run(gatewayToolDefinitions.getApprovalHistory.successOutputSchema, () =>
        core.getApprovalHistory({ deviceId, purpose, limit, beforeSeq, timeoutMs }),
      ),
  );

  server.registerTool(
    gatewayToolDefinitions.callMethod.name,
    {
      title: gatewayToolDefinitions.callMethod.title,
      description: gatewayToolDefinitions.callMethod.description,
      inputSchema: gatewayToolDefinitions.callMethod.inputSchema,
      // Success is a discriminated union (live | not_connected | session_ended),
      // which the SDK outputSchema model cannot represent; it is sanitized at the
      // run() boundary below instead.
    },
    async ({ deviceId, purpose, chain, method, params, timeoutMs }) =>
      run(gatewayToolDefinitions.callMethod.successOutputSchema, () =>
        core.callMethod({ deviceId, purpose, chain, method, params, timeoutMs }),
      ),
  );

  return server;
}

export async function startStdioGateway(): Promise<void> {
  const server = createGatewayMcpServer();
  await server.connect(new StdioServerTransport());
}

function createDefaultGatewayCore(): GatewayCore {
  return new GatewayCore(new ConfigStore(), new SerialPortUsbDriver());
}

// Operator-facing diagnostic on stderr (never stdout, which is the MCP JSON-RPC
// channel). Carries only allowlisted, Gateway-authored fields: the normalized
// code, its canonical public message, and retryability. A raw device/OS/Firmware
// string is never logged — not even sanitized, because stripping control bytes is
// not redaction — so the string hazards closed at the MCP output boundary cannot
// reopen in host logs.
function logToolDiagnostic(event: string, rawCode: string, retryable: boolean): void {
  const code = normalizeErrorCode(rawCode);
  console.error(JSON.stringify({ event, code, retryable, message: PUBLIC_ERROR_MESSAGES[code] }));
}

/**
 * Build a client-safe top-level error result. Neither the code nor the message
 * can carry attacker- or device-controlled text to the MCP client.
 */
function toPublicErrorToolResult(error: GatewayError) {
  return errorToolResultShape.parse({
    source: "error",
    connected: false,
    error: toPublicError(error.code, error.retryable),
  });
}

// identify_devices reports per-device failures nested inside an otherwise
// successful result. Canonicalize each nested error with the same allowlist as
// the top-level path so Firmware/serial/OS raw text never reaches the client.
function sanitizeIdentifyDevicesResult(raw: unknown): object {
  // Canonicalize each nested per-device error BEFORE schema validation, so a raw
  // Firmware/serial/OS message becomes a public error rather than failing the
  // publicErrorShape-constrained schema. The real core already canonicalizes at
  // the source; this also covers a leaky adapter/mock input.
  let candidate = raw;
  if (typeof raw === "object" && raw !== null && Array.isArray((raw as { devices?: unknown }).devices)) {
    const record = raw as Record<string, unknown> & { devices: unknown[] };
    candidate = {
      ...record,
      devices: record.devices.map((device) => {
        if (typeof device === "object" && device !== null) {
          const entry = device as Record<string, unknown>;
          const error = entry.error as Record<string, unknown> | undefined;
          if (entry.source === "error" && error && typeof error.code === "string") {
            return { ...entry, error: toPublicError(error.code, error.retryable === true) };
          }
        }
        return device;
      }),
    };
  }
  return identifyDevicesSuccessOutputShape.parse(candidate);
}

// get_device_status cached results carry a Firmware-supplied diagnostic code.
// It is a code, not a message: normalize unknown codes to `gateway_error` and
// attach no message (unlike an error object).
function sanitizeGetDeviceStatusResult(raw: unknown): object {
  // Normalize the Firmware diagnostic code BEFORE schema validation so an unknown
  // or raw code becomes gateway_error rather than failing the now allowlist-
  // constrained firmwareErrorCode. It is a code, not a message: no message is
  // attached (unlike an error object).
  let candidate = raw;
  if (typeof raw === "object" && raw !== null) {
    const record = raw as Record<string, unknown>;
    if (record.source === "cached" && typeof record.firmwareErrorCode === "string") {
      candidate = { ...record, firmwareErrorCode: normalizeErrorCode(record.firmwareErrorCode) };
    }
  }
  return getDeviceStatusSuccessOutputShape.parse(candidate);
}

type StructuredToolResult =
  | DeviceStatusToolResult
  | DeviceListResult
  | SetDeviceMetadataResult
  | ConnectDeviceResult
  | CallMethodResult
  | DisconnectDeviceResult
  | GetAccountsResult
  | GetApprovalHistoryResult
  | GetCapabilitiesResult
  | GetPolicyResult;

// Must only ever receive an already-sanitized success result or a public error
// result. Both structuredContent and the text mirror are derived from the same
// object, so sanitizing before this call closes the text path too.
function withStructuredContent(structuredContent: StructuredToolResult | object, isError = false) {
  return {
    isError,
    structuredContent: structuredContent as Record<string, unknown>,
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(structuredContent, null, 2),
      },
    ],
  };
}
