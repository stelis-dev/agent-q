import { ProtocolError } from "./protocol-error.js";
import {
  PROTOCOL_VERSION,
  createRequestId,
  hasOnlyObjectKeys,
  isRecord,
} from "./protocol-primitives.js";
import { isSafeRequestId, isSessionId } from "./safe-text.js";

export type DeviceSessionRule = "forbidden" | "required" | "optional";
export type DevicePayloadRule = "forbidden" | "required" | "optional";

export interface DeviceMethodRow {
  readonly method: string;
  readonly sessionRule: DeviceSessionRule;
  readonly payloadRule: DevicePayloadRule;
  readonly payloadSchemaOwner: string;
  readonly resultSchemaOwner: string;
  readonly firmwareGate: string;
}

export const DEVICE_METHOD_ROWS = [
  {
    method: "get_status",
    sessionRule: "forbidden",
    payloadRule: "forbidden",
    payloadSchemaOwner: "no payload",
    resultSchemaOwner: "StatusResult",
    firmwareGate: "status_material_consistency",
  },
  {
    method: "identify_device",
    sessionRule: "forbidden",
    payloadRule: "required",
    payloadSchemaOwner: "IdentifyDevicePayload",
    resultSchemaOwner: "IdentifyDeviceResult",
    firmwareGate: "identification_display",
  },
  {
    method: "connect",
    sessionRule: "forbidden",
    payloadRule: "required",
    payloadSchemaOwner: "ConnectPayload",
    resultSchemaOwner: "ConnectResult",
    firmwareGate: "provisioned_material_policy_auth_approval",
  },
  {
    method: "disconnect",
    sessionRule: "required",
    payloadRule: "forbidden",
    payloadSchemaOwner: "no payload",
    resultSchemaOwner: "DisconnectResult",
    firmwareGate: "active_session_cleanup",
  },
  {
    method: "get_capabilities",
    sessionRule: "required",
    payloadRule: "forbidden",
    payloadSchemaOwner: "no payload",
    resultSchemaOwner: "CapabilitiesResult",
    firmwareGate: "active_session_provisioned_material",
  },
  {
    method: "get_accounts",
    sessionRule: "required",
    payloadRule: "forbidden",
    payloadSchemaOwner: "no payload",
    resultSchemaOwner: "AccountsResult",
    firmwareGate: "active_session_account_material",
  },
  {
    method: "policy_get",
    sessionRule: "required",
    payloadRule: "forbidden",
    payloadSchemaOwner: "no payload",
    resultSchemaOwner: "PolicyGetResult",
    firmwareGate: "active_session_policy_store",
  },
  {
    method: "get_approval_history",
    sessionRule: "required",
    payloadRule: "required",
    payloadSchemaOwner: "ApprovalHistoryPayload",
    resultSchemaOwner: "ApprovalHistoryResult",
    firmwareGate: "active_session_approval_history_store",
  },
  {
    method: "sign_transaction",
    sessionRule: "required",
    payloadRule: "required",
    payloadSchemaOwner: "SuiSignTransactionPayload",
    resultSchemaOwner: "SignTransactionResult",
    firmwareGate: "active_session_account_binding_signing_authorization",
  },
  {
    method: "sign_personal_message",
    sessionRule: "required",
    payloadRule: "required",
    payloadSchemaOwner: "SuiSignPersonalMessagePayload",
    resultSchemaOwner: "SignPersonalMessageResult",
    firmwareGate: "active_session_account_binding_user_confirmation",
  },
  {
    method: "policy_propose",
    sessionRule: "required",
    payloadRule: "required",
    payloadSchemaOwner: "PolicyProposePayload",
    resultSchemaOwner: "PolicyProposalOutcome",
    firmwareGate: "active_session_policy_review_auth_commit",
  },
  {
    method: "credential_prepare",
    sessionRule: "required",
    payloadRule: "required",
    payloadSchemaOwner: "CredentialPreparePayload",
    resultSchemaOwner: "CredentialPreparation",
    firmwareGate: "active_session_credential_preparation",
  },
  {
    method: "credential_propose",
    sessionRule: "required",
    payloadRule: "required",
    payloadSchemaOwner: "CredentialProposePayload",
    resultSchemaOwner: "CredentialProposalOutcome",
    firmwareGate: "active_session_credential_review_auth_commit",
  },
  {
    method: "get_result",
    sessionRule: "required",
    payloadRule: "required",
    payloadSchemaOwner: "RetainedResponsePayload",
    resultSchemaOwner: "retained method response",
    firmwareGate: "active_session_retained_response_lookup",
  },
  {
    method: "ack_result",
    sessionRule: "required",
    payloadRule: "required",
    payloadSchemaOwner: "RetainedResponsePayload",
    resultSchemaOwner: "AckResult",
    firmwareGate: "active_session_retained_response_cleanup",
  },
] as const satisfies readonly DeviceMethodRow[];

export type DeviceMethod = (typeof DEVICE_METHOD_ROWS)[number]["method"];

const DEVICE_METHOD_SET = new Set<string>(DEVICE_METHOD_ROWS.map((row) => row.method));
const DEVICE_METHOD_ROW_BY_METHOD = new Map<DeviceMethod, (typeof DEVICE_METHOD_ROWS)[number]>(
  DEVICE_METHOD_ROWS.map((row) => [row.method, row]),
);

export function isDeviceMethod(value: unknown): value is DeviceMethod {
  return typeof value === "string" && DEVICE_METHOD_SET.has(value);
}

export function deviceMethodRow(method: DeviceMethod): (typeof DEVICE_METHOD_ROWS)[number] {
  const row = DEVICE_METHOD_ROW_BY_METHOD.get(method);
  if (row === undefined) {
    throw new ProtocolError("unsupported_method", "Device method is not supported.");
  }
  return row;
}

export interface DeviceErrorRow {
  readonly code: string;
  readonly retryable: boolean;
  readonly message: string;
  readonly meaning: string;
}

export const DEVICE_ERROR_ROWS = [
  { code: "invalid_request", retryable: false, message: "Device request is malformed.", meaning: "Envelope, JSON, id, version, or method shape is invalid." },
  { code: "invalid_params", retryable: false, message: "Device request payload is invalid.", meaning: "Method payload shape or value is invalid." },
  { code: "invalid_state", retryable: false, message: "Device state does not allow this request.", meaning: "Firmware state does not allow the method." },
  { code: "invalid_session", retryable: false, message: "Session is missing, expired, or does not match.", meaning: "Session is missing, expired, or does not match." },
  { code: "request_id_conflict", retryable: false, message: "Request id is already bound to a different request.", meaning: "Request id is already bound to a different retained request identity." },
  { code: "unknown_request", retryable: false, message: "Requested retained response does not exist.", meaning: "Requested retained response does not exist in the current session." },
  { code: "no_active_device", retryable: false, message: "No active device is configured.", meaning: "Host process has no selected active device for the requested scope." },
  { code: "device_not_found", retryable: true, message: "Requested device is not known to Agent-Q.", meaning: "Host process cannot find the requested stored device." },
  { code: "invalid_device_id", retryable: false, message: "Device id is invalid.", meaning: "Host-side device id input is invalid." },
  { code: "invalid_device", retryable: false, message: "Device identity is unsafe.", meaning: "Host process rejected a device identity as unsafe." },
  { code: "device_mismatch", retryable: false, message: "Connected device does not match the requested device.", meaning: "Host process connected to a device whose Firmware identity did not match the requested device id." },
  { code: "unsupported_method", retryable: false, message: "Device method is not supported.", meaning: "Method is not implemented by this Firmware or host boundary." },
  { code: "unsupported_version", retryable: false, message: "Protocol version is not supported.", meaning: "Protocol version is not supported." },
  { code: "unsupported_chain", retryable: false, message: "Chain is not supported.", meaning: "Chain is not supported for the method." },
  { code: "unsupported_transaction", retryable: false, message: "Transaction shape is not supported.", meaning: "Transaction shape is not supported by the current signing path." },
  { code: "malformed_transaction", retryable: false, message: "Transaction bytes are malformed.", meaning: "Transaction bytes or transaction structure are malformed." },
  { code: "payload_too_large", retryable: false, message: "Payload exceeds the current device payload capacity.", meaning: "Payload exceeds the current device payload capacity." },
  { code: "payload_unavailable", retryable: false, message: "Referenced payload is unavailable.", meaning: "Referenced internal payload is missing, expired, consumed, or wrong-session." },
  { code: "payload_conflict", retryable: true, message: "Another sensitive request blocks this payload.", meaning: "Another payload or sensitive flow blocks this request." },
  { code: "busy", retryable: true, message: "Device is busy with another request.", meaning: "Device is already handling another request." },
  { code: "timeout", retryable: true, message: "The signing request timed out on the device.", meaning: "Device or user action timed out." },
  { code: "user_rejected", retryable: false, message: "The signing request was rejected on the device.", meaning: "Device-local user confirmation rejected the request." },
  { code: "policy_rejected", retryable: false, message: "The signing request was rejected by device policy.", meaning: "Firmware policy rejected the request." },
  { code: "signing_failed", retryable: false, message: "The device could not produce a signature.", meaning: "Firmware could not produce the requested signature." },
  { code: "ui_error", retryable: false, message: "Device could not display or manage required UI.", meaning: "Firmware could not display or manage required device UI." },
  { code: "auth_unavailable", retryable: false, message: "Device-local authentication verifier is unavailable.", meaning: "Device-local authentication verifier is unavailable." },
  { code: "account_unavailable", retryable: false, message: "Device account material is unavailable or does not match the request.", meaning: "Device account material is unavailable or does not match the request." },
  { code: "policy_unavailable", retryable: false, message: "Firmware policy store or active policy is unavailable.", meaning: "Firmware policy store or active policy is unavailable." },
  { code: "history_unavailable", retryable: false, message: "Approval history is unavailable.", meaning: "Approval history is unavailable." },
  { code: "rng_unavailable", retryable: true, message: "Device random generator is unavailable.", meaning: "Firmware random generator is unavailable." },
  { code: "invalid_response", retryable: true, message: "Device response is malformed.", meaning: "Firmware response JSON, envelope, or method result shape is invalid." },
  { code: "handshake_failed", retryable: true, message: "Device status or identification handshake failed.", meaning: "Device status or identification handshake failed." },
  { code: "port_not_found", retryable: true, message: "Requested device port is not connected.", meaning: "Requested device port is not connected." },
  { code: "port_in_use", retryable: true, message: "Requested device port is already in use.", meaning: "Requested device port is already in use." },
  { code: "port_permission_denied", retryable: false, message: "Host process lacks permission to access the device port.", meaning: "Host process lacks permission to access the device port." },
  { code: "unsupported_transport", retryable: false, message: "Host environment does not support the required device transport.", meaning: "Host environment does not provide the transport required by the adapter." },
  { code: "transport_closed", retryable: true, message: "Device connection closed before a valid response.", meaning: "Established host-device connection closed before a valid response." },
  { code: "transport_error", retryable: true, message: "Host-device transport failed before a valid response.", meaning: "Host-device transport failed before a valid device response was received." },
  { code: "local_server_unavailable", retryable: true, message: "Local Agent-Q server is unavailable.", meaning: "Local CLI client cannot reach the local Agent-Q server." },
  { code: "identification_code_exhausted", retryable: true, message: "Identification code could not be allocated.", meaning: "Host process could not allocate a unique identification code." },
  { code: "internal_output_error", retryable: false, message: "Agent-Q produced an unexpected internal result.", meaning: "Output sanitization or internal result validation failed." },
  { code: "unknown_error", retryable: false, message: "Agent-Q request failed.", meaning: "Failure did not match a known public code." },
] as const satisfies readonly DeviceErrorRow[];

export type DeviceErrorCode = (typeof DEVICE_ERROR_ROWS)[number]["code"];

const DEVICE_ERROR_ROW_BY_CODE = new Map<DeviceErrorCode, (typeof DEVICE_ERROR_ROWS)[number]>(
  DEVICE_ERROR_ROWS.map((row) => [row.code, row]),
);
const DEVICE_ERROR_CODE_SET = new Set<string>(DEVICE_ERROR_ROWS.map((row) => row.code));

export interface DeviceError {
  readonly code: DeviceErrorCode;
  readonly message: string;
  readonly retryable: boolean;
}

export function isDeviceErrorCode(value: unknown): value is DeviceErrorCode {
  return typeof value === "string" && DEVICE_ERROR_CODE_SET.has(value);
}

export function deviceErrorRow(code: DeviceErrorCode): (typeof DEVICE_ERROR_ROWS)[number] {
  const row = DEVICE_ERROR_ROW_BY_CODE.get(code);
  if (row === undefined) {
    throw new ProtocolError("invalid_response", "Device error code is not in the contract table.");
  }
  return row;
}

export function makeDeviceError(code: DeviceErrorCode): DeviceError {
  const row = deviceErrorRow(code);
  return { code: row.code, message: row.message, retryable: row.retryable };
}

export function makeUnknownDeviceError(): DeviceError {
  return makeDeviceError("unknown_error");
}

const SIGNING_OUTCOME_STATUS_DEVICE_ERROR_CODES = {
  user_rejected: "user_rejected",
  user_timed_out: "timeout",
  policy_rejected: "policy_rejected",
  signing_failed: "signing_failed",
} as const satisfies Record<string, DeviceErrorCode>;

export type SigningOutcomeErrorCode = keyof typeof SIGNING_OUTCOME_STATUS_DEVICE_ERROR_CODES;

function signingOutcomeErrorMessage(code: SigningOutcomeErrorCode): string {
  return deviceErrorRow(SIGNING_OUTCOME_STATUS_DEVICE_ERROR_CODES[code]).message;
}

export const SIGNING_OUTCOME_ERROR_MESSAGES = {
  user_rejected: signingOutcomeErrorMessage("user_rejected"),
  user_timed_out: signingOutcomeErrorMessage("user_timed_out"),
  policy_rejected: signingOutcomeErrorMessage("policy_rejected"),
  signing_failed: signingOutcomeErrorMessage("signing_failed"),
} as const satisfies Record<SigningOutcomeErrorCode, string>;

export interface DeviceRequest {
  readonly id: string;
  readonly version: typeof PROTOCOL_VERSION;
  readonly sessionId?: string;
  readonly method: DeviceMethod;
  readonly payload?: unknown;
}

export interface MakeDeviceRequestInput {
  readonly id?: string;
  readonly sessionId?: string;
  readonly method: DeviceMethod;
  readonly payload?: unknown;
}

export function makeDeviceRequest(input: MakeDeviceRequestInput): DeviceRequest {
  const request: Record<string, unknown> = {
    id: input.id ?? createRequestId(),
    version: PROTOCOL_VERSION,
    method: input.method,
  };
  if (input.sessionId !== undefined) {
    request.sessionId = input.sessionId;
  }
  if (Object.prototype.hasOwnProperty.call(input, "payload")) {
    request.payload = input.payload;
  }
  return parseDeviceRequest(request);
}

export function parseDeviceRequest(value: unknown): DeviceRequest {
  const record = asContractRecord(value, "DeviceRequest", "invalid_request");
  if (!hasOnlyObjectKeys(record, ["id", "version", "sessionId", "method", "payload"])) {
    throw new ProtocolError("invalid_request", "Device request contains unsupported fields.");
  }
  if (!isSafeRequestId(record.id)) {
    throw new ProtocolError("invalid_request", "Device request id is invalid.");
  }
  if (typeof record.version !== "number" || !Number.isInteger(record.version)) {
    throw new ProtocolError("invalid_request", "Device request version is invalid.");
  }
  if (record.version !== PROTOCOL_VERSION) {
    throw new ProtocolError("unsupported_version", "Protocol version is not supported.");
  }
  if (typeof record.method !== "string") {
    throw new ProtocolError("invalid_request", "Device request method is invalid.");
  }
  if (!isDeviceMethod(record.method)) {
    throw new ProtocolError("unsupported_method", "Device method is not supported.");
  }
  const row = deviceMethodRow(record.method);
  const hasSessionId = Object.prototype.hasOwnProperty.call(record, "sessionId");
  const hasPayload = Object.prototype.hasOwnProperty.call(record, "payload");
  if (hasPayload && record.payload === undefined) {
    throw new ProtocolError("invalid_params", "Device request payload must not be undefined.");
  }
  validateSessionRule(row.sessionRule, hasSessionId, record.sessionId);
  validatePayloadRule(row.payloadRule, hasPayload);

  return {
    id: record.id,
    version: PROTOCOL_VERSION,
    ...(hasSessionId ? { sessionId: record.sessionId as string } : {}),
    method: record.method,
    ...(hasPayload ? { payload: record.payload } : {}),
  };
}

export function serializeDeviceRequest(request: DeviceRequest): string {
  return `${JSON.stringify(parseDeviceRequest(request))}\n`;
}

export type DeviceResultParser<T = unknown> = (result: unknown) => T;

export interface DeviceSuccessResponse<TResult = unknown> {
  readonly id?: string;
  readonly version: typeof PROTOCOL_VERSION;
  readonly success: true;
  readonly method: DeviceMethod;
  readonly result: TResult;
}

export interface DeviceFailureResponse {
  readonly id?: string;
  readonly version: typeof PROTOCOL_VERSION;
  readonly success: false;
  readonly method?: DeviceMethod;
  readonly error: DeviceError;
}

export type DeviceResponse<TResult = unknown> = DeviceSuccessResponse<TResult> | DeviceFailureResponse;

export interface ParseDeviceResponseOptions {
  readonly expectedId?: string;
  readonly expectedMethod?: DeviceMethod;
  readonly resultParsers?: Partial<Record<DeviceMethod, DeviceResultParser>>;
}

export function makeDeviceSuccessResponse<TResult>(
  input: Omit<DeviceSuccessResponse<TResult>, "version" | "success">,
): DeviceSuccessResponse<TResult> {
  return parseDeviceResponse({ ...input, version: PROTOCOL_VERSION, success: true }) as DeviceSuccessResponse<TResult>;
}

export function makeDeviceFailureResponse(input: {
  readonly id?: string;
  readonly method?: DeviceMethod;
  readonly code: DeviceErrorCode;
}): DeviceFailureResponse {
  const response: Record<string, unknown> = {
    version: PROTOCOL_VERSION,
    success: false,
    error: makeDeviceError(input.code),
  };
  if (input.id !== undefined) {
    response.id = input.id;
  }
  if (input.method !== undefined) {
    response.method = input.method;
  }
  return parseDeviceResponse(response) as DeviceFailureResponse;
}

export function parseDeviceResponse<TResult = unknown>(
  value: unknown,
  options: ParseDeviceResponseOptions = {},
): DeviceResponse<TResult> {
  const record = asContractRecord(value, "DeviceResponse", "invalid_response");
  if (!hasOnlyObjectKeys(record, ["id", "version", "success", "method", "result", "error"])) {
    throw new ProtocolError("invalid_response", "Device response contains unsupported fields.");
  }
  if (Object.prototype.hasOwnProperty.call(record, "id") && !isSafeRequestId(record.id)) {
    throw new ProtocolError("invalid_response", "Device response id is invalid.");
  }
  if (options.expectedId !== undefined && record.id !== options.expectedId) {
    throw new ProtocolError("invalid_response", "Device response id does not match request.");
  }
  if (record.version !== PROTOCOL_VERSION) {
    throw new ProtocolError("unsupported_version", "Protocol version is not supported.");
  }
  if (record.success === true) {
    return parseDeviceSuccessResponse(record, options) as DeviceSuccessResponse<TResult>;
  }
  if (record.success === false) {
    return parseDeviceFailureResponse(record, options);
  }
  throw new ProtocolError("invalid_response", "Device response success flag is invalid.");
}

export const DEVICE_RESPONSE_ENVELOPE_FIELDS = {
  success: ["id", "version", "success", "method", "result"],
  failure: ["id", "version", "success", "method", "error"],
  error: ["code", "message", "retryable"],
} as const;

export interface CoreContractManifest {
  readonly protocolVersion: typeof PROTOCOL_VERSION;
  readonly methods: readonly DeviceMethodRow[];
  readonly responseEnvelope: typeof DEVICE_RESPONSE_ENVELOPE_FIELDS;
  readonly errors: readonly DeviceErrorRow[];
}

export function createCoreContractManifest(): CoreContractManifest {
  return {
    protocolVersion: PROTOCOL_VERSION,
    methods: DEVICE_METHOD_ROWS,
    responseEnvelope: DEVICE_RESPONSE_ENVELOPE_FIELDS,
    errors: DEVICE_ERROR_ROWS,
  };
}

function validateSessionRule(rule: DeviceSessionRule, hasSessionId: boolean, sessionId: unknown): void {
  if (rule === "forbidden") {
    if (hasSessionId) {
      throw new ProtocolError("invalid_request", "Device request must not include sessionId.");
    }
    return;
  }
  if (!hasSessionId) {
    if (rule === "required") {
      throw new ProtocolError("invalid_session", "Device request session is required.");
    }
    return;
  }
  if (!isSessionId(sessionId)) {
    throw new ProtocolError("invalid_session", "Device request session is invalid.");
  }
}

function validatePayloadRule(rule: DevicePayloadRule, hasPayload: boolean): void {
  if (rule === "forbidden" && hasPayload) {
    throw new ProtocolError("invalid_request", "Device request must not include payload.");
  }
  if (rule === "required" && !hasPayload) {
    throw new ProtocolError("invalid_params", "Device request payload is required.");
  }
}

function parseDeviceSuccessResponse(
  record: Record<string, unknown>,
  options: ParseDeviceResponseOptions,
): DeviceSuccessResponse {
  if (!hasOnlyObjectKeys(record, ["id", "version", "success", "method", "result"])) {
    throw new ProtocolError("invalid_response", "Device success response shape is invalid.");
  }
  if (!isDeviceMethod(record.method)) {
    throw new ProtocolError("invalid_response", "Device success response method is invalid.");
  }
  if (options.expectedMethod !== undefined && record.method !== options.expectedMethod) {
    throw new ProtocolError("invalid_response", "Device response method does not match request.");
  }
  if (!Object.prototype.hasOwnProperty.call(record, "result")) {
    throw new ProtocolError("invalid_response", "Device success response result is required.");
  }
  const parser = options.resultParsers?.[record.method];
  const result = parser === undefined ? record.result : parser(record.result);
  return {
    ...(Object.prototype.hasOwnProperty.call(record, "id") ? { id: record.id as string } : {}),
    version: PROTOCOL_VERSION,
    success: true,
    method: record.method,
    result,
  };
}

function parseDeviceFailureResponse(
  record: Record<string, unknown>,
  options: ParseDeviceResponseOptions,
): DeviceFailureResponse {
  if (!hasOnlyObjectKeys(record, ["id", "version", "success", "method", "error"])) {
    throw new ProtocolError("invalid_response", "Device failure response shape is invalid.");
  }
  if (Object.prototype.hasOwnProperty.call(record, "method")) {
    if (!isDeviceMethod(record.method)) {
      throw new ProtocolError("invalid_response", "Device failure response method is invalid.");
    }
    if (options.expectedMethod !== undefined && record.method !== options.expectedMethod) {
      throw new ProtocolError("invalid_response", "Device response method does not match request.");
    }
  }
  const error = parseDeviceErrorObject(record.error);
  return {
    ...(Object.prototype.hasOwnProperty.call(record, "id") ? { id: record.id as string } : {}),
    version: PROTOCOL_VERSION,
    success: false,
    ...(Object.prototype.hasOwnProperty.call(record, "method") ? { method: record.method as DeviceMethod } : {}),
    error,
  };
}

function parseDeviceErrorObject(value: unknown): DeviceError {
  const record = asContractRecord(value, "DeviceResponse.error", "invalid_response");
  if (!hasOnlyObjectKeys(record, ["code", "message", "retryable"])) {
    throw new ProtocolError("invalid_response", "Device response error shape is invalid.");
  }
  if (!isDeviceErrorCode(record.code)) {
    throw new ProtocolError("invalid_response", "Device response error code is invalid.");
  }
  const row = deviceErrorRow(record.code);
  if (record.message !== row.message || record.retryable !== row.retryable) {
    throw new ProtocolError("invalid_response", "Device response error does not match the contract table.");
  }
  return { code: row.code, message: row.message, retryable: row.retryable };
}

function asContractRecord(value: unknown, label: string, code: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new ProtocolError(code, `${label} must be an object.`);
  }
  return value;
}
