import {
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
import { ProtocolError } from "./protocol-error.js";
import {
  ED25519_PUBLIC_KEY_BASE64_PATTERN,
  CREDENTIAL_PREPARE_OPERATION,
  CREDENTIAL_PROPOSE_OPERATION,
  MAX_SUI_ZKLOGIN_PUBLIC_KEY_BYTES,
  MAX_ACCOUNTS_PER_RESPONSE,
  MAX_CAPABILITY_ACCOUNTS_PER_CHAIN,
  MAX_CAPABILITY_CHAINS,
  MAX_CREDENTIAL_CAPABILITIES,
  INVALID_ID_ERROR_CODE,
  MAX_RAW_PROTOCOL_JSON_BYTES,
  MAX_SESSION_TTL_MS,
  MAX_SIGN_RESULT_PAYLOAD_BASE64_CHARS,
  MAX_SIGNING_CAPABILITIES,
  MAX_SUI_SIGN_PERSONAL_MESSAGE_BASE64_CHARS,
  MAX_SUI_SIGN_PERSONAL_MESSAGE_BYTES,
  MAX_SUI_SIGN_TRANSACTION_TX_BYTES,
  MAX_SUI_SIGN_TRANSACTION_TX_BYTES_BASE64_CHARS,
  PROTOCOL_VERSION,
  HASH_ID_PATTERN,
  RULE_REF_PATTERN,
  SIGN_RESULT_ERROR_MESSAGES,
  SUI_ADDRESS_PATTERN,
  SUI_CHAIN_ID,
  SUI_DERIVATION_PATH,
  SUI_ZKLOGIN_CREDENTIAL,
  SUI_ED25519_SIGNATURE_BYTES,
  SUI_ED25519_SIGNATURE_BASE64_PATTERN,
  SUI_SIGNATURE_ENVELOPE_MAX_BYTES,
  SUI_SCHEME_PREFIXED_ED25519_PUBLIC_KEY_BYTES,
  SUI_SIGNATURE_SCHEME_FLAG_ED25519,
  SUI_SIGNATURE_SCHEME_FLAG_ZKLOGIN,
  SUI_SIGN_PERSONAL_MESSAGE_METHOD,
  SUI_SIGN_TRANSACTION_METHOD,
  SUI_SIGN_TRANSACTION_NETWORKS,
  MIN_SUI_ZKLOGIN_PUBLIC_KEY_BYTES,
  consumeProtocolResponseChunk,
  createRequestId,
  asRecord,
  hasOnlyObjectKeys,
  hasSecretPayloadKey,
  isRecord,
  isSuiPersonalMessageSignatureBase64,
  isSuiTransactionSignatureEnvelopeBase64,
  isSuiAddressForSchemePrefixedPublicKey,
  rejectSecretPayload,
  requireOnlyKeys,
  utf8ByteLength,
  validateCanonicalBase64Bytes,
  validateCanonicalBase64Syntax,
  validateSuiSignTransactionNetwork,
  type SignResultErrorCode,
  type SuiSignMethod,
  type SuiSignTransactionNetwork,
} from "./protocol-primitives.js";
import {
  identifySignRoute,
  type SignOperationType,
  type SupportedSignRoute,
} from "./protocol-sign-routes.js";
import {
  sanitizePayloadDeliveryCapability,
} from "./protocol-payload-delivery.js";

export { ProtocolError };
export {
  ED25519_PUBLIC_KEY_BASE64_PATTERN,
  MAX_ACCOUNTS_PER_RESPONSE,
  MAX_CAPABILITY_ACCOUNTS_PER_CHAIN,
  MAX_CAPABILITY_CHAINS,
  MAX_RAW_PROTOCOL_JSON_BYTES,
  MAX_SESSION_TTL_MS,
  MAX_SIGN_RESULT_PAYLOAD_BASE64_CHARS,
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
  SUI_ED25519_SIGNATURE_BYTES,
  SUI_ED25519_SIGNATURE_BASE64_PATTERN,
  SUI_SIGNATURE_ENVELOPE_MAX_BYTES,
  SUI_SCHEME_PREFIXED_ED25519_PUBLIC_KEY_BYTES,
  SUI_SIGNATURE_SCHEME_FLAG_ED25519,
  SUI_SIGNATURE_SCHEME_FLAG_ZKLOGIN,
  SUI_SIGN_PERSONAL_MESSAGE_METHOD,
  SUI_SIGN_TRANSACTION_METHOD,
  SUI_SIGN_TRANSACTION_NETWORKS,
  MIN_SUI_ZKLOGIN_PUBLIC_KEY_BYTES,
  MAX_SUI_ZKLOGIN_PUBLIC_KEY_BYTES,
  consumeProtocolResponseChunk,
  createRequestId,
  isSuiPersonalMessageSignatureBase64,
  isSuiAddressForSchemePrefixedPublicKey,
  isSuiTransactionSignatureEnvelopeBase64,
};
export {
  AGENT_Q_USB_PRODUCT_ID_NUMBER,
  AGENT_Q_USB_VENDOR_ID_NUMBER,
  DEFAULT_AGENT_Q_USB_BAUD_RATE,
  INTERNAL_CONNECT_DEADLINE_MS,
  INTERNAL_DISCONNECT_DEADLINE_MS,
  INTERNAL_SIGN_PERSONAL_MESSAGE_DEADLINE_MS,
  INTERNAL_SIGN_TRANSACTION_DEADLINE_MS,
  INTERNAL_USB_DEADLINE_MS,
  MAX_PROTOCOL_RESPONSE_LINE_BYTES,
  PAYLOAD_DELIVERY_DEADLINE_CHUNK_BYTES,
} from "./transport-invariants.js";
export { identifySignRoute };
export type { DeviceState, ProvisioningState, SignOperationType, SupportedSignRoute };

export interface DeviceStatus {
  deviceId: string;
  state: DeviceState;
  firmwareName: string;
  hardware: string;
  firmwareVersion: string;
}

export interface ConnectRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "connect";
  params: {
    clientName: string;
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

export interface SignTransactionParams {
  network: SuiSignTransactionNetwork;
  txBytes: string;
}

export interface SignPersonalMessageParams {
  network: SuiSignTransactionNetwork;
  message: string;
}

export interface SignTransactionRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: typeof SUI_SIGN_TRANSACTION_METHOD;
  sessionId: string;
  chain: typeof SUI_CHAIN_ID;
  method: typeof SUI_SIGN_TRANSACTION_METHOD;
  params: SignTransactionParams;
}

export interface SignPersonalMessageRequest {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: typeof SUI_SIGN_PERSONAL_MESSAGE_METHOD;
  sessionId: string;
  chain: typeof SUI_CHAIN_ID;
  method: typeof SUI_SIGN_PERSONAL_MESSAGE_METHOD;
  params: SignPersonalMessageParams;
}

export type ProviderProtocolRequest =
  | ConnectRequest
  | DisconnectRequest
  | GetAccountsRequest
  | GetCapabilitiesRequest
  | SignPersonalMessageRequest
  | SignTransactionRequest;

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

export type CapabilityAccount =
  | {
      keyScheme: "ed25519";
      derivationPath: typeof SUI_DERIVATION_PATH;
    }
  | {
      keyScheme: "zklogin";
    };

export interface CapabilityChain {
  id: string;
  accounts: CapabilityAccount[];
  methods: string[];
}

export interface SigningPayloadCapability {
  kind: "transaction";
  inlineMaxBytes: string;
  chunkMaxBytes: string;
  payloadMaxBytes: string;
}

export interface SigningCapabilityEntry {
  chain: typeof SUI_CHAIN_ID;
  method: SuiSignMethod;
  payload?: SigningPayloadCapability;
}

export type SignResultAuthorization = "user" | "policy";

export interface SigningCapabilities {
  authorization: SignResultAuthorization;
  methods: SigningCapabilityEntry[];
}

export interface CredentialCapability {
  chain: typeof SUI_CHAIN_ID;
  credential: typeof SUI_ZKLOGIN_CREDENTIAL;
  operations: [typeof CREDENTIAL_PREPARE_OPERATION, typeof CREDENTIAL_PROPOSE_OPERATION];
}

export interface CapabilitiesResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "capabilities";
  chains: CapabilityChain[];
  signing?: SigningCapabilities;
  credentials?: CredentialCapability[];
}

export type Account =
  | {
      chain: typeof SUI_CHAIN_ID;
      address: string;
      publicKey: string;
      keyScheme: "ed25519";
      derivationPath: typeof SUI_DERIVATION_PATH;
    }
  | {
      chain: typeof SUI_CHAIN_ID;
      address: string;
      publicKey: string;
      keyScheme: "zklogin";
    };

export interface AccountsResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "accounts";
  accounts: Account[];
}

export interface SignTransactionSignedResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "sign_result";
  authorization: SignResultAuthorization;
  status: "signed";
  chain: typeof SUI_CHAIN_ID;
  method: typeof SUI_SIGN_TRANSACTION_METHOD;
  signature: string;
}

export interface SignPersonalMessageSignedResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "sign_result";
  authorization: "user";
  status: "signed";
  chain: typeof SUI_CHAIN_ID;
  method: typeof SUI_SIGN_PERSONAL_MESSAGE_METHOD;
  signature: string;
  messageBytes: string;
}

export type SignResultSignedResponse = SignTransactionSignedResponse | SignPersonalMessageSignedResponse;

export interface SignResultUserRejectedResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "sign_result";
  authorization: "user";
  status: "user_rejected" | "user_timed_out";
  error: {
    code: "user_rejected" | "user_timed_out";
    message: string;
  };
}

export interface SignResultPolicyRejectedResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "sign_result";
  authorization: "policy";
  status: "policy_rejected";
  policyHash: string;
  ruleRef: string;
  error: {
    code: "policy_rejected";
    message: string;
  };
}

export interface SignResultSigningFailedResponse {
  id: string;
  version: typeof PROTOCOL_VERSION;
  type: "sign_result";
  authorization: SignResultAuthorization;
  status: "signing_failed";
  error: {
    code: "signing_failed";
    message: string;
  };
}

export type SignResultResponse =
  | SignResultSignedResponse
  | SignResultUserRejectedResponse
  | SignResultPolicyRejectedResponse
  | SignResultSigningFailedResponse;
export type SignResultStatus = SignResultResponse["status"];

export interface ProtocolErrorResponse {
  id?: string;
  version: typeof PROTOCOL_VERSION;
  type: "error";
  error: {
    code: string;
    message: string;
  };
}

export type ProviderProtocolResponse =
  | AccountsResponse
  | CapabilitiesResponse
  | ConnectResponse
  | DisconnectResponse
  | ProtocolErrorResponse
  | SignResultResponse;

export function makeConnectRequest(clientName: string, id = createRequestId()): ConnectRequest {
  validateRequestId(id);
  if (!isClientName(clientName)) {
    throw new ProtocolError("invalid_client_name", "clientName must be 1-64 printable ASCII characters.");
  }
  return { id, version: PROTOCOL_VERSION, type: "connect", params: { clientName } };
}

export function makeDisconnectRequest(sessionId: string, id = createRequestId()): DisconnectRequest {
  validateRequestId(id);
  validateSessionId(sessionId);
  return { id, version: PROTOCOL_VERSION, type: "disconnect", sessionId };
}

export function makeGetCapabilitiesRequest(sessionId: string, id = createRequestId()): GetCapabilitiesRequest {
  validateRequestId(id);
  validateSessionId(sessionId);
  return { id, version: PROTOCOL_VERSION, type: "get_capabilities", sessionId };
}

export function makeGetAccountsRequest(sessionId: string, id = createRequestId()): GetAccountsRequest {
  validateRequestId(id);
  validateSessionId(sessionId);
  return { id, version: PROTOCOL_VERSION, type: "get_accounts", sessionId };
}

export function makeSignTransactionRequest(
  sessionId: string,
  chain: unknown,
  method: unknown,
  params: unknown,
  id = createRequestId(),
): SignTransactionRequest {
  validateRequestId(id);
  const route = identifySignRoute(SUI_SIGN_TRANSACTION_METHOD, chain, method);
  validateSessionId(sessionId);
  const normalizedParams = validateSignTransactionParams(params);
  const request: SignTransactionRequest = {
    id,
    version: PROTOCOL_VERSION,
    type: SUI_SIGN_TRANSACTION_METHOD,
    sessionId,
    chain: route.chain,
    method: route.method,
    params: normalizedParams,
  };
  validateRawRequestSize(request, "sign_transaction");
  return request;
}

export function makeSignPersonalMessageRequest(
  sessionId: string,
  chain: unknown,
  method: unknown,
  params: unknown,
  id = createRequestId(),
): SignPersonalMessageRequest {
  validateRequestId(id);
  const route = identifySignRoute(SUI_SIGN_PERSONAL_MESSAGE_METHOD, chain, method);
  validateSessionId(sessionId);
  const normalizedParams = validateSignPersonalMessageParams(params);
  const request: SignPersonalMessageRequest = {
    id,
    version: PROTOCOL_VERSION,
    type: SUI_SIGN_PERSONAL_MESSAGE_METHOD,
    sessionId,
    chain: route.chain,
    method: route.method,
    params: normalizedParams,
  };
  validateRawRequestSize(request, "sign_personal_message");
  return request;
}

export function serializeProviderProtocolRequest(request: ProviderProtocolRequest): string {
  return `${JSON.stringify(normalizeProviderProtocolRequest(request))}\n`;
}

export function parseJsonLine(line: string): unknown {
  try {
    return JSON.parse(line);
  } catch {
    throw new ProtocolError("invalid_json", "Invalid JSON response.");
  }
}

export function parseProviderProtocolResponse(line: string, expectedId?: string): ProviderProtocolResponse {
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
    return sanitizeProtocolErrorResponse(value);
  }
  if (value.type === "connect_result") {
    return sanitizeConnectResponse(value);
  }
  if (value.type === "disconnect_result") {
    return sanitizeDisconnectResponse(value);
  }
  if (value.type === "capabilities") {
    return sanitizeCapabilitiesResponse(value);
  }
  if (value.type === "accounts") {
    return sanitizeAccountsResponse(value);
  }
  if (value.type === "sign_result") {
    return sanitizeSignResultResponse(value);
  }
  throw new ProtocolError("protocol_error", "Provider protocol response type is unsupported.");
}

export function assertConnectResponse(response: ProviderProtocolResponse): ConnectResponse {
  if (response.type === "error") {
    throw new ProtocolError(response.error.code, response.error.message);
  }
  if (response.type !== "connect_result") {
    throw new ProtocolError("protocol_error", "Protocol response type is not connect_result.");
  }
  return response;
}

export function assertDisconnectResponse(response: ProviderProtocolResponse): DisconnectResponse {
  if (response.type === "error") {
    throw new ProtocolError(response.error.code, response.error.message);
  }
  if (response.type !== "disconnect_result") {
    throw new ProtocolError("protocol_error", "Protocol response type is not disconnect_result.");
  }
  return response;
}

export function assertCapabilitiesResponse(response: ProviderProtocolResponse): CapabilitiesResponse {
  if (response.type === "error") {
    throw new ProtocolError(response.error.code, response.error.message);
  }
  if (response.type !== "capabilities") {
    throw new ProtocolError("protocol_error", "Protocol response type is not capabilities.");
  }
  return response;
}

export function assertAccountsResponse(response: ProviderProtocolResponse): AccountsResponse {
  if (response.type === "error") {
    throw new ProtocolError(response.error.code, response.error.message);
  }
  if (response.type !== "accounts") {
    throw new ProtocolError("protocol_error", "Protocol response type is not accounts.");
  }
  return response;
}

export function assertSignResultResponse(response: ProviderProtocolResponse): SignResultResponse {
  if (response.type === "error") {
    throw new ProtocolError(response.error.code, response.error.message);
  }
  if (response.type !== "sign_result") {
    throw new ProtocolError("protocol_error", "Protocol response type is not sign_result.");
  }
  return response;
}

function normalizeProviderProtocolRequest(request: unknown): ProviderProtocolRequest {
  if (!isRecord(request)) {
    throw new ProtocolError("invalid_method", "Provider protocol request must be an object.");
  }
  if (request.version !== PROTOCOL_VERSION) {
    throw new ProtocolError("unsupported_version", "Unsupported provider protocol request version.");
  }
  switch (request.type) {
    case "connect": {
      requireOnlyKeys(request, ["id", "version", "type", "params"], "connect request");
      const params = asRecord(request.params, "connect params");
      requireOnlyKeys(params, ["clientName"], "connect params");
      return makeConnectRequest(params.clientName as string, request.id as string);
    }
    case "disconnect":
      requireOnlyKeys(request, ["id", "version", "type", "sessionId"], "disconnect request");
      return makeDisconnectRequest(request.sessionId as string, request.id as string);
    case "get_accounts":
      requireOnlyKeys(request, ["id", "version", "type", "sessionId"], "get_accounts request");
      return makeGetAccountsRequest(request.sessionId as string, request.id as string);
    case "get_capabilities":
      requireOnlyKeys(request, ["id", "version", "type", "sessionId"], "get_capabilities request");
      return makeGetCapabilitiesRequest(request.sessionId as string, request.id as string);
    case "sign_personal_message":
      requireOnlyKeys(
        request,
        ["id", "version", "type", "sessionId", "chain", "method", "params"],
        "sign_personal_message request",
      );
      requireOnlyKeys(
        asRecord(request.params, "sign_personal_message params"),
        ["network", "message"],
        "sign_personal_message params",
      );
      return makeSignPersonalMessageRequest(
        request.sessionId as string,
        request.chain,
        request.method,
        request.params,
        request.id as string,
      );
    case "sign_transaction":
      requireOnlyKeys(
        request,
        ["id", "version", "type", "sessionId", "chain", "method", "params"],
        "sign_transaction request",
      );
      requireOnlyKeys(asRecord(request.params, "sign_transaction params"), ["network", "txBytes"], "sign_transaction params");
      return makeSignTransactionRequest(
        request.sessionId as string,
        request.chain,
        request.method,
        request.params,
        request.id as string,
      );
    default:
      throw new ProtocolError("invalid_method", "Provider protocol request type is unsupported.");
  }
}

function validateRequestId(id: string): void {
  if (!isSafeRequestId(id)) {
    throw new ProtocolError(INVALID_ID_ERROR_CODE, "Invalid request id.");
  }
}

function validateSessionId(sessionId: string): void {
  if (!isSessionId(sessionId)) {
    throw new ProtocolError("invalid_session", "Invalid sessionId.");
  }
}

export function validateSignTransactionInput(
  chain: unknown,
  method: unknown,
  params: unknown,
  requestType = "sign_transaction",
): SignTransactionParams {
  identifySignRoute(SUI_SIGN_TRANSACTION_METHOD, chain, method);
  return validateSignTransactionParams(params, requestType);
}

export function validateSignTransactionParams(
  params: unknown,
  requestType = "sign_transaction",
): SignTransactionParams {
  const normalized = asSignParamsRecord(params, requestType, ["network", "txBytes"]);
  return {
    network: validateSuiNetwork(normalized.network),
    txBytes: validateCanonicalBase64Bytes(
      normalized.txBytes,
      MAX_SUI_SIGN_TRANSACTION_TX_BYTES,
      "sui/sign_transaction txBytes",
    ),
  };
}

export function validateSignPersonalMessageInput(
  chain: unknown,
  method: unknown,
  params: unknown,
  requestType = "sign_personal_message",
): SignPersonalMessageParams {
  identifySignRoute(SUI_SIGN_PERSONAL_MESSAGE_METHOD, chain, method);
  return validateSignPersonalMessageParams(params, requestType);
}

export function validateSignPersonalMessageParams(
  params: unknown,
  requestType = "sign_personal_message",
): SignPersonalMessageParams {
  const normalized = asSignParamsRecord(params, requestType, ["network", "message"]);
  return {
    network: validateSuiNetwork(normalized.network),
    message: validateCanonicalBase64Syntax(
      normalized.message,
      MAX_RAW_PROTOCOL_JSON_BYTES,
      "sui/sign_personal_message message",
    ),
  };
}

function asSignParamsRecord(value: unknown, label: string, keys: readonly string[]): Record<string, unknown> {
  const params = asRecord(value, `${label} params`);
  if (hasSecretPayloadKey(params)) {
    throw new ProtocolError("invalid_params", `${label} params must not include secret material.`);
  }
  requireOnlyKeys(params, keys, `${label} params`);
  return params;
}

function validateSuiNetwork(value: unknown): SuiSignTransactionNetwork {
  return validateSuiSignTransactionNetwork(value);
}

function validateRawRequestSize(request: ProviderProtocolRequest, method: string): void {
  if (utf8ByteLength(JSON.stringify(request)) > MAX_RAW_PROTOCOL_JSON_BYTES) {
    throw new ProtocolError("invalid_params", `${method} request is too large for the runtime.`);
  }
}

function sanitizeProtocolErrorResponse(value: Record<string, unknown>): ProtocolErrorResponse {
  if (!hasOnlyObjectKeys(value, ["id", "version", "type", "error"])) {
    throw new ProtocolError("protocol_error", "Protocol error response contains unsupported fields.");
  }
  if (value.id !== undefined && typeof value.id !== "string") {
    throw new ProtocolError("protocol_error", "Protocol error response id is malformed.");
  }
  const error = asRecord(value.error, "Protocol error response error");
  if (typeof error.code !== "string" || typeof error.message !== "string") {
    throw new ProtocolError("protocol_error", "Protocol error response is malformed.");
  }
  requireOnlyKeys(error, ["code", "message"], "Protocol error response error");
  return {
    id: value.id,
    version: PROTOCOL_VERSION,
    type: "error",
    error: { code: error.code, message: error.message },
  };
}

function sanitizeConnectResponse(value: Record<string, unknown>): ConnectResponse {
  if (typeof value.id !== "string") {
    throw new ProtocolError("protocol_error", "Connect response id is malformed.");
  }
  if (value.status === "approved") {
    requireOnlyKeys(value, ["id", "version", "type", "status", "sessionId", "sessionTtlMs", "device"], "Connect approved response");
    const device = sanitizeStrictDeviceStatus(value.device, "Connect response device object");
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
    requireOnlyKeys(value, ["id", "version", "type", "status", "error"], "Connect rejected response");
    const error = asRecord(value.error, "Connect rejected response error");
    if (typeof error.code !== "string" || typeof error.message !== "string") {
      throw new ProtocolError("protocol_error", "Connect rejected response error object is malformed.");
    }
    requireOnlyKeys(error, ["code", "message"], "Connect rejected response error");
    return {
      id: value.id,
      version: PROTOCOL_VERSION,
      type: "connect_result",
      status: "rejected",
      error: { code: error.code, message: error.message },
    };
  }
  throw new ProtocolError("protocol_error", "Connect response status is unsupported.");
}

function sanitizeDisconnectResponse(value: Record<string, unknown>): DisconnectResponse {
  requireOnlyKeys(value, ["id", "version", "type", "status"], "Disconnect response");
  if (typeof value.id !== "string" || value.status !== "disconnected") {
    throw new ProtocolError("protocol_error", "Disconnect response is malformed.");
  }
  return { id: value.id, version: PROTOCOL_VERSION, type: "disconnect_result", status: "disconnected" };
}

function sanitizeCapabilitiesResponse(value: Record<string, unknown>): CapabilitiesResponse {
  if (typeof value.id !== "string") {
    throw new ProtocolError("protocol_error", "Capabilities response id is malformed.");
  }
  rejectSecretPayload(value, "Capabilities response");
  requireOnlyKeys(value, ["id", "version", "type", "chains", "signing", "credentials"], "Capabilities response");
  if (!Array.isArray(value.chains) || value.chains.length !== MAX_CAPABILITY_CHAINS) {
    throw new ProtocolError("protocol_error", "Capabilities response chains are malformed.");
  }
  const signing = sanitizeSigningCapabilities(value.signing);
  const credentials = sanitizeCredentialCapabilities(value.credentials);
  return {
    id: value.id,
    version: PROTOCOL_VERSION,
    type: "capabilities",
    chains: value.chains.map((entry) => sanitizeCapabilityChain(entry)),
    ...(signing === undefined ? {} : { signing }),
    ...(credentials === undefined ? {} : { credentials }),
  };
}

function sanitizeAccountsResponse(value: Record<string, unknown>): AccountsResponse {
  if (typeof value.id !== "string") {
    throw new ProtocolError("protocol_error", "Accounts response id is malformed.");
  }
  rejectSecretPayload(value, "Accounts response");
  requireOnlyKeys(value, ["id", "version", "type", "accounts"], "Accounts response");
  if (!Array.isArray(value.accounts) || value.accounts.length !== MAX_ACCOUNTS_PER_RESPONSE) {
    throw new ProtocolError("protocol_error", "Accounts response accounts are malformed.");
  }
  return {
    id: value.id,
    version: PROTOCOL_VERSION,
    type: "accounts",
    accounts: value.accounts.map((entry) => sanitizeAccount(entry)),
  };
}

function sanitizeCapabilityChain(value: unknown): CapabilityChain {
  const chain = asRecord(value, "Capability chain entry");
  rejectSecretPayload(chain, "Capability chain entry");
  requireOnlyKeys(chain, ["id", "accounts", "methods"], "Capability chain entry");
  if (chain.id !== SUI_CHAIN_ID) {
    throw new ProtocolError("protocol_error", "Capability chain is unsupported.");
  }
  if (!Array.isArray(chain.accounts) || chain.accounts.length !== MAX_CAPABILITY_ACCOUNTS_PER_CHAIN) {
    throw new ProtocolError("protocol_error", "Capability accounts are malformed.");
  }
  if (!Array.isArray(chain.methods) || chain.methods.length !== 0) {
    throw new ProtocolError("protocol_error", "Capability method is unsupported.");
  }
  return {
    id: SUI_CHAIN_ID,
    accounts: chain.accounts.map((entry) => sanitizeCapabilityAccount(entry)),
    methods: [],
  };
}

function sanitizeCapabilityAccount(value: unknown): CapabilityAccount {
  const account = asRecord(value, "Capability account entry");
  rejectSecretPayload(account, "Capability account entry");
  if (account.keyScheme === "ed25519") {
    requireOnlyKeys(account, ["keyScheme", "derivationPath"], "Capability account entry");
    if (account.derivationPath !== SUI_DERIVATION_PATH) {
      throw new ProtocolError("protocol_error", "Capability account entry is unsupported.");
    }
    return { keyScheme: "ed25519", derivationPath: SUI_DERIVATION_PATH };
  }
  if (account.keyScheme === "zklogin") {
    requireOnlyKeys(account, ["keyScheme"], "Capability account entry");
    return { keyScheme: "zklogin" };
  }
  throw new ProtocolError("protocol_error", "Capability account entry is unsupported.");
}

function validateAccountPublicKey(
  address: string,
  publicKey: unknown,
  keyScheme: "ed25519" | "zklogin",
): string {
  if (typeof publicKey !== "string") {
    throw new ProtocolError("protocol_error", "Account entry is unsupported.");
  }
  const expectedSchemeFlag =
    keyScheme === "ed25519"
      ? SUI_SIGNATURE_SCHEME_FLAG_ED25519
      : SUI_SIGNATURE_SCHEME_FLAG_ZKLOGIN;
  const minDecodedBytes =
    keyScheme === "ed25519"
      ? SUI_SCHEME_PREFIXED_ED25519_PUBLIC_KEY_BYTES
      : MIN_SUI_ZKLOGIN_PUBLIC_KEY_BYTES;
  const maxDecodedBytes =
    keyScheme === "ed25519"
      ? SUI_SCHEME_PREFIXED_ED25519_PUBLIC_KEY_BYTES
      : MAX_SUI_ZKLOGIN_PUBLIC_KEY_BYTES;
  if (
    !isSuiAddressForSchemePrefixedPublicKey(
      address,
      publicKey,
      expectedSchemeFlag,
      minDecodedBytes,
      maxDecodedBytes,
    )
  ) {
    throw new ProtocolError("protocol_error", "Account entry is unsupported.");
  }
  return publicKey;
}

function sanitizeSigningCapabilities(value: unknown): SigningCapabilities | undefined {
  if (value === undefined) {
    return undefined;
  }
  const signing = asRecord(value, "Signing capabilities");
  requireOnlyKeys(signing, ["authorization", "methods"], "Signing capabilities");
  if (signing.authorization !== "user" && signing.authorization !== "policy") {
    throw new ProtocolError("protocol_error", "Signing authorization is unsupported.");
  }
  if (!Array.isArray(signing.methods) || signing.methods.length === 0 || signing.methods.length > MAX_SIGNING_CAPABILITIES) {
    throw new ProtocolError("protocol_error", "Signing capabilities are malformed.");
  }
  const methods = signing.methods.map((entry) => sanitizeSigningCapabilityEntry(entry));
  const methodNames = new Set(methods.map((entry) => entry.method));
  if (methodNames.size !== methods.length) {
    throw new ProtocolError("protocol_error", "Signing capability is duplicated.");
  }
  if (signing.authorization === "policy") {
    if (methods.length !== 1 || !methodNames.has(SUI_SIGN_TRANSACTION_METHOD)) {
      throw new ProtocolError("protocol_error", "Signing capability is unsupported.");
    }
  } else if (
    methods.length !== 2 ||
    !methodNames.has(SUI_SIGN_TRANSACTION_METHOD) ||
    !methodNames.has(SUI_SIGN_PERSONAL_MESSAGE_METHOD)
  ) {
    throw new ProtocolError("protocol_error", "Signing capability is unsupported.");
  }
  return { authorization: signing.authorization, methods };
}

function sanitizeCredentialCapabilities(value: unknown): CredentialCapability[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!Array.isArray(value) || value.length !== MAX_CREDENTIAL_CAPABILITIES) {
    throw new ProtocolError("protocol_error", "Credential capabilities are malformed.");
  }
  return value.map((entry) => sanitizeCredentialCapability(entry));
}

function sanitizeCredentialCapability(value: unknown): CredentialCapability {
  const entry = asRecord(value, "Credential capability entry");
  rejectSecretPayload(entry, "Credential capability entry");
  requireOnlyKeys(entry, ["chain", "credential", "operations"], "Credential capability entry");
  if (
    entry.chain !== SUI_CHAIN_ID ||
    entry.credential !== SUI_ZKLOGIN_CREDENTIAL ||
    !Array.isArray(entry.operations) ||
    entry.operations.length !== 2 ||
    entry.operations[0] !== CREDENTIAL_PREPARE_OPERATION ||
    entry.operations[1] !== CREDENTIAL_PROPOSE_OPERATION
  ) {
    throw new ProtocolError("protocol_error", "Credential capability is unsupported.");
  }
  return {
    chain: SUI_CHAIN_ID,
    credential: SUI_ZKLOGIN_CREDENTIAL,
    operations: [CREDENTIAL_PREPARE_OPERATION, CREDENTIAL_PROPOSE_OPERATION],
  };
}

function sanitizeSigningCapabilityEntry(value: unknown): SigningCapabilityEntry {
  const entry = asRecord(value, "Signing capability entry");
  rejectSecretPayload(entry, "Signing capability entry");
  requireOnlyKeys(entry, ["chain", "method", "payload"], "Signing capability entry");
  if (
    entry.chain !== SUI_CHAIN_ID ||
    (entry.method !== SUI_SIGN_TRANSACTION_METHOD && entry.method !== SUI_SIGN_PERSONAL_MESSAGE_METHOD)
  ) {
    throw new ProtocolError("protocol_error", "Signing capability is unsupported.");
  }
  if (entry.payload !== undefined && entry.method !== SUI_SIGN_TRANSACTION_METHOD) {
    throw new ProtocolError("protocol_error", "Signing capability payload metadata is unsupported.");
  }
  return {
    chain: SUI_CHAIN_ID,
    method: entry.method,
    ...(entry.payload === undefined ? {} : { payload: sanitizePayloadDeliveryCapability(entry.payload) }),
  };
}

function sanitizeAccount(value: unknown): Account {
  const account = asRecord(value, "Account entry");
  rejectSecretPayload(account, "Account entry");
  if (
    account.chain !== SUI_CHAIN_ID ||
    typeof account.address !== "string" ||
    !SUI_ADDRESS_PATTERN.test(account.address)
  ) {
    throw new ProtocolError("protocol_error", "Account entry is unsupported.");
  }
  if (account.keyScheme === "ed25519") {
    requireOnlyKeys(account, ["chain", "address", "publicKey", "keyScheme", "derivationPath"], "Account entry");
    if (account.derivationPath !== SUI_DERIVATION_PATH) {
      throw new ProtocolError("protocol_error", "Account entry is unsupported.");
    }
    return {
      chain: SUI_CHAIN_ID,
      address: account.address,
      publicKey: validateAccountPublicKey(account.address, account.publicKey, "ed25519"),
      keyScheme: "ed25519",
      derivationPath: SUI_DERIVATION_PATH,
    };
  }
  if (account.keyScheme === "zklogin") {
    requireOnlyKeys(account, ["chain", "address", "publicKey", "keyScheme"], "Account entry");
    return {
      chain: SUI_CHAIN_ID,
      address: account.address,
      publicKey: validateAccountPublicKey(account.address, account.publicKey, "zklogin"),
      keyScheme: "zklogin",
    };
  }
  throw new ProtocolError("protocol_error", "Account entry is unsupported.");
}

function sanitizeSignResultResponse(value: Record<string, unknown>): SignResultResponse {
  if (typeof value.id !== "string" || typeof value.status !== "string") {
    throw new ProtocolError("protocol_error", "Sign result response is malformed.");
  }
  rejectSecretPayload(value, "Sign result response");
  if (value.status === "signed") {
    requireOnlyKeys(value, ["id", "version", "type", "authorization", "status", "chain", "method", "signature", "messageBytes"], "Sign result response");
    if (
      (value.authorization !== "user" && value.authorization !== "policy") ||
      value.chain !== SUI_CHAIN_ID ||
      typeof value.signature !== "string"
    ) {
      throw new ProtocolError("protocol_error", "Sign result response is malformed.");
    }
    if (value.method === SUI_SIGN_TRANSACTION_METHOD) {
      if (value.messageBytes !== undefined) {
        throw new ProtocolError("protocol_error", "Sign result response is malformed.");
      }
      if (!isSuiTransactionSignatureEnvelopeBase64(value.signature)) {
        throw new ProtocolError("protocol_error", "Sign result response is malformed.");
      }
      return {
        id: value.id,
        version: PROTOCOL_VERSION,
        type: "sign_result",
        authorization: value.authorization,
        status: "signed",
        chain: SUI_CHAIN_ID,
        method: SUI_SIGN_TRANSACTION_METHOD,
        signature: value.signature,
      };
    }
    if (value.method === SUI_SIGN_PERSONAL_MESSAGE_METHOD) {
      if (value.authorization !== "user") {
        throw new ProtocolError("protocol_error", "Sign result response is malformed.");
      }
      if (!isSuiPersonalMessageSignatureBase64(value.signature)) {
        throw new ProtocolError("protocol_error", "Sign result response is malformed.");
      }
      const messageBytes = validateCanonicalBase64Syntax(
        value.messageBytes,
        MAX_SIGN_RESULT_PAYLOAD_BASE64_CHARS,
        "sui/sign_personal_message messageBytes",
        "protocol_error",
      );
      return {
        id: value.id,
        version: PROTOCOL_VERSION,
        type: "sign_result",
        authorization: "user",
        status: "signed",
        chain: SUI_CHAIN_ID,
        method: SUI_SIGN_PERSONAL_MESSAGE_METHOD,
        signature: value.signature,
        messageBytes,
      };
    }
    throw new ProtocolError("protocol_error", "Sign result response is malformed.");
  }

  if (value.status === "user_rejected" || value.status === "user_timed_out") {
    requireOnlyKeys(value, ["id", "version", "type", "authorization", "status", "error"], "Sign result response");
    if (value.authorization !== "user") {
      throw new ProtocolError("protocol_error", "Sign result response is malformed.");
    }
    const expectedCode = value.status;
    const error = sanitizeSignResultError(value.error, expectedCode);
    return { id: value.id, version: PROTOCOL_VERSION, type: "sign_result", authorization: "user", status: expectedCode, error };
  }

  if (value.status === "policy_rejected") {
    requireOnlyKeys(value, ["id", "version", "type", "authorization", "status", "policyHash", "ruleRef", "error"], "Sign result response");
    if (
      value.authorization !== "policy" ||
      typeof value.policyHash !== "string" ||
      !HASH_ID_PATTERN.test(value.policyHash) ||
      typeof value.ruleRef !== "string" ||
      !RULE_REF_PATTERN.test(value.ruleRef)
    ) {
      throw new ProtocolError("protocol_error", "Sign result response is malformed.");
    }
    const error = sanitizeSignResultError(value.error, "policy_rejected");
    return {
      id: value.id,
      version: PROTOCOL_VERSION,
      type: "sign_result",
      authorization: "policy",
      status: "policy_rejected",
      policyHash: value.policyHash,
      ruleRef: value.ruleRef,
      error,
    };
  }

  if (value.status === "signing_failed") {
    requireOnlyKeys(value, ["id", "version", "type", "authorization", "status", "error"], "Sign result response");
    if (value.authorization !== "user" && value.authorization !== "policy") {
      throw new ProtocolError("protocol_error", "Sign result response is malformed.");
    }
    const error = sanitizeSignResultError(value.error, "signing_failed");
    return {
      id: value.id,
      version: PROTOCOL_VERSION,
      type: "sign_result",
      authorization: value.authorization,
      status: "signing_failed",
      error,
    };
  }

  throw new ProtocolError("protocol_error", "Sign result response is malformed.");
}

function sanitizeSignResultError<TCode extends SignResultErrorCode>(value: unknown, expectedCode: TCode): { code: TCode; message: string } {
  const error = asRecord(value, "Sign result error");
  requireOnlyKeys(error, ["code", "message"], "Sign result error");
  if (error.code !== expectedCode || error.message !== SIGN_RESULT_ERROR_MESSAGES[expectedCode]) {
    throw new ProtocolError("protocol_error", "Sign result response error is not canonical.");
  }
  return { code: expectedCode, message: SIGN_RESULT_ERROR_MESSAGES[expectedCode] };
}

function sanitizeStrictDeviceStatus(value: unknown, label: string): DeviceStatus {
  const device = asRecord(value, label);
  requireOnlyKeys(device, ["deviceId", "state", "firmwareName", "hardware", "firmwareVersion"], label);
  if (!isSafeDeviceId(device.deviceId) || !isDeviceState(device.state)) {
    throw new ProtocolError("protocol_error", `${label} is malformed.`);
  }
  return {
    deviceId: device.deviceId,
    state: device.state,
    firmwareName: sanitizeDisplayText(device.firmwareName, MAX_FIRMWARE_NAME_LENGTH),
    hardware: sanitizeDisplayText(device.hardware, MAX_HARDWARE_ID_LENGTH),
    firmwareVersion: sanitizeDisplayText(device.firmwareVersion, MAX_FIRMWARE_VERSION_LENGTH),
  };
}

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

export function sanitizeProvisioningStatus(value: unknown): { state: ProvisioningState } | null {
  if (!isRecord(value) || !isProvisioningState(value.state)) {
    return null;
  }
  return { state: value.state };
}
