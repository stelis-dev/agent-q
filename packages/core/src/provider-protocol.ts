import {
  MAX_FIRMWARE_NAME_LENGTH,
  MAX_FIRMWARE_VERSION_LENGTH,
  MAX_HARDWARE_ID_LENGTH,
  isDeviceState,
  isProvisioningState,
  isSafeDeviceId,
  isSessionId,
  sanitizeDisplayText,
  type DeviceState,
  type ProvisioningState,
} from "./safe-text.js";
import { ProtocolError } from "./protocol-error.js";
import {
  SIGN_RESULT_ERROR_MESSAGES,
  type SignResultErrorCode,
} from "./device-contract.js";
import {
  ED25519_PUBLIC_KEY_BASE64_PATTERN,
  CREDENTIAL_PREPARE_OPERATION,
  CREDENTIAL_PROPOSE_OPERATION,
  MAX_SUI_ZKLOGIN_PUBLIC_KEY_BYTES,
  MAX_ACCOUNTS_PER_RESPONSE,
  MAX_CAPABILITY_ACCOUNTS_PER_CHAIN,
  MAX_CAPABILITY_CHAINS,
  MAX_CREDENTIAL_CAPABILITIES,
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
  consumeDeviceResponseLineChunk,
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
  validateCanonicalBase64Bytes,
  validateCanonicalBase64Syntax,
  validateSuiSignTransactionNetwork,
  type SuiSignMethod,
  type SuiSignTransactionNetwork,
} from "./protocol-primitives.js";
import {
  identifySignRoute,
  type SignOperationType,
  type SupportedSignRoute,
} from "./protocol-sign-routes.js";

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
  consumeDeviceResponseLineChunk,
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

export interface SignTransactionParams {
  network: SuiSignTransactionNetwork;
  txBytes: string;
}

export interface SignPersonalMessageParams {
  network: SuiSignTransactionNetwork;
  message: string;
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

export interface SigningCapabilityEntry {
  chain: typeof SUI_CHAIN_ID;
  method: SuiSignMethod;
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

export interface AccountSponsoredTransactions {
  acceptGasSponsor: boolean;
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
      sponsoredTransactions: AccountSponsoredTransactions;
    }
  | {
      chain: typeof SUI_CHAIN_ID;
      address: string;
      publicKey: string;
      keyScheme: "zklogin";
      sponsoredTransactions: AccountSponsoredTransactions;
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
