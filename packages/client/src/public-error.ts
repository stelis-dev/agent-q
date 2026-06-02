// Single source of truth (SoT) for Gateway's public error policy: the canonical,
// client-safe { code, message, retryable } shown at any untrusted output boundary
// such as MCP and the Admin HTTP API.
//
// Contract: Gateway core (and the modules it calls) may throw a raw GatewayError
// whose message carries OS, serial, or Firmware text that Gateway did not author.
// Core is NOT required to pre-sanitize errors; safety lives at the output
// boundary. Therefore every output adapter MUST project errors through this
// module (toPublicError / normalizeErrorCode) before returning OR logging them,
// so the raw message is dropped and only an allowlisted code maps to a fixed
// message (any unknown code collapses to gateway_error). This module imports
// nothing else from Gateway, so every boundary can depend on it without pulling
// in MCP.

export const GENERIC_ERROR_CODE = "gateway_error";

// Canonical, client-safe messages keyed by error code. The raw error message can
// carry OS serial, Firmware, or arbitrary Error text that is not authored by
// Gateway, so it is never forwarded to an untrusted consumer. Any code outside
// this allowlist is reported as the generic `gateway_error`.
export const PUBLIC_ERROR_MESSAGES: Record<string, string> = {
  no_active_device: "No active device is configured.",
  device_not_found: "The requested device is not known to Gateway.",
  invalid_device_id: "The provided deviceId is invalid.",
  invalid_device: "The device reported an unsafe identity.",
  invalid_metadata: "No metadata field was provided to update.",
  invalid_label: "The provided label is invalid.",
  reserved_purpose: "That purpose name is reserved.",
  invalid_purpose: "The provided purpose is invalid.",
  invalid_timeout: "The provided timeout is invalid.",
  invalid_duration: "The provided duration is invalid.",
  invalid_gateway_name: "The provided gateway name is invalid.",
  invalid_approval_timeout: "The provided approval timeout is invalid.",
  invalid_method: "The requested method is invalid.",
  invalid_params: "The provided method parameters are invalid.",
  invalid_id: "The request id is invalid.",
  invalid_json: "The device sent a malformed response.",
  invalid_code: "The identification code is invalid.",
  invalid_session: "The session is no longer valid.",
  invalid_state: "The device is not in a valid state for this request.",
  policy_error: "The device active policy is unavailable.",
  history_error: "The device approval history is unavailable.",
  unsupported_version: "The device firmware protocol version is not supported.",
  unsupported_type: "The device does not support this request.",
  unsupported_method: "The requested method is not supported.",
  incompatible_version: "The device firmware protocol version is not supported.",
  protocol_error: "The device sent an unexpected response.",
  timeout: "The device did not respond in time.",
  busy: "The device is busy with another request.",
  rejected: "The request was rejected on the device.",
  rng_error: "The device secure random generator is unavailable.",
  account_error: "The device could not derive the requested accounts.",
  handshake_failed: "The device did not respond to a status handshake.",
  port_not_found: "The device is not connected.",
  port_in_use: "The device port is in use by another process.",
  transport_closed: "The device connection was closed.",
  identification_code_exhausted: "Could not allocate a unique identification code.",
  internal_output_error: "Gateway produced an unexpected internal result.",
  gateway_error: "Gateway request failed.",
};

export interface PublicError {
  code: string;
  message: string;
  retryable: boolean;
}

// Keep allowlisted codes, collapse everything else to `gateway_error`. Used for
// both error objects and diagnostic codes (e.g. firmwareErrorCode), so a device-
// or OS-supplied code string can never reach a consumer verbatim.
export function normalizeErrorCode(code: string): string {
  return Object.prototype.hasOwnProperty.call(PUBLIC_ERROR_MESSAGES, code)
    ? code
    : GENERIC_ERROR_CODE;
}

// Canonical { code, message, retryable } from a raw code. Shared by every output
// boundary so they all follow the same allowlist and never echo a raw message.
export function toPublicError(code: string, retryable: boolean): PublicError {
  const normalized = normalizeErrorCode(code);
  return { code: normalized, message: PUBLIC_ERROR_MESSAGES[normalized], retryable };
}
