import {
  DEVICE_ERROR_ROWS,
  deviceErrorRow,
  isDeviceErrorCode,
  type DeviceErrorCode,
} from "./device-contract.js";
import { toDeviceRequestError } from "./errors.js";

// Projection of Agent-Q's device-contract error table for untrusted output
// boundaries such as MCP and the Admin HTTP API.
//
// Contract: Agent-Q core (and the modules it calls) may throw a raw DeviceRequestError
// whose message carries OS, serial, or Firmware text that Agent-Q did not author.
// Core is NOT required to pre-sanitize errors; safety lives at the output
// boundary. Therefore every output adapter MUST project errors through this
// module (toPublicError / normalizeErrorCode) before returning OR logging them,
// so the raw message is dropped and only an allowlisted code maps to a fixed
// message (any unknown code collapses to unknown_error).

export const GENERIC_ERROR_CODE = "unknown_error" satisfies DeviceErrorCode;

export const PUBLIC_ERROR_MESSAGES = Object.fromEntries(
  DEVICE_ERROR_ROWS.map((row) => [row.code, row.message]),
) as Readonly<Record<DeviceErrorCode, string>>;

export interface PublicError {
  code: DeviceErrorCode;
  message: string;
  retryable: boolean;
}

// Keep allowlisted codes, collapse everything else to `unknown_error`. Used for
// both error objects and diagnostic codes (e.g. firmwareErrorCode), so a device-
// or OS-supplied code string can never reach a consumer verbatim.
export function normalizeErrorCode(code: string): DeviceErrorCode {
  return isDeviceErrorCode(code) ? code : GENERIC_ERROR_CODE;
}

// Canonical { code, message, retryable } from a raw code. Shared by every output
// boundary so they all follow the same table and never echo a raw message.
export function toPublicError(code: string, _retryable?: boolean): PublicError {
  const normalized = normalizeErrorCode(code);
  const row = deviceErrorRow(normalized);
  return { code: row.code, message: row.message, retryable: row.retryable };
}

export function toPublicErrorFromUnknown(error: unknown): PublicError {
  const requestError = toDeviceRequestError(error);
  return toPublicError(requestError.code, requestError.retryable);
}
