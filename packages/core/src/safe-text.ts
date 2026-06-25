// Single source of truth (SoT) for string-policy validation and sanitization
// at every Agent-Q trust boundary:
//   - wire ingress   (protocol.ts DeviceResponse assertions): device-supplied text
//   - disk ingress   (config.ts load): the stored, possibly hand-edited registry
//   - MCP egress      (mcp.ts output schemas): the untrusted client/agent surface
//   - MCP input + request building (mcp.ts input schemas, protocol.ts make*)
//
// Two policies, applied with different failure behavior:
//   - Identifiers (deviceId, requestId, sessionId, purpose, clientName) have a
//     strict format. Invalid values are REJECTED so the caller corrects them; an
//     identifier is never silently rewritten.
//   - Display text (firmwareName, hardware, firmwareVersion, port hints) is
//     untrusted device-/OS-supplied text. It is STRIPPED to bounded printable
//     ASCII and never rejected, so one malformed device cannot brick discovery.
//
// This module imports nothing else from Agent-Q. It is the leaf that every
// boundary depends on, so there is exactly one definition of each rule.
//
// Control characters (C0 range and DEL) are detected by code-point scan rather
// than by a regex literal, so this source file never contains raw control bytes.

export const DEVICE_STATES = ["idle", "busy", "awaiting_approval", "locked", "error"] as const;
export const PROVISIONING_STATES = ["unprovisioned", "provisioning", "provisioned", "locked", "error"] as const;

export type DeviceState = (typeof DEVICE_STATES)[number];
export type ProvisioningState = (typeof PROVISIONING_STATES)[number];

// Identifier formats. deviceId and requestId share a character class but differ
// in length bound, so each boundary states its own limit explicitly.
export const DEVICE_ID_PATTERN = /^[A-Za-z0-9_.-]{1,128}$/;
export const REQUEST_ID_PATTERN = /^[A-Za-z0-9_.-]{1,79}$/;
export const SESSION_ID_PATTERN = /^session_[0-9a-f]{1,128}$/;
export const PURPOSE_PATTERN = /^[A-Za-z0-9_.-]{1,32}$/;
// Printable ASCII only: space (0x20) through tilde (0x7E).
export const CLIENT_NAME_PATTERN = /^[\x20-\x7E]{1,64}$/;
// Firmware identification code: exactly four decimal digits.
export const IDENTIFICATION_CODE_PATTERN = /^[0-9]{4}$/;

// Display-text length bounds (printable ASCII; see sanitizeDisplayText).
export const MAX_FIRMWARE_NAME_LENGTH = 64;
export const MAX_HARDWARE_ID_LENGTH = 64;
export const MAX_FIRMWARE_VERSION_LENGTH = 32;
export const MAX_PORT_HINT_LENGTH = 128;
export const MAX_LABEL_LENGTH = 64;

// 'default' is reserved: the default device lives in activeDeviceId, never in
// activeDeviceIdsByPurpose.
export const RESERVED_PURPOSES: ReadonlySet<string> = new Set(["default"]);

// Names that are unsafe as plain-object keys. A purpose string becomes a key of
// the activeDeviceIdsByPurpose map, so "__proto__" would set the prototype
// instead of an own entry (the routing would silently vanish), and
// "constructor"/"prototype" would shadow built-ins. They are rejected even
// though they match PURPOSE_PATTERN. Reads of that map additionally use
// own-property lookups (see config.ts/core.ts) so inherited names such as
// "toString" or "hasOwnProperty" can never resolve to an inherited value.
export const PROTOTYPE_KEYS: ReadonlySet<string> = new Set(["__proto__", "prototype", "constructor"]);

// Printable ASCII: space (0x20) through tilde (0x7E). Excludes C0 controls, DEL
// (0x7F), and every byte >= 0x80, so sanitized text is safe to embed in the MCP
// JSON output stream.
export const PRINTABLE_ASCII_ONLY = /^[\x20-\x7E]*$/;
const NON_PRINTABLE_ASCII = /[^\x20-\x7E]/g;

// ISO-8601 instant with optional milliseconds and a Z or +hh:mm offset.
export const ISO_TIMESTAMP_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/;

// True if value contains a character that is unsafe in label output: a C0
// control (0x00-0x1F), DEL (0x7F), a C1 control (0x80-0x9F), or a Unicode
// line/paragraph separator (U+2028/U+2029). Other printable Unicode (accented or
// CJK text, emoji) is allowed, so this only narrows the label policy; device
// display strings are already reduced to printable ASCII by sanitizeDisplayText.
// A code-point scan avoids a control-character regex literal so this source file
// stays plain text.
function containsControlChar(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (
      code <= 0x1f ||
      code === 0x7f ||
      (code >= 0x80 && code <= 0x9f) ||
      code === 0x2028 ||
      code === 0x2029
    ) {
      return true;
    }
  }
  return false;
}

export function isDeviceState(value: unknown): value is DeviceState {
  return typeof value === "string" && (DEVICE_STATES as readonly string[]).includes(value);
}

export function isProvisioningState(value: unknown): value is ProvisioningState {
  return typeof value === "string" && (PROVISIONING_STATES as readonly string[]).includes(value);
}

export function isSafeDeviceId(value: unknown): value is string {
  return typeof value === "string" && DEVICE_ID_PATTERN.test(value);
}

export function isSafeRequestId(value: unknown): value is string {
  return typeof value === "string" && REQUEST_ID_PATTERN.test(value);
}

export function isSessionId(value: unknown): value is string {
  return typeof value === "string" && SESSION_ID_PATTERN.test(value);
}

export function isClientName(value: unknown): value is string {
  return typeof value === "string" && CLIENT_NAME_PATTERN.test(value);
}

export function isValidPurpose(value: unknown): value is string {
  return (
    typeof value === "string" &&
    PURPOSE_PATTERN.test(value) &&
    !RESERVED_PURPOSES.has(value) &&
    !PROTOTYPE_KEYS.has(value)
  );
}

// A label is a user-supplied display name (a request input). It is rejected —
// not rewritten — when empty, too long, or carrying control characters, so the
// caller can correct it. Spaces and other printable characters are allowed.
export function isValidLabel(value: unknown): value is string | null {
  if (value === null) {
    return true;
  }
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= MAX_LABEL_LENGTH &&
    !containsControlChar(value)
  );
}

// Predicate counterpart of sanitizeDisplayText (the producer). Retained as the
// SoT's explicit "is this already-safe display text?" check for callers and
// tests that need a boolean. The MCP egress expresses the identical rule as
// z.string().regex(PRINTABLE_ASCII_ONLY).max(maxLength) so the constraint also
// appears in the published JSON Schema; this predicate is the same rule in
// imperative form.
export function isSafeDisplayText(value: unknown, maxLength: number): value is string {
  return typeof value === "string" && value.length <= maxLength && PRINTABLE_ASCII_ONLY.test(value);
}

export function isIsoTimestamp(value: unknown): value is string {
  return (
    typeof value === "string" &&
    ISO_TIMESTAMP_PATTERN.test(value) &&
    Number.isFinite(Date.parse(value))
  );
}

// Reduce untrusted device-/OS-supplied text to bounded printable ASCII. Strips
// every non-printable byte and caps the result; never throws and never rejects,
// so a malformed string degrades to safe text instead of failing the request. A
// non-string input becomes "".
export function sanitizeDisplayText(value: unknown, maxLength: number): string {
  if (typeof value !== "string") {
    return "";
  }
  const stripped = value.replace(NON_PRINTABLE_ASCII, "");
  return stripped.length > maxLength ? stripped.slice(0, maxLength) : stripped;
}

// Port hints are OS-supplied diagnostic strings (for example "/dev/cu.usbmodem1"
// or "COM3"), not identifiers, so they are sanitized as display text.
export function sanitizePortHint(value: unknown): string {
  return sanitizeDisplayText(value, MAX_PORT_HINT_LENGTH);
}
