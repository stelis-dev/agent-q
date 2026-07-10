const FIRMWARE_SESSION_INVALIDATED = Symbol("signing.firmwareSessionInvalidated");

/** @internal Package-private side channel consumed before host projection. */
export function markFirmwareSessionInvalidated<T>(value: T): T {
  if ((typeof value === "object" && value !== null) || typeof value === "function") {
    try {
      Object.defineProperty(value, FIRMWARE_SESSION_INVALIDATED, {
        value: true,
        configurable: true,
      });
    } catch {
      // Some Error-like or response-like objects may be non-extensible.
    }
  }
  return value;
}

/** @internal Package-private side channel consumed before host projection. */
export function consumeFirmwareSessionInvalidated(value: unknown): boolean {
  if (
    value === null ||
    (typeof value !== "object" && typeof value !== "function") ||
    (value as { [FIRMWARE_SESSION_INVALIDATED]?: boolean })[FIRMWARE_SESSION_INVALIDATED] !== true
  ) {
    return false;
  }
  try {
    delete (value as { [FIRMWARE_SESSION_INVALIDATED]?: boolean })[FIRMWARE_SESSION_INVALIDATED];
  } catch {
    // Metadata is non-public and non-enumerable; failure to delete is harmless.
  }
  return true;
}
