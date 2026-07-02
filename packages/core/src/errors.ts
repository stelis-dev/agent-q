export class DeviceRequestError extends Error {
  readonly code: string;
  readonly retryable: boolean;

  constructor(code: string, message: string, retryable: boolean) {
    super(message);
    this.name = "DeviceRequestError";
    this.code = code;
    this.retryable = retryable;
  }
}

export function toDeviceRequestError(error: unknown, fallbackCode = "unknown_error"): DeviceRequestError {
  if (error instanceof DeviceRequestError) {
    return error;
  }
  if (error instanceof Error) {
    return new DeviceRequestError(fallbackCode, error.message, true);
  }
  return new DeviceRequestError(fallbackCode, "Agent-Q request failed.", true);
}
