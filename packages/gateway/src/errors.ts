export class GatewayError extends Error {
  readonly code: string;
  readonly retryable: boolean;

  constructor(code: string, message: string, retryable: boolean) {
    super(message);
    this.name = "GatewayError";
    this.code = code;
    this.retryable = retryable;
  }
}

export function toGatewayError(error: unknown, fallbackCode = "gateway_error"): GatewayError {
  if (error instanceof GatewayError) {
    return error;
  }
  if (error instanceof Error) {
    return new GatewayError(fallbackCode, error.message, true);
  }
  return new GatewayError(fallbackCode, "Gateway request failed.", true);
}
