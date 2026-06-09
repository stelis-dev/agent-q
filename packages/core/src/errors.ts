export class AgentQError extends Error {
  readonly code: string;
  readonly retryable: boolean;

  constructor(code: string, message: string, retryable: boolean) {
    super(message);
    this.name = "AgentQError";
    this.code = code;
    this.retryable = retryable;
  }
}

export function toAgentQError(error: unknown, fallbackCode = "agent_q_error"): AgentQError {
  if (error instanceof AgentQError) {
    return error;
  }
  if (error instanceof Error) {
    return new AgentQError(fallbackCode, error.message, true);
  }
  return new AgentQError(fallbackCode, "Agent-Q request failed.", true);
}
