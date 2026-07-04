export class AgentProtocolError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    /** Structured error details, e.g. `{ max_nonce }` on `nonce_not_greater`. */
    public readonly data?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "AgentProtocolError";
  }
}

export function protocolError(
  code: string,
  message: string,
  data?: Record<string, unknown>,
): AgentProtocolError {
  return new AgentProtocolError(code, message, data);
}
