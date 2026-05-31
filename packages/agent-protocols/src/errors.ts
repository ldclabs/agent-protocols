export class AgentProtocolError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "AgentProtocolError";
  }
}

export function protocolError(
  code: string,
  message: string,
): AgentProtocolError {
  return new AgentProtocolError(code, message);
}
