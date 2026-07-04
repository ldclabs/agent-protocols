class AgentProtocolError(ValueError):
    def __init__(self, code: str, message: str, data: dict | None = None):
        super().__init__(message)
        self.code = code
        # Structured error details, e.g. {"max_nonce": ...} on nonce_not_greater.
        self.data = data
