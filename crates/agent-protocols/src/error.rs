use thiserror::Error;

pub type Result<T> = std::result::Result<T, SdkError>;

#[derive(Debug, Error)]
pub enum SdkError {
    #[error("invalid agent id: {0}")]
    InvalidAgentId(String),

    #[error("agent id must start with did:agent:")]
    InvalidAgentIdPrefix,

    #[error("invalid public key length: expected 32 bytes, got {0}")]
    InvalidPublicKeyLength(usize),

    #[error("canonical JSON error: {0}")]
    CanonicalJson(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("base64url decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Ed25519 error: {0}")]
    Ed25519(#[from] ed25519_dalek::SignatureError),

    #[error("random generation error: {0}")]
    Random(String),

    #[error("invalid signature length: expected 64 bytes, got {0}")]
    InvalidSignatureLength(usize),

    #[error("invalid event hash: expected {expected}, got {actual}")]
    InvalidEventHash { expected: String, actual: String },

    #[error("invalid event hash length: expected 32 bytes, got {0}")]
    InvalidEventHashLength(usize),

    #[error("invalid event protocol: expected {expected}, got {actual}")]
    InvalidEventProtocol { expected: String, actual: String },

    #[error("invalid event type: expected {expected}, got {actual}")]
    InvalidEventType { expected: String, actual: String },

    #[error("invalid actor: {0}")]
    InvalidActor(String),

    #[error("timestamp is outside the allowed live-write window")]
    TimestampOutOfWindow,

    #[error("invalid nonce: {0}")]
    InvalidNonce(String),

    #[error("nonce must be greater than accepted max nonce {max_nonce}")]
    NonceNotGreater { max_nonce: u64 },

    #[error("event requires a room_id")]
    MissingRoomId,

    #[error("room id mismatch: expected {expected}, got {actual}")]
    RoomIdMismatch { expected: String, actual: String },

    #[error("permission denied")]
    PermissionDenied,

    #[error("invalid payload: {0}")]
    InvalidPayload(String),

    #[error("event type is not defined in the room: {0}")]
    TypeNotDefined(String),

    #[error("event type is disabled in the room: {0}")]
    TypeDisabled(String),

    #[error("payload does not satisfy the type schema: {0}")]
    PayloadSchemaViolation(String),

    #[error("type pack cannot be resolved or fails verification: {0}")]
    PackUnavailable(String),

    #[error("invalid JWT: {0}")]
    InvalidJwt(String),

    #[error("invalid JWT claim: {0}")]
    InvalidJwtClaim(&'static str),

    /// A protocol error identified by its Agent Protocols error code.
    #[error("{code}: {message}")]
    Protocol { code: &'static str, message: String },

    /// A protocol error with machine-readable error data.
    #[error("{code}: {message}")]
    ProtocolWithData {
        code: &'static str,
        message: String,
        data: serde_json::Value,
    },

    /// A client-side page budget ended before a paginated read completed.
    #[error("paginated read did not complete within {0} pages")]
    PageLimitExceeded(usize),

    /// A non-2xx response. `code` and `data` come from the Agent Identity
    /// error body when the service sent one; `max_seen_nonce` from the
    /// `Max-Seen-Nonce` header.
    #[error("HTTP {status}: {body}")]
    HttpStatus {
        status: u16,
        code: Option<String>,
        data: Option<serde_json::Value>,
        max_seen_nonce: Option<String>,
        body: String,
    },

    #[cfg(feature = "http-client")]
    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),
}

impl SdkError {
    /// Builds a [`SdkError::Protocol`] error.
    pub fn protocol(code: &'static str, message: impl Into<String>) -> Self {
        Self::Protocol {
            code,
            message: message.into(),
        }
    }

    pub fn protocol_with_data(
        code: &'static str,
        message: impl Into<String>,
        data: serde_json::Value,
    ) -> Self {
        Self::ProtocolWithData {
            code,
            message: message.into(),
            data,
        }
    }

    pub fn data(&self) -> Option<&serde_json::Value> {
        match self {
            Self::ProtocolWithData { data, .. } => Some(data),
            Self::HttpStatus { data, .. } => data.as_ref(),
            _ => None,
        }
    }

    /// The Agent Protocols error code this error corresponds to, when there is one.
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Protocol { code, .. } | Self::ProtocolWithData { code, .. } => Some(code),
            Self::HttpStatus { code, .. } => code.as_deref(),
            Self::InvalidSignatureLength(_) | Self::Ed25519(_) => Some("invalid_signature"),
            Self::InvalidEventHash { .. } | Self::InvalidEventHashLength(_) => {
                Some("invalid_event_hash")
            }
            Self::TimestampOutOfWindow => Some("timestamp_out_of_window"),
            Self::NonceNotGreater { .. } => Some("nonce_not_greater"),
            Self::PermissionDenied => Some("permission_denied"),
            Self::TypeNotDefined(_) => Some("type_not_defined"),
            Self::TypeDisabled(_) => Some("type_disabled"),
            Self::PayloadSchemaViolation(_) => Some("payload_schema_violation"),
            Self::PackUnavailable(_) => Some("pack_unavailable"),
            Self::InvalidJwt(_) | Self::InvalidJwtClaim(_) => Some("invalid_token"),
            Self::InvalidActor(_) => Some("invalid_actor"),
            _ => None,
        }
    }
}
