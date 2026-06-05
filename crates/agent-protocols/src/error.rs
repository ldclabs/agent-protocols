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

    #[error("invalid JWT: {0}")]
    InvalidJwt(String),

    #[error("invalid JWT claim: {0}")]
    InvalidJwtClaim(&'static str),

    #[cfg(feature = "http-client")]
    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),
}
