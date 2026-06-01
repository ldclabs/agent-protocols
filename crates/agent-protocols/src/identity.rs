use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use multibase::Base;
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Result, SdkError};

pub const AGENT_ID_PREFIX: &str = "did:agent:";
pub const EVENT_ID_PREFIX: &str = "evt_";
pub const DEFAULT_LIVE_WRITE_WINDOW_MS: i64 = 300_000;
pub const DEFAULT_REQUEST_JWT_TTL_SECS: i64 = 300;
const REQUEST_AUTH_REPLAY_SCOPE: &str = "agent-identity/request-auth";

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct AgentId(String);

impl AgentId {
    pub fn from_public_key(public_key: &[u8; 32]) -> Self {
        Self(format!(
            "{}{}",
            AGENT_ID_PREFIX,
            multibase::encode(Base::Base58Btc, public_key)
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn public_key_bytes(&self) -> Result<[u8; 32]> {
        let encoded = self
            .0
            .strip_prefix(AGENT_ID_PREFIX)
            .ok_or(SdkError::InvalidAgentIdPrefix)?;
        let (base, bytes) =
            multibase::decode(encoded).map_err(|err| SdkError::Multibase(err.to_string()))?;
        if base != Base::Base58Btc {
            return Err(SdkError::UnsupportedAgentIdEncoding);
        }
        bytes
            .try_into()
            .map_err(|bytes: Vec<u8>| SdkError::InvalidPublicKeyLength(bytes.len()))
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        Ok(VerifyingKey::from_bytes(&self.public_key_bytes()?)?)
    }
}

impl fmt::Debug for AgentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("AgentId").field(&self.0).finish()
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for AgentId {
    type Err = SdkError;

    fn from_str(value: &str) -> Result<Self> {
        if !value.starts_with(AGENT_ID_PREFIX) {
            return Err(SdkError::InvalidAgentIdPrefix);
        }
        let agent_id = Self(value.to_owned());
        agent_id.public_key_bytes()?;
        Ok(agent_id)
    }
}

impl TryFrom<String> for AgentId {
    type Error = SdkError;

    fn try_from(value: String) -> Result<Self> {
        Self::from_str(&value)
    }
}

impl Serialize for AgentId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for AgentId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(D::Error::custom)
    }
}

pub struct AgentSigner {
    signing_key: SigningKey,
}

impl AgentSigner {
    pub fn generate() -> Self {
        let mut seed = [0_u8; 32];
        rand::fill(&mut seed);
        Self::from_seed(seed)
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn agent_id(&self) -> AgentId {
        AgentId::from_public_key(&self.signing_key.verifying_key().to_bytes())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn sign_event<P>(&self, event: Event<P>) -> Result<Envelope<P>>
    where
        P: Serialize,
    {
        let event_id = event_id(&event)?;
        let signature = sign_event(&self.signing_key, &event)?;
        Ok(Envelope {
            event_id,
            event,
            signature,
        })
    }

    pub fn sign_request_jwt(&self, claims: &RequestJwtClaims) -> Result<String> {
        let agent_id = self.agent_id();
        if claims.iss != agent_id || claims.sub != agent_id {
            return Err(SdkError::InvalidJwtClaim("iss/sub"));
        }

        let header = RequestJwtHeader {
            alg: "EdDSA".to_owned(),
            typ: "JWT".to_owned(),
            kid: agent_id,
        };
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?);
        let signing_input = format!("{header}.{payload}");
        let signature = self.signing_key.sign(signing_input.as_bytes());
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Event<P = Value> {
    pub protocol: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub actor: AgentId,
    pub created_at: i64,
    pub nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room_id: Option<String>,
    pub payload: P,
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl<P> Event<P> {
    pub fn new(
        protocol: impl Into<String>,
        kind: impl Into<String>,
        actor: AgentId,
        created_at: i64,
        nonce: impl Into<String>,
        payload: P,
    ) -> Self {
        Self {
            protocol: protocol.into(),
            kind: kind.into(),
            actor,
            created_at,
            nonce: nonce.into(),
            room_id: None,
            payload,
            extra: BTreeMap::new(),
        }
    }

    pub fn with_room_id(mut self, room_id: impl Into<String>) -> Self {
        self.room_id = Some(room_id.into());
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Envelope<P = Value> {
    pub event_id: String,
    pub event: Event<P>,
    pub signature: String,
}

pub fn canonical_event_bytes<P>(event: &Event<P>) -> Result<Vec<u8>>
where
    P: Serialize,
{
    serde_jcs::to_vec(event).map_err(|err| SdkError::CanonicalJson(err.to_string()))
}

pub fn event_id<P>(event: &Event<P>) -> Result<String>
where
    P: Serialize,
{
    let digest = Sha256::digest(canonical_event_bytes(event)?);
    Ok(format!(
        "{}{}",
        EVENT_ID_PREFIX,
        multibase::encode(Base::Base58Btc, digest)
    ))
}

pub fn sign_event<P>(signing_key: &SigningKey, event: &Event<P>) -> Result<String>
where
    P: Serialize,
{
    let bytes = canonical_event_bytes(event)?;
    let signature = signing_key.sign(&bytes);
    Ok(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

pub fn verify_event_id<P>(envelope: &Envelope<P>) -> Result<()>
where
    P: Serialize,
{
    let expected = event_id(&envelope.event)?;
    if expected == envelope.event_id {
        Ok(())
    } else {
        Err(SdkError::InvalidEventId {
            expected,
            actual: envelope.event_id.clone(),
        })
    }
}

pub fn verify_signature<P>(envelope: &Envelope<P>) -> Result<()>
where
    P: Serialize,
{
    let bytes = canonical_event_bytes(&envelope.event)?;
    let signature_bytes = URL_SAFE_NO_PAD.decode(&envelope.signature)?;
    let signature_bytes: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| SdkError::InvalidSignatureLength(bytes.len()))?;
    let signature = Signature::from_bytes(&signature_bytes);
    envelope
        .event
        .actor
        .verifying_key()?
        .verify_strict(&bytes, &signature)?;
    Ok(())
}

pub fn verify_envelope<P>(envelope: &Envelope<P>) -> Result<()>
where
    P: Serialize,
{
    verify_event_id(envelope)?;
    verify_signature(envelope)
}

pub fn verify_timestamp(created_at: i64, now_ms: i64, window_ms: i64) -> Result<()> {
    if window_ms < 0 || created_at.abs_diff(now_ms) > window_ms as u64 {
        Err(SdkError::TimestampOutOfWindow)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum NonceScopeKind {
    #[default]
    ActorProtocol,
    ActorRoom,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct NonceScope {
    pub actor: AgentId,
    pub protocol: String,
    pub room_id: Option<String>,
    pub nonce: String,
}

impl NonceScope {
    pub fn for_event<P>(event: &Event<P>, kind: NonceScopeKind) -> Self {
        Self {
            actor: event.actor.clone(),
            protocol: event.protocol.clone(),
            room_id: match kind {
                NonceScopeKind::ActorProtocol => None,
                NonceScopeKind::ActorRoom => event.room_id.clone(),
            },
            nonce: event.nonce.clone(),
        }
    }
}

pub trait NonceStore {
    fn check_and_insert(&mut self, scope: NonceScope) -> Result<()>;
}

#[derive(Clone, Debug, Default)]
pub struct MemoryNonceStore {
    seen: HashSet<NonceScope>,
}

impl MemoryNonceStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl NonceStore for MemoryNonceStore {
    fn check_and_insert(&mut self, scope: NonceScope) -> Result<()> {
        if self.seen.insert(scope) {
            Ok(())
        } else {
            Err(SdkError::NonceReused)
        }
    }
}

#[derive(Clone, Debug)]
pub struct LiveWriteOptions {
    pub now_ms: i64,
    pub window_ms: i64,
    pub nonce_scope: NonceScopeKind,
}

impl Default for LiveWriteOptions {
    fn default() -> Self {
        Self {
            now_ms: unix_time_millis(),
            window_ms: DEFAULT_LIVE_WRITE_WINDOW_MS,
            nonce_scope: NonceScopeKind::ActorProtocol,
        }
    }
}

pub fn verify_live_envelope<P, S>(
    envelope: &Envelope<P>,
    options: &LiveWriteOptions,
    nonce_store: &mut S,
) -> Result<()>
where
    P: Serialize,
    S: NonceStore,
{
    verify_envelope(envelope)?;
    verify_timestamp(envelope.event.created_at, options.now_ms, options.window_ms)?;
    nonce_store.check_and_insert(NonceScope::for_event(&envelope.event, options.nonce_scope))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestJwtHeader {
    pub alg: String,
    pub typ: String,
    pub kid: AgentId,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestJwtClaims {
    pub iss: AgentId,
    pub sub: AgentId,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestBinding {
    pub audience: String,
}

impl RequestBinding {
    pub fn new(audience: impl Into<String>) -> Self {
        Self {
            audience: audience.into(),
        }
    }
}

impl RequestJwtClaims {
    pub fn new(
        agent_id: AgentId,
        binding: RequestBinding,
        issued_at: i64,
        ttl_secs: i64,
        jti: impl Into<String>,
    ) -> Self {
        Self {
            iss: agent_id.clone(),
            sub: agent_id,
            aud: binding.audience,
            iat: issued_at,
            exp: issued_at + ttl_secs,
            jti: jti.into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RequestAuthContext {
    pub audience: String,
    pub now_secs: i64,
    pub max_ttl_secs: i64,
}

impl RequestAuthContext {
    pub fn new(audience: impl Into<String>) -> Self {
        let binding = RequestBinding::new(audience);
        Self {
            audience: binding.audience,
            now_secs: unix_time_secs(),
            max_ttl_secs: DEFAULT_REQUEST_JWT_TTL_SECS,
        }
    }
}

pub fn verify_request_jwt(token: &str, context: &RequestAuthContext) -> Result<RequestJwtClaims> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(SdkError::InvalidJwt(
            "expected three compact JWS parts".into(),
        ));
    }

    let header: RequestJwtHeader = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
    let claims: RequestJwtClaims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
    let signature_bytes = URL_SAFE_NO_PAD.decode(parts[2])?;
    let signature_bytes: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| SdkError::InvalidSignatureLength(bytes.len()))?;
    let signature = Signature::from_bytes(&signature_bytes);
    let signing_input = format!("{}.{}", parts[0], parts[1]);

    if header.alg != "EdDSA" {
        return Err(SdkError::InvalidJwtClaim("alg"));
    }
    if header.typ != "JWT" {
        return Err(SdkError::InvalidJwtClaim("typ"));
    }
    if header.kid != claims.iss || claims.iss != claims.sub {
        return Err(SdkError::InvalidJwtClaim("kid/iss/sub"));
    }

    header
        .kid
        .verifying_key()?
        .verify_strict(signing_input.as_bytes(), &signature)?;

    if claims.aud != context.audience {
        return Err(SdkError::InvalidJwtClaim("aud"));
    }
    if claims.iat > context.now_secs || claims.exp < context.now_secs {
        return Err(SdkError::InvalidJwtClaim("iat/exp"));
    }
    if claims.exp - claims.iat > context.max_ttl_secs {
        return Err(SdkError::InvalidJwtClaim("ttl"));
    }

    Ok(claims)
}

pub fn verify_request_jwt_live<S>(
    token: &str,
    context: &RequestAuthContext,
    nonce_store: &mut S,
) -> Result<RequestJwtClaims>
where
    S: NonceStore,
{
    let claims = verify_request_jwt(token, context)?;
    nonce_store.check_and_insert(NonceScope {
        actor: claims.iss.clone(),
        protocol: REQUEST_AUTH_REPLAY_SCOPE.to_owned(),
        room_id: None,
        nonce: claims.jti.clone(),
    })?;
    Ok(claims)
}

pub fn unix_time_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

pub fn unix_time_secs() -> i64 {
    unix_time_millis() / 1000
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn signs_and_verifies_event_envelope() {
        let signer = AgentSigner::from_seed([7; 32]);
        let event = Event::new(
            "agent-profile/1.0",
            "profile.update",
            signer.agent_id(),
            1_779_753_600_000,
            "n_test",
            json!({"agent_id": signer.agent_id(), "name": "ResearchAgent"}),
        );

        let envelope = signer.sign_event(event).unwrap();

        assert!(envelope.event_id.starts_with("evt_z"));
        verify_envelope(&envelope).unwrap();
    }

    #[test]
    fn rejects_tampered_event_payload() {
        let signer = AgentSigner::from_seed([8; 32]);
        let event = Event::new(
            "agent-profile/1.0",
            "profile.update",
            signer.agent_id(),
            1_779_753_600_000,
            "n_test",
            json!({"name": "before"}),
        );
        let mut envelope = signer.sign_event(event).unwrap();
        envelope.event.payload = json!({"name": "after"});

        assert!(verify_envelope(&envelope).is_err());
    }

    #[test]
    fn rejects_nonce_reuse() {
        let signer = AgentSigner::from_seed([9; 32]);
        let options = LiveWriteOptions {
            now_ms: 1000,
            window_ms: 1000,
            nonce_scope: NonceScopeKind::ActorProtocol,
        };
        let event = Event::new(
            "agent-profile/1.0",
            "profile.update",
            signer.agent_id(),
            1000,
            "n_reused",
            json!({"name": "ResearchAgent"}),
        );
        let envelope = signer.sign_event(event).unwrap();
        let mut store = MemoryNonceStore::new();

        verify_live_envelope(&envelope, &options, &mut store).unwrap();
        assert!(matches!(
            verify_live_envelope(&envelope, &options, &mut store),
            Err(SdkError::NonceReused)
        ));
    }

    #[test]
    fn signs_and_verifies_request_jwt() {
        let signer = AgentSigner::from_seed([10; 32]);
        let claims = RequestJwtClaims::new(
            signer.agent_id(),
            RequestBinding::new("https://api.example.com"),
            100,
            300,
            "jwt_nonce",
        );
        let token = signer.sign_request_jwt(&claims).unwrap();
        let context = RequestAuthContext {
            audience: "https://api.example.com".to_owned(),
            now_secs: 120,
            max_ttl_secs: 300,
        };
        let mut store = MemoryNonceStore::new();

        let verified = verify_request_jwt_live(&token, &context, &mut store).unwrap();

        assert_eq!(verified.jti, "jwt_nonce");
        assert!(matches!(
            verify_request_jwt_live(&token, &context, &mut store),
            Err(SdkError::NonceReused)
        ));
    }
}
