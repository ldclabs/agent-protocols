use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Result, SdkError};

pub const AGENT_ID_PREFIX: &str = "did:agent:";
pub const DEFAULT_LIVE_WRITE_WINDOW_MS: i64 = 300_000;
pub const DEFAULT_NONCE_TTL_MS: i64 = 300_000;
pub const DEFAULT_REQUEST_JWT_TTL_SECS: i64 = 300;
pub const MAX_NONCE_HEADER: &str = "Max-Seen-Nonce";
pub const MAX_SAFE_NONCE: u64 = 0x1FFFFFFFFFFFFF;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct AgentId(String);

impl AgentId {
    pub fn from_public_key(public_key: &[u8; 32]) -> Self {
        Self(format!(
            "{}{}",
            AGENT_ID_PREFIX,
            URL_SAFE_NO_PAD.encode(public_key)
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
        let bytes = URL_SAFE_NO_PAD.decode(encoded)?;
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
        let hash = event_hash(&event)?;
        let signature = sign_event(&self.signing_key, &event)?;
        Ok(Envelope {
            hash,
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
    pub nonce: u64,
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
        nonce: u64,
        payload: P,
    ) -> Self {
        Self {
            protocol: protocol.into(),
            kind: kind.into(),
            actor,
            created_at,
            nonce,
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
    pub hash: String,
    pub event: Event<P>,
    pub signature: String,
}

pub fn canonical_event_bytes<P>(event: &Event<P>) -> Result<Vec<u8>>
where
    P: Serialize,
{
    serde_jcs::to_vec(event).map_err(|err| SdkError::CanonicalJson(err.to_string()))
}

pub fn event_hash<P>(event: &Event<P>) -> Result<String>
where
    P: Serialize,
{
    validate_nonce(event.nonce)?;
    let digest = Sha3_256::digest(canonical_event_bytes(event)?);
    Ok(URL_SAFE_NO_PAD.encode(digest))
}

pub fn sign_event<P>(signing_key: &SigningKey, event: &Event<P>) -> Result<String>
where
    P: Serialize,
{
    validate_nonce(event.nonce)?;
    let bytes = canonical_event_bytes(event)?;
    let signature = signing_key.sign(&bytes);
    Ok(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

pub fn verify_event_hash<P>(envelope: &Envelope<P>) -> Result<()>
where
    P: Serialize,
{
    let expected = event_hash(&envelope.event)?;
    if expected == envelope.hash {
        Ok(())
    } else {
        Err(SdkError::InvalidEventHash {
            expected,
            actual: envelope.hash.clone(),
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
    verify_event_hash(envelope)?;
    verify_signature(envelope)
}

pub fn verify_timestamp(created_at: i64, now_ms: i64, window_ms: i64) -> Result<()> {
    if window_ms < 0 || created_at.abs_diff(now_ms) > window_ms as u64 {
        Err(SdkError::TimestampOutOfWindow)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonceRecord {
    pub max_nonce: u64,
    pub expires_at: i64,
}

pub trait NonceStore {
    fn check_and_update(
        &mut self,
        actor: &AgentId,
        nonce: u64,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<u64>;

    fn max_nonce(&self, actor: &AgentId, now_ms: i64) -> Option<u64>;
}

#[derive(Clone, Debug, Default)]
pub struct MemoryNonceStore {
    records: HashMap<AgentId, NonceRecord>,
}

impl MemoryNonceStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl NonceStore for MemoryNonceStore {
    fn check_and_update(
        &mut self,
        actor: &AgentId,
        nonce: u64,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<u64> {
        validate_nonce(nonce)?;
        if ttl_ms < 0 {
            return Err(SdkError::InvalidNonce(
                "nonce cache ttl must be non-negative".to_owned(),
            ));
        }

        if let Some(record) = self.records.get(actor) {
            if record.expires_at > now_ms && nonce <= record.max_nonce {
                return Err(SdkError::NonceNotGreater {
                    max_nonce: record.max_nonce,
                });
            }
        }

        let record = NonceRecord {
            max_nonce: nonce,
            expires_at: now_ms.saturating_add(ttl_ms),
        };
        self.records.insert(actor.clone(), record);
        Ok(record.max_nonce)
    }

    fn max_nonce(&self, actor: &AgentId, now_ms: i64) -> Option<u64> {
        self.records
            .get(actor)
            .filter(|record| record.expires_at > now_ms)
            .map(|record| record.max_nonce)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientNonceManager {
    next_nonce: u64,
}

impl Default for ClientNonceManager {
    fn default() -> Self {
        Self { next_nonce: 1 }
    }
}

impl ClientNonceManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_next(next_nonce: u64) -> Result<Self> {
        validate_nonce(next_nonce)?;
        Ok(Self { next_nonce })
    }

    pub fn peek(&self) -> u64 {
        self.next_nonce
    }

    pub fn next_nonce(&mut self) -> Result<u64> {
        let nonce = self.next_nonce;
        validate_nonce(nonce)?;
        self.next_nonce = self
            .next_nonce
            .checked_add(1)
            .ok_or_else(|| SdkError::InvalidNonce("nonce counter overflow".to_owned()))?;
        Ok(nonce)
    }

    pub fn observe_max_nonce(&mut self, max_nonce: u64) {
        if max_nonce >= self.next_nonce {
            self.next_nonce = max_nonce.saturating_add(1);
        }
    }

    pub fn observe_max_nonce_header(&mut self, value: &str) -> Result<()> {
        let max_nonce = value
            .parse::<u64>()
            .map_err(|_| SdkError::InvalidNonce("invalid max nonce header".to_owned()))?;
        validate_nonce(max_nonce)?;
        self.observe_max_nonce(max_nonce);
        Ok(())
    }
}

pub fn validate_nonce(nonce: u64) -> Result<()> {
    if nonce == 0 || nonce > MAX_SAFE_NONCE {
        // Number.MAX_SAFE_INTEGER in JavaScript, to prevent interoperability issues with JS clients using Number for nonces
        Err(SdkError::InvalidNonce(
            "nonce must be a positive integer less than or equal to 9007199254740991".to_owned(),
        ))
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct LiveWriteOptions {
    pub now_ms: i64,
    pub window_ms: i64,
    pub nonce_ttl_ms: i64,
}

impl Default for LiveWriteOptions {
    fn default() -> Self {
        Self {
            now_ms: unix_ms(),
            window_ms: DEFAULT_LIVE_WRITE_WINDOW_MS,
            nonce_ttl_ms: DEFAULT_NONCE_TTL_MS,
        }
    }
}

pub fn verify_live_envelope<P, S>(
    envelope: &Envelope<P>,
    options: &LiveWriteOptions,
    nonce_store: &mut S,
) -> Result<u64>
where
    P: Serialize,
    S: NonceStore,
{
    verify_envelope(envelope)?;
    verify_timestamp(envelope.event.created_at, options.now_ms, options.window_ms)?;
    nonce_store.check_and_update(
        &envelope.event.actor,
        envelope.event.nonce,
        options.now_ms,
        options.nonce_ttl_ms,
    )
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
    pub fn new(agent_id: AgentId, binding: RequestBinding, issued_at: i64, ttl_secs: i64) -> Self {
        Self {
            iss: agent_id.clone(),
            sub: agent_id,
            aud: binding.audience,
            iat: issued_at,
            exp: issued_at + ttl_secs,
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
            now_secs: unix_secs(),
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
    if claims.exp <= claims.iat {
        return Err(SdkError::InvalidJwtClaim("exp/iat"));
    }
    if claims.iat > context.now_secs || claims.exp < context.now_secs {
        return Err(SdkError::InvalidJwtClaim("iat/exp"));
    }
    if claims.exp - claims.iat > context.max_ttl_secs {
        return Err(SdkError::InvalidJwtClaim("ttl"));
    }

    Ok(claims)
}

pub fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

pub fn unix_secs() -> i64 {
    unix_ms() / 1000
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
            1,
            json!({"id": signer.agent_id(), "name": "ResearchAgent"}),
        );

        let envelope = signer.sign_event(event).unwrap();

        assert!(!envelope.hash.starts_with("evt_"));
        assert_eq!(envelope.hash.len(), 43);
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
            1,
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
            nonce_ttl_ms: 1000,
        };
        let event = Event::new(
            "agent-profile/1.0",
            "profile.update",
            signer.agent_id(),
            1000,
            1,
            json!({"name": "ResearchAgent"}),
        );
        let envelope = signer.sign_event(event).unwrap();
        let mut store = MemoryNonceStore::new();

        let max_nonce = verify_live_envelope(&envelope, &options, &mut store).unwrap();
        assert_eq!(max_nonce, 1);
        assert!(matches!(
            verify_live_envelope(&envelope, &options, &mut store),
            Err(SdkError::NonceNotGreater { max_nonce: 1 })
        ));
    }

    #[test]
    fn client_nonce_manager_observes_server_max() {
        let mut manager = ClientNonceManager::new();

        assert_eq!(manager.next_nonce().unwrap(), 1);
        manager.observe_max_nonce(5);

        assert_eq!(manager.peek(), 6);
        assert_eq!(manager.next_nonce().unwrap(), 6);
    }

    #[test]
    fn rejects_nonce_values_outside_safe_json_integer_range() {
        let signer = AgentSigner::from_seed([16; 32]);
        let event = Event::new(
            "agent-profile/1.0",
            "profile.update",
            signer.agent_id(),
            1000,
            MAX_SAFE_NONCE + 1,
            json!({"id": signer.agent_id(), "name": "ResearchAgent"}),
        );

        assert!(matches!(
            signer.sign_event(event),
            Err(SdkError::InvalidNonce(_))
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
        );
        let token = signer.sign_request_jwt(&claims).unwrap();
        let context = RequestAuthContext {
            audience: "https://api.example.com".to_owned(),
            now_secs: 120,
            max_ttl_secs: 300,
        };
        let verified = verify_request_jwt(&token, &context).unwrap();

        assert_eq!(verified.iss, signer.agent_id());
    }

    #[test]
    fn rejects_request_jwts_with_non_positive_ttl() {
        let signer = AgentSigner::from_seed([17; 32]);
        let claims = RequestJwtClaims::new(
            signer.agent_id(),
            RequestBinding::new("https://api.example.com"),
            100,
            0,
        );
        let token = signer.sign_request_jwt(&claims).unwrap();
        let context = RequestAuthContext {
            audience: "https://api.example.com".to_owned(),
            now_secs: 100,
            max_ttl_secs: 300,
        };

        assert!(matches!(
            verify_request_jwt(&token, &context),
            Err(SdkError::InvalidJwtClaim("exp/iat"))
        ));
    }
}
