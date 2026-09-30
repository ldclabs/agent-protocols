//! Agent Mail 1.0: signed cards and letters, HPKE packets, and explicit local state.
//!
//! Relays never receive decryption keys. A verified letter is untrusted content,
//! not authorization to execute a task. State helpers are in-memory models;
//! applications must persist snapshots atomically before acknowledging delivery.
mod state;
mod types;
pub use state::*;
pub use types::*;
#[cfg(feature = "http-client")]
mod client;
#[cfg(feature = "http-client")]
pub use client::MailClient;

use crate::identity::{self, AgentId, AgentSigner, Envelope, Event};
use crate::{Result, SdkError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem as _,
    OpModeR, OpModeS, Serializable,
};
use serde::Serialize;
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
};
use zeroize::Zeroizing;

pub const PROTOCOL: &str = "agent-mail/1.0";
pub const MAX_TTL_MS: i64 = 30 * 86_400_000;
pub const FUTURE_SKEW_MS: i64 = 300_000;
pub const MAX_PACKET_BYTES: usize = 1_048_576;
pub const SCHEMA_JSON: &str = include_str!("schema.json");
type Kem = X25519HkdfSha256;
type PrivateKey = <Kem as hpke::Kem>::PrivateKey;
type PublicKey = <Kem as hpke::Kem>::PublicKey;

pub(crate) fn fail(code: &'static str, message: impl Into<String>) -> SdkError {
    SdkError::protocol(code, message)
}
pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_jcs::to_vec(value).map_err(|e| SdkError::CanonicalJson(e.to_string()))
}
pub fn hash_bytes(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha3_256::digest(bytes))
}
pub fn encode_bytes(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn decode_bytes(value: &str) -> Result<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| fail("invalid_event", "noncanonical base64url"))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(fail("invalid_event", "noncanonical base64url"));
    }
    Ok(bytes)
}
pub(crate) fn fixed_bytes(value: &str, size: usize) -> Result<Vec<u8>> {
    let bytes = decode_bytes(value)?;
    if bytes.len() != size {
        return Err(fail("invalid_event", "invalid encoded byte length"));
    }
    Ok(bytes)
}
pub fn random_id() -> Result<String> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|e| SdkError::Random(e.to_string()))?;
    Ok(encode_bytes(&bytes))
}
/// Validate a named structural definition; signatures and semantics are separate.
pub fn validate_mail_schema(value: &Value, definition: &str) -> Result<()> {
    static VALIDATORS: OnceLock<Mutex<BTreeMap<String, jsonschema::Validator>>> = OnceLock::new();
    let mut validators = VALIDATORS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .map_err(|_| fail("invalid_event", "schema cache unavailable"))?;
    if !validators.contains_key(definition) {
        let schema: Value = serde_json::from_str(SCHEMA_JSON)?;
        if schema["$defs"].get(definition).is_none() {
            return Err(fail("invalid_event", "unknown Mail schema definition"));
        }
        let validator = jsonschema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .build(&json!({"$ref":format!("#/$defs/{definition}"),"$defs":schema["$defs"]}))
            .map_err(|e| fail("invalid_event", e.to_string()))?;
        validators.insert(definition.into(), validator);
    }
    validators[definition]
        .validate(value)
        .map_err(|e| fail("invalid_event", e.to_string()))
}
pub(crate) fn normalized(value: &Value) -> Value {
    match value {
        Value::Number(n) if n.as_i64().is_none() && n.as_u64().is_none() => n
            .as_f64()
            .filter(|f| f.fract() == 0.0 && f.abs() <= identity::MAX_SAFE_NONCE as f64)
            .map(|f| json!(f as i64))
            .unwrap_or(value.clone()),
        Value::Array(a) => Value::Array(a.iter().map(normalized).collect()),
        Value::Object(o) => {
            Value::Object(o.iter().map(|(k, v)| (k.clone(), normalized(v))).collect())
        }
        _ => value.clone(),
    }
}
fn signed(value: &Value, definition: &str) -> Result<Envelope<Value>> {
    identity::parse_strict_json(&serde_json::to_string(value)?)?;
    validate_mail_schema(value, definition)?;
    let envelope: Envelope<Value> = serde_json::from_value(normalized(value))?;
    identity::validate_event_fields(&envelope.event, &[])?;
    identity::validate_nonce(envelope.event.nonce)?;
    identity::verify_envelope(&envelope)?;
    Ok(envelope)
}
pub(crate) fn lifetime(created: i64, expires: i64) -> Result<()> {
    if created < 0
        || expires <= created
        || expires > created.saturating_add(MAX_TTL_MS)
        || expires as u64 > identity::MAX_SAFE_NONCE
    {
        return Err(fail("invalid_event", "invalid lifetime"));
    }
    Ok(())
}
pub(crate) fn clock(now: i64) -> Result<()> {
    if now < 0 || now as u64 > identity::MAX_SAFE_NONCE {
        return Err(fail("invalid_request", "invalid clock"));
    }
    Ok(())
}
/// Historical verification: checks intrinsic validity, not live-write freshness.
pub fn validate_card(value: &Value) -> Result<MailboxCard> {
    let envelope = signed(value, "mailboxCardEnvelope")?;
    let card: MailboxCard = serde_json::from_value(serde_json::to_value(envelope)?)?;
    let p = &card.event.payload;
    lifetime(card.event.created_at, p.expires_at)?;
    if p.receive_until < p.expires_at || p.receive_until > p.expires_at.saturating_add(MAX_TTL_MS) {
        return Err(fail("invalid_event", "invalid receive_until"));
    }
    for route in &p.routes {
        identity::validate_origin(route)?;
    }
    let probe_enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&fixed_bytes(&p.public_key, 32)?)
        .map_err(|_| fail("invalid_event", "invalid X25519 key"))?;
    // The maintained KEM rejects low-order/all-zero DH results. A fixed public
    // probe secret is only validation input, never used for actual encryption.
    let probe =
        PrivateKey::from_bytes(&[42; 32]).map_err(|_| fail("invalid_event", "invalid key"))?;
    Kem::decap(&probe, None, &probe_enc)
        .map_err(|_| fail("invalid_event", "unusable X25519 key"))?;
    Ok(card)
}
pub fn validate_card_for_sending(value: &Value, owner: &AgentId, now: i64) -> Result<MailboxCard> {
    let card = validate_card(value)?;
    check_card_usable(&card, owner, now)?;
    Ok(card)
}
pub(crate) fn check_card_usable(card: &MailboxCard, owner: &AgentId, now: i64) -> Result<()> {
    clock(now)?;
    if &card.event.actor != owner {
        return Err(fail("invalid_actor", "unexpected mailbox owner"));
    }
    if card.event.created_at > now.saturating_add(FUTURE_SKEW_MS) {
        return Err(SdkError::TimestampOutOfWindow);
    }
    if !card.event.payload.enabled {
        return Err(fail("mailbox_unavailable", "mailbox disabled"));
    }
    if now >= card.event.payload.expires_at {
        return Err(fail("stale_card", "card expired"));
    }
    Ok(())
}
/// Verify a letter as a historical object. Freshness/deduplication is performed
/// by `MailRecipient`, so a delayed low-nonce letter is never rejected here.
pub fn validate_letter(value: &Value) -> Result<Letter> {
    let e = signed(value, "letterEnvelope")?;
    let expires = e.event.payload["expires_at"]
        .as_i64()
        .ok_or_else(|| fail("invalid_event", "missing expiry"))?;
    lifetime(e.event.created_at, expires)?;
    if e.event.kind == "mail.message" {
        let p: MessagePayload = serde_json::from_value(e.event.payload.clone())?;
        for part in &p.parts {
            let bytes = decode_bytes(&part.data)?;
            if part.media_type.starts_with("text/") {
                std::str::from_utf8(&bytes)
                    .map_err(|_| fail("invalid_event", "text part is not UTF-8"))?;
            }
        }
        if let Some(reply) = &p.reply_card {
            let card = validate_card(reply)?;
            if card.event.actor != e.event.actor {
                return Err(fail(
                    "invalid_actor",
                    "reply card owner differs from sender",
                ));
            }
        }
    }
    Ok(e)
}
pub fn parse_card(text: &str) -> Result<MailboxCard> {
    validate_card(&identity::parse_strict_json(text)?)
}
pub fn parse_letter(text: &str) -> Result<Letter> {
    validate_letter(&identity::parse_strict_json(text)?)
}
pub fn sign_card(
    signer: &AgentSigner,
    payload: MailboxCardPayload,
    created_at: i64,
    nonce: u64,
) -> Result<MailboxCard> {
    let envelope = signer.sign_event(Event::new(
        PROTOCOL,
        "mailbox.publish",
        signer.agent_id(),
        created_at,
        nonce,
        payload,
    ))?;
    validate_card(&serde_json::to_value(&envelope)?)?;
    Ok(envelope)
}
pub fn sign_message(
    signer: &AgentSigner,
    payload: MessagePayload,
    created_at: i64,
    nonce: u64,
) -> Result<Letter> {
    sign_letter(
        signer,
        "mail.message",
        serde_json::to_value(payload)?,
        created_at,
        nonce,
    )
}
pub fn sign_receipt(
    signer: &AgentSigner,
    original: &Letter,
    expires_at: i64,
    created_at: i64,
    nonce: u64,
) -> Result<Letter> {
    validate_letter(&serde_json::to_value(original)?)?;
    if original.event.kind != "mail.message"
        || original.event.payload["to"] != signer.agent_id().as_str()
    {
        return Err(fail("invalid_event", "receipt recipient binding"));
    }
    sign_letter(
        signer,
        "mail.receipt",
        json!({"to":original.event.actor,"expires_at":expires_at,"message_hash":original.hash,"status":"received"}),
        created_at,
        nonce,
    )
}
fn sign_letter(
    signer: &AgentSigner,
    kind: &str,
    payload: Value,
    created_at: i64,
    nonce: u64,
) -> Result<Letter> {
    let envelope = signer.sign_event(Event::new(
        PROTOCOL,
        kind,
        signer.agent_id(),
        created_at,
        nonce,
        payload,
    ))?;
    validate_letter(&serde_json::to_value(&envelope)?)?;
    Ok(envelope)
}
pub fn validate_receipt(receipt: &Letter, original: &Letter) -> Result<()> {
    validate_letter(&serde_json::to_value(receipt)?)?;
    validate_letter(&serde_json::to_value(original)?)?;
    if receipt.event.kind != "mail.receipt"
        || original.event.kind != "mail.message"
        || receipt.event.actor.as_str() != original.event.payload["to"].as_str().unwrap_or("")
        || receipt.event.payload["to"] != original.event.actor.as_str()
        || receipt.event.payload["message_hash"] != original.hash
    {
        return Err(fail("invalid_event", "receipt binding mismatch"));
    }
    Ok(())
}
pub fn validate_reply(reply: &Letter, parent: &Letter) -> Result<()> {
    validate_letter(&serde_json::to_value(reply)?)?;
    validate_letter(&serde_json::to_value(parent)?)?;
    if reply.event.kind != "mail.message"
        || parent.event.kind != "mail.message"
        || reply.event.payload["to"] != parent.event.actor.as_str()
        || parent.event.payload["to"] != reply.event.actor.as_str()
        || reply.event.payload["in_reply_to"] != parent.hash
        || reply.event.payload["thread_id"] != parent.event.payload["thread_id"]
    {
        return Err(fail("invalid_event", "reply binding mismatch"));
    }
    Ok(())
}
/// Independent X25519 secret. Debug output and implicit serialization are absent.
/// `export_secret` is explicit and returns a buffer zeroized on drop.
pub struct MailEncryptionKey(PrivateKey);
impl MailEncryptionKey {
    pub fn generate() -> Result<Self> {
        let mut bytes = Zeroizing::new([0; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|e| SdkError::Random(e.to_string()))?;
        Self::from_secret(bytes.as_ref())
    }
    pub fn from_secret(bytes: &[u8]) -> Result<Self> {
        Ok(Self(PrivateKey::from_bytes(bytes).map_err(|_| {
            fail("invalid_event", "X25519 secret must contain 32 bytes")
        })?))
    }
    pub fn public_key(&self) -> String {
        encode_bytes(&Kem::sk_to_pk(&self.0).to_bytes())
    }
    pub fn export_secret(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.to_bytes().to_vec())
    }
}
/// Exact framing, also useful for boundary conformance tests. Inputs are bounded.
pub fn frame_bytes(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if bytes.is_empty() || bytes.len() > MAX_PACKET_BYTES {
        return Err(fail("invalid_packet", "invalid frame length"));
    }
    let size = (4 + bytes.len()).div_ceil(1024) * 1024;
    let mut frame = Zeroizing::new(vec![0; size]);
    frame[..4].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
    frame[4..4 + bytes.len()].copy_from_slice(bytes);
    Ok(frame)
}
fn unframe(bytes: &[u8]) -> Result<Value> {
    if bytes.len() < 1024 || bytes.len() % 1024 != 0 {
        return Err(fail("invalid_packet", "invalid frame length"));
    }
    let n = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    if n == 0
        || n > bytes.len() - 4
        || (4 + n).div_ceil(1024) * 1024 != bytes.len()
        || bytes[4 + n..].iter().any(|b| *b != 0)
    {
        return Err(fail("invalid_packet", "invalid frame padding"));
    }
    let data = &bytes[4..4 + n];
    let text = std::str::from_utf8(data).map_err(|_| fail("invalid_packet", "invalid UTF-8"))?;
    let value = identity::parse_strict_json(text)?;
    if canonical_bytes(&value)? != data {
        return Err(fail("invalid_packet", "noncanonical plaintext"));
    }
    Ok(value)
}
pub fn validate_packet(value: &Value) -> Result<Packet> {
    validate_mail_schema(value, "packet").map_err(|e| fail("invalid_packet", e.to_string()))?;
    let packet: Packet = serde_json::from_value(normalized(value))?;
    fixed_bytes(&packet.enc, 32)?;
    let n = decode_bytes(&packet.ciphertext)?.len();
    if n < 1040 || n % 1024 != 16 || canonical_bytes(&packet)?.len() > MAX_PACKET_BYTES {
        return Err(fail(
            "invalid_packet",
            "invalid ciphertext or packet length",
        ));
    }
    Ok(packet)
}
pub fn parse_packet(text: &str) -> Result<Packet> {
    if text.len() > 2 * MAX_PACKET_BYTES {
        return Err(fail("payload_too_large", "raw packet body too large"));
    }
    validate_packet(&identity::parse_strict_json(text)?)
}
pub fn packet_id(packet: &Packet) -> Result<String> {
    Ok(hash_bytes(&canonical_bytes(packet)?))
}
fn info(header: &PacketHeader) -> Result<Vec<u8>> {
    let mut bytes = b"agent-mail/1.0\0".to_vec();
    bytes.extend(fixed_bytes(&header.card_hash, 32)?);
    Ok(bytes)
}
/// Production encryption: fresh system randomness, one HPKE context per packet.
/// Caller should observe the card with `CardCache` before using it.
pub fn encrypt_letter(letter: &Letter, card: &MailboxCard, now: i64) -> Result<Packet> {
    let letter = validate_letter(&serde_json::to_value(letter)?)?;
    let owner: AgentId = serde_json::from_value(letter.event.payload["to"].clone())?;
    validate_card_for_sending(&serde_json::to_value(card)?, &owner, now)?;
    let expiry = letter.event.payload["expires_at"].as_i64().unwrap();
    if letter.event.created_at > now.saturating_add(FUTURE_SKEW_MS)
        || expiry <= now
        || expiry > card.event.payload.receive_until
    {
        return Err(fail("invalid_event", "letter expiration or clock binding"));
    }
    let header = PacketHeader {
        protocol: PROTOCOL.into(),
        mailbox_id: card.event.payload.mailbox_id.clone(),
        card_hash: card.hash.clone(),
        key_id: card.event.payload.key_id.clone(),
        expires_at: expiry,
    };
    let json = Zeroizing::new(canonical_bytes(&letter)?);
    let plaintext = frame_bytes(&json)?;
    // Bound allocation/output before doing expensive public-key encryption.
    let projected = Packet {
        header: header.clone(),
        enc: encode_bytes(&[0; 32]),
        ciphertext: encode_bytes(&vec![0; plaintext.len() + 16]),
    };
    if canonical_bytes(&projected)?.len() > card.event.payload.max_packet_bytes {
        return Err(fail("payload_too_large", "packet exceeds card limit"));
    }
    let pk = PublicKey::from_bytes(&fixed_bytes(&card.event.payload.public_key, 32)?)
        .map_err(|_| fail("invalid_packet", "invalid key"))?;
    let (enc, ciphertext) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeS::Base,
        &pk,
        &info(&header)?,
        &plaintext,
        &canonical_bytes(&header)?,
    )
    .map_err(|_| fail("invalid_packet", "encryption failed"))?;
    Ok(Packet {
        header,
        enc: encode_bytes(&enc.to_bytes()),
        ciphertext: encode_bytes(&ciphertext),
    })
}
/// Stateless authenticated opening of a historical packet. This verifies shape,
/// cryptography and future skew; callers must enforce new-acceptance expiry and
/// durable deduplication (`MailRecipient` implements those state transitions).
pub fn decrypt_packet(
    packet: &Packet,
    card: &MailboxCard,
    key: &MailEncryptionKey,
    owner: &AgentId,
    now: i64,
) -> Result<Letter> {
    clock(now)?;
    let packet = validate_packet(&serde_json::to_value(packet)?)?;
    let card = validate_card(&serde_json::to_value(card)?)?;
    let h = &packet.header;
    let p = &card.event.payload;
    if !p.enabled
        || &card.event.actor != owner
        || h.card_hash != card.hash
        || h.mailbox_id != p.mailbox_id
        || h.key_id != p.key_id
        || h.expires_at > p.receive_until
        || canonical_bytes(&packet)?.len() > p.max_packet_bytes
        || key.public_key() != p.public_key
    {
        return Err(fail("invalid_packet", "recipient/card/key binding"));
    }
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&fixed_bytes(&packet.enc, 32)?)
        .map_err(|_| fail("invalid_packet", "invalid encapsulated key"))?;
    let plaintext = Zeroizing::new(
        hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
            &OpModeR::Base,
            &key.0,
            &enc,
            &info(h)?,
            &decode_bytes(&packet.ciphertext)?,
            &canonical_bytes(h)?,
        )
        .map_err(|_| fail("invalid_packet", "unable to decrypt packet"))?,
    );
    let letter = validate_letter(&unframe(&plaintext)?)?;
    if letter.event.payload["to"] != owner.as_str()
        || letter.event.payload["expires_at"] != h.expires_at
        || letter.event.created_at > now.saturating_add(FUTURE_SKEW_MS)
    {
        return Err(fail("invalid_packet", "letter binding or future clock"));
    }
    Ok(letter)
}
pub fn validate_discovery(
    value: &Value,
    origin: &str,
    card: Option<&MailboxCard>,
) -> Result<String> {
    validate_mail_schema(value, "discoveryDocument")?;
    identity::validate_origin(origin)?;
    if value["service"] != origin
        || card.is_some_and(|c| !c.event.payload.routes.iter().any(|s| s == origin))
    {
        return Err(fail("invalid_response", "discovery origin mismatch"));
    }
    let endpoint = value["endpoints"]["mailboxes"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{origin}/v1/mailboxes"));
    let url = url::Url::parse(&endpoint)
        .map_err(|_| fail("invalid_response", "invalid mailbox endpoint"))?;
    if url.origin().ascii_serialization() != origin
        || url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || endpoint.ends_with('/')
        || endpoint.contains('\\')
        || endpoint.chars().any(|c| c <= ' ')
    {
        return Err(fail("invalid_response", "invalid mailbox endpoint"));
    }
    Ok(endpoint)
}
pub fn verify_owner_jwt(token: &str, owner: &AgentId, origin: &str, now: i64) -> Result<()> {
    clock(now)?;
    identity::validate_origin(origin)?;
    // Parse JWT segments strictly before the shared typed verifier: unknown
    // claims remain permitted, but duplicate claims must never be collapsed.
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(fail("invalid_token", "invalid JWT"));
    }
    for part in &parts[..2] {
        let bytes =
            decode_bytes(part).map_err(|_| fail("invalid_token", "invalid JWT encoding"))?;
        let text =
            std::str::from_utf8(&bytes).map_err(|_| fail("invalid_token", "invalid JWT UTF-8"))?;
        let parsed = identity::parse_strict_json(text)
            .map_err(|_| fail("invalid_token", "invalid JWT JSON"))?;
        if *part == parts[1] {
            for field in ["iat", "exp"] {
                if !parsed[field]
                    .as_i64()
                    .is_some_and(|n| n >= 0 && n as u64 <= identity::MAX_SAFE_NONCE)
                {
                    return Err(fail(
                        "invalid_token",
                        "JWT NumericDate must be a safe nonnegative integer",
                    ));
                }
            }
            if parsed["exp"].as_i64().unwrap() <= now / 1000 {
                return Err(fail("invalid_token", "expired JWT"));
            }
        }
    }
    let claims = identity::verify_request_jwt(
        token,
        &identity::RequestAuthContext {
            audience: origin.into(),
            now_secs: now / 1000,
            max_ttl_secs: 300,
        },
    )
    .map_err(|e| fail("invalid_token", e.to_string()))?;
    if &claims.iss != owner || &claims.sub != owner {
        return Err(SdkError::PermissionDenied);
    }
    Ok(())
}
