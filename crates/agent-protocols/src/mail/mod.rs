//! Agent Mail 1.0: signed cards and letters, HPKE packets, and explicit local state.
//!
//! Relays never receive decryption keys. A verified letter is untrusted content,
//! not authorization to execute a task. State helpers are in-memory models;
//! applications must persist snapshots atomically before acknowledging delivery.
//! Relay paths are fixed at `{route}/v1/mailboxes`.
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
/// HPKE `info`: the header, including `card_hash`, is bound as AAD.
const INFO: &[u8] = PROTOCOL.as_bytes();
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
/// Parse `did:agent:<key>/mail/<mailbox_id>[?route=<origin>...]` (Mail Section 3.3).
pub fn parse_mail_address(value: &str) -> Result<MailAddress> {
    let url = identity::parse_agent_url(value)?;
    let mailbox_id = match (url.protocol.as_deref(), url.resource) {
        (Some("mail"), Some(mailbox_id)) => mailbox_id,
        _ => return Err(fail("invalid_url", "not a mailbox address")),
    };
    fixed_bytes(&mailbox_id, 16).map_err(|_| fail("invalid_url", "mailbox_id must be an id16"))?;
    Ok(MailAddress {
        owner: url.agent_id,
        mailbox_id,
        routes: url.routes,
    })
}
/// Format the stable address, or a contact address when routes are given.
pub fn format_mail_address(owner: &AgentId, mailbox_id: &str, routes: &[String]) -> Result<String> {
    fixed_bytes(mailbox_id, 16).map_err(|_| fail("invalid_url", "mailbox_id must be an id16"))?;
    identity::format_agent_url(&identity::AgentUrl {
        agent_id: owner.clone(),
        protocol: Some("mail".into()),
        resource: Some(mailbox_id.into()),
        routes: routes.to_vec(),
    })
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
    if card.event.payload.routes.is_empty() {
        return Err(fail("mailbox_unavailable", "mailbox closed"));
    }
    if now >= card.event.payload.expires_at {
        return Err(fail("stale_card", "card expired"));
    }
    Ok(())
}
/// Validate immutable plaintext. Authentication comes from its signed submission.
pub fn validate_letter(value: &Value) -> Result<Letter> {
    identity::parse_strict_json(&serde_json::to_string(value)?)?;
    validate_mail_schema(value, "messagePayload")?;
    let p: MessagePayload = serde_json::from_value(normalized(value))?;
    lifetime(p.created_at, p.expires_at)?;
    for part in &p.parts {
        let bytes = decode_bytes(&part.data)?;
        if part.media_type.starts_with("text/") {
            std::str::from_utf8(&bytes)
                .map_err(|_| fail("invalid_event", "text part is not UTF-8"))?;
        }
    }
    if let Some(reply) = &p.reply_card {
        if validate_card(reply)?.event.actor != p.sender {
            return Err(fail(
                "invalid_actor",
                "reply card owner differs from sender",
            ));
        }
    }
    Ok(p)
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
pub fn new_mail_message_id() -> Result<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|e| SdkError::Random(e.to_string()))?;
    Ok(encode_bytes(&bytes))
}
pub fn create_mail_message(actor: &AgentId, created_at: i64, mut payload: Value) -> Result<Letter> {
    let fields = payload
        .as_object_mut()
        .ok_or_else(|| fail("invalid_event", "message content must be an object"))?;
    if ["message_id", "from", "created_at"]
        .iter()
        .any(|k| fields.contains_key(*k))
    {
        return Err(fail(
            "invalid_event",
            "message content overrides identity fields",
        ));
    }
    fields.insert("message_id".into(), json!(new_mail_message_id()?));
    fields.insert("from".into(), json!(actor));
    fields.insert("created_at".into(), json!(created_at));
    validate_letter(&payload)
}
/// Bind an immutable reply to both participants and its parent's logical ID.
pub fn validate_reply(reply: &Letter, parent: &Letter) -> Result<()> {
    validate_letter(&serde_json::to_value(reply)?)?;
    validate_letter(&serde_json::to_value(parent)?)?;
    if reply.to != parent.sender
        || parent.to != reply.sender
        || reply.in_reply_to.as_deref() != Some(parent.message_id.as_str())
        || reply.thread_id != parent.thread_id
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
            fail("invalid_private_key", "X25519 secret must contain 32 bytes")
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
/// Validate a packet and return it with its canonical bytes, computed once for ID and size checks.
pub(crate) fn checked_packet(value: &Value) -> Result<(Submission, Vec<u8>)> {
    let envelope = signed(value, "submissionEnvelope")?;
    let packet: Submission = serde_json::from_value(serde_json::to_value(envelope)?)?;
    let e = &packet.event;
    let p = &e.payload;
    fixed_bytes(&p.enc, 32)?;
    let n = decode_bytes(&p.ciphertext)?.len();
    if n < 1040
        || n % 1024 != 16
        || p.header.expires_at <= e.created_at
        || p.header.expires_at > e.created_at.saturating_add(MAX_TTL_MS + FUTURE_SKEW_MS)
    {
        return Err(fail(
            "invalid_packet",
            "invalid ciphertext length or submission lifetime",
        ));
    }
    let bytes = canonical_bytes(&packet)?;
    if bytes.len() > MAX_PACKET_BYTES {
        return Err(fail("payload_too_large", "submission too large"));
    }
    Ok((packet, bytes))
}
pub fn validate_packet(value: &Value) -> Result<Submission> {
    Ok(checked_packet(value)?.0)
}
pub fn parse_packet(text: &str) -> Result<Submission> {
    if text.len() > 2 * MAX_PACKET_BYTES {
        return Err(fail("payload_too_large", "raw submission too large"));
    }
    validate_packet(&identity::parse_strict_json(text)?)
}
pub fn packet_id(packet: &Submission) -> Result<String> {
    checked_packet(&serde_json::to_value(packet)?)?;
    Ok(packet.hash.clone())
}
/// Exact context bound to encryption, derived from the verified outer event.
pub fn mail_submission_aad(event: &Event<Packet>) -> Result<Vec<u8>> {
    canonical_bytes(
        &json!({"protocol":event.protocol,"type":event.kind,"actor":event.actor,
        "created_at":event.created_at,"nonce":event.nonce,"header":event.payload.header}),
    )
}
/// Encrypt immutable plaintext with fresh HPKE randomness, then sign the packet.
pub fn encrypt_letter(
    letter: &Letter,
    card: &MailboxCard,
    signer: &AgentSigner,
    nonce: u64,
    now: i64,
) -> Result<Submission> {
    let letter = validate_letter(&serde_json::to_value(letter)?)?;
    if letter.sender != signer.agent_id() {
        return Err(fail("invalid_actor", "message sender differs from signer"));
    }
    identity::validate_nonce(nonce)?;
    validate_card_for_sending(&serde_json::to_value(card)?, &letter.to, now)?;
    if letter.created_at > now.saturating_add(FUTURE_SKEW_MS) || letter.expires_at <= now {
        return Err(fail("packet_expired", "message expired or future-dated"));
    }
    if letter.expires_at > card.event.payload.receive_until {
        return Err(fail("invalid_packet", "message exceeds receive_until"));
    }
    let plaintext = frame_bytes(&Zeroizing::new(canonical_bytes(&letter)?))?;
    let mut event = Event::new(
        PROTOCOL,
        "mail.submit",
        signer.agent_id(),
        now,
        nonce,
        Packet {
            header: PacketHeader {
                protocol: PROTOCOL.into(),
                mailbox_id: card.event.payload.mailbox_id.clone(),
                card_hash: card.hash.clone(),
                expires_at: letter.expires_at,
            },
            enc: encode_bytes(&[0; 32]),
            ciphertext: encode_bytes(&vec![0; plaintext.len() + 16]),
        },
    );
    let projected = Envelope {
        event: event.clone(),
        hash: "A".repeat(43),
        signature: "A".repeat(86),
    };
    if canonical_bytes(&projected)?.len() > card.event.payload.max_packet_bytes {
        return Err(fail("payload_too_large", "submission exceeds card limit"));
    }
    let pk = PublicKey::from_bytes(&fixed_bytes(&card.event.payload.public_key, 32)?)
        .map_err(|_| fail("invalid_packet", "invalid encryption key"))?;
    let (enc, ciphertext) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeS::Base,
        &pk,
        INFO,
        &plaintext,
        &mail_submission_aad(&event)?,
    )
    .map_err(|_| fail("invalid_packet", "encryption failed"))?;
    event.payload.enc = encode_bytes(&enc.to_bytes());
    event.payload.ciphertext = encode_bytes(&ciphertext);
    signer.sign_event(event)
}
/// Historical verification and opening; inbox acceptance handles expiry and dedup.
pub fn decrypt_packet(
    packet: &Submission,
    card: &MailboxCard,
    key: &MailEncryptionKey,
    owner: &AgentId,
    now: i64,
) -> Result<Letter> {
    clock(now)?;
    let (packet, bytes) = checked_packet(&serde_json::to_value(packet)?)?;
    let card = validate_card(&serde_json::to_value(card)?)?;
    open_verified(&packet, &bytes, &card, key, owner, now)
}
pub(crate) fn open_verified(
    packet: &Submission,
    bytes: &[u8],
    card: &MailboxCard,
    key: &MailEncryptionKey,
    owner: &AgentId,
    now: i64,
) -> Result<Letter> {
    let e = &packet.event;
    let h = &e.payload.header;
    let p = &card.event.payload;
    if e.created_at > now.saturating_add(FUTURE_SKEW_MS) {
        return Err(SdkError::TimestampOutOfWindow);
    }
    if &card.event.actor != owner {
        return Err(fail("invalid_actor", "card owner mismatch"));
    }
    if bytes.len() > p.max_packet_bytes {
        return Err(fail("payload_too_large", "submission exceeds card limit"));
    }
    if key.public_key() != p.public_key {
        return Err(fail("invalid_private_key", "recipient key mismatch"));
    }
    if h.card_hash != card.hash || h.mailbox_id != p.mailbox_id || h.expires_at > p.receive_until {
        return Err(fail("invalid_packet", "recipient/card/key binding"));
    }
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&fixed_bytes(&e.payload.enc, 32)?)
        .map_err(|_| fail("invalid_packet", "invalid encapsulated key"))?;
    let plaintext = Zeroizing::new(
        hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
            &OpModeR::Base,
            &key.0,
            &enc,
            INFO,
            &decode_bytes(&e.payload.ciphertext)?,
            &mail_submission_aad(e)?,
        )
        .map_err(|_| fail("invalid_packet", "unable to decrypt submission"))?,
    );
    let letter = validate_letter(&unframe(&plaintext)?)?;
    if letter.sender != e.actor || &letter.to != owner || letter.expires_at != h.expires_at {
        return Err(fail(
            "invalid_packet",
            "sender, recipient or expiration binding",
        ));
    }
    if letter.created_at > now.min(e.created_at).saturating_add(FUTURE_SKEW_MS) {
        return Err(SdkError::TimestampOutOfWindow);
    }
    Ok(letter)
}
/// Informational discovery document; it never supplies delivery paths.
pub fn validate_discovery(value: &Value, origin: &str) -> Result<()> {
    validate_mail_schema(value, "discoveryDocument")?;
    identity::validate_origin(origin)?;
    if value["service"] != origin {
        return Err(fail("invalid_response", "discovery origin mismatch"));
    }
    Ok(())
}
pub(crate) fn owner_claims(
    token: &str,
    origin: &str,
    now: i64,
) -> Result<identity::RequestJwtClaims> {
    clock(now)?;
    identity::verify_request_jwt(
        token,
        &identity::RequestAuthContext {
            audience: origin.into(),
            now_secs: now / 1000,
            max_ttl_secs: identity::DEFAULT_REQUEST_JWT_TTL_SECS,
        },
    )
    .map_err(|e| fail("invalid_token", e.to_string()))
}
/// Identity request JWT for this relay origin whose subject is the mailbox owner.
pub fn verify_owner_jwt(token: &str, owner: &AgentId, origin: &str, now: i64) -> Result<()> {
    identity::validate_origin(origin)?;
    if &owner_claims(token, origin, now)?.iss != owner {
        return Err(SdkError::PermissionDenied);
    }
    Ok(())
}
