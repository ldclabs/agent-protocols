use super::*;
use crate::identity::{AcceptedRecord, ListResponse, MemoryNonceStore, NonceStore};
use serde::Deserialize;

fn version(value: &Value) -> Result<()> {
    if value["version"] != 1 {
        return Err(fail(
            "invalid_request",
            "unsupported local Mail state version",
        ));
    }
    Ok(())
}
fn mailbox_key(owner: &AgentId, mailbox: &str) -> String {
    format!("{owner}/{mailbox}")
}

/// Sender-side pins: the greatest-nonce card seen per (owner, mailbox),
/// including closed or expired cards. Save `snapshot()` after every
/// observation, even one that returns an error for an unusable new pin.
#[derive(Clone, Default)]
pub struct MailCardCache {
    pins: BTreeMap<String, MailboxCard>,
}
impl MailCardCache {
    pub fn new() -> Self {
        Self::default()
    }
    /// Pin an authenticated card, including a closed or expired one. This is
    /// appropriate for card reads; check usability before encrypting.
    pub fn observe_historical(
        &mut self,
        value: &Value,
        owner: &AgentId,
        now: i64,
    ) -> Result<MailboxCard> {
        let card = validate_card(value)?;
        clock(now)?;
        if &card.event.actor != owner {
            return Err(fail("invalid_actor", "unexpected owner"));
        }
        if card.event.created_at > now.saturating_add(FUTURE_SKEW_MS) {
            return Err(SdkError::TimestampOutOfWindow);
        }
        let key = mailbox_key(owner, &card.event.payload.mailbox_id);
        if let Some(pin) = self.pins.get(&key) {
            if pin.hash != card.hash && card.event.nonce <= pin.event.nonce {
                return Err(fail(
                    "stale_card",
                    "card is older than or conflicts with the pinned card",
                ));
            }
        }
        self.pins.insert(key, card.clone());
        Ok(card)
    }
    /// Pin a card, then require that it is usable for new encryption.
    pub fn observe(&mut self, value: &Value, owner: &AgentId, now: i64) -> Result<MailboxCard> {
        let card = self.observe_historical(value, owner, now)?;
        check_card_usable(&card, owner, now)?;
        Ok(card)
    }
    /// Drop pins old enough that every earlier card of the mailbox has expired.
    pub fn prune(&mut self, now: i64) -> Result<()> {
        clock(now)?;
        self.pins
            .retain(|_, pin| now < pin.event.created_at + MAX_TTL_MS + FUTURE_SKEW_MS);
        Ok(())
    }
    /// Pin the card, then encrypt the original signed letter under it.
    pub fn seal(&mut self, letter: &Letter, card: &Value, now: i64) -> Result<Packet> {
        let owner: AgentId = serde_json::from_value(letter.event.payload["to"].clone())?;
        let card = self.observe(card, &owner, now)?;
        encrypt_letter(letter, &card, now)
    }
    pub fn snapshot(&self) -> Result<Value> {
        Ok(json!({"version":1,"pins":self.pins.values().collect::<Vec<_>>()}))
    }
    pub fn from_snapshot(value: &Value) -> Result<Self> {
        version(value)?;
        let pins: Vec<MailboxCard> = serde_json::from_value(value["pins"].clone())?;
        Ok(Self {
            pins: pins
                .into_iter()
                .map(|card| {
                    (
                        mailbox_key(&card.event.actor, &card.event.payload.mailbox_id),
                        card,
                    )
                })
                .collect(),
        })
    }
}

/// Retained verified cards and their secrets, by card hash, through `receive_until`.
pub struct MailKeyring {
    owner: AgentId,
    entries: BTreeMap<String, (MailboxCard, MailEncryptionKey)>,
}
impl MailKeyring {
    pub fn new(owner: AgentId) -> Self {
        Self {
            owner,
            entries: BTreeMap::new(),
        }
    }
    pub fn owner(&self) -> &AgentId {
        &self.owner
    }
    pub fn add(&mut self, card: &MailboxCard, key: MailEncryptionKey) -> Result<()> {
        let card = validate_card(&serde_json::to_value(card)?)?;
        if card.event.actor != self.owner {
            return Err(fail("invalid_actor", "card owner mismatch"));
        }
        if card.event.payload.public_key != key.public_key() {
            return Err(fail("invalid_private_key", "key does not match card"));
        }
        self.entries.insert(card.hash.clone(), (card, key));
        Ok(())
    }
    /// Verify and decrypt a packet with the retained card it names; cards were verified at `add`.
    pub fn open(&self, packet: &Packet, now: i64) -> Result<Letter> {
        clock(now)?;
        let (packet, bytes) = checked_packet(&serde_json::to_value(packet)?)?;
        let (card, key) = self
            .entries
            .get(&packet.header.card_hash)
            .ok_or_else(|| fail("invalid_packet", "unknown retained card"))?;
        open_verified(&packet, &bytes, card, key, &self.owner, now)
    }
    /// Only keys past the signed `receive_until` are removed. This cannot erase
    /// copies held in snapshots or backups, which the application must manage.
    pub fn prune(&mut self, now: i64) -> Result<()> {
        clock(now)?;
        self.entries
            .retain(|_, (card, _)| now < card.event.payload.receive_until);
        Ok(())
    }
    /// SENSITIVE: includes decryption keys. Protect this output at rest; never
    /// pass it to a relay or log it.
    pub fn snapshot(&self) -> Result<Value> {
        let entries: Vec<_> = self
            .entries
            .values()
            .map(|(card, key)| json!({"card":card,"secret":encode_bytes(&key.export_secret())}))
            .collect();
        Ok(json!({"version":1,"owner":self.owner,"entries":entries}))
    }
    pub fn from_snapshot(value: &Value) -> Result<Self> {
        #[derive(Deserialize)]
        struct Entry {
            card: MailboxCard,
            secret: String,
        }
        version(value)?;
        let mut out = Self::new(serde_json::from_value(value["owner"].clone())?);
        let entries: Vec<Entry> = serde_json::from_value(value["entries"].clone())?;
        for entry in entries {
            let raw = Zeroizing::new(fixed_bytes(&entry.secret, 32)?);
            out.add(&entry.card, MailEncryptionKey::from_secret(&raw)?)?;
        }
        Ok(out)
    }
}

/// Cross-route letter deduplication. The application stores accepted letters;
/// persist the inbox snapshot with them before deleting relay copies or acting.
/// `accept` never executes content or sends replies.
pub struct MailInbox {
    keyring: MailKeyring,
    accepted: BTreeMap<String, i64>,
}
impl MailInbox {
    pub fn new(keyring: MailKeyring) -> Self {
        Self {
            keyring,
            accepted: BTreeMap::new(),
        }
    }
    pub fn keyring(&self) -> &MailKeyring {
        &self.keyring
    }
    pub fn keyring_mut(&mut self) -> &mut MailKeyring {
        &mut self.keyring
    }
    pub fn has(&self, letter_id: &str) -> bool {
        self.accepted.contains_key(letter_id)
    }
    pub fn accept(
        &mut self,
        packet: &Packet,
        claimed_packet_id: Option<&str>,
        now: i64,
    ) -> Result<InboxAcceptance> {
        if claimed_packet_id.is_some_and(|id| packet_id(packet).ok().as_deref() != Some(id)) {
            return Err(fail("invalid_packet", "packet ID mismatch"));
        }
        let letter = self.keyring.open(packet, now)?;
        if self.accepted.contains_key(&letter.hash) {
            return Ok(InboxAcceptance::Duplicate(Box::new(letter)));
        }
        if now >= packet.header.expires_at {
            return Err(fail(
                "packet_expired",
                "expired letter cannot be newly accepted",
            ));
        }
        self.accepted
            .insert(letter.hash.clone(), packet.header.expires_at);
        Ok(InboxAcceptance::Accepted(Box::new(letter)))
    }
    /// Forget letters whose signed expiration passed; they can no longer be newly accepted.
    pub fn prune(&mut self, now: i64) -> Result<()> {
        clock(now)?;
        self.accepted.retain(|_, expires| now < *expires);
        Ok(())
    }
    pub fn snapshot(&self) -> Result<Value> {
        Ok(
            json!({"version":1,"owner":self.keyring.owner,"accepted":self.accepted.iter().collect::<Vec<_>>()}),
        )
    }
    pub fn from_snapshot(keyring: MailKeyring, value: &Value) -> Result<Self> {
        version(value)?;
        if value["owner"] != keyring.owner.as_str() {
            return Err(fail("invalid_request", "inbox owner mismatch"));
        }
        let accepted: Vec<(String, i64)> = serde_json::from_value(value["accepted"].clone())?;
        Ok(Self {
            keyring,
            accepted: accepted.into_iter().collect(),
        })
    }
}

struct RelayMailbox {
    current: AcceptedRecord<MailboxCardPayload>,
    last_seq: u64,
    bytes: usize,
    packets: BTreeMap<String, (PacketRecord, usize)>,
    tombstones: BTreeMap<String, (i64, i64)>,
}
impl RelayMailbox {
    fn drop_expired(&mut self, now: i64) {
        let bytes = &mut self.bytes;
        self.packets.retain(|_, (record, size)| {
            let live = now < record.packet.header.expires_at;
            if !live {
                *bytes -= *size;
            }
            live
        });
    }
}
/// Framework-neutral in-memory relay model, NOT a hosted or durable service.
/// All outputs are owned copies. Save/restore snapshots atomically in a real
/// service; enforce admission limits and serialized access outside this model.
/// The short-lived Identity nonce cache is not part of the snapshot.
pub struct MailRelayStore {
    origin: String,
    max_packets: usize,
    max_bytes: usize,
    nonces: MemoryNonceStore,
    mailboxes: BTreeMap<String, RelayMailbox>,
}
impl MailRelayStore {
    pub fn new(origin: impl Into<String>) -> Result<Self> {
        Self::with_limits(origin, 10_000, 64 * MAX_PACKET_BYTES)
    }
    /// Per-mailbox limits on retained packets.
    pub fn with_limits(
        origin: impl Into<String>,
        max_packets: usize,
        max_bytes: usize,
    ) -> Result<Self> {
        let origin = origin.into();
        identity::validate_origin(&origin)?;
        if max_packets == 0 || max_bytes == 0 {
            return Err(fail("invalid_request", "invalid relay quota"));
        }
        Ok(Self {
            origin,
            max_packets,
            max_bytes,
            nonces: MemoryNonceStore::new(),
            mailboxes: BTreeMap::new(),
        })
    }
    pub fn origin(&self) -> &str {
        &self.origin
    }
    pub fn discovery(&self) -> Value {
        json!({"protocol":PROTOCOL,"service":self.origin})
    }
    pub fn publish(
        &mut self,
        value: &Value,
        now: i64,
    ) -> Result<AcceptedRecord<MailboxCardPayload>> {
        let mut nonces = std::mem::take(&mut self.nonces);
        let result = self.publish_with_nonce_store(value, now, &mut nonces);
        self.nonces = nonces;
        result
    }
    /// Inject the origin-wide Identity nonce store when several protocols share
    /// a service. All other checks precede nonce consumption.
    pub fn publish_with_nonce_store<S: NonceStore + ?Sized>(
        &mut self,
        value: &Value,
        now: i64,
        nonces: &mut S,
    ) -> Result<AcceptedRecord<MailboxCardPayload>> {
        clock(now)?;
        let card = validate_card(value)?;
        let p = &card.event.payload;
        if let Some(mailbox) = self.mailboxes.get(&p.mailbox_id) {
            let current = &mailbox.current.envelope;
            if current.event.actor != card.event.actor {
                return Err(fail("mailbox_conflict", "mailbox belongs to another owner"));
            }
            if current.hash == card.hash {
                return Ok(mailbox.current.clone());
            }
            if card.event.nonce <= current.event.nonce {
                return Err(SdkError::NonceNotGreater {
                    max_nonce: current.event.nonce,
                });
            }
        } else if !p.routes.contains(&self.origin) {
            return Err(SdkError::PermissionDenied);
        }
        identity::verify_timestamp(card.event.created_at, now, FUTURE_SKEW_MS)?;
        nonces.check_and_update(&card.event.actor, card.event.nonce, now, 2 * FUTURE_SKEW_MS)?;
        let record = AcceptedRecord {
            envelope: card.clone(),
            accepted_at: now,
        };
        match self.mailboxes.get_mut(&p.mailbox_id) {
            Some(mailbox) => mailbox.current = record.clone(),
            None => {
                self.mailboxes.insert(
                    p.mailbox_id.clone(),
                    RelayMailbox {
                        current: record.clone(),
                        last_seq: 0,
                        bytes: 0,
                        packets: BTreeMap::new(),
                        tombstones: BTreeMap::new(),
                    },
                );
            }
        }
        Ok(record)
    }
    pub fn card(&self, mailbox_id: &str) -> Result<AcceptedRecord<MailboxCardPayload>> {
        path_id(mailbox_id, 16)?;
        self.mailboxes
            .get(mailbox_id)
            .map(|m| m.current.clone())
            .ok_or_else(|| fail("mailbox_unavailable", "unknown mailbox"))
    }
    pub fn deliver(
        &mut self,
        mailbox_id: &str,
        packet: &Packet,
        now: i64,
    ) -> Result<DeliveryResult> {
        clock(now)?;
        path_id(mailbox_id, 16)?;
        let (packet, bytes) = checked_packet(&serde_json::to_value(packet)?)?;
        let h = &packet.header;
        if h.mailbox_id != mailbox_id {
            return Err(fail("invalid_packet", "path mailbox mismatch"));
        }
        let (id, size) = (hash_bytes(&bytes), bytes.len());
        let mailbox = self
            .mailboxes
            .get_mut(mailbox_id)
            .ok_or_else(|| fail("mailbox_unavailable", "unknown mailbox"))?;
        if let Some((accepted_at, _)) = mailbox.tombstones.get(&id) {
            return Ok(DeliveryResult {
                packet_id: id,
                accepted_at: *accepted_at,
            });
        }
        let card = &mailbox.current.envelope;
        let p = &card.event.payload;
        if !p.routes.contains(&self.origin) {
            return Err(fail("mailbox_unavailable", "relay is not a current route"));
        }
        if h.card_hash != card.hash || now >= p.expires_at {
            return Err(fail("stale_card", "current card mismatch or expired"));
        }
        if now >= h.expires_at {
            return Err(fail("packet_expired", "packet expired"));
        }
        if h.expires_at
            > p.receive_until
                .min(now.saturating_add(MAX_TTL_MS + FUTURE_SKEW_MS))
        {
            return Err(fail("invalid_packet", "packet expiry bound"));
        }
        if size > p.max_packet_bytes {
            return Err(fail("payload_too_large", "card packet limit"));
        }
        mailbox.drop_expired(now);
        if mailbox.packets.len() >= self.max_packets
            || mailbox.bytes.saturating_add(size) > self.max_bytes
            || mailbox.last_seq >= identity::MAX_SAFE_NONCE
        {
            return Err(fail("rate_limited", "mailbox storage quota exhausted"));
        }
        mailbox.last_seq += 1;
        mailbox.bytes += size;
        mailbox
            .tombstones
            .insert(id.clone(), (now, packet.header.expires_at));
        mailbox.packets.insert(
            id.clone(),
            (
                PacketRecord {
                    packet_id: id.clone(),
                    packet,
                    accepted_at: now,
                    seq: mailbox.last_seq,
                },
                size,
            ),
        );
        Ok(DeliveryResult {
            packet_id: id,
            accepted_at: now,
        })
    }
    fn owner_box(&self, mailbox: &str, jwt: &str, now: i64) -> Result<&RelayMailbox> {
        path_id(mailbox, 16)?;
        let claims = owner_claims(jwt, &self.origin, now)?;
        let found = self
            .mailboxes
            .get(mailbox)
            .ok_or_else(|| fail("mailbox_unavailable", "unknown mailbox"))?;
        if claims.iss != found.current.envelope.event.actor {
            return Err(SdkError::PermissionDenied);
        }
        Ok(found)
    }
    /// The cursor is the decimal `seq` of the last returned record.
    pub fn list(
        &self,
        mailbox: &str,
        jwt: &str,
        now: i64,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<ListResponse<PacketRecord>> {
        let found = self.owner_box(mailbox, jwt, now)?;
        if !(1..=1000).contains(&limit) {
            return Err(fail("invalid_request", "list limit must be 1..1000"));
        }
        let after = match cursor {
            None => 0,
            Some(text) => text
                .parse::<u64>()
                .ok()
                .filter(|n| n.to_string() == text && *n <= identity::MAX_SAFE_NONCE)
                .ok_or_else(|| fail("invalid_request", "invalid cursor"))?,
        };
        let mut rows: Vec<_> = found
            .packets
            .values()
            .map(|(record, _)| record)
            .filter(|r| r.seq > after && now < r.packet.header.expires_at)
            .cloned()
            .collect();
        rows.sort_by_key(|r| r.seq);
        let more = rows.len() > limit;
        rows.truncate(limit);
        Ok(ListResponse {
            next_cursor: more.then(|| rows[limit - 1].seq.to_string()),
            result: rows,
        })
    }
    pub fn delete(&mut self, mailbox: &str, id: &str, jwt: &str, now: i64) -> Result<()> {
        self.owner_box(mailbox, jwt, now)?;
        path_id(id, 32)?;
        let found = self.mailboxes.get_mut(mailbox).unwrap();
        if let Some((_, size)) = found.packets.remove(id) {
            found.bytes -= size;
        }
        Ok(())
    }
    /// Drop expired packets and tombstones, then forget mailboxes whose
    /// current card's `receive_until` passed; a later card is a new registration.
    pub fn prune(&mut self, now: i64) -> Result<()> {
        clock(now)?;
        for m in self.mailboxes.values_mut() {
            m.drop_expired(now);
            m.tombstones.retain(|_, (_, expires)| now < *expires);
        }
        self.mailboxes
            .retain(|_, m| now < m.current.envelope.event.payload.receive_until);
        Ok(())
    }
    pub fn snapshot(&self) -> Result<Value> {
        let mailboxes: Vec<_> = self
            .mailboxes
            .values()
            .map(|m| {
                json!({
                    "current": m.current,
                    "last_seq": m.last_seq,
                    "packets": m.packets.values().map(|(r, _)| r).collect::<Vec<_>>(),
                    "tombstones": m.tombstones.iter().map(|(id, (accepted_at, expires_at))| {
                        json!({"packet_id":id,"accepted_at":accepted_at,"expires_at":expires_at})
                    }).collect::<Vec<_>>(),
                })
            })
            .collect();
        Ok(json!({"version":1,"origin":self.origin,"mailboxes":mailboxes}))
    }
    /// Restore trusted local state saved by `snapshot`; limits are not part of it.
    pub fn from_snapshot(value: &Value, max_packets: usize, max_bytes: usize) -> Result<Self> {
        #[derive(Deserialize)]
        struct Tombstone {
            packet_id: String,
            accepted_at: i64,
            expires_at: i64,
        }
        #[derive(Deserialize)]
        struct Saved {
            current: AcceptedRecord<MailboxCardPayload>,
            last_seq: u64,
            packets: Vec<PacketRecord>,
            tombstones: Vec<Tombstone>,
        }
        version(value)?;
        let origin = value["origin"]
            .as_str()
            .ok_or_else(|| fail("invalid_request", "snapshot origin"))?;
        let mut out = Self::with_limits(origin, max_packets, max_bytes)?;
        let saved: Vec<Saved> = serde_json::from_value(normalized(&value["mailboxes"]))?;
        for m in saved {
            let mut mailbox = RelayMailbox {
                current: m.current,
                last_seq: m.last_seq,
                bytes: 0,
                packets: BTreeMap::new(),
                tombstones: m
                    .tombstones
                    .into_iter()
                    .map(|t| (t.packet_id, (t.accepted_at, t.expires_at)))
                    .collect(),
            };
            for record in m.packets {
                let size = canonical_bytes(&record.packet)?.len();
                mailbox.bytes += size;
                mailbox
                    .packets
                    .insert(record.packet_id.clone(), (record, size));
            }
            let id = mailbox.current.envelope.event.payload.mailbox_id.clone();
            out.mailboxes.insert(id, mailbox);
        }
        Ok(out)
    }
}
fn path_id(value: &str, size: usize) -> Result<()> {
    fixed_bytes(value, size).map_err(|_| fail("invalid_request", "invalid path ID"))?;
    Ok(())
}
