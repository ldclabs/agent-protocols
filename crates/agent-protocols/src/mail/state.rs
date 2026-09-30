use super::*;
use crate::identity::{AcceptedRecord, ListResponse, NonceStore};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CardPin {
    card: MailboxCard,
    equivocated: bool,
}
/// Persistent rollback/equivocation/key-ID tracking. There is deliberately no
/// TTL eviction. Save `snapshot()` even when `observe()` reports disabled,
/// expired, or equivocated: those observations still update trust state.
#[derive(Clone, Default)]
pub struct CardCache {
    pins: BTreeMap<String, CardPin>,
    keys: BTreeMap<String, String>,
}
fn mailbox_key(owner: &AgentId, mailbox: &str) -> String {
    format!("{owner}/{mailbox}")
}
fn key_name(card: &MailboxCard) -> String {
    format!(
        "{}/{}/{}",
        card.event.actor, card.event.payload.mailbox_id, card.event.payload.key_id
    )
}
impl CardCache {
    pub fn new() -> Self {
        Self::default()
    }
    /// Observe and pin an authenticated card, including disabled/expired cards.
    /// This is appropriate for historical HTTP reads. The caller must separately
    /// check current usability before creating a new encrypted packet.
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
        let key = key_name(&card);
        if self
            .keys
            .get(&key)
            .is_some_and(|old| old != &card.event.payload.public_key)
        {
            return Err(fail("mailbox_conflict", "key ID reused"));
        }
        self.keys.insert(key, card.event.payload.public_key.clone());
        let mailbox = mailbox_key(owner, &card.event.payload.mailbox_id);
        if let Some(pin) = self.pins.get_mut(&mailbox) {
            if card.event.nonce < pin.card.event.nonce {
                return Err(fail("stale_card", "card rollback"));
            }
            if card.event.nonce == pin.card.event.nonce {
                if card.hash != pin.card.hash {
                    pin.equivocated = true;
                }
                if pin.equivocated {
                    return Err(fail(
                        "card_equivocation",
                        "conflicting cards require a higher nonce",
                    ));
                }
            }
        }
        self.pins.insert(
            mailbox,
            CardPin {
                card: card.clone(),
                equivocated: false,
            },
        );
        Ok(card)
    }
    /// Observe a card and then require that it is usable for new encryption.
    /// Persist state even on disabled/expired/equivocation errors.
    pub fn observe(&mut self, value: &Value, owner: &AgentId, now: i64) -> Result<MailboxCard> {
        let card = self.observe_historical(value, owner, now)?;
        check_card_usable(&card, owner, now)?;
        Ok(card)
    }
    /// Explicit trust reset, not routine cache expiry. All rollback protection
    /// for this mailbox is lost; historical key-ID consistency remains retained.
    pub fn reset_trust(&mut self, owner: &AgentId, mailbox: &str) {
        self.pins.remove(&mailbox_key(owner, mailbox));
    }
    pub fn snapshot(&self) -> Result<Value> {
        Ok(json!({"pins":self.pins,"keys":self.keys}))
    }
    pub fn from_snapshot(value: &Value) -> Result<Self> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Saved {
            pins: BTreeMap<String, CardPin>,
            keys: BTreeMap<String, String>,
        }
        let state: Saved = serde_json::from_value(value.clone())?;
        for (name, pin) in &state.pins {
            validate_card(&serde_json::to_value(&pin.card)?)?;
            if name != &mailbox_key(&pin.card.event.actor, &pin.card.event.payload.mailbox_id)
                || state.keys.get(&key_name(&pin.card)) != Some(&pin.card.event.payload.public_key)
            {
                return Err(fail("invalid_request", "corrupt card cache snapshot"));
            }
        }
        for key in state.keys.values() {
            fixed_bytes(key, 32)?;
        }
        Ok(Self {
            pins: state.pins,
            keys: state.keys,
        })
    }
}
struct KeyEntry {
    card: MailboxCard,
    key: MailEncryptionKey,
}
/// In-memory recipient state, with retained historical keys and cross-route
/// deduplication. `receive` never executes content or sends receipts/deletions.
/// Persist a protected snapshot before acknowledging transport deletion.
pub struct MailRecipient {
    owner: AgentId,
    keys: BTreeMap<String, KeyEntry>,
    key_history: BTreeMap<String, String>,
    letters: BTreeMap<String, Letter>,
    outgoing: BTreeMap<String, Letter>,
}
impl MailRecipient {
    pub fn new(owner: AgentId) -> Self {
        Self {
            owner,
            keys: BTreeMap::new(),
            key_history: BTreeMap::new(),
            letters: BTreeMap::new(),
            outgoing: BTreeMap::new(),
        }
    }
    pub fn owner(&self) -> &AgentId {
        &self.owner
    }
    /// Register an original outgoing message before transmission, so later
    /// receipts can be bound to correspondence this owner actually sent.
    pub fn remember_outgoing(&mut self, letter: &Letter) -> Result<()> {
        validate_letter(&serde_json::to_value(letter)?)?;
        if letter.event.kind != "mail.message" || letter.event.actor != self.owner {
            return Err(fail(
                "invalid_actor",
                "outgoing message must be signed by this owner",
            ));
        }
        self.outgoing.insert(letter.hash.clone(), letter.clone());
        Ok(())
    }
    fn check_receipt(&self, letter: &Letter) -> Result<()> {
        if letter.event.kind == "mail.receipt" {
            let original = self
                .outgoing
                .get(letter.event.payload["message_hash"].as_str().unwrap_or(""))
                .ok_or_else(|| fail("invalid_event", "receipt for unknown outgoing message"))?;
            validate_receipt(letter, original)?;
        }
        Ok(())
    }
    pub fn add_key(&mut self, card: &MailboxCard, key: MailEncryptionKey) -> Result<()> {
        validate_card(&serde_json::to_value(card)?)?;
        if card.event.actor != self.owner || card.event.payload.public_key != key.public_key() {
            return Err(fail("invalid_actor", "key or owner mismatch"));
        }
        let name = key_name(card);
        if self
            .key_history
            .get(&name)
            .is_some_and(|old| old != &key.public_key())
        {
            return Err(fail("mailbox_conflict", "key ID reused"));
        }
        self.key_history.insert(name, key.public_key());
        self.keys.insert(
            card.hash.clone(),
            KeyEntry {
                card: card.clone(),
                key,
            },
        );
        Ok(())
    }
    pub fn receive(
        &mut self,
        packet: &Packet,
        claimed_packet_id: Option<&str>,
        now: i64,
    ) -> Result<RecipientAcceptance> {
        if claimed_packet_id.is_some_and(|id| packet_id(packet).is_ok_and(|actual| actual != id)) {
            return Err(fail("invalid_packet", "packet ID mismatch"));
        }
        let entry = self
            .keys
            .get(&packet.header.card_hash)
            .ok_or_else(|| fail("invalid_packet", "unknown historical card/key"))?;
        let letter = decrypt_packet(packet, &entry.card, &entry.key, &self.owner, now)?;
        self.check_receipt(&letter)?;
        if self.letters.contains_key(&letter.hash) {
            return Ok(RecipientAcceptance::Duplicate(letter.hash));
        }
        if now >= packet.header.expires_at {
            return Err(fail("packet_expired", "letter expired"));
        }
        self.letters.insert(letter.hash.clone(), letter.clone());
        Ok(RecipientAcceptance::Accepted(Box::new(letter)))
    }
    pub fn letters(&self) -> Vec<Letter> {
        self.letters.values().cloned().collect()
    }
    /// Only keys past the signed receive_until are removed. This cannot erase
    /// copies held in snapshots/backups, which the application must manage.
    pub fn prune_expired_keys(&mut self, now: i64) -> Result<()> {
        clock(now)?;
        self.keys
            .retain(|_, e| e.card.event.payload.receive_until > now);
        Ok(())
    }
    /// Explicit compromise/loss response: pending ciphertext may become unreadable.
    pub fn discard_key(&mut self, card_hash: &str) {
        self.keys.remove(card_hash);
    }
    /// SENSITIVE: includes plaintext inbox and decryption keys. Protect this
    /// output at rest; never pass it to a relay or log it. Snapshot provenance
    /// and atomic durable replacement are the application's responsibility.
    pub fn snapshot(&self) -> Result<Value> {
        let keys: Vec<_> = self
            .keys
            .values()
            .map(|e| json!({"card":e.card,"secret":encode_bytes(&e.key.export_secret())}))
            .collect();
        Ok(
            json!({"owner":self.owner,"keys":keys,"key_history":self.key_history,"letters":self.letters.values().collect::<Vec<_>>(),"outgoing":self.outgoing.values().collect::<Vec<_>>()}),
        )
    }
    pub fn from_snapshot(value: &Value) -> Result<Self> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SavedKey {
            card: MailboxCard,
            secret: String,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Saved {
            owner: AgentId,
            keys: Vec<SavedKey>,
            key_history: BTreeMap<String, String>,
            letters: Vec<Letter>,
            outgoing: Vec<Letter>,
        }
        let saved: Saved = serde_json::from_value(value.clone())?;
        let mut out = Self::new(saved.owner);
        out.key_history = saved.key_history;
        for key in out.key_history.values() {
            fixed_bytes(key, 32)?;
        }
        for entry in saved.keys {
            let raw = Zeroizing::new(decode_bytes(&entry.secret)?);
            out.add_key(&entry.card, MailEncryptionKey::from_secret(&raw)?)?;
        }
        for letter in saved.outgoing {
            out.remember_outgoing(&letter)?;
        }
        for letter in saved.letters {
            validate_letter(&serde_json::to_value(&letter)?)?;
            if letter.event.payload["to"] != out.owner.as_str() {
                return Err(fail("invalid_actor", "snapshot letter recipient"));
            }
            out.check_receipt(&letter)?;
            if out.letters.insert(letter.hash.clone(), letter).is_some() {
                return Err(fail("invalid_request", "duplicate snapshot letter"));
            }
        }
        Ok(out)
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayNonces {
    records: BTreeMap<AgentId, (u64, i64)>,
}
impl NonceStore for RelayNonces {
    fn check_and_update(&mut self, actor: &AgentId, nonce: u64, now: i64, ttl: i64) -> Result<u64> {
        identity::validate_nonce(nonce)?;
        if let Some(max) = self.max_nonce(actor, now) {
            if nonce <= max {
                return Err(SdkError::NonceNotGreater { max_nonce: max });
            }
        }
        self.records
            .insert(actor.clone(), (nonce, now.saturating_add(ttl)));
        Ok(nonce)
    }
    fn max_nonce(&self, actor: &AgentId, now: i64) -> Option<u64> {
        self.records
            .get(actor)
            .filter(|(_, expires)| *expires > now)
            .map(|(n, _)| *n)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tombstone {
    result: DeliveryResult,
    expires_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayMailbox {
    current: MailboxCard,
    history: BTreeMap<String, AcceptedRecord<MailboxCardPayload>>,
    keys: BTreeMap<String, String>,
    next_seq: u64,
    packets: BTreeMap<String, PacketRecord>,
    accepted: BTreeMap<String, Tombstone>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    owner: AgentId,
    mailbox: String,
    after_seq: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayState {
    origin: String,
    mailboxes: BTreeMap<String, RelayMailbox>,
    nonces: RelayNonces,
    cursors: BTreeMap<String, Cursor>,
    max_packets: usize,
    max_bytes: usize,
}
/// Framework-neutral in-memory relay model, NOT a hosted or durable service.
/// All outputs are owned copies. Save/restore snapshots atomically in a real
/// service; enforce admission limits and serialized access outside this model.
pub struct MailRelay {
    state: RelayState,
}
impl MailRelay {
    pub fn new(origin: impl Into<String>) -> Result<Self> {
        Self::with_limits(origin, 1000, 64 * MAX_PACKET_BYTES)
    }
    pub fn with_limits(
        origin: impl Into<String>,
        max_packets: usize,
        max_bytes: usize,
    ) -> Result<Self> {
        let origin = origin.into();
        identity::validate_origin(&origin)?;
        if max_packets == 0 || max_bytes < 4096 {
            return Err(fail("invalid_request", "invalid relay quota"));
        }
        Ok(Self {
            state: RelayState {
                origin,
                mailboxes: BTreeMap::new(),
                nonces: RelayNonces::default(),
                cursors: BTreeMap::new(),
                max_packets,
                max_bytes,
            },
        })
    }
    pub fn origin(&self) -> &str {
        &self.state.origin
    }
    pub fn discovery(&self) -> Value {
        json!({"protocol":PROTOCOL,"service":self.state.origin})
    }
    pub fn publish(
        &mut self,
        value: &Value,
        now: i64,
    ) -> Result<AcceptedRecord<MailboxCardPayload>> {
        let mut nonces = std::mem::take(&mut self.state.nonces);
        let result = self.publish_with_nonce_store(value, now, &mut nonces);
        self.state.nonces = nonces;
        result
    }
    /// Inject the origin-wide Identity nonce store when multiple protocols share
    /// a service. All semantic checks precede nonce consumption. The caller must
    /// persist this external store in the same transaction as the relay snapshot.
    pub fn publish_with_nonce_store<S: NonceStore + ?Sized>(
        &mut self,
        value: &Value,
        now: i64,
        nonces: &mut S,
    ) -> Result<AcceptedRecord<MailboxCardPayload>> {
        clock(now)?;
        let card = validate_card(value)?;
        let p = &card.event.payload;
        if !p.routes.iter().any(|r| r == &self.state.origin) {
            return Err(fail("invalid_event", "relay not authorized by routes"));
        }
        if let Some(mailbox) = self.state.mailboxes.get(&p.mailbox_id) {
            if mailbox.current.event.actor != card.event.actor {
                return Err(fail("mailbox_conflict", "mailbox belongs to another owner"));
            }
            if let Some(record) = mailbox.history.get(&card.hash) {
                return Ok(record.clone());
            }
            if card.event.nonce <= mailbox.current.event.nonce {
                return Err(SdkError::NonceNotGreater {
                    max_nonce: mailbox.current.event.nonce,
                });
            }
            if mailbox
                .keys
                .get(&p.key_id)
                .is_some_and(|old| old != &p.public_key)
            {
                return Err(fail("mailbox_conflict", "key ID reused"));
            }
        }
        identity::verify_timestamp(
            card.event.created_at,
            now,
            identity::DEFAULT_LIVE_WRITE_WINDOW_MS,
        )?;
        nonces.check_and_update(
            &card.event.actor,
            card.event.nonce,
            now,
            identity::DEFAULT_NONCE_TTL_MS,
        )?;
        let record = AcceptedRecord {
            envelope: card.clone(),
            accepted_at: now,
        };
        let mailbox = self
            .state
            .mailboxes
            .entry(p.mailbox_id.clone())
            .or_insert_with(|| RelayMailbox {
                current: card.clone(),
                history: BTreeMap::new(),
                keys: BTreeMap::new(),
                next_seq: 1,
                packets: BTreeMap::new(),
                accepted: BTreeMap::new(),
            });
        mailbox.keys.insert(p.key_id.clone(), p.public_key.clone());
        mailbox.current = card.clone();
        mailbox.history.insert(card.hash, record.clone());
        Ok(record)
    }
    pub fn card(&self, mailbox_id: &str) -> Result<AcceptedRecord<MailboxCardPayload>> {
        fixed_bytes(mailbox_id, 16)?;
        let mailbox = self
            .state
            .mailboxes
            .get(mailbox_id)
            .ok_or_else(|| fail("mailbox_unavailable", "unknown mailbox"))?;
        Ok(mailbox.history[&mailbox.current.hash].clone())
    }
    pub fn deliver(
        &mut self,
        mailbox_id: &str,
        packet: &Packet,
        now: i64,
    ) -> Result<DeliveryResult> {
        clock(now)?;
        let packet = validate_packet(&serde_json::to_value(packet)?)?;
        fixed_bytes(mailbox_id, 16)?;
        if packet.header.mailbox_id != mailbox_id {
            return Err(fail("invalid_packet", "path mailbox mismatch"));
        }
        let id = packet_id(&packet)?;
        let mailbox = self
            .state
            .mailboxes
            .get_mut(mailbox_id)
            .ok_or_else(|| fail("mailbox_unavailable", "unknown mailbox"))?;
        if let Some(old) = mailbox.accepted.get(&id) {
            return Ok(old.result.clone());
        }
        let p = &mailbox.current.event.payload;
        if !p.enabled {
            return Err(fail("mailbox_unavailable", "mailbox disabled"));
        }
        if packet.header.card_hash != mailbox.current.hash
            || packet.header.key_id != p.key_id
            || now >= p.expires_at
        {
            return Err(fail("stale_card", "current card mismatch or expired"));
        }
        if now >= packet.header.expires_at {
            return Err(fail("packet_expired", "packet expired"));
        }
        if packet.header.expires_at
            > p.receive_until
                .min(now.saturating_add(MAX_TTL_MS + FUTURE_SKEW_MS))
        {
            return Err(fail("invalid_packet", "packet expiry bound"));
        }
        let bytes = canonical_bytes(&packet)?.len();
        if bytes > p.max_packet_bytes {
            return Err(fail("payload_too_large", "card packet limit"));
        }
        let live: Vec<_> = mailbox
            .packets
            .values()
            .filter(|r| r.packet.header.expires_at > now)
            .collect();
        let used: usize = live
            .iter()
            .map(|r| canonical_bytes(&r.packet).map(|b| b.len()))
            .collect::<Result<Vec<_>>>()?
            .iter()
            .sum();
        if live.len() >= self.state.max_packets
            || used.saturating_add(bytes) > self.state.max_bytes
            || mailbox.next_seq > identity::MAX_SAFE_NONCE
        {
            return Err(fail("quota_exceeded", "relay storage capacity"));
        }
        let result = DeliveryResult {
            packet_id: id.clone(),
            accepted_at: now,
            seq: mailbox.next_seq,
        };
        let record = PacketRecord {
            packet_id: id.clone(),
            packet: packet.clone(),
            accepted_at: now,
            seq: mailbox.next_seq,
        };
        mailbox.next_seq += 1;
        mailbox.packets.insert(id.clone(), record);
        mailbox.accepted.insert(
            id,
            Tombstone {
                result: result.clone(),
                expires_at: packet.header.expires_at,
            },
        );
        Ok(result)
    }
    fn authorize(&self, mailbox: &str, jwt: &str, now: i64) -> Result<AgentId> {
        // Verify token before revealing mailbox existence.
        let mut context = identity::RequestAuthContext::new(&self.state.origin);
        context.now_secs = now / 1000;
        let claims = identity::verify_request_jwt(jwt, &context)
            .map_err(|e| fail("invalid_token", e.to_string()))?;
        let owner = self
            .state
            .mailboxes
            .get(mailbox)
            .map(|m| m.current.event.actor.clone())
            .ok_or_else(|| fail("mailbox_unavailable", "unknown mailbox"))?;
        verify_owner_jwt(jwt, &owner, &self.state.origin, now)?;
        if claims.iss != owner {
            return Err(SdkError::PermissionDenied);
        }
        Ok(owner)
    }
    pub fn list(
        &mut self,
        mailbox: &str,
        jwt: &str,
        now: i64,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<ListResponse<PacketRecord>> {
        let owner = self.authorize(mailbox, jwt, now)?;
        if !(1..=1000).contains(&limit) {
            return Err(fail("invalid_request", "list limit must be 1..1000"));
        }
        let after = if let Some(token) = cursor {
            let c = self
                .state
                .cursors
                .get(token)
                .ok_or_else(|| fail("invalid_request", "invalid cursor"))?;
            if c.owner != owner || c.mailbox != mailbox {
                return Err(fail("invalid_request", "cursor scope mismatch"));
            }
            c.after_seq
        } else {
            0
        };
        let mut rows: Vec<_> = self.state.mailboxes[mailbox]
            .packets
            .values()
            .filter(|r| r.seq > after && r.packet.header.expires_at > now)
            .cloned()
            .collect();
        rows.sort_by_key(|r| r.seq);
        let more = rows.len() > limit;
        rows.truncate(limit);
        let next_cursor = if more {
            let token = random_id()?;
            self.state.cursors.insert(
                token.clone(),
                Cursor {
                    owner,
                    mailbox: mailbox.into(),
                    after_seq: rows.last().unwrap().seq,
                },
            );
            Some(token)
        } else {
            None
        };
        Ok(ListResponse {
            result: rows,
            next_cursor,
        })
    }
    pub fn delete(&mut self, mailbox: &str, id: &str, jwt: &str, now: i64) -> Result<()> {
        self.authorize(mailbox, jwt, now)?;
        fixed_bytes(id, 32)?;
        self.state
            .mailboxes
            .get_mut(mailbox)
            .unwrap()
            .packets
            .remove(id);
        Ok(())
    }
    /// Pruning preserves ownership/current cards, nonce high-water history, and
    /// unexpired tombstones. Cursor storage is service policy; callers may drop
    /// old cursors only by making the affected cursor explicitly invalid.
    pub fn prune(&mut self, now: i64) -> Result<()> {
        clock(now)?;
        for m in self.state.mailboxes.values_mut() {
            m.packets.retain(|_, r| r.packet.header.expires_at > now);
            m.accepted.retain(|_, r| r.expires_at > now);
        }
        Ok(())
    }
    pub fn snapshot(&self) -> Result<Value> {
        Ok(serde_json::to_value(&self.state)?)
    }
    pub fn from_snapshot(value: &Value) -> Result<Self> {
        let state: RelayState = serde_json::from_value(value.clone())?;
        identity::validate_origin(&state.origin)?;
        if state.max_packets == 0 || state.max_bytes < 4096 {
            return Err(fail("invalid_request", "invalid snapshot quota"));
        }
        for (id, m) in &state.mailboxes {
            validate_card(&serde_json::to_value(&m.current)?)?;
            if m.current.event.payload.mailbox_id != *id
                || !m.history.contains_key(&m.current.hash)
                || m.next_seq == 0
                || m.next_seq > identity::MAX_SAFE_NONCE + 1
            {
                return Err(fail("invalid_request", "invalid mailbox snapshot"));
            }
            for (hash, record) in &m.history {
                let c = validate_card(&serde_json::to_value(&record.envelope)?)?;
                clock(record.accepted_at)?;
                if c.hash != *hash
                    || c.event.actor != m.current.event.actor
                    || c.event.payload.mailbox_id != *id
                    || m.keys.get(&c.event.payload.key_id) != Some(&c.event.payload.public_key)
                    || c.event.nonce > m.current.event.nonce
                    || !c.event.payload.routes.contains(&state.origin)
                {
                    return Err(fail("invalid_request", "invalid card snapshot history"));
                }
            }
            let mut seqs = std::collections::BTreeSet::new();
            for (hash, t) in &m.accepted {
                fixed_bytes(hash, 32)?;
                clock(t.expires_at)?;
                clock(t.result.accepted_at)?;
                if t.result.packet_id != *hash
                    || t.result.seq == 0
                    || t.result.seq >= m.next_seq
                    || !seqs.insert(t.result.seq)
                {
                    return Err(fail("invalid_request", "invalid acceptance snapshot"));
                }
            }
            for (hash, r) in &m.packets {
                validate_packet(&serde_json::to_value(&r.packet)?)?;
                if packet_id(&r.packet)? != *hash
                    || r.packet_id != *hash
                    || r.packet.header.mailbox_id != *id
                    || !m.accepted.get(hash).is_some_and(|t| {
                        t.result.seq == r.seq
                            && t.result.accepted_at == r.accepted_at
                            && t.expires_at == r.packet.header.expires_at
                    })
                {
                    return Err(fail("invalid_request", "invalid packet snapshot"));
                }
            }
        }
        for (nonce, expiry) in state.nonces.records.values() {
            identity::validate_nonce(*nonce)?;
            clock(*expiry)?;
        }
        for c in state.cursors.values() {
            if !state
                .mailboxes
                .get(&c.mailbox)
                .is_some_and(|m| m.current.event.actor == c.owner && c.after_seq < m.next_seq)
            {
                return Err(fail("invalid_request", "invalid cursor snapshot"));
            }
        }
        Ok(Self { state })
    }
}
