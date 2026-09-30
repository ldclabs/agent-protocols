use super::*;
use crate::identity::{AcceptedRecord, ErrorResponse, ListResponse, MAX_NONCE_HEADER};
use std::{
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};

/// Mail-only HTTPS transport. It constructs its own credential-free client;
/// callers cannot inject default headers, cookie jars, or redirect policies.
/// Network allowlists (including private-network/DNS policy) remain the
/// application's responsibility.
#[derive(Clone)]
pub struct MailClient {
    origin: String,
    base: String,
    inner: reqwest::Client,
    max_response_bytes: usize,
    cards: Arc<Mutex<CardCache>>,
}
impl fmt::Debug for MailClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailClient")
            .field("origin", &self.origin)
            .field("base", &self.base)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}
impl MailClient {
    pub fn new(origin: impl Into<String>) -> Result<Self> {
        Self::build(origin.into(), reqwest::Client::builder())
    }
    /// An isolated TLS trust store, useful for private relays and HTTPS tests.
    /// This deliberately accepts certificates rather than a preconfigured HTTP
    /// client/builder, which might contain cookies or identity credentials.
    pub fn with_tls_roots(
        origin: impl Into<String>,
        roots: Vec<reqwest::Certificate>,
    ) -> Result<Self> {
        Self::build(
            origin.into(),
            reqwest::Client::builder().tls_certs_only(roots).no_proxy(),
        )
    }
    fn build(origin: String, builder: reqwest::ClientBuilder) -> Result<Self> {
        identity::validate_origin(&origin)?;
        let inner = builder
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            base: format!("{origin}/v1/mailboxes"),
            origin,
            inner,
            max_response_bytes: 16 * MAX_PACKET_BYTES,
            cards: Arc::new(Mutex::new(CardCache::new())),
        })
    }
    /// Share persistent pins across independently constructed clients/origins.
    /// Install a restored cache before the first read; replacing an established
    /// cache with an older snapshot would explicitly lose rollback protection.
    /// Cloning a MailClient automatically shares this cache.
    pub fn with_card_cache(mut self, cards: Arc<Mutex<CardCache>>) -> Self {
        self.cards = cards;
        self
    }
    pub fn card_cache(&self) -> Arc<Mutex<CardCache>> {
        Arc::clone(&self.cards)
    }
    /// Persist after card reads, including equivocation errors. This contains
    /// contact metadata but no decryption keys. Restore with
    /// CardCache::from_snapshot and with_card_cache before subsequent reads.
    pub fn card_cache_snapshot(&self) -> Result<Value> {
        self.cards
            .lock()
            .map_err(|_| fail("invalid_request", "card cache lock poisoned"))?
            .snapshot()
    }
    pub fn with_response_limit(mut self, bytes: usize) -> Result<Self> {
        if bytes < 4096 {
            return Err(fail("invalid_request", "response limit too small"));
        }
        self.max_response_bytes = bytes;
        Ok(self)
    }
    pub fn set_discovery(&mut self, value: &Value) -> Result<()> {
        self.base = validate_discovery(value, &self.origin, None)?;
        Ok(())
    }
    pub async fn protocol(&self) -> Result<Value> {
        let value = self
            .send(
                self.inner
                    .get(format!("{}/.well-known/agent-mail", self.origin)),
                200,
            )
            .await?;
        validate_discovery(&value, &self.origin, None)?;
        Ok(value)
    }
    pub async fn discover(&mut self) -> Result<Value> {
        let value = self.protocol().await?;
        self.set_discovery(&value)?;
        Ok(value)
    }
    async fn send(&self, request: reqwest::RequestBuilder, expected: u16) -> Result<Value> {
        let mut response = request.header(reqwest::header::COOKIE, "").send().await?;
        if response.url().origin().ascii_serialization() != self.origin {
            return Err(fail("invalid_response", "unexpected response origin"));
        }
        let status = response.status().as_u16();
        if status == expected
            && expected != 204
            && !response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|h| h.to_str().ok())
                .is_some_and(|s| {
                    s.split(';')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .eq_ignore_ascii_case("application/json")
                })
        {
            return Err(fail(
                "invalid_response",
                "expected application/json response",
            ));
        }
        let max_seen_nonce = response
            .headers()
            .get(MAX_NONCE_HEADER)
            .and_then(|h| h.to_str().ok())
            .map(str::to_owned);
        if response
            .content_length()
            .is_some_and(|n| n > self.max_response_bytes as u64)
        {
            return Err(fail(
                "payload_too_large",
                "Mail response exceeds configured limit",
            ));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if bytes.len().saturating_add(chunk.len()) > self.max_response_bytes {
                return Err(fail(
                    "payload_too_large",
                    "Mail response exceeds configured limit",
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| fail("invalid_response", "non-UTF-8 response"))?;
        if status != expected {
            let parsed = identity::parse_strict_json(text)
                .ok()
                .and_then(|v| serde_json::from_value::<ErrorResponse>(v).ok());
            return Err(SdkError::HttpStatus {
                status,
                code: parsed.as_ref().map(|p| p.error.code.clone()),
                data: parsed.and_then(|p| p.error.data),
                max_seen_nonce,
                body: text.into(),
            });
        }
        if expected == 204 {
            if !bytes.is_empty() {
                return Err(fail("invalid_response", "DELETE response must be empty"));
            }
            return Ok(Value::Null);
        }
        identity::parse_strict_json(text).map_err(|e| fail("invalid_response", e.to_string()))
    }
    /// Read a card and permanently pin its signed nonce/hash before returning.
    /// Disabled/expired cards are returned as historical records and remain
    /// pinned. Older or equivocating cards are rejected across client clones.
    pub async fn card(
        &self,
        mailbox: &str,
        owner: &AgentId,
    ) -> Result<AcceptedRecord<MailboxCardPayload>> {
        self.card_at(mailbox, owner, identity::unix_ms()).await
    }
    /// Same as `card`, using an explicit verification clock for deterministic
    /// callers. This never applies Identity's live-write lower time bound.
    pub async fn card_at(
        &self,
        mailbox: &str,
        owner: &AgentId,
        now: i64,
    ) -> Result<AcceptedRecord<MailboxCardPayload>> {
        clock(now)?;
        fixed_bytes(mailbox, 16)?;
        let value = self
            .send(self.inner.get(format!("{}/{mailbox}/card", self.base)), 200)
            .await?;
        validate_mail_schema(&value, "cardAcceptedRecord")?;
        let card = validate_card(&value["envelope"])?;
        if &card.event.actor != owner
            || card.event.payload.mailbox_id != mailbox
            || !card.event.payload.routes.contains(&self.origin)
        {
            return Err(fail(
                "invalid_response",
                "card response owner/mailbox/route mismatch",
            ));
        }
        self.cards
            .lock()
            .map_err(|_| fail("invalid_request", "card cache lock poisoned"))?
            .observe_historical(&value["envelope"], owner, now)?;
        Ok(serde_json::from_value(normalized(&value))?)
    }
    pub async fn publish(&self, card: &MailboxCard) -> Result<AcceptedRecord<MailboxCardPayload>> {
        validate_card(&serde_json::to_value(card)?)?;
        if !card.event.payload.routes.contains(&self.origin) {
            return Err(fail("invalid_request", "unadvertised relay"));
        }
        let value = self
            .send(self.inner.post(&self.base).json(card), 200)
            .await?;
        validate_mail_schema(&value, "cardAcceptedRecord")?;
        let result = validate_card(&value["envelope"])?;
        if result.hash != card.hash {
            return Err(fail(
                "invalid_response",
                "publication acknowledgement mismatch",
            ));
        }
        Ok(serde_json::from_value(normalized(&value))?)
    }
    /// Anonymous completed-packet retransmission. No JWT/cookie argument exists.
    /// Old cards/expired packets may be resent for idempotent status lookup.
    pub async fn deliver(&self, card: &MailboxCard, packet: &Packet) -> Result<DeliveryResult> {
        validate_card(&serde_json::to_value(card)?)?;
        validate_packet(&serde_json::to_value(packet)?)?;
        let p = &card.event.payload;
        let h = &packet.header;
        if !p.routes.contains(&self.origin)
            || !p.enabled
            || h.card_hash != card.hash
            || h.mailbox_id != p.mailbox_id
            || h.key_id != p.key_id
            || h.expires_at > p.receive_until
            || canonical_bytes(packet)?.len() > p.max_packet_bytes
        {
            return Err(fail("invalid_request", "packet/card/relay mismatch"));
        }
        let value = self
            .send(
                self.inner
                    .post(format!("{}/{}/packets", self.base, p.mailbox_id))
                    .json(packet),
                202,
            )
            .await?;
        validate_mail_schema(&value, "deliveryResult")?;
        let result: DeliveryResult = serde_json::from_value(normalized(&value))?;
        if result.packet_id != packet_id(packet)? {
            return Err(fail("invalid_response", "delivery packet ID mismatch"));
        }
        Ok(result)
    }
    pub async fn list(
        &self,
        mailbox: &str,
        owner: &AgentId,
        jwt: &str,
        now: i64,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<ListResponse<PacketRecord>> {
        fixed_bytes(mailbox, 16)?;
        verify_owner_jwt(jwt, owner, &self.origin, now)?;
        if !(1..=1000).contains(&limit) {
            return Err(fail("invalid_request", "invalid list limit"));
        }
        let mut url = url::Url::parse(&format!("{}/{mailbox}/packets", self.base))
            .map_err(|_| fail("invalid_request", "invalid list URL"))?;
        url.query_pairs_mut()
            .append_pair("limit", &limit.to_string());
        if let Some(cursor) = cursor {
            url.query_pairs_mut().append_pair("cursor", cursor);
        }
        let value = self.send(self.inner.get(url).bearer_auth(jwt), 200).await?;
        validate_mail_schema(&value, "packetList")?;
        let response: ListResponse<PacketRecord> = serde_json::from_value(normalized(&value))?;
        if response.result.len() > limit {
            return Err(fail("invalid_response", "page exceeds requested limit"));
        }
        if response.result.is_empty() && response.next_cursor.is_some() {
            return Err(fail("invalid_response", "empty page with continuation"));
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut previous = 0;
        for record in &response.result {
            validate_packet(&serde_json::to_value(&record.packet)?)?;
            if record.packet.header.mailbox_id != mailbox
                || packet_id(&record.packet)? != record.packet_id
                || record.seq <= previous
                || !seen.insert(&record.packet_id)
                || record.accepted_at >= record.packet.header.expires_at
            {
                return Err(fail(
                    "invalid_response",
                    "invalid packet list binding/order",
                ));
            }
            previous = record.seq;
        }
        Ok(response)
    }
    pub async fn delete(
        &self,
        mailbox: &str,
        packet_id: &str,
        owner: &AgentId,
        jwt: &str,
        now: i64,
    ) -> Result<()> {
        fixed_bytes(mailbox, 16)?;
        fixed_bytes(packet_id, 32)?;
        verify_owner_jwt(jwt, owner, &self.origin, now)?;
        self.send(
            self.inner
                .delete(format!("{}/{mailbox}/packets/{packet_id}", self.base))
                .bearer_auth(jwt),
            204,
        )
        .await?;
        Ok(())
    }
}
