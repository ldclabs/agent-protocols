use super::*;
use crate::identity::{AcceptedRecord, ErrorResponse, ListResponse, MAX_NONCE_HEADER};
use std::{
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};

/// Mail-only HTTPS transport for one relay origin (a card route); paths are
/// fixed at `/v1/mailboxes`. It constructs its own credential-free client;
/// callers cannot inject default headers, cookie jars, or redirect policies.
/// Network allowlists (including private-network/DNS policy) remain the
/// application's responsibility.
#[derive(Clone)]
pub struct MailClient {
    origin: String,
    base: String,
    inner: reqwest::Client,
    max_response_bytes: usize,
    cards: Arc<Mutex<MailCardCache>>,
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
            max_response_bytes: 128 * MAX_PACKET_BYTES,
            cards: Arc::new(Mutex::new(MailCardCache::new())),
        })
    }
    /// Share persistent pins across independently constructed clients/origins.
    /// Install a restored cache before the first read; replacing an established
    /// cache with an older snapshot would explicitly lose rollback protection.
    /// Cloning a MailClient automatically shares this cache.
    pub fn with_card_cache(mut self, cards: Arc<Mutex<MailCardCache>>) -> Self {
        self.cards = cards;
        self
    }
    pub fn card_cache(&self) -> Arc<Mutex<MailCardCache>> {
        Arc::clone(&self.cards)
    }
    /// Persist after card reads, including ones that return an error. This contains
    /// contact metadata but no decryption keys. Restore with
    /// MailCardCache::from_snapshot and with_card_cache before subsequent reads.
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
    /// Informational discovery document; it never changes delivery paths.
    pub async fn protocol(&self) -> Result<Value> {
        let value = self
            .send(
                self.inner
                    .get(format!("{}/.well-known/agent-mail", self.origin)),
                200,
            )
            .await?;
        validate_discovery(&value, &self.origin)?;
        Ok(value)
    }
    async fn send(&self, request: reqwest::RequestBuilder, expected: u16) -> Result<Value> {
        let mut response = request.send().await?;
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
    /// Read and pin the current card before returning, even a closed or
    /// expired one. An older or conflicting card fails with `stale_card`
    /// across client clones.
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
        if &card.event.actor != owner || card.event.payload.mailbox_id != mailbox {
            return Err(fail(
                "invalid_response",
                "card response owner/mailbox mismatch",
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
    /// Sender-signed delivery or exact retransmission of a completed packet.
    /// No JWT/cookie argument exists.
    pub async fn deliver(&self, packet: &Submission) -> Result<DeliveryResult> {
        let packet = validate_packet(&serde_json::to_value(packet)?)?;
        let value = self
            .send(
                self.inner
                    .post(format!(
                        "{}/{}/packets",
                        self.base, packet.event.payload.header.mailbox_id
                    ))
                    .json(&packet),
                202,
            )
            .await?;
        validate_mail_schema(&value, "deliveryResult")?;
        let result: DeliveryResult = serde_json::from_value(normalized(&value))?;
        if result.packet_id != packet_id(&packet)?
            || result.accepted_at >= packet.event.payload.header.expires_at
        {
            return Err(fail("invalid_response", "delivery result mismatch"));
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
        let mut previous = 0;
        for record in &response.result {
            validate_packet(&serde_json::to_value(&record.packet)?)?;
            if record.packet.event.payload.header.mailbox_id != mailbox
                || packet_id(&record.packet)? != record.packet_id
                || record.seq <= previous
                || record.accepted_at >= record.packet.event.payload.header.expires_at
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
