//! Agent Mail tools (local connector Section 4.3): the active Agent ID's
//! mailboxes, sending with card pins and byte-identical retries, and a sync
//! that stores accepted messages before it deletes their relay copies.

use super::state::StoredMailMessage;
use super::views::truncate;
use super::*;

use crate::identity::validate_origin;
use crate::mail::{
    canonical_bytes, check_card_usable, create_mail_message, decode_bytes, encrypt_message,
    format_mail_address, parse_mail_address, random_id, sign_card, validate_card, validate_reply,
    MailClient, MailKeyring, MailPart, MailboxCard, MailboxCardPayload, MessagePayload,
    PacketRecord, MAX_TTL_MS,
};

/// `max_packet_bytes` of a new mailbox.
const DEFAULT_MAX_PACKET_BYTES: usize = 262_144;
/// Default message lifetime, bounded by the card's `receive_until`.
const MESSAGE_TTL_MS: i64 = 7 * 86_400_000;
/// Packet list pages read per mailbox route in one sync.
const SYNC_MAX_PAGES: usize = 10;
const SYNC_PAGE_LIMIT: usize = 100;
const MAX_ROUTES: usize = 8;

/// How a delivery attempt ended without an error.
enum Delivery {
    Delivered,
    Queued,
}

/// What a sync does with one listed packet.
enum Disposition {
    /// A new message, stored with its inbox item; its relay copy stays until a
    /// later sync, after the host has saved the state this call produced.
    Stored(Box<MailMessageView>),
    Delete,
    Keep(SdkError),
}

impl LocalConnector {
    pub(super) fn mail_mailboxes_list(&self) -> Result<Value> {
        let now = unix_ms();
        let mailboxes = self
            .state
            .mail
            .mailboxes
            .iter()
            .filter_map(|(mailbox_id, cards)| {
                cards
                    .last()
                    .map(|card| self.mailbox_view(mailbox_id, card, now))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(json!({ "mailboxes": mailboxes }))
    }

    pub(super) async fn mail_mailbox_publish(
        &mut self,
        input: MailMailboxPublishInput,
    ) -> Result<Value> {
        let now = unix_ms();
        self.prune_mail(now);
        let routes = checked_routes(&input.routes)?;
        for route in &routes {
            self.require_allowed_host(route)?;
        }
        let (mailbox_id, previous, new_key) = match input.mailbox_id {
            None if routes.is_empty() => {
                return Err(SdkError::InvalidPayload(
                    "a new mailbox needs routes".to_owned(),
                ))
            }
            None => (random_id()?, None, Some(MailEncryptionKey::generate()?)),
            Some(mailbox_id) => {
                let current = self
                    .state
                    .mail
                    .mailboxes
                    .get(&mailbox_id)
                    .and_then(|cards| cards.last().cloned())
                    .ok_or_else(|| SdkError::InvalidPayload("unknown mailbox".to_owned()))?;
                let new_key = if input.rotate_key {
                    Some(MailEncryptionKey::generate()?)
                } else if self
                    .mail_keys
                    .contains_key(&current.event.payload.public_key)
                {
                    None
                } else {
                    return Err(SdkError::InvalidPayload(
                        "the mailbox key is not loaded; restore mail keys or rotate the key"
                            .to_owned(),
                    ));
                };
                (mailbox_id, Some(current), new_key)
            }
        };
        let public_key = match (&new_key, &previous) {
            (Some(key), _) => key.public_key(),
            (None, Some(card)) => card.event.payload.public_key.clone(),
            (None, None) => unreachable!("a new mailbox always draws a key"),
        };
        let expires_at = input.expires_at.unwrap_or(now + MAX_TTL_MS);
        let payload = MailboxCardPayload {
            mailbox_id: mailbox_id.clone(),
            expires_at,
            receive_until: input
                .receive_until
                .unwrap_or_else(|| expires_at.saturating_add(MAX_TTL_MS)),
            public_key,
            routes: routes.clone(),
            max_packet_bytes: input.max_packet_bytes.unwrap_or_else(|| {
                previous.as_ref().map_or(DEFAULT_MAX_PACKET_BYTES, |card| {
                    card.event.payload.max_packet_bytes
                })
            }),
        };

        // Publish to every route of the previous and new cards (Agent Mail
        // Section 4.2); routes the operator no longer allows are reported.
        let mut targets = routes;
        for route in previous
            .iter()
            .flat_map(|card| card.event.payload.routes.iter())
        {
            if !targets.contains(route) {
                targets.push(route.clone());
            }
        }
        let mut failed = Vec::new();
        let mut allowed = Vec::new();
        for route in targets {
            match self.require_allowed_host(&route) {
                Ok(()) => allowed.push(route),
                Err(error) => failed.push(route_error(&route, &error)),
            }
        }
        if allowed.is_empty() {
            return Err(SdkError::PermissionDenied);
        }
        let mut card = self.sign_mail_card(payload.clone())?;
        let mut resynced = false;
        let (published, errors) = loop {
            let mut published = Vec::new();
            let mut errors = Vec::new();
            let mut resync = false;
            for route in &allowed {
                match self.mail_client(route)?.publish(&card).await {
                    Ok(_) => published.push(route.clone()),
                    Err(error) if !resynced && self.resync_nonce(&error) => {
                        resync = true;
                        break;
                    }
                    Err(error) => errors.push((route.clone(), error)),
                }
            }
            if !resync {
                break (published, errors);
            }
            // One re-signed card, published to every route again.
            resynced = true;
            card = self.sign_mail_card(payload.clone())?;
        };
        failed.extend(
            errors
                .iter()
                .map(|(route, error)| route_error(route, error)),
        );
        if published.is_empty() {
            return Err(errors
                .into_iter()
                .next()
                .map(|(_, error)| error)
                .unwrap_or(SdkError::PermissionDenied));
        }
        if let Some(key) = new_key {
            self.mail_keys.insert(key.public_key(), key);
        }
        self.state
            .mail
            .mailboxes
            .entry(mailbox_id.clone())
            .or_default()
            .push(card.clone());
        Ok(json!({
            "mailbox": self.mailbox_view(&mailbox_id, &card, unix_ms())?,
            "published": published,
            "failed": failed
        }))
    }

    pub(super) async fn mail_send(&mut self, input: MailSendInput) -> Result<Value> {
        let now = unix_ms();
        let parent = input
            .in_reply_to
            .as_deref()
            .map(|message_id| self.reply_parent(message_id, input.to.as_deref()))
            .transpose()?;
        let (owner, mailbox_id, routes) = match (input.to.as_deref(), &parent) {
            (Some(to), _) => {
                let address = parse_mail_address(to)?;
                (address.owner, address.mailbox_id, address.routes)
            }
            (None, Some(parent)) => {
                let card = parent.reply_card.as_ref().ok_or_else(|| {
                    SdkError::InvalidPayload(
                        "the parent message carries no reply card; pass to".to_owned(),
                    )
                })?;
                let card = validate_card(card)?;
                let payload = card.event.payload;
                (card.event.actor, payload.mailbox_id, payload.routes)
            }
            (None, None) => {
                return Err(SdkError::InvalidPayload(
                    "to or in_reply_to is required".to_owned(),
                ))
            }
        };
        if parent.as_ref().is_some_and(|parent| parent.sender != owner) {
            return Err(SdkError::InvalidPayload(
                "a reply must be addressed to the parent's sender".to_owned(),
            ));
        }
        let card = self.mail_card(&owner, &mailbox_id, &routes, now).await?;
        if !card
            .event
            .payload
            .routes
            .iter()
            .any(|route| self.require_allowed_host(route).is_ok())
        {
            return Err(SdkError::PermissionDenied);
        }
        let reply_card = input
            .reply_mailbox_id
            .as_deref()
            .map(|mailbox_id| self.open_mailbox_card(mailbox_id, now))
            .transpose()?;

        let mut parts = Vec::new();
        if let Some(text) = &input.text {
            parts.push(MailPart::text(text));
        }
        parts.extend(input.parts);
        if parts.is_empty() {
            return Err(SdkError::InvalidPayload(
                "a message needs text or parts".to_owned(),
            ));
        }
        let thread_id = match &parent {
            Some(parent) => parent.thread_id.clone(),
            None => random_id()?,
        };
        let mut content = json!({
            "to": owner,
            "expires_at": input.expires_at.unwrap_or_else(|| {
                (now + MESSAGE_TTL_MS).min(card.event.payload.receive_until)
            }),
            "thread_id": thread_id,
            "parts": parts
        });
        if let Some(subject) = input.subject {
            content["subject"] = json!(subject);
        }
        if let Some(parent) = &parent {
            content["in_reply_to"] = json!(parent.message_id);
        }
        if let Some(reply_card) = reply_card {
            content["reply_card"] = serde_json::to_value(reply_card)?;
        }
        let message = create_mail_message(&self.agent_id(), now, content)?;
        if let Some(parent) = &parent {
            validate_reply(&message, parent)?;
        }
        let mut stored = StoredMailMessage {
            direction: MailDirection::Sent,
            message,
            mailbox_id,
            received_at: None,
            read: true,
            packet: None,
            delivery: None,
        };
        let status = match self.deliver(&mut stored, card).await? {
            Delivery::Delivered => "delivered",
            Delivery::Queued => "queued",
        };
        let view = mail_message_view(&stored, false);
        self.state.mail.messages.push(stored);
        Ok(json!({ "status": status, "message": view }))
    }

    pub(super) async fn mail_sync(&mut self, input: MailSyncInput) -> Result<Value> {
        if let Some(mailbox_id) = &input.mailbox_id {
            if !self.state.mail.mailboxes.contains_key(mailbox_id) {
                return Err(SdkError::InvalidPayload("unknown mailbox".to_owned()));
            }
        }
        let now = unix_ms();
        let mut errors = Vec::new();
        let (delivered, expired) = self.retry_queued(now, &mut errors).await?;
        self.prune_mail(now);
        let received = self
            .poll_mailboxes(input.mailbox_id.as_deref(), &mut errors)
            .await?;
        let queued = self
            .state
            .mail
            .messages
            .iter()
            .filter(|stored| is_queued(stored))
            .count();
        Ok(json!({
            "received": received,
            "delivered": delivered,
            "expired": expired,
            "queued": queued,
            "errors": errors,
            "synced_at": unix_ms(),
            "pending_inbox_count": self.pending_inbox_count(None)
        }))
    }

    pub(super) fn mail_list(&mut self, input: MailListInput) -> Result<Value> {
        let selected = self
            .state
            .mail
            .messages
            .iter()
            .enumerate()
            .filter(|(_, stored)| input.direction.is_none_or(|d| stored.direction == d))
            .filter(|(_, stored)| {
                input
                    .mailbox_id
                    .as_ref()
                    .is_none_or(|id| &stored.mailbox_id == id)
            })
            .filter(|(_, stored)| {
                input
                    .from
                    .as_ref()
                    .is_none_or(|from| &stored.message.sender == from)
            })
            .filter(|(_, stored)| {
                input
                    .thread_id
                    .as_ref()
                    .is_none_or(|id| &stored.message.thread_id == id)
            })
            .filter(|(_, stored)| {
                input
                    .message_id
                    .as_ref()
                    .is_none_or(|id| &stored.message.message_id == id)
            })
            .filter(|(_, stored)| !input.unread_only || is_unread(stored))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        let (indices, mut next_cursor) =
            page(selected, input.cursor.as_deref(), input.limit.unwrap_or(20));
        if input.unread_only && input.mark_read {
            // The page leaves the unread selection, so the next one starts at
            // the same offset.
            let offset = input
                .cursor
                .as_deref()
                .and_then(|c| c.parse::<usize>().ok());
            next_cursor = next_cursor.map(|_| offset.unwrap_or(0).to_string());
        }
        let mut messages = Vec::new();
        for index in indices {
            let stored = &mut self.state.mail.messages[index];
            messages.push(mail_message_view(stored, input.include_data));
            if input.mark_read && stored.direction == MailDirection::Received {
                stored.read = true;
            }
        }
        let unread_count = self
            .state
            .mail
            .messages
            .iter()
            .filter(|stored| is_unread(stored))
            .count();
        Ok(with_cursor(
            json!({ "messages": messages, "unread_count": unread_count }),
            next_cursor,
        ))
    }

    // ── Cards and delivery.

    fn sign_mail_card(&mut self, payload: MailboxCardPayload) -> Result<MailboxCard> {
        let created_at = unix_ms();
        let nonce = self.nonce_manager.next_nonce_at(created_at)?;
        sign_card(&self.signer, payload, created_at, nonce)
    }

    fn mail_client(&self, route: &str) -> Result<MailClient> {
        self.require_allowed_host(route)?;
        MailClient::with_client(route, self.http.clone())
    }

    /// Reads the card from an allowed route — the given routes, or the pinned
    /// card's — and pins it. A newer card that is closed or expired supersedes
    /// older ones; when no route answers, a usable pin is used.
    async fn mail_card(
        &mut self,
        owner: &AgentId,
        mailbox_id: &str,
        routes: &[String],
        now: i64,
    ) -> Result<MailboxCard> {
        let candidates = if routes.is_empty() {
            self.state
                .mail
                .pins
                .get(owner, mailbox_id)
                .map(|card| card.event.payload.routes.clone())
                .unwrap_or_default()
        } else {
            routes.to_vec()
        };
        let mut last_error = None;
        for route in candidates {
            let client = match self.mail_client(&route) {
                Ok(client) => client,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            match client.card_at(mailbox_id, owner, now).await {
                Ok(record) => {
                    let value = serde_json::to_value(&record.envelope)?;
                    match self.state.mail.pins.observe_historical(&value, owner, now) {
                        Ok(card) => {
                            check_card_usable(&card, owner, now)?;
                            return Ok(card);
                        }
                        Err(error) => last_error = Some(error),
                    }
                }
                Err(error) => last_error = Some(error),
            }
        }
        match self.state.mail.pins.get(owner, mailbox_id) {
            Some(card) if check_card_usable(card, owner, now).is_ok() => Ok(card.clone()),
            _ => Err(last_error.unwrap_or_else(|| {
                SdkError::InvalidPayload(
                    "no card is pinned for this mailbox; use a contact address with routes"
                        .to_owned(),
                )
            })),
        }
    }

    /// Delivers a sent message to its card's allowed routes in order, sealing
    /// a packet unless the stored one was sealed under this card. On
    /// `stale_card` it reads the card again and seals under a newer pin once.
    async fn deliver(
        &mut self,
        stored: &mut StoredMailMessage,
        mut card: MailboxCard,
    ) -> Result<Delivery> {
        let owner = stored.message.to.clone();
        let mut refreshed = false;
        loop {
            let now = unix_ms();
            let packet = match &stored.packet {
                Some(packet) if packet.event.payload.header.card_hash == card.hash => {
                    packet.clone()
                }
                _ => {
                    let nonce = self.nonce_manager.next_nonce_at(now)?;
                    let packet = encrypt_message(&stored.message, &card, &self.signer, nonce, now)?;
                    stored.packet = Some(packet.clone());
                    packet
                }
            };
            let mut transient = None;
            let mut permanent = None;
            let mut stale = false;
            for route in &card.event.payload.routes {
                let Ok(client) = self.mail_client(route) else {
                    continue;
                };
                match client.deliver(&packet).await {
                    Ok(result) => {
                        stored.delivery = Some(MailDelivery {
                            status: MailDeliveryStatus::Delivered,
                            route: Some(route.clone()),
                            packet_id: Some(result.packet_id),
                            accepted_at: Some(result.accepted_at),
                            last_error: None,
                        });
                        return Ok(Delivery::Delivered);
                    }
                    Err(error) => {
                        stale |= error.code() == Some("stale_card");
                        if is_transient(&error) {
                            transient = Some(route_error(route, &error));
                        } else if permanent.is_none() {
                            permanent = Some((route.clone(), error));
                        }
                    }
                }
            }
            if stale && !refreshed {
                refreshed = true;
                let mailbox_id = card.event.payload.mailbox_id.clone();
                let routes = card.event.payload.routes.clone();
                let fresh = self.mail_card(&owner, &mailbox_id, &routes, now).await?;
                if fresh.hash != card.hash {
                    card = fresh;
                    continue;
                }
            }
            let last_error = transient.clone().or_else(|| {
                permanent
                    .as_ref()
                    .map(|(route, error)| route_error(route, error))
            });
            stored.delivery = Some(MailDelivery {
                status: MailDeliveryStatus::Queued,
                route: None,
                packet_id: None,
                accepted_at: None,
                last_error,
            });
            if transient.is_some() {
                return Ok(Delivery::Queued);
            }
            return Err(permanent
                .map(|(_, error)| error)
                .unwrap_or(SdkError::PermissionDenied));
        }
    }

    /// Retries queued messages with their stored packets; reports the
    /// `message_id`s delivered and those that expired undelivered.
    async fn retry_queued(
        &mut self,
        now: i64,
        errors: &mut Vec<RouteError>,
    ) -> Result<(Vec<String>, Vec<String>)> {
        let mut delivered = Vec::new();
        let mut expired = Vec::new();
        for index in 0..self.state.mail.messages.len() {
            let mut stored = self.state.mail.messages[index].clone();
            if !is_queued(&stored) {
                continue;
            }
            if now >= stored.message.expires_at {
                expired.push(stored.message.message_id.clone());
                continue;
            }
            let Some(card) = self
                .state
                .mail
                .pins
                .get(&stored.message.to, &stored.mailbox_id)
                .cloned()
            else {
                continue;
            };
            match self.deliver(&mut stored, card).await {
                Ok(Delivery::Delivered) => delivered.push(stored.message.message_id.clone()),
                Ok(Delivery::Queued) => {}
                Err(_) => errors.extend(
                    stored
                        .delivery
                        .as_ref()
                        .and_then(|delivery| delivery.last_error.clone()),
                ),
            }
            self.state.mail.messages[index] = stored;
        }
        Ok((delivered, expired))
    }

    // ── Receiving.

    async fn poll_mailboxes(
        &mut self,
        only: Option<&str>,
        errors: &mut Vec<RouteError>,
    ) -> Result<Vec<MailMessageView>> {
        let owner = self.agent_id();
        let keyring = self.mail_keyring()?;
        // Every route of every retained card: old routes keep queued packets
        // until they are retrieved or expire (Agent Mail Section 4.3).
        let targets = self
            .state
            .mail
            .mailboxes
            .iter()
            .filter(|(mailbox_id, _)| only.is_none_or(|only| only == *mailbox_id))
            .map(|(mailbox_id, cards)| {
                let mut routes: Vec<String> = Vec::new();
                for route in cards
                    .iter()
                    .rev()
                    .flat_map(|card| card.event.payload.routes.iter())
                {
                    if !routes.contains(route) {
                        routes.push(route.clone());
                    }
                }
                (mailbox_id.clone(), routes)
            })
            .collect::<Vec<_>>();
        let mut received = Vec::new();
        for (mailbox_id, routes) in targets {
            for route in routes {
                let Ok(client) = self.mail_client(&route) else {
                    continue;
                };
                let jwt = self.request_jwt(&route)?;
                let mut deletions = Vec::new();
                let mut cursor: Option<String> = None;
                for _ in 0..SYNC_MAX_PAGES {
                    let now = unix_ms();
                    let page = match client
                        .list(
                            &mailbox_id,
                            &owner,
                            &jwt,
                            now,
                            SYNC_PAGE_LIMIT,
                            cursor.as_deref(),
                        )
                        .await
                    {
                        Ok(page) => page,
                        Err(error) => {
                            errors.push(RouteError {
                                mailbox_id: Some(mailbox_id.clone()),
                                ..route_error(&route, &error)
                            });
                            break;
                        }
                    };
                    for record in &page.result {
                        match self.accept_packet(&keyring, &mailbox_id, record, now) {
                            Disposition::Stored(view) => received.push(*view),
                            Disposition::Delete => deletions.push(record.packet_id.clone()),
                            Disposition::Keep(error) => errors.push(RouteError {
                                mailbox_id: Some(mailbox_id.clone()),
                                packet_id: Some(record.packet_id.clone()),
                                ..route_error(&route, &error)
                            }),
                        }
                    }
                    match page.next_cursor {
                        Some(next) => cursor = Some(next),
                        None => break,
                    }
                }
                for packet_id in deletions {
                    if let Err(error) = client
                        .delete(&mailbox_id, &packet_id, &owner, &jwt, unix_ms())
                        .await
                    {
                        errors.push(RouteError {
                            mailbox_id: Some(mailbox_id.clone()),
                            packet_id: Some(packet_id),
                            ..route_error(&route, &error)
                        });
                    }
                }
            }
        }
        Ok(received)
    }

    /// Recipient acceptance (Agent Mail Section 7.2) of one listed packet,
    /// whose shape, hash, and signature the list already verified.
    fn accept_packet(
        &mut self,
        keyring: &MailKeyring,
        mailbox_id: &str,
        record: &PacketRecord,
        now: i64,
    ) -> Disposition {
        let packet = &record.packet;
        // Sender policy applies before decryption.
        if self
            .state
            .mail
            .blocked_senders
            .contains(&packet.event.actor)
            || now >= packet.event.payload.header.expires_at
        {
            return Disposition::Delete;
        }
        let message = match keyring.open(packet, now) {
            Ok(message) => message,
            Err(error) => return Disposition::Keep(error),
        };
        let existing = self.state.mail.messages.iter().find(|stored| {
            stored.direction == MailDirection::Received
                && stored.message.sender == message.sender
                && stored.message.message_id == message.message_id
        });
        if let Some(existing) = existing {
            return match same_message(&existing.message, &message) {
                Ok(true) => Disposition::Delete,
                Ok(false) => Disposition::Keep(SdkError::protocol(
                    "invalid_event",
                    "message ID reused for different content",
                )),
                Err(error) => Disposition::Keep(error),
            };
        }
        if let Some(reply_card) = &message.reply_card {
            // Verified with the message; a card older than the pin is not used.
            let _ = self
                .state
                .mail
                .pins
                .observe_historical(reply_card, &message.sender, now);
        }
        let stored = StoredMailMessage {
            direction: MailDirection::Received,
            message,
            mailbox_id: mailbox_id.to_owned(),
            received_at: Some(now),
            read: false,
            packet: None,
            delivery: None,
        };
        let view = mail_message_view(&stored, false);
        self.insert_inbox(mail_inbox_item(&stored.message, now));
        self.state.mail.messages.push(stored);
        Disposition::Stored(Box::new(view))
    }

    /// The retained cards whose keys are loaded, for opening packets.
    fn mail_keyring(&self) -> Result<MailKeyring> {
        let mut keyring = MailKeyring::new(self.agent_id());
        for card in self.state.mail.mailboxes.values().flatten() {
            if let Some(key) = self.mail_keys.get(&card.event.payload.public_key) {
                keyring.add(card, MailEncryptionKey::from_secret(&key.export_secret())?)?;
            }
        }
        Ok(keyring)
    }

    // ── Local state.

    /// Drops cards past `receive_until` with keys no retained card advertises,
    /// stale pins, and expired messages.
    fn prune_mail(&mut self, now: i64) {
        let mail = &mut self.state.mail;
        for cards in mail.mailboxes.values_mut() {
            cards.retain(|card| now < card.event.payload.receive_until);
        }
        mail.mailboxes.retain(|_, cards| !cards.is_empty());
        let advertised = mail
            .mailboxes
            .values()
            .flatten()
            .map(|card| card.event.payload.public_key.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        self.mail_keys
            .retain(|public_key, _| advertised.contains(public_key.as_str()));
        let _ = mail.pins.prune(now);
        mail.messages
            .retain(|stored| now < stored.message.expires_at);
    }

    fn reply_parent(&self, message_id: &str, to: Option<&str>) -> Result<MessagePayload> {
        let owner = to.map(parse_mail_address).transpose()?.map(|a| a.owner);
        let mut found = self.state.mail.messages.iter().filter(|stored| {
            stored.direction == MailDirection::Received
                && stored.message.message_id == message_id
                && owner
                    .as_ref()
                    .is_none_or(|owner| &stored.message.sender == owner)
        });
        match (found.next(), found.next()) {
            (Some(stored), None) => Ok(stored.message.clone()),
            (Some(_), Some(_)) => Err(SdkError::InvalidPayload(
                "several received messages share this message_id; pass to".to_owned(),
            )),
            _ => Err(SdkError::InvalidPayload(
                "no received message has this message_id".to_owned(),
            )),
        }
    }

    fn open_mailbox_card(&self, mailbox_id: &str, now: i64) -> Result<MailboxCard> {
        let card = self
            .state
            .mail
            .mailboxes
            .get(mailbox_id)
            .and_then(|cards| cards.last())
            .ok_or_else(|| SdkError::InvalidPayload("unknown reply mailbox".to_owned()))?;
        check_card_usable(card, &self.agent_id(), now)
            .map_err(|_| SdkError::InvalidPayload("the reply mailbox is not open".to_owned()))?;
        Ok(card.clone())
    }

    fn mailbox_view(&self, mailbox_id: &str, card: &MailboxCard, now: i64) -> Result<MailboxView> {
        let payload = &card.event.payload;
        let status = if payload.routes.is_empty() {
            MailboxStatus::Closed
        } else if now >= payload.expires_at {
            MailboxStatus::Expired
        } else {
            MailboxStatus::Open
        };
        Ok(MailboxView {
            mailbox_id: mailbox_id.to_owned(),
            address: format_mail_address(&card.event.actor, mailbox_id, &payload.routes)?,
            routes: payload.routes.clone(),
            card_hash: card.hash.clone(),
            created_at: card.event.created_at,
            expires_at: payload.expires_at,
            receive_until: payload.receive_until,
            max_packet_bytes: payload.max_packet_bytes,
            status,
            unread_count: self
                .state
                .mail
                .messages
                .iter()
                .filter(|stored| is_unread(stored) && stored.mailbox_id == mailbox_id)
                .count(),
        })
    }
}

fn checked_routes(routes: &[String]) -> Result<Vec<String>> {
    if routes.len() > MAX_ROUTES {
        return Err(SdkError::InvalidPayload(
            "a card lists at most 8 routes".to_owned(),
        ));
    }
    let mut checked: Vec<String> = Vec::new();
    for route in routes {
        validate_origin(route)?;
        if checked.contains(route) {
            return Err(SdkError::InvalidPayload("duplicate route".to_owned()));
        }
        checked.push(route.clone());
    }
    Ok(checked)
}

fn is_queued(stored: &StoredMailMessage) -> bool {
    stored.direction == MailDirection::Sent
        && stored
            .delivery
            .as_ref()
            .is_some_and(|delivery| delivery.status == MailDeliveryStatus::Queued)
}

fn is_unread(stored: &StoredMailMessage) -> bool {
    stored.direction == MailDirection::Received && !stored.read
}

/// Network failures, `rate_limited`, and 5xx statuses are worth retrying.
pub(super) fn is_transient(error: &SdkError) -> bool {
    match error {
        SdkError::Http(_) => true,
        SdkError::HttpStatus { status, code, .. } => {
            *status >= 500 || *status == 429 || code.as_deref() == Some("rate_limited")
        }
        _ => false,
    }
}

fn route_error(route: &str, error: &SdkError) -> RouteError {
    RouteError {
        route: route.to_owned(),
        code: error_code(error).to_owned(),
        message: error.to_string(),
        mailbox_id: None,
        packet_id: None,
    }
}

fn same_message(a: &MessagePayload, b: &MessagePayload) -> Result<bool> {
    Ok(canonical_bytes(a)? == canonical_bytes(b)?)
}

fn mail_message_view(stored: &StoredMailMessage, include_data: bool) -> MailMessageView {
    let message = &stored.message;
    let parts = message
        .parts
        .iter()
        .map(|part| {
            let bytes = decode_bytes(&part.data).unwrap_or_default();
            let text = part
                .media_type
                .starts_with("text/")
                .then(|| String::from_utf8_lossy(&bytes).into_owned());
            MailPartView {
                media_type: part.media_type.clone(),
                name: part.name.clone(),
                size: bytes.len(),
                data: (include_data && text.is_none()).then(|| part.data.clone()),
                text,
            }
        })
        .collect();
    let reply_address = message
        .reply_card
        .as_ref()
        .and_then(|card| validate_card(card).ok())
        .and_then(|card| {
            format_mail_address(
                &card.event.actor,
                &card.event.payload.mailbox_id,
                &card.event.payload.routes,
            )
            .ok()
        });
    let received = stored.direction == MailDirection::Received;
    MailMessageView {
        direction: stored.direction,
        message_id: message.message_id.clone(),
        thread_id: message.thread_id.clone(),
        from: message.sender.clone(),
        to: message.to.clone(),
        mailbox_id: stored.mailbox_id.clone(),
        subject: message.subject.clone(),
        created_at: message.created_at,
        expires_at: message.expires_at,
        received_at: stored.received_at,
        in_reply_to: message.in_reply_to.clone(),
        reply_address,
        parts,
        read: received.then_some(stored.read),
        delivery: stored.delivery.clone(),
    }
}

fn mail_inbox_item(message: &MessagePayload, now: i64) -> InboxItem {
    let summary = message
        .subject
        .clone()
        .or_else(|| {
            message
                .parts
                .iter()
                .find(|part| part.media_type.starts_with("text/"))
                .and_then(|part| decode_bytes(&part.data).ok())
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        })
        .filter(|summary| !summary.trim().is_empty())
        .map(|summary| truncate(&summary, SUMMARY_MAX_CHARS))
        .unwrap_or_else(|| "mail".to_owned());
    InboxItem {
        id: format!("mail.received:{}:{}", message.sender, message.message_id),
        kind: InboxKind::MailReceived,
        priority: InboxPriority::Normal,
        room_id: None,
        seq: None,
        event_id: None,
        actor: Some(message.sender.clone()),
        created_at: now,
        requires_response: false,
        deadline: None,
        reason: "received".to_owned(),
        suggested_tools: vec![TOOL_MAIL_LIST.to_owned()],
        message: Some(json!({
            "summary": summary,
            "message_id": message.message_id,
            "thread_id": message.thread_id
        })),
    }
}
