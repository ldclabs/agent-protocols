//! Local Agent Protocols MCP connector core.
//!
//! This module is transport-neutral: it exposes the standard local connector
//! tool names, schemas, structured result types, a JSON dispatcher, and local
//! room-state projection. An MCP stdio server can wrap [`LocalConnector`] without
//! giving the agent direct access to signing keys or reusable request JWTs.
//!
//! The connector itself is one deep module: [`LocalConnector`] presents a small
//! interface (construct, feed observations and records, dispatch a tool call)
//! over a large implementation. That implementation is organised into internal
//! seams that vary independently:
//!
//! - [`catalog`] — the static tool/resource surface advertised to `tools/list`.
//! - [`views`] — the structured result types callers read back.
//! - [`inputs`] — the per-tool deserialization shapes.
//! - [`state`] — the in-memory store records are projected into.
//! - [`projection`] — the pure ADP record → room-state rules and validation.
//!
//! The orchestration that ties signing, networking, and projection together
//! stays here because those methods are mutually recursive over `self`; they
//! form one body of behaviour rather than a seam something varies across.

mod catalog;
mod inputs;
mod projection;
mod state;
mod views;

#[cfg(test)]
mod tests;

pub use catalog::*;
pub use state::{LocalConnectorState, RoomKey};
pub use views::*;

use inputs::*;
use projection::*;
use state::{HeldDraftEntry, HeldDraftRequest, InboxEntry, InboxEntryState, LocalRoomState};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

use crate::delegation::{
    is_principal_alias, validate_delegation_event_authority, verify_delegation_credential,
    DelegationCredential, DelegationGrantPayload, DelegationPayload, DelegationQueryRequest,
    DelegationRevokePayload, PrincipalDocument, DELEGATION_GRANT, DELEGATION_REVOKE,
    PROTOCOL as DELEGATION_PROTOCOL,
};
use crate::discourse::{
    can_join_directly, discourse_event, event_type, room_create_event, room_join_request_event,
    validate_discourse_envelope, validate_room_path, verify_archive_record, AgentStatusInput,
    ArchiveRecord, JoinDecision, JoinRequestStatus, MessageCreatePayload, RoomCreatePayload,
    RoomJoinPayload, RoomJoinRequestPayload, RoomJoinReviewPayload, RoomMemberRemovePayload,
    RoomResponse,
};
use crate::error::{Result, SdkError};
use crate::http_client::{
    DelegationClient, DiscourseClient, JoinRequestsOptions, ProfileClient, PublicRoomsOptions,
    RoomEventsOptions,
};
use crate::identity::{
    service_origin, unix_ms, unix_secs, AgentId, AgentSigner, ClientNonceManager, Envelope, Event,
    RequestBinding, RequestJwtClaims, DEFAULT_REQUEST_JWT_TTL_SECS,
};
use crate::profile::{profile_update_event, AgentProfile, ProfileUpdatePayload};

/// Automatic `send_anyway` re-sign attempts before a draft is held.
pub const SEND_ANYWAY_MAX_ATTEMPTS: u32 = 3;
/// Lease on an inbox item claimed with `claim: true`.
pub const INBOX_CLAIM_LEASE_MS: i64 = 60_000;

/// Signs and submits once, re-signing a single time after a bounded
/// `Max-Seen-Nonce` resync. Evaluates to `Result<(response, envelope)>`.
macro_rules! submit_signed {
    ($self:ident, $sign:expr, |$envelope:ident| $submit:expr) => {{
        let $envelope = $sign?;
        let first = $submit.await;
        match first {
            Ok(value) => Ok((value, $envelope)),
            Err(error) if $self.resync_nonce(&error) => {
                let $envelope = $sign?;
                $submit.await.map(|value| (value, $envelope))
            }
            Err(error) => Err(error),
        }
    }};
}

pub struct LocalConnector {
    signer: AgentSigner,
    nonce_manager: ClientNonceManager,
    state: LocalConnectorState,
    http: reqwest::Client,
}

impl LocalConnector {
    pub fn new(signer: AgentSigner) -> Self {
        Self::with_state(signer, LocalConnectorState::new())
    }

    pub fn with_state(signer: AgentSigner, state: LocalConnectorState) -> Self {
        Self {
            signer,
            nonce_manager: ClientNonceManager::new(),
            state,
            http: reqwest::Client::new(),
        }
    }

    /// Uses `client` for Agent Discourse and Agent Profile requests.
    pub fn with_http_client(mut self, client: reqwest::Client) -> Self {
        self.http = client;
        self
    }

    pub fn agent_id(&self) -> AgentId {
        self.signer.agent_id()
    }

    pub fn state(&self) -> &LocalConnectorState {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut LocalConnectorState {
        &mut self.state
    }

    pub fn add_host(&mut self, host: AgentProtocolsHost) {
        self.state.hosts.insert(normalize_host(&host.host), host);
    }

    pub fn observe_room(&mut self, host: impl Into<String>, room: RoomResponse) {
        let host = normalize_host(&host.into());
        self.ensure_host(&host);
        let key = (host.clone(), room.id.clone());
        let entry = self
            .state
            .rooms
            .entry(key)
            .or_insert_with(|| LocalRoomState::new(host.clone(), room.clone()));
        entry.host = host;
        entry.room = room;
        materialize_creator(entry);
    }

    pub fn accept_room_response(&mut self, host: impl Into<String>, room: RoomResponse) {
        let host = normalize_host(&host.into());
        let key = (host.clone(), room.id.clone());
        self.observe_room(host, room);
        if let Some(entry) = self.state.rooms.get_mut(&key) {
            let (head_seq, head_hash) = room_response_head(&entry.room);
            entry.head_seq = head_seq;
            entry.head_hash = Some(head_hash);
            entry.synced_seq = entry.room.seq;
            entry.synced_hash = Some(entry.room.hash.clone());
        }
    }

    /// Applies a verified record to the room identified by its `room_id`
    /// alone. Fails with an ambiguity error when the room ID matches rooms on
    /// more than one configured host; use [`Self::apply_host_record`] then.
    pub fn apply_record(&mut self, record: impl Into<ArchiveRecord>) -> Result<()> {
        let record = record.into();
        let key = self.resolve_room_key(None, record.room_id())?;
        self.apply_record_to(&key, record)
    }

    /// Applies a verified record to the room on the given host.
    pub fn apply_host_record(
        &mut self,
        host: &str,
        record: impl Into<ArchiveRecord>,
    ) -> Result<()> {
        let record = record.into();
        let key = (normalize_host(host), record.room_id().to_owned());
        self.apply_record_to(&key, record)
    }

    fn apply_record_to(&mut self, key: &RoomKey, record: ArchiveRecord) -> Result<()> {
        if let ArchiveRecord::Signed(signed) = &record {
            validate_discourse_envelope(&signed.envelope)?;
            validate_room_path(&signed.envelope, &signed.room_id)?;
        }
        verify_archive_record(&record)?;

        let active_agent = self.agent_id();
        let mut new_inbox = Vec::new();
        let mut cleared_status: Option<AgentId> = None;
        {
            let room = self.state.rooms.get_mut(key).ok_or_else(|| {
                SdkError::InvalidPayload(format!("room is not open locally: {}", key.1))
            })?;
            if is_duplicate_record(room, &record) {
                return Ok(());
            }
            validate_next_record(room, &record)?;
            validate_record_base_precondition(room, &record)?;

            let item = TimelineItem::from_record(&record, &room.room.types);
            apply_record_projection(room, &record, &item, &active_agent, &mut new_inbox)?;
            if let ArchiveRecord::Signed(signed) = &record {
                if signed.envelope.event.kind == event_type::ROOM_MEMBER_REMOVE {
                    cleared_status = serde_json::from_value::<RoomMemberRemovePayload>(
                        signed.envelope.event.payload.clone(),
                    )
                    .ok()
                    .map(|payload| payload.member);
                }
            }
            if record_advances_room_head(room, &record) {
                room.head_seq = record.seq();
                room.head_hash = Some(record.hash().to_owned());
            }
            room.synced_seq = record.seq();
            room.synced_hash = Some(record.hash().to_owned());
            room.records.push(record);
            room.timeline.push(item);
        }
        // Removal ends membership; the host clears the member's transient
        // agent status, so drop the local cache entry too.
        if let Some(member) = cleared_status {
            if let Some(statuses) = self.state.agent_statuses.get_mut(key) {
                statuses.remove(&member);
            }
        }
        for item in new_inbox {
            self.insert_inbox(item);
        }
        Ok(())
    }

    /// Resolves `(host, room_id)` for a tool call. Without a `host` input the
    /// room ID must match exactly one locally known room; the connector
    /// returns an ambiguity error instead of guessing between hosts.
    fn resolve_room_key(&self, host: Option<&str>, room_id: &str) -> Result<RoomKey> {
        if let Some(host) = host {
            return Ok((normalize_host(host), room_id.to_owned()));
        }
        let mut keys = self
            .state
            .rooms
            .keys()
            .filter(|(_, known_room_id)| known_room_id == room_id);
        match (keys.next(), keys.next()) {
            (Some(key), None) => Ok(key.clone()),
            (Some(_), Some(_)) => Err(SdkError::InvalidPayload(format!(
                "room id {room_id} matches rooms on more than one host; pass host"
            ))),
            _ => Err(SdkError::InvalidPayload(format!(
                "room is not open locally: {room_id}"
            ))),
        }
    }

    pub async fn call_tool(&mut self, name: &str, input: Value) -> Result<Value> {
        match name {
            TOOL_IDENTITY_CURRENT => self.identity_current(),
            TOOL_PRINCIPAL_RESOLVE => self.principal_resolve(parse_input(input)?).await,
            TOOL_DELEGATION_CHECK => self.delegation_check(parse_input(input)?).await,
            TOOL_DELEGATIONS_LIST => self.delegations_list(parse_input(input)?).await,
            TOOL_DELEGATION_GRANT => self.delegation_grant(parse_input(input)?).await,
            TOOL_DELEGATION_REVOKE => self.delegation_revoke(parse_input(input)?).await,
            TOOL_ROOMS_LIST => self.rooms_list(parse_input(input)?).await,
            TOOL_ROOM_STATE => self.room_state(parse_input(input)?).await,
            TOOL_ROOM_MEMBERS_LIST => self.room_members_list(parse_input(input)?),
            TOOL_AGENT_STATUS_LIST => self.agent_status_list(parse_input(input)?).await,
            TOOL_AGENT_STATUS_SET => self.agent_status_set(parse_input(input)?).await,
            TOOL_ROOM_TIMELINE => self.room_timeline(parse_input(input)?).await,
            TOOL_INBOX_NEXT => self.inbox_next(parse_input(input)?),
            TOOL_INBOX_ACK => self.inbox_ack(parse_input(input)?),
            TOOL_DRAFTS_LIST => self.drafts_list(parse_input(input)?),
            TOOL_DRAFT_COMMIT => self.draft_commit(parse_input(input)?).await,
            TOOL_PROFILE_UPDATE => self.profile_update(parse_input(input)?).await,
            TOOL_ROOM_CREATE => self.room_create(parse_input(input)?).await,
            TOOL_ROOM_JOIN => self.room_join(parse_input(input)?).await,
            TOOL_ROOM_SEND_MESSAGE => {
                self.submit_room_write(HeldDraftRequest::Message(parse_input(input)?))
                    .await
            }
            TOOL_ROOM_SUBMIT_EVENT => {
                self.submit_room_write(HeldDraftRequest::Event(parse_input(input)?))
                    .await
            }
            TOOL_JOIN_REQUESTS_LIST => self.join_requests_list(parse_input(input)?).await,
            TOOL_JOIN_REQUEST_REVIEW => self.join_request_review(parse_input(input)?).await,
            _ => Err(SdkError::InvalidPayload(format!(
                "unknown local connector tool: {name}"
            ))),
        }
    }

    fn identity_current(&self) -> Result<Value> {
        let agent_id = self.agent_id();
        let public_key = URL_SAFE_NO_PAD.encode(agent_id.public_key_bytes()?);
        Ok(json!({
            "agent_id": agent_id,
            "public_key": public_key,
            "profiles": self.state.profiles.keys().collect::<Vec<_>>(),
            "hosts": self.state.hosts.values().collect::<Vec<_>>()
        }))
    }

    async fn rooms_list(&mut self, input: RoomsListInput) -> Result<Value> {
        input.validate_scope().map_err(SdkError::InvalidPayload)?;
        match input.scope {
            RoomsListScope::Known => self.known_rooms(input),
            RoomsListScope::Public => self.public_rooms(input).await,
        }
    }

    async fn public_rooms(&mut self, input: RoomsListInput) -> Result<Value> {
        let host = normalize_host(input.host.as_deref().unwrap_or_default());
        self.require_allowed_host(&host)?;
        let response = self
            .discourse(&host)
            .public_rooms(&PublicRoomsOptions {
                status: input.status,
                tag: input.tag,
                keyword: input.keyword,
                creator: input.creator,
                starts_after: input.starts_after,
                ends_before: input.ends_before,
                language: input.language,
                limit: input.limit,
                cursor: input.cursor,
            })
            .await?;
        for room in &response.result {
            self.observe_room(&host, room.clone());
        }
        let rooms = response
            .result
            .iter()
            .map(|room| self.summary_for_response(&host, room))
            .collect::<Vec<_>>();
        Ok(with_cursor(json!({ "rooms": rooms }), response.next_cursor))
    }

    fn known_rooms(&self, input: RoomsListInput) -> Result<Value> {
        let agent_id = self.agent_id();
        let host = input.host.as_deref().map(normalize_host);
        let rooms = self
            .state
            .rooms
            .iter()
            .filter(|(key, _)| host.as_ref().is_none_or(|host| &key.0 == host))
            .filter(|(_, room)| {
                input
                    .status
                    .as_deref()
                    .map(|status| enum_str(&room.room.status).as_deref() == Some(status))
                    .unwrap_or(true)
            })
            .filter(|(key, room)| {
                let pending = self
                    .state
                    .own_join_requests
                    .get(*key)
                    .is_some_and(|request| request.status == JoinRequestStatus::Pending);
                membership_filter(room, &agent_id, input.membership, pending)
            })
            .map(|(_, room)| self.summary_for_room(room))
            .collect::<Vec<_>>();
        let (rooms, next_cursor) = page(rooms, input.cursor.as_deref(), input.limit.unwrap_or(50));
        Ok(with_cursor(json!({ "rooms": rooms }), next_cursor))
    }

    /// Reads the room resource and every record after the local tip, then
    /// verifies and applies them.
    async fn sync_room(&mut self, key: &RoomKey) -> Result<()> {
        let client = self.discourse(&key.0);
        let jwt = self.request_jwt(&key.0)?;
        let room = client.room(&key.1, Some(&jwt)).await?;
        self.observe_room(&key.0, room);
        let synced_seq = self.local_room(key)?.synced_seq;
        let mut cursor = None;
        loop {
            let response = client
                .events_with_options(
                    &key.1,
                    &RoomEventsOptions {
                        after_seq: (synced_seq > 0).then_some(synced_seq),
                        limit: None,
                        cursor,
                        jwt: Some(jwt.clone()),
                    },
                )
                .await?;
            for record in response.result {
                self.apply_host_record(&key.0, record)?;
            }
            match response.next_cursor {
                Some(next) => cursor = Some(next),
                None => return Ok(()),
            }
        }
    }

    async fn room_state(&mut self, input: RoomStateInput) -> Result<Value> {
        let key = match input.host.as_deref() {
            Some(host) => (normalize_host(host), input.room_id.clone()),
            None => self.resolve_room_key(None, &input.room_id)?,
        };
        self.require_allowed_host(&key.0)?;
        let known = self
            .state
            .rooms
            .get(&key)
            .is_some_and(|room| room.synced_seq > 0);
        if !known || input.refresh {
            self.sync_room(&key).await?;
        }
        let room = self.local_room_mut(&key)?;
        if let Some(subscribe) = input.subscribe {
            room.subscribed = subscribe;
        }
        // The first state read in a session is the agent's starting view.
        if room.presented_seq.is_none() {
            let head_seq = room.head_seq;
            present_head(room, head_seq);
        }
        let room = self.local_room(&key)?;
        Ok(json!({
            "room": self.room_state_view(room),
            "sync": self.sync_state(&key)?,
            "active_turn": room.active_turn
        }))
    }

    fn room_members_list(&self, input: RoomMembersListInput) -> Result<Value> {
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
        let room = self.local_room(&key)?;
        let mut members = room
            .members
            .values()
            .filter(|member| {
                input
                    .agent_id
                    .as_ref()
                    .map(|agent_id| &member.agent_id == agent_id)
                    .unwrap_or(true)
            })
            .filter(|member| match input.status {
                Some(MemberStatusFilter::Status(status)) => member.status == status,
                _ => true,
            })
            .filter(|member| input.role.map(|role| role == member.role).unwrap_or(true))
            .cloned()
            .collect::<Vec<_>>();
        if input.agent_id.is_some() && members.is_empty() {
            return Err(SdkError::InvalidPayload("room member not found".to_owned()));
        }
        if input.include_profiles {
            for member in &mut members {
                if member.profile.is_none() {
                    member.profile = self
                        .state
                        .profiles
                        .get(&member.agent_id)
                        .map(profile_to_member_profile);
                }
            }
        }
        let (members, next_cursor) =
            page(members, input.cursor.as_deref(), input.limit.unwrap_or(100));
        let mut result = json!({ "members": members, "sync": self.sync_state(&key)? });
        if let (Some(agent_id), true) = (&input.agent_id, input.include_recent_activity) {
            let recent = room
                .timeline
                .iter()
                .filter(|item| item.actor.as_ref() == Some(agent_id))
                .rev()
                .take(10)
                .cloned()
                .collect::<Vec<_>>();
            result["recent"] = json!(recent);
        }
        Ok(with_cursor(result, next_cursor))
    }

    async fn agent_status_list(&mut self, input: AgentStatusListInput) -> Result<Value> {
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
        if let Some(agent_id) = &input.agent_id {
            let hit = (!input.refresh)
                .then(|| {
                    self.state
                        .agent_statuses
                        .get(&key)
                        .and_then(|statuses| statuses.get(agent_id))
                        .cloned()
                })
                .flatten();
            if let Some(hit) = hit {
                return Ok(json!({ "statuses": [hit], "sync": self.sync_state(&key)? }));
            }
            let host = self.allowed_room_host(&key)?;
            let jwt = self.request_jwt(&host)?;
            let status = match self
                .discourse(&host)
                .agent_status(&input.room_id, agent_id, Some(&jwt))
                .await
            {
                Ok(status) => status,
                Err(error) if http_code(&error) == Some("agent_status_not_found") => {
                    return Ok(json!({ "statuses": [], "sync": self.sync_state(&key)? }));
                }
                Err(error) => return Err(error),
            };
            self.state
                .agent_statuses
                .entry(key.clone())
                .or_default()
                .insert(status.agent_id.clone(), status.clone());
            return Ok(json!({ "statuses": [status], "sync": self.sync_state(&key)? }));
        }
        if !input.refresh {
            if let Some(statuses) = self.state.agent_statuses.get(&key) {
                return Ok(json!({
                    "statuses": statuses.values().collect::<Vec<_>>(),
                    "sync": self.sync_state(&key)?
                }));
            }
        }
        let host = self.allowed_room_host(&key)?;
        let jwt = self.request_jwt(&host)?;
        let response = self
            .discourse(&host)
            .agent_statuses(&input.room_id, Some(&jwt))
            .await?;
        let statuses = response
            .result
            .into_iter()
            .map(|status| (status.agent_id.clone(), status))
            .collect::<BTreeMap<_, _>>();
        let values = statuses.values().cloned().collect::<Vec<_>>();
        self.state.agent_statuses.insert(key.clone(), statuses);
        Ok(json!({ "statuses": values, "sync": self.sync_state(&key)? }))
    }

    async fn agent_status_set(&mut self, input: AgentStatusSetInput) -> Result<Value> {
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
        let host = self.allowed_room_host(&key)?;
        let jwt = self.request_jwt(&host)?;
        let room = self.local_room(&key)?;
        let mut request = AgentStatusInput::new(input.state);
        request.summary = input.summary;
        request.seen_seq = input
            .seen_seq
            .or((room.synced_seq > 0).then_some(room.synced_seq));
        request.seen_hash = input.seen_hash.or_else(|| {
            input
                .seen_seq
                .is_none()
                .then(|| room.synced_hash.clone())
                .flatten()
        });
        request.claim_id = input.claim_id;
        request.activity = input.activity;
        request.expires_at = input.expires_at;
        request.extra = input.extra;
        let status = self
            .discourse(&host)
            .set_agent_status(&input.room_id, &jwt, &request)
            .await?;
        let statuses = self.state.agent_statuses.entry(key.clone()).or_default();
        if status.expires_at <= unix_ms() {
            statuses.remove(&status.agent_id);
        } else {
            statuses.insert(status.agent_id.clone(), status.clone());
        }
        Ok(json!({ "status": status, "sync": self.sync_state(&key)? }))
    }

    async fn room_timeline(&mut self, input: RoomTimelineInput) -> Result<Value> {
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
        if input.refresh {
            self.sync_room(&key).await?;
        }
        let room = self.local_room(&key)?;
        let items = room
            .timeline
            .iter()
            .filter(|item| input.after_seq.map(|seq| item.seq > seq).unwrap_or(true))
            .filter(|item| input.before_seq.map(|seq| item.seq < seq).unwrap_or(true))
            .filter(|item| {
                input
                    .types
                    .as_ref()
                    .map(|types| types.contains(&item.event_type))
                    .unwrap_or(true)
            })
            .filter(|item| {
                input
                    .actors
                    .as_ref()
                    .map(|actors| {
                        item.actor
                            .as_ref()
                            .is_some_and(|actor| actors.contains(actor))
                    })
                    .unwrap_or(true)
            })
            .filter(|item| !input.unread_only || item.seq > room.read_seq)
            .take(input.limit.unwrap_or(50))
            .cloned()
            .collect::<Vec<_>>();
        let last_seq = items.last().map(|item| item.seq);
        let room = self.local_room_mut(&key)?;
        if let (true, Some(last_seq)) = (input.mark_read, last_seq) {
            room.read_seq = room.read_seq.max(last_seq);
        }
        // An unfiltered, gap-free read from the presented head presents the
        // latest head it reaches (local connector Section 4.2).
        if let (None, None, Some(last_seq)) = (&input.types, &input.actors, last_seq) {
            let base = room.presented_seq.unwrap_or(0);
            let contiguous = items.windows(2).all(|pair| pair[1].seq == pair[0].seq + 1);
            if contiguous && items[0].seq <= base + 1 {
                present_through(room, last_seq);
            }
        }
        let unread_count = room.unread_count();
        let mut result = json!({
            "items": items,
            "sync": self.sync_state(&key)?,
            "unread_count": unread_count
        });
        if let Some(last_seq) = last_seq {
            result["next_after_seq"] = json!(last_seq);
        }
        Ok(result)
    }

    fn inbox_next(&mut self, input: InboxNextInput) -> Result<Value> {
        let _ = input.wait_ms;
        let now = unix_ms();
        let mut ids = self
            .state
            .inbox
            .iter()
            .filter(|(_, entry)| inbox_entry_ready(entry, now))
            .filter(|(_, entry)| {
                input
                    .room_id
                    .as_ref()
                    .map(|room_id| entry.item.room_id.as_ref() == Some(room_id))
                    .unwrap_or(true)
            })
            .filter(|(_, entry)| {
                input
                    .kinds
                    .as_ref()
                    .map(|kinds| {
                        enum_str(&entry.item.kind).is_some_and(|kind| kinds.contains(&kind))
                    })
                    .unwrap_or(true)
            })
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        ids.truncate(input.limit.unwrap_or(10));
        let mut items = Vec::new();
        for id in ids {
            if let Some(entry) = self.state.inbox.get_mut(&id) {
                items.push(entry.item.clone());
                // A claim is a lease, so a crashed session cannot hold the item forever.
                if input.claim {
                    entry.state = InboxEntryState::Claimed(now + INBOX_CLAIM_LEASE_MS);
                }
            }
        }
        Ok(json!({
            "items": items,
            "pending_count": self.pending_inbox_count(None)
        }))
    }

    fn inbox_ack(&mut self, input: InboxAckInput) -> Result<Value> {
        let mut acknowledged = Vec::new();
        for id in &input.ids {
            if let Some(entry) = self.state.inbox.get_mut(id) {
                entry.state = match input.action {
                    InboxAckAction::Handled | InboxAckAction::Dismissed => {
                        InboxEntryState::Acknowledged
                    }
                    InboxAckAction::Defer => {
                        InboxEntryState::Deferred(input.defer_until.unwrap_or_else(unix_ms))
                    }
                };
                acknowledged.push(id.clone());
            }
        }
        Ok(json!({
            "acknowledged": acknowledged,
            "pending_count": self.pending_inbox_count(None)
        }))
    }

    fn drafts_list(&mut self, input: DraftsListInput) -> Result<Value> {
        if let Some(draft_id) = &input.draft_id {
            let draft = self
                .state
                .drafts
                .get(draft_id)
                .map(|entry| entry.draft.clone())
                .ok_or_else(|| SdkError::InvalidPayload("draft not found".to_owned()))?;
            let key = (draft.current_sync.host.clone(), draft.room_id.clone());
            let changes = self.room_changes_since(&key, draft.base_seq)?;
            // The changes reach the current head, which is now presented.
            let room = self.local_room_mut(&key)?;
            let head_seq = room.head_seq;
            present_head(room, head_seq);
            return Ok(json!({
                "drafts": [draft],
                "changes": changes,
                "sync": self.sync_state(&key)?
            }));
        }
        let host = input.host.as_deref().map(normalize_host);
        let drafts = self
            .state
            .drafts
            .values()
            .filter(|entry| {
                input
                    .room_id
                    .as_ref()
                    .map(|room_id| &entry.draft.room_id == room_id)
                    .unwrap_or(true)
            })
            .filter(|entry| {
                host.as_ref()
                    .map(|host| &entry.draft.current_sync.host == host)
                    .unwrap_or(true)
            })
            .map(|entry| entry.draft.clone())
            .collect::<Vec<_>>();
        let (drafts, next_cursor) =
            page(drafts, input.cursor.as_deref(), input.limit.unwrap_or(50));
        Ok(with_cursor(json!({ "drafts": drafts }), next_cursor))
    }

    async fn draft_commit(&mut self, input: DraftCommitInput) -> Result<Value> {
        let entry = self
            .state
            .drafts
            .get(&input.draft_id)
            .cloned()
            .ok_or_else(|| SdkError::InvalidPayload("draft not found".to_owned()))?;
        if input.action == DraftAction::Drop {
            self.state.drafts.remove(&input.draft_id);
            return Ok(json!({ "status": "dropped", "draft_id": input.draft_id }));
        }
        let revise = input.action == DraftAction::Revise;
        // Both actions sign against the presented head; a further mismatch is
        // handled by on_head_mismatch.
        let request = match entry.request {
            HeldDraftRequest::Message(mut message) => {
                if revise {
                    if let Some(content) = input.content {
                        message.content = content;
                    }
                    if let Some(content_type) = input.content_type {
                        message.content_type = Some(content_type);
                    }
                    if let Some(mentions) = input.mentions {
                        message.mentions = mentions;
                    }
                    if let Some(references) = input.references {
                        message.references = references;
                    }
                    if let Some(extra) = input.extra {
                        message.extra = extra;
                    }
                }
                message.base_seq = None;
                message.base_hash = None;
                message.on_head_mismatch = input.on_head_mismatch;
                HeldDraftRequest::Message(message)
            }
            HeldDraftRequest::Event(mut event) => {
                if revise {
                    if let Some(event_type) = input.event_type {
                        event.event_type = event_type;
                    }
                    if let Some(payload) = input.payload {
                        event.payload = payload;
                    }
                    if let Some(mentions) = input.mentions {
                        event.mentions = mentions;
                    }
                    if let Some(references) = input.references {
                        event.references = references;
                    }
                }
                event.base_seq = None;
                event.base_hash = None;
                event.on_head_mismatch = input.on_head_mismatch;
                HeldDraftRequest::Event(event)
            }
        };
        let result = self.submit_room_write(request).await?;
        if matches!(result["status"].as_str(), Some("sent" | "held")) {
            self.state.drafts.remove(&input.draft_id);
        }
        Ok(result)
    }

    /// Resolves a principal per Agent Delegation Section 3 and reports
    /// whether the requested URL is an alias the principal acknowledges. Any
    /// origin can redirect to any principal, so an unlisted URL is never
    /// presented as a name for it.
    async fn resolve_principal(&self, url: &str) -> Result<(PrincipalDocument, bool)> {
        let document = DelegationClient::new(url).principal(Some(url)).await?;
        let alias = document.id != url && is_principal_alias(&document, url);
        Ok((document, alias))
    }

    /// The principal's authoritative delegation service, located from its
    /// `delegation_query_url`.
    async fn principal_delegation_service(
        &self,
        document: &PrincipalDocument,
    ) -> Result<(DelegationClient, String)> {
        let query_url = document.delegation_query_url.clone().ok_or_else(|| {
            SdkError::InvalidPayload(format!(
                "principal {} publishes no delegation_query_url",
                document.id
            ))
        })?;
        let origin = service_origin(&query_url)?;
        self.require_allowed_host(&origin)?;
        Ok((DelegationClient::discover(&origin).await, query_url))
    }

    /// Resolves the principal and refuses when the active Agent ID is not one
    /// of its current controller keys with delegation authority, so a grant
    /// that could never be accepted is not signed or transmitted.
    async fn controller_principal(&self, principal_id: &str) -> Result<PrincipalDocument> {
        let (document, _) = self.resolve_principal(principal_id).await?;
        let active = self.agent_id();
        if !document
            .controllers
            .iter()
            .any(|c| c.id == active && c.delegation.is_some() && c.valid_from <= unix_ms())
        {
            return Err(SdkError::InvalidPayload(format!(
                "active agent {active} is not a controller key of {}",
                document.id
            )));
        }
        Ok(document)
    }

    async fn principal_resolve(&self, input: PrincipalResolveInput) -> Result<Value> {
        let (document, alias) = self.resolve_principal(&input.url).await?;
        Ok(json!({
            "canonical_id": document.id,
            "requested_url": input.url,
            "alias": alias,
            "principal": document,
        }))
    }

    async fn delegation_check(&self, input: DelegationCheckInput) -> Result<Value> {
        let (document, _) = self.resolve_principal(&input.principal_id).await?;
        // The authoritative service is the one the principal names, never one
        // supplied by whoever presented a credential.
        let (service, query_url) = self.principal_delegation_service(&document).await?;
        let request = DelegationQueryRequest {
            subject: Some(input.subject.unwrap_or_else(|| self.agent_id())),
            principal_id: Some(document.id.clone()),
            id: input.id,
            ..DelegationQueryRequest::default()
        };
        let response = service
            .query_delegations_at(&query_url, &request, None)
            .await?;
        let now = unix_ms();
        let mut delegations = Vec::new();
        for credential in response.result {
            let verdict = match service.all_delegation_events(&credential.id).await {
                Ok(records) => verify_delegation_credential(
                    &credential,
                    &records,
                    &document,
                    &document.id,
                    &input.audience,
                    now,
                ),
                Err(error) => DelegationVerdict {
                    credential,
                    verified: false,
                    usable: false,
                    reasons: vec![format!("history unavailable: {error}")],
                },
            };
            delegations.push(verdict);
        }
        Ok(json!({
            "canonical_id": document.id,
            "query_url": query_url,
            "delegations": delegations,
        }))
    }

    async fn delegations_list(&self, input: DelegationsListInput) -> Result<Value> {
        // Enumerating one subject requires authorization; the connector proves
        // the active identity and never enumerates anyone else.
        let origin = service_origin(&input.delegation_service)?;
        let jwt = self.request_jwt(&origin)?;
        let service = DelegationClient::discover(&origin).await;
        let request = DelegationQueryRequest {
            subject: Some(self.agent_id()),
            status: input.status,
            limit: input.limit,
            cursor: input.cursor,
            ..DelegationQueryRequest::default()
        };
        let response = service.query_delegations(&request, Some(&jwt)).await?;
        Ok(with_cursor(
            json!({ "delegations": response.result }),
            response.next_cursor,
        ))
    }

    async fn delegation_previous(
        service: &DelegationClient,
        id: &str,
    ) -> Result<Option<DelegationCredential>> {
        match service.delegation(id).await {
            Ok(credential) => Ok(Some(credential)),
            Err(SdkError::HttpStatus { status: 404, .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    async fn delegation_grant(&mut self, input: DelegationGrantInput) -> Result<Value> {
        let principal = self.controller_principal(&input.principal_id).await?;
        let (service, _) = self.principal_delegation_service(&principal).await?;
        let previous = Self::delegation_previous(&service, &input.id).await?;
        let mut payload = DelegationGrantPayload::new(
            input.id,
            principal.id.clone(),
            input.subject,
            input.scopes,
            input.audiences,
        );
        payload.relationship = input.relationship;
        payload.constraints = input.constraints;
        payload.not_before = input.not_before;
        payload.expires_at = input.expires_at;
        let (credential, envelope) = submit_signed!(
            self,
            self.sign_delegation(
                DelegationPayload::Grant(payload.clone()),
                &principal,
                previous.as_ref(),
            ),
            |envelope| service.submit_delegation_event(&envelope)
        )?;
        Ok(json!({ "credential": credential, "envelope": envelope }))
    }

    async fn delegation_revoke(&mut self, input: DelegationRevokeInput) -> Result<Value> {
        let principal = self.controller_principal(&input.principal_id).await?;
        let (service, _) = self.principal_delegation_service(&principal).await?;
        let previous = Self::delegation_previous(&service, &input.id).await?;
        let payload = DelegationRevokePayload {
            id: input.id,
            principal_id: principal.id.clone(),
            reason: input.reason,
        };
        let (credential, envelope) = submit_signed!(
            self,
            self.sign_delegation(
                DelegationPayload::Revoke(payload.clone()),
                &principal,
                previous.as_ref(),
            ),
            |envelope| service.submit_delegation_event(&envelope)
        )?;
        Ok(json!({ "credential": credential, "envelope": envelope }))
    }

    fn sign_delegation(
        &mut self,
        payload: DelegationPayload,
        principal: &PrincipalDocument,
        previous: Option<&DelegationCredential>,
    ) -> Result<Envelope<DelegationPayload>> {
        let kind = match payload {
            DelegationPayload::Grant(_) => DELEGATION_GRANT,
            DelegationPayload::Revoke(_) => DELEGATION_REVOKE,
        };
        let created_at = unix_ms();
        let nonce = self.nonce_manager.next_nonce_at(created_at)?;
        let event = Event::new(
            DELEGATION_PROTOCOL,
            kind,
            self.agent_id(),
            created_at,
            nonce,
            payload,
        );
        validate_delegation_event_authority(&event, principal, created_at, previous)?;
        self.signer.sign_event(event)
    }

    async fn profile_update(&mut self, input: ProfileUpdateInput) -> Result<Value> {
        let mut profile = input.profile;
        let object = profile
            .as_object_mut()
            .ok_or_else(|| SdkError::InvalidPayload("profile must be an object".to_owned()))?;
        self.require_allowed_origin(&input.profile_service)?;
        // payload.id is always the active Agent ID; reject an input that
        // names a different agent instead of silently rewriting it.
        let active_id = serde_json::to_value(self.agent_id())?;
        match object.get("id") {
            None => {
                object.insert("id".to_owned(), active_id);
            }
            Some(id) if *id == active_id => {}
            Some(_) => {
                return Err(SdkError::InvalidPayload(
                    "profile.id must be the active Agent ID".to_owned(),
                ));
            }
        }
        let payload: ProfileUpdatePayload = serde_json::from_value(profile)?;
        let client = ProfileClient::with_client(&input.profile_service, self.http.clone());
        let (materialized, envelope) = submit_signed!(
            self,
            self.sign_profile_update(payload.clone()),
            |envelope| client.submit_profile_update(&envelope)
        )?;
        self.state
            .profiles
            .insert(materialized.id.clone(), materialized.clone());
        Ok(json!({ "profile": materialized, "envelope": envelope }))
    }

    async fn room_create(&mut self, input: RoomCreateInput) -> Result<Value> {
        let host = normalize_host(&input.host);
        self.require_allowed_host(&host)?;
        // Binds the signed event to this host (ADP Section 8.1).
        let mut payload = RoomCreatePayload::new(
            service_origin(&host)?,
            input.topic,
            input.visibility,
            input.start_time,
            input.end_time,
        );
        payload.agenda = input.agenda;
        payload.guidance = input.guidance;
        payload.tags = input.tags;
        payload.language = input.language;
        payload.policy = input.policy;
        payload.types = input.types;
        payload.extra = input.extra;
        let client = self.discourse(&host);
        let (mut room, envelope) =
            submit_signed!(self, self.sign_room_create(payload.clone()), |envelope| {
                client.create_room(&envelope)
            })?;
        if room.envelope.is_none() {
            room.envelope = Some(envelope.clone());
        }
        let key = (host.clone(), room.id.clone());
        self.accept_room_response(&host, room);
        // The creator has seen its own room.
        let local = self.local_room_mut(&key)?;
        let head_seq = local.head_seq;
        present_head(local, head_seq);
        Ok(json!({
            "room": self.room_state_view(self.local_room(&key)?),
            "envelope": envelope,
            "sync": self.sync_state(&key)?
        }))
    }

    async fn room_join(&mut self, input: RoomJoinInput) -> Result<Value> {
        let room_id = input.room_id.clone();
        let key = match input.host.as_deref() {
            Some(host) => (normalize_host(host), room_id.clone()),
            None => self.resolve_room_key(None, &room_id)?,
        };
        let host = key.0.clone();
        self.require_allowed_host(&host)?;
        let agent_id = self.agent_id();
        let client = self.discourse(&host);

        // A stored request decides the outcome until it resolves.
        let own = self.state.own_join_requests.get(&key).cloned();
        if let Some(own) = own.filter(|own| own.status == JoinRequestStatus::Pending) {
            let jwt = self.request_jwt(&host)?;
            let current = client.join_request(&room_id, &own.id, &jwt).await?;
            self.state
                .own_join_requests
                .insert(key.clone(), current.clone());
            match current.status {
                JoinRequestStatus::Pending => {
                    return Ok(json!({
                        "status": "approval_required",
                        "join_request": current,
                        "sync": self.maybe_sync(&key)
                    }));
                }
                JoinRequestStatus::Rejected => {
                    return Ok(json!({
                        "status": "rejected",
                        "join_request": current,
                        "sync": self.maybe_sync(&key)
                    }));
                }
                JoinRequestStatus::Approved => {
                    // The approving review record is the membership event.
                    self.sync_room(&key).await?;
                    let member = self
                        .local_room(&key)?
                        .members
                        .get(&agent_id)
                        .filter(|member| member.status == RoomMemberStatus::Active)
                        .cloned()
                        .ok_or_else(|| {
                            SdkError::InvalidPayload(
                                "approved membership is not yet visible".to_owned(),
                            )
                        })?;
                    return Ok(json!({
                        "status": "joined",
                        "member": member,
                        "join_request": current,
                        "sync": self.sync_state(&key)?
                    }));
                }
                JoinRequestStatus::Expired => {}
            }
        }

        // Read the room when possible: invitees and public rooms are readable.
        if !self.state.rooms.contains_key(&key) {
            let jwt = self.request_jwt(&host)?;
            match client.room(&room_id, Some(&jwt)).await {
                Ok(room) => self.accept_room_response(&host, room),
                Err(SdkError::HttpStatus { .. }) => {}
                Err(error) => return Err(error),
            }
        }
        let direct = self.state.rooms.get(&key).is_some_and(|local| {
            !local
                .members
                .get(&agent_id)
                .is_some_and(|member| member.status == RoomMemberStatus::Banned)
                && room_visibility(&local.room).is_some_and(|visibility| {
                    can_join_directly(
                        visibility,
                        room_policy(&local.room).as_ref(),
                        &agent_id,
                        input.role,
                    )
                })
        });
        if direct {
            let payload = RoomJoinPayload {
                role: input.role,
                perspective: input.perspective.clone(),
            };
            let submitted = submit_signed!(
                self,
                self.sign_room_event(
                    event_type::ROOM_JOIN,
                    &key,
                    None,
                    None,
                    Vec::new(),
                    payload.clone()
                ),
                |envelope| client.submit_event(&room_id, &envelope)
            );
            match submitted {
                Ok((record, _)) => {
                    self.apply_own_record(&key, record.clone().into()).await?;
                    let member = self
                        .local_room(&key)?
                        .members
                        .get(&agent_id)
                        .cloned()
                        .ok_or_else(|| {
                            SdkError::InvalidPayload("joined member not materialized".to_owned())
                        })?;
                    return Ok(json!({
                        "status": "joined", "record": record, "member": member,
                        "sync": self.sync_state(&key)?
                    }));
                }
                // A ban may have arrived since the local snapshot; request review below.
                Err(error) if http_code(&error) == Some("member_banned") => {}
                Err(error) => return Err(error),
            }
        }

        let payload = RoomJoinRequestPayload {
            role: input.role,
            perspective: input.perspective,
            reason: input.reason,
            extra: input.extra,
        };
        let (request, _) = submit_signed!(
            self,
            self.sign_join_request(&room_id, payload.clone()),
            |envelope| client.request_join(&room_id, &envelope)
        )?;
        self.state
            .own_join_requests
            .insert(key.clone(), request.clone());
        Ok(json!({
            "status": "approval_required",
            "join_request": request,
            "sync": self.maybe_sync(&key)
        }))
    }

    /// One room write under the Section 5.1 freshness rules. Contract and
    /// signal writes only anchor, so they are signed against the base and
    /// never held. Message and control writes apply `on_head_mismatch` when
    /// the local head moved past their base or the host returns
    /// `room_head_mismatch`.
    async fn submit_room_write(&mut self, request: HeldDraftRequest) -> Result<Value> {
        let (room_id, host_input, base_seq, base_hash, policy, write_type) = match &request {
            HeldDraftRequest::Message(input) => (
                input.room_id.clone(),
                input.host.clone(),
                input.base_seq,
                input.base_hash.clone(),
                input.on_head_mismatch,
                event_type::MESSAGE_CREATE.to_owned(),
            ),
            HeldDraftRequest::Event(input) => (
                input.room_id.clone(),
                input.host.clone(),
                input.base_seq,
                input.base_hash.clone(),
                input.on_head_mismatch,
                input.event_type.clone(),
            ),
        };
        let key = self.resolve_room_key(host_input.as_deref(), &room_id)?;
        let host = self.allowed_room_host(&key)?;
        let head_bound = event_type_requires_room_head(self.local_room(&key)?, &write_type);
        if base_seq.is_some() != base_hash.is_some() {
            return Err(SdkError::InvalidPayload(
                "base_seq and base_hash must be provided together".to_owned(),
            ));
        }
        let mut base = self.write_base(&key, base_seq, base_hash)?;
        let client = self.discourse(&host);
        let mut attempts = 0;
        loop {
            if head_bound {
                let room = self.local_room(&key)?;
                if !base_is_current(room, &base) {
                    if policy == HeadMismatchPolicy::SendAnyway
                        && attempts < SEND_ANYWAY_MAX_ATTEMPTS
                    {
                        base = (room.head_seq, room.head_hash.clone().unwrap_or_default());
                    } else if policy == HeadMismatchPolicy::Reject {
                        return self.rejected_head_mismatch(&key, base.0);
                    } else {
                        return self.hold_draft(&key, request, base);
                    }
                }
            }
            attempts += 1;
            let presented_seq = self.local_room(&key)?.presented_seq;
            let previous_head_seq = self.local_room(&key)?.head_seq;
            let submitted =
                submit_signed!(self, self.sign_write(&request, &key, &base), |envelope| {
                    client.submit_event(&room_id, &envelope)
                });
            match submitted {
                Ok((record, _)) => {
                    let seq = record.seq;
                    let event_id = record.envelope.hash.clone();
                    self.apply_own_record(&key, record.clone().into()).await?;
                    let after = self.local_room_mut(&key)?;
                    // The agent's own write extends what it saw only when
                    // nothing it has not seen advanced the head in between.
                    if after.head_seq == seq
                        && Some(head_before(after, seq, previous_head_seq)) == presented_seq
                    {
                        present_head(after, seq);
                    }
                    return Ok(json!({
                        "status": "sent",
                        "record": record,
                        "item": self.timeline_item_by_event(&key, &event_id)?,
                        "sync": self.sync_state(&key)?
                    }));
                }
                Err(error) => {
                    if !head_bound || http_code(&error) != Some("room_head_mismatch") {
                        return Err(error);
                    }
                    self.sync_room(&key).await?;
                    // A host that reports a mismatch the verified history does
                    // not show cannot be resolved by retrying.
                    if base_is_current(self.local_room(&key)?, &base) {
                        return Err(error);
                    }
                }
            }
        }
    }

    /// Applies the record the host returned for the agent's own write, first
    /// syncing any records accepted before it that the connector has not seen.
    async fn apply_own_record(&mut self, key: &RoomKey, record: ArchiveRecord) -> Result<()> {
        if record.seq() > self.local_room(key)?.synced_seq + 1 {
            self.sync_room(key).await
        } else {
            self.apply_host_record(&key.0, record)
        }
    }

    /// Applies `Max-Seen-Nonce` from a `nonce_not_greater` rejection; reports
    /// whether to retry.
    fn resync_nonce(&mut self, error: &SdkError) -> bool {
        match error {
            SdkError::HttpStatus {
                code: Some(code),
                max_seen_nonce: Some(max_seen_nonce),
                ..
            } if code == "nonce_not_greater" => self
                .nonce_manager
                .observe_max_nonce_header(max_seen_nonce, unix_ms())
                .is_ok(),
            _ => false,
        }
    }

    fn sign_write(
        &mut self,
        request: &HeldDraftRequest,
        key: &RoomKey,
        base: &(u64, String),
    ) -> Result<Envelope<Value>> {
        match request {
            HeldDraftRequest::Message(input) => {
                let mut payload = MessageCreatePayload::new(
                    input
                        .content_type
                        .clone()
                        .unwrap_or_else(|| "text/plain".to_owned()),
                    Value::String(input.content.clone()),
                );
                if !input.references.is_empty() {
                    payload.references = Some(input.references.clone());
                }
                if !input.extra.is_empty() {
                    payload.extra = Some(input.extra.clone());
                }
                self.sign_room_event(
                    event_type::MESSAGE_CREATE,
                    key,
                    Some(base.0),
                    Some(base.1.clone()),
                    input.mentions.clone(),
                    serde_json::to_value(payload)?,
                )
            }
            HeldDraftRequest::Event(input) => {
                let payload = payload_with_references(input.payload.clone(), &input.references)?;
                self.sign_room_event(
                    input.event_type.clone(),
                    key,
                    Some(base.0),
                    Some(base.1.clone()),
                    input.mentions.clone(),
                    payload,
                )
            }
        }
    }

    async fn join_requests_list(&mut self, input: JoinRequestsListInput) -> Result<Value> {
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
        let host = self.allowed_room_host(&key)?;
        let jwt = self.request_jwt(&host)?;
        let response = self
            .discourse(&host)
            .join_requests(
                &input.room_id,
                &jwt,
                &JoinRequestsOptions {
                    status: input.status,
                    limit: input.limit,
                    cursor: input.cursor,
                },
            )
            .await?;
        self.state
            .join_requests
            .insert(key, response.result.clone());
        Ok(with_cursor(
            json!({ "join_requests": response.result }),
            response.next_cursor,
        ))
    }

    async fn join_request_review(&mut self, input: JoinRequestReviewInput) -> Result<Value> {
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
        let host = self.allowed_room_host(&key)?;
        if input.decision == JoinDecision::Approve && input.role.is_none() {
            return Err(SdkError::InvalidPayload(
                "approving a join request requires a role".to_owned(),
            ));
        }
        let jwt = self.request_jwt(&host)?;
        let client = self.discourse(&host);
        let join_request = client
            .join_request(&input.room_id, &input.request_id, &jwt)
            .await?;
        let payload = RoomJoinReviewPayload {
            request: join_request.request,
            decision: input.decision,
            role: input.role,
            reason: input.reason,
            extra: None,
        };
        let (record, _) = submit_signed!(
            self,
            self.sign_room_event(
                event_type::ROOM_JOIN_REVIEW,
                &key,
                None,
                None,
                Vec::new(),
                payload.clone()
            ),
            |envelope| client.submit_event(&input.room_id, &envelope)
        )?;
        self.apply_own_record(&key, record.clone().into()).await?;
        Ok(json!({ "record": record, "sync": self.sync_state(&key)? }))
    }

    // ── Signing.

    fn sign_profile_update(
        &mut self,
        payload: ProfileUpdatePayload,
    ) -> Result<Envelope<ProfileUpdatePayload>> {
        let created_at = unix_ms();
        let event = profile_update_event(
            self.agent_id(),
            created_at,
            self.nonce_manager.next_nonce_at(created_at)?,
            payload,
        );
        self.signer.sign_event(event)
    }

    fn sign_room_create(
        &mut self,
        payload: RoomCreatePayload,
    ) -> Result<Envelope<RoomCreatePayload>> {
        let created_at = unix_ms();
        let event = room_create_event(
            self.agent_id(),
            created_at,
            self.nonce_manager.next_nonce_at(created_at)?,
            payload,
        );
        let envelope = self.signer.sign_event(event)?;
        validate_discourse_envelope(&envelope)?;
        Ok(envelope)
    }

    fn sign_join_request(
        &mut self,
        room_id: &str,
        payload: RoomJoinRequestPayload,
    ) -> Result<Envelope<RoomJoinRequestPayload>> {
        let created_at = unix_ms();
        let event = room_join_request_event(
            self.agent_id(),
            created_at,
            self.nonce_manager.next_nonce_at(created_at)?,
            room_id,
            payload,
        );
        let envelope = self.signer.sign_event(event)?;
        validate_discourse_envelope(&envelope)?;
        Ok(envelope)
    }

    fn sign_room_event<P>(
        &mut self,
        event_type: impl Into<String>,
        key: &RoomKey,
        base_seq: Option<u64>,
        base_hash: Option<String>,
        mentions: Vec<AgentId>,
        payload: P,
    ) -> Result<Envelope<P>>
    where
        P: Serialize,
    {
        let host = self.local_room(key)?.host.clone();
        self.require_allowed_host(&host)?;
        let (base_seq, base_hash) = self.write_base(key, base_seq, base_hash)?;
        let created_at = unix_ms();
        let mut event = discourse_event(
            event_type,
            self.agent_id(),
            created_at,
            self.nonce_manager.next_nonce_at(created_at)?,
            key.1.clone(),
            base_seq,
            base_hash,
            payload,
        );
        if !mentions.is_empty() {
            event = event.with_mentions(mentions);
        }
        let envelope = self.signer.sign_event(event)?;
        validate_discourse_envelope(&envelope)?;
        Ok(envelope)
    }

    /// The base for a write: the explicit base, else the presented head, else
    /// the current verified head (local connector Section 4.2).
    fn write_base(
        &self,
        key: &RoomKey,
        base_seq: Option<u64>,
        base_hash: Option<String>,
    ) -> Result<(u64, String)> {
        match (base_seq, base_hash) {
            (Some(seq), Some(hash)) if seq > 0 && !hash.trim().is_empty() => Ok((seq, hash)),
            (Some(_), Some(_)) => Err(SdkError::InvalidPayload(
                "base_seq and base_hash must identify a valid room head".to_owned(),
            )),
            (None, None) => {
                let room = self.local_room(key)?;
                if let (Some(seq), Some(hash)) = (room.presented_seq, &room.presented_hash) {
                    return Ok((seq, hash.clone()));
                }
                let sync = self.sync_state(key)?;
                if sync.head_seq == 0 || sync.head_hash.trim().is_empty() {
                    return Err(SdkError::InvalidPayload(
                        "current room head is not known locally".to_owned(),
                    ));
                }
                Ok((sync.head_seq, sync.head_hash))
            }
            _ => Err(SdkError::InvalidPayload(
                "base_seq and base_hash must be provided together".to_owned(),
            )),
        }
    }

    fn request_jwt(&self, host: &str) -> Result<String> {
        // The request JWT aud is always the origin of the host API.
        let host = normalize_host(host);
        self.require_allowed_host(&host)?;
        let audience = service_origin(&host)?;
        let claims = RequestJwtClaims::new(
            self.agent_id(),
            RequestBinding::new(audience),
            unix_secs(),
            DEFAULT_REQUEST_JWT_TTL_SECS,
        );
        self.signer.sign_request_jwt(&claims)
    }

    // ── Head-mismatch handling and draft holding.

    fn rejected_head_mismatch(&mut self, key: &RoomKey, base_seq: u64) -> Result<Value> {
        let changes = self.room_changes_since(key, Some(base_seq))?;
        let room = self.local_room_mut(key)?;
        let head_seq = room.head_seq;
        present_head(room, head_seq);
        Ok(json!({
            "status": "rejected",
            "reason": "room_head_mismatch",
            "changes": changes,
            "sync": self.sync_state(key)?
        }))
    }

    fn hold_draft(
        &mut self,
        key: &RoomKey,
        request: HeldDraftRequest,
        base: (u64, String),
    ) -> Result<Value> {
        let changes = self.room_changes_since(key, Some(base.0))?;
        // The held result shows every change up to the current head.
        let room = self.local_room_mut(key)?;
        let head_seq = room.head_seq;
        present_head(room, head_seq);
        let sync = self.sync_state(key)?;
        let (request, kind, draft_value) = match request {
            HeldDraftRequest::Message(mut input) => {
                input.host = Some(sync.host.clone());
                input.base_seq = Some(base.0);
                input.base_hash = Some(base.1.clone());
                let value = json!({
                    "room_id": &input.room_id,
                    "content": &input.content,
                    "content_type": input.content_type.as_deref().unwrap_or("text/plain"),
                    "mentions": &input.mentions,
                    "references": &input.references,
                    "extra": &input.extra
                });
                (
                    HeldDraftRequest::Message(input),
                    HeldDraftKind::Message,
                    value,
                )
            }
            HeldDraftRequest::Event(mut input) => {
                input.host = Some(sync.host.clone());
                input.base_seq = Some(base.0);
                input.base_hash = Some(base.1.clone());
                let value = json!({
                    "room_id": &input.room_id,
                    "type": &input.event_type,
                    "payload": &input.payload,
                    "mentions": &input.mentions,
                    "references": &input.references
                });
                (HeldDraftRequest::Event(input), HeldDraftKind::Event, value)
            }
        };
        let draft_id = self.next_draft_id(&key.1);
        let draft = HeldDraft {
            id: draft_id.clone(),
            room_id: key.1.clone(),
            kind,
            created_at: unix_ms(),
            base_seq: Some(base.0),
            base_hash: Some(base.1),
            current_sync: sync.clone(),
            draft: draft_value,
            reason: "room_head_mismatch".to_owned(),
            options: vec![DraftAction::Revise, DraftAction::Send, DraftAction::Drop],
        };
        self.state.drafts.insert(
            draft_id,
            HeldDraftEntry {
                draft: draft.clone(),
                request,
            },
        );
        Ok(json!({
            "status": "held",
            "reason": "room_head_mismatch",
            "draft": draft,
            "changes": changes,
            "sync": sync
        }))
    }

    fn room_changes_since(
        &self,
        key: &RoomKey,
        base_seq: Option<u64>,
    ) -> Result<Vec<TimelineItem>> {
        let room = self.local_room(key)?;
        let changes = match base_seq {
            Some(seq) => room
                .timeline
                .iter()
                .filter(|item| item.seq > seq)
                .cloned()
                .collect(),
            None => {
                let skip = room.timeline.len().saturating_sub(20);
                room.timeline[skip..].to_vec()
            }
        };
        Ok(changes)
    }

    fn next_draft_id(&self, room_id: &str) -> String {
        let room = room_id
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                    ch
                } else {
                    '_'
                }
            })
            .collect::<String>();
        let mut n = self.state.drafts.len() + 1;
        while self.state.drafts.contains_key(&format!("draft_{room}_{n}")) {
            n += 1;
        }
        format!("draft_{room}_{n}")
    }

    // ── Views.

    fn sync_state(&self, key: &RoomKey) -> Result<SyncState> {
        let room = self.local_room(key)?;
        let head_hash = room
            .head_hash
            .clone()
            .or_else(|| room.room.head.as_ref().map(|head| head.hash.clone()))
            .unwrap_or_else(|| room.room.hash.clone());
        Ok(SyncState {
            host: room.host.clone(),
            room_id: key.1.clone(),
            head_seq: room.head_seq,
            head_hash,
            presented_seq: room.presented_seq,
            presented_hash: room.presented_hash.clone(),
            synced_seq: room.synced_seq,
            remote_seq: room.room.seq.max(room.synced_seq),
            subscribed: room.subscribed,
            unread_count: room.unread_count(),
            pending_inbox_count: self.pending_inbox_count(Some(&key.1)),
        })
    }

    fn maybe_sync(&self, key: &RoomKey) -> Option<SyncState> {
        self.sync_state(key).ok()
    }

    fn room_state_view(&self, room: &LocalRoomState) -> RoomStateView {
        let envelope = room.room.envelope.as_ref();
        RoomStateView {
            host: room.host.clone(),
            room_id: room.room.id.clone(),
            status: room.room.status,
            visibility: room_visibility(&room.room),
            topic: room_topic(&room.room),
            agenda: room_agenda(&room.room),
            guidance: room_guidance(&room.room),
            creator: room
                .room
                .creator
                .clone()
                .or_else(|| envelope.map(|envelope| envelope.event.actor.clone())),
            created_at: room
                .room
                .created_at
                .or_else(|| envelope.map(|envelope| envelope.event.created_at)),
            start_time: room_start_time(&room.room),
            end_time: room_end_time(&room.room),
            tags: room_tags(&room.room),
            language: room_language(&room.room),
            policy: room_policy(&room.room),
            types: room.room.types.clone(),
            self_member: room.members.get(&self.agent_id()).cloned(),
            members_count: room.members.len(),
            active_turn: room.active_turn.clone(),
            unread_count: room.unread_count(),
            pending_inbox_count: self.pending_inbox_count(Some(&room.room.id)),
        }
    }

    fn summary_for_room(&self, room: &LocalRoomState) -> RoomSummary {
        let mut summary = summary_from_response(&room.host, &room.room);
        summary.role = room.members.get(&self.agent_id()).map(|member| member.role);
        summary.unread_count = room.unread_count();
        summary.pending_inbox_count = self.pending_inbox_count(Some(&room.room.id));
        summary
    }

    fn summary_for_response(&self, host: &str, room: &RoomResponse) -> RoomSummary {
        self.state
            .rooms
            .get(&(host.to_owned(), room.id.clone()))
            .map(|room| self.summary_for_room(room))
            .unwrap_or_else(|| summary_from_response(host, room))
    }

    fn timeline_item_by_event(&self, key: &RoomKey, event_id: &str) -> Result<TimelineItem> {
        self.local_room(key)?
            .timeline
            .iter()
            .find(|item| item.event_id == event_id)
            .cloned()
            .ok_or_else(|| SdkError::InvalidPayload("timeline item not materialized".to_owned()))
    }

    // ── Internal helpers.

    fn local_room(&self, key: &RoomKey) -> Result<&LocalRoomState> {
        self.state
            .rooms
            .get(key)
            .ok_or_else(|| SdkError::InvalidPayload(format!("room is not open locally: {}", key.1)))
    }

    fn local_room_mut(&mut self, key: &RoomKey) -> Result<&mut LocalRoomState> {
        self.state
            .rooms
            .get_mut(key)
            .ok_or_else(|| SdkError::InvalidPayload(format!("room is not open locally: {}", key.1)))
    }

    fn require_allowed_host(&self, host: &str) -> Result<()> {
        match self.state.hosts.get(&normalize_host(host)) {
            Some(host) if host.allowed => Ok(()),
            _ => Err(SdkError::PermissionDenied),
        }
    }

    /// Operator policy for a service URL that is not a discourse host: its
    /// origin must be an allowed host or the profile service of one.
    fn require_allowed_origin(&self, url: &str) -> Result<()> {
        let origin = service_origin(url)?;
        let allowed = self.state.hosts.values().any(|host| {
            host.allowed
                && (host.host == origin
                    || host
                        .profile_service
                        .as_deref()
                        .and_then(|service| service_origin(service).ok())
                        .is_some_and(|service| service == origin))
        });
        if allowed {
            Ok(())
        } else {
            Err(SdkError::PermissionDenied)
        }
    }

    fn allowed_room_host(&self, key: &RoomKey) -> Result<String> {
        let host = self.local_room(key)?.host.clone();
        self.require_allowed_host(&host)?;
        Ok(host)
    }

    fn ensure_host(&mut self, host: &str) {
        self.state
            .hosts
            .entry(host.to_owned())
            .or_insert_with(|| AgentProtocolsHost {
                host: host.to_owned(),
                label: None,
                allowed: false,
                features: Vec::new(),
                profile_service: None,
                last_checked_at: None,
            });
    }

    fn insert_inbox(&mut self, item: InboxItem) {
        self.state
            .inbox
            .entry(item.id.clone())
            .or_insert(InboxEntry {
                item,
                state: InboxEntryState::Pending,
            });
    }

    fn pending_inbox_count(&self, room_id: Option<&str>) -> usize {
        let now = unix_ms();
        self.state
            .inbox
            .values()
            .filter(|entry| inbox_entry_ready(entry, now))
            .filter(|entry| {
                room_id
                    .map(|room_id| entry.item.room_id.as_deref() == Some(room_id))
                    .unwrap_or(true)
            })
            .count()
    }

    fn discourse(&self, host: &str) -> DiscourseClient {
        DiscourseClient::with_client(host, self.http.clone())
    }
}

fn parse_input<T: DeserializeOwned>(input: Value) -> Result<T> {
    Ok(serde_json::from_value(input)?)
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('/').to_owned()
}

/// The Agent Identity error code of an HTTP error response.
fn http_code(error: &SdkError) -> Option<&str> {
    match error {
        SdkError::HttpStatus { code, .. } => code.as_deref(),
        _ => None,
    }
}

/// The JSON string form of a serde enum.
fn enum_str<T: Serialize>(value: &T) -> Option<String> {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
}

fn with_cursor(mut value: Value, next_cursor: Option<String>) -> Value {
    if let Some(next_cursor) = next_cursor {
        value["next_cursor"] = json!(next_cursor);
    }
    value
}

/// Offset-cursor page over a sorted list, with a next cursor when more follow.
fn page<T>(items: Vec<T>, cursor: Option<&str>, limit: usize) -> (Vec<T>, Option<String>) {
    let offset = cursor.and_then(|c| c.parse::<usize>().ok()).unwrap_or(0);
    let total = items.len();
    let items = items.into_iter().skip(offset).take(limit).collect();
    let next = (offset + limit < total).then(|| (offset + limit).to_string());
    (items, next)
}

fn summary_from_response(host: &str, room: &RoomResponse) -> RoomSummary {
    RoomSummary {
        room_id: room.id.clone(),
        host: normalize_host(host),
        topic: room_topic(room),
        status: room.status,
        visibility: room_visibility(room),
        start_time: room_start_time(room),
        end_time: room_end_time(room),
        tags: room_tags(room),
        language: room_language(room),
        role: None,
        unread_count: 0,
        pending_inbox_count: 0,
    }
}

fn payload_with_references(mut payload: Value, references: &[String]) -> Result<Value> {
    if references.is_empty() {
        return Ok(payload);
    }
    let object = payload
        .as_object_mut()
        .ok_or_else(|| SdkError::InvalidPayload("event payload must be an object".to_owned()))?;
    let extra = object
        .entry("extra")
        .or_insert_with(|| Value::Object(Default::default()));
    let extra = extra
        .as_object_mut()
        .ok_or_else(|| SdkError::InvalidPayload("payload.extra must be an object".to_owned()))?;
    extra.insert("references".to_owned(), serde_json::to_value(references)?);
    Ok(payload)
}

fn profile_to_member_profile(profile: &AgentProfile) -> RoomMemberProfile {
    RoomMemberProfile {
        name: Some(profile.name.clone()),
        description: profile.description.clone(),
        avatar_url: profile.avatar_url.clone(),
    }
}
