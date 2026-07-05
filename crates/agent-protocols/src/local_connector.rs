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

use crate::discourse::{
    discourse_event, event_type, room_create_event, validate_discourse_envelope,
    validate_room_path, verify_server_record, AgentStatusInput, JoinRequestStatus,
    MessageCreatePayload, ReasonPayload, Role, RoomCreatePayload, RoomJoinPayload,
    RoomJoinRequestInput, RoomJoinReviewPayload, RoomResponse, ServerRecord, Visibility,
};
use crate::error::{Result, SdkError};
use crate::http_client::{DiscourseClient, ProfileClient, PublicRoomsOptions, RoomEventsOptions};
use crate::identity::{
    unix_ms, unix_secs, AgentId, AgentSigner, ClientNonceManager, Envelope, RequestBinding,
    RequestJwtClaims, DEFAULT_REQUEST_JWT_TTL_SECS,
};
use crate::profile::{profile_update_event, AgentProfile, ProfileUpdatePayload};

struct HeadMismatchState {
    sync: SyncState,
    changes: Vec<TimelineItem>,
}

pub struct LocalConnector {
    signer: AgentSigner,
    nonce_manager: ClientNonceManager,
    state: LocalConnectorState,
}

impl LocalConnector {
    pub fn new(signer: AgentSigner) -> Self {
        Self {
            signer,
            nonce_manager: ClientNonceManager::new(),
            state: LocalConnectorState::new(),
        }
    }

    pub fn with_state(signer: AgentSigner, state: LocalConnectorState) -> Self {
        Self {
            signer,
            nonce_manager: ClientNonceManager::new(),
            state,
        }
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
    pub fn apply_record(&mut self, record: ServerRecord) -> Result<()> {
        let key = self.resolve_room_key(None, &record.room_id)?;
        self.apply_record_to(&key, record)
    }

    /// Applies a verified record to the room on the given host.
    pub fn apply_host_record(&mut self, host: &str, record: ServerRecord) -> Result<()> {
        let key = (normalize_host(host), record.room_id.clone());
        self.apply_record_to(&key, record)
    }

    fn apply_record_to(&mut self, key: &RoomKey, record: ServerRecord) -> Result<()> {
        validate_discourse_envelope(&record.envelope)?;
        validate_room_path(&record.envelope, &record.room_id)?;
        verify_server_record(&record)?;

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

            let item = TimelineItem::from_record(&record);
            apply_record_projection(room, &record, &item, &active_agent, &mut new_inbox)?;
            if record.envelope.event.kind == event_type::ROOM_MEMBER_REMOVE {
                cleared_status =
                    serde_json::from_value::<crate::discourse::RoomMemberRemovePayload>(
                        record.envelope.event.payload.clone(),
                    )
                    .ok()
                    .map(|payload| payload.member);
            }
            if record_advances_room_head(room, &record) {
                room.head_seq = record.seq;
                room.head_hash = Some(record.hash.clone());
            }
            room.synced_seq = record.seq;
            room.synced_hash = Some(record.hash.clone());
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
            TOOL_HOSTS_LIST => self.hosts_list(),
            TOOL_ROOMS_SEARCH => self.rooms_search(parse_input(input)?).await,
            TOOL_ROOMS_LIST => self.rooms_list(parse_input(input)?),
            TOOL_ROOM_OPEN => self.room_open(parse_input(input)?).await,
            TOOL_ROOM_STATE => self.room_state(parse_input(input)?).await,
            TOOL_ROOM_MEMBERS_LIST => self.room_members_list(parse_input(input)?),
            TOOL_ROOM_MEMBER_GET => self.room_member_get(parse_input(input)?),
            TOOL_AGENT_STATUS_LIST => self.agent_status_list(parse_input(input)?).await,
            TOOL_AGENT_STATUS_GET => self.agent_status_get(parse_input(input)?).await,
            TOOL_AGENT_STATUS_SET => self.agent_status_set(parse_input(input)?).await,
            TOOL_AGENT_STATUS_CLEAR => self.agent_status_clear(parse_input(input)?).await,
            TOOL_ROOM_TIMELINE => self.room_timeline(parse_input(input)?),
            TOOL_ROOM_UNREAD => self.room_unread(parse_input(input)?),
            TOOL_ROOM_MARK_READ => self.room_mark_read(parse_input(input)?),
            TOOL_INBOX_NEXT => self.inbox_next(parse_input(input)?),
            TOOL_INBOX_ACK => self.inbox_ack(parse_input(input)?),
            TOOL_DRAFTS_LIST => self.drafts_list(parse_input(input)?),
            TOOL_DRAFT_GET => self.draft_get(parse_input(input)?),
            TOOL_DRAFT_COMMIT => self.draft_commit(parse_input(input)?).await,
            TOOL_DRAFT_DROP => self.draft_drop(parse_input(input)?),
            TOOL_PROFILE_UPDATE => self.profile_update(parse_input(input)?).await,
            TOOL_ROOM_CREATE => self.room_create(parse_input(input)?).await,
            TOOL_ROOM_JOIN => self.room_join(parse_input(input)?).await,
            TOOL_ROOM_JOIN_REQUEST => self.room_join_request(parse_input(input)?).await,
            TOOL_ROOM_JOIN_WHEN_APPROVED => self.room_join_when_approved(parse_input(input)?).await,
            TOOL_ROOM_LEAVE => self.room_leave(parse_input(input)?).await,
            TOOL_ROOM_SEND_MESSAGE => self.room_send_message(parse_input(input)?).await,
            TOOL_ROOM_SUBMIT_EVENT => self.room_submit_event(parse_input(input)?).await,
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
        json_result(json!({
            "agent_id": agent_id,
            "public_key": public_key,
            "profiles": self.state.profiles.keys().collect::<Vec<_>>(),
            "hosts": self.state.hosts.values().collect::<Vec<_>>()
        }))
    }

    fn hosts_list(&self) -> Result<Value> {
        json_result(json!({ "hosts": self.state.hosts.values().collect::<Vec<_>>() }))
    }

    async fn rooms_search(&mut self, input: RoomsSearchInput) -> Result<Value> {
        let host = normalize_host(&input.host);
        self.require_allowed_host(&host)?;
        let rooms = DiscourseClient::new(&host)
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
        for room in &rooms {
            self.observe_room(&host, room.clone());
        }
        let summaries = rooms
            .iter()
            .map(|room| self.summary_for_response(&host, room))
            .collect::<Vec<_>>();
        json_result(json!({ "rooms": summaries }))
    }

    fn rooms_list(&self, input: RoomsListInput) -> Result<Value> {
        let rooms = self
            .state
            .rooms
            .values()
            .filter(|room| {
                input
                    .status
                    .as_deref()
                    .map(|status| {
                        serde_json::to_value(room.room.status)
                            .ok()
                            .and_then(|v| v.as_str().map(str::to_owned))
                            == Some(status.to_owned())
                    })
                    .unwrap_or(true)
            })
            .filter(|room| membership_filter(room, &self.agent_id(), input.membership))
            .skip(
                input
                    .cursor
                    .as_deref()
                    .and_then(|c| c.parse::<usize>().ok())
                    .unwrap_or(0),
            )
            .take(input.limit.unwrap_or(50))
            .map(|room| self.summary_for_room(room))
            .collect::<Vec<_>>();
        json_result(json!({ "rooms": rooms }))
    }

    async fn room_open(&mut self, input: RoomOpenInput) -> Result<Value> {
        let host = normalize_host(&input.host);
        self.require_allowed_host(&host)?;
        let key = (host.clone(), input.room_id.clone());
        let previous_seq = self
            .state
            .rooms
            .get(&key)
            .map(|room| room.synced_seq)
            .unwrap_or(0);
        if input.refresh || previous_seq == 0 {
            let client = DiscourseClient::new(&host);
            let room = client.room(&input.room_id).await?;
            self.observe_room(&host, room);
            let jwt = self.request_jwt(&host)?;
            let records = client
                .events_with_options(
                    &input.room_id,
                    &RoomEventsOptions {
                        after_seq: if previous_seq > 0 {
                            Some(previous_seq)
                        } else {
                            None
                        },
                        limit: None,
                        cursor: None,
                        jwt: Some(jwt),
                    },
                )
                .await?;
            for record in records {
                self.apply_host_record(&host, record)?;
            }
        }
        if let Some(room) = self.state.rooms.get_mut(&key) {
            room.subscribed = input.subscribe.unwrap_or(false);
        }
        let room = self.local_room(&key)?;
        json_result(json!({
            "room": self.room_state_view(room),
            "sync": self.sync_state(&key)?,
            "active_turn": room.active_turn
        }))
    }

    async fn room_state(&mut self, input: RoomStateInput) -> Result<Value> {
        let _ = input.include_types;
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
        if input.refresh {
            let host = self.local_room(&key)?.host.clone();
            return self
                .room_open(RoomOpenInput {
                    host,
                    room_id: input.room_id,
                    subscribe: None,
                    refresh: true,
                })
                .await;
        }
        let room = self.local_room(&key)?;
        json_result(json!({
            "room": self.room_state_view(room),
            "sync": self.sync_state(&key)?
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
                    .status
                    .map(|status| status == member.status)
                    .unwrap_or(true)
            })
            .filter(|member| input.role.map(|role| role == member.role).unwrap_or(true))
            .skip(
                input
                    .cursor
                    .as_deref()
                    .and_then(|c| c.parse::<usize>().ok())
                    .unwrap_or(0),
            )
            .take(input.limit.unwrap_or(100))
            .cloned()
            .collect::<Vec<_>>();
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
        json_result(json!({
            "members": members,
            "sync": self.sync_state(&key)?
        }))
    }

    fn room_member_get(&self, input: RoomMemberGetInput) -> Result<Value> {
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
        let room = self.local_room(&key)?;
        let member = room
            .members
            .get(&input.agent_id)
            .ok_or_else(|| SdkError::InvalidPayload("room member not found".to_owned()))?;
        let mut member = member.clone();
        if input.include_profile && member.profile.is_none() {
            member.profile = self
                .state
                .profiles
                .get(&member.agent_id)
                .map(profile_to_member_profile);
        }
        let recent = if input.include_recent_activity {
            room.timeline
                .iter()
                .filter(|item| item.actor == input.agent_id)
                .rev()
                .take(10)
                .cloned()
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        json_result(json!({
            "member": member,
            "recent": recent,
            "sync": self.sync_state(&key)?
        }))
    }

    async fn agent_status_list(&mut self, input: AgentStatusListInput) -> Result<Value> {
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
        if !input.refresh {
            if let Some(statuses) = self.state.agent_statuses.get(&key) {
                return json_result(json!({
                    "statuses": statuses.values().collect::<Vec<_>>(),
                    "sync": self.sync_state(&key)?
                }));
            }
        }
        let host = self.allowed_room_host(&key)?;
        let jwt = self.request_jwt(&host)?;
        let response = DiscourseClient::new(&host)
            .agent_statuses(&input.room_id, Some(&jwt))
            .await?;
        let statuses = response
            .statuses
            .into_iter()
            .map(|status| (status.agent_id.clone(), status))
            .collect::<BTreeMap<_, _>>();
        let values = statuses.values().cloned().collect::<Vec<_>>();
        self.state.agent_statuses.insert(key.clone(), statuses);
        json_result(json!({
            "statuses": values,
            "sync": self.sync_state(&key)?
        }))
    }

    async fn agent_status_get(&mut self, input: AgentStatusGetInput) -> Result<Value> {
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
        if !input.refresh {
            if let Some(status) = self
                .state
                .agent_statuses
                .get(&key)
                .and_then(|statuses| statuses.get(&input.agent_id))
                .cloned()
            {
                return json_result(json!({
                    "status": status,
                    "sync": self.sync_state(&key)?
                }));
            }
        }
        let host = self.allowed_room_host(&key)?;
        let jwt = self.request_jwt(&host)?;
        let response = DiscourseClient::new(&host)
            .agent_status(&input.room_id, &input.agent_id, Some(&jwt))
            .await?;
        self.state
            .agent_statuses
            .entry(key.clone())
            .or_default()
            .insert(response.status.agent_id.clone(), response.status.clone());
        json_result(json!({
            "status": response.status,
            "sync": self.sync_state(&key)?
        }))
    }

    async fn agent_status_set(&mut self, input: AgentStatusSetInput) -> Result<Value> {
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
        let host = self.allowed_room_host(&key)?;
        let jwt = self.request_jwt(&host)?;
        let mut request = AgentStatusInput::new(input.state);
        request.expires_at = input.expires_at;
        request.summary = input.summary;
        request.seen_seq = input.seen_seq;
        request.seen_hash = input.seen_hash;
        request.claim_id = input.claim_id;
        request.activity = input.activity;
        request.extra = input.extra;
        let status = DiscourseClient::new(&host)
            .set_agent_status(&input.room_id, &jwt, &request)
            .await?;
        self.state
            .agent_statuses
            .entry(key.clone())
            .or_default()
            .insert(status.agent_id.clone(), status.clone());
        json_result(json!({
            "status": status,
            "sync": self.sync_state(&key)?
        }))
    }

    async fn agent_status_clear(&mut self, input: AgentStatusClearInput) -> Result<Value> {
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
        let host = self.allowed_room_host(&key)?;
        let jwt = self.request_jwt(&host)?;
        let request = AgentStatusInput::new("away").with_expires_at(unix_ms().saturating_sub(1));
        let _ = DiscourseClient::new(&host)
            .set_agent_status(&input.room_id, &jwt, &request)
            .await?;
        let active_agent = self.agent_id();
        if let Some(statuses) = self.state.agent_statuses.get_mut(&key) {
            statuses.remove(&active_agent);
        }
        json_result(json!({
            "cleared": true,
            "room_id": input.room_id
        }))
    }

    fn room_timeline(&self, input: RoomTimelineInput) -> Result<Value> {
        let _ = (input.refresh, input.include_records);
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
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
                    .map(|actors| actors.contains(&item.actor))
                    .unwrap_or(true)
            })
            .filter(|item| !input.unread_only || item.seq > room.read_seq)
            .take(input.limit.unwrap_or(50))
            .cloned()
            .collect::<Vec<_>>();
        let next_after_seq = items.last().map(|item| item.seq);
        json_result(json!({
            "items": items,
            "sync": self.sync_state(&key)?,
            "next_after_seq": next_after_seq
        }))
    }

    fn room_unread(&mut self, input: RoomUnreadInput) -> Result<Value> {
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
        let room = self.local_room(&key)?;
        let mut items = room
            .timeline
            .iter()
            .filter(|item| item.seq > room.read_seq)
            .take(input.limit.unwrap_or(50))
            .cloned()
            .collect::<Vec<_>>();
        let through_seq = items.last().map(|item| item.seq);
        if input.mark_read {
            if let Some(through_seq) = through_seq {
                self.local_room_mut(&key)?.read_seq = through_seq;
            }
            items = self
                .local_room(&key)?
                .timeline
                .iter()
                .filter(|item| through_seq.map(|seq| item.seq <= seq).unwrap_or(false))
                .cloned()
                .collect();
        }
        let unread_count = self.local_room(&key)?.unread_count();
        json_result(json!({
            "items": items,
            "unread_count": unread_count,
            "sync": self.sync_state(&key)?
        }))
    }

    fn room_mark_read(&mut self, input: RoomMarkReadInput) -> Result<Value> {
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
        let room = self.local_room_mut(&key)?;
        room.read_seq = room.read_seq.max(input.through_seq);
        let unread_count = room.unread_count();
        json_result(json!({
            "room_id": input.room_id,
            "read_seq": room.read_seq,
            "unread_count": unread_count
        }))
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
                        serde_json::to_value(&entry.item.kind)
                            .ok()
                            .and_then(|value| value.as_str().map(str::to_owned))
                            .map(|kind| kinds.contains(&kind))
                            .unwrap_or(false)
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
                if input.claim {
                    entry.state = InboxEntryState::Claimed;
                }
            }
        }
        json_result(json!({
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
        json_result(json!({
            "acknowledged": acknowledged,
            "pending_count": self.pending_inbox_count(None)
        }))
    }

    fn drafts_list(&self, input: DraftsListInput) -> Result<Value> {
        let offset = input
            .cursor
            .as_deref()
            .and_then(|cursor| cursor.parse::<usize>().ok())
            .unwrap_or(0);
        let limit = input.limit.unwrap_or(50);
        let mut drafts = self
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
                input
                    .host
                    .as_deref()
                    .map(|host| entry.draft.current_sync.host == normalize_host(host))
                    .unwrap_or(true)
            })
            .skip(offset)
            .take(limit + 1)
            .map(|entry| entry.draft.clone())
            .collect::<Vec<_>>();
        let next_cursor = if drafts.len() > limit {
            drafts.pop();
            Some((offset + limit).to_string())
        } else {
            None
        };
        json_result(json!({
            "drafts": drafts,
            "next_cursor": next_cursor
        }))
    }

    fn draft_get(&self, input: DraftGetInput) -> Result<Value> {
        let entry = self
            .state
            .drafts
            .get(&input.draft_id)
            .ok_or_else(|| SdkError::InvalidPayload("draft not found".to_owned()))?;
        let key = (
            entry.draft.current_sync.host.clone(),
            entry.draft.room_id.clone(),
        );
        let changes = self.room_changes_since(&key, entry.draft.base_seq)?;
        json_result(json!({
            "draft": entry.draft,
            "changes": changes,
            "sync": self.sync_state(&key)?
        }))
    }

    async fn draft_commit(&mut self, input: DraftCommitInput) -> Result<Value> {
        let entry = self
            .state
            .drafts
            .get(&input.draft_id)
            .cloned()
            .ok_or_else(|| SdkError::InvalidPayload("draft not found".to_owned()))?;

        if input.action == DraftAction::StaySilent {
            self.state.drafts.remove(&input.draft_id);
            return json_result(json!({
                "status": "dropped",
                "draft_id": input.draft_id
            }));
        }

        let result = match (entry.request, input.action) {
            (HeldDraftRequest::Message(mut request), DraftAction::Revise) => {
                if let Some(content) = input.content {
                    request.content = content;
                }
                if let Some(content_type) = input.content_type {
                    request.content_type = Some(content_type);
                }
                if let Some(mentions) = input.mentions {
                    request.mentions = mentions;
                }
                if let Some(references) = input.references {
                    request.references = references;
                }
                if let Some(extra) = input.extra {
                    request.extra = extra;
                }
                request.base_seq = input.base_seq;
                request.base_hash = input.base_hash;
                request.on_head_mismatch = input.on_head_mismatch;
                self.room_send_message(request).await?
            }
            (HeldDraftRequest::Message(mut request), DraftAction::SendAsIs) => {
                request.base_seq = input.base_seq;
                request.base_hash = input.base_hash;
                request.on_head_mismatch = input.on_head_mismatch;
                self.room_send_message(request).await?
            }
            (HeldDraftRequest::Message(mut request), DraftAction::SendAnyway) => {
                request.base_seq = None;
                request.base_hash = None;
                request.on_head_mismatch = HeadMismatchPolicy::SendAnyway;
                self.submit_message_unchecked(request).await?
            }
            (HeldDraftRequest::Event(mut request), DraftAction::Revise) => {
                if let Some(event_type) = input.event_type {
                    request.event_type = event_type;
                }
                if let Some(payload) = input.payload {
                    request.payload = payload;
                }
                if let Some(mentions) = input.mentions {
                    request.mentions = mentions;
                }
                if let Some(references) = input.references {
                    request.references = references;
                }
                request.base_seq = input.base_seq;
                request.base_hash = input.base_hash;
                request.on_head_mismatch = input.on_head_mismatch;
                self.room_submit_event(request).await?
            }
            (HeldDraftRequest::Event(mut request), DraftAction::SendAsIs) => {
                request.base_seq = input.base_seq;
                request.base_hash = input.base_hash;
                request.on_head_mismatch = input.on_head_mismatch;
                self.room_submit_event(request).await?
            }
            (HeldDraftRequest::Event(mut request), DraftAction::SendAnyway) => {
                request.base_seq = None;
                request.base_hash = None;
                request.on_head_mismatch = HeadMismatchPolicy::SendAnyway;
                self.submit_event_unchecked(request).await?
            }
            (_, DraftAction::StaySilent) => unreachable!(),
        };

        if matches!(
            result.get("status").and_then(Value::as_str),
            Some("sent" | "held")
        ) {
            self.state.drafts.remove(&input.draft_id);
        }
        Ok(result)
    }

    fn draft_drop(&mut self, input: DraftDropInput) -> Result<Value> {
        self.state.drafts.remove(&input.draft_id);
        json_result(json!({
            "status": "dropped",
            "draft_id": input.draft_id,
            "pending_count": self.state.drafts.len()
        }))
    }

    async fn profile_update(&mut self, input: ProfileUpdateInput) -> Result<Value> {
        let mut profile = input.profile;
        let object = profile
            .as_object_mut()
            .ok_or_else(|| SdkError::InvalidPayload("profile must be an object".to_owned()))?;
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
        let envelope = self.sign_profile_update(payload)?;
        let materialized = ProfileClient::new(&input.profile_service)
            .submit_profile_update(&envelope)
            .await?;
        self.state
            .profiles
            .insert(materialized.id.clone(), materialized.clone());
        json_result(json!({ "profile": materialized, "envelope": envelope }))
    }

    async fn room_create(&mut self, input: RoomCreateInput) -> Result<Value> {
        let host = normalize_host(&input.host);
        self.require_allowed_host(&host)?;
        let mut payload = RoomCreatePayload::new(
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
        let envelope = self.sign_room_create(payload)?;
        let mut room = DiscourseClient::new(&host).create_room(&envelope).await?;
        if room.envelope.is_none() {
            room.envelope = Some(envelope.clone());
        }
        self.accept_room_response(&host, room.clone());
        let key = (host, room.id.clone());
        json_result(json!({
            "room": self.room_state_view(self.local_room(&key)?),
            "envelope": envelope,
            "sync": self.sync_state(&key)?
        }))
    }

    async fn room_join(&mut self, input: RoomJoinInput) -> Result<Value> {
        let room_id = input.room_id.clone();
        let key = match input.host.as_deref() {
            Some(host) => {
                let host = normalize_host(host);
                self.require_allowed_host(&host)?;
                (host, room_id.clone())
            }
            None => {
                let key = self.resolve_room_key(None, &room_id)?;
                self.require_allowed_host(&key.0)?;
                key
            }
        };
        let host = key.0.clone();

        if !self.state.rooms.contains_key(&key) {
            let room = DiscourseClient::new(&host).room(&room_id).await?;
            self.accept_room_response(&host, room);
        }

        if let Some(request_id) = input.request_id {
            let jwt = self.request_jwt(&host)?;
            let status = DiscourseClient::new(&host)
                .join_request(&room_id, &request_id, &jwt)
                .await?;
            if status.request.applicant != self.agent_id() {
                return Err(SdkError::InvalidPayload(
                    "join request belongs to another agent".to_owned(),
                ));
            }
            if status.status != JoinRequestStatus::Approved {
                return Err(SdkError::InvalidPayload(
                    "join request is not approved".to_owned(),
                ));
            }
            // The completion call signs room.join with the approved role; a
            // differing input role is a mismatch error, never a silent
            // substitution.
            let approved_role = status.approved_role.unwrap_or(status.request.role);
            if input.role != approved_role {
                return Err(SdkError::InvalidPayload(format!(
                    "join_request_role_mismatch: approved role is {approved_role:?}"
                )));
            }
            let payload = RoomJoinPayload {
                request_id: Some(request_id),
                role: approved_role,
                perspective: None,
            };
            let envelope =
                self.sign_room_event(event_type::ROOM_JOIN, &key, None, None, Vec::new(), payload)?;
            let record = DiscourseClient::new(&host)
                .join_room(&room_id, &envelope)
                .await?;
            let record = typed_record_to_value(record)?;
            self.apply_host_record(&host, record.clone())?;
            let member = self
                .local_room(&key)?
                .members
                .get(&self.agent_id())
                .cloned()
                .ok_or_else(|| {
                    SdkError::InvalidPayload("joined member not materialized".to_owned())
                })?;
            return json_result(json!({
                "status": "joined",
                "record": record,
                "member": member,
                "sync": self.sync_state(&key)?
            }));
        }

        if room_visibility(&self.local_room(&key)?.room) == Some(Visibility::Public) {
            let payload = RoomJoinPayload {
                request_id: None,
                role: input.role,
                perspective: input.perspective,
            };
            let envelope =
                self.sign_room_event(event_type::ROOM_JOIN, &key, None, None, Vec::new(), payload)?;
            let record = DiscourseClient::new(&host)
                .join_room(&room_id, &envelope)
                .await?;
            let record = typed_record_to_value(record)?;
            self.apply_host_record(&host, record.clone())?;
            let member = self
                .local_room(&key)?
                .members
                .get(&self.agent_id())
                .cloned()
                .ok_or_else(|| {
                    SdkError::InvalidPayload("joined member not materialized".to_owned())
                })?;
            return json_result(json!({
                "status": "joined",
                "record": record,
                "member": member,
                "sync": self.sync_state(&key)?
            }));
        }

        let jwt = self.request_jwt(&host)?;
        let mut request = RoomJoinRequestInput::new(input.role);
        request.perspective = input.perspective;
        request.reason = input.reason;
        request.extra = input.extra;
        let status = DiscourseClient::new(&host)
            .request_join(&room_id, &jwt, &request)
            .await?;
        self.state
            .join_requests
            .entry(key.clone())
            .or_default()
            .push(status.clone());
        json_result(json!({
            "status": "approval_required",
            "join_request": status,
            "sync": self.sync_state(&key).ok()
        }))
    }

    async fn room_join_request(&mut self, input: RoomJoinRequestToolInput) -> Result<Value> {
        let host = normalize_host(&input.host);
        self.require_allowed_host(&host)?;
        let jwt = self.request_jwt(&host)?;
        let mut request = RoomJoinRequestInput::new(input.role);
        request.perspective = input.perspective;
        request.reason = input.reason;
        request.extra = input.extra;
        let status = DiscourseClient::new(&host)
            .request_join(&input.room_id, &jwt, &request)
            .await?;
        self.state
            .join_requests
            .entry((host, input.room_id))
            .or_default()
            .push(status.clone());
        json_result(json!({ "join_request": status }))
    }

    async fn room_join_when_approved(&mut self, input: RoomJoinWhenApprovedInput) -> Result<Value> {
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
        let host = self.allowed_room_host(&key)?;
        let jwt = self.request_jwt(&host)?;
        let status = DiscourseClient::new(&host)
            .join_request(&input.room_id, &input.request_id, &jwt)
            .await?;
        if status.request.applicant != self.agent_id() {
            return Err(SdkError::InvalidPayload(
                "join request belongs to another agent".to_owned(),
            ));
        }
        if status.status != JoinRequestStatus::Approved {
            return Err(SdkError::InvalidPayload(
                "join request is not approved".to_owned(),
            ));
        }
        let role = status.approved_role.unwrap_or(status.request.role);
        let payload = RoomJoinPayload {
            request_id: Some(input.request_id),
            role,
            perspective: None,
        };
        let envelope =
            self.sign_room_event(event_type::ROOM_JOIN, &key, None, None, Vec::new(), payload)?;
        let record = DiscourseClient::new(&host)
            .join_room(&input.room_id, &envelope)
            .await?;
        let record = typed_record_to_value(record)?;
        self.apply_host_record(&host, record.clone())?;
        let member = self
            .local_room(&key)?
            .members
            .get(&self.agent_id())
            .cloned()
            .ok_or_else(|| SdkError::InvalidPayload("joined member not materialized".to_owned()))?;
        json_result(json!({
            "record": record,
            "member": member,
            "sync": self.sync_state(&key)?
        }))
    }

    async fn room_leave(&mut self, input: RoomLeaveInput) -> Result<Value> {
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
        let host = self.allowed_room_host(&key)?;
        let payload = ReasonPayload {
            reason: input.reason,
            references: Vec::new(),
            extra: BTreeMap::new(),
        };
        let envelope = self.sign_room_event(
            event_type::ROOM_LEAVE,
            &key,
            None,
            None,
            Vec::new(),
            payload,
        )?;
        let record = DiscourseClient::new(&host)
            .leave_room(&input.room_id, &envelope)
            .await?;
        let record = typed_record_to_value(record)?;
        self.apply_host_record(&host, record.clone())?;
        json_result(json!({ "record": record, "sync": self.sync_state(&key)? }))
    }

    async fn room_send_message(&mut self, mut input: RoomSendMessageInput) -> Result<Value> {
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
        if let Some(result) = self.head_mismatch_message_result(&key, &mut input)? {
            return Ok(result);
        }
        self.submit_message_unchecked(input).await
    }

    async fn submit_message_unchecked(&mut self, input: RoomSendMessageInput) -> Result<Value> {
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
        let host = self.allowed_room_host(&key)?;
        let mut payload = MessageCreatePayload::new(
            input
                .content_type
                .unwrap_or_else(|| "text/plain".to_owned()),
            Value::String(input.content),
        );
        payload.references = input.references;
        payload.extra = input.extra;
        let envelope = self.sign_room_event(
            event_type::MESSAGE_CREATE,
            &key,
            input.base_seq,
            input.base_hash.clone(),
            input.mentions,
            payload,
        )?;
        let record = DiscourseClient::new(&host)
            .submit_event(&input.room_id, &envelope)
            .await?;
        self.apply_host_record(&host, record.clone())?;
        let item = self.timeline_item_by_event(&key, &record.envelope.hash)?;
        json_result(json!({
            "status": "sent",
            "record": record,
            "item": item,
            "sync": self.sync_state(&key)?
        }))
    }

    async fn room_submit_event(&mut self, mut input: RoomSubmitEventInput) -> Result<Value> {
        // For signal-kind writes — including the membership events — the base
        // is only an anchor: never hold the draft, ignore on_head_mismatch.
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
        let advances_head = self
            .state
            .rooms
            .get(&key)
            .map(|room| event_type_advances_room_head(room, &input.event_type))
            .unwrap_or(true);
        if advances_head {
            if let Some(result) = self.head_mismatch_event_result(&key, &mut input)? {
                return Ok(result);
            }
        }
        self.submit_event_unchecked(input).await
    }

    async fn submit_event_unchecked(&mut self, input: RoomSubmitEventInput) -> Result<Value> {
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
        let host = self.allowed_room_host(&key)?;
        let payload = payload_with_references(input.payload, input.references)?;
        let envelope = self.sign_room_event(
            input.event_type,
            &key,
            input.base_seq,
            input.base_hash.clone(),
            input.mentions,
            payload,
        )?;
        let record = DiscourseClient::new(&host)
            .submit_event(&input.room_id, &envelope)
            .await?;
        self.apply_host_record(&host, record.clone())?;
        let item = self.timeline_item_by_event(&key, &record.envelope.hash)?;
        json_result(json!({
            "status": "sent",
            "record": record,
            "item": item,
            "sync": self.sync_state(&key)?
        }))
    }

    async fn join_requests_list(&mut self, input: JoinRequestsListInput) -> Result<Value> {
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
        let host = self.allowed_room_host(&key)?;
        let jwt = self.request_jwt(&host)?;
        let mut requests = DiscourseClient::new(&host)
            .join_requests(&input.room_id, &jwt)
            .await?;
        if let Some(status) = input.status {
            requests.retain(|request| {
                serde_json::to_value(request.status)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    == Some(status.clone())
            });
        }
        let offset = input
            .cursor
            .as_deref()
            .and_then(|cursor| cursor.parse::<usize>().ok())
            .unwrap_or(0);
        if offset > 0 {
            requests = requests.into_iter().skip(offset).collect();
        }
        requests.truncate(input.limit.unwrap_or(requests.len()));
        self.state
            .join_requests
            .insert(key.clone(), requests.clone());
        json_result(json!({ "join_requests": requests }))
    }

    async fn join_request_review(&mut self, input: JoinRequestReviewInput) -> Result<Value> {
        let key = self.resolve_room_key(input.host.as_deref(), &input.room_id)?;
        let host = self.allowed_room_host(&key)?;
        let jwt = self.request_jwt(&host)?;
        let status = DiscourseClient::new(&host)
            .join_request(&input.room_id, &input.request_id, &jwt)
            .await?;
        let payload = RoomJoinReviewPayload {
            request: status.request,
            decision: input.decision,
            role: input.role,
            reason: input.reason,
            extra: BTreeMap::new(),
        };
        let envelope = self.sign_room_event(
            event_type::ROOM_JOIN_REVIEW,
            &key,
            None,
            None,
            Vec::new(),
            payload,
        )?;
        let record = DiscourseClient::new(&host)
            .submit_event(&input.room_id, &envelope)
            .await?;
        self.apply_host_record(&host, record.clone())?;
        json_result(json!({ "record": record, "sync": self.sync_state(&key)? }))
    }

    fn sign_profile_update(
        &mut self,
        payload: ProfileUpdatePayload,
    ) -> Result<Envelope<ProfileUpdatePayload>> {
        let event = profile_update_event(
            self.agent_id(),
            unix_ms(),
            self.nonce_manager.next_nonce()?,
            payload,
        );
        self.signer.sign_event(event)
    }

    fn sign_room_create(
        &mut self,
        payload: RoomCreatePayload,
    ) -> Result<Envelope<RoomCreatePayload>> {
        let event = room_create_event(
            self.agent_id(),
            unix_ms(),
            self.nonce_manager.next_nonce()?,
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
        let (base_seq, base_hash) = self.room_head_for_write(key, base_seq, base_hash)?;
        let event = discourse_event(
            event_type,
            self.agent_id(),
            unix_ms(),
            self.nonce_manager.next_nonce()?,
            key.1.clone(),
            base_seq,
            base_hash,
            payload,
        )
        .with_mentions(mentions);
        let envelope = self.signer.sign_event(event)?;
        validate_discourse_envelope(&envelope)?;
        Ok(envelope)
    }

    fn room_head_for_write(
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
                let sync = self.sync_state(key)?;
                let hash = sync.head_hash;
                if sync.head_seq == 0 || hash.trim().is_empty() {
                    return Err(SdkError::InvalidPayload(
                        "current room head is not known locally".to_owned(),
                    ));
                }
                Ok((sync.head_seq, hash))
            }
            _ => Err(SdkError::InvalidPayload(
                "base_seq and base_hash must be provided together".to_owned(),
            )),
        }
    }

    fn request_jwt(&self, host: &str) -> Result<String> {
        // The request JWT aud is always the origin of the host API.
        let audience = crate::identity::service_origin(host)?;
        let claims = RequestJwtClaims::new(
            self.agent_id(),
            RequestBinding::new(audience),
            unix_secs(),
            DEFAULT_REQUEST_JWT_TTL_SECS,
        );
        self.signer.sign_request_jwt(&claims)
    }

    fn head_mismatch_message_result(
        &mut self,
        key: &RoomKey,
        input: &mut RoomSendMessageInput,
    ) -> Result<Option<Value>> {
        let Some(head_mismatch) =
            self.head_mismatch_write_state(key, input.base_seq, input.base_hash.as_deref())?
        else {
            return Ok(None);
        };

        match input.on_head_mismatch {
            HeadMismatchPolicy::SendAnyway => {
                input.base_seq = None;
                input.base_hash = None;
                Ok(None)
            }
            HeadMismatchPolicy::Reject => {
                Ok(Some(self.rejected_head_mismatch_result(head_mismatch)))
            }
            HeadMismatchPolicy::Hold => {
                Ok(Some(self.hold_message_draft(input.clone(), head_mismatch)?))
            }
        }
    }

    fn head_mismatch_event_result(
        &mut self,
        key: &RoomKey,
        input: &mut RoomSubmitEventInput,
    ) -> Result<Option<Value>> {
        let Some(head_mismatch) =
            self.head_mismatch_write_state(key, input.base_seq, input.base_hash.as_deref())?
        else {
            return Ok(None);
        };

        match input.on_head_mismatch {
            HeadMismatchPolicy::SendAnyway => {
                input.base_seq = None;
                input.base_hash = None;
                Ok(None)
            }
            HeadMismatchPolicy::Reject => {
                Ok(Some(self.rejected_head_mismatch_result(head_mismatch)))
            }
            HeadMismatchPolicy::Hold => {
                Ok(Some(self.hold_event_draft(input.clone(), head_mismatch)?))
            }
        }
    }

    fn head_mismatch_write_state(
        &self,
        key: &RoomKey,
        base_seq: Option<u64>,
        base_hash: Option<&str>,
    ) -> Result<Option<HeadMismatchState>> {
        if base_seq.is_none() && base_hash.is_none() {
            return Ok(None);
        }

        let sync = self.sync_state(key)?;
        let seq_mismatch = base_seq
            .map(|base_seq| base_seq != sync.head_seq)
            .unwrap_or(false);
        let hash_mismatch = base_hash
            .map(|expected_hash| sync.head_hash != expected_hash)
            .unwrap_or(false);
        if !seq_mismatch && !hash_mismatch {
            return Ok(None);
        }

        Ok(Some(HeadMismatchState {
            sync,
            changes: self.room_changes_since(key, base_seq)?,
        }))
    }

    fn rejected_head_mismatch_result(&self, head_mismatch: HeadMismatchState) -> Value {
        json!({
            "status": "rejected",
            "reason": "room_head_mismatch",
            "changes": head_mismatch.changes,
            "sync": head_mismatch.sync
        })
    }

    fn hold_message_draft(
        &mut self,
        mut input: RoomSendMessageInput,
        head_mismatch: HeadMismatchState,
    ) -> Result<Value> {
        input.host = Some(head_mismatch.sync.host.clone());
        let draft_id = self.next_draft_id(&input.room_id);
        let draft = HeldDraft {
            id: draft_id.clone(),
            room_id: input.room_id.clone(),
            kind: HeldDraftKind::Message,
            created_at: unix_ms(),
            base_seq: input.base_seq,
            base_hash: input.base_hash.clone(),
            current_sync: head_mismatch.sync.clone(),
            draft: message_draft_value(&input)?,
            reason: "room_head_mismatch".to_owned(),
            options: held_draft_options(),
        };
        self.state.drafts.insert(
            draft_id,
            HeldDraftEntry {
                draft: draft.clone(),
                request: HeldDraftRequest::Message(input),
            },
        );
        json_result(json!({
            "status": "held",
            "reason": "room_head_mismatch",
            "draft": draft,
            "changes": head_mismatch.changes,
            "sync": head_mismatch.sync
        }))
    }

    fn hold_event_draft(
        &mut self,
        mut input: RoomSubmitEventInput,
        head_mismatch: HeadMismatchState,
    ) -> Result<Value> {
        input.host = Some(head_mismatch.sync.host.clone());
        let draft_id = self.next_draft_id(&input.room_id);
        let draft = HeldDraft {
            id: draft_id.clone(),
            room_id: input.room_id.clone(),
            kind: HeldDraftKind::Event,
            created_at: unix_ms(),
            base_seq: input.base_seq,
            base_hash: input.base_hash.clone(),
            current_sync: head_mismatch.sync.clone(),
            draft: event_draft_value(&input)?,
            reason: "room_head_mismatch".to_owned(),
            options: held_draft_options(),
        };
        self.state.drafts.insert(
            draft_id,
            HeldDraftEntry {
                draft: draft.clone(),
                request: HeldDraftRequest::Event(input),
            },
        );
        json_result(json!({
            "status": "held",
            "reason": "room_head_mismatch",
            "draft": draft,
            "changes": head_mismatch.changes,
            "sync": head_mismatch.sync
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
                let mut items = room
                    .timeline
                    .iter()
                    .rev()
                    .take(20)
                    .cloned()
                    .collect::<Vec<_>>();
                items.reverse();
                items
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
        format!("draft_{}_{}", room, self.state.drafts.len() + 1)
    }

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
            synced_seq: room.synced_seq,
            remote_seq: room.room.seq.max(room.synced_seq),
            subscribed: room.subscribed,
            unread_count: room.unread_count(),
            pending_inbox_count: self.pending_inbox_count(Some(&key.1)),
        })
    }

    fn room_state_view(&self, room: &LocalRoomState) -> RoomStateView {
        let self_member = room.members.get(&self.agent_id()).cloned();
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
                .envelope
                .as_ref()
                .map(|envelope| envelope.event.actor.clone()),
            created_at: room
                .room
                .envelope
                .as_ref()
                .map(|envelope| envelope.event.created_at),
            start_time: room_start_time(&room.room),
            end_time: room_end_time(&room.room),
            tags: room_tags(&room.room),
            language: room_language(&room.room),
            policy: room_policy(&room.room),
            types: room.room.types.clone(),
            self_member,
            members_count: room.members.len(),
            active_turn: room.active_turn.clone(),
            unread_count: room.unread_count(),
            pending_inbox_count: self.pending_inbox_count(Some(&room.room.id)),
        }
    }

    fn summary_for_room(&self, room: &LocalRoomState) -> RoomSummary {
        let self_member = room.members.get(&self.agent_id());
        RoomSummary {
            room_id: room.room.id.clone(),
            host: room.host.clone(),
            topic: room_topic(&room.room),
            status: room.room.status,
            visibility: room_visibility(&room.room),
            start_time: room_start_time(&room.room),
            end_time: room_end_time(&room.room),
            tags: room_tags(&room.room),
            language: room_language(&room.room),
            role: self_member.map(|member| member.role),
            unread_count: room.unread_count(),
            pending_inbox_count: self.pending_inbox_count(Some(&room.room.id)),
        }
    }

    fn summary_for_response(&self, host: &str, room: &RoomResponse) -> RoomSummary {
        self.state
            .rooms
            .get(&(host.to_owned(), room.id.clone()))
            .map(|room| self.summary_for_room(room))
            .unwrap_or_else(|| RoomSummary {
                room_id: room.id.clone(),
                host: host.to_owned(),
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
            })
    }

    fn timeline_item_by_event(&self, key: &RoomKey, event_id: &str) -> Result<TimelineItem> {
        self.local_room(key)?
            .timeline
            .iter()
            .find(|item| item.event_id == event_id)
            .cloned()
            .ok_or_else(|| SdkError::InvalidPayload("timeline item not materialized".to_owned()))
    }

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
        match self.state.hosts.get(host) {
            Some(host) if host.allowed => Ok(()),
            _ => Err(SdkError::PermissionDenied),
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
}

fn parse_input<T: DeserializeOwned>(input: Value) -> Result<T> {
    Ok(serde_json::from_value(input)?)
}

fn json_result(value: Value) -> Result<Value> {
    Ok(value)
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('/').to_owned()
}

fn typed_record_to_value<P>(record: ServerRecord<P>) -> Result<ServerRecord>
where
    P: Serialize,
{
    Ok(serde_json::from_value(serde_json::to_value(record)?)?)
}

fn membership_filter(
    room: &LocalRoomState,
    agent_id: &AgentId,
    membership: Option<RoomsListMembership>,
) -> bool {
    match membership.unwrap_or(RoomsListMembership::All) {
        RoomsListMembership::All => true,
        RoomsListMembership::Member => room.members.contains_key(agent_id),
        RoomsListMembership::Creator => room
            .members
            .get(agent_id)
            .map(|member| member.is_creator)
            .unwrap_or(false),
        RoomsListMembership::Moderator => room
            .members
            .get(agent_id)
            .map(|member| member.role == Role::Moderator)
            .unwrap_or(false),
        RoomsListMembership::Pending => false,
    }
}

fn payload_with_references(mut payload: Value, references: Vec<String>) -> Result<Value> {
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

fn message_draft_value(input: &RoomSendMessageInput) -> Result<Value> {
    Ok(json!({
        "room_id": &input.room_id,
        "content": &input.content,
        "content_type": input.content_type.as_deref().unwrap_or("text/plain"),
        "mentions": &input.mentions,
        "references": &input.references,
        "extra": &input.extra
    }))
}

fn event_draft_value(input: &RoomSubmitEventInput) -> Result<Value> {
    Ok(json!({
        "room_id": &input.room_id,
        "type": &input.event_type,
        "payload": &input.payload,
        "mentions": &input.mentions,
        "references": &input.references
    }))
}

fn held_draft_options() -> Vec<DraftAction> {
    vec![
        DraftAction::Revise,
        DraftAction::SendAsIs,
        DraftAction::StaySilent,
        DraftAction::SendAnyway,
    ]
}

fn profile_to_member_profile(profile: &AgentProfile) -> RoomMemberProfile {
    RoomMemberProfile {
        name: Some(profile.name.clone()),
        description: profile.description.clone(),
        avatar_url: profile.avatar_url.clone(),
    }
}
