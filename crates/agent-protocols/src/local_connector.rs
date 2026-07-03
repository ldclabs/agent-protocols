//! Local Agent Protocols MCP connector core.
//!
//! This module is transport-neutral: it exposes the standard local connector
//! tool names, schemas, structured result types, a JSON dispatcher, and local
//! room-state projection. An MCP stdio server can wrap [`LocalConnector`] without
//! giving the agent direct access to signing keys or reusable request JWTs.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

use crate::discourse::{
    discourse_event, event_type, room_create_event, validate_discourse_envelope,
    validate_room_path, verify_server_record, AgentStatus, AgentStatusInput, JoinDecision,
    JoinRequestStatus, MessageCreatePayload, ReasonPayload, Role, RoleUpdatePayload,
    RoomCreatePayload, RoomJoinPayload, RoomJoinRequestInput, RoomJoinRequestStatus,
    RoomJoinReviewPayload, RoomResponse, RoomState, ServerRecord, TypeDeclaration, TypeDef,
    Visibility,
};
use crate::error::{Result, SdkError};
use crate::http_client::{DiscourseClient, ProfileClient, PublicRoomsOptions, RoomEventsOptions};
use crate::identity::{
    unix_ms, unix_secs, AgentId, AgentSigner, ClientNonceManager, Envelope, RequestBinding,
    RequestJwtClaims, DEFAULT_REQUEST_JWT_TTL_SECS,
};
use crate::profile::{profile_update_event, AgentProfile, ProfileUpdatePayload};

pub const TOOL_IDENTITY_CURRENT: &str = "agent_protocols_identity_current";
pub const TOOL_HOSTS_LIST: &str = "agent_protocols_hosts_list";
pub const TOOL_HOST_ADD: &str = "agent_protocols_host_add";
pub const TOOL_ROOMS_SEARCH: &str = "agent_protocols_rooms_search";
pub const TOOL_ROOMS_LIST: &str = "agent_protocols_rooms_list";
pub const TOOL_ROOM_OPEN: &str = "agent_protocols_room_open";
pub const TOOL_ROOM_STATE: &str = "agent_protocols_room_state";
pub const TOOL_ROOM_MEMBERS_LIST: &str = "agent_protocols_room_members_list";
pub const TOOL_ROOM_MEMBER_GET: &str = "agent_protocols_room_member_get";
pub const TOOL_AGENT_STATUS_LIST: &str = "agent_protocols_agent_status_list";
pub const TOOL_AGENT_STATUS_GET: &str = "agent_protocols_agent_status_get";
pub const TOOL_AGENT_STATUS_SET: &str = "agent_protocols_agent_status_set";
pub const TOOL_AGENT_STATUS_CLEAR: &str = "agent_protocols_agent_status_clear";
pub const TOOL_ROOM_TIMELINE: &str = "agent_protocols_room_timeline";
pub const TOOL_ROOM_UNREAD: &str = "agent_protocols_room_unread";
pub const TOOL_ROOM_MARK_READ: &str = "agent_protocols_room_mark_read";
pub const TOOL_INBOX_NEXT: &str = "agent_protocols_inbox_next";
pub const TOOL_INBOX_ACK: &str = "agent_protocols_inbox_ack";
pub const TOOL_DRAFTS_LIST: &str = "agent_protocols_drafts_list";
pub const TOOL_DRAFT_GET: &str = "agent_protocols_draft_get";
pub const TOOL_DRAFT_COMMIT: &str = "agent_protocols_draft_commit";
pub const TOOL_DRAFT_DROP: &str = "agent_protocols_draft_drop";
pub const TOOL_PROFILE_UPDATE: &str = "agent_protocols_profile_update";
pub const TOOL_ROOM_CREATE: &str = "agent_protocols_room_create";
pub const TOOL_ROOM_JOIN: &str = "agent_protocols_room_join";
pub const TOOL_ROOM_JOIN_REQUEST: &str = "agent_protocols_room_join_request";
pub const TOOL_ROOM_JOIN_WHEN_APPROVED: &str = "agent_protocols_room_join_when_approved";
pub const TOOL_ROOM_LEAVE: &str = "agent_protocols_room_leave";
pub const TOOL_ROOM_SEND_MESSAGE: &str = "agent_protocols_room_send_message";
pub const TOOL_ROOM_SUBMIT_EVENT: &str = "agent_protocols_room_submit_event";
pub const TOOL_JOIN_REQUESTS_LIST: &str = "agent_protocols_join_requests_list";
pub const TOOL_JOIN_REQUEST_REVIEW: &str = "agent_protocols_join_request_review";

pub const RESOURCE_IDENTITY_CURRENT: &str = "agent-protocols://identity/current";
pub const RESOURCE_HOSTS: &str = "agent-protocols://hosts";
pub const RESOURCE_ROOMS: &str = "agent-protocols://rooms";
pub const RESOURCE_INBOX_PENDING: &str = "agent-protocols://inbox/pending";
pub const RESOURCE_DRAFTS_HELD: &str = "agent-protocols://drafts/held";
pub const RESOURCE_ROOM_AGENT_STATUS_SUFFIX: &str = "/agent-status";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LocalConnectorToolAnnotations {
    pub read_only_hint: bool,
    pub idempotent_hint: bool,
    pub destructive_hint: bool,
    pub open_world_hint: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LocalConnectorToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub output_schema: Value,
    pub annotations: LocalConnectorToolAnnotations,
}

pub fn standard_tool_definitions() -> Vec<LocalConnectorToolDefinition> {
    [
        (
            TOOL_IDENTITY_CURRENT,
            "Return the active local Agent ID and non-secret connector configuration.",
            true,
            true,
            false,
        ),
        (
            TOOL_HOSTS_LIST,
            "List configured Agent Discourse hosts.",
            true,
            true,
            false,
        ),
        (
            TOOL_HOST_ADD,
            "Add an allowed Agent Discourse host after discovery.",
            false,
            true,
            true,
        ),
        (
            TOOL_ROOMS_SEARCH,
            "Search public rooms on an allowed host.",
            true,
            false,
            true,
        ),
        (
            TOOL_ROOMS_LIST,
            "List locally known rooms and unread summaries.",
            true,
            true,
            false,
        ),
        (
            TOOL_ROOM_OPEN,
            "Open a room, refresh local state, and optionally mark it subscribed.",
            false,
            true,
            true,
        ),
        (
            TOOL_ROOM_STATE,
            "Read the local materialized room state.",
            true,
            true,
            false,
        ),
        (
            TOOL_ROOM_MEMBERS_LIST,
            "List materialized room members.",
            true,
            true,
            false,
        ),
        (
            TOOL_ROOM_MEMBER_GET,
            "Read one materialized room member.",
            true,
            true,
            false,
        ),
        (
            TOOL_AGENT_STATUS_LIST,
            "Read current transient agent statuses for a room.",
            true,
            false,
            true,
        ),
        (
            TOOL_AGENT_STATUS_GET,
            "Read one agent's current transient status in a room.",
            true,
            false,
            true,
        ),
        (
            TOOL_AGENT_STATUS_SET,
            "Update the active local agent's transient status in a room.",
            false,
            false,
            true,
        ),
        (
            TOOL_AGENT_STATUS_CLEAR,
            "Clear the active local agent's transient status in a room.",
            false,
            true,
            true,
        ),
        (
            TOOL_ROOM_TIMELINE,
            "Read simplified timeline items from the local cache.",
            true,
            true,
            false,
        ),
        (
            TOOL_ROOM_UNREAD,
            "Read unread timeline items, optionally marking them read.",
            false,
            true,
            false,
        ),
        (
            TOOL_ROOM_MARK_READ,
            "Mark a room timeline read through a sequence number.",
            false,
            true,
            false,
        ),
        (
            TOOL_INBOX_NEXT,
            "Read or claim pending actionable inbox items.",
            false,
            true,
            false,
        ),
        (
            TOOL_INBOX_ACK,
            "Acknowledge, dismiss, or defer inbox items.",
            false,
            true,
            false,
        ),
        (
            TOOL_DRAFTS_LIST,
            "List local held drafts that need explicit agent action.",
            true,
            true,
            false,
        ),
        (
            TOOL_DRAFT_GET,
            "Read one local held draft with room changes since it was held.",
            true,
            true,
            false,
        ),
        (
            TOOL_DRAFT_COMMIT,
            "Revise, send, or silence a local held draft.",
            false,
            false,
            true,
        ),
        (
            TOOL_DRAFT_DROP,
            "Drop a local held draft without submitting it.",
            false,
            true,
            false,
        ),
        (
            TOOL_PROFILE_UPDATE,
            "Sign and submit a profile.update envelope.",
            false,
            false,
            true,
        ),
        (
            TOOL_ROOM_CREATE,
            "Sign and submit a room.create envelope.",
            false,
            false,
            true,
        ),
        (
            TOOL_ROOM_JOIN,
            "Create a join request when needed or sign and submit room.join.",
            false,
            false,
            true,
        ),
        (
            TOOL_ROOM_LEAVE,
            "Sign and submit room.leave.",
            false,
            false,
            true,
        ),
        (
            TOOL_ROOM_SEND_MESSAGE,
            "Sign and submit message.create.",
            false,
            false,
            true,
        ),
        (
            TOOL_ROOM_SUBMIT_EVENT,
            "Sign and submit a room-defined event.",
            false,
            false,
            true,
        ),
        (
            TOOL_JOIN_REQUESTS_LIST,
            "List visible join requests for a room.",
            true,
            false,
            true,
        ),
        (
            TOOL_JOIN_REQUEST_REVIEW,
            "Sign and submit room.join.review.",
            false,
            false,
            true,
        ),
    ]
    .into_iter()
    .map(
        |(name, description, read_only, idempotent, open_world)| LocalConnectorToolDefinition {
            name: name.to_owned(),
            description: description.to_owned(),
            input_schema: json!({"type": "object"}),
            output_schema: json!({"type": "object"}),
            annotations: LocalConnectorToolAnnotations {
                read_only_hint: read_only,
                idempotent_hint: idempotent,
                destructive_hint: false,
                open_world_hint: open_world,
            },
        },
    )
    .collect()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncState {
    pub host: String,
    pub room_id: String,
    pub head_seq: u64,
    pub head_hash: String,
    pub synced_seq: u64,
    pub remote_seq: u64,
    pub subscribed: bool,
    pub unread_count: usize,
    pub pending_inbox_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentProtocolsHost {
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub allowed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_checked_at: Option<i64>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RoomMemberStatus {
    Active,
    Left,
    Removed,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoomMemberProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RoomMemberView {
    pub agent_id: AgentId,
    pub role: Role,
    pub status: RoomMemberStatus,
    pub is_creator: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perspective: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joined_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_event_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<RoomMemberProfile>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TimelineItem {
    pub room_id: String,
    pub seq: u64,
    pub event_id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub kind: String,
    pub actor: AgentId,
    pub created_at: i64,
    pub received_at: i64,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mentions: Vec<AgentId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum InboxKind {
    #[serde(rename = "room.message.new")]
    RoomMessageNew,
    #[serde(rename = "room.mention")]
    RoomMention,
    #[serde(rename = "room.turn.assigned")]
    RoomTurnAssigned,
    #[serde(rename = "room.steer")]
    RoomSteer,
    #[serde(rename = "room.join.requested")]
    RoomJoinRequested,
    #[serde(rename = "room.join.approved")]
    RoomJoinApproved,
    #[serde(rename = "room.role.changed")]
    RoomRoleChanged,
    #[serde(rename = "room.state.changed")]
    RoomStateChanged,
    #[serde(rename = "room.event.custom")]
    RoomEventCustom,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InboxPriority {
    Low,
    Normal,
    High,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct InboxItem {
    pub id: String,
    pub kind: InboxKind,
    pub priority: InboxPriority,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<AgentId>,
    pub created_at: i64,
    pub requires_response: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline: Option<i64>,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suggested_tools: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<Value>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HeadMismatchPolicy {
    Hold,
    Reject,
    SendAnyway,
}

impl Default for HeadMismatchPolicy {
    fn default() -> Self {
        Self::Hold
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HeldDraftKind {
    Message,
    Event,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DraftAction {
    Revise,
    SendAsIs,
    StaySilent,
    SendAnyway,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct HeldDraft {
    pub id: String,
    pub room_id: String,
    pub kind: HeldDraftKind,
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_hash: Option<String>,
    pub current_sync: SyncState,
    pub draft: Value,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<DraftAction>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ActiveTurn {
    pub turn_id: String,
    pub speaker: AgentId,
    pub assigned_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instruction: Option<String>,
    pub source_event_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RoomSummary {
    pub room_id: String,
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    pub status: RoomState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<Visibility>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,
    pub unread_count: usize,
    pub pending_inbox_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RoomStateView {
    pub host: String,
    pub room_id: String,
    pub status: RoomState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<Visibility>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agenda: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guidance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator: Option<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<crate::discourse::RoomPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<TypeDef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_member: Option<RoomMemberView>,
    pub members_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_turn: Option<ActiveTurn>,
    pub unread_count: usize,
    pub pending_inbox_count: usize,
}

#[derive(Clone, Debug, Default)]
pub struct LocalConnectorState {
    pub hosts: BTreeMap<String, AgentProtocolsHost>,
    rooms: BTreeMap<String, LocalRoomState>,
    profiles: BTreeMap<AgentId, AgentProfile>,
    join_requests: BTreeMap<String, Vec<RoomJoinRequestStatus>>,
    agent_statuses: BTreeMap<String, BTreeMap<AgentId, AgentStatus>>,
    inbox: BTreeMap<String, InboxEntry>,
    drafts: BTreeMap<String, HeldDraftEntry>,
}

impl LocalConnectorState {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Clone, Debug)]
struct LocalRoomState {
    host: String,
    room: RoomResponse,
    head_seq: u64,
    head_hash: Option<String>,
    synced_seq: u64,
    synced_hash: Option<String>,
    subscribed: bool,
    members: BTreeMap<AgentId, RoomMemberView>,
    timeline: Vec<TimelineItem>,
    records: Vec<ServerRecord>,
    read_seq: u64,
    active_turn: Option<ActiveTurn>,
}

impl LocalRoomState {
    fn new(host: String, room: RoomResponse) -> Self {
        Self {
            host,
            room,
            head_seq: 0,
            head_hash: None,
            synced_seq: 0,
            synced_hash: None,
            subscribed: false,
            members: BTreeMap::new(),
            timeline: Vec::new(),
            records: Vec::new(),
            read_seq: 0,
            active_turn: None,
        }
    }

    fn unread_count(&self) -> usize {
        self.timeline
            .iter()
            .filter(|item| item.seq > self.read_seq)
            .count()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum InboxEntryState {
    Pending,
    Claimed,
    Deferred(i64),
    Acknowledged,
}

#[derive(Clone, Debug)]
struct InboxEntry {
    item: InboxItem,
    state: InboxEntryState,
}

#[derive(Clone, Debug)]
struct HeldDraftEntry {
    draft: HeldDraft,
    request: HeldDraftRequest,
}

#[derive(Clone, Debug)]
enum HeldDraftRequest {
    Message(RoomSendMessageInput),
    Event(RoomSubmitEventInput),
}

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
        let room_id = room.id.clone();
        let entry = self
            .state
            .rooms
            .entry(room_id)
            .or_insert_with(|| LocalRoomState::new(host.clone(), room.clone()));
        entry.host = host;
        entry.room = room;
        materialize_creator(entry);
    }

    pub fn accept_room_response(&mut self, host: impl Into<String>, room: RoomResponse) {
        let room_id = room.id.clone();
        self.observe_room(host, room);
        if let Some(entry) = self.state.rooms.get_mut(&room_id) {
            let (head_seq, head_hash) = room_response_head(&entry.room);
            entry.head_seq = head_seq;
            entry.head_hash = Some(head_hash);
            entry.synced_seq = entry.room.seq;
            entry.synced_hash = Some(entry.room.hash.clone());
        }
    }

    pub fn apply_record(&mut self, record: ServerRecord) -> Result<()> {
        validate_discourse_envelope(&record.envelope)?;
        validate_room_path(&record.envelope, &record.room_id)?;
        verify_server_record(&record)?;

        let room_id = record.room_id.clone();
        let active_agent = self.agent_id();
        let mut new_inbox = Vec::new();
        {
            let room = self.state.rooms.get_mut(&room_id).ok_or_else(|| {
                SdkError::InvalidPayload(format!("room is not open locally: {room_id}"))
            })?;
            if is_duplicate_record(room, &record) {
                return Ok(());
            }
            validate_next_record(room, &record)?;
            validate_record_base_precondition(room, &record)?;

            let item = TimelineItem::from_record(&record);
            apply_record_projection(room, &record, &item, &active_agent, &mut new_inbox)?;
            if record_advances_room_head(room, &record) {
                room.head_seq = record.seq;
                room.head_hash = Some(record.hash.clone());
            }
            room.synced_seq = record.seq;
            room.synced_hash = Some(record.hash.clone());
            room.records.push(record);
            room.timeline.push(item);
        }
        for item in new_inbox {
            self.insert_inbox(item);
        }
        Ok(())
    }

    pub async fn call_tool(&mut self, name: &str, input: Value) -> Result<Value> {
        match name {
            TOOL_IDENTITY_CURRENT => self.identity_current(),
            TOOL_HOSTS_LIST => self.hosts_list(),
            TOOL_HOST_ADD => self.host_add(parse_input(input)?).await,
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

    async fn host_add(&mut self, input: HostAddInput) -> Result<Value> {
        let host = normalize_host(&input.host);
        let discovery = DiscourseClient::new(&host).protocol().await?;
        let profile_service = input
            .profile_service
            .or_else(|| discovery.profile.and_then(|profile| profile.service));
        let host_view = AgentProtocolsHost {
            host: host.clone(),
            label: input.label,
            allowed: true,
            features: discovery.features,
            profile_service,
            last_checked_at: Some(unix_ms()),
        };
        self.add_host(host_view.clone());
        json_result(json!({ "host": host_view }))
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
        let previous_seq = self
            .state
            .rooms
            .get(&input.room_id)
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
                self.apply_record(record)?;
            }
        }
        if let Some(room) = self.state.rooms.get_mut(&input.room_id) {
            room.subscribed = input.subscribe.unwrap_or(false);
        }
        let room = self.local_room(&input.room_id)?;
        json_result(json!({
            "room": self.room_state_view(room),
            "sync": self.sync_state(&input.room_id)?,
            "active_turn": room.active_turn
        }))
    }

    async fn room_state(&mut self, input: RoomStateInput) -> Result<Value> {
        let _ = input.include_types;
        if input.refresh {
            let host = self.local_room(&input.room_id)?.host.clone();
            return self
                .room_open(RoomOpenInput {
                    host,
                    room_id: input.room_id,
                    subscribe: None,
                    refresh: true,
                })
                .await;
        }
        let room = self.local_room(&input.room_id)?;
        json_result(json!({
            "room": self.room_state_view(room),
            "sync": self.sync_state(&input.room_id)?
        }))
    }

    fn room_members_list(&self, input: RoomMembersListInput) -> Result<Value> {
        let room = self.local_room(&input.room_id)?;
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
            "sync": self.sync_state(&input.room_id)?
        }))
    }

    fn room_member_get(&self, input: RoomMemberGetInput) -> Result<Value> {
        let room = self.local_room(&input.room_id)?;
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
            "sync": self.sync_state(&input.room_id)?
        }))
    }

    async fn agent_status_list(&mut self, input: AgentStatusListInput) -> Result<Value> {
        if !input.refresh {
            if let Some(statuses) = self.state.agent_statuses.get(&input.room_id) {
                return json_result(json!({
                    "statuses": statuses.values().collect::<Vec<_>>(),
                    "sync": self.sync_state(&input.room_id)?
                }));
            }
        }
        let host = self.allowed_room_host(&input.room_id)?;
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
        self.state
            .agent_statuses
            .insert(input.room_id.clone(), statuses);
        json_result(json!({
            "statuses": values,
            "sync": self.sync_state(&input.room_id)?
        }))
    }

    async fn agent_status_get(&mut self, input: AgentStatusGetInput) -> Result<Value> {
        if !input.refresh {
            if let Some(status) = self
                .state
                .agent_statuses
                .get(&input.room_id)
                .and_then(|statuses| statuses.get(&input.agent_id))
                .cloned()
            {
                return json_result(json!({
                    "status": status,
                    "sync": self.sync_state(&input.room_id)?
                }));
            }
        }
        let host = self.allowed_room_host(&input.room_id)?;
        let jwt = self.request_jwt(&host)?;
        let response = DiscourseClient::new(&host)
            .agent_status(&input.room_id, &input.agent_id, Some(&jwt))
            .await?;
        self.state
            .agent_statuses
            .entry(input.room_id.clone())
            .or_default()
            .insert(response.status.agent_id.clone(), response.status.clone());
        json_result(json!({
            "status": response.status,
            "sync": self.sync_state(&input.room_id)?
        }))
    }

    async fn agent_status_set(&mut self, input: AgentStatusSetInput) -> Result<Value> {
        let host = self.allowed_room_host(&input.room_id)?;
        let jwt = self.request_jwt(&host)?;
        let mut request = AgentStatusInput::new(input.state, input.expires_at);
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
            .entry(input.room_id.clone())
            .or_default()
            .insert(status.agent_id.clone(), status.clone());
        json_result(json!({
            "status": status,
            "sync": self.sync_state(&input.room_id)?
        }))
    }

    async fn agent_status_clear(&mut self, input: AgentStatusClearInput) -> Result<Value> {
        let host = self.allowed_room_host(&input.room_id)?;
        let jwt = self.request_jwt(&host)?;
        let request = AgentStatusInput::new("away", unix_ms().saturating_sub(1));
        let _ = DiscourseClient::new(&host)
            .set_agent_status(&input.room_id, &jwt, &request)
            .await?;
        let active_agent = self.agent_id();
        if let Some(statuses) = self.state.agent_statuses.get_mut(&input.room_id) {
            statuses.remove(&active_agent);
        }
        json_result(json!({
            "cleared": true,
            "room_id": input.room_id
        }))
    }

    fn room_timeline(&self, input: RoomTimelineInput) -> Result<Value> {
        let _ = (input.refresh, input.include_records);
        let room = self.local_room(&input.room_id)?;
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
            "sync": self.sync_state(&input.room_id)?,
            "next_after_seq": next_after_seq
        }))
    }

    fn room_unread(&mut self, input: RoomUnreadInput) -> Result<Value> {
        let room = self.local_room(&input.room_id)?;
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
                self.local_room_mut(&input.room_id)?.read_seq = through_seq;
            }
            items = self
                .local_room(&input.room_id)?
                .timeline
                .iter()
                .filter(|item| through_seq.map(|seq| item.seq <= seq).unwrap_or(false))
                .cloned()
                .collect();
        }
        let unread_count = self.local_room(&input.room_id)?.unread_count();
        json_result(json!({
            "items": items,
            "unread_count": unread_count,
            "sync": self.sync_state(&input.room_id)?
        }))
    }

    fn room_mark_read(&mut self, input: RoomMarkReadInput) -> Result<Value> {
        let room = self.local_room_mut(&input.room_id)?;
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
        let changes = self.room_changes_since(&entry.draft.room_id, entry.draft.base_seq)?;
        json_result(json!({
            "draft": entry.draft,
            "changes": changes,
            "sync": self.sync_state(&entry.draft.room_id)?
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
        object.insert("id".to_owned(), serde_json::to_value(self.agent_id())?);
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
        json_result(json!({
            "room": self.room_state_view(self.local_room(&room.id)?),
            "envelope": envelope,
            "sync": self.sync_state(&room.id)?
        }))
    }

    async fn room_join(&mut self, input: RoomJoinInput) -> Result<Value> {
        let room_id = input.room_id.clone();
        let host = match input.host.as_deref() {
            Some(host) => {
                let host = normalize_host(host);
                self.require_allowed_host(&host)?;
                host
            }
            None => self.allowed_room_host(&room_id)?,
        };

        if !self.state.rooms.contains_key(&room_id) {
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
            let role = status.approved_role.unwrap_or(status.request.role);
            let payload = RoomJoinPayload {
                request_id: Some(request_id),
                role,
                perspective: None,
            };
            let envelope = self.sign_room_event(
                event_type::ROOM_JOIN,
                &room_id,
                None,
                None,
                Vec::new(),
                payload,
            )?;
            let record = DiscourseClient::new(&host)
                .join_room(&room_id, &envelope)
                .await?;
            let record = typed_record_to_value(record)?;
            self.apply_record(record.clone())?;
            let member = self
                .local_room(&room_id)?
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
                "sync": self.sync_state(&room_id)?
            }));
        }

        if room_visibility(&self.local_room(&room_id)?.room) == Some(Visibility::Public) {
            let payload = RoomJoinPayload {
                request_id: None,
                role: input.role,
                perspective: input.perspective,
            };
            let envelope = self.sign_room_event(
                event_type::ROOM_JOIN,
                &room_id,
                None,
                None,
                Vec::new(),
                payload,
            )?;
            let record = DiscourseClient::new(&host)
                .join_room(&room_id, &envelope)
                .await?;
            let record = typed_record_to_value(record)?;
            self.apply_record(record.clone())?;
            let member = self
                .local_room(&room_id)?
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
                "sync": self.sync_state(&room_id)?
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
            .entry(room_id.clone())
            .or_default()
            .push(status.clone());
        json_result(json!({
            "status": "approval_required",
            "join_request": status,
            "sync": self.sync_state(&room_id).ok()
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
            .entry(input.room_id)
            .or_default()
            .push(status.clone());
        json_result(json!({ "join_request": status }))
    }

    async fn room_join_when_approved(&mut self, input: RoomJoinWhenApprovedInput) -> Result<Value> {
        let host = self.allowed_room_host(&input.room_id)?;
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
        let envelope = self.sign_room_event(
            event_type::ROOM_JOIN,
            &input.room_id,
            None,
            None,
            Vec::new(),
            payload,
        )?;
        let record = DiscourseClient::new(&host)
            .join_room(&input.room_id, &envelope)
            .await?;
        let record = typed_record_to_value(record)?;
        self.apply_record(record.clone())?;
        let member = self
            .local_room(&input.room_id)?
            .members
            .get(&self.agent_id())
            .cloned()
            .ok_or_else(|| SdkError::InvalidPayload("joined member not materialized".to_owned()))?;
        json_result(json!({
            "record": record,
            "member": member,
            "sync": self.sync_state(&input.room_id)?
        }))
    }

    async fn room_leave(&mut self, input: RoomLeaveInput) -> Result<Value> {
        let host = self.allowed_room_host(&input.room_id)?;
        let payload = ReasonPayload {
            reason: input.reason,
            references: Vec::new(),
            extra: BTreeMap::new(),
        };
        let envelope = self.sign_room_event(
            event_type::ROOM_LEAVE,
            &input.room_id,
            None,
            None,
            Vec::new(),
            payload,
        )?;
        let record = DiscourseClient::new(&host)
            .leave_room(&input.room_id, &envelope)
            .await?;
        let record = typed_record_to_value(record)?;
        self.apply_record(record.clone())?;
        json_result(json!({ "record": record, "sync": self.sync_state(&input.room_id)? }))
    }

    async fn room_send_message(&mut self, mut input: RoomSendMessageInput) -> Result<Value> {
        if let Some(result) = self.head_mismatch_message_result(&mut input)? {
            return Ok(result);
        }
        self.submit_message_unchecked(input).await
    }

    async fn submit_message_unchecked(&mut self, input: RoomSendMessageInput) -> Result<Value> {
        let host = self.allowed_room_host(&input.room_id)?;
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
            &input.room_id,
            input.base_seq,
            input.base_hash.clone(),
            input.mentions,
            payload,
        )?;
        let record = DiscourseClient::new(&host)
            .submit_event(&input.room_id, &envelope)
            .await?;
        self.apply_record(record.clone())?;
        let item = self.timeline_item_by_event(&input.room_id, &record.envelope.hash)?;
        json_result(json!({
            "status": "sent",
            "record": record,
            "item": item,
            "sync": self.sync_state(&input.room_id)?
        }))
    }

    async fn room_submit_event(&mut self, mut input: RoomSubmitEventInput) -> Result<Value> {
        if let Some(result) = self.head_mismatch_event_result(&mut input)? {
            return Ok(result);
        }
        self.submit_event_unchecked(input).await
    }

    async fn submit_event_unchecked(&mut self, input: RoomSubmitEventInput) -> Result<Value> {
        let host = self.allowed_room_host(&input.room_id)?;
        let payload = payload_with_references(input.payload, input.references)?;
        let envelope = self.sign_room_event(
            input.event_type,
            &input.room_id,
            input.base_seq,
            input.base_hash.clone(),
            input.mentions,
            payload,
        )?;
        let record = DiscourseClient::new(&host)
            .submit_event(&input.room_id, &envelope)
            .await?;
        self.apply_record(record.clone())?;
        let item = self.timeline_item_by_event(&input.room_id, &record.envelope.hash)?;
        json_result(json!({
            "status": "sent",
            "record": record,
            "item": item,
            "sync": self.sync_state(&input.room_id)?
        }))
    }

    async fn join_requests_list(&mut self, input: JoinRequestsListInput) -> Result<Value> {
        let host = self.allowed_room_host(&input.room_id)?;
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
            .insert(input.room_id.clone(), requests.clone());
        json_result(json!({ "join_requests": requests }))
    }

    async fn join_request_review(&mut self, input: JoinRequestReviewInput) -> Result<Value> {
        let host = self.allowed_room_host(&input.room_id)?;
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
            &input.room_id,
            None,
            None,
            Vec::new(),
            payload,
        )?;
        let record = DiscourseClient::new(&host)
            .submit_event(&input.room_id, &envelope)
            .await?;
        self.apply_record(record.clone())?;
        json_result(json!({ "record": record, "sync": self.sync_state(&input.room_id)? }))
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
        room_id: &str,
        base_seq: Option<u64>,
        base_hash: Option<String>,
        mentions: Vec<AgentId>,
        payload: P,
    ) -> Result<Envelope<P>>
    where
        P: Serialize,
    {
        let host = self.local_room(room_id)?.host.clone();
        self.require_allowed_host(&host)?;
        let (base_seq, base_hash) = self.room_head_for_write(room_id, base_seq, base_hash)?;
        let event = discourse_event(
            event_type,
            self.agent_id(),
            unix_ms(),
            self.nonce_manager.next_nonce()?,
            room_id,
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
        room_id: &str,
        base_seq: Option<u64>,
        base_hash: Option<String>,
    ) -> Result<(u64, String)> {
        match (base_seq, base_hash) {
            (Some(seq), Some(hash)) if seq > 0 && !hash.trim().is_empty() => Ok((seq, hash)),
            (Some(_), Some(_)) => Err(SdkError::InvalidPayload(
                "base_seq and base_hash must identify a valid room head".to_owned(),
            )),
            (None, None) => {
                let sync = self.sync_state(room_id)?;
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

    fn request_jwt(&self, audience: &str) -> Result<String> {
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
        input: &mut RoomSendMessageInput,
    ) -> Result<Option<Value>> {
        let Some(head_mismatch) = self.head_mismatch_write_state(
            &input.room_id,
            input.base_seq,
            input.base_hash.as_deref(),
        )?
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
        input: &mut RoomSubmitEventInput,
    ) -> Result<Option<Value>> {
        let Some(head_mismatch) = self.head_mismatch_write_state(
            &input.room_id,
            input.base_seq,
            input.base_hash.as_deref(),
        )?
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
        room_id: &str,
        base_seq: Option<u64>,
        base_hash: Option<&str>,
    ) -> Result<Option<HeadMismatchState>> {
        if base_seq.is_none() && base_hash.is_none() {
            return Ok(None);
        }

        let sync = self.sync_state(room_id)?;
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
            changes: self.room_changes_since(room_id, base_seq)?,
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
        input: RoomSendMessageInput,
        head_mismatch: HeadMismatchState,
    ) -> Result<Value> {
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
        input: RoomSubmitEventInput,
        head_mismatch: HeadMismatchState,
    ) -> Result<Value> {
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
        room_id: &str,
        base_seq: Option<u64>,
    ) -> Result<Vec<TimelineItem>> {
        let room = self.local_room(room_id)?;
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

    fn sync_state(&self, room_id: &str) -> Result<SyncState> {
        let room = self.local_room(room_id)?;
        let head_hash = room
            .head_hash
            .clone()
            .or_else(|| room.room.head.as_ref().map(|head| head.hash.clone()))
            .unwrap_or_else(|| room.room.hash.clone());
        Ok(SyncState {
            host: room.host.clone(),
            room_id: room_id.to_owned(),
            head_seq: room.head_seq,
            head_hash,
            synced_seq: room.synced_seq,
            remote_seq: room.room.seq.max(room.synced_seq),
            subscribed: room.subscribed,
            unread_count: room.unread_count(),
            pending_inbox_count: self.pending_inbox_count(Some(room_id)),
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
            .get(&room.id)
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

    fn timeline_item_by_event(&self, room_id: &str, event_id: &str) -> Result<TimelineItem> {
        self.local_room(room_id)?
            .timeline
            .iter()
            .find(|item| item.event_id == event_id)
            .cloned()
            .ok_or_else(|| SdkError::InvalidPayload("timeline item not materialized".to_owned()))
    }

    fn local_room(&self, room_id: &str) -> Result<&LocalRoomState> {
        self.state
            .rooms
            .get(room_id)
            .ok_or_else(|| SdkError::InvalidPayload(format!("room is not open locally: {room_id}")))
    }

    fn local_room_mut(&mut self, room_id: &str) -> Result<&mut LocalRoomState> {
        self.state
            .rooms
            .get_mut(room_id)
            .ok_or_else(|| SdkError::InvalidPayload(format!("room is not open locally: {room_id}")))
    }

    fn require_allowed_host(&self, host: &str) -> Result<()> {
        match self.state.hosts.get(host) {
            Some(host) if host.allowed => Ok(()),
            _ => Err(SdkError::PermissionDenied),
        }
    }

    fn allowed_room_host(&self, room_id: &str) -> Result<String> {
        let host = self.local_room(room_id)?.host.clone();
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

impl TimelineItem {
    fn from_record(record: &ServerRecord) -> Self {
        let event = &record.envelope.event;
        let payload = event.payload.clone();
        let mut content_type = None;
        let mut content = None;
        let mut references = Vec::new();
        if event.kind == event_type::MESSAGE_CREATE {
            if let Ok(message) = serde_json::from_value::<MessageCreatePayload>(payload.clone()) {
                content_type = Some(message.content_type);
                content = Some(message.content);
                references = message.references;
            }
        }
        Self {
            room_id: record.room_id.clone(),
            seq: record.seq,
            event_id: record.envelope.hash.clone(),
            event_type: event.kind.clone(),
            kind: timeline_kind(&event.kind),
            actor: event.actor.clone(),
            created_at: event.created_at,
            received_at: record.received_at,
            summary: summarize_payload(&event.kind, &payload),
            content_type,
            content,
            mentions: event.mentions.clone(),
            references,
            payload,
        }
    }
}

#[derive(Deserialize)]
struct HostAddInput {
    host: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    profile_service: Option<String>,
}

#[derive(Deserialize)]
struct RoomsSearchInput {
    host: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    tag: Option<String>,
    #[serde(default)]
    keyword: Option<String>,
    #[serde(default)]
    creator: Option<String>,
    #[serde(default)]
    starts_after: Option<i64>,
    #[serde(default)]
    ends_before: Option<i64>,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RoomsListMembership {
    Member,
    Creator,
    Moderator,
    Pending,
    All,
}

#[derive(Deserialize)]
struct RoomsListInput {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    membership: Option<RoomsListMembership>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Deserialize)]
struct RoomOpenInput {
    host: String,
    room_id: String,
    #[serde(default)]
    subscribe: Option<bool>,
    #[serde(default)]
    refresh: bool,
}

#[derive(Deserialize)]
struct RoomStateInput {
    room_id: String,
    #[serde(default)]
    refresh: bool,
    #[serde(default)]
    include_types: bool,
}

#[derive(Deserialize)]
struct RoomMembersListInput {
    room_id: String,
    #[serde(default)]
    status: Option<RoomMemberStatus>,
    #[serde(default)]
    role: Option<Role>,
    #[serde(default)]
    include_profiles: bool,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Deserialize)]
struct RoomMemberGetInput {
    room_id: String,
    agent_id: AgentId,
    #[serde(default)]
    include_profile: bool,
    #[serde(default)]
    include_recent_activity: bool,
}

#[derive(Deserialize)]
struct AgentStatusListInput {
    room_id: String,
    #[serde(default)]
    refresh: bool,
}

#[derive(Deserialize)]
struct AgentStatusGetInput {
    room_id: String,
    agent_id: AgentId,
    #[serde(default)]
    refresh: bool,
}

#[derive(Deserialize)]
struct AgentStatusSetInput {
    room_id: String,
    state: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    seen_seq: Option<u64>,
    #[serde(default)]
    seen_hash: Option<String>,
    #[serde(default)]
    claim_id: Option<String>,
    #[serde(default)]
    activity: Option<String>,
    expires_at: i64,
    #[serde(default)]
    extra: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
struct AgentStatusClearInput {
    room_id: String,
}

#[derive(Deserialize)]
struct RoomTimelineInput {
    room_id: String,
    #[serde(default)]
    after_seq: Option<u64>,
    #[serde(default)]
    before_seq: Option<u64>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    types: Option<Vec<String>>,
    #[serde(default)]
    actors: Option<Vec<AgentId>>,
    #[serde(default)]
    unread_only: bool,
    #[serde(default)]
    refresh: bool,
    #[serde(default)]
    include_records: bool,
}

#[derive(Deserialize)]
struct RoomUnreadInput {
    room_id: String,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    mark_read: bool,
}

#[derive(Deserialize)]
struct RoomMarkReadInput {
    room_id: String,
    through_seq: u64,
}

#[derive(Deserialize)]
struct InboxNextInput {
    #[serde(default)]
    room_id: Option<String>,
    #[serde(default)]
    kinds: Option<Vec<String>>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    wait_ms: Option<u64>,
    #[serde(default)]
    claim: bool,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InboxAckAction {
    Handled,
    Dismissed,
    Defer,
}

#[derive(Deserialize)]
struct InboxAckInput {
    ids: Vec<String>,
    action: InboxAckAction,
    #[serde(default)]
    defer_until: Option<i64>,
}

#[derive(Deserialize)]
struct DraftsListInput {
    #[serde(default)]
    room_id: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Deserialize)]
struct DraftGetInput {
    draft_id: String,
}

#[derive(Deserialize)]
struct DraftCommitInput {
    draft_id: String,
    action: DraftAction,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    mentions: Option<Vec<AgentId>>,
    #[serde(default)]
    references: Option<Vec<String>>,
    #[serde(default)]
    extra: Option<BTreeMap<String, Value>>,
    #[serde(rename = "type", default)]
    event_type: Option<String>,
    #[serde(default)]
    payload: Option<Value>,
    #[serde(default)]
    base_seq: Option<u64>,
    #[serde(default)]
    base_hash: Option<String>,
    #[serde(default)]
    on_head_mismatch: HeadMismatchPolicy,
}

#[derive(Deserialize)]
struct DraftDropInput {
    draft_id: String,
}

#[derive(Deserialize)]
struct ProfileUpdateInput {
    profile_service: String,
    profile: Value,
}

#[derive(Deserialize)]
struct RoomCreateInput {
    host: String,
    topic: String,
    visibility: Visibility,
    start_time: i64,
    end_time: i64,
    #[serde(default)]
    agenda: Option<String>,
    #[serde(default)]
    guidance: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    policy: Option<crate::discourse::RoomPolicy>,
    #[serde(default)]
    types: Vec<TypeDeclaration>,
}

#[derive(Deserialize)]
struct RoomJoinInput {
    #[serde(default)]
    host: Option<String>,
    room_id: String,
    role: Role,
    #[serde(default)]
    perspective: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    request_id: Option<String>,
    #[serde(default)]
    extra: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
struct RoomJoinRequestToolInput {
    host: String,
    room_id: String,
    role: Role,
    #[serde(default)]
    perspective: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    extra: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
struct RoomJoinWhenApprovedInput {
    room_id: String,
    request_id: String,
}

#[derive(Deserialize)]
struct RoomLeaveInput {
    room_id: String,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Clone, Deserialize, Debug)]
struct RoomSendMessageInput {
    room_id: String,
    content: String,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    mentions: Vec<AgentId>,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    extra: BTreeMap<String, Value>,
    #[serde(default)]
    base_seq: Option<u64>,
    #[serde(default)]
    base_hash: Option<String>,
    #[serde(default)]
    on_head_mismatch: HeadMismatchPolicy,
}

#[derive(Clone, Deserialize, Debug)]
struct RoomSubmitEventInput {
    room_id: String,
    #[serde(rename = "type")]
    event_type: String,
    payload: Value,
    #[serde(default)]
    mentions: Vec<AgentId>,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    base_seq: Option<u64>,
    #[serde(default)]
    base_hash: Option<String>,
    #[serde(default)]
    on_head_mismatch: HeadMismatchPolicy,
}

#[derive(Deserialize)]
struct JoinRequestsListInput {
    room_id: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Deserialize)]
struct JoinRequestReviewInput {
    room_id: String,
    request_id: String,
    decision: JoinDecision,
    #[serde(default)]
    role: Option<Role>,
    #[serde(default)]
    reason: Option<String>,
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

fn room_create_payload(room: &RoomResponse) -> Option<&RoomCreatePayload> {
    room.envelope
        .as_ref()
        .map(|envelope| &envelope.event.payload)
}

fn room_topic(room: &RoomResponse) -> Option<String> {
    room.topic
        .clone()
        .or_else(|| room_create_payload(room).map(|payload| payload.topic.clone()))
}

fn room_agenda(room: &RoomResponse) -> Option<String> {
    room.agenda
        .clone()
        .or_else(|| room_create_payload(room).and_then(|payload| payload.agenda.clone()))
}

fn room_guidance(room: &RoomResponse) -> Option<String> {
    room.guidance
        .clone()
        .or_else(|| room_create_payload(room).and_then(|payload| payload.guidance.clone()))
}

fn room_visibility(room: &RoomResponse) -> Option<Visibility> {
    room.visibility
        .or_else(|| room_create_payload(room).map(|payload| payload.visibility))
}

fn room_start_time(room: &RoomResponse) -> Option<i64> {
    room.start_time
        .or_else(|| room_create_payload(room).map(|payload| payload.start_time))
}

fn room_end_time(room: &RoomResponse) -> Option<i64> {
    room.end_time
        .or_else(|| room_create_payload(room).map(|payload| payload.end_time))
}

fn room_tags(room: &RoomResponse) -> Vec<String> {
    if room.tags.is_empty() {
        room_create_payload(room)
            .map(|payload| payload.tags.clone())
            .unwrap_or_default()
    } else {
        room.tags.clone()
    }
}

fn room_language(room: &RoomResponse) -> Option<String> {
    room.language
        .clone()
        .or_else(|| room_create_payload(room).and_then(|payload| payload.language.clone()))
}

fn room_policy(room: &RoomResponse) -> Option<crate::discourse::RoomPolicy> {
    room.policy
        .clone()
        .or_else(|| room_create_payload(room).and_then(|payload| payload.policy.clone()))
}

fn room_response_head(room: &RoomResponse) -> (u64, String) {
    room.head
        .as_ref()
        .map(|head| (head.seq, head.hash.clone()))
        .unwrap_or_else(|| (room.seq, room.hash.clone()))
}

fn record_advances_room_head(room: &LocalRoomState, record: &ServerRecord) -> bool {
    let event_type = record.envelope.event.kind.as_str();
    if crate::discourse::is_builtin_event_type(event_type) {
        return true;
    }
    room.room
        .types
        .iter()
        .find(|definition| definition.name == event_type)
        .map(|definition| definition.kind != crate::discourse::TypeKind::Signal)
        .unwrap_or(true)
}

fn materialize_creator(room: &mut LocalRoomState) {
    let Some(envelope) = &room.room.envelope else {
        return;
    };
    let creator = envelope.event.actor.clone();
    room.members
        .entry(creator.clone())
        .or_insert_with(|| RoomMemberView {
            agent_id: creator,
            role: Role::Moderator,
            status: RoomMemberStatus::Active,
            is_creator: true,
            perspective: None,
            joined_seq: Some(1),
            left_seq: None,
            last_event_seq: Some(1),
            profile: None,
            extra: BTreeMap::new(),
        });
}

fn is_duplicate_record(room: &LocalRoomState, record: &ServerRecord) -> bool {
    record.seq <= room.synced_seq
        && room
            .records
            .iter()
            .any(|existing| existing.seq == record.seq && existing.hash == record.hash)
}

fn validate_next_record(room: &LocalRoomState, record: &ServerRecord) -> Result<()> {
    if room.synced_seq == 0 {
        if record.seq != 1 || record.pre_hash.is_some() {
            return Err(SdkError::InvalidPayload(
                "first local record must have seq 1 and null pre_hash".to_owned(),
            ));
        }
        return Ok(());
    }
    if record.seq != room.synced_seq + 1 {
        return Err(SdkError::InvalidPayload(
            "record seq must continue local chain".to_owned(),
        ));
    }
    if record.pre_hash.as_deref() != room.synced_hash.as_deref() {
        return Err(SdkError::InvalidPayload(
            "record pre_hash mismatch".to_owned(),
        ));
    }
    Ok(())
}

fn validate_record_base_precondition(room: &LocalRoomState, record: &ServerRecord) -> Result<()> {
    if record.envelope.event.kind == event_type::ROOM_CREATE {
        return Ok(());
    }
    let base_seq = record
        .envelope
        .event
        .base_seq
        .ok_or_else(|| SdkError::InvalidPayload("record event requires base_seq".to_owned()))?;
    let base_hash =
        record.envelope.event.base_hash.as_deref().ok_or_else(|| {
            SdkError::InvalidPayload("record event requires base_hash".to_owned())
        })?;
    if base_seq >= record.seq {
        return Err(SdkError::InvalidPayload(
            "record base_seq must reference an earlier accepted record".to_owned(),
        ));
    }
    if !record_advances_room_head(room, record) {
        return Ok(());
    }
    if room.head_seq != base_seq || room.head_hash.as_deref() != Some(base_hash) {
        return Err(SdkError::InvalidPayload(
            "record base_seq/base_hash must match current room head".to_owned(),
        ));
    }
    Ok(())
}

fn apply_record_projection(
    room: &mut LocalRoomState,
    record: &ServerRecord,
    item: &TimelineItem,
    active_agent: &AgentId,
    inbox: &mut Vec<InboxItem>,
) -> Result<()> {
    let event = &record.envelope.event;
    match event.kind.as_str() {
        event_type::ROOM_JOIN => {
            let payload: RoomJoinPayload = serde_json::from_value(event.payload.clone())?;
            room.members.insert(
                event.actor.clone(),
                RoomMemberView {
                    agent_id: event.actor.clone(),
                    role: payload.role,
                    status: RoomMemberStatus::Active,
                    is_creator: false,
                    perspective: None,
                    joined_seq: Some(record.seq),
                    left_seq: None,
                    last_event_seq: Some(record.seq),
                    profile: None,
                    extra: BTreeMap::new(),
                },
            );
        }
        event_type::ROOM_LEAVE => {
            if let Some(member) = room.members.get_mut(&event.actor) {
                member.status = RoomMemberStatus::Left;
                member.left_seq = Some(record.seq);
                member.last_event_seq = Some(record.seq);
            }
        }
        event_type::ROOM_MEMBER_ROLE_UPDATE => {
            let payload: RoleUpdatePayload = serde_json::from_value(event.payload.clone())?;
            if let Some(member) = room.members.get_mut(&payload.member) {
                member.role = payload.role;
                member.last_event_seq = Some(record.seq);
                if payload.member == *active_agent {
                    inbox.push(inbox_from_item(
                        InboxKind::RoomRoleChanged,
                        InboxPriority::Normal,
                        item,
                        "role_changed",
                        false,
                    ));
                }
            }
        }
        event_type::ROOM_CLOSE => {
            room.room.status = RoomState::Ended;
            inbox.push(inbox_from_item(
                InboxKind::RoomStateChanged,
                InboxPriority::Normal,
                item,
                "room_closed",
                false,
            ));
        }
        event_type::ROOM_CANCEL => {
            room.room.status = RoomState::Cancelled;
            inbox.push(inbox_from_item(
                InboxKind::RoomStateChanged,
                InboxPriority::Normal,
                item,
                "room_cancelled",
                false,
            ));
        }
        event_type::TYPE_DEFINE => {
            if let Ok(TypeDeclaration::Def(def)) =
                serde_json::from_value::<TypeDeclaration>(event.payload.clone())
            {
                room.room.types.retain(|existing| existing.name != def.name);
                room.room.types.push(def);
                inbox.push(inbox_from_item(
                    InboxKind::RoomStateChanged,
                    InboxPriority::Normal,
                    item,
                    "type_registry_changed",
                    false,
                ));
            }
        }
        event_type::ROOM_JOIN_REVIEW => {
            let payload: RoomJoinReviewPayload = serde_json::from_value(event.payload.clone())?;
            if payload.request.applicant == *active_agent
                && payload.decision == JoinDecision::Approve
            {
                inbox.push(inbox_from_item(
                    InboxKind::RoomJoinApproved,
                    InboxPriority::High,
                    item,
                    "join_approved",
                    true,
                ));
            }
        }
        event_type::MESSAGE_CREATE => {
            if item.mentions.contains(active_agent) {
                inbox.push(inbox_from_item(
                    InboxKind::RoomMention,
                    InboxPriority::High,
                    item,
                    "mentioned",
                    true,
                ));
            } else if event.actor != *active_agent {
                inbox.push(inbox_from_item(
                    InboxKind::RoomMessageNew,
                    InboxPriority::Normal,
                    item,
                    "new_message",
                    false,
                ));
            }
        }
        "turn.update" => {
            if let Some(turn) = active_turn_from_item(item) {
                let assigned_to_self = turn.speaker == *active_agent;
                room.active_turn = Some(turn);
                if assigned_to_self {
                    inbox.push(inbox_from_item(
                        InboxKind::RoomTurnAssigned,
                        InboxPriority::High,
                        item,
                        "turn_assigned",
                        true,
                    ));
                }
            }
        }
        "steer.create" => {
            if steer_targets_agent(&event.payload, active_agent) {
                inbox.push(inbox_from_item(
                    InboxKind::RoomSteer,
                    InboxPriority::High,
                    item,
                    "steer",
                    true,
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

fn active_turn_from_item(item: &TimelineItem) -> Option<ActiveTurn> {
    let speaker = item.payload.get("speaker")?.as_str()?.parse().ok()?;
    let turn_id = item.payload.get("turn_id").map(|value| match value {
        Value::String(value) => value.clone(),
        other => other.to_string(),
    })?;
    let instruction = item
        .payload
        .get("intent")
        .or_else(|| item.payload.get("topic"))
        .or_else(|| item.payload.get("reason"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Some(ActiveTurn {
        turn_id,
        speaker,
        assigned_seq: item.seq,
        expires_at: item.payload.get("expires_at").and_then(Value::as_i64),
        instruction,
        source_event_id: item.event_id.clone(),
    })
}

fn steer_targets_agent(payload: &Value, active_agent: &AgentId) -> bool {
    payload
        .get("target")
        .and_then(Value::as_str)
        .map(|target| target == active_agent.as_str())
        .unwrap_or(true)
}

fn inbox_from_item(
    kind: InboxKind,
    priority: InboxPriority,
    item: &TimelineItem,
    reason: &str,
    requires_response: bool,
) -> InboxItem {
    let suggested_tools = if requires_response {
        vec![TOOL_ROOM_SEND_MESSAGE.to_owned()]
    } else {
        Vec::new()
    };
    InboxItem {
        id: format!(
            "{}:{}:{}:{}",
            item.room_id,
            serde_json::to_value(&kind)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| "room.event".to_owned()),
            item.seq,
            item.event_id
        ),
        kind,
        priority,
        room_id: Some(item.room_id.clone()),
        seq: Some(item.seq),
        event_id: Some(item.event_id.clone()),
        actor: Some(item.actor.clone()),
        created_at: item.received_at,
        requires_response,
        deadline: None,
        reason: reason.to_owned(),
        suggested_tools,
        message: Some(json!({ "summary": item.summary })),
    }
}

fn inbox_entry_ready(entry: &InboxEntry, now_ms: i64) -> bool {
    match entry.state {
        InboxEntryState::Pending => true,
        InboxEntryState::Deferred(until) => until <= now_ms,
        InboxEntryState::Claimed | InboxEntryState::Acknowledged => false,
    }
}

fn summarize_payload(event_type: &str, payload: &Value) -> String {
    if event_type == event_type::MESSAGE_CREATE {
        if let Some(content) = payload.get("content") {
            return match content {
                Value::String(text) => text.chars().take(160).collect(),
                other => other.to_string().chars().take(160).collect(),
            };
        }
    }
    payload
        .get("instruction")
        .or_else(|| payload.get("intent"))
        .or_else(|| payload.get("reason"))
        .and_then(Value::as_str)
        .map(|text| text.chars().take(160).collect())
        .unwrap_or_else(|| event_type.to_owned())
}

fn timeline_kind(event_type: &str) -> String {
    if event_type == event_type::MESSAGE_CREATE {
        "message".to_owned()
    } else if event_type.starts_with("room.") {
        "room".to_owned()
    } else if event_type == "turn.update" || event_type.ends_with(".update") {
        "control".to_owned()
    } else if event_type.ends_with(".create") {
        "signal".to_owned()
    } else {
        "event".to_owned()
    }
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
        username: profile.username.clone(),
        description: profile.description.clone(),
        avatar_url: profile.avatar_url.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discourse::{
        build_server_record, event_type, room_create_event, MessageCreatePayload,
        RoomCreatePayload, Visibility,
    };
    use crate::profile::materialize_profile;

    fn signer(byte: u8) -> AgentSigner {
        AgentSigner::from_seed([byte; 32])
    }

    fn room_response(room_id: &str, signer: &AgentSigner) -> RoomResponse {
        let envelope = signer
            .sign_event(room_create_event(
                signer.agent_id(),
                100,
                1,
                RoomCreatePayload::new("Room", Visibility::Public, 1, 2),
            ))
            .unwrap();
        RoomResponse {
            id: room_id.to_owned(),
            status: RoomState::Active,
            url: format!("https://api.example.test/v1/rooms/{room_id}"),
            topic: Some("Room".to_owned()),
            agenda: None,
            guidance: None,
            visibility: Some(Visibility::Public),
            start_time: Some(1),
            end_time: Some(2),
            tags: Vec::new(),
            language: None,
            policy: None,
            types: Vec::new(),
            seq: 1,
            pre_hash: None,
            hash: "room-create-head".to_owned(),
            received_at: 100,
            head: Some(crate::discourse::RoomHead {
                seq: 1,
                hash: "room-create-head".to_owned(),
            }),
            envelope: Some(envelope),
        }
    }

    #[test]
    fn standard_tool_definitions_include_agent_facing_tools() {
        let tools = standard_tool_definitions();
        let names = tools
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>();
        assert!(names.contains(&TOOL_ROOM_MEMBERS_LIST));
        assert!(names.contains(&TOOL_INBOX_NEXT));
        assert!(names.contains(&TOOL_DRAFTS_LIST));
        assert!(names.contains(&TOOL_ROOM_JOIN));
        assert!(!names.contains(&TOOL_ROOM_JOIN_REQUEST));
        assert!(names.contains(&TOOL_ROOM_SEND_MESSAGE));
        assert!(
            tools
                .iter()
                .find(|tool| tool.name == TOOL_ROOM_MEMBERS_LIST)
                .unwrap()
                .annotations
                .read_only_hint
        );
    }

    #[test]
    fn observed_hosts_do_not_bypass_allowlist_for_signing() {
        let active = signer(1);
        let creator = signer(5);
        let mut connector = LocalConnector::new(active);
        connector.accept_room_response(
            "https://untrusted.example.test",
            room_response("room1", &creator),
        );

        assert_eq!(
            connector
                .state
                .hosts
                .get("https://untrusted.example.test")
                .unwrap()
                .allowed,
            false
        );
        let result = connector.sign_room_event(
            event_type::MESSAGE_CREATE,
            "room1",
            None,
            None,
            Vec::new(),
            MessageCreatePayload::text("hi"),
        );
        assert!(matches!(result, Err(SdkError::PermissionDenied)));
    }

    #[test]
    fn room_views_fall_back_to_room_create_payload_metadata() {
        let active = signer(1);
        let creator = signer(5);
        let mut connector = LocalConnector::new(active);
        let mut room = room_response("room1", &creator);
        let payload = &mut room.envelope.as_mut().unwrap().event.payload;
        payload.agenda = Some("Review the proposal".to_owned());
        payload.guidance = Some("Stay concise".to_owned());
        payload.tags = vec!["review".to_owned()];
        payload.language = Some("en".to_owned());
        room.topic = None;
        room.agenda = None;
        room.guidance = None;
        room.visibility = None;
        room.start_time = None;
        room.end_time = None;
        room.tags.clear();
        room.language = None;

        connector.observe_room("https://api.example.test", room);
        let room = connector.local_room("room1").unwrap();
        let view = connector.room_state_view(room);
        let summary = connector.summary_for_room(room);

        assert_eq!(view.topic.as_deref(), Some("Room"));
        assert_eq!(view.agenda.as_deref(), Some("Review the proposal"));
        assert_eq!(view.guidance.as_deref(), Some("Stay concise"));
        assert_eq!(view.visibility, Some(Visibility::Public));
        assert_eq!(view.start_time, Some(1));
        assert_eq!(view.end_time, Some(2));
        assert_eq!(view.tags, vec!["review"]);
        assert_eq!(view.language.as_deref(), Some("en"));
        assert_eq!(summary.topic.as_deref(), Some("Room"));
        assert_eq!(summary.tags, vec!["review"]);
    }

    #[test]
    fn applies_room_records_into_members_timeline_and_inbox() {
        let active = signer(1);
        let speaker = signer(2);
        let creator = signer(5);
        let mut connector = LocalConnector::new(active);
        connector.add_host(AgentProtocolsHost {
            host: "https://api.example.test".to_owned(),
            label: None,
            allowed: true,
            features: Vec::new(),
            profile_service: None,
            last_checked_at: None,
        });
        connector
            .accept_room_response("https://api.example.test", room_response("room1", &creator));

        let join_envelope = speaker
            .sign_event(discourse_event(
                event_type::ROOM_JOIN,
                speaker.agent_id(),
                110,
                1,
                "room1",
                1,
                "room-create-head",
                RoomJoinPayload {
                    request_id: Some("jr1".to_owned()),
                    role: Role::Speaker,
                    perspective: None,
                },
            ))
            .unwrap();
        let join = build_server_record(
            "room1",
            2,
            Some("room-create-head".to_owned()),
            111,
            join_envelope,
        )
        .unwrap();
        connector
            .apply_record(typed_record_to_value(join).unwrap())
            .unwrap();

        let message = MessageCreatePayload::text("please review this");
        let message_base_hash = connector
            .local_room("room1")
            .unwrap()
            .head_hash
            .clone()
            .unwrap();
        let message_envelope = speaker
            .sign_event(
                discourse_event(
                    event_type::MESSAGE_CREATE,
                    speaker.agent_id(),
                    120,
                    2,
                    "room1",
                    2,
                    message_base_hash.clone(),
                    message,
                )
                .with_mention(connector.agent_id()),
            )
            .unwrap();
        let message =
            build_server_record("room1", 3, Some(message_base_hash), 121, message_envelope)
                .unwrap();
        connector
            .apply_record(typed_record_to_value(message).unwrap())
            .unwrap();

        let members = connector
            .room_members_list(RoomMembersListInput {
                room_id: "room1".to_owned(),
                status: Some(RoomMemberStatus::Active),
                role: None,
                include_profiles: false,
                limit: None,
                cursor: None,
            })
            .unwrap();
        assert_eq!(members["members"].as_array().unwrap().len(), 2);

        let inbox = connector
            .inbox_next(InboxNextInput {
                room_id: Some("room1".to_owned()),
                kinds: Some(vec!["room.mention".to_owned()]),
                limit: None,
                wait_ms: None,
                claim: true,
            })
            .unwrap();
        assert_eq!(inbox["items"].as_array().unwrap().len(), 1);
        assert_eq!(inbox["items"][0]["kind"], "room.mention");
        assert_eq!(inbox["pending_count"], 0);
    }

    #[test]
    fn room_head_mismatch_holds_message_draft_before_network_submit() {
        let active = signer(1);
        let speaker = signer(2);
        let creator = signer(5);
        let mut connector = LocalConnector::new(active);
        connector
            .accept_room_response("https://api.example.test", room_response("room1", &creator));

        let message = MessageCreatePayload::text("new context");
        let message_envelope = speaker
            .sign_event(discourse_event(
                event_type::MESSAGE_CREATE,
                speaker.agent_id(),
                120,
                1,
                "room1",
                1,
                "room-create-head",
                message,
            ))
            .unwrap();
        let message = build_server_record(
            "room1",
            2,
            Some("room-create-head".to_owned()),
            121,
            message_envelope,
        )
        .unwrap();
        connector
            .apply_record(typed_record_to_value(message).unwrap())
            .unwrap();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime
            .block_on(connector.room_send_message(RoomSendMessageInput {
                room_id: "room1".to_owned(),
                content: "answer based on old context".to_owned(),
                content_type: None,
                mentions: Vec::new(),
                references: Vec::new(),
                extra: BTreeMap::new(),
                base_seq: Some(1),
                base_hash: Some("room-create-head".to_owned()),
                on_head_mismatch: HeadMismatchPolicy::Hold,
            }))
            .unwrap();

        assert_eq!(result["status"], "held");
        assert_eq!(result["draft"]["kind"], "message");
        assert_eq!(result["draft"]["base_seq"], 1);
        assert_eq!(result["changes"].as_array().unwrap().len(), 1);
        assert_eq!(connector.state.drafts.len(), 1);

        let draft_id = result["draft"]["id"].as_str().unwrap().to_owned();
        let drafts = connector
            .drafts_list(DraftsListInput {
                room_id: Some("room1".to_owned()),
                limit: None,
                cursor: None,
            })
            .unwrap();
        assert_eq!(drafts["drafts"].as_array().unwrap().len(), 1);

        let draft = connector
            .draft_get(DraftGetInput {
                draft_id: draft_id.clone(),
            })
            .unwrap();
        assert_eq!(draft["changes"].as_array().unwrap().len(), 1);

        let dropped = connector.draft_drop(DraftDropInput { draft_id }).unwrap();
        assert_eq!(dropped["status"], "dropped");
        assert_eq!(connector.state.drafts.len(), 0);
    }

    #[test]
    fn signal_records_do_not_advance_room_head() {
        let active = signer(1);
        let speaker = signer(2);
        let creator = signer(5);
        let mut connector = LocalConnector::new(active);
        let mut room = room_response("room1", &creator);
        room.types.push(TypeDef {
            name: "reaction.create".to_owned(),
            kind: crate::discourse::TypeKind::Signal,
            title: "Reaction".to_owned(),
            description: None,
            schema: json!({"type": "object"}),
            roles: None,
            instructions: None,
            version: None,
            status: None,
            rate_hint: None,
            max_payload_hint: None,
            extra: BTreeMap::new(),
        });
        connector.accept_room_response("https://api.example.test", room);

        let signal_envelope = speaker
            .sign_event(discourse_event(
                "reaction.create",
                speaker.agent_id(),
                120,
                1,
                "room1",
                1,
                "room-create-head",
                json!({"emoji": "+1"}),
            ))
            .unwrap();
        let signal = build_server_record(
            "room1",
            2,
            Some("room-create-head".to_owned()),
            121,
            signal_envelope,
        )
        .unwrap();
        connector
            .apply_record(typed_record_to_value(signal).unwrap())
            .unwrap();

        let sync = connector.sync_state("room1").unwrap();
        assert_eq!(sync.head_seq, 1);
        assert_eq!(sync.head_hash, "room-create-head");
        assert_eq!(sync.synced_seq, 2);
        assert_eq!(sync.remote_seq, 2);
    }

    #[test]
    fn rejects_non_signal_records_not_based_on_room_head() {
        let active = signer(1);
        let speaker = signer(2);
        let creator = signer(5);
        let mut connector = LocalConnector::new(active);
        let mut room = room_response("room1", &creator);
        room.types.push(TypeDef {
            name: "reaction.create".to_owned(),
            kind: crate::discourse::TypeKind::Signal,
            title: "Reaction".to_owned(),
            description: None,
            schema: json!({"type": "object"}),
            roles: None,
            instructions: None,
            version: None,
            status: None,
            rate_hint: None,
            max_payload_hint: None,
            extra: BTreeMap::new(),
        });
        connector.accept_room_response("https://api.example.test", room);

        let signal_envelope = speaker
            .sign_event(discourse_event(
                "reaction.create",
                speaker.agent_id(),
                120,
                1,
                "room1",
                1,
                "room-create-head",
                json!({"emoji": "+1"}),
            ))
            .unwrap();
        let signal = build_server_record(
            "room1",
            2,
            Some("room-create-head".to_owned()),
            121,
            signal_envelope,
        )
        .unwrap();
        let signal_hash = signal.hash.clone();
        connector
            .apply_record(typed_record_to_value(signal).unwrap())
            .unwrap();

        let stale_message_envelope = speaker
            .sign_event(discourse_event(
                event_type::MESSAGE_CREATE,
                speaker.agent_id(),
                122,
                2,
                "room1",
                2,
                signal_hash.clone(),
                MessageCreatePayload::text("based on signal, not room head"),
            ))
            .unwrap();
        let stale_message =
            build_server_record("room1", 3, Some(signal_hash), 123, stale_message_envelope)
                .unwrap();

        let err = connector
            .apply_record(typed_record_to_value(stale_message).unwrap())
            .unwrap_err();
        assert!(err.to_string().contains("must match current room head"));
    }

    #[test]
    fn signs_profile_update_without_exposing_private_key() {
        let signer = signer(3);
        let mut connector = LocalConnector::new(signer);
        let payload = ProfileUpdatePayload::new(connector.agent_id(), "Agent");
        let envelope = connector.sign_profile_update(payload).unwrap();
        let profile = materialize_profile(&envelope).unwrap();
        assert_eq!(profile.name, "Agent");
        assert_eq!(envelope.event.nonce, 1);
    }

    #[test]
    fn payload_with_references_stores_references_under_extra() {
        let payload =
            payload_with_references(json!({"instruction": "answer"}), vec!["abc".to_owned()])
                .unwrap();
        assert_eq!(payload["extra"]["references"][0], "abc");
    }
}
