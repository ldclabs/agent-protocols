//! Structured result types returned by the local connector, together with the
//! pure projections that build them: a [`ServerRecord`] into a [`TimelineItem`]
//! and a [`RoomResponse`] into its display metadata. These are the shapes a
//! caller reads back from [`super::LocalConnector`]; they carry no signing keys
//! and no live network handles.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::discourse::{
    event_type, MessageCreatePayload, Role, RoomCreatePayload, RoomResponse, RoomState, ServerRecord,
    TypeDef, Visibility,
};
use crate::identity::AgentId;

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

/// `Removed` and `Banned` are produced by accepted `room.member.remove` records.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RoomMemberStatus {
    Active,
    Left,
    Removed,
    Banned,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoomMemberProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
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

impl TimelineItem {
    pub(crate) fn from_record(record: &ServerRecord) -> Self {
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
    #[serde(rename = "room.member.removed")]
    RoomMemberRemoved,
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

fn room_create_payload(room: &RoomResponse) -> Option<&RoomCreatePayload> {
    room.envelope
        .as_ref()
        .map(|envelope| &envelope.event.payload)
}

pub(crate) fn room_topic(room: &RoomResponse) -> Option<String> {
    room.topic
        .clone()
        .or_else(|| room_create_payload(room).map(|payload| payload.topic.clone()))
}

pub(crate) fn room_agenda(room: &RoomResponse) -> Option<String> {
    room.agenda
        .clone()
        .or_else(|| room_create_payload(room).and_then(|payload| payload.agenda.clone()))
}

pub(crate) fn room_guidance(room: &RoomResponse) -> Option<String> {
    room.guidance
        .clone()
        .or_else(|| room_create_payload(room).and_then(|payload| payload.guidance.clone()))
}

pub(crate) fn room_visibility(room: &RoomResponse) -> Option<Visibility> {
    room.visibility
        .or_else(|| room_create_payload(room).map(|payload| payload.visibility))
}

pub(crate) fn room_start_time(room: &RoomResponse) -> Option<i64> {
    room.start_time
        .or_else(|| room_create_payload(room).map(|payload| payload.start_time))
}

pub(crate) fn room_end_time(room: &RoomResponse) -> Option<i64> {
    room.end_time
        .or_else(|| room_create_payload(room).map(|payload| payload.end_time))
}

pub(crate) fn room_tags(room: &RoomResponse) -> Vec<String> {
    if room.tags.is_empty() {
        room_create_payload(room)
            .map(|payload| payload.tags.clone())
            .unwrap_or_default()
    } else {
        room.tags.clone()
    }
}

pub(crate) fn room_language(room: &RoomResponse) -> Option<String> {
    room.language
        .clone()
        .or_else(|| room_create_payload(room).and_then(|payload| payload.language.clone()))
}

pub(crate) fn room_policy(room: &RoomResponse) -> Option<crate::discourse::RoomPolicy> {
    room.policy
        .clone()
        .or_else(|| room_create_payload(room).and_then(|payload| payload.policy.clone()))
}

pub(crate) fn room_response_head(room: &RoomResponse) -> (u64, String) {
    room.head
        .as_ref()
        .map(|head| (head.seq, head.hash.clone()))
        .unwrap_or_else(|| (room.seq, room.hash.clone()))
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
