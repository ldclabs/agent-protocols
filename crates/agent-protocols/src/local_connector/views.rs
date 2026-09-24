//! Structured result types returned by the local connector, together with the
//! pure projections that build them: an [`ArchiveRecord`] into a [`TimelineItem`]
//! and a [`RoomResponse`] into its display metadata. These are the shapes a
//! caller reads back from [`super::LocalConnector`]; they carry no signing keys
//! and no live network handles.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::discourse::{
    event_type, record_class, ArchiveRecord, RecordClass, Role, RoomCreatePayload, RoomResponse,
    RoomState, TypeDef, Visibility,
};
use crate::identity::AgentId;

pub use crate::delegation::DelegationVerdict;

/// Connector sync marker for one room. `head_seq` / `head_hash` are the latest
/// locally verified head-advancing record per ADP Section 5.1;
/// `presented_seq` / `presented_hash` are the latest head the agent has been
/// shown with every record before it, the default write base.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncState {
    pub host: String,
    pub room_id: String,
    pub head_seq: u64,
    pub head_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented_hash: Option<String>,
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
    /// The record's ADP class: freshness class for built-ins, registry kind for custom types.
    pub kind: RecordClass,
    /// Absent on redacted records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<AgentId>,
    /// Absent on redacted records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
    pub accepted_at: i64,
    /// Informative excerpt; its derivation is connector-defined.
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mentions: Vec<AgentId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    /// Absent on redacted records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub redacted: bool,
}

impl TimelineItem {
    /// Projects a record into a timeline item. `types` is the room's
    /// materialized registry; a custom type missing from it is reported as `message`.
    pub fn from_record(record: &ArchiveRecord, types: &[TypeDef]) -> Self {
        let signed = match record {
            ArchiveRecord::Redacted(redacted) => {
                let event_type = redacted.envelope.kind.clone();
                return Self {
                    room_id: redacted.room_id.clone(),
                    seq: redacted.seq,
                    event_id: redacted.envelope.hash.clone(),
                    kind: record_class(&event_type, types).unwrap_or(RecordClass::Message),
                    event_type,
                    actor: None,
                    created_at: None,
                    accepted_at: redacted.accepted_at,
                    summary: "[redacted]".to_owned(),
                    content_type: None,
                    content: None,
                    mentions: Vec::new(),
                    references: Vec::new(),
                    payload: None,
                    redacted: true,
                };
            }
            ArchiveRecord::Signed(signed) => signed,
        };
        let event = &signed.envelope.event;
        let payload = &event.payload;
        let (content_type, content) = if event.kind == event_type::MESSAGE_CREATE {
            match payload.get("content_type").and_then(Value::as_str) {
                Some(content_type) => (
                    Some(content_type.to_owned()),
                    payload.get("content").cloned(),
                ),
                None => (None, None),
            }
        } else {
            (None, None)
        };
        let references = payload
            .get("references")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(|value| value.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            room_id: signed.room_id.clone(),
            seq: signed.seq,
            event_id: signed.envelope.hash.clone(),
            event_type: event.kind.clone(),
            kind: record_class(&event.kind, types).unwrap_or(RecordClass::Message),
            actor: Some(event.actor.clone()),
            created_at: Some(event.created_at),
            accepted_at: signed.accepted_at,
            summary: summarize_payload(&event.kind, payload),
            content_type,
            content,
            mentions: event.mentions().to_vec(),
            references,
            payload: Some(payload.clone()),
            redacted: false,
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

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HeadMismatchPolicy {
    #[default]
    Hold,
    Reject,
    SendAnyway,
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
    Send,
    Drop,
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

/// The latest accepted `turn.update`; fields are copied from its payload.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ActiveTurn {
    pub turn_id: u64,
    pub speaker: AgentId,
    pub assigned_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
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
            .and_then(|payload| payload.tags.clone())
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

/// Maximum summary length in Unicode code points.
pub const SUMMARY_MAX_CHARS: usize = 160;
const SUMMARY_FIELDS: [&str; 7] = [
    "summary",
    "title",
    "instruction",
    "intent",
    "question",
    "reason",
    "state",
];

/// Informative summary shared by the SDK connectors: a string message body, or
/// the first non-empty summary-like payload field, truncated to 160 code points
/// with a trailing ellipsis; otherwise the event type.
pub fn summarize_payload(event_type: &str, payload: &Value) -> String {
    if event_type == event_type::MESSAGE_CREATE
        && payload.get("content_type").is_some_and(Value::is_string)
    {
        if let Some(content) = payload.get("content").and_then(Value::as_str) {
            if !content.trim().is_empty() {
                return truncate(content, SUMMARY_MAX_CHARS);
            }
        }
    }
    SUMMARY_FIELDS
        .iter()
        .filter_map(|field| payload.get(*field).and_then(Value::as_str))
        .find(|value| !value.trim().is_empty())
        .map(|value| truncate(value, SUMMARY_MAX_CHARS))
        .unwrap_or_else(|| event_type.to_owned())
}

fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }
    let mut truncated: String = value.chars().take(max_chars - 1).collect();
    truncated.push('…');
    truncated
}
