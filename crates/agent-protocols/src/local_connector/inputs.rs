//! Deserialization shapes for each local connector tool call. They are the
//! parse boundary between untyped tool JSON and the typed handlers on
//! [`super::LocalConnector`]; nothing outside the crate constructs them.

use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

use crate::delegation::DelegationStatus;
use crate::discourse::{JoinDecision, Role, TypeDeclaration, Visibility};
use crate::identity::AgentId;

use super::views::{DraftAction, HeadMismatchPolicy, RoomMemberStatus};

#[derive(Deserialize)]
pub(crate) struct PrincipalResolveInput {
    pub url: String,
}

#[derive(Deserialize)]
pub(crate) struct DelegationCheckInput {
    pub principal_id: String,
    #[serde(default)]
    pub subject: Option<AgentId>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub status: Option<DelegationStatus>,
}

#[derive(Deserialize)]
pub(crate) struct DelegationsListInput {
    pub delegation_service: String,
    #[serde(default)]
    pub status: Option<DelegationStatus>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Deserialize)]
pub(crate) struct DelegationGrantInput {
    pub delegation_service: String,
    pub id: String,
    pub principal_id: String,
    pub subject: AgentId,
    #[serde(default)]
    pub relationship: Option<String>,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub constraints: BTreeMap<String, Value>,
    #[serde(default)]
    pub not_before: Option<i64>,
    #[serde(default)]
    pub expires_at: Option<i64>,
}

#[derive(Deserialize)]
pub(crate) struct DelegationRevokeInput {
    pub delegation_service: String,
    pub id: String,
    pub principal_id: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct RoomsSearchInput {
    pub host: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub keyword: Option<String>,
    #[serde(default)]
    pub creator: Option<String>,
    #[serde(default)]
    pub starts_after: Option<i64>,
    #[serde(default)]
    pub ends_before: Option<i64>,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RoomsListMembership {
    Member,
    Creator,
    Moderator,
    Pending,
    All,
}

#[derive(Deserialize)]
pub(crate) struct RoomsListInput {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub membership: Option<RoomsListMembership>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct RoomOpenInput {
    pub host: String,
    pub room_id: String,
    #[serde(default)]
    pub subscribe: Option<bool>,
    #[serde(default)]
    pub refresh: bool,
}

#[derive(Deserialize)]
pub(crate) struct RoomStateInput {
    pub room_id: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub refresh: bool,
    #[serde(default)]
    pub include_types: bool,
}

#[derive(Deserialize)]
pub(crate) struct RoomMembersListInput {
    pub room_id: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub status: Option<RoomMemberStatus>,
    #[serde(default)]
    pub role: Option<Role>,
    #[serde(default)]
    pub include_profiles: bool,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct RoomMemberGetInput {
    pub room_id: String,
    #[serde(default)]
    pub host: Option<String>,
    pub agent_id: AgentId,
    #[serde(default)]
    pub include_profile: bool,
    #[serde(default)]
    pub include_recent_activity: bool,
}

#[derive(Deserialize)]
pub(crate) struct AgentStatusListInput {
    pub room_id: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub refresh: bool,
}

#[derive(Deserialize)]
pub(crate) struct AgentStatusGetInput {
    pub room_id: String,
    #[serde(default)]
    pub host: Option<String>,
    pub agent_id: AgentId,
    #[serde(default)]
    pub refresh: bool,
}

#[derive(Deserialize)]
pub(crate) struct AgentStatusSetInput {
    pub room_id: String,
    #[serde(default)]
    pub host: Option<String>,
    pub state: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub seen_seq: Option<u64>,
    #[serde(default)]
    pub seen_hash: Option<String>,
    #[serde(default)]
    pub claim_id: Option<String>,
    #[serde(default)]
    pub activity: Option<String>,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
pub(crate) struct AgentStatusClearInput {
    pub room_id: String,
    #[serde(default)]
    pub host: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct RoomTimelineInput {
    pub room_id: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub after_seq: Option<u64>,
    #[serde(default)]
    pub before_seq: Option<u64>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub types: Option<Vec<String>>,
    #[serde(default)]
    pub actors: Option<Vec<AgentId>>,
    #[serde(default)]
    pub unread_only: bool,
    #[serde(default)]
    pub refresh: bool,
    #[serde(default)]
    pub include_records: bool,
}

#[derive(Deserialize)]
pub(crate) struct RoomUnreadInput {
    pub room_id: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub mark_read: bool,
}

#[derive(Deserialize)]
pub(crate) struct RoomMarkReadInput {
    pub room_id: String,
    #[serde(default)]
    pub host: Option<String>,
    pub through_seq: u64,
}

#[derive(Deserialize)]
pub(crate) struct InboxNextInput {
    #[serde(default)]
    pub room_id: Option<String>,
    #[serde(default)]
    pub kinds: Option<Vec<String>>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub wait_ms: Option<u64>,
    #[serde(default)]
    pub claim: bool,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InboxAckAction {
    Handled,
    Dismissed,
    Defer,
}

#[derive(Deserialize)]
pub(crate) struct InboxAckInput {
    pub ids: Vec<String>,
    pub action: InboxAckAction,
    #[serde(default)]
    pub defer_until: Option<i64>,
}

#[derive(Deserialize)]
pub(crate) struct DraftsListInput {
    #[serde(default)]
    pub room_id: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct DraftGetInput {
    pub draft_id: String,
}

#[derive(Deserialize)]
pub(crate) struct DraftCommitInput {
    pub draft_id: String,
    pub action: DraftAction,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub mentions: Option<Vec<AgentId>>,
    #[serde(default)]
    pub references: Option<Vec<String>>,
    #[serde(default)]
    pub extra: Option<BTreeMap<String, Value>>,
    #[serde(rename = "type", default)]
    pub event_type: Option<String>,
    #[serde(default)]
    pub payload: Option<Value>,
    #[serde(default)]
    pub base_seq: Option<u64>,
    #[serde(default)]
    pub base_hash: Option<String>,
    #[serde(default)]
    pub on_head_mismatch: HeadMismatchPolicy,
}

#[derive(Deserialize)]
pub(crate) struct DraftDropInput {
    pub draft_id: String,
}

#[derive(Deserialize)]
pub(crate) struct ProfileUpdateInput {
    pub profile_service: String,
    pub profile: Value,
}

#[derive(Deserialize)]
pub(crate) struct RoomCreateInput {
    pub host: String,
    pub topic: String,
    pub visibility: Visibility,
    pub start_time: i64,
    pub end_time: i64,
    #[serde(default)]
    pub agenda: Option<String>,
    #[serde(default)]
    pub guidance: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub policy: Option<crate::discourse::RoomPolicy>,
    #[serde(default)]
    pub types: Vec<TypeDeclaration>,
}

#[derive(Deserialize)]
pub(crate) struct RoomJoinInput {
    #[serde(default)]
    pub host: Option<String>,
    pub room_id: String,
    pub role: Role,
    #[serde(default)]
    pub perspective: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
pub(crate) struct RoomJoinRequestToolInput {
    pub host: String,
    pub room_id: String,
    pub role: Role,
    #[serde(default)]
    pub perspective: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
pub(crate) struct RoomJoinWhenApprovedInput {
    pub room_id: String,
    #[serde(default)]
    pub host: Option<String>,
    pub request_id: String,
}

#[derive(Deserialize)]
pub(crate) struct RoomLeaveInput {
    pub room_id: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Clone, Deserialize, Debug)]
pub(crate) struct RoomSendMessageInput {
    pub room_id: String,
    #[serde(default)]
    pub host: Option<String>,
    pub content: String,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub mentions: Vec<AgentId>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub extra: BTreeMap<String, Value>,
    #[serde(default)]
    pub base_seq: Option<u64>,
    #[serde(default)]
    pub base_hash: Option<String>,
    #[serde(default)]
    pub on_head_mismatch: HeadMismatchPolicy,
}

#[derive(Clone, Deserialize, Debug)]
pub(crate) struct RoomSubmitEventInput {
    pub room_id: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(rename = "type")]
    pub event_type: String,
    pub payload: Value,
    #[serde(default)]
    pub mentions: Vec<AgentId>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub base_seq: Option<u64>,
    #[serde(default)]
    pub base_hash: Option<String>,
    #[serde(default)]
    pub on_head_mismatch: HeadMismatchPolicy,
}

#[derive(Deserialize)]
pub(crate) struct JoinRequestsListInput {
    pub room_id: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct JoinRequestReviewInput {
    pub room_id: String,
    #[serde(default)]
    pub host: Option<String>,
    pub request_id: String,
    pub decision: JoinDecision,
    #[serde(default)]
    pub role: Option<Role>,
    #[serde(default)]
    pub reason: Option<String>,
}
