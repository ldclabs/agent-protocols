use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Result, SdkError};
use crate::identity::{verify_envelope, AgentId, Envelope, Event};

pub const PROTOCOL: &str = "agent-discourse/1.0";
pub const LEGACY_PROTOCOL: &str = "adp/1.0";

pub mod event_type {
    pub const ROOM_CREATE: &str = "room.create";
    pub const ROOM_JOIN: &str = "room.join";
    pub const ROOM_JOIN_REVIEW: &str = "room.join.review";
    pub const ROOM_LEAVE: &str = "room.leave";
    pub const ROOM_MEMBER_ROLE_UPDATE: &str = "room.member.role.update";
    pub const ROOM_CLOSE: &str = "room.close";
    pub const ROOM_CANCEL: &str = "room.cancel";
    pub const MESSAGE_CREATE: &str = "message.create";
    pub const REACTION_CREATE: &str = "reaction.create";
    pub const MESSAGE_PROPOSAL_CREATE: &str = "message.proposal.create";
    pub const MESSAGE_POLL_CREATE: &str = "message.poll.create";
    pub const MESSAGE_POLL_VOTE: &str = "message.poll.vote";
    pub const MESSAGE_RESOLUTION_CREATE: &str = "message.resolution.create";
    pub const SOURCE_ADD: &str = "source.add";
    pub const TURN_UPDATE: &str = "turn.update";
    pub const QUESTION_CREATE: &str = "question.create";
    pub const ROOM_STEER: &str = "room.steer";
    pub const MAP_UPDATE: &str = "map.update";
    pub const ARTIFACT_CREATE: &str = "artifact.create";
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RoomState {
    Scheduled,
    Active,
    Ended,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    Public,
    Restricted,
    Private,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TurnPolicy {
    Free,
    RoundRobin,
    ModeratorLed,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Moderator,
    Expert,
    Participant,
    Observer,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JoinRequestStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MessageIntent {
    Question,
    Answer,
    Clarification,
    Critique,
    Synthesis,
    FollowUp,
    Other,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MapOperation {
    UpsertNode,
    MoveNode,
    DeleteNode,
    MergeNodes,
    ReplaceSnapshot,
    MarkResolved,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RoomCreatePayload {
    pub topic: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agenda: Option<String>,
    pub visibility: Visibility,
    pub start_time: i64,
    pub end_time: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<RoomPolicy>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct RoomPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_policy: Option<TurnPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub moderator_agent_ids: Vec<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_participants: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observer_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observer_steering_allowed: Option<bool>,
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl RoomPolicy {
    pub fn new() -> Self {
        Self::default()
    }
}

impl RoomCreatePayload {
    pub fn new(
        topic: impl Into<String>,
        visibility: Visibility,
        start_time: i64,
        end_time: i64,
    ) -> Self {
        Self {
            topic: topic.into(),
            agenda: None,
            visibility,
            start_time,
            end_time,
            tags: Vec::new(),
            language: None,
            policy: None,
            extensions: BTreeMap::new(),
            extra: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerRecord<P = Value> {
    pub room_id: String,
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_hash: Option<String>,
    pub hash: String,
    pub received_at: i64,
    pub envelope: Envelope<P>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoomResponse {
    pub id: String,
    pub status: RoomState,
    pub url: String,
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_hash: Option<String>,
    pub hash: String,
    pub received_at: i64,
    pub envelope: Option<Envelope<RoomCreatePayload>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RoomJoinPayload {
    pub request_id: String,
    pub role: Role,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perspective: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RoomJoinRequestPayload {
    pub requested_role: Role,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perspective: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl RoomJoinRequestPayload {
    pub fn new(requested_role: Role) -> Self {
        Self {
            requested_role,
            perspective: None,
            reason: None,
            extra: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RoomJoinRequest {
    pub id: String,
    pub room_id: String,
    pub applicant: AgentId,
    pub requested_role: Role,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_role: Option<Role>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perspective: Option<String>,
    pub status: JoinRequestStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_reason: Option<String>,
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_by: Option<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JoinDecision {
    Approve,
    Reject,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoomJoinReviewPayload {
    pub request_id: String,
    pub member: AgentId,
    pub decision: JoinDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoomLeavePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoleUpdatePayload {
    pub member: AgentId,
    pub role: Role,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageCreatePayload {
    pub content_type: String,
    pub content: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

impl MessageCreatePayload {
    pub fn new(content_type: impl Into<String>, content: Value) -> Self {
        Self {
            content_type: content_type.into(),
            content,
            references: Vec::new(),
        }
    }

    pub fn text(text: impl Into<String>) -> Self {
        Self::new("text/plain", Value::String(text.into()))
    }

    pub fn markdown(markdown: impl Into<String>) -> Self {
        Self::new("text/markdown", Value::String(markdown.into()))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ReactionCreatePayload {
    pub event_id: String,
    pub reaction: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
}

impl ReactionCreatePayload {
    pub fn new(event_id: impl Into<String>, reaction: impl Into<String>) -> Self {
        Self {
            event_id: event_id.into(),
            reaction: reaction.into(),
            score: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SourceAddPayload {
    pub source_type: String,
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrieved_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub excerpt: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TurnUpdatePayload {
    pub turn_id: u64,
    pub speaker: AgentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<MessageIntent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct QuestionGeneratePayload {
    pub question: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_perspectives: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basis: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_event_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<f64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DiscourseSteerPayload {
    pub instruction: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<f64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MapNodeStatus {
    Open,
    Resolved,
    Closed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MapNode {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<MapNodeStatus>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_event_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub discussion_event_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<MapNode>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MapUpdatePayload {
    pub operation: MapOperation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<MapNode>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ArtifactCreatePayload {
    pub artifact_id: String,
    pub format: String,
    pub title: String,
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_event_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub discussion_event_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub map_event_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoomClosePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoomCancelPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileResolverMetadata {
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscourseProtocolDiscovery {
    pub protocol: String,
    pub host: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileResolverMetadata>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub endpoints: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MapSnapshotRef {
    pub event_id: String,
    pub digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ArtifactManifest {
    pub artifact_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub format: String,
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ArchiveManifest {
    pub protocol: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub host: String,
    pub room_id: String,
    pub url: String,
    pub generated_at: i64,
    pub event_count: u64,
    pub first_seq: u64,
    pub last_seq: u64,
    pub last_hash: String,
    pub events_sha3_256: String,
    pub archive_root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub map_snapshot: Option<MapSnapshotRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ArtifactManifest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discourse_trace_quality_score: Option<f64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub formats: BTreeMap<String, String>,
}

pub fn room_create_event(
    actor: AgentId,
    created_at: i64,
    nonce: u64,
    payload: RoomCreatePayload,
) -> Event<RoomCreatePayload> {
    Event::new(
        PROTOCOL,
        event_type::ROOM_CREATE,
        actor,
        created_at,
        nonce,
        payload,
    )
}

pub fn discourse_event<P>(
    kind: impl Into<String>,
    actor: AgentId,
    created_at: i64,
    nonce: u64,
    room_id: impl Into<String>,
    payload: P,
) -> Event<P> {
    Event::new(PROTOCOL, kind, actor, created_at, nonce, payload).with_room_id(room_id)
}

pub fn validate_discourse_envelope<P>(
    envelope: &Envelope<P>,
    accept_legacy_protocol: bool,
) -> Result<()>
where
    P: Serialize,
{
    verify_envelope(envelope)?;
    let protocol = envelope.event.protocol.as_str();
    let protocol_ok =
        protocol == PROTOCOL || (accept_legacy_protocol && protocol == LEGACY_PROTOCOL);
    if !protocol_ok {
        return Err(SdkError::InvalidEventProtocol {
            expected: PROTOCOL.to_owned(),
            actual: envelope.event.protocol.clone(),
        });
    }
    if event_requires_room_id(&envelope.event.kind) && envelope.event.room_id.is_none() {
        return Err(SdkError::MissingRoomId);
    }
    Ok(())
}

pub fn validate_room_path<P>(envelope: &Envelope<P>, path_room_id: &str) -> Result<()> {
    match envelope.event.room_id.as_deref() {
        Some(actual) if actual == path_room_id => Ok(()),
        Some(actual) => Err(SdkError::RoomIdMismatch {
            expected: path_room_id.to_owned(),
            actual: actual.to_owned(),
        }),
        None if envelope.event.kind == event_type::ROOM_CREATE => Ok(()),
        None => Err(SdkError::MissingRoomId),
    }
}

pub fn event_requires_room_id(event_type: &str) -> bool {
    event_type != event_type::ROOM_CREATE
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PermissionContext {
    pub role: Option<Role>,
    pub is_creator: bool,
    pub join_request_approved: bool,
    pub moderator_authorized: bool,
    pub expert_policy_allowed: bool,
    pub participant_policy_allowed: bool,
    pub observer_steering_allowed: bool,
    pub observer_poll_vote_allowed: bool,
}

impl PermissionContext {
    pub fn for_role(role: Role) -> Self {
        Self {
            role: Some(role),
            ..Self::default()
        }
    }

    pub fn creator(role: Option<Role>) -> Self {
        Self {
            role,
            is_creator: true,
            ..Self::default()
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StateWriteOptions {
    pub post_end_reaction_allowed: bool,
}

pub fn can_submit_event(event_type: &str, context: &PermissionContext) -> bool {
    if event_type == event_type::ROOM_CREATE {
        return true;
    }
    if event_type == event_type::ROOM_JOIN {
        return context.join_request_approved;
    }

    if context.is_creator {
        return is_known_event_type(event_type);
    }

    match context.role {
        Some(Role::Moderator) => moderator_can_submit(event_type, context.moderator_authorized),
        Some(Role::Expert) => speaker_can_submit(event_type, context.expert_policy_allowed),
        Some(Role::Participant) => {
            speaker_can_submit(event_type, context.participant_policy_allowed)
        }
        Some(Role::Observer) => observer_can_submit(event_type, context),
        None => false,
    }
}

pub fn can_write_in_state(event_type: &str, state: RoomState, options: StateWriteOptions) -> bool {
    match state {
        RoomState::Scheduled => matches!(
            event_type,
            event_type::ROOM_JOIN | event_type::ROOM_JOIN_REVIEW | event_type::ROOM_CANCEL
        ),
        RoomState::Active => {
            event_type != event_type::ROOM_CREATE && event_type != event_type::ROOM_CANCEL
        }
        RoomState::Ended => {
            options.post_end_reaction_allowed && event_type == event_type::REACTION_CREATE
        }
        RoomState::Cancelled => false,
    }
}

pub fn can_accept_room_write(
    event_type: &str,
    state: RoomState,
    permission: &PermissionContext,
    state_options: StateWriteOptions,
) -> bool {
    can_submit_event(event_type, permission) && can_write_in_state(event_type, state, state_options)
}

pub fn validate_room_write(
    event_type: &str,
    state: RoomState,
    permission: &PermissionContext,
    state_options: StateWriteOptions,
) -> Result<()> {
    if can_accept_room_write(event_type, state, permission, state_options) {
        Ok(())
    } else {
        Err(SdkError::PermissionDenied)
    }
}

fn moderator_can_submit(event_type: &str, moderator_authorized: bool) -> bool {
    matches!(
        event_type,
        event_type::ROOM_JOIN_REVIEW
            | event_type::ROOM_CLOSE
            | event_type::MESSAGE_CREATE
            | event_type::SOURCE_ADD
            | event_type::TURN_UPDATE
            | event_type::QUESTION_CREATE
            | event_type::ROOM_STEER
            | event_type::MAP_UPDATE
            | event_type::ARTIFACT_CREATE
            | event_type::MESSAGE_PROPOSAL_CREATE
            | event_type::MESSAGE_POLL_CREATE
            | event_type::MESSAGE_POLL_VOTE
            | event_type::MESSAGE_RESOLUTION_CREATE
            | event_type::REACTION_CREATE
            | event_type::ROOM_LEAVE
    ) || (moderator_authorized
        && matches!(
            event_type,
            event_type::ROOM_MEMBER_ROLE_UPDATE | event_type::ROOM_CANCEL
        ))
}

fn speaker_can_submit(event_type: &str, policy_allowed: bool) -> bool {
    matches!(
        event_type,
        event_type::MESSAGE_CREATE
            | event_type::SOURCE_ADD
            | event_type::ROOM_STEER
            | event_type::MESSAGE_PROPOSAL_CREATE
            | event_type::MESSAGE_POLL_CREATE
            | event_type::MESSAGE_POLL_VOTE
            | event_type::REACTION_CREATE
            | event_type::ROOM_LEAVE
    ) || (policy_allowed
        && matches!(
            event_type,
            event_type::QUESTION_CREATE
                | event_type::MAP_UPDATE
                | event_type::ARTIFACT_CREATE
                | event_type::MESSAGE_RESOLUTION_CREATE
        ))
}

fn observer_can_submit(event_type: &str, context: &PermissionContext) -> bool {
    matches!(
        event_type,
        event_type::REACTION_CREATE | event_type::ROOM_LEAVE
    ) || (context.observer_steering_allowed && event_type == event_type::ROOM_STEER)
        || (context.observer_poll_vote_allowed && event_type == event_type::MESSAGE_POLL_VOTE)
}

fn is_known_event_type(event_type: &str) -> bool {
    matches!(
        event_type,
        event_type::ROOM_CREATE
            | event_type::ROOM_JOIN
            | event_type::ROOM_JOIN_REVIEW
            | event_type::ROOM_LEAVE
            | event_type::ROOM_MEMBER_ROLE_UPDATE
            | event_type::ROOM_CLOSE
            | event_type::ROOM_CANCEL
            | event_type::MESSAGE_CREATE
            | event_type::REACTION_CREATE
            | event_type::MESSAGE_PROPOSAL_CREATE
            | event_type::MESSAGE_POLL_CREATE
            | event_type::MESSAGE_POLL_VOTE
            | event_type::MESSAGE_RESOLUTION_CREATE
            | event_type::SOURCE_ADD
            | event_type::TURN_UPDATE
            | event_type::QUESTION_CREATE
            | event_type::ROOM_STEER
            | event_type::MAP_UPDATE
            | event_type::ARTIFACT_CREATE
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentSigner;

    #[test]
    fn validates_room_create_without_room_id() {
        let signer = AgentSigner::from_seed([14; 32]);
        let payload = RoomCreatePayload::new("Research room", Visibility::Public, 1000, 2000);
        let event = Event::new(
            PROTOCOL,
            event_type::ROOM_CREATE,
            signer.agent_id(),
            100,
            1,
            payload,
        );
        let envelope = signer.sign_event(event).unwrap();

        validate_discourse_envelope(&envelope, false).unwrap();
        validate_room_path(&envelope, "d8ftedhpqhsusbg001tg").unwrap();
    }

    #[test]
    fn rejects_room_event_without_room_id() {
        let signer = AgentSigner::from_seed([15; 32]);
        let event = Event::new(
            PROTOCOL,
            event_type::MESSAGE_CREATE,
            signer.agent_id(),
            100,
            1,
            MessageCreatePayload::text("hello"),
        );
        let envelope = signer.sign_event(event).unwrap();

        assert!(matches!(
            validate_discourse_envelope(&envelope, false),
            Err(SdkError::MissingRoomId)
        ));
    }

    #[test]
    fn applies_permission_matrix() {
        let observer = PermissionContext::for_role(Role::Observer);
        assert!(can_submit_event(event_type::REACTION_CREATE, &observer));
        assert!(!can_submit_event(event_type::MESSAGE_CREATE, &observer));
        assert!(!can_submit_event(event_type::ROOM_JOIN, &observer));

        let approved_join = PermissionContext {
            join_request_approved: true,
            ..PermissionContext::default()
        };
        assert!(can_submit_event(event_type::ROOM_JOIN, &approved_join));

        let mut moderator = PermissionContext::for_role(Role::Moderator);
        assert!(can_submit_event(event_type::ROOM_JOIN_REVIEW, &moderator));
        assert!(!can_submit_event(event_type::ROOM_CANCEL, &moderator));
        moderator.moderator_authorized = true;
        assert!(can_submit_event(event_type::ROOM_CANCEL, &moderator));

        let participant = PermissionContext::for_role(Role::Participant);
        assert!(!can_submit_event(
            event_type::ROOM_JOIN_REVIEW,
            &participant
        ));
    }

    #[test]
    fn applies_state_restrictions() {
        let participant = PermissionContext::for_role(Role::Participant);
        assert!(can_accept_room_write(
            event_type::MESSAGE_CREATE,
            RoomState::Active,
            &participant,
            StateWriteOptions::default()
        ));
        assert!(!can_accept_room_write(
            event_type::MESSAGE_CREATE,
            RoomState::Scheduled,
            &participant,
            StateWriteOptions::default()
        ));
        assert!(!can_accept_room_write(
            event_type::REACTION_CREATE,
            RoomState::Ended,
            &participant,
            StateWriteOptions::default()
        ));
        assert!(can_accept_room_write(
            event_type::ROOM_JOIN_REVIEW,
            RoomState::Scheduled,
            &PermissionContext::for_role(Role::Moderator),
            StateWriteOptions::default()
        ));
        assert!(can_accept_room_write(
            event_type::ROOM_JOIN,
            RoomState::Scheduled,
            &PermissionContext {
                join_request_approved: true,
                ..PermissionContext::default()
            },
            StateWriteOptions::default()
        ));
        assert!(can_accept_room_write(
            event_type::REACTION_CREATE,
            RoomState::Ended,
            &participant,
            StateWriteOptions {
                post_end_reaction_allowed: true,
            }
        ));
    }
}
