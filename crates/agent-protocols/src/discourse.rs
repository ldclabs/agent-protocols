use std::collections::{BTreeMap, BTreeSet};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha3::{Digest, Sha3_256};

use crate::error::{Result, SdkError};
use crate::identity::{verify_envelope, AgentId, Envelope, Event};

pub const PROTOCOL: &str = "agent-discourse/1.0";

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
    pub const SESSION_OFFER: &str = "session.offer";
    pub const SESSION_ANSWER: &str = "session.answer";
    pub const SESSION_CANDIDATE: &str = "session.candidate";
    pub const SESSION_CLOSE: &str = "session.close";
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

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionOutcome {
    Accepted,
    Rejected,
    Deferred,
    Superseded,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionType {
    Webrtc,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionMediaKind {
    Audio,
    Video,
    Screen,
    Data,
    File,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionTopology {
    PeerToPeer,
    Sfu,
    TurnRelay,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionDescriptionType {
    Offer,
    Answer,
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
    #[serde(default)]
    pub pre_hash: Option<String>,
    pub hash: String,
    pub received_at: i64,
    pub envelope: Envelope<P>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerRecordHashPayload {
    pub room_id: String,
    pub seq: u64,
    pub pre_hash: Option<String>,
    pub envelope_hash: String,
    pub received_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoomResponse {
    pub id: String,
    pub status: RoomState,
    pub url: String,
    pub seq: u64,
    #[serde(default)]
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
pub struct ProposalCreatePayload {
    pub proposal_id: String,
    pub title: String,
    pub body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_event_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PollOption {
    pub id: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PollCreatePayload {
    pub poll_id: String,
    pub question: String,
    pub options: Vec<PollOption>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_choices: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_choices: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closes_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PollVotePayload {
    pub event_id: String,
    pub option_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ResolutionCreatePayload {
    pub resolution_id: String,
    pub outcome: ResolutionOutcome,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poll_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
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
pub struct SessionDescription {
    #[serde(rename = "type")]
    pub kind: SessionDescriptionType,
    pub sdp: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionIceCandidate {
    pub candidate: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdp_mid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdp_mline_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username_fragment: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionDataTransfer {
    pub transfer_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SessionOfferPayload {
    pub session_id: String,
    pub session_type: SessionType,
    pub media: Vec<SessionMediaKind>,
    pub description: SessionDescription,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topology: Option<SessionTopology>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transfers: Vec<SessionDataTransfer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SessionAnswerPayload {
    pub session_id: String,
    pub offer_event_id: String,
    pub description: SessionDescription,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_media: Vec<SessionMediaKind>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transfers: Vec<SessionDataTransfer>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SessionCandidatePayload {
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate: Option<SessionIceCandidate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_of_candidates: Option<bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SessionClosePayload {
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
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

pub fn validate_discourse_envelope<P>(envelope: &Envelope<P>) -> Result<()>
where
    P: Serialize,
{
    verify_envelope(envelope)?;
    let protocol = envelope.event.protocol.as_str();
    if protocol != PROTOCOL {
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

pub fn validate_room_create_payload(payload: &RoomCreatePayload) -> Result<()> {
    if payload.topic.trim().is_empty() {
        return Err(SdkError::InvalidPayload(
            "room topic must not be empty".to_owned(),
        ));
    }
    if payload.start_time >= payload.end_time {
        return Err(SdkError::InvalidPayload(
            "start_time must be before end_time".to_owned(),
        ));
    }
    if let Some(policy) = &payload.policy {
        if matches!(policy.max_participants, Some(0)) {
            return Err(SdkError::InvalidPayload(
                "max_participants must be a positive integer".to_owned(),
            ));
        }
    }
    Ok(())
}

pub fn validate_poll_create_payload(payload: &PollCreatePayload) -> Result<()> {
    if payload.poll_id.trim().is_empty() || payload.question.trim().is_empty() {
        return Err(SdkError::InvalidPayload(
            "poll_id and question are required".to_owned(),
        ));
    }
    if payload.options.len() < 2 {
        return Err(SdkError::InvalidPayload(
            "poll requires at least two options".to_owned(),
        ));
    }
    let mut option_ids = BTreeSet::new();
    for option in &payload.options {
        if option.id.trim().is_empty() || option.label.trim().is_empty() {
            return Err(SdkError::InvalidPayload(
                "option id and label are required".to_owned(),
            ));
        }
        if !option_ids.insert(option.id.as_str()) {
            return Err(SdkError::InvalidPayload(
                "poll option ids must be unique".to_owned(),
            ));
        }
    }
    let min_choices = payload.min_choices.unwrap_or(1);
    let max_choices = payload.max_choices.unwrap_or(1);
    if min_choices < 1 || max_choices < min_choices {
        return Err(SdkError::InvalidPayload(
            "invalid poll choice limits".to_owned(),
        ));
    }
    Ok(())
}

pub fn validate_poll_vote_payload(
    payload: &PollVotePayload,
    poll: &PollCreatePayload,
    now_ms: Option<i64>,
) -> Result<()> {
    if let (Some(closes_at), Some(now_ms)) = (poll.closes_at, now_ms) {
        if now_ms > closes_at {
            return Err(SdkError::InvalidPayload("poll is closed".to_owned()));
        }
    }
    let min_choices = poll.min_choices.unwrap_or(1) as usize;
    let max_choices = poll.max_choices.unwrap_or(1) as usize;
    let option_ids: BTreeSet<&str> = poll
        .options
        .iter()
        .map(|option| option.id.as_str())
        .collect();
    let selected: BTreeSet<&str> = payload.option_ids.iter().map(String::as_str).collect();
    if selected.len() != payload.option_ids.len() {
        return Err(SdkError::InvalidPayload(
            "duplicate poll options".to_owned(),
        ));
    }
    if selected.len() < min_choices || selected.len() > max_choices {
        return Err(SdkError::InvalidPayload(
            "invalid number of options".to_owned(),
        ));
    }
    if selected
        .iter()
        .any(|option_id| !option_ids.contains(option_id))
    {
        return Err(SdkError::InvalidPayload("unknown poll option".to_owned()));
    }
    Ok(())
}

pub fn validate_session_offer_payload(payload: &SessionOfferPayload) -> Result<()> {
    validate_session_id(&payload.session_id)?;
    if payload.media.is_empty() {
        return Err(SdkError::InvalidPayload(
            "media must not be empty".to_owned(),
        ));
    }
    validate_session_description(&payload.description, SessionDescriptionType::Offer)?;
    validate_session_transfers(&payload.transfers)
}

pub fn validate_session_answer_payload(payload: &SessionAnswerPayload) -> Result<()> {
    validate_session_id(&payload.session_id)?;
    if payload.offer_event_id.trim().is_empty() {
        return Err(SdkError::InvalidPayload(
            "offer_event_id is required".to_owned(),
        ));
    }
    validate_session_description(&payload.description, SessionDescriptionType::Answer)?;
    validate_session_transfers(&payload.transfers)
}

pub fn validate_session_candidate_payload(payload: &SessionCandidatePayload) -> Result<()> {
    validate_session_id(&payload.session_id)?;
    if payload.end_of_candidates.unwrap_or(false) {
        return Ok(());
    }
    match &payload.candidate {
        Some(candidate) if !candidate.candidate.trim().is_empty() => Ok(()),
        _ => Err(SdkError::InvalidPayload(
            "candidate is required unless end_of_candidates is true".to_owned(),
        )),
    }
}

pub fn server_record_hash_payload(
    room_id: &str,
    seq: u64,
    pre_hash: Option<&str>,
    envelope_hash: &str,
    received_at: i64,
) -> ServerRecordHashPayload {
    ServerRecordHashPayload {
        room_id: room_id.to_owned(),
        seq,
        pre_hash: pre_hash.map(str::to_owned),
        envelope_hash: envelope_hash.to_owned(),
        received_at,
    }
}

pub fn server_record_hash(
    room_id: &str,
    seq: u64,
    pre_hash: Option<&str>,
    envelope_hash: &str,
    received_at: i64,
) -> Result<String> {
    hash_canonical_json(&server_record_hash_payload(
        room_id,
        seq,
        pre_hash,
        envelope_hash,
        received_at,
    ))
}

pub fn build_server_record<P>(
    room_id: impl Into<String>,
    seq: u64,
    pre_hash: Option<String>,
    received_at: i64,
    envelope: Envelope<P>,
) -> Result<ServerRecord<P>> {
    let room_id = room_id.into();
    let hash = server_record_hash(
        &room_id,
        seq,
        pre_hash.as_deref(),
        &envelope.hash,
        received_at,
    )?;
    Ok(ServerRecord {
        room_id,
        seq,
        pre_hash,
        hash,
        received_at,
        envelope,
    })
}

pub fn verify_server_record<P>(record: &ServerRecord<P>) -> Result<()>
where
    P: Serialize,
{
    let expected = server_record_hash(
        &record.room_id,
        record.seq,
        record.pre_hash.as_deref(),
        &record.envelope.hash,
        record.received_at,
    )?;
    if record.hash == expected {
        Ok(())
    } else {
        Err(SdkError::InvalidEventHash {
            expected,
            actual: record.hash.clone(),
        })
    }
}

pub fn verify_server_record_chain<P>(records: &[ServerRecord<P>]) -> Result<()>
where
    P: Serialize,
{
    let mut previous: Option<&ServerRecord<P>> = None;
    for record in records {
        verify_server_record(record)?;
        if let Some(previous) = previous {
            if record.seq != previous.seq + 1 {
                return Err(SdkError::InvalidPayload(
                    "seq must increase by 1".to_owned(),
                ));
            }
            if record.pre_hash.as_deref() != Some(previous.hash.as_str()) {
                return Err(SdkError::InvalidPayload("pre_hash mismatch".to_owned()));
            }
        } else if record.seq != 1 {
            return Err(SdkError::InvalidPayload("first seq must be 1".to_owned()));
        } else if record.pre_hash.is_some() {
            return Err(SdkError::InvalidPayload(
                "first pre_hash must be null".to_owned(),
            ));
        }
        previous = Some(record);
    }
    Ok(())
}

pub fn archive_events_digest<P>(records: &[ServerRecord<P>]) -> Result<String>
where
    P: Serialize,
{
    hash_canonical_json(records)
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
            | event_type::SESSION_OFFER
            | event_type::SESSION_ANSWER
            | event_type::SESSION_CANDIDATE
            | event_type::SESSION_CLOSE
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
            | event_type::SESSION_OFFER
            | event_type::SESSION_ANSWER
            | event_type::SESSION_CANDIDATE
            | event_type::SESSION_CLOSE
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
            | event_type::SESSION_OFFER
            | event_type::SESSION_ANSWER
            | event_type::SESSION_CANDIDATE
            | event_type::SESSION_CLOSE
    )
}

fn validate_session_id(session_id: &str) -> Result<()> {
    if session_id.trim().is_empty() {
        Err(SdkError::InvalidPayload(
            "session_id is required".to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn validate_session_description(
    description: &SessionDescription,
    expected_type: SessionDescriptionType,
) -> Result<()> {
    if description.kind != expected_type {
        return Err(SdkError::InvalidPayload(format!(
            "session description type must be {}",
            match expected_type {
                SessionDescriptionType::Offer => "offer",
                SessionDescriptionType::Answer => "answer",
            }
        )));
    }
    if description.sdp.trim().is_empty() {
        return Err(SdkError::InvalidPayload(
            "session description sdp is required".to_owned(),
        ));
    }
    Ok(())
}

fn validate_session_transfers(transfers: &[SessionDataTransfer]) -> Result<()> {
    for transfer in transfers {
        if transfer.transfer_id.trim().is_empty() {
            return Err(SdkError::InvalidPayload(
                "transfer_id is required".to_owned(),
            ));
        }
    }
    Ok(())
}

fn hash_canonical_json<T>(value: &T) -> Result<String>
where
    T: Serialize + ?Sized,
{
    let bytes = serde_jcs::to_vec(value).map_err(|err| SdkError::CanonicalJson(err.to_string()))?;
    let digest = Sha3_256::digest(bytes);
    Ok(URL_SAFE_NO_PAD.encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentSigner;
    use serde_json::json;

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

        validate_discourse_envelope(&envelope).unwrap();
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
            validate_discourse_envelope(&envelope),
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
        assert!(can_submit_event(event_type::SESSION_OFFER, &participant));
        assert!(!can_submit_event(
            event_type::ROOM_JOIN_REVIEW,
            &participant
        ));
        assert!(!can_submit_event(event_type::SESSION_CANDIDATE, &observer));
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

    #[test]
    fn validates_room_creation_payloads() {
        let mut payload = RoomCreatePayload::new("Research room", Visibility::Public, 1000, 2000);
        payload.policy = Some(RoomPolicy {
            max_participants: Some(2),
            ..RoomPolicy::default()
        });
        validate_room_create_payload(&payload).unwrap();

        let empty_topic = RoomCreatePayload::new(" ", Visibility::Public, 1000, 2000);
        assert!(matches!(
            validate_room_create_payload(&empty_topic),
            Err(SdkError::InvalidPayload(_))
        ));

        let invalid_time = RoomCreatePayload::new("Research room", Visibility::Public, 2000, 1000);
        assert!(matches!(
            validate_room_create_payload(&invalid_time),
            Err(SdkError::InvalidPayload(_))
        ));
    }

    #[test]
    fn validates_poll_payloads_and_votes() {
        let poll = PollCreatePayload {
            poll_id: "poll_review_order".to_owned(),
            question: "Which review order?".to_owned(),
            options: vec![
                PollOption {
                    id: "a".to_owned(),
                    label: "Correctness first".to_owned(),
                    description: None,
                },
                PollOption {
                    id: "b".to_owned(),
                    label: "Security first".to_owned(),
                    description: None,
                },
            ],
            min_choices: Some(1),
            max_choices: Some(1),
            closes_at: None,
            references: Vec::new(),
            extra: BTreeMap::new(),
        };

        validate_poll_create_payload(&poll).unwrap();
        validate_poll_vote_payload(
            &PollVotePayload {
                event_id: "evt".to_owned(),
                option_ids: vec!["a".to_owned()],
            },
            &poll,
            None,
        )
        .unwrap();
        assert!(matches!(
            validate_poll_vote_payload(
                &PollVotePayload {
                    event_id: "evt".to_owned(),
                    option_ids: vec!["a".to_owned(), "b".to_owned()],
                },
                &poll,
                None,
            ),
            Err(SdkError::InvalidPayload(_))
        ));

        let mut duplicate = poll.clone();
        duplicate.options[1].id = "a".to_owned();
        assert!(matches!(
            validate_poll_create_payload(&duplicate),
            Err(SdkError::InvalidPayload(_))
        ));
    }

    #[test]
    fn validates_webrtc_session_payloads() {
        let offer = SessionOfferPayload {
            session_id: "sess_live_review".to_owned(),
            session_type: SessionType::Webrtc,
            media: vec![
                SessionMediaKind::Audio,
                SessionMediaKind::Video,
                SessionMediaKind::File,
            ],
            description: SessionDescription {
                kind: SessionDescriptionType::Offer,
                sdp: "v=0\r\n...".to_owned(),
            },
            to: Vec::new(),
            topology: Some(SessionTopology::PeerToPeer),
            transfers: vec![SessionDataTransfer {
                transfer_id: "file_1".to_owned(),
                file_name: Some("trace.har".to_owned()),
                size_bytes: Some(1024),
                mime_type: Some("application/json".to_owned()),
                content_digest: Some("sha256:abc".to_owned()),
            }],
            expires_at: None,
            references: Vec::new(),
            extra: BTreeMap::new(),
        };
        validate_session_offer_payload(&offer).unwrap();

        validate_session_answer_payload(&SessionAnswerPayload {
            session_id: "sess_live_review".to_owned(),
            offer_event_id: "evt_offer".to_owned(),
            description: SessionDescription {
                kind: SessionDescriptionType::Answer,
                sdp: "v=0\r\n...".to_owned(),
            },
            accepted_media: vec![SessionMediaKind::Audio, SessionMediaKind::File],
            transfers: Vec::new(),
            extra: BTreeMap::new(),
        })
        .unwrap();

        validate_session_candidate_payload(&SessionCandidatePayload {
            session_id: "sess_live_review".to_owned(),
            candidate: Some(SessionIceCandidate {
                candidate: "candidate:1 1 udp 1 127.0.0.1 3478 typ host".to_owned(),
                sdp_mid: None,
                sdp_mline_index: None,
                username_fragment: None,
            }),
            target: None,
            end_of_candidates: None,
            extra: BTreeMap::new(),
        })
        .unwrap();

        validate_session_candidate_payload(&SessionCandidatePayload {
            session_id: "sess_live_review".to_owned(),
            candidate: None,
            target: None,
            end_of_candidates: Some(true),
            extra: BTreeMap::new(),
        })
        .unwrap();

        let mut invalid_offer = offer;
        invalid_offer.description.kind = SessionDescriptionType::Answer;
        assert!(matches!(
            validate_session_offer_payload(&invalid_offer),
            Err(SdkError::InvalidPayload(_))
        ));

        assert!(matches!(
            validate_session_candidate_payload(&SessionCandidatePayload {
                session_id: "sess_live_review".to_owned(),
                candidate: None,
                target: None,
                end_of_candidates: None,
                extra: BTreeMap::new(),
            }),
            Err(SdkError::InvalidPayload(_))
        ));
    }

    #[test]
    fn builds_and_verifies_server_record_chains() {
        let signer = AgentSigner::from_seed([18; 32]);
        let envelope1 = signer
            .sign_event(Event::new(
                PROTOCOL,
                event_type::ROOM_CREATE,
                signer.agent_id(),
                100,
                1,
                json!({
                    "topic": "Research room",
                    "visibility": "public",
                    "start_time": 1000,
                    "end_time": 2000
                }),
            ))
            .unwrap();
        let record1 = build_server_record("room123", 1, None, 110, envelope1).unwrap();

        let envelope2 = signer
            .sign_event(discourse_event(
                event_type::MESSAGE_CREATE,
                signer.agent_id(),
                120,
                2,
                "room123",
                json!({"content_type": "text/plain", "content": "hello"}),
            ))
            .unwrap();
        let record2 =
            build_server_record("room123", 2, Some(record1.hash.clone()), 130, envelope2).unwrap();

        assert_eq!(
            record1.hash,
            server_record_hash("room123", 1, None, &record1.envelope.hash, 110).unwrap()
        );
        verify_server_record(&record1).unwrap();
        verify_server_record_chain(&[record1.clone(), record2.clone()]).unwrap();
        assert_eq!(
            archive_events_digest(&[record1.clone(), record2.clone()])
                .unwrap()
                .len(),
            43
        );
        assert!(verify_server_record_chain(&[record2]).is_err());

        let broken = ServerRecord {
            pre_hash: Some("bad".to_owned()),
            ..record1
        };
        assert!(verify_server_record_chain(&[broken]).is_err());
    }
}
