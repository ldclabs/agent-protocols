//! Agent Discourse Protocol 1.0: kernel types, the room type system, and
//! verification helpers.
//!
//! The protocol defines twelve built-in event types. Every other event type is
//! declared per room as a schema-validated type definition, either inline or
//! imported from a type pack. Hosts validate structure and permissions; they
//! never need to understand application semantics.

use std::collections::{BTreeMap, BTreeSet};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use sha3::{Digest, Sha3_256};

use crate::error::{Result, SdkError};
use crate::identity::{
    validate_event_fields, validate_origin, verify_envelope, AgentId, Envelope, Event,
    ListResponse, MAX_SAFE_NONCE,
};

pub const PROTOCOL: &str = "agent-discourse/1.0";

/// The twelve built-in event types. All other types are room-defined.
pub mod event_type {
    pub const ROOM_CREATE: &str = "room.create";
    pub const ROOM_UPDATE: &str = "room.update";
    pub const ROOM_JOIN: &str = "room.join";
    pub const ROOM_JOIN_REQUEST: &str = "room.join.request";
    pub const ROOM_JOIN_REVIEW: &str = "room.join.review";
    pub const ROOM_LEAVE: &str = "room.leave";
    pub const ROOM_MEMBER_ROLE_UPDATE: &str = "room.member.role.update";
    pub const ROOM_MEMBER_REMOVE: &str = "room.member.remove";
    pub const ROOM_CLOSE: &str = "room.close";
    pub const ROOM_CANCEL: &str = "room.cancel";
    pub const TYPE_DEFINE: &str = "type.define";
    pub const MESSAGE_CREATE: &str = "message.create";
}

pub const BUILTIN_EVENT_TYPES: [&str; 12] = [
    event_type::ROOM_CREATE,
    event_type::ROOM_UPDATE,
    event_type::ROOM_JOIN,
    event_type::ROOM_JOIN_REQUEST,
    event_type::ROOM_JOIN_REVIEW,
    event_type::ROOM_LEAVE,
    event_type::ROOM_MEMBER_ROLE_UPDATE,
    event_type::ROOM_MEMBER_REMOVE,
    event_type::ROOM_CLOSE,
    event_type::ROOM_CANCEL,
    event_type::TYPE_DEFINE,
    event_type::MESSAGE_CREATE,
];

/// Built-in membership events. They are `signal`-class: they anchor to an
/// accepted record but are never checked against or advance the room head, so
/// busy rooms cannot starve joins, reviews, or other membership writes.
pub const MEMBERSHIP_EVENT_TYPES: [&str; 5] = [
    event_type::ROOM_JOIN,
    event_type::ROOM_JOIN_REVIEW,
    event_type::ROOM_LEAVE,
    event_type::ROOM_MEMBER_ROLE_UPDATE,
    event_type::ROOM_MEMBER_REMOVE,
];

/// Contract writes (Section 5.1): anchored like signals, so discussion traffic
/// cannot starve them, but head-advancing, so messages and control writes
/// composed against the old contract are rejected and re-read.
pub const CONTRACT_EVENT_TYPES: [&str; 4] = [
    event_type::ROOM_UPDATE,
    event_type::ROOM_CLOSE,
    event_type::ROOM_CANCEL,
    event_type::TYPE_DEFINE,
];

/// ADP-specific error codes (Section 19); shared codes come from Agent Identity.
pub const DISCOURSE_ERROR_CODES: [&str; 19] = [
    "room_not_found",
    "room_not_active",
    "host_mismatch",
    "approval_required",
    "join_request_not_found",
    "join_request_not_pending",
    "member_banned",
    "role_not_allowed",
    "max_speakers_exceeded",
    "membership_required",
    "room_head_mismatch",
    "base_record_mismatch",
    "agent_status_not_found",
    "type_not_defined",
    "type_disabled",
    "type_conflict",
    "invalid_type_schema",
    "payload_schema_violation",
    "pack_unavailable",
];

/// Hosts MUST reject events with more than this many `mentions` entries.
pub const MAX_MENTIONS: usize = 32;

/// Custom event types must not use these prefixes.
pub const RESERVED_TYPE_PREFIXES: [&str; 3] = ["room.", "type.", "message."];

/// Registered type packs defined by the specification in `1.0.packs.json`.
pub mod pack_id {
    pub const REACTIONS: &str = "adp:reactions/1.0";
    pub const DELIBERATION: &str = "adp:deliberation/1.0";
    pub const CURATION: &str = "adp:curation/1.0";
    pub const MODERATION: &str = "adp:moderation/1.0";
    pub const REALTIME: &str = "adp:realtime/1.0";

    pub const REGISTERED: [&str; 5] = [REACTIONS, DELIBERATION, CURATION, MODERATION, REALTIME];
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

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Moderator,
    Speaker,
    Observer,
}

/// Permission class of an event type.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TypeKind {
    Message,
    Signal,
    Control,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TypeStatus {
    Active,
    Deprecated,
    Disabled,
}

/// Freshness class of an accepted record (Section 5.1): `genesis` and
/// `contract` for the room lifecycle built-ins, `signal` for membership
/// built-ins, `message` for `message.create`, and the registry `kind` for
/// custom types. `message` and `control` writes must be based at or after the
/// room head; `genesis`, `contract`, and `control` records advance it.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecordClass {
    Genesis,
    Contract,
    Message,
    Signal,
    Control,
}

/// Class of a built-in type per the Section 12.2 table; `None` for
/// room-defined types and for `room.join.request`, which never becomes a record.
pub fn builtin_event_class(event_type: &str) -> Option<RecordClass> {
    match event_type {
        event_type::ROOM_CREATE => Some(RecordClass::Genesis),
        event_type::ROOM_UPDATE
        | event_type::ROOM_CLOSE
        | event_type::ROOM_CANCEL
        | event_type::TYPE_DEFINE => Some(RecordClass::Contract),
        event_type::ROOM_JOIN
        | event_type::ROOM_JOIN_REVIEW
        | event_type::ROOM_LEAVE
        | event_type::ROOM_MEMBER_ROLE_UPDATE
        | event_type::ROOM_MEMBER_REMOVE => Some(RecordClass::Signal),
        event_type::MESSAGE_CREATE => Some(RecordClass::Message),
        _ => None,
    }
}

fn kind_class(kind: TypeKind) -> RecordClass {
    match kind {
        TypeKind::Message => RecordClass::Message,
        TypeKind::Signal => RecordClass::Signal,
        TypeKind::Control => RecordClass::Control,
    }
}

/// Record class of an event type; `None` for `room.join.request` and for
/// custom types absent from `types`.
pub fn record_class(event_type: &str, types: &[TypeDef]) -> Option<RecordClass> {
    if let Some(class) = builtin_event_class(event_type) {
        return Some(class);
    }
    if is_builtin_event_type(event_type) {
        return None;
    }
    types
        .iter()
        .find(|def| def.name == event_type)
        .map(|def| kind_class(def.kind))
}

/// Whether an accepted record of this type advances the room head (Section
/// 5.1): `genesis`, `contract`, and `control` records. Unknown custom types
/// default to head-advancing.
pub fn event_advances_room_head(event_type: &str, registry: &TypeRegistry) -> bool {
    event_type_advances_head(
        event_type,
        &registry.definitions().cloned().collect::<Vec<_>>(),
    )
}

/// [`event_advances_room_head`] over a materialized type list.
pub fn event_type_advances_head(event_type: &str, types: &[TypeDef]) -> bool {
    !matches!(
        record_class(event_type, types),
        Some(RecordClass::Message | RecordClass::Signal)
    )
}

/// Whether a write of this type is checked against the room head (Section
/// 5.1): `message.create` and custom `message`/`control` kinds must be based
/// at or after the current head. Contract and signal writes only anchor.
/// Unknown custom types default to head-checked.
pub fn event_requires_room_head(event_type: &str, types: &[TypeDef]) -> bool {
    match record_class(event_type, types) {
        Some(RecordClass::Message | RecordClass::Control) => true,
        Some(_) => false,
        None => !is_builtin_event_type(event_type),
    }
}

/// Section 5.1 base check for a room write based on `base_seq` / `base_hash`.
/// `anchor_hash` is the hash of the accepted record at `base_seq` in the same
/// room (`None` when there is none) and `head_seq` is the current room head.
/// Every base must name an accepted record (`base_record_mismatch`);
/// `message` and `control` writes must also be based at or after the head
/// (`room_head_mismatch`).
pub fn validate_room_base(
    event_type: &str,
    types: &[TypeDef],
    base_seq: u64,
    base_hash: &str,
    anchor_hash: Option<&str>,
    head_seq: u64,
) -> Result<()> {
    if anchor_hash != Some(base_hash) {
        return Err(SdkError::protocol(
            "base_record_mismatch",
            format!("base {base_seq} does not name an accepted record of this room"),
        ));
    }
    if event_requires_room_head(event_type, types) && base_seq < head_seq {
        return Err(SdkError::protocol(
            "room_head_mismatch",
            format!("base {base_seq} is before the room head {head_seq}"),
        ));
    }
    Ok(())
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
pub enum JoinDecision {
    Approve,
    Reject,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RoomCreatePayload {
    /// Origin of the host API the room is created on; binds the event to one host.
    pub host: String,
    pub topic: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agenda: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guidance: Option<String>,
    pub visibility: Visibility,
    pub start_time: i64,
    pub end_time: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<RoomPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<TypeDeclaration>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<BTreeMap<String, Value>>,
}

impl RoomCreatePayload {
    pub fn new(
        host: impl Into<String>,
        topic: impl Into<String>,
        visibility: Visibility,
        start_time: i64,
        end_time: i64,
    ) -> Self {
        Self {
            host: host.into(),
            topic: topic.into(),
            agenda: None,
            guidance: None,
            visibility,
            start_time,
            end_time,
            tags: None,
            language: None,
            policy: None,
            types: None,
            extra: None,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RoomPolicy {
    /// Agent IDs pre-approved for direct `room.join` with exactly this role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invites: Option<BTreeMap<AgentId, Role>>,
    /// Roles anyone may take by direct `room.join`; see [`effective_open_roles`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_roles: Option<Vec<Role>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_speakers: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observer_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<BTreeMap<String, Value>>,
}

impl RoomPolicy {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Payload of `room.update`: a partial contract revision. A present field
/// replaces the current value entirely; an empty value clears an optional
/// field. `host` and `visibility` are not updatable, and the type registry
/// evolves only through `type.define`. The field set is closed:
/// `deny_unknown_fields` rejects non-updatable fields so all three SDKs agree.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RoomUpdatePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agenda: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guidance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<RoomPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_time: Option<i64>,
}

impl RoomUpdatePayload {
    pub fn is_empty(&self) -> bool {
        self.topic.is_none()
            && self.agenda.is_none()
            && self.guidance.is_none()
            && self.tags.is_none()
            && self.language.is_none()
            && self.policy.is_none()
            && self.start_time.is_none()
            && self.end_time.is_none()
    }
}

/// Payload of `room.member.remove`: removal and optional ban.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RoomMemberRemovePayload {
    pub member: AgentId,
    /// Defaults to `false`. `true` additionally bans the agent from the room.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ban: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<BTreeMap<String, Value>>,
}

impl RoomMemberRemovePayload {
    pub fn new(member: AgentId) -> Self {
        Self {
            member,
            ban: None,
            reason: None,
            references: None,
            extra: None,
        }
    }

    pub fn banning(&self) -> bool {
        self.ban.unwrap_or(false)
    }
}

/// A room-scoped declaration of a custom event type. The field set is closed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TypeDef {
    #[serde(rename = "type")]
    pub name: String,
    pub kind: TypeKind,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema for the event payload, following the type schema profile.
    pub schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<Role>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<TypeStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_hint: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_payload_hint: Option<u64>,
    /// `None` when absent; an explicit `{}` is kept so a signed declaration
    /// re-serializes to the bytes that were signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<BTreeMap<String, Value>>,
}

impl TypeDef {
    pub fn status(&self) -> TypeStatus {
        self.status.unwrap_or(TypeStatus::Active)
    }
}

/// Per-type adjustments applied when importing a pack.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct TypeOverride {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<Role>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<TypeStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_hint: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_payload_hint: Option<u64>,
}

/// Imports a registered pack (`use`) or an external pack (`pack` + `digest`).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct PackImport {
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub use_pack: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<String>>,
    /// `None` when absent; an explicit `{}` is kept so a signed declaration
    /// re-serializes to the bytes that were signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overrides: Option<BTreeMap<String, TypeOverride>>,
}

/// One entry of `room.create.payload.types` or a `type.define` payload.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum TypeDeclaration {
    Def(TypeDef),
    Import(PackImport),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Pack {
    pub id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub types: Vec<TypeDef>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// The shape of `1.0.packs.json` and externally published pack documents.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PackDocument {
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub packs: Vec<Pack>,
}

/// Indexes the packs of a document by pack id for registry materialization.
pub fn pack_map(document: &PackDocument) -> BTreeMap<String, Pack> {
    document
        .packs
        .iter()
        .map(|pack| (pack.id.clone(), pack.clone()))
        .collect()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerRecord<P = Value> {
    pub room_id: String,
    pub seq: u64,
    #[serde(default)]
    pub pre_hash: Option<String>,
    pub hash: String,
    pub accepted_at: i64,
    pub envelope: Envelope<P>,
}

/// Envelope of a redacted record (Section 14.1): its event ID and type only.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RedactedEnvelope {
    pub hash: String,
    pub redacted: bool,
    #[serde(rename = "type")]
    pub kind: String,
}

/// A redacted server record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedactedServerRecord {
    pub room_id: String,
    pub seq: u64,
    #[serde(default)]
    pub pre_hash: Option<String>,
    pub hash: String,
    pub accepted_at: i64,
    pub envelope: RedactedEnvelope,
}

/// A record as it appears in history or an archive: signed or redacted.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum ArchiveRecord {
    Redacted(RedactedServerRecord),
    Signed(ServerRecord),
}

impl ArchiveRecord {
    pub fn room_id(&self) -> &str {
        match self {
            Self::Signed(r) => &r.room_id,
            Self::Redacted(r) => &r.room_id,
        }
    }
    pub fn seq(&self) -> u64 {
        match self {
            Self::Signed(r) => r.seq,
            Self::Redacted(r) => r.seq,
        }
    }
    pub fn pre_hash(&self) -> Option<&str> {
        match self {
            Self::Signed(r) => r.pre_hash.as_deref(),
            Self::Redacted(r) => r.pre_hash.as_deref(),
        }
    }
    pub fn hash(&self) -> &str {
        match self {
            Self::Signed(r) => &r.hash,
            Self::Redacted(r) => &r.hash,
        }
    }
    pub fn accepted_at(&self) -> i64 {
        match self {
            Self::Signed(r) => r.accepted_at,
            Self::Redacted(r) => r.accepted_at,
        }
    }
    pub fn envelope_hash(&self) -> &str {
        match self {
            Self::Signed(r) => &r.envelope.hash,
            Self::Redacted(r) => &r.envelope.hash,
        }
    }
    /// The event type, kept even when the record is redacted.
    pub fn event_type(&self) -> &str {
        match self {
            Self::Signed(r) => &r.envelope.event.kind,
            Self::Redacted(r) => &r.envelope.kind,
        }
    }
    pub fn is_redacted(&self) -> bool {
        matches!(self, Self::Redacted(_))
    }
}

impl From<ServerRecord> for ArchiveRecord {
    fn from(record: ServerRecord) -> Self {
        Self::Signed(record)
    }
}

impl From<RedactedServerRecord> for ArchiveRecord {
    fn from(record: RedactedServerRecord) -> Self {
        Self::Redacted(record)
    }
}

pub type RoomEventsResponse = ListResponse<ArchiveRecord>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerRecordHashPayload {
    pub room_id: String,
    pub seq: u64,
    pub pre_hash: Option<String>,
    pub envelope_hash: String,
    pub accepted_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoomResponse {
    pub id: String,
    pub status: RoomState,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator: Option<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agenda: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guidance: Option<String>,
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
    pub policy: Option<RoomPolicy>,
    /// Materialized type registry served by the host.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<TypeDef>,
    pub seq: u64,
    #[serde(default)]
    pub pre_hash: Option<String>,
    pub hash: String,
    pub accepted_at: i64,
    /// Latest accepted head-advancing record. Falls back to `seq`/`hash` on older hosts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<RoomHead>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope: Option<Envelope<RoomCreatePayload>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoomHead {
    pub seq: u64,
    pub hash: String,
}

/// Payload of a direct `room.join` (Section 9.2).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RoomJoinPayload {
    pub role: Role,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perspective: Option<String>,
}

/// Payload of a signed `room.join.request` (Section 10).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RoomJoinRequestPayload {
    pub role: Role,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perspective: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<BTreeMap<String, Value>>,
}

impl RoomJoinRequestPayload {
    pub fn new(role: Role) -> Self {
        Self {
            role,
            perspective: None,
            reason: None,
            extra: None,
        }
    }
}

/// The join request resource: the signed request plus review state.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RoomJoinRequest {
    /// Event ID of the signed request.
    pub id: String,
    pub request: Envelope<RoomJoinRequestPayload>,
    pub status: JoinRequestStatus,
    pub expires_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_by: Option<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_event_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AgentStatusInput {
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activity: Option<String>,
    /// Optional: when omitted, the host assigns its maximum TTL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl AgentStatusInput {
    pub fn new(state: impl Into<String>) -> Self {
        Self {
            state: state.into(),
            summary: None,
            seen_seq: None,
            seen_hash: None,
            claim_id: None,
            activity: None,
            expires_at: None,
            extra: BTreeMap::new(),
        }
    }

    pub fn with_expires_at(mut self, expires_at: i64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AgentStatus {
    pub room_id: String,
    pub agent_id: AgentId,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activity: Option<String>,
    pub expires_at: i64,
    pub updated_at: i64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

pub type AgentStatusListResponse = ListResponse<AgentStatus>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RoomJoinReviewPayload {
    /// The applicant's signed `room.join.request` envelope.
    pub request: Envelope<RoomJoinRequestPayload>,
    pub decision: JoinDecision,
    /// Required when approving.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<BTreeMap<String, Value>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RoleUpdatePayload {
    pub member: AgentId,
    pub role: Role,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<BTreeMap<String, Value>>,
}

/// Shared payload of `room.leave`, `room.close`, and `room.cancel`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct ReasonPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<BTreeMap<String, Value>>,
}

pub type RoomLeavePayload = ReasonPayload;
pub type RoomClosePayload = ReasonPayload;
pub type RoomCancelPayload = ReasonPayload;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MessageCreatePayload {
    pub content_type: String,
    /// A JSON string, or a JSON object for a JSON media type.
    pub content: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<BTreeMap<String, Value>>,
}

impl MessageCreatePayload {
    pub fn new(content_type: impl Into<String>, content: Value) -> Self {
        Self {
            content_type: content_type.into(),
            content,
            references: None,
            extra: None,
        }
    }

    pub fn text(text: impl Into<String>) -> Self {
        Self::new("text/plain", Value::String(text.into()))
    }

    pub fn markdown(markdown: impl Into<String>) -> Self {
        Self::new("text/markdown", Value::String(markdown.into()))
    }
}

/// The `profile` discovery member (Agent Profile Section 8): the Agent
/// Profile service a host resolves profiles from, and whether local policy
/// requires a verified profile before accepting an agent's writes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProfileResolverMetadata {
    pub service: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscourseProtocolDiscovery {
    pub protocol: String,
    pub service: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub registered_packs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileResolverMetadata>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub endpoints: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ArchiveManifest {
    pub protocol: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub room_id: String,
    pub url: String,
    pub generated_at: i64,
    pub last_seq: u64,
    /// Hash of the record at `last_seq`: the archive's commitment to every record.
    pub last_hash: String,
    /// Format names mapped to URLs; `jsonl` is the required record log.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub formats: BTreeMap<String, String>,
    /// Every external pack the room imported, with a URL serving its exact bytes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packs: Vec<ArchivedPack>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// An external pack document retained in an archive (Section 18).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArchivedPack {
    pub pack: String,
    pub digest: String,
    pub url: String,
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

/// A `room.join.request` carries `room_id` but no base: its author may not be
/// able to read the room.
pub fn room_join_request_event(
    actor: AgentId,
    created_at: i64,
    nonce: u64,
    room_id: impl Into<String>,
    payload: RoomJoinRequestPayload,
) -> Event<RoomJoinRequestPayload> {
    Event::new(
        PROTOCOL,
        event_type::ROOM_JOIN_REQUEST,
        actor,
        created_at,
        nonce,
        payload,
    )
    .with_room_id(room_id)
}

pub fn type_define_event(
    actor: AgentId,
    created_at: i64,
    nonce: u64,
    room_id: impl Into<String>,
    base_seq: u64,
    base_hash: impl Into<String>,
    declaration: TypeDeclaration,
) -> Event<TypeDeclaration> {
    Event::new(
        PROTOCOL,
        event_type::TYPE_DEFINE,
        actor,
        created_at,
        nonce,
        declaration,
    )
    .with_room_id(room_id)
    .with_room_head(base_seq, base_hash)
}

#[allow(clippy::too_many_arguments)]
pub fn discourse_event<P>(
    kind: impl Into<String>,
    actor: AgentId,
    created_at: i64,
    nonce: u64,
    room_id: impl Into<String>,
    base_seq: u64,
    base_hash: impl Into<String>,
    payload: P,
) -> Event<P> {
    Event::new(PROTOCOL, kind, actor, created_at, nonce, payload)
        .with_room_id(room_id)
        .with_room_head(base_seq, base_hash)
}

pub fn is_builtin_event_type(event_type: &str) -> bool {
    BUILTIN_EVENT_TYPES.contains(&event_type)
}

pub fn event_requires_room_id(event_type: &str) -> bool {
    event_type != event_type::ROOM_CREATE
}

/// Whether events of this type carry `base_seq` / `base_hash`.
pub fn event_requires_base(event_type: &str) -> bool {
    event_type != event_type::ROOM_CREATE && event_type != event_type::ROOM_JOIN_REQUEST
}

/// Room IDs are host-assigned and URL-safe (Section 6.1).
pub fn validate_room_id(room_id: &str) -> Result<()> {
    let valid = (1..=64).contains(&room_id.len())
        && room_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if valid {
        Ok(())
    } else {
        Err(invalid_event("room_id must match [A-Za-z0-9_-]{1,64}"))
    }
}

fn invalid_event(message: impl Into<String>) -> SdkError {
    SdkError::protocol("invalid_event", message)
}

pub fn validate_discourse_envelope<P>(envelope: &Envelope<P>) -> Result<()>
where
    P: Serialize,
{
    verify_envelope(envelope)?;
    validate_discourse_event_fields(&envelope.event)
}

/// Section 5 event-shape rules: closed fields, room ID, base, and mentions.
pub fn validate_discourse_event_fields<P>(event: &Event<P>) -> Result<()> {
    if event.protocol != PROTOCOL {
        return Err(SdkError::InvalidEventProtocol {
            expected: PROTOCOL.to_owned(),
            actual: event.protocol.clone(),
        });
    }
    match event.kind.as_str() {
        event_type::ROOM_CREATE => validate_event_fields(event, &[]),
        event_type::ROOM_JOIN_REQUEST => {
            validate_event_fields(event, &["room_id"])?;
            validate_room_id(event.room_id.as_deref().ok_or(SdkError::MissingRoomId)?)
        }
        _ => {
            validate_event_fields(event, &["room_id", "base_seq", "base_hash", "mentions"])?;
            validate_room_id(event.room_id.as_deref().ok_or(SdkError::MissingRoomId)?)?;
            validate_room_head_precondition(event)?;
            validate_mentions(event.mentions())
        }
    }
}

pub fn validate_room_path<P>(envelope: &Envelope<P>, path_room_id: &str) -> Result<()> {
    validate_discourse_event_fields(&envelope.event)?;
    if envelope.event.kind == event_type::ROOM_CREATE {
        return Ok(());
    }
    match envelope.event.room_id.as_deref() {
        Some(actual) if actual == path_room_id => Ok(()),
        Some(actual) => Err(SdkError::RoomIdMismatch {
            expected: path_room_id.to_owned(),
            actual: actual.to_owned(),
        }),
        None => Err(SdkError::MissingRoomId),
    }
}

fn validate_room_head_precondition<P>(event: &Event<P>) -> Result<()> {
    match (event.base_seq, event.base_hash.as_deref()) {
        (Some(seq), Some(hash)) if seq > 0 && seq <= MAX_SAFE_NONCE && !hash.trim().is_empty() => {
            Ok(())
        }
        (Some(0), _) => Err(invalid_event(
            "base_seq must be a positive safe JSON integer",
        )),
        (Some(_), Some(hash)) if hash.trim().is_empty() => {
            Err(invalid_event("base_hash must not be empty"))
        }
        (Some(seq), _) if seq > MAX_SAFE_NONCE => {
            Err(invalid_event("base_seq must be a safe JSON integer"))
        }
        _ => Err(invalid_event("room event requires base_seq and base_hash")),
    }
}

fn validate_mentions(mentions: &[AgentId]) -> Result<()> {
    if mentions.len() > MAX_MENTIONS {
        return Err(invalid_event(format!(
            "mentions must not exceed {MAX_MENTIONS} entries"
        )));
    }
    let unique: BTreeSet<&AgentId> = mentions.iter().collect();
    if unique.len() != mentions.len() {
        return Err(invalid_event("mentions must be unique"));
    }
    Ok(())
}

/// Checks the shape of a custom event type name: lowercase dot-separated,
/// at least two segments, not built-in, not under a reserved prefix.
pub fn validate_custom_event_type_name(name: &str) -> Result<()> {
    let segments: Vec<&str> = name.split('.').collect();
    let valid_shape = segments.len() >= 2 && segments.iter().all(|segment| {
        let mut chars = segment.chars();
        matches!(chars.next(), Some(first) if first.is_ascii_lowercase() || first.is_ascii_digit())
            && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    });
    if !valid_shape {
        return Err(invalid_event(format!("invalid event type name: {name}")));
    }
    if is_builtin_event_type(name) {
        return Err(invalid_event(format!("{name} is a built-in event type")));
    }
    if RESERVED_TYPE_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
    {
        return Err(invalid_event(format!("{name} uses a reserved type prefix")));
    }
    Ok(())
}

pub fn validate_type_def(def: &TypeDef) -> Result<()> {
    validate_custom_event_type_name(&def.name)?;
    if def.title.trim().is_empty() {
        return Err(invalid_event("type definition title must not be empty"));
    }
    if !def.schema.is_object() {
        return Err(SdkError::protocol(
            "invalid_type_schema",
            "type definition schema must be a JSON Schema object",
        ));
    }
    validate_type_schema_profile(&def.schema)?;
    compile_schema(&def.schema)?;
    if matches!(&def.roles, Some(roles) if roles.is_empty()) {
        return Err(invalid_event("type definition roles must not be empty"));
    }
    if matches!(def.rate_hint, Some(0)) || matches!(def.max_payload_hint, Some(0)) {
        return Err(invalid_event("type definition hints must be positive"));
    }
    Ok(())
}

/// `<algorithm>:<base64url-digest>` content digests (Section 12.5).
pub fn validate_content_digest(digest: &str) -> Result<()> {
    let valid = digest.split_once(':').is_some_and(|(algorithm, value)| {
        matches!(algorithm, "sha256" | "sha3-256")
            && value.len() == 43
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    if valid {
        Ok(())
    } else {
        Err(invalid_event(
            "external pack digest must be <sha256|sha3-256>:<base64url-digest>",
        ))
    }
}

pub fn validate_pack_import(import: &PackImport) -> Result<()> {
    match (&import.use_pack, &import.pack, &import.digest) {
        (Some(id), None, None) => {
            if !is_registered_pack_id(id) {
                return Err(invalid_event(format!("invalid registered pack id: {id}")));
            }
        }
        (None, Some(pack), Some(digest)) => {
            if !pack.starts_with("https://") {
                return Err(invalid_event("external pack must be an HTTPS URL"));
            }
            validate_content_digest(digest)?;
        }
        _ => {
            return Err(invalid_event(
                "pack import requires either use, or pack with digest",
            ));
        }
    }
    if let Some(types) = &import.types {
        if types.is_empty() {
            return Err(invalid_event("pack import types subset must not be empty"));
        }
        if types.iter().collect::<BTreeSet<_>>().len() != types.len() {
            return Err(SdkError::protocol(
                "type_conflict",
                "pack import types subset has duplicates",
            ));
        }
    }
    Ok(())
}

pub fn validate_type_declaration(declaration: &TypeDeclaration) -> Result<()> {
    match declaration {
        TypeDeclaration::Def(def) => validate_type_def(def),
        TypeDeclaration::Import(import) => validate_pack_import(import),
    }
}

fn is_registered_pack_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("adp:") else {
        return false;
    };
    let Some((name, version)) = rest.split_once('/') else {
        return false;
    };
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && version.split('.').count() == 2
        && version
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
}

// ── Type schema profile (Section 12.3.1).

const FORBIDDEN_SCHEMA_KEYWORDS: [&str; 5] = [
    "$dynamicRef",
    "$dynamicAnchor",
    "$recursiveRef",
    "$recursiveAnchor",
    "$vocabulary",
];
const SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";
const SUBSCHEMA_KEYWORDS: [&str; 11] = [
    "items",
    "additionalProperties",
    "not",
    "if",
    "then",
    "else",
    "contains",
    "propertyNames",
    "unevaluatedItems",
    "unevaluatedProperties",
    "additionalItems",
];
const SUBSCHEMA_ARRAY_KEYWORDS: [&str; 4] = ["allOf", "anyOf", "oneOf", "prefixItems"];
const SUBSCHEMA_MAP_KEYWORDS: [&str; 5] = [
    "properties",
    "patternProperties",
    "$defs",
    "definitions",
    "dependentSchemas",
];

fn walk_schema(
    schema: &Value,
    visit: &mut dyn FnMut(&serde_json::Map<String, Value>) -> Result<()>,
) -> Result<()> {
    let Some(node) = schema.as_object() else {
        return Ok(());
    };
    visit(node)?;
    for key in SUBSCHEMA_KEYWORDS {
        if let Some(child) = node.get(key) {
            walk_schema(child, visit)?;
        }
    }
    for key in SUBSCHEMA_ARRAY_KEYWORDS {
        if let Some(Value::Array(items)) = node.get(key) {
            for item in items {
                walk_schema(item, visit)?;
            }
        }
    }
    for key in SUBSCHEMA_MAP_KEYWORDS {
        if let Some(Value::Object(map)) = node.get(key) {
            for value in map.values() {
                walk_schema(value, visit)?;
            }
        }
    }
    Ok(())
}

fn invalid_schema(message: impl Into<String>) -> SdkError {
    SdkError::protocol("invalid_type_schema", message)
}

/// Enforces the type schema profile (Section 12.3.1): fragment-only `$ref`,
/// no dynamic or recursive references, the 2020-12 dialect, and portable
/// regular expressions.
pub fn validate_type_schema_profile(schema: &Value) -> Result<()> {
    walk_schema(schema, &mut |node| {
        for keyword in FORBIDDEN_SCHEMA_KEYWORDS {
            if node.contains_key(keyword) {
                return Err(invalid_schema(format!("{keyword} is not allowed")));
            }
        }
        if let Some(dialect) = node.get("$schema") {
            if dialect.as_str() != Some(SCHEMA_DIALECT) {
                return Err(invalid_schema("$schema must be the draft 2020-12 dialect"));
            }
        }
        if let Some(reference) = node.get("$ref") {
            if !reference.as_str().is_some_and(|r| r.starts_with('#')) {
                return Err(invalid_schema("$ref must be a fragment inside the schema"));
            }
        }
        if let Some(pattern) = node.get("pattern") {
            let pattern = pattern
                .as_str()
                .ok_or_else(|| invalid_schema("pattern must be a string"))?;
            validate_portable_pattern(pattern)?;
        }
        if let Some(Value::Object(properties)) = node.get("patternProperties") {
            for pattern in properties.keys() {
                validate_portable_pattern(pattern)?;
            }
        }
        Ok(())
    })
}

/// Checks that a pattern is an I-Regexp (RFC 9485) without `\p{…}`/`\P{…}`
/// and without `.` outside a character class, optionally anchored with a
/// leading `^` and a trailing `$` (Section 12.3.1).
pub fn validate_portable_pattern(pattern: &str) -> Result<()> {
    let reject =
        |reason: &str| invalid_schema(format!("pattern {pattern:?} is not portable: {reason}"));
    let mut body = pattern.strip_prefix('^').unwrap_or(pattern);
    if body.ends_with('$') && !body.ends_with("\\$") {
        body = &body[..body.len() - 1];
    }
    let chars: Vec<char> = body.chars().collect();
    const SINGLE_ESCAPES: &str = "()*+-.?[\\]^{|}nrt";
    let mut i = 0;
    let mut depth = 0usize;
    let mut can_quantify = false;
    let read_escape = |i: &mut usize| -> Result<()> {
        match chars.get(*i + 1) {
            None => Err(reject("dangling escape")),
            Some(next) if !SINGLE_ESCAPES.contains(*next) => {
                Err(reject(&format!("escape \\{next}")))
            }
            Some(_) => {
                *i += 2;
                Ok(())
            }
        }
    };
    while i < chars.len() {
        match chars[i] {
            '\\' => {
                read_escape(&mut i)?;
                can_quantify = true;
            }
            '[' => {
                i += 1;
                if chars.get(i) == Some(&'^') {
                    i += 1;
                }
                // A leading `]` is literal in some engines and an empty class in others.
                if chars.get(i) == Some(&']') {
                    return Err(reject("empty character class"));
                }
                while i < chars.len() && chars[i] != ']' {
                    match chars[i] {
                        '\\' => read_escape(&mut i)?,
                        '[' => return Err(reject("nested character class")),
                        _ => i += 1,
                    }
                }
                if chars.get(i) != Some(&']') {
                    return Err(reject("unterminated character class"));
                }
                i += 1;
                can_quantify = true;
            }
            '(' => {
                if chars.get(i + 1) == Some(&'?') {
                    return Err(reject("group modifiers"));
                }
                depth += 1;
                i += 1;
                can_quantify = false;
            }
            ')' => {
                if depth == 0 {
                    return Err(reject("unbalanced parenthesis"));
                }
                depth -= 1;
                i += 1;
                can_quantify = true;
            }
            '|' => {
                i += 1;
                can_quantify = false;
            }
            '*' | '+' | '?' => {
                if !can_quantify {
                    return Err(reject("quantifier without operand"));
                }
                i += 1;
                if matches!(chars.get(i), Some('?' | '+')) {
                    return Err(reject("lazy or possessive quantifier"));
                }
                can_quantify = false;
            }
            '{' => {
                if !can_quantify {
                    return Err(reject("quantifier without operand"));
                }
                let mut j = i + 1;
                let start = j;
                while j < chars.len() && chars[j].is_ascii_digit() {
                    j += 1;
                }
                if j == start {
                    return Err(reject("malformed quantifier"));
                }
                if chars.get(j) == Some(&',') {
                    j += 1;
                    while j < chars.len() && chars[j].is_ascii_digit() {
                        j += 1;
                    }
                }
                if chars.get(j) != Some(&'}') {
                    return Err(reject("malformed quantifier"));
                }
                i = j + 1;
                if matches!(chars.get(i), Some('?' | '+')) {
                    return Err(reject("lazy or possessive quantifier"));
                }
                can_quantify = false;
            }
            '.' => return Err(reject("'.' outside a character class")),
            '^' | '$' => return Err(reject("anchor inside the pattern")),
            '}' | ']' => return Err(reject(&format!("unescaped {}", chars[i]))),
            _ => {
                i += 1;
                can_quantify = true;
            }
        }
    }
    if depth != 0 {
        return Err(reject("unbalanced parenthesis"));
    }
    Ok(())
}

const ROLE_ORDER: [Role; 3] = [Role::Moderator, Role::Speaker, Role::Observer];

/// Section 8.3 rules for a room policy.
pub fn validate_room_policy(policy: Option<&RoomPolicy>) -> Result<()> {
    let Some(policy) = policy else {
        return Ok(());
    };
    if matches!(policy.max_speakers, Some(0)) {
        return Err(invalid_event("max_speakers must be a positive integer"));
    }
    let observer_allowed = policy.observer_allowed.unwrap_or(true);
    for role in policy.invites.iter().flat_map(|invites| invites.values()) {
        if *role == Role::Observer && !observer_allowed {
            return Err(SdkError::protocol(
                "role_not_allowed",
                "observers are not allowed",
            ));
        }
    }
    if let Some(open_roles) = &policy.open_roles {
        if open_roles.iter().collect::<BTreeSet<_>>().len() != open_roles.len() {
            return Err(invalid_event("open_roles must be a list of unique roles"));
        }
        for role in open_roles {
            match role {
                Role::Moderator => {
                    return Err(invalid_event("open_roles cannot contain moderator"))
                }
                Role::Observer if !observer_allowed => {
                    return Err(SdkError::protocol(
                        "role_not_allowed",
                        "observers are not allowed",
                    ))
                }
                _ => {}
            }
        }
    }
    Ok(())
}

/// Section 8.3 rule tying the policy to the room's visibility: a private
/// room admits agents only by invitation or review, so its `open_roles`
/// must be empty.
pub fn validate_room_visibility_policy(
    visibility: Visibility,
    policy: Option<&RoomPolicy>,
) -> Result<()> {
    let open = policy
        .and_then(|p| p.open_roles.as_ref())
        .is_some_and(|roles| !roles.is_empty());
    if visibility == Visibility::Private && open {
        return Err(invalid_event("a private room cannot have open roles"));
    }
    Ok(())
}

/// The roles any agent may take by direct `room.join` (Section 8.3): the
/// explicit `open_roles`, or by default `observer` in a public room when
/// observers are allowed, and none otherwise.
pub fn effective_open_roles(visibility: Visibility, policy: Option<&RoomPolicy>) -> Vec<Role> {
    if let Some(open_roles) = policy.and_then(|p| p.open_roles.clone()) {
        return open_roles;
    }
    if visibility == Visibility::Public && policy.and_then(|p| p.observer_allowed) != Some(false) {
        vec![Role::Observer]
    } else {
        Vec::new()
    }
}

/// Section 9.2 direct-join eligibility: the actor is invited with exactly
/// `role`, or `role` is one of the room's effective open roles. Bans and
/// quotas are separate host checks.
pub fn can_join_directly(
    visibility: Visibility,
    policy: Option<&RoomPolicy>,
    actor: &AgentId,
    role: Role,
) -> bool {
    if policy
        .and_then(|p| p.invites.as_ref())
        .and_then(|invites| invites.get(actor))
        == Some(&role)
    {
        return true;
    }
    effective_open_roles(visibility, policy).contains(&role)
}

pub fn validate_room_create_payload(payload: &RoomCreatePayload) -> Result<()> {
    if validate_origin(&payload.host).is_err() {
        return Err(invalid_event("room.create host must be an HTTPS origin"));
    }
    if payload.topic.trim().is_empty() {
        return Err(invalid_event("room topic must not be empty"));
    }
    if payload.start_time >= payload.end_time {
        return Err(invalid_event("start_time must be before end_time"));
    }
    validate_room_policy(payload.policy.as_ref())?;
    validate_room_visibility_policy(payload.visibility, payload.policy.as_ref())?;
    for declaration in payload.types.iter().flatten() {
        validate_type_declaration(declaration)?;
    }
    Ok(())
}

/// Host binding check (Section 8.1): `host` must be the receiving host's API origin.
pub fn validate_room_create_host(payload: &RoomCreatePayload, host_origin: &str) -> Result<()> {
    if payload.host == host_origin {
        Ok(())
    } else {
        Err(SdkError::protocol(
            "host_mismatch",
            format!("room.create names {}, not {host_origin}", payload.host),
        ))
    }
}

pub fn validate_message_create_payload(payload: &MessageCreatePayload) -> Result<()> {
    if payload.content_type.trim().is_empty() {
        return Err(invalid_event("content_type must not be empty"));
    }
    if !payload.content.is_string() && !payload.content.is_object() {
        return Err(invalid_event("content must be a string or an object"));
    }
    Ok(())
}

/// Verifies a signed `room.join.request` envelope for embedding or review:
/// hash, signature, and shape — historical verification, without the live
/// time window or nonce check.
pub fn validate_join_request_envelope(
    envelope: &Envelope<RoomJoinRequestPayload>,
    room_id: Option<&str>,
) -> Result<()> {
    validate_discourse_envelope(envelope)?;
    if envelope.event.kind != event_type::ROOM_JOIN_REQUEST {
        return Err(invalid_event(
            "embedded request must be a room.join.request",
        ));
    }
    if let Some(room_id) = room_id {
        if envelope.event.room_id.as_deref() != Some(room_id) {
            return Err(SdkError::RoomIdMismatch {
                expected: room_id.to_owned(),
                actual: envelope.event.room_id.clone().unwrap_or_default(),
            });
        }
    }
    Ok(())
}

/// Shape checks for `room.join.review`, including the embedded signed request.
pub fn validate_room_join_review_payload(
    payload: &RoomJoinReviewPayload,
    room_id: Option<&str>,
) -> Result<()> {
    validate_join_request_envelope(&payload.request, room_id)?;
    if payload.decision == JoinDecision::Approve && payload.role.is_none() {
        return Err(invalid_event("an approving review requires a role"));
    }
    Ok(())
}

/// Shape checks for a `room.update` payload. State-dependent rules — room
/// status, effective time ordering against the current contract — remain
/// host-side.
pub fn validate_room_update_payload(payload: &RoomUpdatePayload) -> Result<()> {
    if payload.is_empty() {
        return Err(invalid_event("room.update payload must not be empty"));
    }
    if matches!(&payload.topic, Some(topic) if topic.trim().is_empty()) {
        return Err(invalid_event("room topic must not be empty"));
    }
    if let (Some(start_time), Some(end_time)) = (payload.start_time, payload.end_time) {
        if start_time >= end_time {
            return Err(invalid_event("start_time must be before end_time"));
        }
    }
    validate_room_policy(payload.policy.as_ref())
}

/// Shape checks for a `room.member.remove` payload. Creator, self, and
/// membership checks remain host-side.
pub fn validate_room_member_remove_payload(payload: &RoomMemberRemovePayload) -> Result<()> {
    payload.member.public_key_bytes()?;
    Ok(())
}

/// The effective set of type definitions active in a room.
#[derive(Clone, Debug, Default)]
pub struct TypeRegistry {
    types: BTreeMap<String, TypeDef>,
}

impl TypeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Materializes a registry from the `room.create` declarations, resolving
    /// pack imports from `packs`, keyed by registered pack id or external pack
    /// URI. A type name may appear only once across these declarations.
    pub fn from_declarations(
        declarations: &[TypeDeclaration],
        packs: &BTreeMap<String, Pack>,
    ) -> Result<Self> {
        let mut registry = Self::new();
        let mut declared = BTreeSet::new();
        for declaration in declarations {
            for name in registry.apply(declaration, packs)? {
                if !declared.insert(name.clone()) {
                    return Err(SdkError::protocol(
                        "type_conflict",
                        format!("type {name} is declared twice"),
                    ));
                }
            }
        }
        Ok(registry)
    }

    /// Applies one declaration — an inline definition or a pack import — and
    /// returns the type names it declared. Declaring an existing type is a
    /// redefinition: it must keep the type's kind, and the latest definition wins.
    pub fn apply(
        &mut self,
        declaration: &TypeDeclaration,
        packs: &BTreeMap<String, Pack>,
    ) -> Result<Vec<String>> {
        match declaration {
            TypeDeclaration::Def(def) => {
                self.define(def.clone())?;
                Ok(vec![def.name.clone()])
            }
            TypeDeclaration::Import(import) => self.import(import, packs),
        }
    }

    pub fn define(&mut self, def: TypeDef) -> Result<()> {
        validate_type_def(&def)?;
        if let Some(existing) = self.types.get(&def.name) {
            if existing.kind != def.kind {
                return Err(SdkError::protocol(
                    "type_conflict",
                    format!("type {} cannot change kind on redefinition", def.name),
                ));
            }
        }
        self.types.insert(def.name.clone(), def);
        Ok(())
    }

    fn import(
        &mut self,
        import: &PackImport,
        packs: &BTreeMap<String, Pack>,
    ) -> Result<Vec<String>> {
        validate_pack_import(import)?;
        let reference = import
            .use_pack
            .as_deref()
            .or(import.pack.as_deref())
            .expect("validated pack import has a reference");
        let pack = packs
            .get(reference)
            .ok_or_else(|| SdkError::PackUnavailable(reference.to_owned()))?;
        let mut available = BTreeSet::new();
        for def in &pack.types {
            if !available.insert(def.name.as_str()) {
                return Err(SdkError::protocol(
                    "type_conflict",
                    format!("pack {reference} defines {} twice", def.name),
                ));
            }
        }
        if let Some(subset) = &import.types {
            for name in subset {
                if !available.contains(name.as_str()) {
                    return Err(SdkError::protocol(
                        "type_conflict",
                        format!("type {name} is not in pack {reference}"),
                    ));
                }
            }
        }
        for name in import.overrides.iter().flat_map(BTreeMap::keys) {
            let imported = import
                .types
                .as_ref()
                .map(|subset| subset.contains(name))
                .unwrap_or_else(|| available.contains(name.as_str()));
            if !imported {
                return Err(SdkError::protocol(
                    "type_conflict",
                    format!("override target {name} is not imported from pack {reference}"),
                ));
            }
        }
        let mut declared = Vec::new();
        for def in &pack.types {
            if let Some(subset) = &import.types {
                if !subset.contains(&def.name) {
                    continue;
                }
            }
            let mut def = def.clone();
            if let Some(over) = import
                .overrides
                .as_ref()
                .and_then(|overrides| overrides.get(&def.name))
            {
                if let Some(roles) = &over.roles {
                    def.roles = Some(roles.clone());
                }
                if let Some(instructions) = &over.instructions {
                    def.instructions = Some(instructions.clone());
                }
                if let Some(status) = over.status {
                    def.status = Some(status);
                }
                if let Some(rate_hint) = over.rate_hint {
                    def.rate_hint = Some(rate_hint);
                }
                if let Some(max_payload_hint) = over.max_payload_hint {
                    def.max_payload_hint = Some(max_payload_hint);
                }
            }
            declared.push(def.name.clone());
            self.define(def)?;
        }
        Ok(declared)
    }

    pub fn get(&self, event_type: &str) -> Option<&TypeDef> {
        self.types.get(event_type)
    }

    pub fn contains(&self, event_type: &str) -> bool {
        self.types.contains_key(event_type)
    }

    pub fn len(&self) -> usize {
        self.types.len()
    }

    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    pub fn definitions(&self) -> impl Iterator<Item = &TypeDef> {
        self.types.values()
    }

    /// Validates a custom event payload against the type's schema and status.
    pub fn validate_payload(&self, event_type: &str, payload: &Value) -> Result<()> {
        let def = self
            .get(event_type)
            .ok_or_else(|| SdkError::TypeNotDefined(event_type.to_owned()))?;
        if def.status() == TypeStatus::Disabled {
            return Err(SdkError::TypeDisabled(event_type.to_owned()));
        }
        let validator = compile_schema(&def.schema)?;
        if let Err(error) = validator.validate(payload) {
            return Err(SdkError::PayloadSchemaViolation(format!(
                "{event_type}: {error}"
            )));
        }
        Ok(())
    }
}

/// Validates an event payload: built-in payloads are accepted as-is (use the
/// typed validators for them); custom payloads must satisfy the registry.
pub fn validate_event_against_registry(
    event_type: &str,
    payload: &Value,
    registry: &TypeRegistry,
) -> Result<()> {
    if is_builtin_event_type(event_type) {
        return Ok(());
    }
    registry.validate_payload(event_type, payload)
}

fn compile_schema(schema: &Value) -> Result<jsonschema::Validator> {
    // Annotation keywords such as `format` are never asserted (Section 12.3.1).
    jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .should_validate_formats(false)
        .build(schema)
        .map_err(|err| invalid_schema(format!("invalid type schema: {err}")))
}

/// Verifies a `<algorithm>:<base64url-digest>` content digest over raw bytes.
/// Supports `sha256` and `sha3-256`.
pub fn verify_pack_digest(bytes: &[u8], digest: &str) -> Result<()> {
    validate_content_digest(digest)
        .map_err(|_| SdkError::PackUnavailable(format!("invalid digest format: {digest}")))?;
    let (algorithm, expected) = digest.split_once(':').expect("validated digest");
    let actual = match algorithm {
        "sha256" => URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)),
        _ => URL_SAFE_NO_PAD.encode(Sha3_256::digest(bytes)),
    };
    if actual == expected {
        Ok(())
    } else {
        Err(SdkError::PackUnavailable("pack digest mismatch".to_owned()))
    }
}

pub fn server_record_hash_payload(
    room_id: &str,
    seq: u64,
    pre_hash: Option<&str>,
    envelope_hash: &str,
    accepted_at: i64,
) -> ServerRecordHashPayload {
    ServerRecordHashPayload {
        room_id: room_id.to_owned(),
        seq,
        pre_hash: pre_hash.map(str::to_owned),
        envelope_hash: envelope_hash.to_owned(),
        accepted_at,
    }
}

pub fn server_record_hash(
    room_id: &str,
    seq: u64,
    pre_hash: Option<&str>,
    envelope_hash: &str,
    accepted_at: i64,
) -> Result<String> {
    hash_canonical_json(&server_record_hash_payload(
        room_id,
        seq,
        pre_hash,
        envelope_hash,
        accepted_at,
    ))
}

pub fn build_server_record<P>(
    room_id: impl Into<String>,
    seq: u64,
    pre_hash: Option<String>,
    accepted_at: i64,
    envelope: Envelope<P>,
) -> Result<ServerRecord<P>> {
    let room_id = room_id.into();
    let hash = server_record_hash(
        &room_id,
        seq,
        pre_hash.as_deref(),
        &envelope.hash,
        accepted_at,
    )
    .expect("server record hash payload is always serializable");
    Ok(ServerRecord {
        room_id,
        seq,
        pre_hash,
        hash,
        accepted_at,
        envelope,
    })
}

/// Replaces a record's envelope with its redacted form (Section 14.1). Only
/// `message.create` and custom-type records may be redacted.
pub fn redact_server_record(record: &ServerRecord) -> Result<RedactedServerRecord> {
    let kind = record.envelope.event.kind.clone();
    if is_builtin_event_type(&kind) && kind != event_type::MESSAGE_CREATE {
        return Err(invalid_event(format!("{kind} records cannot be redacted")));
    }
    Ok(RedactedServerRecord {
        room_id: record.room_id.clone(),
        seq: record.seq,
        pre_hash: record.pre_hash.clone(),
        hash: record.hash.clone(),
        accepted_at: record.accepted_at,
        envelope: RedactedEnvelope {
            hash: record.envelope.hash.clone(),
            redacted: true,
            kind,
        },
    })
}

pub fn verify_server_record<P>(record: &ServerRecord<P>) -> Result<()>
where
    P: Serialize,
{
    verify_record_hash(
        &record.room_id,
        record.seq,
        record.pre_hash.as_deref(),
        &record.envelope.hash,
        record.accepted_at,
        &record.hash,
    )
}

fn verify_record_hash(
    room_id: &str,
    seq: u64,
    pre_hash: Option<&str>,
    envelope_hash: &str,
    accepted_at: i64,
    hash: &str,
) -> Result<()> {
    let expected = server_record_hash(room_id, seq, pre_hash, envelope_hash, accepted_at)
        .expect("server record hash payload is always serializable");
    if hash == expected {
        Ok(())
    } else {
        Err(SdkError::InvalidEventHash {
            expected,
            actual: hash.to_owned(),
        })
    }
}

/// Verifies one signed or redacted record's hash; a redacted record must be
/// of a redactable type.
pub fn verify_archive_record(record: &ArchiveRecord) -> Result<()> {
    verify_record_hash(
        record.room_id(),
        record.seq(),
        record.pre_hash(),
        record.envelope_hash(),
        record.accepted_at(),
        record.hash(),
    )?;
    if let ArchiveRecord::Redacted(redacted) = record {
        let kind = redacted.envelope.kind.as_str();
        if !redacted.envelope.redacted
            || (is_builtin_event_type(kind) && kind != event_type::MESSAGE_CREATE)
        {
            return Err(SdkError::InvalidPayload(format!(
                "{kind} records cannot be redacted"
            )));
        }
    }
    Ok(())
}

pub fn verify_server_record_chain<P>(records: &[ServerRecord<P>]) -> Result<()>
where
    P: Serialize,
{
    let mut previous: Option<&ServerRecord<P>> = None;
    for record in records {
        verify_server_record(record)?;
        check_link(
            record.seq,
            record.pre_hash.as_deref(),
            previous.map(|p| (p.seq, p.hash.as_str())),
        )?;
        previous = Some(record);
    }
    Ok(())
}

fn check_link(seq: u64, pre_hash: Option<&str>, previous: Option<(u64, &str)>) -> Result<()> {
    match previous {
        Some((previous_seq, previous_hash)) => {
            if seq != previous_seq + 1 {
                return Err(SdkError::InvalidPayload(
                    "seq must increase by 1".to_owned(),
                ));
            }
            if pre_hash != Some(previous_hash) {
                return Err(SdkError::InvalidPayload("pre_hash mismatch".to_owned()));
            }
        }
        None if seq != 1 => {
            return Err(SdkError::InvalidPayload("first seq must be 1".to_owned()));
        }
        None if pre_hash.is_some() => {
            return Err(SdkError::InvalidPayload(
                "first pre_hash must be null".to_owned(),
            ));
        }
        None => {}
    }
    Ok(())
}

/// [`verify_server_record_chain`] over signed and redacted records.
pub fn verify_archive_chain(records: &[ArchiveRecord]) -> Result<()> {
    let mut previous: Option<&ArchiveRecord> = None;
    for record in records {
        verify_archive_record(record)?;
        check_link(
            record.seq(),
            record.pre_hash(),
            previous.map(|p| (p.seq(), p.hash())),
        )?;
        previous = Some(record);
    }
    Ok(())
}

/// Archive verification steps 1–3 (Section 18): a gap-free chain from seq 1
/// to `last_seq` ending in `last_hash`, and a valid signature on every record
/// that is not redacted. Returns the sequence numbers of redacted records,
/// which verifiers must report. State replay (step 4) is the caller's.
pub fn verify_archive_records(
    manifest: &ArchiveManifest,
    records: &[ArchiveRecord],
) -> Result<Vec<u64>> {
    verify_archive_chain(records)?;
    match records.last() {
        Some(last) if last.seq() == manifest.last_seq && last.hash() == manifest.last_hash => {}
        _ => {
            return Err(SdkError::InvalidPayload(
                "archive does not end at last_seq / last_hash".to_owned(),
            ))
        }
    }
    let mut redacted = Vec::new();
    for record in records {
        if record.room_id() != manifest.room_id {
            return Err(SdkError::InvalidPayload(
                "record belongs to another room".to_owned(),
            ));
        }
        match record {
            ArchiveRecord::Redacted(r) => redacted.push(r.seq),
            ArchiveRecord::Signed(r) => validate_discourse_envelope(&r.envelope)?,
        }
    }
    Ok(redacted)
}

/// Permission inputs for one actor in one room.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PermissionContext {
    pub role: Option<Role>,
    pub is_creator: bool,
    /// The actor may take the requested role by direct `room.join` (see [`can_join_directly`]).
    pub direct_join_allowed: bool,
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

/// Default sender roles for each kind. The creator passes every role check.
pub fn default_kind_roles(kind: TypeKind) -> &'static [Role] {
    match kind {
        TypeKind::Message => &[Role::Moderator, Role::Speaker],
        TypeKind::Signal => &ROLE_ORDER,
        TypeKind::Control => &[Role::Moderator],
    }
}

/// Role check for one event type, using kind defaults and per-type overrides
/// from the room's type registry. State checks are separate.
pub fn can_submit_event(
    event_type: &str,
    context: &PermissionContext,
    registry: &TypeRegistry,
) -> bool {
    match event_type {
        event_type::ROOM_CREATE => true,
        event_type::ROOM_JOIN => {
            context.direct_join_allowed && !context.is_creator && context.role.is_none()
        }
        event_type::ROOM_JOIN_REQUEST => !context.is_creator && context.role.is_none(),
        // The creator is a member until the room ends and cannot leave.
        event_type::ROOM_LEAVE => !context.is_creator && context.role.is_some(),
        event_type::ROOM_UPDATE
        | event_type::ROOM_JOIN_REVIEW
        | event_type::ROOM_MEMBER_ROLE_UPDATE
        | event_type::ROOM_MEMBER_REMOVE
        | event_type::ROOM_CLOSE
        | event_type::ROOM_CANCEL
        | event_type::TYPE_DEFINE => context.is_creator || context.role == Some(Role::Moderator),
        event_type::MESSAGE_CREATE => {
            context.is_creator
                || matches!(context.role, Some(Role::Moderator) | Some(Role::Speaker))
        }
        custom => {
            let Some(def) = registry.get(custom) else {
                return false;
            };
            if def.status() == TypeStatus::Disabled {
                return false;
            }
            if context.is_creator {
                return true;
            }
            let Some(role) = context.role else {
                return false;
            };
            match &def.roles {
                Some(roles) => roles.contains(&role),
                None => default_kind_roles(def.kind).contains(&role),
            }
        }
    }
}

pub fn can_write_in_state(event_type: &str, state: RoomState) -> bool {
    match state {
        RoomState::Scheduled => matches!(
            event_type,
            event_type::ROOM_JOIN_REQUEST
                | event_type::ROOM_JOIN
                | event_type::ROOM_JOIN_REVIEW
                | event_type::ROOM_MEMBER_ROLE_UPDATE
                | event_type::ROOM_MEMBER_REMOVE
                | event_type::ROOM_LEAVE
                | event_type::ROOM_UPDATE
                | event_type::TYPE_DEFINE
                | event_type::ROOM_CANCEL
        ),
        RoomState::Active => {
            event_type != event_type::ROOM_CREATE && event_type != event_type::ROOM_CANCEL
        }
        RoomState::Ended | RoomState::Cancelled => false,
    }
}

pub fn can_accept_room_write(
    event_type: &str,
    state: RoomState,
    permission: &PermissionContext,
    registry: &TypeRegistry,
) -> bool {
    can_submit_event(event_type, permission, registry) && can_write_in_state(event_type, state)
}

pub fn validate_room_write(
    event_type: &str,
    state: RoomState,
    permission: &PermissionContext,
    registry: &TypeRegistry,
) -> Result<()> {
    if can_accept_room_write(event_type, state, permission, registry) {
        Ok(())
    } else {
        Err(SdkError::PermissionDenied)
    }
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

    const HOST: &str = "https://api.example.com";

    fn signer(byte: u8) -> AgentSigner {
        AgentSigner::from_seed([byte; 32])
    }

    fn packs() -> BTreeMap<String, Pack> {
        let document: PackDocument = serde_json::from_str(include_str!(
            "../../../docs/protocols/agent-discourse/1.0.packs.json"
        ))
        .unwrap();
        pack_map(&document)
    }

    fn vectors() -> Value {
        serde_json::from_str(include_str!(
            "../../../docs/protocols/agent-discourse/1.0.vectors.json"
        ))
        .unwrap()
    }

    fn finding_def() -> TypeDef {
        serde_json::from_value(json!({
            "type": "review.finding",
            "kind": "message",
            "title": "Review finding",
            "schema": {
                "type": "object",
                "required": ["severity", "summary"],
                "properties": {
                    "severity": { "type": "string", "enum": ["low", "medium", "high"] },
                    "summary": { "type": "string", "minLength": 1 }
                },
                "additionalProperties": false
            }
        }))
        .unwrap()
    }

    fn room_payload() -> RoomCreatePayload {
        RoomCreatePayload::new(HOST, "Research room", Visibility::Public, 1000, 2000)
    }

    fn message(
        author: &AgentSigner,
        room: &str,
        base_seq: u64,
        base_hash: &str,
        nonce: u64,
    ) -> Envelope<Value> {
        author
            .sign_event(discourse_event(
                event_type::MESSAGE_CREATE,
                author.agent_id(),
                100,
                nonce,
                room,
                base_seq,
                base_hash,
                json!({ "content_type": "text/plain", "content": "hi" }),
            ))
            .unwrap()
    }

    #[test]
    fn kernel_defines_twelve_builtins_and_freshness_classes() {
        assert_eq!(BUILTIN_EVENT_TYPES.len(), 12);
        assert!(is_builtin_event_type(event_type::ROOM_JOIN_REQUEST));
        for kind in MEMBERSHIP_EVENT_TYPES {
            assert_eq!(builtin_event_class(kind), Some(RecordClass::Signal));
            assert!(!event_type_advances_head(kind, &[]));
            assert!(!event_requires_room_head(kind, &[]));
        }
        for kind in CONTRACT_EVENT_TYPES {
            assert_eq!(builtin_event_class(kind), Some(RecordClass::Contract));
            assert!(event_type_advances_head(kind, &[]));
            assert!(!event_requires_room_head(kind, &[]));
        }
        assert_eq!(
            builtin_event_class(event_type::ROOM_CREATE),
            Some(RecordClass::Genesis)
        );
        assert_eq!(record_class(event_type::ROOM_JOIN_REQUEST, &[]), None);
        assert!(event_requires_room_head(event_type::MESSAGE_CREATE, &[]));
        assert!(event_requires_room_head("unknown.custom", &[]));
        for code in [
            "host_mismatch",
            "type_conflict",
            "invalid_type_schema",
            "join_request_not_pending",
        ] {
            assert!(DISCOURSE_ERROR_CODES.contains(&code));
        }
    }

    #[test]
    fn discourse_vectors_reproduce_chains_redaction_and_heads() {
        let vectors = vectors();
        let records: Vec<ServerRecord> =
            serde_json::from_value(vectors["records"].clone()).unwrap();
        for record in &records {
            verify_server_record(record).unwrap();
            validate_discourse_envelope(&record.envelope).unwrap();
        }
        verify_server_record_chain(&records).unwrap();
        let redacted: Vec<ArchiveRecord> =
            serde_json::from_value(vectors["redacted_records"].clone()).unwrap();
        assert!(redacted[2].is_redacted());
        verify_archive_chain(&redacted).unwrap();
        let manifest = ArchiveManifest {
            protocol: PROTOCOL.into(),
            kind: "room.archive".into(),
            room_id: vectors["room_id"].as_str().unwrap().into(),
            url: format!("{HOST}/v1/rooms/x"),
            generated_at: 0,
            last_seq: vectors["last_seq"].as_u64().unwrap(),
            last_hash: vectors["last_hash"].as_str().unwrap().into(),
            formats: BTreeMap::new(),
            packs: Vec::new(),
            extra: BTreeMap::new(),
        };
        let signed: Vec<ArchiveRecord> =
            records.iter().cloned().map(ArchiveRecord::Signed).collect();
        assert_eq!(
            verify_archive_records(&manifest, &signed).unwrap(),
            Vec::<u64>::new()
        );
        assert_eq!(
            verify_archive_records(&manifest, &redacted).unwrap(),
            vec![3]
        );
        let mut short = manifest.clone();
        short.last_hash = records[0].hash.clone();
        assert!(verify_archive_records(&short, &signed).is_err());

        let create: RoomCreatePayload =
            serde_json::from_value(records[0].envelope.event.payload.clone()).unwrap();
        let registry =
            TypeRegistry::from_declarations(create.types.as_deref().unwrap(), &packs()).unwrap();
        let mut head = 0;
        for (record, expected) in records
            .iter()
            .zip(vectors["head_seq_after"].as_array().unwrap())
        {
            if event_advances_room_head(&record.envelope.event.kind, &registry) {
                head = record.seq;
            }
            assert_eq!(head, expected.as_u64().unwrap());
        }
    }

    #[test]
    fn discourse_vectors_classes_and_patterns() {
        let vectors = vectors();
        let declarations: Vec<TypeDeclaration> =
            serde_json::from_value(vectors["freshness"]["registry"].clone()).unwrap();
        let registry = TypeRegistry::from_declarations(&declarations, &packs()).unwrap();
        let types: Vec<TypeDef> = registry.definitions().cloned().collect();
        let list = |name: &str| -> Vec<String> {
            serde_json::from_value(vectors["freshness"][name].clone()).unwrap()
        };
        let (head_checked, head_advancing) = (list("head_checked"), list("head_advancing"));
        for (kind, class) in vectors["freshness"]["classes"].as_object().unwrap() {
            let expected: RecordClass = serde_json::from_value(class.clone()).unwrap();
            assert_eq!(record_class(kind, &types), Some(expected), "{kind}");
            assert_eq!(
                event_requires_room_head(kind, &types),
                head_checked.contains(kind),
                "{kind}"
            );
            assert_eq!(
                event_type_advances_head(kind, &types),
                head_advancing.contains(kind),
                "{kind}"
            );
        }
        for case in vectors["freshness"]["base_checks"].as_array().unwrap() {
            let base_hash = "base-hash";
            let anchor = case["anchored"].as_bool().unwrap().then_some(base_hash);
            let result = validate_room_base(
                case["type"].as_str().unwrap(),
                &types,
                case["base_seq"].as_u64().unwrap(),
                base_hash,
                anchor,
                case["head_seq"].as_u64().unwrap(),
            );
            let outcome = match &result {
                Ok(()) => "ok",
                Err(error) => error.code().unwrap_or("other"),
            };
            assert_eq!(
                outcome,
                case["expected"].as_str().unwrap(),
                "{}",
                case["name"]
            );
        }
        for name in vectors["type_names"]["valid"].as_array().unwrap() {
            validate_custom_event_type_name(name.as_str().unwrap()).unwrap();
        }
        for name in vectors["type_names"]["invalid"].as_array().unwrap() {
            let name = name.as_str().unwrap();
            assert!(validate_custom_event_type_name(name).is_err(), "{name}");
        }
        for case in vectors["open_roles"]["effective"].as_array().unwrap() {
            let visibility: Visibility =
                serde_json::from_value(case["visibility"].clone()).unwrap();
            let policy: Option<RoomPolicy> = case
                .get("policy")
                .map(|p| serde_json::from_value(p.clone()).unwrap());
            let expected: Vec<Role> = serde_json::from_value(case["expected"].clone()).unwrap();
            assert_eq!(
                effective_open_roles(visibility, policy.as_ref()),
                expected,
                "{}",
                case["name"]
            );
        }
        for case in vectors["open_roles"]["invalid"].as_array().unwrap() {
            let visibility: Visibility =
                serde_json::from_value(case["visibility"].clone()).unwrap();
            let policy: RoomPolicy = serde_json::from_value(case["policy"].clone()).unwrap();
            let result = validate_room_policy(Some(&policy))
                .and_then(|()| validate_room_visibility_policy(visibility, Some(&policy)));
            assert!(result.is_err(), "{}", case["name"]);
        }
        for pattern in vectors["patterns"]["valid"].as_array().unwrap() {
            validate_portable_pattern(pattern.as_str().unwrap()).unwrap();
        }
        for pattern in vectors["patterns"]["invalid"].as_array().unwrap() {
            let pattern = pattern.as_str().unwrap();
            assert!(validate_portable_pattern(pattern).is_err(), "{pattern}");
        }
    }

    #[test]
    fn registered_packs_follow_the_profile() {
        let packs = packs();
        assert_eq!(packs.len(), 5);
        for pack in packs.values() {
            for def in &pack.types {
                validate_type_def(def).unwrap();
            }
        }
        assert!(packs[pack_id::MODERATION]
            .types
            .iter()
            .any(|d| d.name == "claim.update"));
        assert!(!packs[pack_id::REALTIME]
            .types
            .iter()
            .any(|d| d.name == "session.candidate"));
    }

    #[test]
    fn room_create_is_host_bound_and_closed() {
        let creator = signer(14);
        let envelope = creator
            .sign_event(room_create_event(
                creator.agent_id(),
                100,
                1,
                room_payload(),
            ))
            .unwrap();
        validate_discourse_envelope(&envelope).unwrap();
        validate_room_path(&envelope, "d8ftedhpqhsusbg001tg").unwrap();
        validate_room_create_host(&envelope.event.payload, HOST).unwrap();
        assert_eq!(
            validate_room_create_host(&envelope.event.payload, "https://other.example")
                .unwrap_err()
                .code(),
            Some("host_mismatch")
        );
        let mut path_host = room_payload();
        path_host.host = format!("{HOST}/v1");
        assert!(validate_room_create_payload(&path_host).is_err());
        let with_room = creator
            .sign_event(
                room_create_event(creator.agent_id(), 100, 2, room_payload()).with_room_id("r1"),
            )
            .unwrap();
        assert!(validate_discourse_envelope(&with_room).is_err());
        let mut extra = room_create_event(creator.agent_id(), 100, 3, room_payload());
        extra.extra.insert("audience".into(), json!("x"));
        let extra = creator.sign_event(extra).unwrap();
        assert_eq!(
            validate_discourse_envelope(&extra).unwrap_err().code(),
            Some("invalid_event")
        );
    }

    #[test]
    fn room_events_require_valid_room_ids_and_bases() {
        let author = signer(15);
        let no_room = author
            .sign_event(Event::new(
                PROTOCOL,
                event_type::MESSAGE_CREATE,
                author.agent_id(),
                1,
                1,
                json!({}),
            ))
            .unwrap();
        assert!(matches!(
            validate_discourse_envelope(&no_room),
            Err(SdkError::MissingRoomId)
        ));
        assert!(validate_discourse_envelope(&message(&author, "room/../x", 1, "h", 2)).is_err());
        validate_room_path(&message(&author, "room1", 1, "h", 3), "room1").unwrap();
        assert!(matches!(
            validate_room_path(&message(&author, "room1", 1, "h", 4), "room2"),
            Err(SdkError::RoomIdMismatch { .. })
        ));
        let mentions: Vec<AgentId> = (0..33).map(|i| signer(100 + i).agent_id()).collect();
        let many = author
            .sign_event(
                discourse_event(
                    event_type::MESSAGE_CREATE,
                    author.agent_id(),
                    1,
                    5,
                    "room1",
                    1,
                    "h",
                    json!({}),
                )
                .with_mentions(mentions.clone()),
            )
            .unwrap();
        assert!(validate_discourse_envelope(&many).is_err());
        let ok = author
            .sign_event(
                discourse_event(
                    event_type::MESSAGE_CREATE,
                    author.agent_id(),
                    1,
                    6,
                    "room1",
                    1,
                    "h",
                    json!({}),
                )
                .with_mentions(mentions[..32].to_vec()),
            )
            .unwrap();
        validate_discourse_envelope(&ok).unwrap();
    }

    #[test]
    fn join_requests_are_signed_unanchored_and_embedded_by_reviews() {
        let moderator = signer(21);
        let applicant = signer(22);
        let room = "d8ftedhpqhsusbg001tg";
        let mut payload = RoomJoinRequestPayload::new(Role::Speaker);
        payload.perspective = Some("reviewer".into());
        let request = applicant
            .sign_event(room_join_request_event(
                applicant.agent_id(),
                1,
                1,
                room,
                payload,
            ))
            .unwrap();
        validate_discourse_envelope(&request).unwrap();
        let anchored = applicant
            .sign_event(
                room_join_request_event(
                    applicant.agent_id(),
                    1,
                    2,
                    room,
                    RoomJoinRequestPayload::new(Role::Speaker),
                )
                .with_room_head(1, "h"),
            )
            .unwrap();
        assert!(validate_discourse_envelope(&anchored).is_err());

        let review = RoomJoinReviewPayload {
            request: request.clone(),
            decision: JoinDecision::Approve,
            role: Some(Role::Speaker),
            reason: None,
            extra: None,
        };
        let signed = moderator
            .sign_event(discourse_event(
                event_type::ROOM_JOIN_REVIEW,
                moderator.agent_id(),
                2,
                1,
                room,
                1,
                "h",
                review.clone(),
            ))
            .unwrap();
        validate_discourse_envelope(&signed).unwrap();
        validate_room_join_review_payload(&review, Some(room)).unwrap();
        assert!(validate_room_join_review_payload(
            &RoomJoinReviewPayload {
                role: None,
                ..review.clone()
            },
            Some(room)
        )
        .is_err());
        assert!(validate_room_join_review_payload(&review, Some("other")).is_err());
        let mut tampered = review;
        tampered.request.event.payload.role = Role::Moderator;
        assert!(validate_room_join_review_payload(&tampered, Some(room)).is_err());
    }

    #[test]
    fn direct_join_follows_invites_and_open_roles() {
        let invited = signer(23).agent_id();
        let stranger = signer(24).agent_id();
        let policy = RoomPolicy {
            invites: Some(BTreeMap::from([(invited.clone(), Role::Moderator)])),
            open_roles: Some(vec![Role::Observer]),
            ..RoomPolicy::default()
        };
        assert!(can_join_directly(
            Visibility::Private,
            Some(&policy),
            &invited,
            Role::Moderator
        ));
        assert!(!can_join_directly(
            Visibility::Private,
            Some(&policy),
            &invited,
            Role::Speaker
        ));
        // Open roles apply to any visibility; a private room cannot list them.
        assert!(can_join_directly(
            Visibility::Restricted,
            Some(&policy),
            &stranger,
            Role::Observer
        ));
        assert!(validate_room_visibility_policy(Visibility::Private, Some(&policy)).is_err());
        validate_room_visibility_policy(Visibility::Restricted, Some(&policy)).unwrap();
        assert!(can_join_directly(
            Visibility::Public,
            Some(&policy),
            &stranger,
            Role::Observer
        ));
        assert!(!can_join_directly(
            Visibility::Public,
            Some(&policy),
            &stranger,
            Role::Speaker
        ));
        assert_eq!(
            effective_open_roles(Visibility::Public, None),
            vec![Role::Observer]
        );
        assert!(effective_open_roles(Visibility::Restricted, None).is_empty());
        assert!(!can_join_directly(
            Visibility::Private,
            None,
            &stranger,
            Role::Observer
        ));
        let no_observers = RoomPolicy {
            observer_allowed: Some(false),
            ..RoomPolicy::default()
        };
        assert!(effective_open_roles(Visibility::Public, Some(&no_observers)).is_empty());
        let bad = RoomPolicy {
            open_roles: Some(vec![Role::Moderator]),
            ..RoomPolicy::default()
        };
        assert!(validate_room_policy(Some(&bad)).is_err());
        let conflicting = RoomPolicy {
            observer_allowed: Some(false),
            open_roles: Some(vec![Role::Observer]),
            ..RoomPolicy::default()
        };
        assert!(validate_room_policy(Some(&conflicting)).is_err());
        assert!(
            serde_json::from_value::<RoomPolicy>(json!({ "moderator_agent_ids": [] })).is_err()
        );
    }

    #[test]
    fn type_schemas_follow_the_portable_profile() {
        validate_type_schema_profile(&json!({
            "type": "object",
            "properties": { "a": { "$ref": "#/$defs/x" } },
            "$defs": { "x": { "type": "string", "pattern": "^a$" } }
        }))
        .unwrap();
        for schema in [
            json!({ "$ref": "https://example.com/schema.json" }),
            json!({ "$dynamicRef": "#x" }),
            json!({ "$schema": "http://json-schema.org/draft-07/schema#" }),
            json!({ "properties": { "a": { "pattern": "\\w" } } }),
            json!({ "patternProperties": { "\\d": {} } }),
            json!({ "allOf": [{ "items": { "pattern": "." } }] }),
        ] {
            assert_eq!(
                validate_type_schema_profile(&schema).unwrap_err().code(),
                Some("invalid_type_schema")
            );
        }
        let mut def = finding_def();
        def.schema = json!({ "type": "string", "pattern": "\\s" });
        assert!(TypeRegistry::new().define(def).is_err());
        // `format` is an annotation: a non-URI string is not a schema violation.
        let registry = TypeRegistry::from_declarations(
            &[TypeDeclaration::Import(PackImport {
                use_pack: Some(pack_id::CURATION.into()),
                ..PackImport::default()
            })],
            &packs(),
        )
        .unwrap();
        registry
            .validate_payload(
                "resource.add",
                &json!({ "resource_type": "web", "uri": "not a uri" }),
            )
            .unwrap();
    }

    #[test]
    fn registry_imports_packs_and_rejects_conflicts() {
        let packs = packs();
        let import = |id: &str| {
            TypeDeclaration::Import(PackImport {
                use_pack: Some(id.into()),
                ..PackImport::default()
            })
        };
        let mut deliberation = PackImport {
            use_pack: Some(pack_id::DELIBERATION.into()),
            ..PackImport::default()
        };
        deliberation.overrides = Some(BTreeMap::from([(
            "poll.vote".into(),
            TypeOverride {
                roles: Some(vec![Role::Moderator, Role::Speaker, Role::Observer]),
                ..TypeOverride::default()
            },
        )]));
        let registry = TypeRegistry::from_declarations(
            &[
                import(pack_id::REACTIONS),
                TypeDeclaration::Import(deliberation),
                TypeDeclaration::Def(finding_def()),
            ],
            &packs,
        )
        .unwrap();
        assert_eq!(registry.len(), 6);
        assert!(can_submit_event(
            "poll.vote",
            &PermissionContext::for_role(Role::Observer),
            &registry
        ));
        let twice = TypeRegistry::from_declarations(
            &[
                TypeDeclaration::Def(finding_def()),
                TypeDeclaration::Def(finding_def()),
            ],
            &packs,
        );
        assert_eq!(twice.unwrap_err().code(), Some("type_conflict"));
        assert!(TypeRegistry::from_declarations(
            &[import(pack_id::REACTIONS), import(pack_id::REACTIONS)],
            &packs
        )
        .is_err());
        assert!(TypeRegistry::from_declarations(&[import("adp:unknown/1.0")], &packs).is_err());
        let mut subset = PackImport {
            use_pack: Some(pack_id::DELIBERATION.into()),
            types: Some(vec!["poll.vote".into(), "poll.vote".into()]),
            ..PackImport::default()
        };
        assert!(validate_pack_import(&subset).is_err());
        subset.types = Some(vec!["does.not.exist".into()]);
        assert!(
            TypeRegistry::from_declarations(&[TypeDeclaration::Import(subset)], &packs).is_err()
        );
        let mut registry = TypeRegistry::new();
        registry.define(finding_def()).unwrap();
        let mut signal = finding_def();
        signal.kind = TypeKind::Signal;
        assert_eq!(
            registry.define(signal).unwrap_err().code(),
            Some("type_conflict")
        );
        let external = PackImport {
            pack: Some("http://example.com/p.json".into()),
            digest: Some(format!("sha256:{}", "A".repeat(43))),
            ..PackImport::default()
        };
        assert!(validate_pack_import(&external).is_err());
        let digest = PackImport {
            pack: Some("https://example.com/p.json".into()),
            digest: Some("sha256:abc".into()),
            ..PackImport::default()
        };
        assert!(validate_pack_import(&digest).is_err());
    }

    #[test]
    fn verifies_pack_digests() {
        let bytes = b"pack document bytes";
        let sha256 = format!("sha256:{}", URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)));
        let sha3 = format!(
            "sha3-256:{}",
            URL_SAFE_NO_PAD.encode(Sha3_256::digest(bytes))
        );
        verify_pack_digest(bytes, &sha256).unwrap();
        verify_pack_digest(bytes, &sha3).unwrap();
        assert!(verify_pack_digest(b"tampered", &sha256).is_err());
        assert!(verify_pack_digest(bytes, "md5:abc").is_err());
    }

    #[test]
    fn permissions_follow_kinds_and_builtin_rules() {
        let registry = TypeRegistry::from_declarations(
            &[
                TypeDeclaration::Import(PackImport {
                    use_pack: Some(pack_id::REACTIONS.into()),
                    ..PackImport::default()
                }),
                TypeDeclaration::Import(PackImport {
                    use_pack: Some(pack_id::CURATION.into()),
                    ..PackImport::default()
                }),
            ],
            &packs(),
        )
        .unwrap();
        let observer = PermissionContext::for_role(Role::Observer);
        let speaker = PermissionContext::for_role(Role::Speaker);
        let moderator = PermissionContext::for_role(Role::Moderator);
        let creator = PermissionContext::creator(Some(Role::Observer));
        assert!(can_submit_event("reaction.create", &observer, &registry));
        assert!(can_submit_event("resource.add", &speaker, &registry));
        assert!(!can_submit_event("resource.add", &observer, &registry));
        assert!(can_submit_event("graph.update", &moderator, &registry));
        assert!(!can_submit_event("graph.update", &speaker, &registry));
        assert!(can_submit_event("graph.update", &creator, &registry));
        assert!(!can_submit_event("session.offer", &speaker, &registry));
        assert!(can_submit_event(
            event_type::ROOM_LEAVE,
            &observer,
            &registry
        ));
        assert!(!can_submit_event(
            event_type::ROOM_LEAVE,
            &PermissionContext::creator(Some(Role::Moderator)),
            &registry
        ));
        assert!(!can_submit_event(
            event_type::ROOM_JOIN,
            &PermissionContext::default(),
            &registry
        ));
        assert!(can_submit_event(
            event_type::ROOM_JOIN,
            &PermissionContext {
                direct_join_allowed: true,
                ..PermissionContext::default()
            },
            &registry
        ));
        assert!(can_submit_event(
            event_type::ROOM_JOIN_REQUEST,
            &PermissionContext::default(),
            &registry
        ));
        assert!(!can_submit_event(
            event_type::ROOM_JOIN_REQUEST,
            &speaker,
            &registry
        ));
        assert!(can_write_in_state(
            event_type::ROOM_JOIN_REQUEST,
            RoomState::Scheduled
        ));
        assert!(!can_write_in_state(
            event_type::ROOM_JOIN_REQUEST,
            RoomState::Ended
        ));
        assert!(!can_write_in_state(
            event_type::ROOM_CLOSE,
            RoomState::Scheduled
        ));
        assert!(!can_write_in_state(
            event_type::ROOM_CANCEL,
            RoomState::Active
        ));
        validate_room_write(
            event_type::MESSAGE_CREATE,
            RoomState::Active,
            &speaker,
            &registry,
        )
        .unwrap();
        assert!(validate_room_write(
            event_type::MESSAGE_CREATE,
            RoomState::Ended,
            &speaker,
            &registry
        )
        .is_err());
    }

    #[test]
    fn validates_payload_shapes() {
        validate_message_create_payload(&MessageCreatePayload::text("hi")).unwrap();
        validate_message_create_payload(&MessageCreatePayload::new(
            "application/json",
            json!({ "a": 1 }),
        ))
        .unwrap();
        for content in [json!(1), json!([]), json!(null)] {
            assert!(validate_message_create_payload(&MessageCreatePayload::new(
                "application/json",
                content
            ))
            .is_err());
        }
        assert!(validate_room_update_payload(&RoomUpdatePayload::default()).is_err());
        assert!(serde_json::from_value::<RoomUpdatePayload>(json!({ "host": "x" })).is_err());
        assert!(
            serde_json::from_value::<RoomUpdatePayload>(json!({ "visibility": "private" }))
                .is_err()
        );
        let update = RoomUpdatePayload {
            start_time: Some(5),
            end_time: Some(5),
            ..RoomUpdatePayload::default()
        };
        assert!(validate_room_update_payload(&update).is_err());
        assert!(serde_json::from_value::<RoomJoinPayload>(
            json!({ "role": "speaker", "request_id": "jr" })
        )
        .is_err());
        let member = signer(41).agent_id();
        validate_room_member_remove_payload(&RoomMemberRemovePayload::new(member)).unwrap();
        let mut bad_create = room_payload();
        bad_create.topic = " ".into();
        assert!(validate_room_create_payload(&bad_create).is_err());
    }

    #[test]
    fn builds_redacts_and_verifies_record_chains() {
        let author = signer(18);
        let create = author
            .sign_event(room_create_event(author.agent_id(), 100, 1, room_payload()))
            .unwrap();
        let first = build_server_record("room123", 1, None, 110, create).unwrap();
        let second = build_server_record(
            "room123",
            2,
            Some(first.hash.clone()),
            130,
            message(&author, "room123", 1, &first.hash, 2),
        )
        .unwrap();
        let first_value: ServerRecord =
            serde_json::from_value(serde_json::to_value(&first).unwrap()).unwrap();
        verify_server_record_chain(&[first_value.clone(), second.clone()]).unwrap();
        assert!(verify_server_record_chain(std::slice::from_ref(&second)).is_err());
        let redacted = redact_server_record(&second).unwrap();
        assert_eq!(redacted.envelope.kind, event_type::MESSAGE_CREATE);
        verify_archive_chain(&[
            ArchiveRecord::Signed(first_value.clone()),
            ArchiveRecord::Redacted(redacted),
        ])
        .unwrap();
        assert!(redact_server_record(&first_value).is_err());
    }
}
