//! Agent Discourse Protocol 1.0: kernel types, the room type system, and
//! verification helpers.
//!
//! The protocol defines nine built-in event types. Every other event type is
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
use crate::identity::{verify_envelope, AgentId, Envelope, Event};

pub const PROTOCOL: &str = "agent-discourse/1.0";

/// The nine built-in event types. All other types are room-defined.
pub mod event_type {
    pub const ROOM_CREATE: &str = "room.create";
    pub const ROOM_JOIN: &str = "room.join";
    pub const ROOM_JOIN_REVIEW: &str = "room.join.review";
    pub const ROOM_LEAVE: &str = "room.leave";
    pub const ROOM_MEMBER_ROLE_UPDATE: &str = "room.member.role.update";
    pub const ROOM_CLOSE: &str = "room.close";
    pub const ROOM_CANCEL: &str = "room.cancel";
    pub const TYPE_DEFINE: &str = "type.define";
    pub const MESSAGE_CREATE: &str = "message.create";
}

pub const BUILTIN_EVENT_TYPES: [&str; 9] = [
    event_type::ROOM_CREATE,
    event_type::ROOM_JOIN,
    event_type::ROOM_JOIN_REVIEW,
    event_type::ROOM_LEAVE,
    event_type::ROOM_MEMBER_ROLE_UPDATE,
    event_type::ROOM_CLOSE,
    event_type::ROOM_CANCEL,
    event_type::TYPE_DEFINE,
    event_type::MESSAGE_CREATE,
];

/// Custom event types must not use these prefixes.
pub const RESERVED_TYPE_PREFIXES: [&str; 2] = ["room.", "type."];

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
    pub topic: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agenda: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guidance: Option<String>,
    pub visibility: Visibility,
    pub start_time: i64,
    pub end_time: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<RoomPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<TypeDeclaration>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
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
            guidance: None,
            visibility,
            start_time,
            end_time,
            tags: Vec::new(),
            language: None,
            policy: None,
            types: Vec::new(),
            extra: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct RoomPolicy {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub moderator_agent_ids: Vec<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_speakers: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observer_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl RoomPolicy {
    pub fn new() -> Self {
        Self::default()
    }
}

/// A room-scoped declaration of a custom event type.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TypeDef {
    #[serde(rename = "type")]
    pub name: String,
    pub kind: TypeKind,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Self-contained JSON Schema (draft 2020-12) for the event payload.
    pub schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<Role>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<TypeStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_hint: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_payload_hint: Option<u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub overrides: BTreeMap<String, TypeOverride>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guidance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<Visibility>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<RoomPolicy>,
    /// Materialized type registry served by the host.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<TypeDef>,
    pub seq: u64,
    #[serde(default)]
    pub pre_hash: Option<String>,
    pub hash: String,
    pub received_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope: Option<Envelope<RoomCreatePayload>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RoomJoinPayload {
    pub request_id: String,
    pub role: Role,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RoomJoinRequestInput {
    pub role: Role,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perspective: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl RoomJoinRequestInput {
    pub fn new(role: Role) -> Self {
        Self {
            role,
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
    pub role: Role,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perspective: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RoomJoinRequestStatus {
    pub request: RoomJoinRequest,
    pub status: JoinRequestStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_role: Option<Role>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_by: Option<AgentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RoomJoinReviewPayload {
    pub request: RoomJoinRequest,
    pub decision: JoinDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RoleUpdatePayload {
    pub member: AgentId,
    pub role: Role,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Shared payload of `room.leave`, `room.close`, and `room.cancel`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct ReasonPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

pub type RoomLeavePayload = ReasonPayload;
pub type RoomClosePayload = ReasonPayload;
pub type RoomCancelPayload = ReasonPayload;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MessageCreatePayload {
    pub content_type: String,
    pub content: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl MessageCreatePayload {
    pub fn new(content_type: impl Into<String>, content: Value) -> Self {
        Self {
            content_type: content_type.into(),
            content,
            references: Vec::new(),
            extra: BTreeMap::new(),
        }
    }

    pub fn text(text: impl Into<String>) -> Self {
        Self::new("text/plain", Value::String(text.into()))
    }

    pub fn markdown(markdown: impl Into<String>) -> Self {
        Self::new("text/markdown", Value::String(markdown.into()))
    }
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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub formats: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
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

pub fn type_define_event(
    actor: AgentId,
    created_at: i64,
    nonce: u64,
    room_id: impl Into<String>,
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

pub fn is_builtin_event_type(event_type: &str) -> bool {
    BUILTIN_EVENT_TYPES.contains(&event_type)
}

pub fn event_requires_room_id(event_type: &str) -> bool {
    event_type != event_type::ROOM_CREATE
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
    if envelope.event.kind == event_type::ROOM_CREATE {
        if envelope.event.room_id.is_some() {
            return Err(SdkError::InvalidPayload(
                "room.create must not include room_id".to_owned(),
            ));
        }
    } else if envelope.event.room_id.is_none() {
        return Err(SdkError::MissingRoomId);
    }
    Ok(())
}

pub fn validate_room_path<P>(envelope: &Envelope<P>, path_room_id: &str) -> Result<()> {
    if envelope.event.kind == event_type::ROOM_CREATE {
        return match envelope.event.room_id.as_deref() {
            None => Ok(()),
            Some(_) => Err(SdkError::InvalidPayload(
                "room.create must not include room_id".to_owned(),
            )),
        };
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

/// Checks the shape of a custom event type name: lowercase dot-separated,
/// at least two segments, not built-in, not under a reserved prefix.
pub fn validate_custom_event_type_name(name: &str) -> Result<()> {
    let segments: Vec<&str> = name.split('.').collect();
    let valid_shape = segments.len() >= 2
        && segments.iter().all(|segment| {
            let mut chars = segment.chars();
            matches!(chars.next(), Some(first) if first.is_ascii_lowercase() || first.is_ascii_digit())
                && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        });
    if !valid_shape {
        return Err(SdkError::InvalidPayload(format!(
            "invalid event type name: {name}"
        )));
    }
    if is_builtin_event_type(name) {
        return Err(SdkError::InvalidPayload(format!(
            "{name} is a built-in event type"
        )));
    }
    if RESERVED_TYPE_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
    {
        return Err(SdkError::InvalidPayload(format!(
            "{name} uses a reserved type prefix"
        )));
    }
    Ok(())
}

pub fn validate_type_def(def: &TypeDef) -> Result<()> {
    validate_custom_event_type_name(&def.name)?;
    if def.title.trim().is_empty() {
        return Err(SdkError::InvalidPayload(
            "type definition title must not be empty".to_owned(),
        ));
    }
    if !def.schema.is_object() {
        return Err(SdkError::InvalidPayload(
            "type definition schema must be a JSON Schema object".to_owned(),
        ));
    }
    compile_schema(&def.schema)?;
    if matches!(&def.roles, Some(roles) if roles.is_empty()) {
        return Err(SdkError::InvalidPayload(
            "type definition roles must not be empty".to_owned(),
        ));
    }
    if matches!(def.rate_hint, Some(0)) || matches!(def.max_payload_hint, Some(0)) {
        return Err(SdkError::InvalidPayload(
            "type definition hints must be positive".to_owned(),
        ));
    }
    Ok(())
}

pub fn validate_pack_import(import: &PackImport) -> Result<()> {
    match (&import.use_pack, &import.pack, &import.digest) {
        (Some(id), None, None) => {
            if !is_registered_pack_id(id) {
                return Err(SdkError::InvalidPayload(format!(
                    "invalid registered pack id: {id}"
                )));
            }
        }
        (None, Some(_), Some(digest)) => {
            if digest.trim().is_empty() {
                return Err(SdkError::InvalidPayload(
                    "external pack digest must not be empty".to_owned(),
                ));
            }
        }
        _ => {
            return Err(SdkError::InvalidPayload(
                "pack import requires either use, or pack with digest".to_owned(),
            ));
        }
    }
    if matches!(&import.types, Some(types) if types.is_empty()) {
        return Err(SdkError::InvalidPayload(
            "pack import types subset must not be empty".to_owned(),
        ));
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
        if matches!(policy.max_speakers, Some(0)) {
            return Err(SdkError::InvalidPayload(
                "max_speakers must be a positive integer".to_owned(),
            ));
        }
    }
    for declaration in &payload.types {
        validate_type_declaration(declaration)?;
    }
    Ok(())
}

pub fn validate_message_create_payload(payload: &MessageCreatePayload) -> Result<()> {
    if payload.content_type.trim().is_empty() {
        return Err(SdkError::InvalidPayload(
            "content_type must not be empty".to_owned(),
        ));
    }
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

    /// Materializes a registry from declarations, resolving pack imports from
    /// `packs`, keyed by registered pack id or external pack URI.
    pub fn from_declarations(
        declarations: &[TypeDeclaration],
        packs: &BTreeMap<String, Pack>,
    ) -> Result<Self> {
        let mut registry = Self::new();
        for declaration in declarations {
            registry.apply(declaration, packs)?;
        }
        Ok(registry)
    }

    /// Applies one declaration: an inline definition or a pack import.
    /// Redefining an existing type replaces it; the latest definition wins.
    pub fn apply(
        &mut self,
        declaration: &TypeDeclaration,
        packs: &BTreeMap<String, Pack>,
    ) -> Result<()> {
        match declaration {
            TypeDeclaration::Def(def) => self.define(def.clone()),
            TypeDeclaration::Import(import) => self.import(import, packs),
        }
    }

    pub fn define(&mut self, def: TypeDef) -> Result<()> {
        validate_type_def(&def)?;
        self.types.insert(def.name.clone(), def);
        Ok(())
    }

    fn import(&mut self, import: &PackImport, packs: &BTreeMap<String, Pack>) -> Result<()> {
        validate_pack_import(import)?;
        let reference = import
            .use_pack
            .as_deref()
            .or(import.pack.as_deref())
            .expect("validated pack import has a reference");
        let pack = packs
            .get(reference)
            .ok_or_else(|| SdkError::PackUnavailable(reference.to_owned()))?;
        let available: BTreeSet<&str> = pack.types.iter().map(|def| def.name.as_str()).collect();
        if let Some(subset) = &import.types {
            for name in subset {
                if !available.contains(name.as_str()) {
                    return Err(SdkError::PackUnavailable(format!(
                        "type {name} is not in pack {reference}"
                    )));
                }
            }
        }
        for name in import.overrides.keys() {
            let imported = import
                .types
                .as_ref()
                .map(|subset| subset.contains(name))
                .unwrap_or_else(|| available.contains(name.as_str()));
            if !imported {
                return Err(SdkError::InvalidPayload(format!(
                    "override target {name} is not imported from pack {reference}"
                )));
            }
        }
        for def in &pack.types {
            if let Some(subset) = &import.types {
                if !subset.contains(&def.name) {
                    continue;
                }
            }
            let mut def = def.clone();
            if let Some(over) = import.overrides.get(&def.name) {
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
            self.define(def)?;
        }
        Ok(())
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
    jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .build(schema)
        .map_err(|err| SdkError::InvalidPayload(format!("invalid type schema: {err}")))
}

/// Verifies a `<algorithm>:<base64url-digest>` content digest over raw bytes.
/// Supports `sha256` and `sha3-256`.
pub fn verify_pack_digest(bytes: &[u8], digest: &str) -> Result<()> {
    let (algorithm, expected) = digest.split_once(':').ok_or_else(|| {
        SdkError::PackUnavailable(format!("invalid digest format: {digest}"))
    })?;
    let actual = match algorithm {
        "sha256" => URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)),
        "sha3-256" => URL_SAFE_NO_PAD.encode(Sha3_256::digest(bytes)),
        _ => {
            return Err(SdkError::PackUnavailable(format!(
                "unsupported digest algorithm: {algorithm}"
            )));
        }
    };
    if actual == expected {
        Ok(())
    } else {
        Err(SdkError::PackUnavailable(
            "pack digest mismatch".to_owned(),
        ))
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

/// Permission inputs for one actor in one room.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PermissionContext {
    pub role: Option<Role>,
    pub is_creator: bool,
    pub join_request_approved: bool,
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
        TypeKind::Signal => &[Role::Moderator, Role::Speaker, Role::Observer],
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
        event_type::ROOM_JOIN => context.join_request_approved,
        event_type::ROOM_LEAVE => context.is_creator || context.role.is_some(),
        event_type::ROOM_JOIN_REVIEW
        | event_type::ROOM_MEMBER_ROLE_UPDATE
        | event_type::ROOM_CLOSE
        | event_type::ROOM_CANCEL
        | event_type::TYPE_DEFINE => {
            context.is_creator || context.role == Some(Role::Moderator)
        }
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
            event_type::ROOM_JOIN
                | event_type::ROOM_JOIN_REVIEW
                | event_type::ROOM_MEMBER_ROLE_UPDATE
                | event_type::ROOM_LEAVE
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

    fn registered_packs() -> BTreeMap<String, Pack> {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/protocols/agent-discourse/1.0.packs.json"
        ))
        .expect("read registered packs");
        let document: PackDocument = serde_json::from_str(&raw).expect("parse registered packs");
        assert_eq!(document.protocol, PROTOCOL);
        pack_map(&document)
    }

    fn finding_def() -> TypeDef {
        TypeDef {
            name: "review.finding".to_owned(),
            kind: TypeKind::Message,
            title: "Review finding".to_owned(),
            description: None,
            schema: json!({
                "type": "object",
                "required": ["severity", "summary"],
                "properties": {
                    "severity": {"type": "string", "enum": ["low", "medium", "high"]},
                    "summary": {"type": "string", "minLength": 1}
                },
                "additionalProperties": false
            }),
            roles: None,
            instructions: None,
            version: None,
            status: None,
            rate_hint: None,
            max_payload_hint: None,
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn validates_room_create_without_room_id() {
        let signer = AgentSigner::from_seed([14; 32]);
        let payload = RoomCreatePayload::new("Research room", Visibility::Public, 1000, 2000);
        let envelope = signer
            .sign_event(room_create_event(signer.agent_id(), 100, 1, payload))
            .unwrap();

        validate_discourse_envelope(&envelope).unwrap();
        validate_room_path(&envelope, "d8ftedhpqhsusbg001tg").unwrap();
    }

    #[test]
    fn rejects_room_create_with_room_id() {
        let signer = AgentSigner::from_seed([14; 32]);
        let payload = RoomCreatePayload::new("Research room", Visibility::Public, 1000, 2000);
        let event = room_create_event(signer.agent_id(), 100, 1, payload)
            .with_room_id("d8ftedhpqhsusbg001tg");
        let envelope = signer.sign_event(event).unwrap();

        assert!(matches!(
            validate_discourse_envelope(&envelope),
            Err(SdkError::InvalidPayload(_))
        ));
        assert!(validate_room_path(&envelope, "d8ftedhpqhsusbg001tg").is_err());
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
    fn validates_join_review_canonical_request() {
        let moderator = AgentSigner::from_seed([21; 32]);
        let applicant = AgentSigner::from_seed([22; 32]);
        let payload = RoomJoinReviewPayload {
            request: RoomJoinRequest {
                id: "jr_01J8ZM7A3G2T9B4Q6X8R0N1P2Q".to_owned(),
                room_id: "d8ftedhpqhsusbg001tg".to_owned(),
                applicant: applicant.agent_id(),
                role: Role::Speaker,
                perspective: Some("distributed-systems reviewer".to_owned()),
                reason: Some("I can cover replication and failure-mode tradeoffs.".to_owned()),
                created_at: 1_779_757_210_000,
                expires_at: 1_779_760_810_000,
                extra: BTreeMap::new(),
            },
            decision: JoinDecision::Approve,
            role: Some(Role::Speaker),
            reason: Some("relevant expertise".to_owned()),
            extra: BTreeMap::new(),
        };
        let envelope = moderator
            .sign_event(discourse_event(
                event_type::ROOM_JOIN_REVIEW,
                moderator.agent_id(),
                1_779_757_250_000,
                1,
                "d8ftedhpqhsusbg001tg",
                payload.clone(),
            ))
            .unwrap();

        validate_discourse_envelope(&envelope).unwrap();
        let value = serde_json::to_value(payload).unwrap();
        assert!(value.get("member").is_none());
        assert_eq!(
            value["request"]["applicant"],
            json!(applicant.agent_id().to_string())
        );
        assert_eq!(value["request"]["role"], json!("speaker"));
    }

    #[test]
    fn role_serde_matches_spec() {
        assert_eq!(serde_json::to_string(&Role::Speaker).unwrap(), "\"speaker\"");
        assert!(serde_json::from_str::<Role>("\"expert\"").is_err());
        assert!(serde_json::from_str::<Role>("\"participant\"").is_err());
    }

    #[test]
    fn validates_custom_event_type_names() {
        validate_custom_event_type_name("review.finding").unwrap();
        validate_custom_event_type_name("poll.vote").unwrap();
        assert!(validate_custom_event_type_name("freeform").is_err());
        assert!(validate_custom_event_type_name("room.custom").is_err());
        assert!(validate_custom_event_type_name("type.new").is_err());
        assert!(validate_custom_event_type_name("message.create").is_err());
        assert!(validate_custom_event_type_name("Bad.Name").is_err());
    }

    #[test]
    fn materializes_registry_from_packs_and_inline_defs() {
        let packs = registered_packs();
        let declarations = vec![
            TypeDeclaration::Import(PackImport {
                use_pack: Some(pack_id::REACTIONS.to_owned()),
                ..PackImport::default()
            }),
            TypeDeclaration::Import(PackImport {
                use_pack: Some(pack_id::DELIBERATION.to_owned()),
                overrides: BTreeMap::from([(
                    "poll.vote".to_owned(),
                    TypeOverride {
                        roles: Some(vec![Role::Moderator, Role::Speaker, Role::Observer]),
                        ..TypeOverride::default()
                    },
                )]),
                ..PackImport::default()
            }),
            TypeDeclaration::Def(finding_def()),
        ];
        let registry = TypeRegistry::from_declarations(&declarations, &packs).unwrap();

        assert_eq!(registry.len(), 6);
        assert!(registry.contains("reaction.create"));
        assert!(registry.contains("poll.create"));
        assert!(registry.contains("review.finding"));
        let vote = registry.get("poll.vote").unwrap();
        assert_eq!(
            vote.roles.as_deref(),
            Some([Role::Moderator, Role::Speaker, Role::Observer].as_slice())
        );

        let subset = TypeDeclaration::Import(PackImport {
            use_pack: Some(pack_id::DELIBERATION.to_owned()),
            types: Some(vec!["poll.create".to_owned(), "poll.vote".to_owned()]),
            ..PackImport::default()
        });
        let registry = TypeRegistry::from_declarations(&[subset], &packs).unwrap();
        assert_eq!(registry.len(), 2);
        assert!(!registry.contains("question.create"));
    }

    #[test]
    fn rejects_bad_pack_imports() {
        let packs = registered_packs();
        let unknown = TypeDeclaration::Import(PackImport {
            use_pack: Some("adp:unknown/1.0".to_owned()),
            ..PackImport::default()
        });
        assert!(matches!(
            TypeRegistry::from_declarations(&[unknown], &packs),
            Err(SdkError::PackUnavailable(_))
        ));

        let bad_override = TypeDeclaration::Import(PackImport {
            use_pack: Some(pack_id::REACTIONS.to_owned()),
            overrides: BTreeMap::from([("poll.vote".to_owned(), TypeOverride::default())]),
            ..PackImport::default()
        });
        assert!(TypeRegistry::from_declarations(&[bad_override], &packs).is_err());

        let both = PackImport {
            use_pack: Some(pack_id::REACTIONS.to_owned()),
            pack: Some("https://example.com/p.json".to_owned()),
            digest: Some("sha256:abc".to_owned()),
            ..PackImport::default()
        };
        assert!(validate_pack_import(&both).is_err());
    }

    #[test]
    fn latest_type_definition_wins() {
        let mut registry = TypeRegistry::new();
        registry.define(finding_def()).unwrap();
        let mut redefined = finding_def();
        redefined.status = Some(TypeStatus::Disabled);
        registry.define(redefined).unwrap();
        assert_eq!(
            registry.get("review.finding").unwrap().status(),
            TypeStatus::Disabled
        );
    }

    #[test]
    fn validates_custom_payloads_against_pack_schemas() {
        let packs = registered_packs();
        let registry = TypeRegistry::from_declarations(
            &[TypeDeclaration::Import(PackImport {
                use_pack: Some(pack_id::DELIBERATION.to_owned()),
                ..PackImport::default()
            })],
            &packs,
        )
        .unwrap();

        let hash = "GDt8oHZQfQ3jl5ZUfyNxKZu07yAJdDYuaw_jf_JjLYs";
        registry
            .validate_payload(
                "poll.vote",
                &json!({"poll_event_id": hash, "option_ids": ["a"]}),
            )
            .unwrap();
        assert!(matches!(
            registry.validate_payload("poll.vote", &json!({"poll_event_id": hash})),
            Err(SdkError::PayloadSchemaViolation(_))
        ));
        assert!(matches!(
            registry.validate_payload("turn.update", &json!({})),
            Err(SdkError::TypeNotDefined(_))
        ));

        let mut disabled = TypeRegistry::new();
        let mut def = finding_def();
        def.status = Some(TypeStatus::Disabled);
        disabled.define(def).unwrap();
        assert!(matches!(
            disabled.validate_payload("review.finding", &json!({"severity": "high", "summary": "s"})),
            Err(SdkError::TypeDisabled(_))
        ));
    }

    #[test]
    fn applies_kind_based_permissions() {
        let packs = registered_packs();
        let registry = TypeRegistry::from_declarations(
            &[
                TypeDeclaration::Import(PackImport {
                    use_pack: Some(pack_id::REACTIONS.to_owned()),
                    ..PackImport::default()
                }),
                TypeDeclaration::Import(PackImport {
                    use_pack: Some(pack_id::DELIBERATION.to_owned()),
                    overrides: BTreeMap::from([(
                        "poll.vote".to_owned(),
                        TypeOverride {
                            roles: Some(vec![Role::Moderator, Role::Speaker, Role::Observer]),
                            ..TypeOverride::default()
                        },
                    )]),
                    ..PackImport::default()
                }),
                TypeDeclaration::Import(PackImport {
                    use_pack: Some(pack_id::CURATION.to_owned()),
                    ..PackImport::default()
                }),
            ],
            &packs,
        )
        .unwrap();

        let observer = PermissionContext::for_role(Role::Observer);
        let speaker = PermissionContext::for_role(Role::Speaker);
        let moderator = PermissionContext::for_role(Role::Moderator);
        let creator = PermissionContext::creator(Some(Role::Observer));

        // signal kind: all members, including observers
        assert!(can_submit_event("reaction.create", &observer, &registry));
        // poll.vote default excludes observers, but this room overrode roles
        assert!(can_submit_event("poll.vote", &observer, &registry));
        // message kind: speakers and moderators only
        assert!(can_submit_event("resource.add", &speaker, &registry));
        assert!(!can_submit_event("resource.add", &observer, &registry));
        // control kind: moderators only
        assert!(can_submit_event("graph.update", &moderator, &registry));
        assert!(!can_submit_event("graph.update", &speaker, &registry));
        // creator passes every role check regardless of current role
        assert!(can_submit_event("graph.update", &creator, &registry));
        assert!(can_submit_event(event_type::MESSAGE_CREATE, &creator, &registry));
        // undefined types are rejected
        assert!(!can_submit_event("session.offer", &speaker, &registry));

        // built-in lifecycle rules
        assert!(can_submit_event(event_type::ROOM_JOIN_REVIEW, &moderator, &registry));
        assert!(!can_submit_event(event_type::ROOM_JOIN_REVIEW, &speaker, &registry));
        assert!(can_submit_event(event_type::ROOM_MEMBER_ROLE_UPDATE, &moderator, &registry));
        assert!(can_submit_event(event_type::ROOM_CANCEL, &moderator, &registry));
        assert!(can_submit_event(event_type::TYPE_DEFINE, &moderator, &registry));
        assert!(!can_submit_event(event_type::TYPE_DEFINE, &speaker, &registry));
        assert!(can_submit_event(event_type::MESSAGE_CREATE, &speaker, &registry));
        assert!(!can_submit_event(event_type::MESSAGE_CREATE, &observer, &registry));
        assert!(can_submit_event(event_type::ROOM_LEAVE, &observer, &registry));
        assert!(!can_submit_event(event_type::ROOM_JOIN, &observer, &registry));
        let approved = PermissionContext {
            join_request_approved: true,
            ..PermissionContext::default()
        };
        assert!(can_submit_event(event_type::ROOM_JOIN, &approved, &registry));
    }

    #[test]
    fn applies_state_restrictions() {
        let registry = TypeRegistry::new();
        let speaker = PermissionContext::for_role(Role::Speaker);
        let moderator = PermissionContext::for_role(Role::Moderator);

        assert!(can_accept_room_write(
            event_type::MESSAGE_CREATE,
            RoomState::Active,
            &speaker,
            &registry
        ));
        assert!(!can_accept_room_write(
            event_type::MESSAGE_CREATE,
            RoomState::Scheduled,
            &speaker,
            &registry
        ));
        // scheduled allows pre-start setup: reviews, role updates, leave, type.define
        assert!(can_write_in_state(event_type::ROOM_JOIN_REVIEW, RoomState::Scheduled));
        assert!(can_write_in_state(event_type::ROOM_MEMBER_ROLE_UPDATE, RoomState::Scheduled));
        assert!(can_write_in_state(event_type::ROOM_LEAVE, RoomState::Scheduled));
        assert!(can_write_in_state(event_type::TYPE_DEFINE, RoomState::Scheduled));
        assert!(can_write_in_state(event_type::ROOM_CANCEL, RoomState::Scheduled));
        assert!(!can_write_in_state(event_type::ROOM_CLOSE, RoomState::Scheduled));
        assert!(can_accept_room_write(
            event_type::TYPE_DEFINE,
            RoomState::Scheduled,
            &moderator,
            &registry
        ));
        // ended rooms are strictly read-only
        assert!(!can_write_in_state("reaction.create", RoomState::Ended));
        assert!(!can_write_in_state(event_type::ROOM_LEAVE, RoomState::Ended));
        assert!(!can_write_in_state(event_type::ROOM_JOIN, RoomState::Cancelled));
        // cancel only while scheduled, close only while active
        assert!(can_write_in_state(event_type::ROOM_CLOSE, RoomState::Active));
        assert!(!can_write_in_state(event_type::ROOM_CANCEL, RoomState::Active));
    }

    #[test]
    fn validates_room_creation_payloads() {
        let mut payload = RoomCreatePayload::new("Research room", Visibility::Public, 1000, 2000);
        payload.policy = Some(RoomPolicy {
            max_speakers: Some(2),
            ..RoomPolicy::default()
        });
        payload.guidance = Some("Cite sources.".to_owned());
        payload.types = vec![
            TypeDeclaration::Import(PackImport {
                use_pack: Some(pack_id::REACTIONS.to_owned()),
                ..PackImport::default()
            }),
            TypeDeclaration::Def(finding_def()),
        ];
        validate_room_create_payload(&payload).unwrap();

        let empty_topic = RoomCreatePayload::new(" ", Visibility::Public, 1000, 2000);
        assert!(validate_room_create_payload(&empty_topic).is_err());

        let invalid_time = RoomCreatePayload::new("Research room", Visibility::Public, 2000, 1000);
        assert!(validate_room_create_payload(&invalid_time).is_err());

        let mut zero_speakers =
            RoomCreatePayload::new("Research room", Visibility::Public, 1000, 2000);
        zero_speakers.policy = Some(RoomPolicy {
            max_speakers: Some(0),
            ..RoomPolicy::default()
        });
        assert!(validate_room_create_payload(&zero_speakers).is_err());

        let mut reserved = RoomCreatePayload::new("Research room", Visibility::Public, 1000, 2000);
        let mut bad_def = finding_def();
        bad_def.name = "room.custom".to_owned();
        reserved.types = vec![TypeDeclaration::Def(bad_def)];
        assert!(validate_room_create_payload(&reserved).is_err());
    }

    #[test]
    fn verifies_pack_digests() {
        let bytes = b"pack document bytes";
        let digest = format!("sha256:{}", URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)));
        verify_pack_digest(bytes, &digest).unwrap();
        assert!(matches!(
            verify_pack_digest(b"tampered", &digest),
            Err(SdkError::PackUnavailable(_))
        ));
        assert!(verify_pack_digest(bytes, "md5:abc").is_err());
        assert!(verify_pack_digest(bytes, "not-a-digest").is_err());
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

    #[test]
    fn type_declaration_serde_round_trips() {
        let inline: TypeDeclaration = serde_json::from_value(json!({
            "type": "review.finding",
            "kind": "message",
            "title": "Review finding",
            "schema": {"type": "object"}
        }))
        .unwrap();
        assert!(matches!(inline, TypeDeclaration::Def(_)));

        let import: TypeDeclaration = serde_json::from_value(json!({
            "use": "adp:reactions/1.0",
            "overrides": {"reaction.create": {"status": "deprecated"}}
        }))
        .unwrap();
        match &import {
            TypeDeclaration::Import(import) => {
                assert_eq!(import.use_pack.as_deref(), Some("adp:reactions/1.0"));
            }
            TypeDeclaration::Def(_) => panic!("expected pack import"),
        }
        validate_type_declaration(&import).unwrap();
    }
}
