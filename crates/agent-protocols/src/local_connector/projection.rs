//! Pure room-state projection: the ADP rules that turn an accepted
//! [`ServerRecord`] into member, timeline, contract, and inbox changes on a
//! [`LocalRoomState`], plus the local-chain validation that gates them. Every
//! function here is a plain transform over borrowed state — no signing, no
//! network — which is what makes the connector's projection behaviour testable
//! in isolation.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::discourse::{
    event_type, JoinDecision, RoleUpdatePayload, RoomJoinPayload, RoomJoinReviewPayload, RoomState,
    Role, ServerRecord, TypeDeclaration,
};
use crate::error::{Result, SdkError};
use crate::identity::AgentId;

use super::catalog::TOOL_ROOM_SEND_MESSAGE;
use super::state::{InboxEntry, InboxEntryState, LocalRoomState};
use super::views::{
    ActiveTurn, InboxItem, InboxKind, InboxPriority, RoomMemberStatus, RoomMemberView, TimelineItem,
};

pub(crate) fn record_advances_room_head(room: &LocalRoomState, record: &ServerRecord) -> bool {
    event_type_advances_room_head(room, record.envelope.event.kind.as_str())
}

/// ADP Section 6.1: room lifecycle, `message`-kind, and `control`-kind records
/// advance the room head. `signal`-kind records — including the built-in
/// membership events — only anchor to an accepted record.
pub(crate) fn event_type_advances_room_head(room: &LocalRoomState, event_type: &str) -> bool {
    if let Some(class) = crate::discourse::builtin_event_class(event_type) {
        return class != crate::discourse::BuiltinEventClass::Signal;
    }
    room.room
        .types
        .iter()
        .find(|definition| definition.name == event_type)
        .map(|definition| definition.kind != crate::discourse::TypeKind::Signal)
        .unwrap_or(true)
}

pub(crate) fn materialize_creator(room: &mut LocalRoomState) {
    let creator = match (
        room.room.creator.clone(),
        room.room
            .envelope
            .as_ref()
            .map(|envelope| envelope.event.actor.clone()),
    ) {
        (Some(creator), _) => creator,
        (None, Some(creator)) => creator,
        (None, None) => return,
    };
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

/// Applies an accepted `room.update` to the local room contract. A present
/// field replaces the current value entirely; an empty value clears an
/// optional field.
fn apply_room_update(
    room: &mut LocalRoomState,
    payload: &crate::discourse::RoomUpdatePayload,
    received_at: i64,
) {
    let response = &mut room.room;
    if let Some(topic) = &payload.topic {
        response.topic = Some(topic.clone());
    }
    if let Some(agenda) = &payload.agenda {
        response.agenda = (!agenda.is_empty()).then(|| agenda.clone());
    }
    if let Some(guidance) = &payload.guidance {
        response.guidance = (!guidance.is_empty()).then(|| guidance.clone());
    }
    if let Some(tags) = &payload.tags {
        response.tags = tags.clone();
    }
    if let Some(language) = &payload.language {
        response.language = (!language.is_empty()).then(|| language.clone());
    }
    if let Some(policy) = &payload.policy {
        // A present field replaces the current value entirely; a policy that
        // happens to equal the default is still an explicit revision, not a
        // clear, so store it verbatim.
        response.policy = Some(policy.clone());
    }
    if let Some(start_time) = payload.start_time {
        response.start_time = Some(start_time);
        // A scheduled room whose new start_time is at or before acceptance
        // time becomes active.
        if response.status == RoomState::Scheduled && start_time <= received_at {
            response.status = RoomState::Active;
        }
    }
    if let Some(end_time) = payload.end_time {
        response.end_time = Some(end_time);
    }
}

pub(crate) fn is_duplicate_record(room: &LocalRoomState, record: &ServerRecord) -> bool {
    record.seq <= room.synced_seq
        && room
            .records
            .iter()
            .any(|existing| existing.seq == record.seq && existing.hash == record.hash)
}

pub(crate) fn validate_next_record(room: &LocalRoomState, record: &ServerRecord) -> Result<()> {
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

pub(crate) fn validate_record_base_precondition(
    room: &LocalRoomState,
    record: &ServerRecord,
) -> Result<()> {
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

pub(crate) fn apply_record_projection(
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
        event_type::ROOM_UPDATE => {
            let payload: crate::discourse::RoomUpdatePayload =
                serde_json::from_value(event.payload.clone())?;
            apply_room_update(room, &payload, record.received_at);
            inbox.push(inbox_from_item(
                InboxKind::RoomStateChanged,
                InboxPriority::Normal,
                item,
                "room_updated",
                false,
            ));
        }
        event_type::ROOM_MEMBER_REMOVE => {
            let payload: crate::discourse::RoomMemberRemovePayload =
                serde_json::from_value(event.payload.clone())?;
            let status = if payload.banning() {
                RoomMemberStatus::Banned
            } else {
                RoomMemberStatus::Removed
            };
            room.members
                .entry(payload.member.clone())
                .and_modify(|member| {
                    member.status = status;
                    member.left_seq = Some(record.seq);
                    member.last_event_seq = Some(record.seq);
                })
                .or_insert_with(|| RoomMemberView {
                    // A `ban: true` remove may target a non-member as a
                    // pre-emptive ban; it never had a real role.
                    agent_id: payload.member.clone(),
                    role: Role::Observer,
                    status,
                    is_creator: false,
                    perspective: None,
                    joined_seq: None,
                    left_seq: Some(record.seq),
                    last_event_seq: Some(record.seq),
                    profile: None,
                    extra: BTreeMap::new(),
                });
            if payload.member == *active_agent {
                inbox.push(inbox_from_item(
                    InboxKind::RoomMemberRemoved,
                    InboxPriority::High,
                    item,
                    if payload.banning() {
                        "member_banned"
                    } else {
                        "member_removed"
                    },
                    false,
                ));
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

pub(crate) fn inbox_entry_ready(entry: &InboxEntry, now_ms: i64) -> bool {
    match entry.state {
        InboxEntryState::Pending => true,
        InboxEntryState::Deferred(until) => until <= now_ms,
        InboxEntryState::Claimed | InboxEntryState::Acknowledged => false,
    }
}
