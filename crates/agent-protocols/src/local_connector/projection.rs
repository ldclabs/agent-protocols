//! Pure room-state projection: the ADP Section 5.1 rules that turn an accepted
//! [`ArchiveRecord`] into member, timeline, contract, and inbox changes on a
//! [`LocalRoomState`], plus the local-chain validation that gates them and the
//! read-side predicates over room state. Every function here is a plain
//! transform over borrowed state — no signing, no network — which is what
//! makes the connector's projection behaviour testable in isolation.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::discourse::{
    event_requires_room_head, event_type, event_type_advances_head, ArchiveRecord, JoinDecision,
    Role, RoleUpdatePayload, RoomJoinPayload, RoomJoinReviewPayload, RoomMemberRemovePayload,
    RoomState, RoomUpdatePayload, TypeDeclaration,
};
use crate::error::{Result, SdkError};
use crate::identity::AgentId;

use super::catalog::TOOL_ROOM_SEND_MESSAGE;
use super::inputs::RoomsListMembership;
use super::state::{InboxEntry, InboxEntryState, LocalRoomState};
use super::views::{
    ActiveTurn, InboxItem, InboxKind, InboxPriority, RoomMemberStatus, RoomMemberView, TimelineItem,
};

pub(crate) fn record_advances_room_head(room: &LocalRoomState, record: &ArchiveRecord) -> bool {
    event_type_advances_room_head(room, record.event_type())
}

/// Every record class except `signal` advances the room head.
pub(crate) fn event_type_advances_room_head(room: &LocalRoomState, event_type: &str) -> bool {
    event_type_advances_head(event_type, &room.room.types)
}

/// Head-bound writes — `message.create` and `message`/`control` kinds — must match the head.
pub(crate) fn event_type_requires_room_head(room: &LocalRoomState, event_type: &str) -> bool {
    event_requires_room_head(event_type, &room.room.types)
}

pub(crate) fn materialize_creator(room: &mut LocalRoomState) {
    let Some(creator) = room.room.creator.clone().or_else(|| {
        room.room
            .envelope
            .as_ref()
            .map(|envelope| envelope.event.actor.clone())
    }) else {
        return;
    };
    room.members.entry(creator.clone()).or_insert_with(|| {
        member(
            creator,
            Role::Moderator,
            RoomMemberStatus::Active,
            true,
            Some(1),
            None,
            1,
        )
    });
}

fn member(
    agent_id: AgentId,
    role: Role,
    status: RoomMemberStatus,
    is_creator: bool,
    joined_seq: Option<u64>,
    left_seq: Option<u64>,
    last_event_seq: u64,
) -> RoomMemberView {
    RoomMemberView {
        agent_id,
        role,
        status,
        is_creator,
        perspective: None,
        joined_seq,
        left_seq,
        last_event_seq: Some(last_event_seq),
        profile: None,
        extra: BTreeMap::new(),
    }
}

/// Applies an accepted `room.update` to the local room contract. A present
/// field replaces the current value entirely; an empty value clears an
/// optional field.
fn apply_room_update(room: &mut LocalRoomState, payload: &RoomUpdatePayload, accepted_at: i64) {
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
        // An all-default policy is still an explicit revision: store it verbatim.
        response.policy = Some(policy.clone());
    }
    if let Some(start_time) = payload.start_time {
        response.start_time = Some(start_time);
        // A scheduled room whose new start_time is at or before acceptance
        // becomes active.
        if response.status == RoomState::Scheduled && start_time <= accepted_at {
            response.status = RoomState::Active;
        }
    }
    if let Some(end_time) = payload.end_time {
        response.end_time = Some(end_time);
    }
}

pub(crate) fn is_duplicate_record(room: &LocalRoomState, record: &ArchiveRecord) -> bool {
    record.seq() <= room.synced_seq
        && room
            .records
            .iter()
            .any(|existing| existing.seq() == record.seq() && existing.hash() == record.hash())
}

pub(crate) fn validate_next_record(room: &LocalRoomState, record: &ArchiveRecord) -> Result<()> {
    if room.synced_seq == 0 {
        if record.seq() != 1 || record.pre_hash().is_some() {
            return Err(invalid(
                "first local record must have seq 1 and null pre_hash",
            ));
        }
        return Ok(());
    }
    if record.seq() != room.synced_seq + 1 {
        return Err(invalid("record seq must continue local chain"));
    }
    if record.pre_hash() != room.synced_hash.as_deref() {
        return Err(invalid("record pre_hash mismatch"));
    }
    Ok(())
}

/// Section 5.1 base check against local state: head-bound records must name
/// the current head; contract and signal records must name an earlier accepted
/// record. A redacted record's base is not visible and is not checked.
pub(crate) fn validate_record_base_precondition(
    room: &LocalRoomState,
    record: &ArchiveRecord,
) -> Result<()> {
    let ArchiveRecord::Signed(signed) = record else {
        return Ok(());
    };
    let event = &signed.envelope.event;
    if event.kind == event_type::ROOM_CREATE {
        return Ok(());
    }
    if event.kind == event_type::ROOM_JOIN_REQUEST {
        return Err(invalid("a room.join.request is never a record"));
    }
    let base_seq = event
        .base_seq
        .ok_or_else(|| invalid("record event requires base_seq"))?;
    let base_hash = event
        .base_hash
        .as_deref()
        .ok_or_else(|| invalid("record event requires base_hash"))?;
    if base_seq >= signed.seq {
        return Err(invalid(
            "record base_seq must reference an earlier accepted record",
        ));
    }
    if event_type_requires_room_head(room, &event.kind) {
        if room.head_seq != base_seq || room.head_hash.as_deref() != Some(base_hash) {
            return Err(invalid(
                "record base_seq/base_hash must match current room head",
            ));
        }
        return Ok(());
    }
    if let Some(anchor) = room
        .records
        .iter()
        .find(|existing| existing.seq() == base_seq)
    {
        if anchor.hash() != base_hash {
            return Err(invalid(
                "record base_hash does not match the anchored record",
            ));
        }
    }
    Ok(())
}

pub(crate) fn apply_record_projection(
    room: &mut LocalRoomState,
    record: &ArchiveRecord,
    item: &TimelineItem,
    active_agent: &AgentId,
    inbox: &mut Vec<InboxItem>,
) -> Result<()> {
    let ArchiveRecord::Signed(signed) = record else {
        return Ok(());
    };
    let event = &signed.envelope.event;
    let seq = signed.seq;
    match event.kind.as_str() {
        event_type::ROOM_JOIN => {
            let payload: RoomJoinPayload = serde_json::from_value(event.payload.clone())?;
            let mut joined = member(
                event.actor.clone(),
                payload.role,
                RoomMemberStatus::Active,
                false,
                Some(seq),
                None,
                seq,
            );
            joined.perspective = payload.perspective;
            room.members.insert(event.actor.clone(), joined);
        }
        event_type::ROOM_LEAVE => {
            if let Some(member) = room.members.get_mut(&event.actor) {
                member.status = RoomMemberStatus::Left;
                member.left_seq = Some(seq);
                member.last_event_seq = Some(seq);
            }
        }
        event_type::ROOM_MEMBER_ROLE_UPDATE => {
            let payload: RoleUpdatePayload = serde_json::from_value(event.payload.clone())?;
            if let Some(member) = room.members.get_mut(&payload.member) {
                member.role = payload.role;
                member.last_event_seq = Some(seq);
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
            let payload: RoomUpdatePayload = serde_json::from_value(event.payload.clone())?;
            apply_room_update(room, &payload, signed.accepted_at);
            inbox.push(inbox_from_item(
                InboxKind::RoomStateChanged,
                InboxPriority::Normal,
                item,
                "room_updated",
                false,
            ));
        }
        event_type::ROOM_MEMBER_REMOVE => {
            let payload: RoomMemberRemovePayload = serde_json::from_value(event.payload.clone())?;
            let status = if payload.banning() {
                RoomMemberStatus::Banned
            } else {
                RoomMemberStatus::Removed
            };
            room.members
                .entry(payload.member.clone())
                .and_modify(|member| {
                    member.status = status;
                    member.left_seq = Some(seq);
                    member.last_event_seq = Some(seq);
                })
                // A `ban: true` remove may target a non-member as a
                // pre-emptive ban; it never had a real role.
                .or_insert_with(|| {
                    member(
                        payload.member.clone(),
                        Role::Observer,
                        status,
                        false,
                        None,
                        Some(seq),
                        seq,
                    )
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
            }
            inbox.push(inbox_from_item(
                InboxKind::RoomStateChanged,
                InboxPriority::Normal,
                item,
                "type_registry_changed",
                false,
            ));
        }
        event_type::ROOM_JOIN_REVIEW => {
            let payload: RoomJoinReviewPayload = serde_json::from_value(event.payload.clone())?;
            if let (JoinDecision::Approve, Some(role)) = (payload.decision, payload.role) {
                // The review record is the approved applicant's membership event.
                let request = &payload.request.event;
                let mut approved = member(
                    request.actor.clone(),
                    role,
                    RoomMemberStatus::Active,
                    false,
                    Some(seq),
                    None,
                    seq,
                );
                approved.perspective = request.payload.perspective.clone();
                room.members.insert(request.actor.clone(), approved);
                if request.actor == *active_agent {
                    inbox.push(inbox_from_item(
                        InboxKind::RoomJoinApproved,
                        InboxPriority::High,
                        item,
                        "join_approved",
                        false,
                    ));
                }
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
        "steer.create" if steer_targets_agent(&event.payload, active_agent) => {
            inbox.push(inbox_from_item(
                InboxKind::RoomSteer,
                InboxPriority::High,
                item,
                "steer",
                true,
            ));
        }
        _ => {}
    }
    Ok(())
}

fn active_turn_from_item(item: &TimelineItem) -> Option<ActiveTurn> {
    let payload = item.payload.as_ref()?;
    let speaker = payload.get("speaker")?.as_str()?.parse().ok()?;
    let turn_id = payload.get("turn_id")?.as_u64()?;
    let text = |field: &str| {
        payload
            .get(field)
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    Some(ActiveTurn {
        turn_id,
        speaker,
        assigned_seq: item.seq,
        expires_at: payload.get("expires_at").and_then(Value::as_i64),
        intent: text("intent"),
        topic: text("topic"),
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
        actor: item.actor.clone(),
        created_at: item.accepted_at,
        requires_response,
        deadline: None,
        reason: reason.to_owned(),
        suggested_tools,
        message: Some(json!({ "summary": item.summary })),
    }
}

/// Pending, due deferred, and claimed-but-expired entries are ready.
pub(crate) fn inbox_entry_ready(entry: &InboxEntry, now_ms: i64) -> bool {
    match entry.state {
        InboxEntryState::Pending => true,
        InboxEntryState::Deferred(until) | InboxEntryState::Claimed(until) => until <= now_ms,
        InboxEntryState::Acknowledged => false,
    }
}

pub(crate) fn membership_filter(
    room: &LocalRoomState,
    agent_id: &AgentId,
    membership: Option<RoomsListMembership>,
    pending: bool,
) -> bool {
    let member = room.members.get(agent_id);
    match membership.unwrap_or(RoomsListMembership::All) {
        RoomsListMembership::All => true,
        RoomsListMembership::Member => {
            member.is_some_and(|member| member.status == RoomMemberStatus::Active)
        }
        RoomsListMembership::Creator => member.is_some_and(|member| member.is_creator),
        RoomsListMembership::Moderator => {
            member.is_some_and(|member| member.role == Role::Moderator)
        }
        RoomsListMembership::Pending => pending,
    }
}

/// Presents the head at `seq`, which must be a known head-advancing record or
/// the current head (local connector Section 4.2).
pub(crate) fn present_head(room: &mut LocalRoomState, seq: u64) {
    if seq == 0 {
        return;
    }
    let hash = if seq == room.head_seq {
        room.head_hash.clone()
    } else {
        room.records
            .iter()
            .find(|record| record.seq() == seq)
            .map(|record| record.hash().to_owned())
    };
    if let Some(hash) = hash {
        room.presented_seq = Some(seq);
        room.presented_hash = Some(hash);
    }
}

/// Presents the latest head-advancing record at or before `seq`, if it moves
/// the presented head forward.
pub(crate) fn present_through(room: &mut LocalRoomState, seq: u64) {
    let base = room.presented_seq.unwrap_or(0);
    let found = (base + 1..=seq.min(room.synced_seq)).rev().find_map(|s| {
        room.records
            .iter()
            .find(|record| record.seq() == s)
            .filter(|record| record_advances_room_head(room, record))
            .map(|record| (s, record.hash().to_owned()))
    });
    if let Some((seq, hash)) = found {
        room.presented_seq = Some(seq);
        room.presented_hash = Some(hash);
    }
}

/// Seq of the latest head-advancing record before `seq`, or 0.
pub(crate) fn head_before(room: &LocalRoomState, seq: u64, previous_head_seq: u64) -> u64 {
    (1..seq)
        .rev()
        .find(|s| {
            room.records
                .iter()
                .any(|record| record.seq() == *s && record_advances_room_head(room, record))
        })
        // A room snapshot may provide a verified head without its older records.
        .unwrap_or(if previous_head_seq < seq {
            previous_head_seq
        } else {
            0
        })
}

fn invalid(message: &str) -> SdkError {
    SdkError::InvalidPayload(message.to_owned())
}
