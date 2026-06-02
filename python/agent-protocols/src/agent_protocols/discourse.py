from __future__ import annotations

from typing import Any, Literal, TypedDict

from .errors import AgentProtocolError
from .identity import AgentId, Envelope, Event, create_event, verify_envelope, with_room_id

DISCOURSE_PROTOCOL = "agent-discourse/1.0"
LEGACY_DISCOURSE_PROTOCOL = "adp/1.0"

ROOM_CREATE = "room.create"
ROOM_JOIN = "room.join"
ROOM_LEAVE = "room.leave"
ROOM_MEMBER_ROLE_UPDATE = "room.member.role.update"
ROOM_INVITE = "room.invite"
ROOM_INVITE_REVOKE = "room.invite.revoke"
ROOM_CLOSE = "room.close"
ROOM_CANCEL = "room.cancel"
MESSAGE_CREATE = "message.create"
REACTION_CREATE = "reaction.create"
MESSAGE_PROPOSAL_CREATE = "message.proposal.create"
MESSAGE_POLL_CREATE = "message.poll.create"
MESSAGE_POLL_VOTE = "message.poll.vote"
MESSAGE_RESOLUTION_CREATE = "message.resolution.create"
SOURCE_ADD = "source.add"
TURN_UPDATE = "turn.update"
QUESTION_CREATE = "question.create"
ROOM_STEER = "room.steer"
MAP_UPDATE = "map.update"
ARTIFACT_CREATE = "artifact.create"
SESSION_AUTH = "session.auth"

KNOWN_EVENT_TYPES = {
    ROOM_CREATE,
    ROOM_JOIN,
    ROOM_LEAVE,
    ROOM_MEMBER_ROLE_UPDATE,
    ROOM_INVITE,
    ROOM_INVITE_REVOKE,
    ROOM_CLOSE,
    ROOM_CANCEL,
    MESSAGE_CREATE,
    REACTION_CREATE,
    MESSAGE_PROPOSAL_CREATE,
    MESSAGE_POLL_CREATE,
    MESSAGE_POLL_VOTE,
    MESSAGE_RESOLUTION_CREATE,
    SOURCE_ADD,
    TURN_UPDATE,
    QUESTION_CREATE,
    ROOM_STEER,
    MAP_UPDATE,
    ARTIFACT_CREATE,
    SESSION_AUTH,
}

RoomState = Literal["scheduled", "active", "ended", "cancelled"]
Role = Literal["moderator", "expert", "participant", "observer"]


class PermissionContext(TypedDict, total=False):
    role: Role
    is_creator: bool
    moderator_authorized: bool
    expert_policy_allowed: bool
    participant_policy_allowed: bool
    observer_steering_allowed: bool
    observer_poll_vote_allowed: bool


def room_create_event(actor: AgentId, created_at: int, nonce: int, payload: dict[str, Any]) -> Event:
    return create_event(DISCOURSE_PROTOCOL, ROOM_CREATE, actor, created_at, nonce, payload)


def discourse_event(event_type: str, actor: AgentId, created_at: int, nonce: int, room_id: str, payload: Any) -> Event:
    return with_room_id(create_event(DISCOURSE_PROTOCOL, event_type, actor, created_at, nonce, payload), room_id)


def validate_discourse_envelope(envelope: Envelope, accept_legacy_protocol: bool = False) -> None:
    verify_envelope(envelope)
    event = envelope["event"]
    protocol = event["protocol"]
    if protocol != DISCOURSE_PROTOCOL and not (accept_legacy_protocol and protocol == LEGACY_DISCOURSE_PROTOCOL):
        raise AgentProtocolError("invalid_event_protocol", f"expected {DISCOURSE_PROTOCOL}, got {protocol}")
    if event_requires_room_id(event["type"]) and "room_id" not in event:
        raise AgentProtocolError("missing_room_id", "event requires a room_id")


def validate_room_path(envelope: Envelope, path_room_id: str) -> None:
    actual = envelope["event"].get("room_id")
    if actual is None:
        raise AgentProtocolError("missing_room_id", "event requires a room_id")
    if actual != path_room_id:
        raise AgentProtocolError("room_id_mismatch", f"expected {path_room_id}, got {actual}")


def event_requires_room_id(event_type: str) -> bool:
    return event_type != ROOM_CREATE


def can_submit_event(event_type: str, context: PermissionContext) -> bool:
    if event_type in {ROOM_CREATE, ROOM_JOIN}:
        return True
    if context.get("is_creator"):
        return event_type in KNOWN_EVENT_TYPES

    role = context.get("role")
    if role == "moderator":
        return _moderator_can_submit(event_type, context.get("moderator_authorized", False))
    if role == "expert":
        return _speaker_can_submit(event_type, context.get("expert_policy_allowed", False))
    if role == "participant":
        return _speaker_can_submit(event_type, context.get("participant_policy_allowed", False))
    if role == "observer":
        return _observer_can_submit(event_type, context)
    return False


def can_write_in_state(event_type: str, state: RoomState, *, post_end_reaction_allowed: bool = False) -> bool:
    if state == "scheduled":
        return event_type in {ROOM_JOIN, ROOM_INVITE, ROOM_INVITE_REVOKE, ROOM_CANCEL}
    if state == "active":
        return event_type not in {ROOM_CREATE, ROOM_CANCEL}
    if state == "ended":
        return post_end_reaction_allowed and event_type == REACTION_CREATE
    if state == "cancelled":
        return False
    return False


def can_accept_room_write(event_type: str, state: RoomState, context: PermissionContext, *, post_end_reaction_allowed: bool = False) -> bool:
    return can_submit_event(event_type, context) and can_write_in_state(event_type, state, post_end_reaction_allowed=post_end_reaction_allowed)


def validate_room_write(event_type: str, state: RoomState, context: PermissionContext, *, post_end_reaction_allowed: bool = False) -> None:
    if not can_accept_room_write(event_type, state, context, post_end_reaction_allowed=post_end_reaction_allowed):
        raise AgentProtocolError("permission_denied", "actor lacks permission or state is not writable")


def _moderator_can_submit(event_type: str, moderator_authorized: bool) -> bool:
    allowed = {
        ROOM_INVITE,
        ROOM_INVITE_REVOKE,
        ROOM_CLOSE,
        MESSAGE_CREATE,
        SOURCE_ADD,
        TURN_UPDATE,
        QUESTION_CREATE,
        ROOM_STEER,
        MAP_UPDATE,
        ARTIFACT_CREATE,
        MESSAGE_PROPOSAL_CREATE,
        MESSAGE_POLL_CREATE,
        MESSAGE_POLL_VOTE,
        MESSAGE_RESOLUTION_CREATE,
        REACTION_CREATE,
        ROOM_LEAVE,
    }
    return event_type in allowed or (moderator_authorized and event_type in {ROOM_MEMBER_ROLE_UPDATE, ROOM_CANCEL})


def _speaker_can_submit(event_type: str, policy_allowed: bool) -> bool:
    allowed = {
        MESSAGE_CREATE,
        SOURCE_ADD,
        ROOM_STEER,
        MESSAGE_PROPOSAL_CREATE,
        MESSAGE_POLL_CREATE,
        MESSAGE_POLL_VOTE,
        REACTION_CREATE,
        ROOM_LEAVE,
    }
    policy_events = {QUESTION_CREATE, MAP_UPDATE, ARTIFACT_CREATE, MESSAGE_RESOLUTION_CREATE}
    return event_type in allowed or (policy_allowed and event_type in policy_events)


def _observer_can_submit(event_type: str, context: PermissionContext) -> bool:
    return (
        event_type in {REACTION_CREATE, ROOM_LEAVE}
        or (context.get("observer_steering_allowed", False) and event_type == ROOM_STEER)
        or (context.get("observer_poll_vote_allowed", False) and event_type == MESSAGE_POLL_VOTE)
    )
