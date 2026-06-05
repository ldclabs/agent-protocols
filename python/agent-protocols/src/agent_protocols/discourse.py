from __future__ import annotations

import base64
import hashlib
from typing import Any, Literal, TypedDict

import rfc8785

from .errors import AgentProtocolError
from .identity import AgentId, Envelope, Event, create_event, verify_envelope, with_room_id

DISCOURSE_PROTOCOL = "agent-discourse/1.0"

ROOM_CREATE = "room.create"
ROOM_JOIN = "room.join"
ROOM_JOIN_REVIEW = "room.join.review"
ROOM_LEAVE = "room.leave"
ROOM_MEMBER_ROLE_UPDATE = "room.member.role.update"
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
SESSION_OFFER = "session.offer"
SESSION_ANSWER = "session.answer"
SESSION_CANDIDATE = "session.candidate"
SESSION_CLOSE = "session.close"

KNOWN_EVENT_TYPES = {
    ROOM_CREATE,
    ROOM_JOIN,
    ROOM_JOIN_REVIEW,
    ROOM_LEAVE,
    ROOM_MEMBER_ROLE_UPDATE,
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
    SESSION_OFFER,
    SESSION_ANSWER,
    SESSION_CANDIDATE,
    SESSION_CLOSE,
}

RoomState = Literal["scheduled", "active", "ended", "cancelled"]
Role = Literal["moderator", "expert", "participant", "observer"]
JoinRequestStatus = Literal["pending", "approved", "rejected", "expired"]
SESSION_MEDIA_KINDS = {"audio", "video", "screen", "data", "file"}


class PermissionContext(TypedDict, total=False):
    role: Role
    is_creator: bool
    join_request_approved: bool
    moderator_authorized: bool
    expert_policy_allowed: bool
    participant_policy_allowed: bool
    observer_steering_allowed: bool
    observer_poll_vote_allowed: bool


def room_create_event(actor: AgentId, created_at: int, nonce: int, payload: dict[str, Any]) -> Event:
    return create_event(DISCOURSE_PROTOCOL, ROOM_CREATE, actor, created_at, nonce, payload)


def discourse_event(event_type: str, actor: AgentId, created_at: int, nonce: int, room_id: str, payload: Any) -> Event:
    return with_room_id(create_event(DISCOURSE_PROTOCOL, event_type, actor, created_at, nonce, payload), room_id)


def validate_discourse_envelope(envelope: Envelope) -> None:
    verify_envelope(envelope)
    event = envelope["event"]
    protocol = event["protocol"]
    if protocol != DISCOURSE_PROTOCOL:
        raise AgentProtocolError("invalid_event_protocol", f"expected {DISCOURSE_PROTOCOL}, got {protocol}")
    if event_requires_room_id(event["type"]) and "room_id" not in event:
        raise AgentProtocolError("missing_room_id", "event requires a room_id")


def validate_room_path(envelope: Envelope, path_room_id: str) -> None:
    actual = envelope["event"].get("room_id")
    if actual is None and envelope["event"]["type"] == ROOM_CREATE:
        return
    if actual is None:
        raise AgentProtocolError("missing_room_id", "event requires a room_id")
    if actual != path_room_id:
        raise AgentProtocolError("room_id_mismatch", f"expected {path_room_id}, got {actual}")


def event_requires_room_id(event_type: str) -> bool:
    return event_type != ROOM_CREATE


def validate_room_create_payload(payload: dict[str, Any]) -> None:
    if not str(payload.get("topic", "")).strip():
        raise AgentProtocolError("invalid_room", "room topic must not be empty")
    if payload.get("start_time", 0) >= payload.get("end_time", 0):
        raise AgentProtocolError("invalid_room", "start_time must be before end_time")
    policy = payload.get("policy") or {}
    max_participants = policy.get("max_participants")
    if max_participants is not None and (
        not isinstance(max_participants, int) or max_participants < 1
    ):
        raise AgentProtocolError("invalid_room", "max_participants must be a positive integer")


def validate_poll_create_payload(payload: dict[str, Any]) -> None:
    if not str(payload.get("poll_id", "")).strip() or not str(payload.get("question", "")).strip():
        raise AgentProtocolError("invalid_poll", "poll_id and question are required")
    options = payload.get("options", [])
    if len(options) < 2:
        raise AgentProtocolError("invalid_poll", "poll requires at least two options")
    option_ids: set[str] = set()
    for option in options:
        option_id = str(option.get("id", ""))
        label = str(option.get("label", ""))
        if not option_id.strip() or not label.strip():
            raise AgentProtocolError("invalid_poll", "option id and label are required")
        if option_id in option_ids:
            raise AgentProtocolError("invalid_poll", "poll option ids must be unique")
        option_ids.add(option_id)
    min_choices = payload.get("min_choices", 1)
    max_choices = payload.get("max_choices", 1)
    if min_choices < 1 or max_choices < min_choices:
        raise AgentProtocolError("invalid_poll", "invalid poll choice limits")


def validate_poll_vote_payload(payload: dict[str, Any], poll: dict[str, Any], now_ms: int | None = None) -> None:
    if poll.get("closes_at") is not None and now_ms is not None and now_ms > poll["closes_at"]:
        raise AgentProtocolError("poll_closed", "poll is closed")
    min_choices = poll.get("min_choices", 1)
    max_choices = poll.get("max_choices", 1)
    option_ids = {option["id"] for option in poll.get("options", [])}
    selected = payload.get("option_ids", [])
    selected_set = set(selected)
    if len(selected_set) != len(selected):
        raise AgentProtocolError("invalid_poll_vote", "duplicate poll options")
    if len(selected_set) < min_choices or len(selected_set) > max_choices:
        raise AgentProtocolError("invalid_poll_vote", "invalid number of options")
    if any(option_id not in option_ids for option_id in selected_set):
        raise AgentProtocolError("invalid_poll_vote", "unknown poll option")


def validate_session_offer_payload(payload: dict[str, Any]) -> None:
    _validate_session_id(payload.get("session_id"))
    if payload.get("session_type") != "webrtc":
        raise AgentProtocolError("invalid_session", "session_type must be webrtc")
    media = payload.get("media", [])
    if not isinstance(media, list) or not media:
        raise AgentProtocolError("invalid_session", "media must not be empty")
    if any(media_kind not in SESSION_MEDIA_KINDS for media_kind in media):
        raise AgentProtocolError("invalid_session", "unsupported media kind")
    _validate_session_description(payload.get("description"), "offer")
    _validate_session_transfers(payload.get("transfers", []))


def validate_session_answer_payload(payload: dict[str, Any]) -> None:
    _validate_session_id(payload.get("session_id"))
    if not str(payload.get("offer_event_id", "")).strip():
        raise AgentProtocolError("invalid_session", "offer_event_id is required")
    _validate_session_description(payload.get("description"), "answer")
    _validate_session_transfers(payload.get("transfers", []))


def validate_session_candidate_payload(payload: dict[str, Any]) -> None:
    _validate_session_id(payload.get("session_id"))
    if payload.get("end_of_candidates"):
        return
    candidate = payload.get("candidate") or {}
    if not str(candidate.get("candidate", "")).strip():
        raise AgentProtocolError("invalid_session", "candidate is required unless end_of_candidates is true")


def server_record_hash_payload(
    room_id: str,
    seq: int,
    pre_hash: str | None,
    envelope_hash: str,
    received_at: int,
) -> dict[str, Any]:
    return {
        "room_id": room_id,
        "seq": seq,
        "pre_hash": pre_hash,
        "envelope_hash": envelope_hash,
        "received_at": received_at,
    }


def server_record_hash(
    room_id: str,
    seq: int,
    pre_hash: str | None,
    envelope_hash: str,
    received_at: int,
) -> str:
    return _hash_canonical_json(server_record_hash_payload(room_id, seq, pre_hash, envelope_hash, received_at))


def build_server_record(
    room_id: str,
    seq: int,
    pre_hash: str | None,
    received_at: int,
    envelope: Envelope,
) -> dict[str, Any]:
    return {
        "room_id": room_id,
        "seq": seq,
        "pre_hash": pre_hash,
        "hash": server_record_hash(room_id, seq, pre_hash, envelope["hash"], received_at),
        "received_at": received_at,
        "envelope": envelope,
    }


def verify_server_record(record: dict[str, Any]) -> None:
    expected = server_record_hash(
        record["room_id"],
        record["seq"],
        record.get("pre_hash"),
        record["envelope"]["hash"],
        record["received_at"],
    )
    if record["hash"] != expected:
        raise AgentProtocolError("invalid_record_hash", f"invalid server record hash: expected {expected}, got {record['hash']}")


def verify_server_record_chain(records: list[dict[str, Any]]) -> None:
    previous: dict[str, Any] | None = None
    for record in records:
        verify_server_record(record)
        if previous is None:
            if record["seq"] != 1:
                raise AgentProtocolError("invalid_record_chain", "first seq must be 1")
            if record.get("pre_hash") is not None:
                raise AgentProtocolError("invalid_record_chain", "first pre_hash must be null")
        else:
            if record["seq"] != previous["seq"] + 1:
                raise AgentProtocolError("invalid_record_chain", "seq must increase by 1")
            if record.get("pre_hash") != previous["hash"]:
                raise AgentProtocolError("invalid_record_chain", "pre_hash mismatch")
        previous = record


def archive_events_digest(records: list[dict[str, Any]]) -> str:
    return _hash_canonical_json(records)


def can_submit_event(event_type: str, context: PermissionContext) -> bool:
    if event_type == ROOM_CREATE:
        return True
    if event_type == ROOM_JOIN:
        return context.get("join_request_approved", False)
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
        return event_type in {ROOM_JOIN, ROOM_JOIN_REVIEW, ROOM_CANCEL}
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
        ROOM_JOIN_REVIEW,
        ROOM_CLOSE,
        MESSAGE_CREATE,
        SOURCE_ADD,
        TURN_UPDATE,
        QUESTION_CREATE,
        ROOM_STEER,
        MAP_UPDATE,
        ARTIFACT_CREATE,
        SESSION_OFFER,
        SESSION_ANSWER,
        SESSION_CANDIDATE,
        SESSION_CLOSE,
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
        SESSION_OFFER,
        SESSION_ANSWER,
        SESSION_CANDIDATE,
        SESSION_CLOSE,
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


def _validate_session_id(session_id: Any) -> None:
    if not str(session_id or "").strip():
        raise AgentProtocolError("invalid_session", "session_id is required")


def _validate_session_description(description: Any, expected_type: str) -> None:
    if not isinstance(description, dict):
        raise AgentProtocolError("invalid_session", "session description is required")
    if description.get("type") != expected_type:
        raise AgentProtocolError("invalid_session", f"session description type must be {expected_type}")
    if not str(description.get("sdp", "")).strip():
        raise AgentProtocolError("invalid_session", "session description sdp is required")


def _validate_session_transfers(transfers: Any) -> None:
    if transfers is None:
        return
    if not isinstance(transfers, list):
        raise AgentProtocolError("invalid_session", "transfers must be an array")
    for transfer in transfers:
        if not isinstance(transfer, dict):
            raise AgentProtocolError("invalid_session", "transfer must be an object")
        if not str(transfer.get("transfer_id", "")).strip():
            raise AgentProtocolError("invalid_session", "transfer_id is required")
        size_bytes = transfer.get("size_bytes")
        if size_bytes is not None and (not isinstance(size_bytes, int) or size_bytes < 0):
            raise AgentProtocolError("invalid_session", "size_bytes must be a non-negative integer")


def _hash_canonical_json(value: Any) -> str:
    canonical = rfc8785.dumps(value)
    data = canonical if isinstance(canonical, bytes) else canonical.encode()
    digest = hashlib.sha3_256(data).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
