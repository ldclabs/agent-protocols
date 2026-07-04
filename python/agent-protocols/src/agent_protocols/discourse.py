"""Agent Discourse Protocol 1.0: kernel types, the room type system, and
verification helpers.

The protocol defines eleven built-in event types. Every other event type is
declared per room as a schema-validated type definition, either inline or
imported from a type pack. Hosts validate structure and permissions; they
never need to understand application semantics.
"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Any, Iterable, Literal, TypedDict

import rfc8785
from jsonschema.validators import Draft202012Validator

from .errors import AgentProtocolError
from .identity import (
    AgentId,
    Envelope,
    Event,
    MAX_SAFE_NONCE,
    create_event,
    validate_agent_id,
    verify_envelope,
    with_room_head,
    with_room_id,
)

DISCOURSE_PROTOCOL = "agent-discourse/1.0"

# The eleven built-in event types. All other types are room-defined.
ROOM_CREATE = "room.create"
ROOM_UPDATE = "room.update"
ROOM_JOIN = "room.join"
ROOM_JOIN_REVIEW = "room.join.review"
ROOM_LEAVE = "room.leave"
ROOM_MEMBER_ROLE_UPDATE = "room.member.role.update"
ROOM_MEMBER_REMOVE = "room.member.remove"
ROOM_CLOSE = "room.close"
ROOM_CANCEL = "room.cancel"
TYPE_DEFINE = "type.define"
MESSAGE_CREATE = "message.create"

BUILTIN_EVENT_TYPES = {
    ROOM_CREATE,
    ROOM_UPDATE,
    ROOM_JOIN,
    ROOM_JOIN_REVIEW,
    ROOM_LEAVE,
    ROOM_MEMBER_ROLE_UPDATE,
    ROOM_MEMBER_REMOVE,
    ROOM_CLOSE,
    ROOM_CANCEL,
    TYPE_DEFINE,
    MESSAGE_CREATE,
}

# Built-in membership events. They carry the `signal` class: they anchor to
# an accepted record but never contend for or advance the room head, so busy
# rooms cannot starve joins, reviews, or other membership writes.
MEMBERSHIP_EVENT_TYPES = (
    ROOM_JOIN,
    ROOM_JOIN_REVIEW,
    ROOM_LEAVE,
    ROOM_MEMBER_ROLE_UPDATE,
    ROOM_MEMBER_REMOVE,
)

# Standard ADP error codes from the Section 20 table.
DISCOURSE_ERROR_CODES = frozenset(
    {
        "invalid_event",
        "invalid_event_hash",
        "invalid_signature",
        "invalid_actor",
        "timestamp_out_of_window",
        "nonce_not_greater",
        "room_not_found",
        "room_not_active",
        "room_ended",
        "permission_denied",
        "approval_required",
        "join_request_not_found",
        "join_request_not_approved",
        "join_request_role_mismatch",
        "join_request_expired",
        "member_banned",
        "role_not_allowed",
        "max_speakers_exceeded",
        "membership_required",
        "invalid_token",
        "room_head_mismatch",
        "base_record_mismatch",
        "agent_status_not_found",
        "rate_limited",
        "payload_too_large",
        "type_not_defined",
        "type_disabled",
        "payload_schema_violation",
        "pack_unavailable",
    }
)

# Hosts MUST reject events with more than this many `mentions` entries.
MAX_MENTIONS = 32

# Custom event types must not use these prefixes.
RESERVED_TYPE_PREFIXES = ("room.", "type.")

# Registered type packs defined by the specification in `1.0.packs.json`.
PACK_REACTIONS = "adp:reactions/1.0"
PACK_DELIBERATION = "adp:deliberation/1.0"
PACK_CURATION = "adp:curation/1.0"
PACK_MODERATION = "adp:moderation/1.0"
PACK_REALTIME = "adp:realtime/1.0"

REGISTERED_PACK_IDS = (
    PACK_REACTIONS,
    PACK_DELIBERATION,
    PACK_CURATION,
    PACK_MODERATION,
    PACK_REALTIME,
)

RoomState = Literal["scheduled", "active", "ended", "cancelled"]
Role = Literal["moderator", "speaker", "observer"]
TypeKind = Literal["message", "signal", "control"]
TypeStatus = Literal["active", "deprecated", "disabled"]
JoinRequestStatus = Literal["pending", "approved", "rejected", "expired"]
JoinDecision = Literal["approve", "reject"]
Visibility = Literal["public", "restricted", "private"]

ROLES = ("moderator", "speaker", "observer")
TYPE_KINDS = ("message", "signal", "control")
TYPE_STATUSES = ("active", "deprecated", "disabled")

_TYPE_SEGMENT = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_REGISTERED_PACK_ID = re.compile(r"^adp:[a-z0-9-]+/[0-9]+\.[0-9]+$")


class PermissionContext(TypedDict, total=False):
    """Permission inputs for one actor in one room."""

    role: Role
    is_creator: bool
    public_join_allowed: bool
    join_request_approved: bool


class AgentStatusInput(TypedDict, total=False):
    state: str
    summary: str
    seen_seq: int
    seen_hash: str
    claim_id: str
    activity: str
    expires_at: int
    extra: dict[str, Any]


class AgentStatus(TypedDict, total=False):
    room_id: str
    agent_id: AgentId
    state: str
    summary: str
    seen_seq: int
    seen_hash: str
    claim_id: str
    activity: str
    expires_at: int
    updated_at: int
    extra: dict[str, Any]


def room_create_event(actor: AgentId, created_at: int, nonce: int, payload: dict[str, Any]) -> Event:
    return create_event(DISCOURSE_PROTOCOL, ROOM_CREATE, actor, created_at, nonce, payload)


def type_define_event(
    actor: AgentId,
    created_at: int,
    nonce: int,
    room_id: str,
    base_seq: int,
    base_hash: str,
    declaration: dict[str, Any],
) -> Event:
    return with_room_head(
        with_room_id(
            create_event(DISCOURSE_PROTOCOL, TYPE_DEFINE, actor, created_at, nonce, declaration),
            room_id,
        ),
        base_seq,
        base_hash,
    )


def discourse_event(
    event_type: str,
    actor: AgentId,
    created_at: int,
    nonce: int,
    room_id: str,
    base_seq: int,
    base_hash: str,
    payload: Any,
) -> Event:
    return with_room_head(
        with_room_id(create_event(DISCOURSE_PROTOCOL, event_type, actor, created_at, nonce, payload), room_id),
        base_seq,
        base_hash,
    )


def is_builtin_event_type(event_type: str) -> bool:
    return event_type in BUILTIN_EVENT_TYPES


def event_requires_room_id(event_type: str) -> bool:
    return event_type != ROOM_CREATE


BuiltinEventClass = Literal["lifecycle", "signal", "control", "message"]

_BUILTIN_EVENT_CLASSES: dict[str, BuiltinEventClass] = {
    ROOM_CREATE: "lifecycle",
    ROOM_UPDATE: "lifecycle",
    ROOM_CLOSE: "lifecycle",
    ROOM_CANCEL: "lifecycle",
    ROOM_JOIN: "signal",
    ROOM_JOIN_REVIEW: "signal",
    ROOM_LEAVE: "signal",
    ROOM_MEMBER_ROLE_UPDATE: "signal",
    ROOM_MEMBER_REMOVE: "signal",
    TYPE_DEFINE: "control",
    MESSAGE_CREATE: "message",
}


def builtin_event_class(event_type: str) -> BuiltinEventClass | None:
    """Section 13.2 class of a built-in type; ``None`` for room-defined types."""
    return _BUILTIN_EVENT_CLASSES.get(event_type)


def event_advances_room_head(event_type: str, registry: "TypeRegistry | None" = None) -> bool:
    """Whether an accepted record of this type advances the room head and must
    therefore match the current head when written (Section 6.1). Room
    lifecycle, `message`-kind, and `control`-kind records advance the head;
    `signal`-kind records — including the built-in membership events — only
    anchor to an accepted record. Unknown custom types default to
    head-advancing."""
    builtin_class = builtin_event_class(event_type)
    if builtin_class is not None:
        return builtin_class != "signal"
    definition = registry.get(event_type) if registry is not None else None
    return definition is None or definition.get("kind") != "signal"


def validate_discourse_envelope(envelope: Envelope) -> None:
    verify_envelope(envelope)
    event = envelope["event"]
    protocol = event["protocol"]
    if protocol != DISCOURSE_PROTOCOL:
        raise AgentProtocolError("invalid_event_protocol", f"expected {DISCOURSE_PROTOCOL}, got {protocol}")
    if event["type"] == ROOM_CREATE:
        _validate_room_create_event_fields(event)
    else:
        if "room_id" not in event:
            raise AgentProtocolError("missing_room_id", "event requires a room_id")
        validate_room_head_precondition(event)
        _validate_mentions(event.get("mentions"))


def validate_room_path(envelope: Envelope, path_room_id: str) -> None:
    event = envelope["event"]
    actual = event.get("room_id")
    if event["type"] == ROOM_CREATE:
        _validate_room_create_event_fields(event)
        return
    validate_room_head_precondition(event)
    _validate_mentions(event.get("mentions"))
    if actual is None:
        raise AgentProtocolError("missing_room_id", "event requires a room_id")
    if actual != path_room_id:
        raise AgentProtocolError("room_id_mismatch", f"expected {path_room_id}, got {actual}")


def _validate_room_create_event_fields(event: Event) -> None:
    if any(field in event for field in ("room_id", "base_seq", "base_hash", "mentions")):
        raise AgentProtocolError(
            "invalid_event",
            "room.create must not include room_id, base_seq, base_hash, or mentions",
        )


def validate_room_head_precondition(event: Event) -> None:
    base_seq = event.get("base_seq")
    base_hash = event.get("base_hash")
    if not isinstance(base_seq, int) or base_seq < 1 or base_seq > MAX_SAFE_NONCE:
        raise AgentProtocolError("invalid_event", "base_seq must be a positive safe JSON integer")
    if not isinstance(base_hash, str) or not base_hash.strip():
        raise AgentProtocolError("invalid_event", "base_hash must not be empty")


def _validate_mentions(mentions: Any) -> None:
    if mentions is None:
        return
    if not isinstance(mentions, list):
        raise AgentProtocolError("invalid_event", "mentions must be an Agent ID array")
    if len(mentions) > MAX_MENTIONS:
        raise AgentProtocolError("invalid_event", f"mentions must not exceed {MAX_MENTIONS} entries")
    # Validate each entry before testing uniqueness: a non-string mention would
    # otherwise raise a raw TypeError from set() instead of a clean protocol
    # error.
    seen: set[str] = set()
    for mention in mentions:
        validate_agent_id(mention)
        if mention in seen:
            raise AgentProtocolError("invalid_event", "mentions must be unique")
        seen.add(mention)


def validate_custom_event_type_name(name: str) -> None:
    """Checks the shape of a custom event type name: lowercase dot-separated,
    at least two segments, not built-in, not under a reserved prefix."""
    segments = name.split(".")
    if len(segments) < 2 or not all(_TYPE_SEGMENT.match(segment) for segment in segments):
        raise AgentProtocolError("invalid_event", f"invalid event type name: {name}")
    if is_builtin_event_type(name):
        raise AgentProtocolError("invalid_event", f"{name} is a built-in event type")
    if name.startswith(RESERVED_TYPE_PREFIXES):
        raise AgentProtocolError("invalid_event", f"{name} uses a reserved type prefix")


def is_pack_import(declaration: dict[str, Any]) -> bool:
    return "use" in declaration or "pack" in declaration or "digest" in declaration


def validate_type_def(definition: dict[str, Any]) -> None:
    validate_custom_event_type_name(str(definition.get("type", "")))
    if definition.get("kind") not in TYPE_KINDS:
        raise AgentProtocolError("invalid_event", f"invalid type kind: {definition.get('kind')}")
    if not str(definition.get("title", "")).strip():
        raise AgentProtocolError("invalid_event", "type definition title must not be empty")
    schema = definition.get("schema")
    if not isinstance(schema, dict):
        raise AgentProtocolError("invalid_event", "type definition schema must be a JSON Schema object")
    _compile_schema(schema)
    roles = definition.get("roles")
    if roles is not None:
        if not isinstance(roles, list) or not roles or any(role not in ROLES for role in roles):
            raise AgentProtocolError("invalid_event", "type definition roles must be a non-empty role list")
    status = definition.get("status")
    if status is not None and status not in TYPE_STATUSES:
        raise AgentProtocolError("invalid_event", f"invalid type status: {status}")
    for hint in ("rate_hint", "max_payload_hint"):
        value = definition.get(hint)
        if value is not None and (not isinstance(value, int) or value < 1):
            raise AgentProtocolError("invalid_event", "type definition hints must be positive integers")


def validate_pack_import(declaration: dict[str, Any]) -> None:
    has_use = "use" in declaration
    has_external = "pack" in declaration and "digest" in declaration
    if has_use:
        if "pack" in declaration or "digest" in declaration:
            raise AgentProtocolError("invalid_event", "pack import requires either use, or pack with digest")
        if not _REGISTERED_PACK_ID.match(str(declaration["use"])):
            raise AgentProtocolError("invalid_event", f"invalid registered pack id: {declaration['use']}")
    elif has_external:
        if not str(declaration["digest"]).strip():
            raise AgentProtocolError("invalid_event", "external pack digest must not be empty")
    else:
        raise AgentProtocolError("invalid_event", "pack import requires either use, or pack with digest")
    types = declaration.get("types")
    if types is not None and (not isinstance(types, list) or not types):
        raise AgentProtocolError("invalid_event", "pack import types subset must not be empty")


def validate_type_declaration(declaration: dict[str, Any]) -> None:
    if not isinstance(declaration, dict):
        raise AgentProtocolError("invalid_event", "type declaration must be an object")
    if is_pack_import(declaration):
        validate_pack_import(declaration)
    elif "type" in declaration:
        validate_type_def(declaration)
    else:
        raise AgentProtocolError(
            "invalid_event", "type declaration must be an inline definition or a pack import"
        )


def pack_map(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Indexes the packs of a document by pack id for registry materialization."""
    return {pack["id"]: pack for pack in document.get("packs", [])}


class TypeRegistry:
    """The effective set of type definitions active in a room."""

    def __init__(self) -> None:
        self._types: dict[str, dict[str, Any]] = {}

    @classmethod
    def from_declarations(
        cls,
        declarations: Iterable[dict[str, Any]],
        packs: dict[str, dict[str, Any]] | None = None,
    ) -> "TypeRegistry":
        """Materializes a registry from declarations, resolving pack imports
        from `packs`, keyed by registered pack id or external pack URI."""
        registry = cls()
        for declaration in declarations:
            registry.apply(declaration, packs)
        return registry

    def apply(self, declaration: dict[str, Any], packs: dict[str, dict[str, Any]] | None = None) -> None:
        """Applies one declaration: an inline definition or a pack import.
        Redefining an existing type replaces it; the latest definition wins."""
        if is_pack_import(declaration):
            self._import(declaration, packs or {})
        elif "type" in declaration:
            self.define(declaration)
        else:
            raise AgentProtocolError(
                "invalid_event", "type declaration must be an inline definition or a pack import"
            )

    def define(self, definition: dict[str, Any]) -> None:
        validate_type_def(definition)
        existing = self._types.get(definition["type"])
        if existing is not None and existing.get("kind") != definition.get("kind"):
            raise AgentProtocolError(
                "invalid_event",
                f"type {definition['type']} cannot change kind on redefinition",
            )
        self._types[definition["type"]] = definition

    def _import(self, declaration: dict[str, Any], packs: dict[str, dict[str, Any]]) -> None:
        validate_pack_import(declaration)
        reference = declaration.get("use") or declaration.get("pack")
        pack = packs.get(reference)
        if pack is None:
            raise AgentProtocolError("pack_unavailable", f"pack not available: {reference}")
        available = {definition["type"] for definition in pack.get("types", [])}
        subset = declaration.get("types")
        if subset is not None:
            for name in subset:
                if name not in available:
                    raise AgentProtocolError("pack_unavailable", f"type {name} is not in pack {reference}")
        overrides = declaration.get("overrides") or {}
        for name in overrides:
            imported = name in subset if subset is not None else name in available
            if not imported:
                raise AgentProtocolError(
                    "invalid_event", f"override target {name} is not imported from pack {reference}"
                )
        for definition in pack.get("types", []):
            if subset is not None and definition["type"] not in subset:
                continue
            merged = dict(definition)
            merged.update(overrides.get(definition["type"], {}))
            self.define(merged)

    def get(self, event_type: str) -> dict[str, Any] | None:
        return self._types.get(event_type)

    def __contains__(self, event_type: str) -> bool:
        return event_type in self._types

    def __len__(self) -> int:
        return len(self._types)

    def definitions(self) -> list[dict[str, Any]]:
        return list(self._types.values())

    def validate_payload(self, event_type: str, payload: Any) -> None:
        """Validates a custom event payload against the type's schema and status."""
        definition = self._types.get(event_type)
        if definition is None:
            raise AgentProtocolError("type_not_defined", f"event type is not defined in the room: {event_type}")
        if definition.get("status", "active") == "disabled":
            raise AgentProtocolError("type_disabled", f"event type is disabled in this room: {event_type}")
        validator = _compile_schema(definition["schema"])
        errors = sorted(validator.iter_errors(payload), key=lambda error: list(error.absolute_path))
        if errors:
            detail = "; ".join(error.message for error in errors[:3])
            raise AgentProtocolError("payload_schema_violation", f"{event_type}: {detail}")


def validate_event_against_registry(event_type: str, payload: Any, registry: TypeRegistry) -> None:
    """Validates an event payload: built-in payloads are accepted as-is (use
    the typed validators for them); custom payloads must satisfy the registry."""
    if is_builtin_event_type(event_type):
        return
    registry.validate_payload(event_type, payload)


def _compile_schema(schema: dict[str, Any]) -> Draft202012Validator:
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as error:  # jsonschema.SchemaError
        raise AgentProtocolError("invalid_event", f"invalid type schema: {error}") from error
    return Draft202012Validator(schema)


def verify_pack_digest(data: bytes, digest: str) -> None:
    """Verifies a `<algorithm>:<base64url-digest>` content digest over raw
    bytes. Supports `sha256` and `sha3-256`."""
    algorithm, separator, expected = digest.partition(":")
    if not separator:
        raise AgentProtocolError("pack_unavailable", f"invalid digest format: {digest}")
    if algorithm == "sha256":
        raw = hashlib.sha256(data).digest()
    elif algorithm == "sha3-256":
        raw = hashlib.sha3_256(data).digest()
    else:
        raise AgentProtocolError("pack_unavailable", f"unsupported digest algorithm: {algorithm}")
    actual = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    if actual != expected:
        raise AgentProtocolError("pack_unavailable", "pack digest mismatch")


def validate_room_create_payload(payload: dict[str, Any]) -> None:
    if not str(payload.get("topic", "")).strip():
        raise AgentProtocolError("invalid_event", "room topic must not be empty")
    if payload.get("start_time", 0) >= payload.get("end_time", 0):
        raise AgentProtocolError("invalid_event", "start_time must be before end_time")
    policy = payload.get("policy") or {}
    max_speakers = policy.get("max_speakers")
    if max_speakers is not None and (not isinstance(max_speakers, int) or max_speakers < 1):
        raise AgentProtocolError("invalid_event", "max_speakers must be a positive integer")
    for declaration in payload.get("types", []):
        validate_type_declaration(declaration)


def validate_message_create_payload(payload: dict[str, Any]) -> None:
    if not str(payload.get("content_type", "")).strip():
        raise AgentProtocolError("invalid_event", "content_type must not be empty")


def validate_room_join_payload(payload: dict[str, Any]) -> None:
    if payload.get("role") not in ROLES:
        raise AgentProtocolError("invalid_event", f"invalid room role: {payload.get('role')}")
    request_id = payload.get("request_id")
    if request_id is not None and not str(request_id).strip():
        raise AgentProtocolError("invalid_event", "request_id must not be empty")
    if request_id is not None and "perspective" in payload:
        raise AgentProtocolError(
            "invalid_event",
            "room.join payload cannot include both request_id and perspective",
        )


_ROOM_UPDATE_FIELDS = frozenset(
    {"topic", "agenda", "guidance", "tags", "language", "policy", "start_time", "end_time"}
)


def validate_room_update_payload(payload: dict[str, Any]) -> None:
    """Shape checks for a `room.update` payload. State-dependent rules — room
    status, effective time ordering against the current contract — remain
    host-side."""
    if not payload:
        raise AgentProtocolError("invalid_event", "room.update payload must not be empty")
    for field in payload:
        if field not in _ROOM_UPDATE_FIELDS:
            raise AgentProtocolError(
                "invalid_event", f"room.update payload field {field} is not updatable"
            )
    topic = payload.get("topic")
    if topic is not None and not str(topic).strip():
        raise AgentProtocolError("invalid_event", "room topic must not be empty")
    start_time = payload.get("start_time")
    end_time = payload.get("end_time")
    if start_time is not None and end_time is not None and start_time >= end_time:
        raise AgentProtocolError("invalid_event", "start_time must be before end_time")
    policy = payload.get("policy") or {}
    max_speakers = policy.get("max_speakers")
    if max_speakers is not None and (not isinstance(max_speakers, int) or max_speakers < 1):
        raise AgentProtocolError("invalid_event", "max_speakers must be a positive integer")


def validate_room_member_remove_payload(payload: dict[str, Any]) -> None:
    """Shape checks for a `room.member.remove` payload. Creator, self, and
    membership checks remain host-side."""
    validate_agent_id(payload.get("member"))
    ban = payload.get("ban")
    if ban is not None and not isinstance(ban, bool):
        raise AgentProtocolError("invalid_event", "ban must be a boolean")


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


def default_kind_roles(kind: str) -> tuple[str, ...]:
    """Default sender roles for each kind. The creator passes every role check."""
    if kind == "message":
        return ("moderator", "speaker")
    if kind == "signal":
        return ("moderator", "speaker", "observer")
    if kind == "control":
        return ("moderator",)
    raise AgentProtocolError("invalid_event", f"invalid type kind: {kind}")


def can_submit_event(
    event_type: str,
    context: PermissionContext,
    registry: TypeRegistry | None = None,
) -> bool:
    """Role check for one event type, using kind defaults and per-type role
    overrides from the room's type registry. State checks are separate."""
    is_creator = bool(context.get("is_creator"))
    role = context.get("role")
    if event_type == ROOM_CREATE:
        return True
    if event_type == ROOM_JOIN:
        return bool(context.get("public_join_allowed") or context.get("join_request_approved"))
    if event_type == ROOM_LEAVE:
        return is_creator or role is not None
    if event_type in {
        ROOM_UPDATE,
        ROOM_JOIN_REVIEW,
        ROOM_MEMBER_ROLE_UPDATE,
        ROOM_MEMBER_REMOVE,
        ROOM_CLOSE,
        ROOM_CANCEL,
        TYPE_DEFINE,
    }:
        return is_creator or role == "moderator"
    if event_type == MESSAGE_CREATE:
        return is_creator or role in ("moderator", "speaker")

    definition = registry.get(event_type) if registry is not None else None
    if definition is None or definition.get("status", "active") == "disabled":
        return False
    if is_creator:
        return True
    if role is None:
        return False
    roles = definition.get("roles") or default_kind_roles(definition["kind"])
    return role in roles


def can_write_in_state(event_type: str, state: RoomState) -> bool:
    if state == "scheduled":
        return event_type in {
            ROOM_JOIN,
            ROOM_JOIN_REVIEW,
            ROOM_MEMBER_ROLE_UPDATE,
            ROOM_MEMBER_REMOVE,
            ROOM_LEAVE,
            ROOM_UPDATE,
            TYPE_DEFINE,
            ROOM_CANCEL,
        }
    if state == "active":
        return event_type not in {ROOM_CREATE, ROOM_CANCEL}
    return False


def can_accept_room_write(
    event_type: str,
    state: RoomState,
    context: PermissionContext,
    registry: TypeRegistry | None = None,
) -> bool:
    return can_submit_event(event_type, context, registry) and can_write_in_state(event_type, state)


def validate_room_write(
    event_type: str,
    state: RoomState,
    context: PermissionContext,
    registry: TypeRegistry | None = None,
) -> None:
    if not can_accept_room_write(event_type, state, context, registry):
        raise AgentProtocolError("permission_denied", "actor lacks permission or state is not writable")


def _hash_canonical_json(value: Any) -> str:
    canonical = rfc8785.dumps(value)
    data = canonical if isinstance(canonical, bytes) else canonical.encode()
    digest = hashlib.sha3_256(data).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
