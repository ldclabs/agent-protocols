"""Agent Discourse Protocol 1.0: kernel types, the room type system, and
verification helpers.

The protocol defines twelve built-in event types. Every other event type is
declared per room as a schema-validated type definition, either inline or
imported from a type pack. Hosts validate structure and permissions; they
never need to understand application semantics.
"""

from __future__ import annotations

import base64
import copy
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
    validate_event_fields,
    validate_origin,
    verify_envelope,
    with_room_head,
    with_room_id,
)

DISCOURSE_PROTOCOL = "agent-discourse/1.0"

# The twelve built-in event types. All other types are room-defined.
ROOM_CREATE = "room.create"
ROOM_UPDATE = "room.update"
ROOM_JOIN = "room.join"
ROOM_JOIN_REQUEST = "room.join.request"
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
    ROOM_JOIN_REQUEST,
    ROOM_JOIN_REVIEW,
    ROOM_LEAVE,
    ROOM_MEMBER_ROLE_UPDATE,
    ROOM_MEMBER_REMOVE,
    ROOM_CLOSE,
    ROOM_CANCEL,
    TYPE_DEFINE,
    MESSAGE_CREATE,
}

# Built-in membership events. They are `signal`-class: they anchor to an
# accepted record but are never checked against or advance the room head, so
# busy rooms cannot starve joins, reviews, or other membership writes.
MEMBERSHIP_EVENT_TYPES = (
    ROOM_JOIN,
    ROOM_JOIN_REVIEW,
    ROOM_LEAVE,
    ROOM_MEMBER_ROLE_UPDATE,
    ROOM_MEMBER_REMOVE,
)

# Contract writes (Section 5.1): anchored like signals, so discussion traffic
# cannot starve them, but head-advancing, so messages and control writes
# composed against the old contract are rejected and re-read.
CONTRACT_EVENT_TYPES = (ROOM_UPDATE, ROOM_CLOSE, ROOM_CANCEL, TYPE_DEFINE)

# ADP-specific error codes (Section 19); shared codes come from Agent Identity.
DISCOURSE_ERROR_CODES = (
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
)

# Hosts MUST reject events with more than this many `mentions` entries.
MAX_MENTIONS = 32

# Room IDs are host-assigned and URL-safe (Section 6.1).
ROOM_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}")

# `<algorithm>:<base64url-digest>` content digests (Section 12.5).
CONTENT_DIGEST_PATTERN = re.compile(r"(sha256|sha3-256):[A-Za-z0-9_-]{43}")

# Custom event types must not use these prefixes.
RESERVED_TYPE_PREFIXES = ("room.", "type.", "message.")

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
BuiltinEventClass = Literal["genesis", "contract", "signal", "message"]
# Freshness class for built-in types, registry kind for custom types.
RecordClass = Literal["genesis", "contract", "message", "signal", "control"]

ROLES = ("moderator", "speaker", "observer")
TYPE_KINDS = ("message", "signal", "control")
TYPE_STATUSES = ("active", "deprecated", "disabled")

_TYPE_SEGMENT = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_REGISTERED_PACK_ID = re.compile(r"^adp:[a-z0-9-]+/[0-9]+\.[0-9]+$")


class PermissionContext(TypedDict, total=False):
    """Permission inputs for one actor in one room."""

    role: Role
    is_creator: bool
    # The actor may take the requested role by direct `room.join` (see can_join_directly).
    direct_join_allowed: bool


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


def room_join_request_event(
    actor: AgentId, created_at: int, nonce: int, room_id: str, payload: dict[str, Any]
) -> Event:
    """A `room.join.request` carries `room_id` but no base: its author may not
    be able to read the room."""
    return with_room_id(create_event(DISCOURSE_PROTOCOL, ROOM_JOIN_REQUEST, actor, created_at, nonce, payload), room_id)


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


def event_requires_base(event_type: str) -> bool:
    """Whether events of this type carry `base_seq` / `base_hash`."""
    return event_type not in (ROOM_CREATE, ROOM_JOIN_REQUEST)


_BUILTIN_EVENT_CLASSES: dict[str, BuiltinEventClass] = {
    ROOM_CREATE: "genesis",
    ROOM_UPDATE: "contract",
    ROOM_CLOSE: "contract",
    ROOM_CANCEL: "contract",
    TYPE_DEFINE: "contract",
    ROOM_JOIN: "signal",
    ROOM_JOIN_REVIEW: "signal",
    ROOM_LEAVE: "signal",
    ROOM_MEMBER_ROLE_UPDATE: "signal",
    ROOM_MEMBER_REMOVE: "signal",
    MESSAGE_CREATE: "message",
}


def builtin_event_class(event_type: str) -> BuiltinEventClass | None:
    """Section 12.2 class of a built-in type; ``None`` for room-defined types
    and for `room.join.request`, which never becomes a record."""
    return _BUILTIN_EVENT_CLASSES.get(event_type)


def record_class(
    event_type: str, registry: "TypeRegistry | Iterable[dict[str, Any]] | None" = None
) -> RecordClass | None:
    """Record class of an event type; ``None`` for `room.join.request` and for
    custom types absent from ``registry``."""
    builtin = builtin_event_class(event_type)
    if builtin is not None:
        return builtin
    if is_builtin_event_type(event_type):
        return None
    if isinstance(registry, TypeRegistry):
        definition = registry.get(event_type)
    else:
        definition = next((d for d in registry or [] if d.get("type") == event_type), None)
    return definition.get("kind") if definition is not None else None


def event_advances_room_head(
    event_type: str, registry: "TypeRegistry | Iterable[dict[str, Any]] | None" = None
) -> bool:
    """Whether an accepted record of this type advances the room head (Section
    5.1): `genesis`, `contract`, and `control` records. Unknown custom types
    default to head-advancing."""
    return record_class(event_type, registry) not in ("message", "signal")


def event_requires_room_head(
    event_type: str, registry: "TypeRegistry | Iterable[dict[str, Any]] | None" = None
) -> bool:
    """Whether a write of this type is checked against the room head (Section
    5.1): `message.create` and custom `message`/`control` kinds must be based
    at or after the current head. Contract and signal writes only anchor.
    Unknown custom types default to head-checked."""
    cls = record_class(event_type, registry)
    if cls is None:
        return not is_builtin_event_type(event_type)
    return cls in ("message", "control")


def validate_room_base(
    event_type: str,
    registry: "TypeRegistry | Iterable[dict[str, Any]] | None",
    base_seq: int,
    base_hash: str,
    anchor_hash: str | None,
    head_seq: int,
) -> None:
    """Section 5.1 base check for a room write based on ``base_seq`` /
    ``base_hash``. ``anchor_hash`` is the hash of the accepted record at
    ``base_seq`` in the same room (``None`` when there is none) and
    ``head_seq`` is the current room head. Every base must name an accepted
    record (`base_record_mismatch`); `message` and `control` writes must also
    be based at or after the head (`room_head_mismatch`)."""
    if anchor_hash != base_hash:
        raise AgentProtocolError(
            "base_record_mismatch", f"base {base_seq} does not name an accepted record of this room"
        )
    if event_requires_room_head(event_type, registry) and base_seq < head_seq:
        raise AgentProtocolError("room_head_mismatch", f"base {base_seq} is before the room head {head_seq}")


def validate_room_id(room_id: Any) -> None:
    if not isinstance(room_id, str) or not ROOM_ID_PATTERN.fullmatch(room_id):
        raise AgentProtocolError("invalid_event", "room_id must match [A-Za-z0-9_-]{1,64}")


def validate_discourse_envelope(envelope: Envelope) -> None:
    verify_envelope(envelope)
    validate_discourse_event_fields(envelope["event"])


def validate_discourse_event_fields(event: Event) -> None:
    """Section 5 event-shape rules: closed fields, room ID, base, and mentions."""
    protocol = event.get("protocol")
    if protocol != DISCOURSE_PROTOCOL:
        raise AgentProtocolError("invalid_event_protocol", f"expected {DISCOURSE_PROTOCOL}, got {protocol}")
    if event["type"] == ROOM_CREATE:
        validate_event_fields(event)
        return
    if event["type"] == ROOM_JOIN_REQUEST:
        validate_event_fields(event, ("room_id",))
        if "room_id" not in event:
            raise AgentProtocolError("missing_room_id", "event requires a room_id")
        validate_room_id(event["room_id"])
        return
    validate_event_fields(event, ("room_id", "base_seq", "base_hash", "mentions"))
    if "room_id" not in event:
        raise AgentProtocolError("missing_room_id", "event requires a room_id")
    validate_room_id(event["room_id"])
    validate_room_head_precondition(event)
    _validate_mentions(event.get("mentions"))


def validate_room_path(envelope: Envelope, path_room_id: str) -> None:
    event = envelope["event"]
    validate_discourse_event_fields(event)
    if event["type"] == ROOM_CREATE:
        return
    actual = event.get("room_id")
    if actual != path_room_id:
        raise AgentProtocolError("room_id_mismatch", f"expected {path_room_id}, got {actual}")


def validate_room_head_precondition(event: Event) -> None:
    base_seq = event.get("base_seq")
    base_hash = event.get("base_hash")
    if type(base_seq) is not int or base_seq < 1 or base_seq > MAX_SAFE_NONCE:
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
    return isinstance(declaration, dict) and ("use" in declaration or "pack" in declaration or "digest" in declaration)


_TYPE_DEF_FIELDS = frozenset(
    {"type", "kind", "title", "description", "schema", "roles", "instructions",
     "status", "rate_hint", "max_payload_hint", "extra"}
)


def validate_type_def(definition: dict[str, Any]) -> None:
    for key in definition:
        if key not in _TYPE_DEF_FIELDS:
            raise AgentProtocolError("invalid_event", f"unknown type definition field: {key}")
    validate_custom_event_type_name(str(definition.get("type", "")))
    if definition.get("kind") not in TYPE_KINDS:
        raise AgentProtocolError("invalid_event", f"invalid type kind: {definition.get('kind')}")
    if not str(definition.get("title", "")).strip():
        raise AgentProtocolError("invalid_event", "type definition title must not be empty")
    schema = definition.get("schema")
    if not isinstance(schema, dict):
        raise AgentProtocolError("invalid_type_schema", "type definition schema must be a JSON Schema object")
    validate_type_schema_profile(schema)
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
        if value is not None and (type(value) is not int or value < 1):
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
        if not str(declaration["pack"]).startswith("https://"):
            raise AgentProtocolError("invalid_event", "external pack must be an HTTPS URL")
        if not isinstance(declaration["digest"], str) or not CONTENT_DIGEST_PATTERN.fullmatch(declaration["digest"]):
            raise AgentProtocolError(
                "invalid_event", "external pack digest must be <sha256|sha3-256>:<base64url-digest>"
            )
    else:
        raise AgentProtocolError("invalid_event", "pack import requires either use, or pack with digest")
    types = declaration.get("types")
    if types is not None:
        if not isinstance(types, list) or not types:
            raise AgentProtocolError("invalid_event", "pack import types subset must not be empty")
        if len(set(types)) != len(types):
            raise AgentProtocolError("type_conflict", "pack import types subset has duplicates")


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


# ── Type schema profile (Section 12.3.1).

_FORBIDDEN_SCHEMA_KEYWORDS = ("$dynamicRef", "$dynamicAnchor", "$recursiveRef", "$recursiveAnchor", "$vocabulary")
_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
_ANNOTATION_KEYWORDS = ("format", "contentEncoding", "contentMediaType", "contentSchema")
_SUBSCHEMA_KEYWORDS = (
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
)
_SUBSCHEMA_ARRAY_KEYWORDS = ("allOf", "anyOf", "oneOf", "prefixItems")
_SUBSCHEMA_MAP_KEYWORDS = ("properties", "patternProperties", "$defs", "definitions", "dependentSchemas")


def _walk_schema(schema: Any, visit: Any) -> None:
    """Calls ``visit`` on every subschema object of ``schema``, depth first."""
    if not isinstance(schema, dict):
        return
    visit(schema)
    for key in _SUBSCHEMA_KEYWORDS:
        _walk_schema(schema.get(key), visit)
    for key in _SUBSCHEMA_ARRAY_KEYWORDS:
        if isinstance(schema.get(key), list):
            for item in schema[key]:
                _walk_schema(item, visit)
    for key in _SUBSCHEMA_MAP_KEYWORDS:
        if isinstance(schema.get(key), dict):
            for value in schema[key].values():
                _walk_schema(value, visit)


def validate_type_schema_profile(schema: dict[str, Any]) -> None:
    """Enforces the type schema profile (Section 12.3.1): fragment-only `$ref`,
    no dynamic or recursive references, the 2020-12 dialect, and portable
    regular expressions."""

    def visit(node: dict[str, Any]) -> None:
        for keyword in _FORBIDDEN_SCHEMA_KEYWORDS:
            if keyword in node:
                raise AgentProtocolError("invalid_type_schema", f"{keyword} is not allowed")
        if "$schema" in node and node["$schema"] != _SCHEMA_DIALECT:
            raise AgentProtocolError("invalid_type_schema", "$schema must be the draft 2020-12 dialect")
        if "$ref" in node and (not isinstance(node["$ref"], str) or not node["$ref"].startswith("#")):
            raise AgentProtocolError("invalid_type_schema", "$ref must be a fragment inside the schema")
        if "pattern" in node:
            if not isinstance(node["pattern"], str):
                raise AgentProtocolError("invalid_type_schema", "pattern must be a string")
            validate_portable_pattern(node["pattern"])
        if isinstance(node.get("patternProperties"), dict):
            for pattern in node["patternProperties"]:
                validate_portable_pattern(pattern)

    _walk_schema(schema, visit)


_SINGLE_ESCAPES = "()*+-.?[\\]^{|}nrt"
_QUANTIFIER = re.compile(r"\{[0-9]+(,[0-9]*)?\}")


def validate_portable_pattern(pattern: str) -> None:
    """Checks that a pattern is an I-Regexp (RFC 9485) without ``\\p{…}``/``\\P{…}``
    and without ``.`` outside a character class, optionally anchored with a
    leading ``^`` and a trailing ``$`` (Section 12.3.1)."""

    def reject(reason: str) -> AgentProtocolError:
        return AgentProtocolError("invalid_type_schema", f"pattern {pattern!r} is not portable: {reason}")

    body = pattern[1:] if pattern.startswith("^") else pattern
    if body.endswith("$") and not body.endswith("\\$"):
        body = body[:-1]
    chars = list(body)
    i = 0
    depth = 0
    can_quantify = False

    def read_escape(index: int) -> int:
        following = chars[index + 1] if index + 1 < len(chars) else None
        if following is None:
            raise reject("dangling escape")
        if following not in _SINGLE_ESCAPES:
            raise reject(f"escape \\{following}")
        return index + 2

    while i < len(chars):
        ch = chars[i]
        if ch == "\\":
            i = read_escape(i)
            can_quantify = True
        elif ch == "[":
            i += 1
            if i < len(chars) and chars[i] == "^":
                i += 1
            # A leading `]` is literal in some engines and an empty class in others.
            if i < len(chars) and chars[i] == "]":
                raise reject("empty character class")
            while i < len(chars) and chars[i] != "]":
                if chars[i] == "\\":
                    i = read_escape(i)
                elif chars[i] == "[":
                    raise reject("nested character class")
                else:
                    i += 1
            if i >= len(chars):
                raise reject("unterminated character class")
            i += 1
            can_quantify = True
        elif ch == "(":
            if i + 1 < len(chars) and chars[i + 1] == "?":
                raise reject("group modifiers")
            depth += 1
            i += 1
            can_quantify = False
        elif ch == ")":
            if depth == 0:
                raise reject("unbalanced parenthesis")
            depth -= 1
            i += 1
            can_quantify = True
        elif ch == "|":
            i += 1
            can_quantify = False
        elif ch in "*+?":
            if not can_quantify:
                raise reject("quantifier without operand")
            i += 1
            if i < len(chars) and chars[i] in "?+":
                raise reject("lazy or possessive quantifier")
            can_quantify = False
        elif ch == "{":
            if not can_quantify:
                raise reject("quantifier without operand")
            match = _QUANTIFIER.match("".join(chars[i:]))
            if match is None:
                raise reject("malformed quantifier")
            i += len(match.group(0))
            if i < len(chars) and chars[i] in "?+":
                raise reject("lazy or possessive quantifier")
            can_quantify = False
        elif ch == ".":
            raise reject("'.' outside a character class")
        elif ch in "^$":
            raise reject("anchor inside the pattern")
        elif ch in "}]":
            raise reject(f"unescaped {ch}")
        else:
            i += 1
            can_quantify = True
    if depth != 0:
        raise reject("unbalanced parenthesis")


def _strip_annotations(schema: dict[str, Any]) -> dict[str, Any]:
    """A copy of ``schema`` without annotation-only keywords, which validators must not assert."""
    stripped = copy.deepcopy(schema)

    def visit(node: dict[str, Any]) -> None:
        for keyword in _ANNOTATION_KEYWORDS:
            node.pop(keyword, None)

    _walk_schema(stripped, visit)
    return stripped


_ROOM_POLICY_FIELDS = frozenset({"invites", "open_roles", "max_speakers", "observer_allowed", "extra"})


def validate_room_policy(policy: dict[str, Any] | None) -> None:
    """Section 8.3 rules for a room policy."""
    if policy is None:
        return
    if not isinstance(policy, dict):
        raise AgentProtocolError("invalid_event", "policy must be an object")
    for key in policy:
        if key not in _ROOM_POLICY_FIELDS:
            raise AgentProtocolError("invalid_event", f"unknown policy field: {key}")
    max_speakers = policy.get("max_speakers")
    if max_speakers is not None and (type(max_speakers) is not int or max_speakers < 1):
        raise AgentProtocolError("invalid_event", "max_speakers must be a positive integer")
    observer_allowed = policy.get("observer_allowed", True)
    invites = policy.get("invites")
    if invites is not None:
        if not isinstance(invites, dict):
            raise AgentProtocolError("invalid_event", "invites must be an object")
        for agent_id, role in invites.items():
            validate_agent_id(agent_id)
            if role not in ROLES:
                raise AgentProtocolError("invalid_event", f"invalid invited role: {role}")
            if role == "observer" and not observer_allowed:
                raise AgentProtocolError("role_not_allowed", "observers are not allowed")
    open_roles = policy.get("open_roles")
    if open_roles is not None:
        if not isinstance(open_roles, list) or len(set(open_roles)) != len(open_roles):
            raise AgentProtocolError("invalid_event", "open_roles must be a list of unique roles")
        for role in open_roles:
            if role not in ("speaker", "observer"):
                raise AgentProtocolError("invalid_event", f"open_roles cannot contain {role}")
            if role == "observer" and not observer_allowed:
                raise AgentProtocolError("role_not_allowed", "observers are not allowed")


def validate_room_visibility_policy(visibility: Visibility, policy: dict[str, Any] | None) -> None:
    """Section 8.3 rule tying the policy to the room's visibility: a private
    room admits agents only by invitation or review, so its `open_roles` must
    be empty."""
    if visibility == "private" and policy is not None and policy.get("open_roles"):
        raise AgentProtocolError("invalid_event", "a private room cannot have open roles")


def effective_open_roles(visibility: Visibility, policy: dict[str, Any] | None) -> list[Role]:
    """The roles any agent may take by direct `room.join` (Section 8.3): the
    explicit `open_roles`, or by default `observer` in a public room when
    observers are allowed, and none otherwise."""
    if policy is not None and policy.get("open_roles") is not None:
        return list(policy["open_roles"])
    if visibility == "public" and (policy is None or policy.get("observer_allowed") is not False):
        return ["observer"]
    return []


def can_join_directly(visibility: Visibility, policy: dict[str, Any] | None, actor: AgentId, role: Role) -> bool:
    """Section 9.2 direct-join eligibility: the actor is invited with exactly
    ``role``, or ``role`` is one of the room's effective open roles. Bans and
    quotas are separate host checks."""
    if policy is not None and (policy.get("invites") or {}).get(actor) == role:
        return True
    return role in effective_open_roles(visibility, policy)


def validate_room_create_payload(payload: dict[str, Any]) -> None:
    try:
        validate_origin(payload.get("host"))
    except AgentProtocolError as exc:
        raise AgentProtocolError("invalid_event", "room.create host must be an HTTPS origin") from exc
    if not str(payload.get("topic", "")).strip():
        raise AgentProtocolError("invalid_event", "room topic must not be empty")
    if payload.get("start_time", 0) >= payload.get("end_time", 0):
        raise AgentProtocolError("invalid_event", "start_time must be before end_time")
    validate_room_policy(payload.get("policy"))
    validate_room_visibility_policy(payload.get("visibility"), payload.get("policy"))
    for declaration in payload.get("types", []):
        validate_type_declaration(declaration)


def validate_room_create_host(payload: dict[str, Any], host_origin: str) -> None:
    """Host binding check (Section 8.1): `host` must be the receiving host's API origin."""
    if payload.get("host") != host_origin:
        raise AgentProtocolError("host_mismatch", f"room.create names {payload.get('host')}, not {host_origin}")


def validate_message_create_payload(payload: dict[str, Any]) -> None:
    content_type = payload.get("content_type")
    if not isinstance(content_type, str) or not content_type.strip():
        raise AgentProtocolError("invalid_event", "content_type must not be empty")
    if not isinstance(payload.get("content"), (str, dict)):
        raise AgentProtocolError("invalid_event", "content must be a string or an object")


def validate_room_join_payload(payload: dict[str, Any]) -> None:
    for key in payload:
        if key not in ("role", "perspective"):
            raise AgentProtocolError("invalid_event", f"unknown room.join payload field: {key}")
    if payload.get("role") not in ROLES:
        raise AgentProtocolError("invalid_event", f"invalid room role: {payload.get('role')}")


def validate_room_join_request_payload(payload: dict[str, Any]) -> None:
    for key in payload:
        if key not in ("role", "perspective", "reason", "extra"):
            raise AgentProtocolError("invalid_event", f"unknown room.join.request payload field: {key}")
    if payload.get("role") not in ROLES:
        raise AgentProtocolError("invalid_event", f"invalid room role: {payload.get('role')}")


def validate_join_request_envelope(envelope: Envelope, room_id: str | None = None) -> None:
    """Verifies a signed `room.join.request` envelope for embedding or review:
    hash, signature, and shape — historical verification, without the live
    time window or nonce check."""
    validate_discourse_envelope(envelope)
    event = envelope["event"]
    if event["type"] != ROOM_JOIN_REQUEST:
        raise AgentProtocolError("invalid_event", "embedded request must be a room.join.request")
    if room_id is not None and event.get("room_id") != room_id:
        raise AgentProtocolError("room_id_mismatch", "join request belongs to another room")
    validate_room_join_request_payload(event["payload"])


def validate_room_join_review_payload(payload: dict[str, Any], room_id: str | None = None) -> None:
    """Shape checks for `room.join.review`, including the embedded signed request."""
    validate_join_request_envelope(payload.get("request"), room_id)
    decision = payload.get("decision")
    if decision not in ("approve", "reject"):
        raise AgentProtocolError("invalid_event", f"invalid review decision: {decision}")
    if decision == "approve" and payload.get("role") not in ROLES:
        raise AgentProtocolError("invalid_event", "an approving review requires a role")


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
    validate_room_policy(payload.get("policy"))


def validate_room_member_remove_payload(payload: dict[str, Any]) -> None:
    """Shape checks for a `room.member.remove` payload. Creator, self, and
    membership checks remain host-side."""
    validate_agent_id(payload.get("member"))
    ban = payload.get("ban")
    if ban is not None and not isinstance(ban, bool):
        raise AgentProtocolError("invalid_event", "ban must be a boolean")


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
        """Materializes a registry from the `room.create` declarations,
        resolving pack imports from `packs`, keyed by registered pack id or
        external pack URI. A type name may appear only once across these
        declarations."""
        registry = cls()
        declared: set[str] = set()
        for declaration in declarations:
            for name in registry.apply(declaration, packs):
                if name in declared:
                    raise AgentProtocolError("type_conflict", f"type {name} is declared twice")
                declared.add(name)
        return registry

    def apply(self, declaration: dict[str, Any], packs: dict[str, dict[str, Any]] | None = None) -> list[str]:
        """Applies one declaration — an inline definition or a pack import —
        and returns the type names it declared. Declaring an existing type is
        a redefinition: it must keep the type's kind, and the latest
        definition wins."""
        if is_pack_import(declaration):
            return self._import(declaration, packs or {})
        if isinstance(declaration, dict) and "type" in declaration:
            self.define(declaration)
            return [declaration["type"]]
        else:
            raise AgentProtocolError(
                "invalid_event", "type declaration must be an inline definition or a pack import"
            )

    def define(self, definition: dict[str, Any]) -> None:
        validate_type_def(definition)
        existing = self._types.get(definition["type"])
        if existing is not None and existing.get("kind") != definition.get("kind"):
            raise AgentProtocolError(
                "type_conflict",
                f"type {definition['type']} cannot change kind from {existing.get('kind')} to {definition.get('kind')}",
            )
        self._types[definition["type"]] = definition

    def _import(self, declaration: dict[str, Any], packs: dict[str, dict[str, Any]]) -> list[str]:
        validate_pack_import(declaration)
        reference = declaration.get("use") or declaration.get("pack")
        pack = packs.get(reference)
        if pack is None:
            raise AgentProtocolError("pack_unavailable", f"pack not available: {reference}")
        available: set[str] = set()
        for definition in pack.get("types", []):
            if definition["type"] in available:
                raise AgentProtocolError("type_conflict", f"pack {reference} defines {definition['type']} twice")
            available.add(definition["type"])
        subset = declaration.get("types")
        if subset is not None:
            for name in subset:
                if name not in available:
                    raise AgentProtocolError("type_conflict", f"type {name} is not in pack {reference}")
        overrides = declaration.get("overrides") or {}
        for name in overrides:
            imported = name in subset if subset is not None else name in available
            if not imported:
                raise AgentProtocolError(
                    "type_conflict", f"override target {name} is not imported from pack {reference}"
                )
        declared: list[str] = []
        for definition in pack.get("types", []):
            if subset is not None and definition["type"] not in subset:
                continue
            merged = dict(definition)
            merged.update(overrides.get(definition["type"], {}))
            self.define(merged)
            declared.append(definition["type"])
        return declared

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
        raise AgentProtocolError("invalid_type_schema", f"invalid type schema: {error}") from error
    # Annotation keywords are never asserted (Section 12.3.1).
    return Draft202012Validator(_strip_annotations(schema))


def verify_pack_digest(data: bytes, digest: str) -> None:
    """Verifies a `<algorithm>:<base64url-digest>` content digest over raw
    bytes. Supports `sha256` and `sha3-256`."""
    if not isinstance(digest, str) or not CONTENT_DIGEST_PATTERN.fullmatch(digest):
        raise AgentProtocolError("pack_unavailable", f"invalid digest format: {digest}")
    algorithm, _, expected = digest.partition(":")
    raw = hashlib.sha256(data).digest() if algorithm == "sha256" else hashlib.sha3_256(data).digest()
    actual = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    if actual != expected:
        raise AgentProtocolError("pack_unavailable", "pack digest mismatch")


def server_record_hash_payload(
    room_id: str,
    seq: int,
    pre_hash: str | None,
    envelope_hash: str,
    accepted_at: int,
) -> dict[str, Any]:
    return {
        "room_id": room_id,
        "seq": seq,
        "pre_hash": pre_hash,
        "envelope_hash": envelope_hash,
        "accepted_at": accepted_at,
    }


def server_record_hash(
    room_id: str,
    seq: int,
    pre_hash: str | None,
    envelope_hash: str,
    accepted_at: int,
) -> str:
    return _hash_canonical_json(server_record_hash_payload(room_id, seq, pre_hash, envelope_hash, accepted_at))


def build_server_record(
    room_id: str,
    seq: int,
    pre_hash: str | None,
    accepted_at: int,
    envelope: Envelope,
) -> dict[str, Any]:
    return {
        "room_id": room_id,
        "seq": seq,
        "pre_hash": pre_hash,
        "hash": server_record_hash(room_id, seq, pre_hash, envelope["hash"], accepted_at),
        "accepted_at": accepted_at,
        "envelope": envelope,
    }


def is_redacted_record(record: dict[str, Any]) -> bool:
    envelope = record.get("envelope")
    return isinstance(envelope, dict) and envelope.get("redacted") is True


def redact_server_record(record: dict[str, Any]) -> dict[str, Any]:
    """Replaces a record's envelope with its redacted form (Section 14.1). Only
    `message.create` and custom-type records may be redacted."""
    event_type = record["envelope"]["event"]["type"]
    if is_builtin_event_type(event_type) and event_type != MESSAGE_CREATE:
        raise AgentProtocolError("invalid_event", f"{event_type} records cannot be redacted")
    return {**record, "envelope": {"hash": record["envelope"]["hash"], "redacted": True, "type": event_type}}


def verify_server_record(record: dict[str, Any]) -> None:
    """Verifies one signed or redacted record's hash; a redacted record must be
    of a redactable type."""
    expected = server_record_hash(
        record["room_id"],
        record["seq"],
        record.get("pre_hash"),
        record["envelope"]["hash"],
        record["accepted_at"],
    )
    if record["hash"] != expected:
        raise AgentProtocolError("invalid_record_hash", f"invalid server record hash: expected {expected}, got {record['hash']}")
    if is_redacted_record(record):
        event_type = record["envelope"].get("type")
        if is_builtin_event_type(event_type) and event_type != MESSAGE_CREATE:
            raise AgentProtocolError("invalid_record_chain", f"{event_type} records cannot be redacted")


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


def verify_archive_records(manifest: dict[str, Any], records: list[dict[str, Any]]) -> list[int]:
    """Archive verification steps 1–3 (Section 18): a gap-free chain from seq 1
    to `last_seq` ending in `last_hash`, and a valid signature on every record
    that is not redacted. Returns the sequence numbers of redacted records,
    which verifiers must report. State replay (step 4) is the caller's."""
    verify_server_record_chain(records)
    if not records or records[-1]["seq"] != manifest.get("last_seq") or records[-1]["hash"] != manifest.get("last_hash"):
        raise AgentProtocolError("invalid_record_chain", "archive does not end at last_seq / last_hash")
    redacted: list[int] = []
    for record in records:
        if record["room_id"] != manifest.get("room_id"):
            raise AgentProtocolError("invalid_record_chain", "record belongs to another room")
        if is_redacted_record(record):
            redacted.append(record["seq"])
        else:
            validate_discourse_envelope(record["envelope"])
    return redacted


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
        return bool(context.get("direct_join_allowed")) and not is_creator and role is None
    if event_type == ROOM_JOIN_REQUEST:
        return not is_creator and role is None
    if event_type == ROOM_LEAVE:
        # The creator is a member until the room ends and cannot leave.
        return not is_creator and role is not None
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
            ROOM_JOIN_REQUEST,
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
