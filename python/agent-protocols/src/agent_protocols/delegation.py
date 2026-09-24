from __future__ import annotations

from typing import Any, TypedDict, Literal
from copy import deepcopy
from urllib.parse import urlparse
import re

import rfc8785

from .errors import AgentProtocolError
from .identity import (
    AGENT_ID_PREFIX,
    AgentId,
    Envelope,
    Event,
    create_event,
    validate_agent_id,
    validate_event_fields,
    validate_origin,
    verify_envelope,
)

DELEGATION_PROTOCOL = "agent-delegation/1.0"
DELEGATION_GRANT = "delegation.grant"
DELEGATION_REVOKE = "delegation.revoke"

# Delegation IDs are unreserved URL characters: no percent-encoding, no look-alikes.
DELEGATION_ID_PATTERN = re.compile(r"[A-Za-z0-9._~-]{1,128}")

# Delegation-specific error codes (Agent Delegation Section 9.7).
DELEGATION_ERROR_CODES = (
    "principal_unresolvable",
    "principal_not_canonical",
    "controller_not_current",
    "delegation_not_permitted",
    "delegation_ceiling_exceeded",
    "not_owner_controller",
    "credential_not_found",
    "credential_identity_mismatch",
    "grant_expired",
)

_STATUSES = ("active", "suspended", "expired", "revoked")

DelegationGrantPayload = dict[str, Any]
DelegationRevokePayload = dict[str, Any]
DelegationCredential = dict[str, Any]
class DelegationPolicy(TypedDict):
    scopes: list[str]
    audiences: list[str]


class _ControllerBinding(TypedDict):
    id: AgentId
    source: str
    valid_from: int


class Controller(_ControllerBinding, total=False):
    name: str
    delegation: Literal["*"] | DelegationPolicy
    # Earlier controllers of this principal whose credentials this key may manage.
    supersedes: list[AgentId]
    retired_at: int
    invalid_from: int


class DelegationRecord(TypedDict):
    """An accepted record (Agent Identity Section 8.3)."""

    envelope: Envelope
    accepted_at: int


class DelegationVerdict(TypedDict):
    """Result of :func:`verify_delegation_credential`."""

    credential: DelegationCredential
    # Latest-grant signature, controller, ceiling, and consistency checks passed.
    verified: bool
    # Verified, and usable for the audience now.
    usable: bool
    # Every failed check.
    reasons: list[str]


PrincipalDocument = dict[str, Any]


def delegation_grant_event(
    actor: AgentId,
    created_at: int,
    nonce: int,
    payload: DelegationGrantPayload,
) -> Event:
    return create_event(DELEGATION_PROTOCOL, DELEGATION_GRANT, actor, created_at, nonce, payload)


def delegation_revoke_event(
    actor: AgentId,
    created_at: int,
    nonce: int,
    payload: DelegationRevokePayload,
) -> Event:
    return create_event(DELEGATION_PROTOCOL, DELEGATION_REVOKE, actor, created_at, nonce, payload)


def validate_controller(controller: Controller, retired: bool = False) -> None:
    if not isinstance(controller, dict):
        _fail("controller must be an object")
    validate_agent_id(controller.get("id"))
    if controller.get("source") != "local":
        validate_origin(controller.get("source"))
    _timestamp(controller.get("valid_from"), "valid_from")
    if "name" in controller:
        _validate_non_empty(controller["name"], "name")
    if "delegation" in controller and controller["delegation"] != "*":
        policy = controller["delegation"]
        if not isinstance(policy, dict) or set(policy) != {"scopes", "audiences"}:
            _fail("invalid delegation policy")
        _strings(policy["scopes"], "scopes")
        _strings(policy["audiences"], "audiences")
        for audience in policy["audiences"]:
            validate_audience(audience)
    if "supersedes" in controller:
        _strings(controller["supersedes"], "supersedes")
        for agent_id in controller["supersedes"]:
            validate_agent_id(agent_id)
    if retired:
        _timestamp(controller.get("retired_at"), "retired_at")
        if controller["retired_at"] < controller["valid_from"]:
            _fail("retired_at precedes valid_from")
        if "invalid_from" in controller:
            _timestamp(controller["invalid_from"], "invalid_from")
            if not controller["valid_from"] <= controller["invalid_from"] <= controller["retired_at"]:
                _fail("invalid compromise interval")
    elif "retired_at" in controller or "invalid_from" in controller:
        _fail("current controller has retirement fields")


def validate_principal_document(document: PrincipalDocument) -> None:
    if not isinstance(document, dict):
        _fail("principal must be an object")
    _validate_https_url(document.get("id"), "principal.id")
    if document.get("protocol") != DELEGATION_PROTOCOL:
        _fail("invalid principal protocol")
    _timestamp(document.get("updated_at"), "updated_at")
    records: dict[AgentId, Controller] = {}
    delegates = False
    for entries, retired in [(document.get("controllers"), False), (document.get("retired_controllers", []), True)]:
        if not isinstance(entries, list):
            _fail("controllers must be arrays")
        for record in entries:
            validate_controller(record, retired)
            if record["id"] in records:
                _fail("duplicate controller key")
            records[record["id"]] = record
            delegates = delegates or "delegation" in record
            if record["valid_from"] > document["updated_at"] or record.get("retired_at", 0) > document["updated_at"]:
                _fail("controller timestamp exceeds document update")
    # Succession (Section 5.1): each entry names another, earlier record.
    for record in records.values():
        for agent_id in record.get("supersedes", []):
            predecessor = records.get(agent_id)
            if predecessor is None or agent_id == record["id"] or predecessor["valid_from"] >= record["valid_from"]:
                _fail("invalid supersedes entry")
    if "aliases" in document:
        _strings(document["aliases"], "aliases", empty=True)
        for alias in document["aliases"]:
            _validate_https_url(alias, "alias")
    if "avatar_url" in document:
        _validate_https_url(document["avatar_url"], "avatar_url")
    if "delegation_query_url" in document:
        _validate_https_url(document["delegation_query_url"], "delegation_query_url")
    elif delegates:
        _fail("delegation_query_url is required when a controller carries delegation")


def validate_principal_resolution(document: PrincipalDocument, resolved_url: str) -> None:
    """Checks the authoritative-read rule of Agent Delegation Section 3: a
    principal document binds controller keys only when it is read at its own
    `id`. A document served anywhere else is a copy; its `controllers` must be
    discarded and `document["id"]` resolved instead."""
    if document.get("id") != resolved_url:
        raise AgentProtocolError(
            "invalid_principal",
            f"principal document id {document.get('id')} was served at {resolved_url}",
        )


def is_principal_alias(document: PrincipalDocument, url: str) -> bool:
    """Reports whether `url` is an alias the principal itself acknowledges. Any
    origin can redirect to any principal, so an alias must not be shown as a
    name for the principal unless it is listed here."""
    aliases = document.get("aliases")
    return isinstance(aliases, list) and url in aliases


def controller_lineage(document: PrincipalDocument, controller_id: AgentId) -> set[AgentId]:
    """The lineage of a controller (Section 5.1): its own ID plus, transitively,
    every record it supersedes. A restricted controller owns a credential whose
    `owner_controller` is in its lineage."""
    records = {
        record["id"]: record
        for record in [*document.get("controllers", []), *document.get("retired_controllers", [])]
    }
    lineage: set[AgentId] = set()
    pending = [controller_id]
    while pending:
        agent_id = pending.pop()
        if agent_id in lineage:
            continue
        lineage.add(agent_id)
        pending.extend(records.get(agent_id, {}).get("supersedes", []))
    return lineage


def validate_delegation_grant_payload(
    payload: DelegationGrantPayload,
    created_at: int | None = None,
) -> None:
    if not isinstance(payload, dict):
        _fail("payload must be an object")
    validate_delegation_id(payload.get("id"))
    _validate_https_url(payload.get("principal_id"), "principal_id")
    validate_agent_id(payload.get("subject"))
    _strings(payload.get("scopes"), "scopes")
    _strings(payload.get("audiences"), "audiences")
    for audience in payload["audiences"]:
        validate_audience(audience)
    if created_at is not None:
        _timestamp(created_at, "created_at")
    for field in ("not_before", "expires_at"):
        if field in payload:
            _timestamp(payload[field], field)
    if "constraints" in payload and not isinstance(payload["constraints"], dict):
        _fail("constraints must be an object")
    expires_at = payload.get("expires_at")
    if expires_at is not None:
        not_before = payload.get("not_before")
        if not_before is not None and expires_at <= not_before:
            raise AgentProtocolError("grant_expired", "expires_at must be greater than not_before")
        if created_at is not None and expires_at <= created_at:
            raise AgentProtocolError("grant_expired", "expires_at must be greater than created_at")


def validate_delegation_query_request(
    request: dict[str, Any],
    *,
    allow_enumeration: bool = False,
) -> None:
    """A public delegation query is an existence check and must include both
    `subject` and `principal_id`. Omitting either side makes it an enumeration
    query, which services must authorize before answering; pass
    `allow_enumeration` when building such an authorized request. `limit`
    defaults to 20; services SHOULD cap it at 100."""
    subject = request.get("subject")
    principal_id = request.get("principal_id")
    if allow_enumeration:
        if subject is None and principal_id is None:
            raise AgentProtocolError(
                "invalid_request",
                "query must include at least one of subject or principal_id",
            )
    elif subject is None or principal_id is None:
        raise AgentProtocolError(
            "invalid_request",
            "public query must include both subject and principal_id",
        )
    if request.get("id") is not None:
        validate_delegation_id(request["id"])
    if request.get("status") is not None and request["status"] not in _STATUSES:
        _fail("invalid status")
    if subject is not None:
        validate_agent_id(subject)
    if principal_id is not None:
        _validate_https_url(principal_id, "principal_id")
    limit = request.get("limit")
    if limit is not None and (type(limit) is not int or limit < 1 or limit > 2**53 - 1):
        raise AgentProtocolError("invalid_request", "limit must be a positive integer")


def validate_delegation_revoke_payload(payload: DelegationRevokePayload) -> None:
    if not isinstance(payload, dict):
        _fail("payload must be an object")
    validate_delegation_id(payload.get("id"))
    _validate_https_url(payload.get("principal_id"), "principal_id")


def validate_delegation_id(value: Any) -> None:
    if not isinstance(value, str) or not DELEGATION_ID_PATTERN.fullmatch(value) or value in (".", ".."):
        _fail("delegation id must match [A-Za-z0-9._~-]{1,128} and not be a dot segment")


def validate_delegation_envelope(envelope: Envelope) -> None:
    verify_envelope(envelope)
    event = envelope["event"]
    # Delegation events carry only the six Agent Identity event fields.
    validate_event_fields(event)
    if event["protocol"] != DELEGATION_PROTOCOL:
        raise AgentProtocolError(
            "invalid_event_protocol",
            f"expected {DELEGATION_PROTOCOL}, got {event['protocol']}",
        )
    if event["type"] == DELEGATION_GRANT:
        validate_delegation_grant_payload(event["payload"], event["created_at"])
    elif event["type"] == DELEGATION_REVOKE:
        validate_delegation_revoke_payload(event["payload"])
    else:
        raise AgentProtocolError(
            "invalid_event_type",
            f"expected {DELEGATION_GRANT} or {DELEGATION_REVOKE}, got {event['type']}",
        )


def materialize_delegation_credential(
    envelope: Envelope,
    *,
    accepted_at: int,
    previous: DelegationCredential | None = None,
    status: str = "active",
    checked_at: int | None = None,
) -> DelegationCredential:
    """Materialize an already accepted event, with trusted previous state and actual
    service acceptance time. This helper does not authorize the event."""
    validate_delegation_envelope(envelope)
    event = envelope["event"]
    _timestamp(accepted_at, "accepted_at")
    _previous(event, previous)
    if previous and accepted_at < previous["accepted_at"]:
        _fail("acceptance order reversed")
    checked_at = accepted_at if checked_at is None else checked_at
    _timestamp(checked_at, "checked_at")
    if checked_at < accepted_at:
        _fail("checked_at precedes acceptance")
    if event["type"] == DELEGATION_REVOKE:
        credential = deepcopy(previous)
        credential.update(
            controller=event["actor"],
            status="revoked",
            event_id=envelope["hash"],
            accepted_at=accepted_at,
            checked_at=checked_at,
        )
        return credential
    payload = event["payload"]
    if "expires_at" in payload and payload["expires_at"] <= accepted_at:
        raise AgentProtocolError("grant_expired", "grant expired at acceptance")
    if status not in _STATUSES:
        _fail("invalid status")
    return {
        **deepcopy(payload),
        "protocol": DELEGATION_PROTOCOL,
        "controller": event["actor"],
        "owner_controller": previous["owner_controller"] if previous else event["actor"],
        "status": status,
        "event_id": envelope["hash"],
        "grant_event_id": envelope["hash"],
        "accepted_at": accepted_at,
        "checked_at": checked_at,
    }


def validate_delegation_event_authority(event: Event, document: PrincipalDocument, accepted_at: int,
                                        previous: DelegationCredential | None = None) -> None:
    """Pre-signing policy check over trusted inputs. No signature, HTTP cache,
    live timestamp window, or nonce verification is performed."""
    _authority(event, document, accepted_at, previous, False)


def validate_delegation_acceptance(envelope: Envelope, document: PrincipalDocument, resolved_url: str,
                                   accepted_at: int, previous: DelegationCredential | None = None) -> None:
    """Online authority checks. Caller enforces fresh HTTPS, live Identity replay
    rules, and atomic acceptance/retirement persistence."""
    validate_delegation_envelope(envelope)
    validate_principal_resolution(document, resolved_url)
    _authority(envelope["event"], document, accepted_at, previous, False)


def validate_historical_delegation(record: DelegationRecord, document: PrincipalDocument, resolved_url: str,
                                   previous: DelegationCredential | None = None) -> None:
    """Uses caller-trusted acceptance evidence, never an event's self-reported
    time as proof. Current status and application constraints are separate checks."""
    validate_delegation_envelope(record["envelope"])
    validate_principal_resolution(document, resolved_url)
    _authority(record["envelope"]["event"], document, record.get("accepted_at"), previous, True)


def validate_controller_enumeration(document: PrincipalDocument, actor: AgentId, now: int, owner: AgentId) -> None:
    """Per-result authorization; caller authenticates actor and resolves document."""
    validate_principal_document(document)
    _timestamp(now, "now")
    validate_agent_id(owner)
    controller = next((c for c in document["controllers"] if c["id"] == actor), None)
    if not controller or now < controller["valid_from"]:
        raise AgentProtocolError("controller_not_current", "controller cannot enumerate")
    if "delegation" not in controller:
        raise AgentProtocolError("delegation_not_permitted", "controller cannot enumerate")
    if controller["delegation"] != "*" and owner not in controller_lineage(document, actor):
        raise AgentProtocolError("not_owner_controller", "controller does not own credential")


def validate_delegation_use(credential: DelegationCredential, audience: str, now: int) -> None:
    """Audience/status/time check after cryptographic and historical verification.
    Caller still authenticates subject and enforces scopes and constraints."""
    validate_audience(audience)
    _timestamp(now, "now")
    validate_delegation_grant_payload(credential)
    if (credential.get("protocol") != DELEGATION_PROTOCOL or credential.get("status") != "active"
        or audience not in credential["audiences"]
        or ("not_before" in credential and now < credential["not_before"])
        or ("expires_at" in credential and now >= credential["expires_at"])):
        _fail("delegation is not usable")


def verify_delegation_credential(
    credential: DelegationCredential,
    records: list[DelegationRecord],
    document: PrincipalDocument,
    resolved_url: str,
    audience: str,
    now: int,
) -> DelegationVerdict:
    """Verifies a credential under Agent Delegation Section 8 with the online
    service-trusting evidence policy: checks the accepted record of its latest
    grant — signature, Controller binding, ceiling, and authority interval —
    confirms that the grant matches the credential, and then checks use for
    `audience` at `now`. Ownership and `supersedes` lineage govern management,
    which the service enforced at acceptance; auditors replay them with
    :func:`audit_delegation_history`. Relying parties still enforce scopes and
    constraints and authenticate the subject."""
    reasons: list[str] = []
    try:
        record = next((r for r in records if r["envelope"]["hash"] == credential.get("grant_event_id")), None)
        if record is None:
            _fail("latest grant record is missing")
        validate_historical_delegation(record, document, resolved_url)
        event = record["envelope"]["event"]
        if event["type"] != DELEGATION_GRANT:
            _fail("grant_event_id does not name a grant")
        grant = {field: event["payload"][field] for field in _GRANT_FIELDS if field in event["payload"]}
        claimed = {field: credential[field] for field in _GRANT_FIELDS if field in credential}
        # Canonical JSON preserves JSON types (Python otherwise equates True and 1).
        if credential.get("protocol") != DELEGATION_PROTOCOL or rfc8785.dumps(grant) != rfc8785.dumps(claimed):
            _fail("credential does not match its latest grant")
        if credential.get("event_id") == credential.get("grant_event_id"):
            if (credential.get("accepted_at") != record["accepted_at"] or credential.get("controller") != event["actor"]
                    or credential.get("status") == "revoked"):
                _fail("credential does not match its latest grant")
        elif credential.get("status") != "revoked":
            _fail("a credential last changed by a revocation must be revoked")
    except (AgentProtocolError, KeyError, TypeError, rfc8785.CanonicalizationError) as error:
        reasons.append(str(error))
    verified = not reasons
    if credential.get("status") != "active":
        reasons.append(f"status is {credential.get('status')}")
    if audience not in (credential.get("audiences") or []):
        reasons.append(f"audience {audience} is not granted")
    if "not_before" in credential and now < credential["not_before"]:
        reasons.append("not yet valid")
    if "expires_at" in credential and now >= credential["expires_at"]:
        reasons.append("expired")
    return {"credential": credential, "verified": verified, "usable": not reasons, "reasons": reasons}


def _event_identity(event: Event) -> tuple[str, str]:
    payload = event["payload"]
    return payload["id"], payload["principal_id"]


def _previous(event: Event, previous: DelegationCredential | None) -> None:
    if previous is None:
        if event["type"] == DELEGATION_REVOKE:
            raise AgentProtocolError("credential_not_found", "revocation requires previous credential")
        return
    validate_agent_id(previous.get("owner_controller"))
    _timestamp(previous.get("accepted_at"), "previous.accepted_at")
    delegation_id, principal_id = _event_identity(event)
    same_subject = event["type"] != DELEGATION_GRANT or event["payload"]["subject"] == previous.get("subject")
    if (previous.get("id") != delegation_id or previous.get("principal_id") != principal_id
            or previous.get("protocol") != DELEGATION_PROTOCOL or not same_subject):
        raise AgentProtocolError(
            "credential_identity_mismatch", "credential principal, subject, and protocol are immutable"
        )


def _authority(event: Event, document: PrincipalDocument, accepted_at: int,
               previous: DelegationCredential | None, historical: bool) -> None:
    validate_principal_document(document)
    _timestamp(accepted_at, "accepted_at")
    _timestamp(event["created_at"], "created_at")
    validate_agent_id(event["actor"])
    if event["protocol"] != DELEGATION_PROTOCOL:
        _fail("invalid event protocol")
    grant = event["type"] == DELEGATION_GRANT
    payload = event["payload"]
    if grant:
        validate_delegation_grant_payload(payload, event["created_at"])
    elif event["type"] == DELEGATION_REVOKE:
        validate_delegation_revoke_payload(payload)
    else:
        _fail("invalid event type")
    if _event_identity(event)[1] != document["id"]:
        raise AgentProtocolError("principal_not_canonical", "principal mismatch")
    records = document["controllers"] + (document.get("retired_controllers", []) if historical else [])
    controller = next((c for c in records if c["id"] == event["actor"]), None)
    if controller is None:
        raise AgentProtocolError("controller_not_current", "actor is not a controller of the principal")
    if "delegation" not in controller:
        raise AgentProtocolError("delegation_not_permitted", "actor has no delegation authority")
    for time in [event["created_at"], accepted_at]:
        if (time < controller["valid_from"] or ("retired_at" in controller and time >= controller["retired_at"])
                or ("invalid_from" in controller and time >= controller["invalid_from"])):
            raise AgentProtocolError("controller_not_current", "outside controller authority interval")
    _previous(event, previous)
    if previous and accepted_at < previous["accepted_at"]:
        _fail("acceptance order reversed")
    if (previous and controller["delegation"] != "*"
            and previous["owner_controller"] not in controller_lineage(document, event["actor"])):
        raise AgentProtocolError("not_owner_controller", "controller does not own credential")
    if grant:
        if "expires_at" in payload and payload["expires_at"] <= accepted_at:
            raise AgentProtocolError("grant_expired", "grant expired at acceptance")
        policy = controller["delegation"]
        if policy != "*" and (not set(payload["scopes"]) <= set(policy["scopes"])
                              or not set(payload["audiences"]) <= set(policy["audiences"])):
            raise AgentProtocolError("delegation_ceiling_exceeded", "grant exceeds controller delegation policy")


# Grant fields a credential carries from its latest grant.
_GRANT_FIELDS = (
    "id", "principal_id", "subject", "relationship", "scopes", "audiences",
    "constraints", "not_before", "expires_at",
)


def audit_delegation_history(
    credential: DelegationCredential,
    records: list[DelegationRecord],
    document: PrincipalDocument,
    resolved_url: str,
) -> None:
    """Auditor check (Section 8): replays every accepted record of a credential
    against the authoritative principal document — signatures, controller
    intervals, ceilings, and ownership lineage — and confirms that the replay
    matches the credential. Relying parties use :func:`verify_delegation_credential`."""
    if not records:
        _fail("no accepted records")
    replayed: DelegationCredential | None = None
    for record in records:
        validate_historical_delegation(record, document, resolved_url, replayed)
        replayed = materialize_delegation_credential(
            record["envelope"], accepted_at=record["accepted_at"], previous=replayed
        )
    assert replayed is not None
    # Only status and the service's check time may differ from event replay.
    fields = (*_GRANT_FIELDS, "protocol", "event_id", "grant_event_id", "owner_controller", "controller", "accepted_at")
    expected = {field: replayed[field] for field in fields if field in replayed}
    actual = {field: credential[field] for field in fields if field in credential}
    if rfc8785.dumps(expected) != rfc8785.dumps(actual) or (
        (replayed["status"] == "revoked") != (credential.get("status") == "revoked")
    ):
        _fail("credential does not match its accepted records")


def validate_audience(value: Any) -> None:
    """A relying-party audience (Section 5): an origin for a relying
    application, or an Agent ID for a relying agent."""
    if isinstance(value, str) and value.startswith(AGENT_ID_PREFIX):
        validate_agent_id(value)
    else:
        validate_origin(value)


def _fail(message: str) -> None:
    raise AgentProtocolError("invalid_delegation", message)


def _timestamp(value: Any, field: str) -> None:
    if type(value) is not int or not 0 <= value <= 2**53 - 1:
        _fail(f"{field} must be a non-negative safe integer")


def _strings(value: Any, field: str, empty: bool = False) -> None:
    if not isinstance(value, list) or (not empty and not value):
        _fail(f"{field} must be a non-empty array")
    for item in value:
        _validate_non_empty(item, field)
        if item == "*":
            _fail(f"{field} cannot contain wildcard")
    if len(set(value)) != len(value):
        _fail(f"{field} contains duplicates")


def _validate_https_url(value: Any, field: str) -> None:
    if not isinstance(value, str):
        raise AgentProtocolError("invalid_url", f"{field} must be an HTTPS URL")
    try:
        parsed = urlparse(value)
        valid = parsed.scheme == "https" and bool(parsed.hostname)
        _ = parsed.port
    except ValueError:
        valid = False
    if not valid:
        raise AgentProtocolError("invalid_url", f"{field} must be an HTTPS URL")


def _validate_non_empty(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise AgentProtocolError("invalid_delegation", f"{field} must not be empty")
