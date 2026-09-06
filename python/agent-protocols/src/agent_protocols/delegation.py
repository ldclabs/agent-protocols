from __future__ import annotations

from typing import Any, TypedDict, Literal
from copy import deepcopy
from urllib.parse import urlparse
import re
import ipaddress

from .errors import AgentProtocolError
from .identity import AgentId, Envelope, Event, create_event, validate_agent_id, verify_envelope

DELEGATION_PROTOCOL = "agent-delegation/1.0"
DELEGATION_GRANT = "delegation.grant"
DELEGATION_REVOKE = "delegation.revoke"

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
    retired_at: int
    invalid_from: int


class DelegationAcceptance(TypedDict):
    event_id: str
    accepted_at: int


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
        _origin(controller.get("source"))
    _timestamp(controller.get("valid_from"), "valid_from")
    if "name" in controller:
        _validate_non_empty(controller["name"], "name")
    if "delegation" in controller and controller["delegation"] != "*":
        policy = controller["delegation"]
        if not isinstance(policy, dict) or set(policy) != {"scopes", "audiences"}:
            _fail("invalid delegation policy")
        _strings(policy["scopes"], "scopes")
        _strings(policy["audiences"], "audiences")
        for origin in policy["audiences"]:
            _origin(origin)
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
    seen = set()
    for records, retired in [(document.get("controllers"), False), (document.get("retired_controllers", []), True)]:
        if not isinstance(records, list):
            _fail("controllers must be arrays")
        for record in records:
            validate_controller(record, retired)
            if record["id"] in seen:
                _fail("duplicate controller key")
            seen.add(record["id"])
            if record["valid_from"] > document["updated_at"] or record.get("retired_at", 0) > document["updated_at"]:
                _fail("controller timestamp exceeds document update")
    if "aliases" in document:
        _strings(document["aliases"], "aliases", empty=True)
        for alias in document["aliases"]:
            _validate_https_url(alias, "alias")
    for field in ("avatar_url", "delegation_query_url"):
        if field in document:
            _validate_https_url(document[field], field)


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


def validate_delegation_grant_payload(
    payload: DelegationGrantPayload,
    created_at: int | None = None,
) -> None:
    if not isinstance(payload, dict):
        _fail("payload must be an object")
    validate_delegation_id(payload.get("id"))
    _validate_principal_descriptor(payload.get("principal"))
    validate_agent_id(payload.get("subject"))
    _strings(payload.get("scopes"), "scopes")
    _strings(payload.get("audiences"), "audiences")
    for origin in payload["audiences"]:
        _origin(origin)
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
            raise AgentProtocolError(
                "invalid_delegation",
                "expires_at must be greater than not_before",
            )
        if created_at is not None and expires_at <= created_at:
            raise AgentProtocolError(
                "invalid_delegation",
                "expires_at must be greater than created_at",
            )


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
                "invalid_delegation",
                "query must include at least one of subject or principal_id",
            )
    elif subject is None or principal_id is None:
        raise AgentProtocolError(
            "invalid_delegation",
            "public query must include both subject and principal_id",
        )
    if subject is not None:
        validate_agent_id(subject)
    if principal_id is not None:
        _validate_https_url(principal_id, "principal_id")
    if request.get("id") is not None:
        validate_delegation_id(request["id"])
    limit = request.get("limit")
    if limit is not None and (type(limit) is not int or limit < 1 or limit > 2**53 - 1):
        raise AgentProtocolError("invalid_delegation", "limit must be a positive integer")


def validate_delegation_revoke_payload(payload: DelegationRevokePayload) -> None:
    if not isinstance(payload, dict):
        _fail("payload must be an object")
    validate_delegation_id(payload.get("id"))
    _validate_https_url(payload.get("principal_id"), "principal_id")


def validate_delegation_id(value: Any) -> None:
    _validate_non_empty(value, "delegation id")
    if value in (".", ".."):
        _fail("delegation id cannot be a dot segment")


def validate_delegation_envelope(envelope: Envelope) -> None:
    verify_envelope(envelope)
    event = envelope["event"]
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
    envelope: Envelope, *, accepted_at: int, previous: DelegationCredential | None = None,
    status: str = "active", updated_at: int | None = None,
) -> DelegationCredential:
    """Materialize an already accepted event, with trusted previous state and actual
    service acceptance time. This helper does not authorize the event."""
    validate_delegation_envelope(envelope)
    event = envelope["event"]
    _timestamp(accepted_at, "accepted_at")
    _previous(event, previous)
    if previous and accepted_at < previous["accepted_at"]:
        _fail("acceptance order reversed")
    updated_at = accepted_at if updated_at is None else updated_at
    _timestamp(updated_at, "updated_at")
    if updated_at < accepted_at:
        _fail("updated_at precedes acceptance")
    if event["type"] == DELEGATION_REVOKE:
        credential = deepcopy(previous)
        credential.update(controller=event["actor"], status="revoked", event_id=envelope["hash"], accepted_at=accepted_at, updated_at=updated_at)
        return credential
    payload = event["payload"]
    if "expires_at" in payload and payload["expires_at"] <= accepted_at:
        _fail("grant expired at acceptance")
    if status not in ("active", "suspended", "expired", "revoked"):
        _fail("invalid status")
    return {**deepcopy(payload), "protocol": DELEGATION_PROTOCOL, "controller": event["actor"],
            "owner_controller": previous["owner_controller"] if previous else event["actor"],
            "status": status, "updated_at": updated_at, "event_id": envelope["hash"],
            "grant_event_id": envelope["hash"], "accepted_at": accepted_at}


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


def validate_historical_delegation(envelope: Envelope, acceptance: DelegationAcceptance,
                                   document: PrincipalDocument, resolved_url: str,
                                   previous: DelegationCredential | None = None) -> None:
    """Caller authenticates acceptance evidence and previous state. This checks its
    hash binding and historical policy, not current status or application constraints."""
    validate_delegation_envelope(envelope)
    if acceptance.get("event_id") != envelope["hash"]:
        _fail("acceptance hash mismatch")
    validate_principal_resolution(document, resolved_url)
    _authority(envelope["event"], document, acceptance.get("accepted_at"), previous, True)


def validate_controller_enumeration(document: PrincipalDocument, actor: AgentId, now: int, owner: AgentId) -> None:
    """Per-result authorization; caller authenticates actor and resolves document."""
    validate_principal_document(document)
    _timestamp(now, "now")
    validate_agent_id(owner)
    controller = next((c for c in document["controllers"] if c["id"] == actor), None)
    if not controller or now < controller["valid_from"] or "delegation" not in controller:
        _fail("controller cannot enumerate")
    if controller["delegation"] != "*" and owner != actor:
        _fail("controller does not own credential")


def validate_delegation_use(credential: DelegationCredential, audience: str, now: int) -> None:
    """Audience/status/time check after cryptographic and historical verification.
    Caller still authenticates subject and enforces scopes and constraints."""
    _origin(audience)
    _timestamp(now, "now")
    validate_delegation_grant_payload(credential)
    if (credential.get("protocol") != DELEGATION_PROTOCOL or credential.get("status") != "active"
        or audience not in credential["audiences"]
        or ("not_before" in credential and now < credential["not_before"])
        or ("expires_at" in credential and now >= credential["expires_at"])):
        _fail("delegation is not usable")


def _previous(event: Event, previous: DelegationCredential | None) -> None:
    if previous is None:
        if event["type"] == DELEGATION_REVOKE:
            _fail("revocation requires previous credential")
        return
    validate_agent_id(previous.get("owner_controller"))
    _timestamp(previous.get("accepted_at"), "previous.accepted_at")
    payload = event["payload"]
    principal = payload["principal"]["id"] if event["type"] == DELEGATION_GRANT else payload["principal_id"]
    if previous.get("id") != payload["id"] or previous.get("principal", {}).get("id") != principal or previous.get("protocol") != DELEGATION_PROTOCOL:
        _fail("previous credential identity mismatch")


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
    principal = payload["principal"]["id"] if grant else payload["principal_id"]
    if principal != document["id"]:
        _fail("principal mismatch")
    records = document["controllers"] + (document.get("retired_controllers", []) if historical else [])
    controller = next((c for c in records if c["id"] == event["actor"]), None)
    if not controller or "delegation" not in controller:
        _fail("actor has no delegation authority")
    for time in [event["created_at"], accepted_at]:
        if (time < controller["valid_from"] or ("retired_at" in controller and time >= controller["retired_at"])
            or ("invalid_from" in controller and time >= controller["invalid_from"])):
            _fail("outside controller authority interval")
    _previous(event, previous)
    if previous and accepted_at < previous["accepted_at"]:
        _fail("acceptance order reversed")
    if previous and controller["delegation"] != "*" and previous["owner_controller"] != event["actor"]:
        _fail("controller does not own credential")
    if grant:
        if "expires_at" in payload and payload["expires_at"] <= accepted_at:
            _fail("grant expired at acceptance")
        policy = controller["delegation"]
        if policy != "*" and (not set(payload["scopes"]) <= set(policy["scopes"]) or not set(payload["audiences"]) <= set(policy["audiences"])):
            _fail("grant exceeds controller delegation policy")


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


def _origin(value: Any) -> None:
    _validate_https_url(value, "origin")
    parsed = urlparse(value)
    if any(c.isspace() for c in value) or "\\" in value or "%" in value:
        _fail("invalid HTTPS origin")
    try:
        host = parsed.hostname
        # Python does not serialize IDNs/IP literals like WHATWG; require the
        # wire origin to use canonical ASCII host spelling.
        host = host.encode("idna").decode("ascii")
        if ":" in host:
            host = "[" + ipaddress.IPv6Address(host).compressed + "]"
        elif re.fullmatch(r"(?:[0-9]+|0[xX][0-9a-fA-F]+)", host.rstrip(".").split(".")[-1]):
            host = str(ipaddress.IPv4Address(host))
        port = parsed.port
        canonical = "https://" + host + (f":{port}" if port is not None and port != 443 else "")
    except (ValueError, UnicodeError, AttributeError):
        _fail("invalid HTTPS origin")
    if value != canonical:
        _fail("origin must be a serialized HTTPS origin")


def _validate_principal_descriptor(value: Any) -> None:
    if not isinstance(value, dict):
        raise AgentProtocolError("invalid_principal", "principal must be an object")
    _validate_https_url(value.get("id"), "principal.id")


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
