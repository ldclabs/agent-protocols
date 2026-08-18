from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from .errors import AgentProtocolError
from .identity import AgentId, Envelope, Event, create_event, validate_agent_id, verify_envelope

DELEGATION_PROTOCOL = "agent-delegation/1.0"
DELEGATION_GRANT = "delegation.grant"
DELEGATION_REVOKE = "delegation.revoke"

DelegationGrantPayload = dict[str, Any]
DelegationRevokePayload = dict[str, Any]
DelegationCredential = dict[str, Any]
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


def validate_principal_document(document: PrincipalDocument) -> None:
    _validate_https_url(document.get("id"), "principal.id")
    controllers = document.get("controllers")
    if not isinstance(controllers, list) or not controllers:
        raise AgentProtocolError(
            "invalid_principal",
            "principal document controllers must be non-empty",
        )
    for controller in controllers:
        validate_agent_id(controller)
    aliases = document.get("aliases")
    if aliases is not None:
        if not isinstance(aliases, list):
            raise AgentProtocolError("invalid_principal", "aliases must be an array")
        for alias in aliases:
            _validate_https_url(alias, "alias")
    if document.get("delegation_query_url") is not None:
        _validate_https_url(document["delegation_query_url"], "delegation_query_url")


def validate_principal_resolution(document: PrincipalDocument, resolved_url: str) -> None:
    """Checks the authoritative-read rule of Agent Delegation Section 5.3: a
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
    _validate_non_empty(payload.get("id"), "payload.id")
    _validate_principal_descriptor(payload.get("principal"))
    validate_agent_id(payload.get("subject"))
    scopes = payload.get("scopes")
    if not isinstance(scopes, list) or not scopes:
        raise AgentProtocolError("invalid_delegation", "delegation scopes must be non-empty")
    for scope in scopes:
        _validate_non_empty(scope, "scope")
    constraints = payload.get("constraints")
    if constraints is not None and not isinstance(constraints, dict):
        raise AgentProtocolError("invalid_delegation", "constraints must be an object")
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
    limit = request.get("limit")
    if limit is not None and (not isinstance(limit, int) or limit < 1):
        raise AgentProtocolError("invalid_delegation", "limit must be a positive integer")


def validate_delegation_revoke_payload(payload: DelegationRevokePayload) -> None:
    _validate_non_empty(payload.get("id"), "payload.id")
    _validate_https_url(payload.get("principal_id"), "principal_id")


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
    envelope: Envelope,
    *,
    status: str = "active",
    updated_at: int | None = None,
) -> DelegationCredential:
    validate_delegation_envelope(envelope)
    event = envelope["event"]
    if event["type"] != DELEGATION_GRANT:
        raise AgentProtocolError(
            "invalid_event_type",
            "delegation credential materialization requires a grant event",
        )
    payload = event["payload"]
    credential = {
        "id": payload["id"],
        "protocol": DELEGATION_PROTOCOL,
        "principal": payload["principal"],
        "controller": event["actor"],
        "subject": payload["subject"],
        "relationship": payload.get("relationship"),
        "scopes": payload["scopes"],
        "constraints": payload.get("constraints"),
        "not_before": payload.get("not_before"),
        "expires_at": payload.get("expires_at"),
        "status": status,
        "updated_at": updated_at if updated_at is not None else event["created_at"],
        "event_id": envelope["hash"],
    }
    return credential


def _validate_principal_descriptor(value: Any) -> None:
    if not isinstance(value, dict):
        raise AgentProtocolError("invalid_principal", "principal must be an object")
    _validate_https_url(value.get("id"), "principal.id")


def _validate_https_url(value: Any, field: str) -> None:
    if not isinstance(value, str):
        raise AgentProtocolError("invalid_url", f"{field} must be an HTTPS URL")
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise AgentProtocolError("invalid_url", f"{field} must be an HTTPS URL")


def _validate_non_empty(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise AgentProtocolError("invalid_delegation", f"{field} must not be empty")
