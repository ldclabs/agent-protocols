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
    if document.get("delegations_url") is not None:
        _validate_https_url(document["delegations_url"], "delegations_url")


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
        not_before = payload.get("not_before", created_at)
        if not_before is not None and expires_at <= not_before:
            raise AgentProtocolError(
                "invalid_delegation",
                "expires_at must be greater than not_before or created_at",
            )


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
    status_url: str | None = None,
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
        "status_url": status_url,
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
