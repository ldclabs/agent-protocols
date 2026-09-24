from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from .delegation import validate_delegation_id
from .errors import AgentProtocolError
from .identity import AgentId, Envelope, Event, create_event, validate_agent_id, validate_event_fields, verify_envelope

PROFILE_PROTOCOL = "agent-profile/1.0"
PROFILE_UPDATE = "profile.update"

# Registered link relations (Section 4.3); the vocabulary is open, so other
# values are valid and clients ignore relations they do not understand.
LINK_REL_HOMEPAGE = "homepage"
LINK_REL_DOCUMENTATION = "documentation"
LINK_REL_SOURCE_CODE = "source_code"
LINK_REL_SOCIAL = "social"
LINK_REL_BROWSER = "browser"

ProfileUpdatePayload = dict[str, Any]
AgentProfile = dict[str, Any]


def profile_update_event(actor: AgentId, created_at: int, nonce: int, payload: ProfileUpdatePayload) -> Event:
    return create_event(PROFILE_PROTOCOL, PROFILE_UPDATE, actor, created_at, nonce, payload)


def validate_profile_update(envelope: Envelope) -> None:
    verify_envelope(envelope)
    event = envelope["event"]
    # Profile events carry only the six Agent Identity event fields.
    validate_event_fields(event)
    if event["protocol"] != PROFILE_PROTOCOL:
        raise AgentProtocolError("invalid_event_protocol", f"expected {PROFILE_PROTOCOL}, got {event['protocol']}")
    if event["type"] != PROFILE_UPDATE:
        raise AgentProtocolError("invalid_event_type", f"expected {PROFILE_UPDATE}, got {event['type']}")
    validate_profile_payload(event["payload"], event["actor"])


_PAYLOAD_FIELDS = frozenset(
    {"id", "name", "description", "avatar_url", "provider", "capabilities",
     "service_endpoints", "links", "delegations", "extra"}
)


def validate_profile_payload(payload: Any, actor: AgentId) -> None:
    """Section 4.1 rules for a closed ``profile.update`` payload: only defined
    fields, ``id`` equal to the signing ``actor``, and the field rules for
    names, URLs, uniqueness, and delegation hints."""
    if not isinstance(payload, dict):
        _invalid("payload must be an object")
    if not payload.get("id") or payload["id"] != actor:
        raise AgentProtocolError("invalid_actor", "profile update actor must match payload.id")
    validate_agent_id(payload["id"])
    for key in payload:
        if key not in _PAYLOAD_FIELDS:
            _invalid(f"undefined profile field: {key}")
    if not isinstance(payload.get("name"), str) or payload["name"] == "":
        _invalid("name must be a non-empty string")
    for field in ("description", "provider"):
        if field in payload and not isinstance(payload[field], str):
            _invalid(f"{field} must be a string")
    if "avatar_url" in payload:
        _require_url(payload["avatar_url"], ("https",), "avatar_url")
    if "extra" in payload and not isinstance(payload["extra"], dict):
        _invalid("extra must be an object")
    _unique_strings(payload.get("capabilities"), "capabilities")
    endpoints: set[str] = set()
    for endpoint in _objects(payload.get("service_endpoints"), "service_endpoints"):
        _closed(endpoint, ("type", "url", "protocols"), "service endpoint")
        if not isinstance(endpoint.get("type"), str) or endpoint["type"] == "":
            _invalid("service endpoint type must not be empty")
        _require_url(endpoint.get("url"), ("https",), "service endpoint url")
        _unique_strings(endpoint.get("protocols"), "service endpoint protocols")
        key = json.dumps([endpoint["type"], endpoint["url"]])
        if key in endpoints:
            _invalid("service endpoints must be unique by type and url")
        endpoints.add(key)
    links: set[str] = set()
    for link in _objects(payload.get("links"), "links"):
        _closed(link, ("name", "url", "rel"), "link")
        if not all(isinstance(link.get(f), str) and link[f] != "" for f in ("name", "rel")):
            _invalid("link name and rel must not be empty")
        _require_url(link.get("url"), ("http", "https"), "link url")
        key = json.dumps([link["url"], link["rel"]])
        if key in links:
            _invalid("links must be unique by url and rel")
        links.add(key)
    for hint in _objects(payload.get("delegations"), "delegations"):
        _closed(hint, ("id", "principal", "relationship", "scopes"), "delegation hint")
        if "id" in hint:
            validate_delegation_id(hint["id"])
        if not isinstance(hint.get("principal"), dict):
            _invalid("delegation hint requires a principal")
        _require_url(hint["principal"].get("id"), ("https",), "delegation principal id")
        if "relationship" in hint and not isinstance(hint["relationship"], str):
            _invalid("relationship must be a string")
        _unique_strings(hint.get("scopes"), "delegation hint scopes")


def _invalid(message: str) -> None:
    raise AgentProtocolError("invalid_event", message)


def _objects(value: Any, field: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        _invalid(f"{field} must be an array of objects")
    return value


def _closed(value: dict[str, Any], fields: tuple[str, ...], name: str) -> None:
    for key in value:
        if key not in fields:
            _invalid(f"undefined {name} field: {key}")


def _require_url(value: Any, schemes: tuple[str, ...], field: str) -> None:
    try:
        parsed = urlparse(value) if isinstance(value, str) else None
        valid = parsed is not None and parsed.scheme in schemes and bool(parsed.hostname)
    except ValueError:
        valid = False
    if not valid:
        _invalid(f"{field} must be an {' or '.join(schemes)} URL")


def _unique_strings(value: Any, field: str) -> None:
    if value is None:
        return
    if not isinstance(value, list) or any(not isinstance(item, str) or item == "" for item in value):
        _invalid(f"{field} entries must be non-empty strings")
    if len(set(value)) != len(value):
        _invalid(f"{field} entries must be unique")


def validate_profile_succession(envelope: Envelope, latest_nonce: int | None) -> None:
    """Rejects an update whose nonce does not exceed the latest accepted
    profile nonce, which services check against durable history rather than
    the expiring live-write nonce cache."""
    if latest_nonce is not None and envelope["event"]["nonce"] <= latest_nonce:
        raise AgentProtocolError(
            "nonce_not_greater",
            f"nonce must be greater than the latest accepted profile nonce {latest_nonce}",
            data={"max_nonce": latest_nonce},
        )


def materialize_profile(envelope: Envelope) -> AgentProfile:
    validate_profile_update(envelope)
    payload = envelope["event"]["payload"]
    payload_id = payload.get("id")
    return {
        "id": payload_id,
        "name": payload["name"],
        "description": payload.get("description"),
        "avatar_url": payload.get("avatar_url"),
        "provider": payload.get("provider"),
        "capabilities": payload.get("capabilities", []),
        "service_endpoints": payload.get("service_endpoints", []),
        "links": payload.get("links", []),
        "delegations": payload.get("delegations", []),
        "extra": payload.get("extra", {}),
        "updated_at": envelope["event"]["created_at"],
        "event_id": envelope["hash"],
    }


def latest_profile_update(envelopes: list[Envelope]) -> Envelope | None:
    """Selects the latest profile state from accepted update envelopes. Nonces
    are strictly monotonic per Agent ID, so the latest profile is defined as
    the accepted `profile.update` with the greatest `nonce` — deterministic
    and independently checkable from event history alone."""
    if not envelopes:
        return None
    return max(envelopes, key=lambda envelope: envelope["event"]["nonce"])
