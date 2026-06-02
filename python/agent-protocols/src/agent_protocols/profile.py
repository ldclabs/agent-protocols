from __future__ import annotations

from typing import Any

from .errors import AgentProtocolError
from .identity import AgentId, Envelope, Event, create_event, verify_envelope

PROFILE_PROTOCOL = "agent-profile/1.0"
PROFILE_UPDATE = "profile.update"

ProfileUpdatePayload = dict[str, Any]
AgentProfile = dict[str, Any]


def profile_update_event(actor: AgentId, created_at: int, nonce: int, payload: ProfileUpdatePayload) -> Event:
    return create_event(PROFILE_PROTOCOL, PROFILE_UPDATE, actor, created_at, nonce, payload)


def validate_profile_update(envelope: Envelope) -> None:
    verify_envelope(envelope)
    event = envelope["event"]
    payload_id = event["payload"].get("id") or event["payload"].get("agent_id")
    if event["protocol"] != PROFILE_PROTOCOL:
        raise AgentProtocolError("invalid_event_protocol", f"expected {PROFILE_PROTOCOL}, got {event['protocol']}")
    if event["type"] != PROFILE_UPDATE:
        raise AgentProtocolError("invalid_event_type", f"expected {PROFILE_UPDATE}, got {event['type']}")
    if event["actor"] != payload_id:
        raise AgentProtocolError("invalid_actor", "profile update actor must match payload.id")


def materialize_profile(envelope: Envelope) -> AgentProfile:
    validate_profile_update(envelope)
    payload = envelope["event"]["payload"]
    payload_id = payload.get("id") or payload.get("agent_id")
    return {
        "id": payload_id,
        "name": payload["name"],
        "description": payload.get("description"),
        "avatar_url": payload.get("avatar_url"),
        "provider": payload.get("provider"),
        "capabilities": payload.get("capabilities", []),
        "service_endpoints": payload.get("service_endpoints", []),
        "links": payload.get("links", []),
        "extra": payload.get("extra", {}),
        "updated_at": envelope["event"]["created_at"],
        "event_id": envelope["hash"],
    }
