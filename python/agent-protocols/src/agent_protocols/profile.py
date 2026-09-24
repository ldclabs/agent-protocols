from __future__ import annotations

from typing import Any

from .errors import AgentProtocolError
from .identity import AgentId, Envelope, Event, create_event, validate_event_fields, verify_envelope

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
    payload_id = event["payload"].get("id")
    if event["protocol"] != PROFILE_PROTOCOL:
        raise AgentProtocolError("invalid_event_protocol", f"expected {PROFILE_PROTOCOL}, got {event['protocol']}")
    if event["type"] != PROFILE_UPDATE:
        raise AgentProtocolError("invalid_event_type", f"expected {PROFILE_UPDATE}, got {event['type']}")
    if not payload_id or event["actor"] != payload_id:
        raise AgentProtocolError("invalid_actor", "profile update actor must match payload.id")


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
