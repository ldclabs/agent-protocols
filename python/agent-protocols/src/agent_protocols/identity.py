from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any, MutableMapping, Protocol

import base58
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .errors import AgentProtocolError

AGENT_ID_PREFIX = "did:agent:"
EVENT_ID_PREFIX = "evt_"
DEFAULT_LIVE_WRITE_WINDOW_MS = 300_000
DEFAULT_REQUEST_JWT_TTL_SECS = 300
_REQUEST_AUTH_REPLAY_SCOPE = "agent-identity/request-auth"

Event = dict[str, Any]
Envelope = dict[str, Any]
AgentId = str


def agent_id_from_public_key(public_key: bytes) -> AgentId:
    if len(public_key) != 32:
        raise AgentProtocolError("invalid_public_key", f"public key must be 32 bytes, got {len(public_key)}")
    return f"{AGENT_ID_PREFIX}{_base58btc_encode(public_key)}"


def public_key_bytes(agent_id: AgentId) -> bytes:
    if not agent_id.startswith(AGENT_ID_PREFIX):
        raise AgentProtocolError("invalid_agent_id", "agent id must start with did:agent:")
    data = _base58btc_decode(agent_id[len(AGENT_ID_PREFIX):])
    if len(data) != 32:
        raise AgentProtocolError("invalid_public_key", f"agent id public key must be 32 bytes, got {len(data)}")
    return data


def validate_agent_id(agent_id: AgentId) -> AgentId:
    public_key_bytes(agent_id)
    return agent_id


@dataclass(frozen=True)
class RequestBinding:
    audience: str

    @classmethod
    def create(cls, audience: str) -> "RequestBinding":
        return cls(audience=audience)


class AgentSigner:
    def __init__(self, private_key: Ed25519PrivateKey):
        self._private_key = private_key

    @classmethod
    def generate(cls) -> "AgentSigner":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> "AgentSigner":
        if len(seed) != 32:
            raise AgentProtocolError("invalid_private_key", f"seed must be 32 bytes, got {len(seed)}")
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    def public_key(self) -> bytes:
        return self._private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def agent_id(self) -> AgentId:
        return agent_id_from_public_key(self.public_key())

    def sign_event(self, event: Event) -> Envelope:
        return {
            "event_id": event_id(event),
            "event": event,
            "signature": sign_event(self._private_key, event),
        }

    def sign_request_jwt(self, claims: dict[str, Any]) -> str:
        agent_id = self.agent_id()
        if claims.get("iss") != agent_id or claims.get("sub") != agent_id:
            raise AgentProtocolError("invalid_jwt_claim", "iss and sub must match the signing agent id")
        header = {"alg": "EdDSA", "typ": "JWT", "kid": agent_id}
        encoded_header = _base64url_encode(json.dumps(header, separators=(",", ":")).encode())
        encoded_payload = _base64url_encode(json.dumps(claims, separators=(",", ":")).encode())
        signing_input = f"{encoded_header}.{encoded_payload}".encode()
        signature = self._private_key.sign(signing_input)
        return f"{encoded_header}.{encoded_payload}.{_base64url_encode(signature)}"


class NonceStore(Protocol):
    def check_and_insert(self, scope: tuple[AgentId, str, str | None, str]) -> None: ...


class MemoryNonceStore:
    def __init__(self) -> None:
        self._seen: set[tuple[AgentId, str, str | None, str]] = set()

    def check_and_insert(self, scope: tuple[AgentId, str, str | None, str]) -> None:
        if scope in self._seen:
            raise AgentProtocolError("nonce_reused", "nonce was already used in this replay scope")
        self._seen.add(scope)


def create_event(protocol: str, event_type: str, actor: AgentId, created_at: int, nonce: str, payload: Any) -> Event:
    validate_agent_id(actor)
    return {
        "protocol": protocol,
        "type": event_type,
        "actor": actor,
        "created_at": created_at,
        "nonce": nonce,
        "payload": payload,
    }


def with_room_id(event: Event, room_id: str) -> Event:
    next_event = dict(event)
    next_event["room_id"] = room_id
    return next_event


def canonical_event_bytes(event: Event) -> bytes:
    canonical = rfc8785.dumps(event)
    return canonical if isinstance(canonical, bytes) else canonical.encode()


def event_id(event: Event) -> str:
    digest = hashlib.sha256(canonical_event_bytes(event)).digest()
    return f"{EVENT_ID_PREFIX}{_base58btc_encode(digest)}"


def sign_event(private_key: Ed25519PrivateKey, event: Event) -> str:
    return _base64url_encode(private_key.sign(canonical_event_bytes(event)))


def verify_event_id(envelope: Envelope) -> None:
    expected = event_id(envelope["event"])
    actual = envelope["event_id"]
    if expected != actual:
        raise AgentProtocolError("invalid_event_id", f"invalid event id: expected {expected}, got {actual}")


def verify_signature(envelope: Envelope) -> None:
    signature = _base64url_decode(envelope["signature"])
    if len(signature) != 64:
        raise AgentProtocolError("invalid_signature", f"signature must be 64 bytes, got {len(signature)}")
    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes(envelope["event"]["actor"]))
    try:
        public_key.verify(signature, canonical_event_bytes(envelope["event"]))
    except InvalidSignature as exc:
        raise AgentProtocolError("invalid_signature", "signature verification failed") from exc


def verify_envelope(envelope: Envelope) -> None:
    verify_event_id(envelope)
    verify_signature(envelope)


def verify_timestamp(created_at: int, now_ms: int, window_ms: int) -> None:
    if window_ms < 0 or abs(created_at - now_ms) > window_ms:
        raise AgentProtocolError("timestamp_out_of_window", "timestamp is outside the allowed live-write window")


def nonce_scope_for_event(event: Event, kind: str = "actor_protocol") -> tuple[AgentId, str, str | None, str]:
    room_id = event.get("room_id") if kind == "actor_room" else None
    return (event["actor"], event["protocol"], room_id, event["nonce"])


def verify_live_envelope(envelope: Envelope, nonce_store: NonceStore, *, now_ms: int | None = None, window_ms: int = DEFAULT_LIVE_WRITE_WINDOW_MS, nonce_scope: str = "actor_protocol") -> None:
    verify_envelope(envelope)
    verify_timestamp(envelope["event"]["created_at"], now_ms if now_ms is not None else unix_time_millis(), window_ms)
    nonce_store.check_and_insert(nonce_scope_for_event(envelope["event"], nonce_scope))


def create_request_jwt_claims(agent_id: AgentId, binding: RequestBinding, issued_at: int, ttl_secs: int, jti: str) -> dict[str, Any]:
    return {
        "iss": agent_id,
        "sub": agent_id,
        "aud": binding.audience,
        "iat": issued_at,
        "exp": issued_at + ttl_secs,
        "jti": jti,
    }


def verify_request_jwt(token: str, *, audience: str, now_secs: int | None = None, max_ttl_secs: int = DEFAULT_REQUEST_JWT_TTL_SECS) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise AgentProtocolError("invalid_jwt", "expected three compact JWS parts")
    header = json.loads(_base64url_decode(parts[0]))
    claims = json.loads(_base64url_decode(parts[1]))
    signature = _base64url_decode(parts[2])
    signing_input = f"{parts[0]}.{parts[1]}".encode()

    if header.get("alg") != "EdDSA":
        raise AgentProtocolError("invalid_jwt_claim", "alg must be EdDSA")
    if header.get("typ") != "JWT":
        raise AgentProtocolError("invalid_jwt_claim", "typ must be JWT")
    if header.get("kid") != claims.get("iss") or claims.get("iss") != claims.get("sub"):
        raise AgentProtocolError("invalid_jwt_claim", "kid, iss, and sub must identify the same Agent ID")

    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes(header["kid"]))
    try:
        public_key.verify(signature, signing_input)
    except InvalidSignature as exc:
        raise AgentProtocolError("invalid_signature", "JWT signature verification failed") from exc

    if claims.get("aud") != audience:
        raise AgentProtocolError("invalid_jwt_claim", "aud mismatch")

    now = now_secs if now_secs is not None else unix_time_secs()
    if claims["iat"] > now or claims["exp"] < now:
        raise AgentProtocolError("invalid_jwt_claim", "iat/exp outside valid time window")
    if claims["exp"] - claims["iat"] > max_ttl_secs:
        raise AgentProtocolError("invalid_jwt_claim", "JWT ttl exceeds maximum")
    return claims


def verify_request_jwt_live(token: str, nonce_store: NonceStore, **context: Any) -> dict[str, Any]:
    claims = verify_request_jwt(token, **context)
    nonce_store.check_and_insert((claims["iss"], _REQUEST_AUTH_REPLAY_SCOPE, None, claims["jti"]))
    return claims


def unix_time_millis() -> int:
    return int(time.time() * 1000)


def unix_time_secs() -> int:
    return int(time.time())


def random_nonce(prefix: str = "n_") -> str:
    return f"{prefix}{_base64url_encode(os.urandom(16))}"


def _base58btc_encode(data: bytes) -> str:
    return "z" + base58.b58encode(data).decode()


def _base58btc_decode(value: str) -> bytes:
    if not value.startswith("z"):
        raise AgentProtocolError("invalid_encoding", "expected base58btc multibase value")
    return base58.b58decode(value[1:])


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _base64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)
