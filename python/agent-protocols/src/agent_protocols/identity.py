from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any, MutableMapping, Protocol

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .errors import AgentProtocolError

AGENT_ID_PREFIX = "did:agent:"
DEFAULT_LIVE_WRITE_WINDOW_MS = 300_000
DEFAULT_NONCE_TTL_MS = 300_000
DEFAULT_REQUEST_JWT_TTL_SECS = 300
MAX_NONCE_HEADER = "Max-Seen-Nonce"
MAX_SAFE_NONCE = 0x1FFFFFFFFFFFFF

Event = dict[str, Any]
Envelope = dict[str, Any]
AgentId = str


def agent_id_from_public_key(public_key: bytes) -> AgentId:
    if len(public_key) != 32:
        raise AgentProtocolError("invalid_public_key", f"public key must be 32 bytes, got {len(public_key)}")
    return f"{AGENT_ID_PREFIX}{_base64url_encode(public_key)}"


def public_key_bytes(agent_id: AgentId) -> bytes:
    if not agent_id.startswith(AGENT_ID_PREFIX):
        raise AgentProtocolError("invalid_agent_id", "agent id must start with did:agent:")
    data = _base64url_decode_no_pad(agent_id[len(AGENT_ID_PREFIX):])
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
        digest = event_hash_bytes(event)
        return {
            "hash": _base64url_encode(digest),
            "event": event,
            "signature": sign_event_hash(self._private_key, digest),
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
    def check_and_update(self, actor: AgentId, nonce: int, now_ms: int, ttl_ms: int) -> int: ...

    def max_nonce(self, actor: AgentId, now_ms: int) -> int | None: ...


class MemoryNonceStore:
    def __init__(self) -> None:
        self._records: dict[AgentId, tuple[int, int]] = {}

    def check_and_update(self, actor: AgentId, nonce: int, now_ms: int, ttl_ms: int) -> int:
        validate_nonce(nonce)
        if ttl_ms < 0:
            raise AgentProtocolError("invalid_nonce", "nonce cache ttl must be non-negative")
        record = self._records.get(actor)
        if record is not None:
            max_nonce, expires_at = record
            if expires_at > now_ms and nonce <= max_nonce:
                raise AgentProtocolError("nonce_not_greater", f"nonce must be greater than accepted max nonce {max_nonce}")
        self._records[actor] = (nonce, now_ms + ttl_ms)
        return nonce

    def max_nonce(self, actor: AgentId, now_ms: int) -> int | None:
        record = self._records.get(actor)
        if record is None:
            return None
        max_nonce, expires_at = record
        return max_nonce if expires_at > now_ms else None


class ClientNonceManager:
    def __init__(self, next_nonce: int = 1) -> None:
        validate_nonce(next_nonce)
        self._next_nonce = next_nonce

    def peek(self) -> int:
        return self._next_nonce

    def next_nonce(self) -> int:
        nonce = self._next_nonce
        validate_nonce(nonce)
        self._next_nonce += 1
        return nonce

    def observe_max_nonce(self, max_nonce: int | str | None) -> None:
        if max_nonce is None or max_nonce == "":
            return
        try:
            parsed = int(max_nonce)
        except (TypeError, ValueError) as exc:
            raise AgentProtocolError("invalid_nonce", "invalid max nonce header") from exc
        validate_nonce(parsed)
        if parsed >= self._next_nonce:
            self._next_nonce = parsed + 1


def create_event(protocol: str, event_type: str, actor: AgentId, created_at: int, nonce: int, payload: Any) -> Event:
    validate_agent_id(actor)
    validate_nonce(nonce)
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


def event_hash(event: Event) -> str:
    return _base64url_encode(event_hash_bytes(event))


def event_hash_bytes(event: Event) -> bytes:
    validate_nonce(event["nonce"])
    return hashlib.sha3_256(canonical_event_bytes(event)).digest()


def sign_event(private_key: Ed25519PrivateKey, event: Event) -> str:
    return sign_event_hash(private_key, event_hash_bytes(event))


def sign_event_hash(private_key: Ed25519PrivateKey, event_hash: bytes) -> str:
    return _base64url_encode(private_key.sign(_valid_event_hash_bytes(event_hash)))


def verify_event_hash(envelope: Envelope) -> None:
    expected = event_hash(envelope["event"])
    actual = envelope["hash"]
    if expected != actual:
        raise AgentProtocolError("invalid_event_hash", f"invalid event hash: expected {expected}, got {actual}")


def verify_signature(envelope: Envelope) -> None:
    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes(envelope["event"]["actor"]))
    verify_event_hash_signature(public_key, event_hash_bytes(envelope["event"]), envelope["signature"])


def verify_event_hash_signature(public_key: Ed25519PublicKey, event_hash: bytes, encoded_signature: str) -> None:
    signature = _base64url_decode(encoded_signature)
    if len(signature) != 64:
        raise AgentProtocolError("invalid_signature", f"signature must be 64 bytes, got {len(signature)}")
    try:
        public_key.verify(signature, _valid_event_hash_bytes(event_hash))
    except InvalidSignature as exc:
        raise AgentProtocolError("invalid_signature", "signature verification failed") from exc


def verify_envelope(envelope: Envelope) -> None:
    verify_event_hash(envelope)
    verify_signature(envelope)


def verify_timestamp(created_at: int, now_ms: int, window_ms: int) -> None:
    if window_ms < 0 or abs(created_at - now_ms) > window_ms:
        raise AgentProtocolError("timestamp_out_of_window", "timestamp is outside the allowed live-write window")


def verify_live_envelope(envelope: Envelope, nonce_store: NonceStore, *, now_ms: int | None = None, window_ms: int = DEFAULT_LIVE_WRITE_WINDOW_MS, nonce_ttl_ms: int = DEFAULT_NONCE_TTL_MS) -> int:
    current_now_ms = now_ms if now_ms is not None else unix_ms()
    verify_envelope(envelope)
    verify_timestamp(envelope["event"]["created_at"], current_now_ms, window_ms)
    return nonce_store.check_and_update(envelope["event"]["actor"], envelope["event"]["nonce"], current_now_ms, nonce_ttl_ms)


def create_request_jwt_claims(agent_id: AgentId, binding: RequestBinding, issued_at: int, ttl_secs: int) -> dict[str, Any]:
    return {
        "iss": agent_id,
        "sub": agent_id,
        "aud": binding.audience,
        "iat": issued_at,
        "exp": issued_at + ttl_secs,
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

    now = now_secs if now_secs is not None else unix_secs()
    if claims["exp"] <= claims["iat"]:
        raise AgentProtocolError("invalid_jwt_claim", "exp must be greater than iat")
    if claims["iat"] > now or claims["exp"] < now:
        raise AgentProtocolError("invalid_jwt_claim", "iat/exp outside valid time window")
    if claims["exp"] - claims["iat"] > max_ttl_secs:
        raise AgentProtocolError("invalid_jwt_claim", "JWT ttl exceeds maximum")
    return claims


def unix_ms() -> int:
    return int(time.time() * 1000)


def unix_secs() -> int:
    return int(time.time())


def validate_nonce(nonce: int) -> None:
    if not isinstance(nonce, int) or nonce < 1 or nonce > MAX_SAFE_NONCE:
        raise AgentProtocolError("invalid_nonce", "nonce must be a positive integer less than or equal to 9007199254740991")


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _base64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _base64url_decode_no_pad(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise AgentProtocolError("invalid_encoding", "expected base64url without padding")
    return _base64url_decode(value)


def _valid_event_hash_bytes(event_hash: bytes) -> bytes:
    if len(event_hash) != 32:
        raise AgentProtocolError("invalid_event_hash", f"event hash must be 32 bytes, got {len(event_hash)}")
    return event_hash
