from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import re
import time
from dataclasses import dataclass
from urllib.parse import urlparse
from typing import Any, Callable, Iterable, Literal, MutableMapping, Protocol

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .errors import AgentProtocolError

AGENT_ID_PREFIX = "did:agent:"
DEFAULT_LIVE_WRITE_WINDOW_MS = 300_000
# Nonce cache validity (Agent Identity Section 6.2): at least twice the
# live-write window, because an envelope signed up to one window ahead of the
# receiver's clock stays inside the window for two windows after acceptance.
DEFAULT_NONCE_TTL_MS = 2 * DEFAULT_LIVE_WRITE_WINDOW_MS
DEFAULT_REQUEST_JWT_TTL_SECS = 300
MAX_NONCE_HEADER = "Max-Seen-Nonce"
MAX_SAFE_NONCE = 0x1FFFFFFFFFFFFF
# Largest accepted Max-Seen-Nonce jump beyond max(next_nonce, now)
# (Agent Identity Section 6.2). The nonce sequence is shared by every service
# an agent uses, so one hostile service must not be able to exhaust it.
MAX_NONCE_JUMP = 2**32

# The six Agent Identity event fields; protocols add their own on top.
IDENTITY_EVENT_FIELDS = ("protocol", "type", "actor", "created_at", "nonce", "payload")

# Error codes shared by every Agent Protocols service (Section 8.1).
SHARED_ERROR_CODES = (
    "invalid_request",
    "invalid_event",
    "invalid_event_hash",
    "invalid_signature",
    "invalid_actor",
    "timestamp_out_of_window",
    "nonce_not_greater",
    "invalid_token",
    "permission_denied",
    "not_found",
    "rate_limited",
    "payload_too_large",
)

Event = dict[str, Any]
Envelope = dict[str, Any]
AgentId = str


def agent_id_from_public_key(public_key: bytes) -> AgentId:
    if len(public_key) != 32:
        raise AgentProtocolError("invalid_public_key", f"public key must be 32 bytes, got {len(public_key)}")
    return f"{AGENT_ID_PREFIX}{_base64url_encode(public_key)}"


def public_key_bytes(agent_id: AgentId) -> bytes:
    if not isinstance(agent_id, str):
        raise AgentProtocolError("invalid_agent_id", "agent id must be a string")
    if not agent_id.startswith(AGENT_ID_PREFIX):
        raise AgentProtocolError("invalid_agent_id", "agent id must start with did:agent:")
    data = _base64url_decode(agent_id[len(AGENT_ID_PREFIX):])
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
                # Services rejecting for this reason MUST return the effective
                # maximum in the `Max-Seen-Nonce` response header; `data`
                # carries it.
                raise AgentProtocolError(
                    "nonce_not_greater",
                    f"nonce must be greater than accepted max nonce {max_nonce}",
                    data={"max_nonce": max_nonce},
                )
        self._records[actor] = (nonce, now_ms + ttl_ms)
        return nonce

    def max_nonce(self, actor: AgentId, now_ms: int) -> int | None:
        record = self._records.get(actor)
        if record is None:
            return None
        max_nonce, expires_at = record
        return max_nonce if expires_at > now_ms else None


class ClientNonceManager:
    """Client-side nonce sequence for one Agent ID (Agent Identity Section 6.2).

    Pass the event's ``created_at`` to derive clock-based nonces,
    ``max(last + 1, created_at)``, which stay monotonic across restarts,
    restores, and devices sharing a key; without it the manager is a plain
    counter."""

    def __init__(self, next_nonce: int = 1) -> None:
        validate_nonce(next_nonce)
        self._next_nonce = next_nonce

    def peek(self) -> int:
        return self._next_nonce

    def next_nonce(self, created_at: int | None = None) -> int:
        nonce = created_at if created_at is not None and created_at > self._next_nonce else self._next_nonce
        validate_nonce(nonce)
        self._next_nonce = nonce + 1
        return nonce

    def observe_max_nonce(self, max_nonce: int | str | None, now_ms: int | None = None) -> None:
        """Applies a ``Max-Seen-Nonce`` header. A value more than
        :data:`MAX_NONCE_JUMP` beyond ``max(next_nonce, now_ms)`` is rejected
        rather than applied."""
        if max_nonce is None or max_nonce == "":
            return
        try:
            parsed = int(max_nonce)
        except (TypeError, ValueError) as exc:
            raise AgentProtocolError("invalid_nonce", "invalid max nonce header") from exc
        validate_nonce(parsed)
        now = now_ms if now_ms is not None else unix_ms()
        if parsed > max(self._next_nonce, now) + MAX_NONCE_JUMP:
            raise AgentProtocolError(
                "invalid_nonce", f"Max-Seen-Nonce {parsed} jumps too far beyond the local sequence"
            )
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


def validate_event_fields(event: Event, extra_fields: Iterable[str] = ()) -> None:
    """Enforces the closed event object (Section 5.1): the event may carry only
    the six Agent Identity fields plus ``extra_fields`` the protocol defines."""
    if not isinstance(event, dict):
        raise AgentProtocolError("invalid_event", "event must be an object")
    for field in IDENTITY_EVENT_FIELDS:
        if field not in event:
            raise AgentProtocolError("invalid_event", f"event requires {field}")
    allowed = set(IDENTITY_EVENT_FIELDS) | set(extra_fields)
    for key in event:
        if key not in allowed:
            raise AgentProtocolError("invalid_event", f"unknown event field: {key}")


def with_room_id(event: Event, room_id: str) -> Event:
    next_event = dict(event)
    next_event["room_id"] = room_id
    return next_event


def with_room_head(event: Event, base_seq: int, base_hash: str) -> Event:
    validate_nonce(base_seq)
    if not isinstance(base_hash, str) or not base_hash.strip():
        raise AgentProtocolError("invalid_event", "base_hash must not be empty")
    next_event = dict(event)
    next_event["base_seq"] = base_seq
    next_event["base_hash"] = base_hash
    return next_event


def with_mentions(event: Event, mentions: list[AgentId]) -> Event:
    for mention in mentions:
        validate_agent_id(mention)
    next_event = dict(event)
    next_event["mentions"] = list(mentions)
    return next_event


def with_mention(event: Event, agent_id: AgentId) -> Event:
    validate_agent_id(agent_id)
    next_event = dict(event)
    next_event["mentions"] = [*next_event.get("mentions", []), agent_id]
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
    """Signs a precomputed 32-byte event hash. Signing a digest supplied by
    another component without seeing the event it commits to (blind signing)
    is NOT RECOMMENDED: ``actor`` and all event content are inside the digest,
    so a blind signer can be tricked into signing arbitrary events attributed
    to its key. Prefer :func:`sign_event`."""
    return _base64url_encode(private_key.sign(_valid_event_hash_bytes(event_hash)))


def verify_event_hash(envelope: Envelope) -> None:
    expected = event_hash(envelope["event"])
    actual = envelope["hash"]
    if expected != actual:
        raise AgentProtocolError("invalid_event_hash", f"invalid event hash: expected {expected}, got {actual}")


def verify_signature(envelope: Envelope) -> None:
    verify_event_hash_signature(
        public_key_bytes(envelope["event"]["actor"]), event_hash_bytes(envelope["event"]), envelope["signature"]
    )


def verify_event_hash_signature(public_key: Ed25519PublicKey | bytes, event_hash: bytes, encoded_signature: str) -> None:
    signature = _base64url_decode(encoded_signature)
    if len(signature) != 64:
        raise AgentProtocolError("invalid_signature", f"signature must be 64 bytes, got {len(signature)}")
    if not verify_ed25519_strict(_valid_event_hash_bytes(event_hash), signature, _raw_public_key(public_key)):
        raise AgentProtocolError("invalid_signature", "signature verification failed")


# p = 2^255 - 19 and L = 2^252 + 27742317777372353535851937790883648493.
_FIELD_P = (1 << 255) - 19
_GROUP_L = (1 << 252) + 27742317777372353535851937790883648493
# y-coordinates (sign bit cleared) of every small-order point (Appendix B).
_SMALL_ORDER_Y = frozenset(
    {
        0,
        1,
        _FIELD_P - 1,
        int.from_bytes(bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"), "little"),
        int.from_bytes(bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"), "little"),
    }
)


def _is_strict_point(encoding: bytes) -> bool:
    """Canonical encoding (y < p) of a point that is not of small order."""
    y = int.from_bytes(encoding, "little") & ((1 << 255) - 1)
    return y < _FIELD_P and y not in _SMALL_ORDER_Y


def verify_ed25519_strict(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Ed25519 verification under the deterministic rules of Agent Identity
    Section 3.1: canonical, non-small-order ``A`` and ``R``, reduced ``S``,
    and the cofactorless equation."""
    if len(signature) != 64 or len(public_key) != 32:
        return False
    if not _is_strict_point(public_key) or not _is_strict_point(signature[:32]):
        return False
    if int.from_bytes(signature[32:], "little") >= _GROUP_L:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def _raw_public_key(public_key: Ed25519PublicKey | bytes) -> bytes:
    if isinstance(public_key, (bytes, bytearray)):
        return bytes(public_key)
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def parse_strict_json(text: str | bytes) -> Any:
    """Parses signed JSON strictly (Agent Identity Section 4.1): rejects
    duplicate member names, unpaired surrogates, and integers outside the safe
    range. ``json.loads`` silently keeps the last of two duplicate names, so
    parse raw request bodies with this before hashing."""

    def fail(message: str) -> AgentProtocolError:
        return AgentProtocolError("invalid_event", f"invalid JSON: {message}")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise fail(f"duplicate member name {json.dumps(key)}")
            result[key] = value
        return result

    def parse_int(value: str) -> int:
        number = int(value)
        if abs(number) > MAX_SAFE_NONCE:
            raise fail("integer outside the safe range")
        return number

    def parse_float(value: str) -> float:
        number = float(value)
        if not math.isfinite(number):
            raise fail("number out of range")
        if number.is_integer() and abs(number) > MAX_SAFE_NONCE:
            raise fail("integer outside the safe range")
        return number

    def parse_constant(value: str) -> Any:
        raise fail(f"unexpected token {value}")

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=parse_int,
            parse_float=parse_float,
            parse_constant=parse_constant,
        )
    except AgentProtocolError:
        raise
    except (ValueError, RecursionError) as exc:
        raise fail(str(exc)) from exc
    _reject_unpaired_surrogates(value, 0, fail)
    return value


def _reject_unpaired_surrogates(value: Any, depth: int, fail: Callable[[str], AgentProtocolError]) -> None:
    # json.loads joins escaped surrogate pairs, so any surrogate left is unpaired.
    if depth > 256:
        raise fail("nesting too deep")
    if isinstance(value, str):
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
            raise fail("unpaired surrogate in string")
    elif isinstance(value, dict):
        for key, item in value.items():
            _reject_unpaired_surrogates(key, depth + 1, fail)
            _reject_unpaired_surrogates(item, depth + 1, fail)
    elif isinstance(value, list):
        for item in value:
            _reject_unpaired_surrogates(item, depth + 1, fail)


def parse_envelope_json(text: str | bytes) -> Envelope:
    """:func:`parse_strict_json` for a signed envelope, checking its outer shape."""
    value = parse_strict_json(text)
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("hash"), str)
        or not isinstance(value.get("signature"), str)
        or not isinstance(value.get("event"), dict)
    ):
        raise AgentProtocolError("invalid_event", "envelope must contain hash, event, and signature")
    for key in value:
        if key not in ("hash", "event", "signature"):
            raise AgentProtocolError("invalid_event", f"unknown envelope field: {key}")
    return value


def verify_envelope(envelope: Envelope) -> None:
    verify_event_hash(envelope)
    verify_signature(envelope)


def verify_timestamp(created_at: int, now_ms: int, window_ms: int) -> None:
    if window_ms < 0 or abs(created_at - now_ms) > window_ms:
        raise AgentProtocolError("timestamp_out_of_window", "timestamp is outside the allowed live-write window")


@dataclass(frozen=True)
class SubmissionResult:
    """Outcome of :func:`verify_submission`: an exact resubmission of an
    accepted envelope, or a new live write with the nonce now recorded."""

    kind: Literal["resubmission", "accepted"]
    max_nonce: int | None = None


def verify_submission(
    envelope: Envelope,
    nonce_store: NonceStore,
    *,
    is_accepted: Callable[[str], bool] | None = None,
    now_ms: int | None = None,
    window_ms: int = DEFAULT_LIVE_WRITE_WINDOW_MS,
    nonce_ttl_ms: int = DEFAULT_NONCE_TTL_MS,
) -> SubmissionResult:
    """Agent Identity Section 6.1 for one submission: verifies the envelope,
    answers an exact resubmission of an accepted envelope before the time
    window and nonce checks (Section 6.3), and otherwise enforces both."""
    verify_envelope(envelope)
    if is_accepted is not None and is_accepted(envelope["hash"]):
        return SubmissionResult("resubmission")
    current_now_ms = now_ms if now_ms is not None else unix_ms()
    verify_timestamp(envelope["event"]["created_at"], current_now_ms, window_ms)
    max_nonce = nonce_store.check_and_update(
        envelope["event"]["actor"], envelope["event"]["nonce"], current_now_ms, nonce_ttl_ms
    )
    return SubmissionResult("accepted", max_nonce)


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

    if not verify_ed25519_strict(signing_input, signature, public_key_bytes(header["kid"])):
        raise AgentProtocolError("invalid_signature", "JWT signature verification failed")

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


def validate_origin(value: Any) -> None:
    """Checks that ``value`` is a serialized HTTPS origin (Agent Identity
    Section 4.4): WHATWG URL parsing and origin serialization must reproduce it
    exactly. Python has no WHATWG parser, so this re-serializes the host the
    way WHATWG does for the ASCII, IPv4, and IPv6 forms that can appear."""
    if not isinstance(value, str) or any(c.isspace() for c in value) or "\\" in value or "%" in value:
        raise AgentProtocolError("invalid_url", f"origin must be a serialized HTTPS origin: {value!r}")
    try:
        parsed = urlparse(value)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("not an https URL")
        host = parsed.hostname.encode("idna").decode("ascii")
        if ":" in host:
            host = "[" + ipaddress.IPv6Address(host).compressed + "]"
        elif re.fullmatch(r"(?:[0-9]+|0[xX][0-9a-fA-F]+)", host.rstrip(".").split(".")[-1]):
            host = str(ipaddress.IPv4Address(host))
        port = parsed.port
        canonical = "https://" + host + (f":{port}" if port is not None and port != 443 else "")
    except (ValueError, UnicodeError, AttributeError) as exc:
        raise AgentProtocolError("invalid_url", f"origin must be a serialized HTTPS origin: {value!r}") from exc
    if value != canonical:
        raise AgentProtocolError("invalid_url", f"origin must be a serialized HTTPS origin: {value!r}")


def service_origin(url: str) -> str:
    """Derives the request JWT ``aud`` from a request URL: the service origin —
    scheme, host, and non-default port, with no path (Agent Identity Section 7)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        raise AgentProtocolError("invalid_url", f"not an HTTP(S) URL: {url}")
    host = parsed.hostname
    port = parsed.port
    default_port = 443 if parsed.scheme == "https" else 80
    if port is None or port == default_port:
        return f"{parsed.scheme}://{host}"
    return f"{parsed.scheme}://{host}:{port}"


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
    """Canonical base64url decoding: URL-safe alphabet, no padding, zero
    trailing bits. Receivers MUST reject non-canonical encodings, otherwise
    one value gains multiple distinct string forms and corrupts string-keyed
    comparisons."""
    if not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise AgentProtocolError("invalid_encoding", "expected canonical base64url without padding")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        data = base64.urlsafe_b64decode(value + padding)
    except (ValueError, TypeError) as exc:
        raise AgentProtocolError("invalid_encoding", "expected canonical base64url without padding") from exc
    if _base64url_encode(data) != value:
        raise AgentProtocolError("invalid_encoding", "expected canonical base64url without padding")
    return data


def _valid_event_hash_bytes(event_hash: bytes) -> bytes:
    if len(event_hash) != 32:
        raise AgentProtocolError("invalid_event_hash", f"event hash must be 32 bytes, got {len(event_hash)}")
    return event_hash
