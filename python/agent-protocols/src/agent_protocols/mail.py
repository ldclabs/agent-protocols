"""Agent Mail 1.0: signed correspondence and one-shot RFC 9180 encryption.

HPKE is supplied by PyHPKE, backed by cryptography. This module never fetches,
executes, or renders message content. Stateful retention/acceptance is provided
by mail_state; applications must persist that state before acknowledging mail.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import secrets
from importlib.resources import files
from typing import Any
from urllib.parse import urlsplit

import rfc8785
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from jsonschema import Draft202012Validator
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey, PyHPKEError

from .errors import AgentProtocolError
from .identity import (
    AgentSigner, Envelope, Event, MAX_SAFE_NONCE, create_event, parse_strict_json,
    unix_ms, validate_origin, verify_envelope, verify_request_jwt,
)

MAIL_PROTOCOL = 'agent-mail/1.0'
MAILBOX_PUBLISH = 'mailbox.publish'
MAIL_MESSAGE = 'mail.message'
MAIL_RECEIPT = 'mail.receipt'
MAIL_MAX_TTL_MS = 30 * 86_400_000
MAIL_FUTURE_SKEW_MS = 300_000
MAIL_MAX_PACKET_BYTES = 1_048_576
MAIL_ERROR_CODES = ('mailbox_unavailable', 'stale_card', 'packet_expired', 'invalid_packet', 'mailbox_conflict', 'quota_exceeded')
MAIL_SCHEMA = parse_strict_json(files(__package__).joinpath('mail.schema.json').read_bytes())
_VALIDATORS = {name: Draft202012Validator({'$ref': '#/$defs/' + name, '$defs': MAIL_SCHEMA['$defs']}) for name in MAIL_SCHEMA['$defs']}


def _fail(code: str, message: str) -> None:
    raise AgentProtocolError(code, message)


def _require(ok: bool, code: str, message: str) -> None:
    if not ok:
        _fail(code, message)


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def _decode(value: Any, size: int | None = None, code: str = 'invalid_event') -> bytes:
    try:
        if not isinstance(value, str):
            raise ValueError('not a string')
        raw = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
    except (ValueError, TypeError) as exc:
        raise AgentProtocolError(code, 'invalid base64url encoding') from exc
    _require(_b64(raw) == value and (size is None or len(raw) == size), code, 'noncanonical base64url or wrong byte length')
    return raw


def _jcs(value: Any) -> bytes:
    try:
        return rfc8785.dumps(value)
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise AgentProtocolError('invalid_event', 'value cannot be canonicalized') from exc


def _now(now_ms: int | None) -> int:
    value = unix_ms() if now_ms is None else now_ms
    _require(type(value) is int and 0 <= value <= MAX_SAFE_NONCE, 'invalid_request', 'invalid current time')
    return value


def _strict_value(value: Any, code: str) -> None:
    try:
        parse_strict_json(json.dumps(value, ensure_ascii=False, allow_nan=False))
    except (AgentProtocolError, ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise AgentProtocolError(code, 'value violates strict I-JSON') from exc


def validate_mail_schema(value: Any, definition: str = 'envelope', code: str = 'invalid_event') -> None:
    """Validate structure/strict I-JSON only, not signatures, lifetimes or state."""
    _strict_value(value, code)
    if definition not in _VALIDATORS:
        _fail('invalid_request', 'unknown Mail schema definition')
    _require(_VALIDATORS[definition].is_valid(value), code, definition + ' schema violation')


def validate_mail_id(value: Any, *, size: int = 32, code: str = 'invalid_request') -> None:
    _decode(value, size, code)


def new_mail_id() -> str:
    """Generate an independent random 16-byte mailbox/key/thread identifier."""
    return _b64(secrets.token_bytes(16))


def _public_key(value: str) -> X25519PublicKey:
    key = X25519PublicKey.from_public_bytes(_decode(value, 32))
    try:
        # Reject all-zero exchanges, including low-order/noncanonical aliases.
        X25519PrivateKey.from_private_bytes(bytes([42]) * 32).exchange(key)
    except ValueError as exc:
        raise AgentProtocolError('invalid_event', 'unusable X25519 key') from exc
    return key


class MailEncryptionKey:
    """Independent X25519 recipient key. Never derive it from an identity seed.

    Export is explicit and contains secret material; protect exported state.
    Python does not promise erasure of immutable buffers or GC-managed objects.
    """
    def __init__(self, private_key: X25519PrivateKey):
        if not isinstance(private_key, X25519PrivateKey):
            _fail('invalid_request', 'expected an independently generated X25519 private key')
        self._private_key = private_key

    @classmethod
    def generate(cls) -> 'MailEncryptionKey':
        return cls(X25519PrivateKey.generate())

    @classmethod
    def from_private_bytes(cls, secret: bytes) -> 'MailEncryptionKey':
        if not isinstance(secret, bytes) or len(secret) != 32:
            _fail('invalid_request', 'X25519 secret must be 32 bytes')
        return cls(X25519PrivateKey.from_private_bytes(secret))

    def private_bytes(self) -> bytes:
        return self._private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    def public_key(self) -> str:
        return _b64(self._private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def mailbox_publish_event(actor: str, created_at: int, nonce: int, payload: dict[str, Any]) -> Event:
    return create_event(MAIL_PROTOCOL, MAILBOX_PUBLISH, actor, created_at, nonce, copy.deepcopy(payload))


def mail_message_event(actor: str, created_at: int, nonce: int, payload: dict[str, Any]) -> Event:
    return create_event(MAIL_PROTOCOL, MAIL_MESSAGE, actor, created_at, nonce, copy.deepcopy(payload))


def mail_receipt_event(actor: str, created_at: int, nonce: int, payload: dict[str, Any]) -> Event:
    return create_event(MAIL_PROTOCOL, MAIL_RECEIPT, actor, created_at, nonce, copy.deepcopy(payload))


def sign_mail_event(signer: AgentSigner, event: Event) -> Envelope:
    _require(isinstance(event, dict), 'invalid_event', 'event must be an object')
    _require(event.get('actor') == signer.agent_id(), 'invalid_actor', 'signer must match event actor')
    result = signer.sign_event(copy.deepcopy(event))
    validate_mail_envelope(result)
    return result


def mail_part(media_type: str, data: bytes | str, *, name: str | None = None) -> dict[str, Any]:
    if isinstance(data, str):
        data = data.encode('utf-8')
    _require(isinstance(data, bytes), 'invalid_event', 'part data must be bytes or text')
    part = {'media_type': media_type, 'data': _b64(data)}
    if name is not None:
        part['name'] = name
    decode_mail_part(part)
    return part


def decode_mail_part(part: dict[str, Any]) -> bytes:
    validate_mail_schema(part, 'part')
    data = _decode(part['data'])
    if part['media_type'].startswith('text/'):
        try:
            data.decode('utf-8')
        except UnicodeDecodeError as exc:
            raise AgentProtocolError('invalid_event', 'text part is not UTF-8') from exc
    return data


def validate_mail_envelope(envelope: Envelope) -> None:
    """Historical verification: shape, signature, intrinsic lifetimes and content.

    No live nonce cache, current-card check or past-age window is applied.
    """
    validate_mail_schema(envelope)
    normalized = copy.deepcopy(envelope)
    # JSON 1 and 1.0 have the same JCS representation and safe-integer meaning.
    normalized['event']['nonce'] = int(normalized['event']['nonce'])
    normalized['event']['created_at'] = int(normalized['event']['created_at'])
    verify_envelope(normalized)
    event, payload = envelope['event'], envelope['event']['payload']
    _require(event['created_at'] < payload['expires_at'] <= event['created_at'] + MAIL_MAX_TTL_MS,
             'invalid_event', 'invalid letter/card lifetime')
    if event['type'] == MAILBOX_PUBLISH:
        _require(payload['expires_at'] <= payload['receive_until'] <= payload['expires_at'] + MAIL_MAX_TTL_MS,
                 'invalid_event', 'invalid receive_until')
        for route in payload['routes']:
            validate_origin(route)
        _public_key(payload['public_key'])
    elif event['type'] == MAIL_MESSAGE:
        for part in payload['parts']:
            decode_mail_part(part)
        if 'reply_card' in payload:
            validate_mailbox_card(payload['reply_card'], event['actor'])


def parse_mail_envelope(raw: str | bytes, *, max_bytes: int = MAIL_MAX_PACKET_BYTES) -> Envelope:
    envelope = _parse_bounded(raw, max_bytes, 'invalid_event')
    validate_mail_envelope(envelope)
    return envelope


def _parse_bounded(raw: str | bytes, maximum: int, code: str) -> Any:
    try:
        data = raw.encode('utf-8') if isinstance(raw, str) else raw
        _require(isinstance(data, bytes), code, 'expected UTF-8 JSON bytes or string')
        _require(len(data) <= maximum, 'payload_too_large', 'raw JSON exceeds configured limit')
        return parse_strict_json(data.decode('utf-8'))
    except (UnicodeError, RecursionError) as exc:
        raise AgentProtocolError(code, 'invalid UTF-8 JSON') from exc


def validate_mailbox_card(card: Envelope, expected_owner: str, *, now_ms: int | None = None,
                          for_sending: bool = False) -> None:
    validate_mail_schema(card, 'mailboxCardEnvelope')
    validate_mail_envelope(card)
    _require(card['event']['actor'] == expected_owner, 'invalid_actor', 'card owner mismatch')
    if for_sending:
        now = _now(now_ms)
        event, payload = card['event'], card['event']['payload']
        _require(event['created_at'] <= now + MAIL_FUTURE_SKEW_MS, 'invalid_event', 'card timestamp too far in future')
        _require(payload['enabled'], 'mailbox_unavailable', 'mailbox card is disabled')
        _require(now < payload['expires_at'], 'stale_card', 'mailbox card expired')


def validate_mail_reply(reply: Envelope, parent: Envelope) -> None:
    """Bind a known parent and both participants before linking a thread."""
    validate_mail_schema(reply, 'messageEnvelope')
    validate_mail_schema(parent, 'messageEnvelope')
    validate_mail_envelope(reply)
    validate_mail_envelope(parent)
    r, p = reply['event'], parent['event']
    _require(r['actor'] == p['payload']['to'] and r['payload']['to'] == p['actor']
             and r['payload'].get('in_reply_to') == parent['hash']
             and r['payload']['thread_id'] == p['payload']['thread_id'],
             'invalid_event', 'reply participants, parent or thread mismatch')


def validate_mail_receipt(receipt: Envelope, sent_message: Envelope) -> None:
    """The caller must supply an original message it actually sent."""
    validate_mail_schema(receipt, 'receiptEnvelope')
    validate_mail_schema(sent_message, 'messageEnvelope')
    validate_mail_envelope(receipt)
    validate_mail_envelope(sent_message)
    r, m = receipt['event'], sent_message['event']
    _require(r['actor'] == m['payload']['to'] and r['payload']['to'] == m['actor']
             and r['payload']['message_hash'] == sent_message['hash'],
             'invalid_event', 'receipt does not match the sent message')


def _frame_json(data: bytes) -> bytes:
    _require(len(data) <= MAIL_MAX_PACKET_BYTES, 'payload_too_large', 'letter too large')
    size = 1024 * ((4 + len(data) + 1023) // 1024)
    return len(data).to_bytes(4, 'big') + data + bytes(size - 4 - len(data))


def encode_mail_plaintext(letter: Envelope) -> bytes:
    validate_mail_schema(letter, 'letterEnvelope')
    validate_mail_envelope(letter)
    return _frame_json(_jcs(letter))


def decode_mail_plaintext(plaintext: bytes) -> Envelope:
    _require(isinstance(plaintext, bytes) and 1024 <= len(plaintext) <= MAIL_MAX_PACKET_BYTES
             and len(plaintext) % 1024 == 0, 'invalid_packet', 'invalid plaintext block length')
    n = int.from_bytes(plaintext[:4], 'big')
    _require(0 < n <= len(plaintext) - 4, 'invalid_packet', 'invalid plaintext JSON length')
    _require(len(plaintext) == 1024 * ((4 + n + 1023) // 1024), 'invalid_packet', 'nonminimal padding')
    _require(not any(plaintext[4+n:]), 'invalid_packet', 'nonzero padding')
    data = plaintext[4:4+n]
    letter = _parse_bounded(data, MAIL_MAX_PACKET_BYTES, 'invalid_packet')
    _require(_jcs(letter) == data, 'invalid_packet', 'plaintext JSON is not JCS')
    validate_mail_schema(letter, 'letterEnvelope', 'invalid_packet')
    validate_mail_envelope(letter)
    return letter


def mail_packet_id(packet: dict[str, Any]) -> str:
    validate_mail_packet(packet)
    return _b64(hashlib.sha3_256(_jcs(packet)).digest())


def validate_mail_packet(packet: dict[str, Any], *, packet_id: str | None = None,
                         max_bytes: int = MAIL_MAX_PACKET_BYTES) -> None:
    validate_mail_schema(packet, 'packet', 'invalid_packet')
    _decode(packet['enc'], 32, 'invalid_packet')
    ct = _decode(packet['ciphertext'], code='invalid_packet')
    _require(len(ct) >= 1040 and len(ct) % 1024 == 16, 'invalid_packet', 'invalid ciphertext block length')
    _require(len(_jcs(packet)) <= min(max_bytes, MAIL_MAX_PACKET_BYTES), 'payload_too_large', 'packet size exceeds limit')
    if packet_id is not None:
        _require(_b64(hashlib.sha3_256(_jcs(packet)).digest()) == packet_id, 'invalid_packet', 'packet ID mismatch')


def parse_mail_packet(raw: str | bytes, *, max_body_bytes: int = MAIL_MAX_PACKET_BYTES + 65536) -> dict[str, Any]:
    packet = _parse_bounded(raw, max_body_bytes, 'invalid_packet')
    validate_mail_packet(packet)
    return packet


def _suite() -> CipherSuite:
    # Construct per operation: PyHPKE context/KDF state is never shared by threads.
    return CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.CHACHA20_POLY1305)


def _info(header: dict[str, Any]) -> bytes:
    return MAIL_PROTOCOL.encode() + b'\0' + _decode(header['card_hash'], 32)


def _check_packet_card(packet: dict[str, Any], card: Envelope, owner: str) -> None:
    validate_mailbox_card(card, owner)
    c, h = card['event']['payload'], packet['header']
    _require(c['enabled'], 'invalid_packet', 'encryption card itself was disabled')
    _require(h['card_hash'] == card['hash'] and h['mailbox_id'] == c['mailbox_id']
             and h['key_id'] == c['key_id'], 'invalid_packet', 'packet/card binding mismatch')
    _require(h['expires_at'] <= c['receive_until'], 'invalid_packet', 'packet exceeds key retention deadline')
    validate_mail_packet(packet, max_bytes=c['max_packet_bytes'])


def encrypt_mail(letter: Envelope, card: Envelope, *, now_ms: int | None = None) -> dict[str, Any]:
    """Fresh one-shot HPKE encryption; no caller-controlled ephemeral randomness.

    Use MailSender with a persisted MailCardCache/MailOutbox for rollback-safe
    sending and retries. This stateless primitive cannot know earlier cards.
    """
    letter, card, now = copy.deepcopy(letter), copy.deepcopy(card), _now(now_ms)
    validate_mail_schema(letter, 'letterEnvelope')
    validate_mail_envelope(letter)
    e, p = letter['event'], letter['event']['payload']
    validate_mailbox_card(card, p['to'], now_ms=now, for_sending=True)
    c = card['event']['payload']
    _require(e['created_at'] <= now + MAIL_FUTURE_SKEW_MS, 'invalid_event', 'letter timestamp too far in future')
    _require(now < p['expires_at'] <= c['receive_until'], 'packet_expired', 'letter expired or exceeds receive_until')
    header = {'protocol': MAIL_PROTOCOL, 'mailbox_id': c['mailbox_id'], 'card_hash': card['hash'],
              'key_id': c['key_id'], 'expires_at': p['expires_at']}
    plaintext = encode_mail_plaintext(letter)
    # Account for exact base64/JSON overhead before encryption and allocation.
    bound = len(_jcs({'header': header, 'enc': 'A' * 43, 'ciphertext': ''})) + ((len(plaintext) + 16) * 8 + 5) // 6
    _require(bound <= min(c['max_packet_bytes'], MAIL_MAX_PACKET_BYTES), 'payload_too_large', 'encrypted packet would exceed limit')
    try:
        enc, context = _suite().create_sender_context(KEMKey.from_pyca_cryptography_key(_public_key(c['public_key'])), info=_info(header))
        try:
            ciphertext = context.seal(plaintext, _jcs(header))
        finally:
            del context
    except (PyHPKEError, ValueError) as exc:
        raise AgentProtocolError('invalid_packet', 'HPKE encryption failed') from exc
    packet = {'header': header, 'enc': _b64(enc), 'ciphertext': _b64(ciphertext)}
    validate_mail_packet(packet, max_bytes=c['max_packet_bytes'])
    return packet


def decrypt_mail(packet: dict[str, Any], card: Envelope, key: MailEncryptionKey, owner: str, *,
                 now_ms: int | None = None, packet_id: str | None = None,
                 allow_expired: bool = False) -> Envelope:
    """Verify/decrypt locally. Acceptance and cross-route dedup use MailInbox.

    allow_expired is only for checking an already accepted duplicate. It never
    grants permission for new acceptance. Detailed failures stay local.
    """
    packet, card, now = copy.deepcopy(packet), copy.deepcopy(card), _now(now_ms)
    validate_mail_packet(packet, packet_id=packet_id)
    _check_packet_card(packet, card, owner)
    _require(isinstance(key, MailEncryptionKey) and key.public_key() == card['event']['payload']['public_key'],
             'invalid_packet', 'recipient secret does not match card')
    h = packet['header']
    try:
        context = _suite().create_recipient_context(_decode(packet['enc'], 32), KEMKey.from_pyca_cryptography_key(key._private_key), info=_info(h))
        try:
            plaintext = context.open(_decode(packet['ciphertext']), _jcs(h))
        finally:
            del context
    except (PyHPKEError, ValueError) as exc:
        raise AgentProtocolError('invalid_packet', 'HPKE decryption failed') from exc
    letter = decode_mail_plaintext(plaintext)
    e, p = letter['event'], letter['event']['payload']
    _require(p['to'] == owner and p['expires_at'] == h['expires_at'], 'invalid_packet', 'recipient or expiration mismatch')
    _require(e['created_at'] <= now + MAIL_FUTURE_SKEW_MS, 'invalid_event', 'letter timestamp too far in future')
    if not allow_expired:
        _require(now < p['expires_at'], 'packet_expired', 'letter acceptance deadline passed')
    return letter


def validate_mail_discovery(document: dict[str, Any], origin: str, card: Envelope | None = None) -> str:
    validate_origin(origin)
    validate_mail_schema(document, 'discoveryDocument', 'invalid_response')
    validate_origin(document['service'])
    _require(document['service'] == origin, 'invalid_response', 'discovery service origin mismatch')
    if card is not None:
        validate_mail_envelope(card)
        _require(card['event']['type'] == MAILBOX_PUBLISH and origin in card['event']['payload']['routes'],
                 'invalid_response', 'discovery origin is not an authorized card route')
    endpoint = document.get('endpoints', {}).get('mailboxes', origin + '/v1/mailboxes')
    try:
        parsed = urlsplit(endpoint)
    except ValueError as exc:
        raise AgentProtocolError('invalid_response', 'invalid mailbox endpoint URL') from exc
    _require(parsed.scheme == 'https' and parsed.netloc == urlsplit(origin).netloc
             and parsed.username is None and parsed.password is None
             and '?' not in endpoint and '#' not in endpoint and not endpoint.endswith('/')
             and '\\' not in endpoint and not any(ord(c) <= 32 for c in endpoint),
             'invalid_response', 'invalid same-origin mailbox endpoint')
    return endpoint


def validate_mail_card_record(record: dict[str, Any], owner: str, mailbox_id: str | None = None) -> None:
    validate_mail_schema(record, 'cardAcceptedRecord', 'invalid_response')
    validate_mailbox_card(record['envelope'], owner)
    if mailbox_id is not None:
        _require(record['envelope']['event']['payload']['mailbox_id'] == mailbox_id,
                 'invalid_response', 'card record mailbox mismatch')


def validate_mail_delivery_result(result: dict[str, Any], packet_id: str | None = None) -> None:
    validate_mail_schema(result, 'deliveryResult', 'invalid_response')
    if packet_id is not None:
        _require(result['packet_id'] == packet_id, 'invalid_response', 'delivery result packet mismatch')


def validate_mail_packet_record(record: dict[str, Any], mailbox_id: str | None = None) -> None:
    validate_mail_schema(record, 'packetRecord', 'invalid_response')
    validate_mail_packet(record['packet'], packet_id=record['packet_id'])
    _require(record['accepted_at'] < record['packet']['header']['expires_at'], 'invalid_response', 'record was accepted after expiration')
    if mailbox_id is not None:
        _require(record['packet']['header']['mailbox_id'] == mailbox_id, 'invalid_response', 'record mailbox mismatch')


def validate_mail_packet_list(page: dict[str, Any], mailbox_id: str, *, limit: int = 100) -> None:
    validate_mail_schema(page, 'packetList', 'invalid_response')
    _require(len(page['result']) <= limit, 'invalid_response', 'page exceeds requested limit')
    seen, seq = set(), 0
    for record in page['result']:
        validate_mail_packet_record(record, mailbox_id)
        _require(record['seq'] > seq and record['packet_id'] not in seen, 'invalid_response', 'page order or duplicate packet')
        seq = record['seq']
        seen.add(record['packet_id'])
    _require('next_cursor' not in page or bool(page['result']), 'invalid_response', 'empty nonterminal page')


def verify_mail_owner_jwt(token: str, owner: str | None, origin: str, *, now_ms: int | None = None) -> dict[str, Any]:
    """Strict Identity JWT validation plus optional mailbox ownership binding."""
    now = _now(now_ms)
    validate_origin(origin)
    try:
        _require(isinstance(token, str) and len(token) <= 16384, 'invalid_token', 'invalid owner token')
        parts = token.split('.')
        _require(len(parts) == 3, 'invalid_token', 'invalid owner token')
        header = parse_strict_json(_decode(parts[0], code='invalid_token').decode('utf-8'))
        claims = parse_strict_json(_decode(parts[1], code='invalid_token').decode('utf-8'))
        _require(isinstance(header, dict) and isinstance(claims, dict), 'invalid_token', 'invalid JWT objects')
        for name in ('iat', 'exp'):
            value = claims.get(name)
            _require(isinstance(value, (int, float)) and not isinstance(value, bool) and value == int(value)
                     and 0 <= value <= MAX_SAFE_NONCE, 'invalid_token', 'invalid JWT timestamp')
        claims = verify_request_jwt(token, audience=origin, now_secs=now // 1000)
        _require(claims['exp'] > now // 1000, 'invalid_token', 'owner token expired')
    except (AgentProtocolError, ValueError, KeyError, TypeError, AttributeError, OverflowError, UnicodeError) as exc:
        raise AgentProtocolError('invalid_token', 'invalid owner request JWT') from exc
    if owner is not None:
        _require(claims['iss'] == claims['sub'] == owner, 'permission_denied', 'requester is not mailbox owner')
    return claims


__all__ = [
    'MAIL_PROTOCOL', 'MAILBOX_PUBLISH', 'MAIL_MESSAGE', 'MAIL_RECEIPT', 'MAIL_MAX_TTL_MS',
    'MAIL_FUTURE_SKEW_MS', 'MAIL_MAX_PACKET_BYTES', 'MAIL_ERROR_CODES', 'MAIL_SCHEMA',
    'MailEncryptionKey', 'new_mail_id', 'mailbox_publish_event', 'mail_message_event',
    'mail_receipt_event', 'sign_mail_event', 'mail_part', 'decode_mail_part',
    'validate_mail_schema', 'validate_mail_id', 'validate_mail_envelope', 'parse_mail_envelope',
    'validate_mailbox_card', 'validate_mail_reply', 'validate_mail_receipt',
    'encode_mail_plaintext', 'decode_mail_plaintext', 'mail_packet_id', 'validate_mail_packet',
    'parse_mail_packet', 'encrypt_mail', 'decrypt_mail', 'validate_mail_discovery',
    'validate_mail_card_record', 'validate_mail_delivery_result', 'validate_mail_packet_record',
    'validate_mail_packet_list', 'verify_mail_owner_jwt',
]
