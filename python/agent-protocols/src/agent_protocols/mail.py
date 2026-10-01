"""Agent Mail 1.0: sender-signed packets and one-shot RFC 9180 encryption.

HPKE is supplied by PyHPKE, backed by cryptography. This module never fetches,
executes, or renders message content. Stateful pinning, key retention and
deduplication live in mail_state; persist that state before acknowledging mail.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import secrets
from importlib.resources import files
from typing import Any, Iterable

import rfc8785
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from jsonschema import Draft202012Validator
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey, PyHPKEError

from .errors import AgentProtocolError
from .identity import (
    AgentSigner, Envelope, Event, MAX_SAFE_NONCE, create_event, format_agent_url, parse_agent_url,
    parse_strict_json, unix_ms, validate_agent_id, validate_origin, verify_envelope, verify_request_jwt,
)

MAIL_PROTOCOL = 'agent-mail/1.0'
MAILBOX_PUBLISH = 'mailbox.publish'
MAIL_SUBMIT = 'mail.submit'
MAIL_MAX_TTL_MS = 30 * 86_400_000
MAIL_FUTURE_SKEW_MS = 300_000
MAIL_MAX_PACKET_BYTES = 1_048_576
MAIL_SCHEMA = parse_strict_json(files(__package__).joinpath('mail.schema.json').read_bytes())
_VALIDATORS = {name: Draft202012Validator({'$ref': '#/$defs/' + name, '$defs': MAIL_SCHEMA['$defs']}) for name in MAIL_SCHEMA['$defs']}
_INFO = MAIL_PROTOCOL.encode()


def _fail(code: str, message: str) -> None:
    raise AgentProtocolError(code, message)


def _require(ok: bool, code: str, message: str) -> None:
    if not ok:
        _fail(code, message)


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def _hash(raw: bytes) -> str:
    return _b64(hashlib.sha3_256(raw).digest())


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
    """Generate an independent random 16-byte mailbox, thread or message identifier."""
    return _b64(secrets.token_bytes(16))


def parse_mail_address(value: Any) -> dict[str, Any]:
    """Parse ``did:agent:<key>/mail/<mailbox_id>[?route=<origin>...]`` (Mail Section 3.3).

    Returns ``{"owner", "mailbox_id", "routes"}``; ``routes`` is empty for the stable form.
    """
    url = parse_agent_url(value)
    _require(url['protocol'] == 'mail', 'invalid_url', 'not a mailbox address')
    _decode(url['resource'], 16, 'invalid_url')
    return {'owner': url['agent_id'], 'mailbox_id': url['resource'], 'routes': url['routes']}


def format_mail_address(owner: str, mailbox_id: str, routes: Iterable[str] = ()) -> str:
    """Format the stable address, or a contact address when routes are given."""
    _decode(mailbox_id, 16, 'invalid_url')
    return format_agent_url(owner, 'mail', mailbox_id, routes)


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


def create_mail_message(actor: str, created_at: int, payload: dict[str, Any]) -> dict[str, Any]:
    _require(isinstance(payload, dict) and not {'message_id', 'from', 'created_at'}.intersection(payload),
             'invalid_event', 'message content must not override generated identity fields')
    message = {**copy.deepcopy(payload), 'message_id': new_mail_id(), 'from': actor, 'created_at': created_at}
    validate_mail_message(message)
    return message


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


def validate_mail_message(message: dict[str, Any]) -> None:
    """Validate immutable plaintext; its authentication comes from the signed packet."""
    validate_mail_schema(message, 'messagePayload')
    _require(message['created_at'] < message['expires_at'] <= message['created_at'] + MAIL_MAX_TTL_MS,
             'invalid_event', 'invalid message lifetime')
    for part in message['parts']:
        decode_mail_part(part)
    if 'reply_card' in message:
        validate_mailbox_card(message['reply_card'], message['from'])


def validate_mail_envelope(envelope: Envelope, definition: str = 'envelope', *, code: str = 'invalid_event') -> None:
    """Historical verification of a card or a sender-signed encrypted packet."""
    validate_mail_schema(envelope, definition, code)
    normalized = copy.deepcopy(envelope)
    normalized['event']['nonce'] = int(normalized['event']['nonce'])
    normalized['event']['created_at'] = int(normalized['event']['created_at'])
    verify_envelope(normalized)
    event, payload = envelope['event'], envelope['event']['payload']
    if event['type'] == MAILBOX_PUBLISH:
        _require(event['created_at'] < payload['expires_at'] <= event['created_at'] + MAIL_MAX_TTL_MS,
                 'invalid_event', 'invalid card lifetime')
        _require(payload['expires_at'] <= payload['receive_until'] <= payload['expires_at'] + MAIL_MAX_TTL_MS,
                 'invalid_event', 'invalid receive_until')
        for route in payload['routes']:
            validate_origin(route)
        _public_key(payload['public_key'])
    else:
        _decode(payload['enc'], 32, 'invalid_packet')
        ct = _decode(payload['ciphertext'], code='invalid_packet')
        _require(len(ct) >= 1040 and len(ct) % 1024 == 16, 'invalid_packet', 'invalid ciphertext block length')
        _require(event['created_at'] < payload['header']['expires_at'] <= event['created_at'] + MAIL_MAX_TTL_MS + MAIL_FUTURE_SKEW_MS,
                 'invalid_packet', 'invalid packet lifetime')


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
    """Verify a card; with for_sending, also require it to be current, open and unexpired."""
    validate_mail_envelope(card, 'mailboxCardEnvelope')
    _require(card['event']['actor'] == expected_owner, 'invalid_actor', 'card owner mismatch')
    if for_sending:
        now = _now(now_ms)
        event, payload = card['event'], card['event']['payload']
        _require(event['created_at'] <= now + MAIL_FUTURE_SKEW_MS, 'timestamp_out_of_window', 'card is future-dated')
        _require(bool(payload['routes']), 'mailbox_unavailable', 'mailbox closed')
        _require(now < payload['expires_at'], 'stale_card', 'mailbox card expired')


def validate_mail_reply(reply: dict[str, Any], parent: dict[str, Any]) -> None:
    validate_mail_message(reply)
    validate_mail_message(parent)
    _require(reply['from'] == parent['to'] and reply['to'] == parent['from']
             and reply.get('in_reply_to') == parent['message_id'] and reply['thread_id'] == parent['thread_id'],
             'invalid_event', 'reply participants, parent or thread mismatch')


def _frame_json(data: bytes) -> bytes:
    _require(len(data) <= MAIL_MAX_PACKET_BYTES, 'payload_too_large', 'message too large')
    size = 1024 * ((4 + len(data) + 1023) // 1024)
    return len(data).to_bytes(4, 'big') + data + bytes(size - 4 - len(data))


def encode_mail_plaintext(message: dict[str, Any]) -> bytes:
    validate_mail_message(message)
    return _frame_json(_jcs(message))


def decode_mail_plaintext(plaintext: bytes) -> dict[str, Any]:
    _require(isinstance(plaintext, bytes) and 1024 <= len(plaintext) <= MAIL_MAX_PACKET_BYTES
             and len(plaintext) % 1024 == 0, 'invalid_packet', 'invalid plaintext block length')
    n = int.from_bytes(plaintext[:4], 'big')
    _require(0 < n <= len(plaintext) - 4, 'invalid_packet', 'invalid plaintext JSON length')
    _require(len(plaintext) == 1024 * ((4 + n + 1023) // 1024), 'invalid_packet', 'nonminimal padding')
    _require(not any(plaintext[4+n:]), 'invalid_packet', 'nonzero padding')
    data = plaintext[4:4+n]
    message = _parse_bounded(data, MAIL_MAX_PACKET_BYTES, 'invalid_packet')
    _require(_jcs(message) == data, 'invalid_packet', 'plaintext JSON is not JCS')
    validate_mail_message(message)
    return message


def mail_packet_id(packet: dict[str, Any]) -> str:
    _packet_bytes(packet)
    return packet['hash']


def _packet_bytes(packet: dict[str, Any], packet_id: str | None = None) -> bytes:
    """Verify the outer signature before policy checks or private-key operations."""
    validate_mail_envelope(packet, 'packetEnvelope')
    raw = _jcs(packet)
    _require(len(raw) <= MAIL_MAX_PACKET_BYTES, 'payload_too_large', 'packet exceeds limit')
    if packet_id is not None:
        _require(packet['hash'] == packet_id, 'invalid_packet', 'packet ID mismatch')
    return raw


def mail_packet_aad(event: Event) -> bytes:
    """HPKE AAD: the packet's five metadata fields and header, from the verified outer event."""
    return _jcs({**{k: event[k] for k in ('protocol', 'type', 'actor', 'created_at', 'nonce')},
                 'header': event['payload']['header']})


def validate_mail_packet(packet: dict[str, Any], *, packet_id: str | None = None) -> None:
    _packet_bytes(packet, packet_id)


def parse_mail_packet(raw: str | bytes, *, max_body_bytes: int = MAIL_MAX_PACKET_BYTES + 65536) -> dict[str, Any]:
    packet = _parse_bounded(raw, max_body_bytes, 'invalid_packet')
    validate_mail_packet(packet)
    return packet


def _suite() -> CipherSuite:
    # Construct per operation: PyHPKE context/KDF state is never shared by threads.
    return CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.CHACHA20_POLY1305)


def encrypt_mail(message: dict[str, Any], card: Envelope, signer: AgentSigner, nonce: int, *,
                 now_ms: int | None = None) -> Envelope:
    """Encrypt an immutable message, then sign it as a packet."""
    message, card, now = copy.deepcopy(message), copy.deepcopy(card), _now(now_ms)
    validate_mail_message(message)
    _require(message['from'] == signer.agent_id(), 'invalid_actor', 'message sender must match signer')
    validate_mailbox_card(card, message['to'], now_ms=now, for_sending=True)
    c = card['event']['payload']
    _require(message['created_at'] <= now + MAIL_FUTURE_SKEW_MS and now < message['expires_at'],
             'packet_expired', 'message is expired or future-dated')
    _require(message['expires_at'] <= c['receive_until'], 'invalid_packet', 'message exceeds receive_until')
    header = {'mailbox_id': c['mailbox_id'], 'card_hash': card['hash'], 'expires_at': message['expires_at']}
    event = create_event(MAIL_PROTOCOL, MAIL_SUBMIT, signer.agent_id(), now, nonce, {'header': header})
    plaintext = encode_mail_plaintext(message)
    estimated_event = {**event, 'payload': {'header': header, 'enc': 'A' * 43, 'ciphertext': ''}}
    bound = len(_jcs({'event': estimated_event, 'hash': 'A' * 43, 'signature': 'A' * 86})) + ((len(plaintext) + 16) * 8 + 5) // 6
    _require(bound <= min(c['max_packet_bytes'], MAIL_MAX_PACKET_BYTES), 'payload_too_large', 'packet would exceed limit')
    try:
        enc, context = _suite().create_sender_context(KEMKey.from_pyca_cryptography_key(_public_key(c['public_key'])), info=_INFO)
        try:
            ciphertext = context.seal(plaintext, mail_packet_aad(event))
        finally:
            del context
    except (PyHPKEError, ValueError) as exc:
        raise AgentProtocolError('invalid_packet', 'HPKE encryption failed') from exc
    event['payload'].update(enc=_b64(enc), ciphertext=_b64(ciphertext))
    packet = signer.sign_event(event)
    _require(len(_packet_bytes(packet)) <= c['max_packet_bytes'], 'payload_too_large', 'packet exceeds card limit')
    return packet


def decrypt_mail(packet: dict[str, Any], card: Envelope, key: MailEncryptionKey, owner: str, *,
                 now_ms: int | None = None, packet_id: str | None = None) -> dict[str, Any]:
    """Verify/decrypt a queued packet locally. New-acceptance expiry and dedup are MailInbox's job."""
    packet, card, now = copy.deepcopy(packet), copy.deepcopy(card), _now(now_ms)
    raw = _packet_bytes(packet, packet_id)
    validate_mailbox_card(card, owner)
    return _open_verified(packet, raw, card, key, owner, now)


def _open_verified(packet: dict[str, Any], raw: bytes, card: Envelope, key: MailEncryptionKey,
                   owner: str, now: int) -> dict[str, Any]:
    """Open with a card already verified for ``owner`` (MailKeyring verifies at ``add``)."""
    c, h = card['event']['payload'], packet['event']['payload']['header']
    _require(packet['event']['created_at'] <= now + MAIL_FUTURE_SKEW_MS, 'timestamp_out_of_window', 'packet is future-dated')
    _require(h['card_hash'] == card['hash'] and h['mailbox_id'] == c['mailbox_id'],
             'invalid_packet', 'packet/card binding mismatch')
    _require(len(raw) <= c['max_packet_bytes'], 'payload_too_large', 'packet exceeds card limit')
    _require(h['expires_at'] <= c['receive_until'], 'invalid_packet', 'packet exceeds key retention deadline')
    _require(isinstance(key, MailEncryptionKey) and key.public_key() == c['public_key'],
             'invalid_private_key', 'recipient secret does not match card')
    try:
        context = _suite().create_recipient_context(_decode(packet['event']['payload']['enc'], 32), KEMKey.from_pyca_cryptography_key(key._private_key), info=_INFO)
        try:
            plaintext = context.open(_decode(packet['event']['payload']['ciphertext']), mail_packet_aad(packet['event']))
        finally:
            del context
    except (PyHPKEError, ValueError) as exc:
        raise AgentProtocolError('invalid_packet', 'HPKE decryption failed') from exc
    message = decode_mail_plaintext(plaintext)
    e = packet['event']
    _require(message['from'] == e['actor'] and message['to'] == owner and message['expires_at'] == h['expires_at'],
             'invalid_packet', 'sender, recipient or expiration mismatch')
    _require(message['created_at'] <= min(now, e['created_at']) + MAIL_FUTURE_SKEW_MS,
             'timestamp_out_of_window', 'message timestamp too far in future')
    return message


def validate_mail_discovery(document: dict[str, Any], origin: str) -> None:
    """Informational discovery; it never supplies delivery paths."""
    validate_origin(origin)
    validate_mail_schema(document, 'discoveryDocument', 'invalid_response')
    _require(document['service'] == origin, 'invalid_response', 'discovery service origin mismatch')


def validate_mail_card_record(record: dict[str, Any], owner: str, mailbox_id: str | None = None,
                              card_hash: str | None = None) -> None:
    validate_mail_schema(record, 'cardAcceptedRecord', 'invalid_response')
    validate_mailbox_card(record['envelope'], owner)
    card = record['envelope']
    _require((mailbox_id is None or card['event']['payload']['mailbox_id'] == mailbox_id)
             and (card_hash is None or card['hash'] == card_hash), 'invalid_response', 'card record mismatch')


def validate_mail_delivery_result(result: dict[str, Any], packet: dict[str, Any] | None = None) -> None:
    validate_mail_schema(result, 'deliveryResult', 'invalid_response')
    if packet is not None:
        _require(result['packet_id'] == mail_packet_id(packet) and result['accepted_at'] < packet['event']['payload']['header']['expires_at'],
                 'invalid_response', 'delivery result mismatch')


def validate_mail_packet_record(record: dict[str, Any], mailbox_id: str | None = None) -> None:
    validate_mail_schema(record, 'packetRecord', 'invalid_response')
    validate_mail_packet(record['packet'], packet_id=record['packet_id'])
    _require(record['accepted_at'] < record['packet']['event']['payload']['header']['expires_at']
             and (mailbox_id is None or record['packet']['event']['payload']['header']['mailbox_id'] == mailbox_id),
             'invalid_response', 'packet record mismatch')


def validate_mail_packet_list(page: dict[str, Any], mailbox_id: str, *, limit: int = 100) -> None:
    validate_mail_schema(page, 'packetList', 'invalid_response')
    _require(len(page['result']) <= limit and ('next_cursor' not in page or bool(page['result'])),
             'invalid_response', 'invalid page size')
    seq = 0
    for record in page['result']:
        validate_mail_packet_record(record, mailbox_id)
        _require(record['seq'] > seq, 'invalid_response', 'unordered packets')
        seq = record['seq']


def verify_mail_owner_jwt(token: str, owner: str | None, origin: str, *, now_ms: int | None = None) -> dict[str, Any]:
    """Identity request JWT for this relay origin; with owner, also require iss == owner."""
    now = _now(now_ms)
    validate_origin(origin)
    try:
        _require(isinstance(token, str), 'invalid_token', 'invalid owner token')
        claims = verify_request_jwt(token, audience=origin, now_secs=now // 1000)
    except (AgentProtocolError, ValueError, KeyError, TypeError) as exc:
        raise AgentProtocolError('invalid_token', 'invalid owner request JWT') from exc
    if owner is not None:
        validate_agent_id(owner)
        _require(claims['iss'] == owner, 'permission_denied', 'requester is not mailbox owner')
    return claims


__all__ = [
    'MAIL_PROTOCOL', 'MAILBOX_PUBLISH', 'MAIL_SUBMIT', 'MAIL_MAX_TTL_MS',
    'MAIL_FUTURE_SKEW_MS', 'MAIL_MAX_PACKET_BYTES', 'MAIL_SCHEMA',
    'MailEncryptionKey', 'new_mail_id', 'parse_mail_address', 'format_mail_address',
    'mailbox_publish_event', 'create_mail_message', 'validate_mail_message', 'mail_packet_aad',
    'sign_mail_event', 'mail_part', 'decode_mail_part',
    'validate_mail_schema', 'validate_mail_id', 'validate_mail_envelope', 'parse_mail_envelope',
    'validate_mailbox_card', 'validate_mail_reply',
    'encode_mail_plaintext', 'decode_mail_plaintext', 'mail_packet_id', 'validate_mail_packet',
    'parse_mail_packet', 'encrypt_mail', 'decrypt_mail', 'validate_mail_discovery',
    'validate_mail_card_record', 'validate_mail_delivery_result', 'validate_mail_packet_record',
    'validate_mail_packet_list', 'verify_mail_owner_jwt',
]
