"""Synchronized in-memory Agent Mail components with explicit state snapshots.

These are SDK state machines, not a durable mail service. Snapshot data is local
trusted application state, never a peer-supplied wire format. Persist successful
mutations (including rejected observations that advance a card pin) atomically
before sending, acknowledging deletion, or exposing work. Protect keyring and
inbox/outbox snapshots as secrets. An injected nonce store must itself provide
atomic check-and-update and share the host service's other live-write protocols.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import secrets
import threading
from typing import Any, Callable

from .errors import AgentProtocolError
from .identity import MAX_SAFE_NONCE, Envelope, NonceStore, parse_strict_json, validate_agent_id, validate_origin
from .mail import (
    MAIL_FUTURE_SKEW_MS, MAIL_MAX_PACKET_BYTES, MAIL_MAX_TTL_MS, MAIL_MESSAGE, MAIL_RECEIPT,
    MailEncryptionKey, _b64, _decode, _fail, _jcs, _now, _require,
    decrypt_mail, encrypt_mail, mail_packet_id, parse_mail_packet, parse_mail_envelope,
    validate_mail_card_record, validate_mail_envelope, validate_mail_id,
    validate_mail_packet, validate_mail_packet_record, validate_mail_receipt,
    validate_mail_schema, validate_mailbox_card, verify_mail_owner_jwt,
)


def _binding(card: Envelope) -> tuple[str, str, str]:
    e = card['event']
    return e['actor'], e['payload']['mailbox_id'], e['payload']['key_id']


def _check_history(history: dict, card: Envelope) -> None:
    binding, public = _binding(card), card['event']['payload']['public_key']
    _require(binding not in history or history[binding] == public, 'mailbox_conflict', 'key ID reused for different key material')


def _snapshot_version(state: dict[str, Any]) -> None:
    _require(isinstance(state, dict) and state.get('version') == 1, 'invalid_request', 'unsupported local Mail state version')


class MailCardCache:
    """Permanent high-water marks; expiry is never permission to forget a pin.

    observe can update the pin and then raise for an expired/disabled card or
    equivocation. Persist snapshot() even after those observation failures.
    """
    def __init__(self):
        self._lock = threading.RLock()
        self._pins: dict[tuple[str, str], dict] = {}
        self._cards: dict[str, Envelope] = {}
        self._keys: dict[tuple[str, str, str], str] = {}

    def observe(self, card: Envelope, owner: str, *, now_ms: int | None = None,
                require_usable: bool = True) -> Envelope:
        card, now = copy.deepcopy(card), _now(now_ms)
        validate_mailbox_card(card, owner)
        _require(card['event']['created_at'] <= now + MAIL_FUTURE_SKEW_MS, 'invalid_event', 'card too far in future')
        with self._lock:
            self._observe(card)
            if require_usable:
                return self.get(owner, card['event']['payload']['mailbox_id'], now_ms=now)
            return copy.deepcopy(card)

    def _observe(self, card: Envelope) -> None:
        _check_history(self._keys, card)
        e = card['event']
        binding = (e['actor'], e['payload']['mailbox_id'])
        previous = self._pins.get(binding)
        self._keys[_binding(card)] = e['payload']['public_key']
        self._cards[card['hash']] = card
        if previous is not None and e['nonce'] < previous['nonce']:
            _fail('stale_card', 'card rollback below durable high-water mark')
        if previous is None or e['nonce'] > previous['nonce']:
            self._pins[binding] = {'nonce': e['nonce'], 'hash': card['hash'], 'equivocation': False}
        elif previous['hash'] != card['hash']:
            previous['equivocation'] = True
        if self._pins[binding]['equivocation']:
            _fail('mailbox_conflict', 'card equivocation requires a higher nonce')

    def get(self, owner: str, mailbox_id: str, *, now_ms: int | None = None) -> Envelope:
        with self._lock:
            pin = self._pins.get((owner, mailbox_id))
            _require(pin is not None, 'mailbox_unavailable', 'no pinned mailbox card')
            _require(not pin['equivocation'], 'mailbox_conflict', 'mailbox card equivocation')
            card = self._cards[pin['hash']]
            validate_mailbox_card(card, owner, now_ms=now_ms, for_sending=True)
            return copy.deepcopy(card)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {'version': 1, 'cards': copy.deepcopy(list(self._cards.values()))}

    @classmethod
    def from_snapshot(cls, state: dict[str, Any]) -> 'MailCardCache':
        state = copy.deepcopy(state)
        _snapshot_version(state)
        obj = cls()
        # All history is retained: rebuilding also restores sticky equivocation.
        for card in sorted(state['cards'], key=lambda item: item['event']['nonce']):
            validate_mailbox_card(card, card['event']['actor'])
            _check_history(obj._keys, card)
            try:
                obj._observe(card)
            except AgentProtocolError as exc:
                if exc.code != 'mailbox_conflict' or not obj._pins.get((card['event']['actor'], card['event']['payload']['mailbox_id']), {}).get('equivocation'):
                    raise
        return obj


class MailKeyring:
    """Retain verified historical cards and independent secrets through receive_until."""
    def __init__(self, owner: str):
        validate_agent_id(owner)
        self.owner = owner
        self._lock = threading.RLock()
        self._cards: dict[str, Envelope] = {}
        self._secrets: dict[tuple[str, str, str], MailEncryptionKey] = {}
        self._keys: dict[tuple[str, str, str], str] = {}

    def add(self, card: Envelope, key: MailEncryptionKey) -> None:
        card = copy.deepcopy(card)
        validate_mailbox_card(card, self.owner)
        _require(isinstance(key, MailEncryptionKey) and key.public_key() == card['event']['payload']['public_key'], 'invalid_event', 'key does not match mailbox card')
        with self._lock:
            _check_history(self._keys, card)
            self._keys[_binding(card)] = key.public_key()
            self._secrets[_binding(card)] = key
            self._cards[card['hash']] = card

    def decrypt(self, packet: dict[str, Any], *, now_ms: int | None = None,
                packet_id: str | None = None, allow_expired: bool = False) -> Envelope:
        packet = copy.deepcopy(packet)
        validate_mail_packet(packet, packet_id=packet_id)
        with self._lock:
            card = self._cards.get(packet['header']['card_hash'])
            _require(card is not None, 'invalid_packet', 'unknown retained mailbox card')
            return decrypt_mail(packet, card, self._secrets[_binding(card)], self.owner,
                                now_ms=now_ms, packet_id=packet_id, allow_expired=allow_expired)

    def prune(self, *, now_ms: int | None = None) -> int:
        now = _now(now_ms)
        with self._lock:
            expired = [h for h, c in self._cards.items() if c['event']['payload']['receive_until'] <= now]
            for h in expired:
                del self._cards[h]
            used = {_binding(c) for c in self._cards.values()}
            for key in list(self._secrets):
                if key not in used:
                    del self._secrets[key]
            # Public key-ID history survives secret/card pruning.
            return len(expired)

    def snapshot(self) -> dict[str, Any]:
        """Contains private keys in clear; encrypt/protect at the persistence boundary."""
        with self._lock:
            return {'version': 1, 'owner': self.owner,
                    'entries': [{'card': copy.deepcopy(card), 'secret': _b64(self._secrets[_binding(card)].private_bytes())} for card in self._cards.values()],
                    'key_history': [[*binding, public] for binding, public in self._keys.items()]}

    @classmethod
    def from_snapshot(cls, state: dict[str, Any]) -> 'MailKeyring':
        state = copy.deepcopy(state)
        _snapshot_version(state)
        obj = cls(state['owner'])
        for owner, mailbox, key_id, public in state['key_history']:
            _require(owner == obj.owner, 'invalid_request', 'key history owner mismatch')
            validate_mail_id(mailbox, size=16)
            validate_mail_id(key_id, size=16)
            _decode(public, 32)
            binding = (owner, mailbox, key_id)
            _require(binding not in obj._keys or obj._keys[binding] == public, 'mailbox_conflict', 'inconsistent key history')
            obj._keys[binding] = public
        for entry in state['entries']:
            obj.add(entry['card'], MailEncryptionKey.from_private_bytes(_decode(entry['secret'], 32)))
        return obj


class MailInbox:
    """Atomic in-process acceptance, without automatic receipts or tool execution."""
    def __init__(self, keyring: MailKeyring, outbox: MailOutbox | None = None):
        self.keyring = keyring
        self.outbox = outbox
        _require(outbox is None or outbox.owner == keyring.owner, 'invalid_request', 'inbox/outbox owner mismatch')
        self._lock = threading.RLock()
        self._accepted: dict[str, dict[str, Any]] = {}

    def accept(self, packet: dict[str, Any], *, now_ms: int | None = None,
               packet_id: str | None = None,
               policy: Callable[[Envelope], bool] | None = None) -> dict[str, Any]:
        now = _now(now_ms)
        letter = self.keyring.decrypt(packet, now_ms=now, packet_id=packet_id, allow_expired=True)
        self._validate_receipt(letter)
        with self._lock:
            previous = self._accepted.get(letter['hash'])
            if previous is not None:
                return {'kind': 'duplicate', **copy.deepcopy(previous)}
            _require(now < letter['event']['payload']['expires_at'], 'packet_expired', 'expired letter cannot be newly accepted')
            if policy is not None:
                _require(policy(copy.deepcopy(letter)) is True, 'permission_denied', 'local correspondence policy rejected letter')
            record = {'letter': copy.deepcopy(letter), 'accepted_at': now}
            self._accepted[letter['hash']] = record
            return {'kind': 'accepted', **copy.deepcopy(record)}

    def _validate_receipt(self, letter: Envelope) -> None:
        if letter['event']['type'] == MAIL_RECEIPT:
            _require(self.outbox is not None, 'invalid_event', 'receipt requires a sent-message outbox')
            self.outbox.verify_receipt(letter)

    def letter(self, letter_id: str) -> Envelope | None:
        with self._lock:
            record = self._accepted.get(letter_id)
            return copy.deepcopy(record['letter']) if record else None

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {'version': 1, 'owner': self.keyring.owner, 'accepted': copy.deepcopy(list(self._accepted.values()))}

    @classmethod
    def from_snapshot(cls, keyring: MailKeyring, state: dict[str, Any], outbox: MailOutbox | None = None) -> 'MailInbox':
        state = copy.deepcopy(state)
        _snapshot_version(state)
        _require(state['owner'] == keyring.owner, 'invalid_request', 'inbox owner mismatch')
        obj = cls(keyring, outbox)
        for record in state['accepted']:
            letter = record['letter']
            validate_mail_schema(letter, 'letterEnvelope')
            validate_mail_envelope(letter)
            obj._validate_receipt(letter)
            _now(record['accepted_at'])
            _require(letter['event']['payload']['to'] == keyring.owner and record['accepted_at'] < letter['event']['payload']['expires_at'],
                     'invalid_request', 'invalid accepted inbox state')
            obj._accepted[letter['hash']] = record
        return obj


class MailOutbox:
    """Retain original signed letters and attempted-send status for receipt binding."""
    def __init__(self, owner: str):
        validate_agent_id(owner)
        self.owner = owner
        self._lock = threading.RLock()
        self._letters: dict[str, Envelope] = {}
        self._sent: set[str] = set()

    def retain(self, letter: Envelope) -> str:
        letter = copy.deepcopy(letter)
        validate_mail_schema(letter, 'letterEnvelope')
        validate_mail_envelope(letter)
        _require(letter['event']['actor'] == self.owner, 'invalid_actor', 'outbox actor mismatch')
        with self._lock:
            self._letters[letter['hash']] = letter
        return letter['hash']

    def mark_sent(self, letter_id: str) -> None:
        """Record an actual delivery attempt, including ambiguous network outcomes."""
        with self._lock:
            _require(letter_id in self._letters, 'not_found', 'unknown outgoing letter')
            self._sent.add(letter_id)

    def letter(self, letter_id: str) -> Envelope:
        with self._lock:
            _require(letter_id in self._letters, 'not_found', 'unknown outgoing letter')
            return copy.deepcopy(self._letters[letter_id])

    def verify_receipt(self, receipt: Envelope) -> None:
        validate_mail_schema(receipt, 'receiptEnvelope')
        with self._lock:
            message_id = receipt['event']['payload']['message_hash']
            _require(message_id in self._sent, 'invalid_event', 'receipt refers to a letter not sent by this outbox')
            validate_mail_receipt(receipt, self._letters[message_id])

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {'version': 1, 'owner': self.owner, 'letters': copy.deepcopy(list(self._letters.values())), 'sent': sorted(self._sent)}

    @classmethod
    def from_snapshot(cls, state: dict[str, Any]) -> 'MailOutbox':
        state = copy.deepcopy(state)
        _snapshot_version(state)
        obj = cls(state['owner'])
        for letter in state['letters']:
            obj.retain(letter)
        for letter_id in state['sent']:
            obj.mark_sent(letter_id)
        return obj


class MailSender:
    """Compose permanent card pins, original-letter retention and encryption."""
    def __init__(self, cache: MailCardCache, outbox: MailOutbox):
        self.cache, self.outbox = cache, outbox

    def prepare(self, letter: Envelope, card: Envelope, *, now_ms: int | None = None) -> dict[str, Any]:
        letter = copy.deepcopy(letter)
        validate_mail_schema(letter, 'letterEnvelope')
        validate_mail_envelope(letter)
        _require(letter['event']['actor'] == self.outbox.owner, 'invalid_actor', 'sender/outbox identity mismatch')
        pinned = self.cache.observe(card, letter['event']['payload']['to'], now_ms=now_ms)
        packet = encrypt_mail(letter, pinned, now_ms=now_ms)
        self.outbox.retain(letter)
        return packet

    def retry(self, letter_id: str, card: Envelope, *, now_ms: int | None = None) -> dict[str, Any]:
        return self.prepare(self.outbox.letter(letter_id), card, now_ms=now_ms)


class MailNonceStore:
    """Thread-safe Identity NonceStore, shareable across service components."""
    def __init__(self):
        self._lock = threading.RLock()
        self._records: dict[str, tuple[int, int]] = {}

    def max_nonce(self, actor: str, now_ms: int) -> int | None:
        with self._lock:
            record = self._records.get(actor)
            return record[0] if record and record[1] > now_ms else None

    def check_and_update(self, actor: str, nonce: int, now_ms: int, ttl_ms: int) -> int:
        _require(type(nonce) is int and 1 <= nonce <= MAX_SAFE_NONCE, 'invalid_event', 'invalid nonce')
        _require(type(ttl_ms) is int and ttl_ms >= 0, 'invalid_request', 'invalid nonce TTL')
        with self._lock:
            previous = self.max_nonce(actor, now_ms)
            if previous is not None and nonce <= previous:
                raise AgentProtocolError('nonce_not_greater', 'nonce must exceed service-wide maximum', {'max_nonce': previous})
            self._records[actor] = (nonce, now_ms + ttl_ms)
            return nonce

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {'version': 1, 'records': [[actor, nonce, until] for actor, (nonce, until) in self._records.items()]}

    @classmethod
    def from_snapshot(cls, state: dict[str, Any]) -> 'MailNonceStore':
        _snapshot_version(state)
        obj = cls()
        for actor, nonce, until in state['records']:
            validate_agent_id(actor)
            _require(type(nonce) is int and 1 <= nonce <= MAX_SAFE_NONCE and type(until) is int and until >= 0,
                     'invalid_request', 'invalid nonce state')
            obj._records[actor] = (nonce, until)
        return obj


class MailRelayStore:
    """Opaque synchronized relay state; application hosting must add durability.

    All checks and allocation occur under one lock. An injected nonce store must
    be atomic and separately persisted with the host service; the default store
    is included in snapshots. Admission limits are local operator policy.
    """
    def __init__(self, origin: str, *, nonce_store: NonceStore | None = None,
                 max_packets_per_mailbox: int = 10000, max_storage_bytes: int = 64 * 1024 * 1024,
                 max_body_bytes: int = MAIL_MAX_PACKET_BYTES + 65536):
        validate_origin(origin)
        _require(type(max_packets_per_mailbox) is int and max_packets_per_mailbox > 0
                 and type(max_storage_bytes) is int and max_storage_bytes > 0
                 and type(max_body_bytes) is int and max_body_bytes >= MAIL_MAX_PACKET_BYTES,
                 'invalid_request', 'invalid relay limits')
        self.origin = origin
        self.max_packets_per_mailbox, self.max_storage_bytes = max_packets_per_mailbox, max_storage_bytes
        self.max_body_bytes = max_body_bytes
        self._lock = threading.RLock()
        self._owns_nonces = nonce_store is None
        self.nonce_store = MailNonceStore() if nonce_store is None else nonce_store
        self._current: dict[str, str] = {}
        self._cards: dict[str, dict[str, Any]] = {}
        self._keys: dict[tuple[str, str, str], str] = {}
        self._seq: dict[str, int] = {}
        self._packets: dict[str, dict[str, dict[str, Any]]] = {}
        self._history: dict[str, dict[str, dict[str, Any]]] = {}
        self._cursor_secret = secrets.token_bytes(32)

    def publish(self, card: Envelope | str | bytes, *, now_ms: int | None = None) -> dict[str, Any]:
        card = parse_mail_envelope(card, max_bytes=self.max_body_bytes) if isinstance(card, (str, bytes)) else copy.deepcopy(card)
        now = _now(now_ms)
        validate_mail_schema(card, 'mailboxCardEnvelope')
        validate_mail_envelope(card)
        _require(len(_jcs(card)) <= self.max_body_bytes, 'payload_too_large', 'card exceeds raw-body policy')
        e, p = card['event'], card['event']['payload']
        _require(self.origin in p['routes'], 'invalid_event', 'relay origin absent from card routes')
        with self._lock:
            if card['hash'] in self._cards:
                return copy.deepcopy(self._cards[card['hash']])
            _require(abs(e['created_at'] - now) <= MAIL_FUTURE_SKEW_MS, 'timestamp_out_of_window', 'control write outside live window')
            mailbox = p['mailbox_id']
            current = self._cards.get(self._current.get(mailbox, ''))
            if current:
                previous = current['envelope']['event']
                _require(previous['actor'] == e['actor'], 'mailbox_conflict', 'mailbox owner binding is permanent')
                if e['nonce'] <= previous['nonce']:
                    raise AgentProtocolError('nonce_not_greater', 'nonce must exceed durable mailbox high-water mark', {'max_nonce': int(previous['nonce'])})
            _check_history(self._keys, card)
            # Last potentially rejecting mutation; commits no nonce on failed admission.
            self.nonce_store.check_and_update(e['actor'], int(e['nonce']), now, 2 * MAIL_FUTURE_SKEW_MS)
            record = {'envelope': card, 'accepted_at': now}
            self._cards[card['hash']] = record
            self._current[mailbox] = card['hash']
            self._keys[_binding(card)] = p['public_key']
            self._seq.setdefault(mailbox, 0)
            self._packets.setdefault(mailbox, {})
            self._history.setdefault(mailbox, {})
            return copy.deepcopy(record)

    def card(self, mailbox_id: str) -> dict[str, Any]:
        validate_mail_id(mailbox_id, size=16)
        with self._lock:
            _require(mailbox_id in self._current, 'mailbox_unavailable', 'unknown mailbox')
            return copy.deepcopy(self._cards[self._current[mailbox_id]])

    def deliver(self, mailbox_id: str, packet: dict[str, Any] | str | bytes, *, now_ms: int | None = None) -> dict[str, Any]:
        now = _now(now_ms)
        validate_mail_id(mailbox_id, size=16)
        packet = parse_mail_packet(packet, max_body_bytes=self.max_body_bytes) if isinstance(packet, (str, bytes)) else copy.deepcopy(packet)
        validate_mail_packet(packet)
        h = packet['header']
        _require(h['mailbox_id'] == mailbox_id, 'invalid_packet', 'path/header mailbox mismatch')
        pid = mail_packet_id(packet)
        with self._lock:
            previous = self._history.get(mailbox_id, {}).get(pid)
            if previous is not None:
                return copy.deepcopy(previous['result'])
            _require(mailbox_id in self._current, 'mailbox_unavailable', 'unknown mailbox')
            card = self._cards[self._current[mailbox_id]]['envelope']
            c = card['event']['payload']
            _require(c['enabled'], 'mailbox_unavailable', 'mailbox disabled')
            _require(card['hash'] == h['card_hash'] and c['key_id'] == h['key_id'] and now < c['expires_at'],
                     'stale_card', 'packet needs the current enabled unexpired card')
            _require(now < h['expires_at'], 'packet_expired', 'packet expired')
            _require(h['expires_at'] <= min(c['receive_until'], now + MAIL_MAX_TTL_MS + MAIL_FUTURE_SKEW_MS),
                     'invalid_packet', 'packet exceeds accepted lifetime')
            validate_mail_packet(packet, max_bytes=c['max_packet_bytes'])
            self._prune(now)
            stored = self._packets[mailbox_id]
            total = sum(len(_jcs(record['packet'])) for box in self._packets.values() for record in box.values())
            _require(len(stored) < self.max_packets_per_mailbox and total + len(_jcs(packet)) <= self.max_storage_bytes,
                     'quota_exceeded', 'relay cannot retain another packet')
            _require(self._seq[mailbox_id] < MAX_SAFE_NONCE, 'quota_exceeded', 'mailbox sequence exhausted')
            seq = self._seq[mailbox_id] + 1
            result = {'packet_id': pid, 'accepted_at': now, 'seq': seq}
            self._seq[mailbox_id] = seq
            self._history[mailbox_id][pid] = {'result': result, 'expires_at': h['expires_at']}
            stored[pid] = {**result, 'packet': packet}
            return copy.deepcopy(result)

    def _owner(self, mailbox_id: str, token: str, now: int) -> str:
        # Authenticate before revealing whether a mailbox or packet exists.
        claims = verify_mail_owner_jwt(token, None, self.origin, now_ms=now)
        current = self._cards.get(self._current.get(mailbox_id, ''))
        _require(current is not None and claims['iss'] == current['envelope']['event']['actor'],
                 'permission_denied', 'requester is not mailbox owner')
        return claims['iss']

    def _cursor(self, data: dict[str, Any]) -> str:
        raw = _jcs(data)
        return _b64(raw) + '.' + _b64(hmac.digest(self._cursor_secret, raw, 'sha256'))

    def _read_cursor(self, cursor: str, owner: str, mailbox: str) -> tuple[int, int]:
        try:
            _require(isinstance(cursor, str) and len(cursor) <= 4096, 'invalid_cursor', 'invalid cursor')
            encoded, mac = cursor.split('.')
            raw = _decode(encoded, code='invalid_cursor')
            _require(hmac.compare_digest(hmac.digest(self._cursor_secret, raw, 'sha256'), _decode(mac, 32, 'invalid_cursor')),
                     'invalid_cursor', 'cursor authentication failed')
            data = parse_strict_json(raw.decode('utf-8'))
            _require(set(data) == {'owner', 'mailbox', 'after', 'through'} and data['owner'] == owner and data['mailbox'] == mailbox,
                     'invalid_cursor', 'cursor scope mismatch')
            after, through = data['after'], data['through']
            _require(type(after) is int and type(through) is int and 0 <= after <= through <= self._seq[mailbox],
                     'invalid_cursor', 'cursor position mismatch')
            return after, through
        except (ValueError, TypeError, KeyError, UnicodeError, AgentProtocolError) as exc:
            raise AgentProtocolError('invalid_cursor', 'invalid mailbox cursor') from exc

    def list_packets(self, mailbox_id: str, token: str, *, limit: int = 100,
                     cursor: str | None = None, now_ms: int | None = None) -> dict[str, Any]:
        now = _now(now_ms)
        validate_mail_id(mailbox_id, size=16)
        _require(type(limit) is int and 1 <= limit <= 1000, 'invalid_request', 'limit must be 1..1000')
        with self._lock:
            owner = self._owner(mailbox_id, token, now)
            after, through = self._read_cursor(cursor, owner, mailbox_id) if cursor is not None else (0, self._seq[mailbox_id])
            candidates = sorted((r for r in self._packets[mailbox_id].values() if after < r['seq'] <= through
                                 and now < r['packet']['header']['expires_at']), key=lambda r: r['seq'])
            records = candidates[:limit]
            page = {'result': copy.deepcopy(records)}
            if len(candidates) > limit:
                page['next_cursor'] = self._cursor({'owner': owner, 'mailbox': mailbox_id, 'after': records[-1]['seq'], 'through': through})
            return page

    def delete(self, mailbox_id: str, packet_id: str, token: str, *, now_ms: int | None = None) -> None:
        now = _now(now_ms)
        validate_mail_id(mailbox_id, size=16)
        validate_mail_id(packet_id)
        with self._lock:
            self._owner(mailbox_id, token, now)
            self._packets[mailbox_id].pop(packet_id, None)

    def _prune(self, now: int) -> None:
        for mailbox, records in self._packets.items():
            for pid in list(records):
                if records[pid]['packet']['header']['expires_at'] <= now:
                    del records[pid]
            for pid in list(self._history[mailbox]):
                if self._history[mailbox][pid]['expires_at'] <= now:
                    del self._history[mailbox][pid]

    def prune(self, *, now_ms: int | None = None) -> None:
        with self._lock:
            self._prune(_now(now_ms))

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {'version': 1, 'origin': self.origin,
                    'limits': {'max_packets_per_mailbox': self.max_packets_per_mailbox, 'max_storage_bytes': self.max_storage_bytes, 'max_body_bytes': self.max_body_bytes},
                    'current': copy.deepcopy(self._current), 'cards': copy.deepcopy(self._cards),
                    'seq': copy.deepcopy(self._seq), 'packets': copy.deepcopy(self._packets), 'history': copy.deepcopy(self._history),
                    'cursor_secret': _b64(self._cursor_secret),
                    'nonces': self.nonce_store.snapshot() if self._owns_nonces else None}

    @classmethod
    def from_snapshot(cls, state: dict[str, Any], *, nonce_store: NonceStore | None = None) -> 'MailRelayStore':
        state = copy.deepcopy(state)
        _snapshot_version(state)
        _require(state['nonces'] is not None or nonce_store is not None, 'invalid_request', 'restore the externally shared nonce store')
        obj = cls(state['origin'], nonce_store=nonce_store, **state['limits'])
        if nonce_store is None:
            obj.nonce_store = MailNonceStore.from_snapshot(state['nonces'])
        for card_hash, record in state['cards'].items():
            card = record['envelope']
            validate_mail_card_record(record, card['event']['actor'])
            _require(card_hash == card['hash'] and obj.origin in card['event']['payload']['routes'], 'invalid_request', 'invalid retained relay card')
            _check_history(obj._keys, card)
            obj._keys[_binding(card)] = card['event']['payload']['public_key']
        for mailbox, card_hash in state['current'].items():
            card = state['cards'][card_hash]['envelope']
            validate_mail_id(mailbox, size=16)
            _require(card['event']['payload']['mailbox_id'] == mailbox, 'invalid_request', 'current mailbox mismatch')
            histories = [r['envelope'] for r in state['cards'].values() if r['envelope']['event']['payload']['mailbox_id'] == mailbox]
            _require(all(c['event']['actor'] == card['event']['actor'] and c['event']['nonce'] <= card['event']['nonce'] for c in histories),
                     'invalid_request', 'inconsistent mailbox ownership/high-water mark')
            seq = state['seq'][mailbox]
            _require(type(seq) is int and 0 <= seq <= MAX_SAFE_NONCE, 'invalid_request', 'invalid sequence state')
            seen_seq = set()
            for pid, history in state['history'][mailbox].items():
                result = history['result']
                validate_mail_schema(result, 'deliveryResult')
                _require(result['packet_id'] == pid and result['seq'] <= seq and result['seq'] not in seen_seq,
                         'invalid_request', 'inconsistent packet history')
                _require(result['accepted_at'] < history['expires_at'], 'invalid_request', 'invalid tombstone lifetime')
                seen_seq.add(result['seq'])
            for pid, record in state['packets'][mailbox].items():
                validate_mail_packet_record(record, mailbox)
                expected = state['history'][mailbox][pid]
                _require({k: record[k] for k in ('packet_id', 'accepted_at', 'seq')} == expected['result']
                         and record['packet']['header']['expires_at'] == expected['expires_at'],
                         'invalid_request', 'packet/history mismatch')
        obj._current, obj._cards, obj._seq = state['current'], state['cards'], state['seq']
        obj._packets, obj._history = state['packets'], state['history']
        obj._cursor_secret = _decode(state['cursor_secret'], 32)
        return obj


__all__ = ['MailCardCache', 'MailKeyring', 'MailInbox', 'MailOutbox', 'MailSender', 'MailNonceStore', 'MailRelayStore']
