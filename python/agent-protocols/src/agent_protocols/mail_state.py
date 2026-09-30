"""Synchronized in-memory Agent Mail state with explicit snapshots.

These are SDK state machines, not a durable mail service. Snapshots are trusted
local application state, never a peer-supplied wire format, so restoring them
checks only their version and shape. Persist successful mutations (including an
observation that advanced a card pin and then raised) atomically before sending,
acknowledging deletion, or acting. Protect keyring snapshots as secrets.
"""
from __future__ import annotations

import copy
import re
import threading
from typing import Any

from .errors import AgentProtocolError
from .identity import MAX_SAFE_NONCE, Envelope, MemoryNonceStore, NonceStore, validate_agent_id, validate_origin
from .mail import (
    MAIL_FUTURE_SKEW_MS, MAIL_MAX_PACKET_BYTES, MAIL_MAX_TTL_MS,
    MailEncryptionKey, _b64, _decode, _hash, _jcs, _now, _open_verified, _packet_bytes, _parse_bounded, _require,
    encrypt_mail, validate_mail_envelope, validate_mail_id, validate_mail_schema, validate_mailbox_card,
    verify_mail_owner_jwt,
)


def _snapshot_version(state: dict[str, Any]) -> None:
    _require(isinstance(state, dict) and state.get('version') == 1, 'invalid_request', 'unsupported local Mail state version')


class MailCardCache:
    """Sender-side pins: the greatest-nonce card seen per (owner, mailbox), including closed
    or expired cards. A pin may be pruned once every earlier card has expired."""
    def __init__(self):
        self._lock = threading.RLock()
        self._pins: dict[tuple[str, str], Envelope] = {}

    def observe(self, card: Envelope, owner: str, *, now_ms: int | None = None,
                require_usable: bool = True) -> Envelope:
        card, now = copy.deepcopy(card), _now(now_ms)
        validate_mailbox_card(card, owner)
        _require(card['event']['created_at'] <= now + MAIL_FUTURE_SKEW_MS, 'timestamp_out_of_window', 'card is future-dated')
        key = (owner, card['event']['payload']['mailbox_id'])
        with self._lock:
            pin = self._pins.get(key)
            if pin is not None and pin['hash'] != card['hash']:
                _require(card['event']['nonce'] > pin['event']['nonce'], 'stale_card',
                         'card is older than or conflicts with the pinned card')
            self._pins[key] = card
        if require_usable:
            validate_mailbox_card(card, owner, now_ms=now, for_sending=True)
        return copy.deepcopy(card)

    def prune(self, *, now_ms: int | None = None) -> None:
        now = _now(now_ms)
        with self._lock:
            for key, pin in list(self._pins.items()):
                if now >= pin['event']['created_at'] + MAIL_MAX_TTL_MS + MAIL_FUTURE_SKEW_MS:
                    del self._pins[key]

    def seal(self, letter: Envelope, card: Envelope, *, now_ms: int | None = None) -> dict[str, Any]:
        """Pin the card, then encrypt the original signed letter under it."""
        now = _now(now_ms)
        return encrypt_mail(letter, self.observe(card, letter['event']['payload']['to'], now_ms=now), now_ms=now)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {'version': 1, 'pins': copy.deepcopy(list(self._pins.values()))}

    @classmethod
    def from_snapshot(cls, state: dict[str, Any]) -> 'MailCardCache':
        _snapshot_version(state)
        obj = cls()
        for card in state['pins']:
            validate_mail_schema(card, 'mailboxCardEnvelope')
            obj._pins[(card['event']['actor'], card['event']['payload']['mailbox_id'])] = copy.deepcopy(card)
        return obj


class MailKeyring:
    """Retained verified cards and their independent secrets, by card hash, through receive_until."""
    def __init__(self, owner: str):
        validate_agent_id(owner)
        self.owner = owner
        self._lock = threading.RLock()
        self._entries: dict[str, tuple[Envelope, MailEncryptionKey]] = {}

    def add(self, card: Envelope, key: MailEncryptionKey) -> None:
        card = copy.deepcopy(card)
        validate_mailbox_card(card, self.owner)
        _require(isinstance(key, MailEncryptionKey) and key.public_key() == card['event']['payload']['public_key'],
                 'invalid_private_key', 'key does not match mailbox card')
        with self._lock:
            self._entries[card['hash']] = (card, key)

    def open(self, packet: dict[str, Any], *, now_ms: int | None = None, packet_id: str | None = None) -> Envelope:
        """Verify and decrypt with the retained card the packet names; cards were verified at ``add``."""
        packet, now = copy.deepcopy(packet), _now(now_ms)
        raw = _packet_bytes(packet, packet_id)
        with self._lock:
            entry = self._entries.get(packet['header']['card_hash'])
        _require(entry is not None, 'invalid_packet', 'unknown retained mailbox card')
        return _open_verified(packet, raw, entry[0], entry[1], self.owner, now)

    def prune(self, *, now_ms: int | None = None) -> int:
        now = _now(now_ms)
        with self._lock:
            expired = [h for h, (card, _) in self._entries.items() if now >= card['event']['payload']['receive_until']]
            for h in expired:
                del self._entries[h]
            return len(expired)

    def snapshot(self) -> dict[str, Any]:
        """Contains private keys in clear; encrypt/protect at the persistence boundary."""
        with self._lock:
            return {'version': 1, 'owner': self.owner,
                    'entries': [{'card': copy.deepcopy(card), 'secret': _b64(key.private_bytes())}
                                for card, key in self._entries.values()]}

    @classmethod
    def from_snapshot(cls, state: dict[str, Any]) -> 'MailKeyring':
        _snapshot_version(state)
        obj = cls(state['owner'])
        for entry in state['entries']:
            obj.add(entry['card'], MailEncryptionKey.from_private_bytes(_decode(entry['secret'], 32)))
        return obj


class MailInbox:
    """Atomic cross-route deduplication by letter ID. The application stores accepted letters;
    persist this state with them before deleting relay copies or acting. No automatic replies."""
    def __init__(self, keyring: MailKeyring):
        self.keyring = keyring
        self._lock = threading.RLock()
        self._accepted: dict[str, int] = {}

    def accept(self, packet: dict[str, Any], *, now_ms: int | None = None,
               packet_id: str | None = None) -> dict[str, Any]:
        now = _now(now_ms)
        letter = self.keyring.open(packet, now_ms=now, packet_id=packet_id)
        with self._lock:
            if letter['hash'] in self._accepted:
                return {'kind': 'duplicate', 'letter': letter}
            expires = letter['event']['payload']['expires_at']
            _require(now < expires, 'packet_expired', 'expired letter cannot be newly accepted')
            self._accepted[letter['hash']] = expires
            return {'kind': 'accepted', 'letter': letter}

    def has(self, letter_id: str) -> bool:
        with self._lock:
            return letter_id in self._accepted

    def prune(self, *, now_ms: int | None = None) -> None:
        """Forget letters whose signed expiration passed; they can no longer be newly accepted."""
        now = _now(now_ms)
        with self._lock:
            for letter_id, expires in list(self._accepted.items()):
                if now >= expires:
                    del self._accepted[letter_id]

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {'version': 1, 'owner': self.keyring.owner, 'accepted': [[k, v] for k, v in self._accepted.items()]}

    @classmethod
    def from_snapshot(cls, keyring: MailKeyring, state: dict[str, Any]) -> 'MailInbox':
        _snapshot_version(state)
        _require(state['owner'] == keyring.owner, 'invalid_request', 'inbox owner mismatch')
        obj = cls(keyring)
        obj._accepted = {letter_id: expires for letter_id, expires in state['accepted']}
        return obj


class _Mailbox:
    def __init__(self, current: dict[str, Any], last_seq: int = 0):
        self.current = current
        self.last_seq = last_seq
        self.bytes = 0
        self.packets: dict[str, tuple[dict[str, Any], int]] = {}
        self.tombstones: dict[str, dict[str, int]] = {}

    def drop_expired(self, now: int) -> None:
        for pid, (record, size) in list(self.packets.items()):
            if now >= record['packet']['header']['expires_at']:
                del self.packets[pid]
                self.bytes -= size


_CURSOR = re.compile(r'(?:0|[1-9][0-9]{0,15})')  # A decimal safe integer has at most 16 digits.


class MailRelayStore:
    """Synchronized in-memory relay model; application hosting must add durability.

    All checks precede mutation under one lock. The injected Identity nonce store is
    the service-wide live-write cache; it is short-lived and not part of the snapshot.
    Packet limits apply per mailbox.
    """
    def __init__(self, origin: str, *, nonce_store: NonceStore | None = None,
                 max_packets: int = 10000, max_bytes: int = 64 * MAIL_MAX_PACKET_BYTES,
                 max_body_bytes: int = MAIL_MAX_PACKET_BYTES + 65536):
        validate_origin(origin)
        _require(type(max_packets) is int and max_packets > 0 and type(max_bytes) is int and max_bytes > 0
                 and type(max_body_bytes) is int and max_body_bytes >= MAIL_MAX_PACKET_BYTES,
                 'invalid_request', 'invalid relay limits')
        self.origin = origin
        self.max_packets, self.max_bytes, self.max_body_bytes = max_packets, max_bytes, max_body_bytes
        self.nonce_store = nonce_store if nonce_store is not None else MemoryNonceStore()
        self._lock = threading.RLock()
        self._boxes: dict[str, _Mailbox] = {}

    def discovery(self) -> dict[str, Any]:
        return {'protocol': 'agent-mail/1.0', 'service': self.origin}

    def publish(self, card: Envelope | str | bytes, *, now_ms: int | None = None) -> dict[str, Any]:
        card = _parse_bounded(card, self.max_body_bytes, 'invalid_event') if isinstance(card, (str, bytes)) else copy.deepcopy(card)
        now = _now(now_ms)
        validate_mail_envelope(card, 'mailboxCardEnvelope')
        e, p = card['event'], card['event']['payload']
        with self._lock:
            box = self._boxes.get(p['mailbox_id'])
            if box is not None:
                current = box.current['envelope']
                _require(current['event']['actor'] == e['actor'], 'mailbox_conflict', 'mailbox belongs to another owner')
                if current['hash'] == card['hash']:
                    return copy.deepcopy(box.current)
                if e['nonce'] <= current['event']['nonce']:
                    raise AgentProtocolError('nonce_not_greater', 'card nonce does not advance',
                                             {'max_nonce': current['event']['nonce']})
            else:
                _require(self.origin in p['routes'], 'permission_denied', 'first card must list this relay')
            _require(abs(e['created_at'] - now) <= MAIL_FUTURE_SKEW_MS, 'timestamp_out_of_window', 'control write outside live window')
            # The final fallible step, so a rejected card consumes no nonce.
            self.nonce_store.check_and_update(e['actor'], e['nonce'], now, 2 * MAIL_FUTURE_SKEW_MS)
            record = {'envelope': card, 'accepted_at': now}
            if box is None:
                self._boxes[p['mailbox_id']] = _Mailbox(record)
            else:
                box.current = record
            return copy.deepcopy(record)

    def card(self, mailbox_id: str) -> dict[str, Any]:
        validate_mail_id(mailbox_id, size=16)
        with self._lock:
            box = self._boxes.get(mailbox_id)
            _require(box is not None, 'mailbox_unavailable', 'unknown mailbox')
            return copy.deepcopy(box.current)

    def deliver(self, mailbox_id: str, packet: dict[str, Any] | str | bytes, *, now_ms: int | None = None) -> dict[str, Any]:
        now = _now(now_ms)
        validate_mail_id(mailbox_id, size=16)
        packet = _parse_bounded(packet, self.max_body_bytes, 'invalid_packet') if isinstance(packet, (str, bytes)) else copy.deepcopy(packet)
        raw = _packet_bytes(packet)
        h = packet['header']
        _require(h['mailbox_id'] == mailbox_id, 'invalid_packet', 'path/header mailbox mismatch')
        pid, size = _hash(raw), len(raw)
        with self._lock:
            box = self._boxes.get(mailbox_id)
            _require(box is not None, 'mailbox_unavailable', 'unknown mailbox')
            prior = box.tombstones.get(pid)
            if prior is not None:
                return {'packet_id': pid, 'accepted_at': prior['accepted_at']}
            card = box.current['envelope']
            c = card['event']['payload']
            _require(self.origin in c['routes'], 'mailbox_unavailable', 'relay is not a current route')
            _require(card['hash'] == h['card_hash'] and now < c['expires_at'], 'stale_card', 'packet needs the current unexpired card')
            _require(now < h['expires_at'], 'packet_expired', 'packet expired')
            _require(h['expires_at'] <= min(c['receive_until'], now + MAIL_MAX_TTL_MS + MAIL_FUTURE_SKEW_MS),
                     'invalid_packet', 'packet exceeds accepted lifetime')
            _require(size <= c['max_packet_bytes'], 'payload_too_large', 'packet exceeds card limit')
            box.drop_expired(now)
            _require(len(box.packets) < self.max_packets and box.bytes + size <= self.max_bytes and box.last_seq < MAX_SAFE_NONCE,
                     'rate_limited', 'mailbox storage quota exhausted')
            box.last_seq += 1
            box.packets[pid] = ({'packet_id': pid, 'packet': packet, 'accepted_at': now, 'seq': box.last_seq}, size)
            box.bytes += size
            box.tombstones[pid] = {'accepted_at': now, 'expires_at': h['expires_at']}
            return {'packet_id': pid, 'accepted_at': now}

    def _owner_box(self, mailbox_id: str, token: str, now: int) -> _Mailbox:
        validate_mail_id(mailbox_id, size=16)
        claims = verify_mail_owner_jwt(token, None, self.origin, now_ms=now)
        box = self._boxes.get(mailbox_id)
        _require(box is not None, 'mailbox_unavailable', 'unknown mailbox')
        _require(claims['iss'] == box.current['envelope']['event']['actor'], 'permission_denied', 'requester is not mailbox owner')
        return box

    def list(self, mailbox_id: str, token: str, *, limit: int = 100,
             cursor: str | None = None, now_ms: int | None = None) -> dict[str, Any]:
        now = _now(now_ms)
        with self._lock:
            box = self._owner_box(mailbox_id, token, now)
            _require(type(limit) is int and 1 <= limit <= 1000, 'invalid_request', 'limit must be 1..1000')
            # The cursor is the last returned seq; ownership is checked by the JWT.
            _require(cursor is None or (isinstance(cursor, str) and _CURSOR.fullmatch(cursor) is not None
                                        and int(cursor) <= MAX_SAFE_NONCE), 'invalid_request', 'invalid cursor')
            after = 0 if cursor is None else int(cursor)
            rows = [record for record, _ in box.packets.values()
                    if record['seq'] > after and now < record['packet']['header']['expires_at']]
            page = {'result': copy.deepcopy(rows[:limit])}
            if len(rows) > limit:
                page['next_cursor'] = str(rows[limit - 1]['seq'])
            return page

    def delete(self, mailbox_id: str, packet_id: str, token: str, *, now_ms: int | None = None) -> None:
        now = _now(now_ms)
        with self._lock:
            box = self._owner_box(mailbox_id, token, now)
            validate_mail_id(packet_id)
            stored = box.packets.pop(packet_id, None)
            if stored is not None:
                box.bytes -= stored[1]

    def prune(self, *, now_ms: int | None = None) -> None:
        """Drop expired packets and tombstones, then forget mailboxes whose current card's receive_until passed."""
        now = _now(now_ms)
        with self._lock:
            for mailbox_id, box in list(self._boxes.items()):
                box.drop_expired(now)
                for pid in [pid for pid, t in box.tombstones.items() if now >= t['expires_at']]:
                    del box.tombstones[pid]
                if now >= box.current['envelope']['event']['payload']['receive_until']:
                    del self._boxes[mailbox_id]

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {'version': 1, 'origin': self.origin, 'mailboxes': [
                {'current': copy.deepcopy(box.current), 'last_seq': box.last_seq,
                 'packets': [copy.deepcopy(record) for record, _ in box.packets.values()],
                 'tombstones': [{'packet_id': pid, **t} for pid, t in box.tombstones.items()]}
                for box in self._boxes.values()]}

    @classmethod
    def from_snapshot(cls, state: dict[str, Any], **options: Any) -> 'MailRelayStore':
        _snapshot_version(state)
        obj = cls(state['origin'], **options)
        for saved in state['mailboxes']:
            box = _Mailbox(copy.deepcopy(saved['current']), saved['last_seq'])
            for record in saved['packets']:
                size = len(_jcs(record['packet']))
                box.packets[record['packet_id']] = (copy.deepcopy(record), size)
                box.bytes += size
            for t in saved['tombstones']:
                box.tombstones[t['packet_id']] = {'accepted_at': t['accepted_at'], 'expires_at': t['expires_at']}
            obj._boxes[saved['current']['envelope']['event']['payload']['mailbox_id']] = box
        return obj


__all__ = ['MailCardCache', 'MailKeyring', 'MailInbox', 'MailRelayStore']
