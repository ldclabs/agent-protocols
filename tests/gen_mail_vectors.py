#!/usr/bin/env python3
"""Development generator for docs/protocols/agent-mail/1.0.vectors.json.

Run from the repository root:
    .venv/bin/python tests/gen_mail_vectors.py

The script first checks its minimal, sequence-zero HPKE code against RFC 9180
Appendix A.2.1. It then builds deterministic public test fixtures, asserts each
intended outcome with the small models below, and rewrites the vectors file.
The three SDKs verify the vectors; this script is not a Mail implementation.
Deterministic private and ephemeral keys here are PUBLIC TEST MATERIAL.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'python/agent-protocols/src'))
import jsonschema
import rfc8785
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from agent_protocols.errors import AgentProtocolError
from agent_protocols.identity import (
    AgentSigner, parse_strict_json, validate_agent_id, validate_origin, verify_event_hash, verify_request_jwt,
    verify_signature,
)

DOCS = ROOT / 'docs/protocols/agent-mail'
PROTOCOL = 'agent-mail/1.0'
DAY = 86_400_000
MAX_TTL = 30 * DAY
SKEW = 300_000
NOW = 1_790_726_400_000
RELAY = 'https://relay.example'
MIRROR = 'https://mirror.example'
SCHEMA = json.loads((DOCS / '1.0.schema.json').read_text())
KEM_SUITE = b'KEM\x00\x20'
HPKE_SUITE = b'HPKE\x00\x20\x00\x01\x00\x03'
INFO = PROTOCOL.encode()


class Reject(ValueError):
    """Local diagnostic label for a vector case."""


def require(condition, reason):
    if not condition:
        raise Reject(reason)


def outcome(callback):
    try:
        callback()
        return 'valid'
    except Reject as exc:
        return str(exc)


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def unb64(value):
    try:
        result = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
    except (ValueError, TypeError) as exc:
        raise Reject('base64url') from exc
    require(b64(result) == value, 'base64url')
    return result


def jcs(value):
    return rfc8785.dumps(value)


def digest(data):
    return b64(hashlib.sha3_256(data).digest())


def schema_check(value, definition):
    selected = {'$schema': SCHEMA['$schema'], '$defs': SCHEMA['$defs'], '$ref': '#/$defs/' + definition}
    try:
        jsonschema.Draft202012Validator(selected).validate(value)
    except jsonschema.ValidationError as exc:
        raise Reject('schema') from exc


# Minimal RFC 9180 Base mode for fixed test ephemerals: DHKEM(X25519), HKDF-SHA256, ChaCha20Poly1305.
def labeled_extract(suite, salt, label, ikm):
    return hmac.digest(salt or bytes(32), b'HPKE-v1' + suite + label + ikm, 'sha256')


def labeled_expand(suite, prk, label, info, length):
    info = length.to_bytes(2, 'big') + b'HPKE-v1' + suite + label + info
    output, block = b'', b''
    for counter in range(1, (length + 31) // 32 + 1):
        block = hmac.digest(prk, block + info + bytes([counter]), 'sha256')
        output += block
    return output[:length]


def public_key(secret):
    return X25519PrivateKey.from_private_bytes(secret).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def shared_secret(secret, peer, enc, recipient_public):
    try:
        dh = X25519PrivateKey.from_private_bytes(secret).exchange(X25519PublicKey.from_public_bytes(peer))
    except ValueError as exc:
        raise Reject('x25519') from exc
    require(dh != bytes(32), 'x25519')
    prk = labeled_extract(KEM_SUITE, b'', b'eae_prk', dh)
    return labeled_expand(KEM_SUITE, prk, b'shared_secret', enc + recipient_public, 32)


def schedule(shared, info):
    context = (b'\x00' + labeled_extract(HPKE_SUITE, b'', b'psk_id_hash', b'')
               + labeled_extract(HPKE_SUITE, b'', b'info_hash', info))
    secret = labeled_extract(HPKE_SUITE, shared, b'secret', b'')
    return {
        'shared_secret': shared, 'key_schedule_context': context, 'secret': secret,
        'key': labeled_expand(HPKE_SUITE, secret, b'key', context, 32),
        'base_nonce': labeled_expand(HPKE_SUITE, secret, b'base_nonce', context, 12),
        'exporter_secret': labeled_expand(HPKE_SUITE, secret, b'exp', context, 32),
    }


def seal(recipient_public, ephemeral_secret, info, aad, plaintext):
    enc = public_key(ephemeral_secret)
    state = schedule(shared_secret(ephemeral_secret, recipient_public, enc, recipient_public), info)
    return enc, ChaCha20Poly1305(state['key']).encrypt(state['base_nonce'], plaintext, aad)


def open_hpke(recipient_secret, enc, info, aad, ciphertext):
    state = schedule(shared_secret(recipient_secret, enc, enc, public_key(recipient_secret)), info)
    try:
        return ChaCha20Poly1305(state['key']).decrypt(state['base_nonce'], ciphertext, aad)
    except InvalidTag as exc:
        raise Reject('aead') from exc


# Directly transcribed from the official RFC, not generated by this program.
RFC_VECTOR = {
    'source': 'https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.2.1',
    'mode': 0, 'kem_id': 32, 'kdf_id': 1, 'aead_id': 3, 'sequence_number': 0,
    'info': '4f6465206f6e2061204772656369616e2055726e',
    'skEm': 'f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600',
    'pkEm': '1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a',
    'skRm': '8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb',
    'pkRm': '4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a',
    'shared_secret': '0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7',
    'key_schedule_context': '00431df6cd95e11ff49d7013563baf7f11588c75a6611ee2a4404a49306ae4cfc5b69c5718a60cc5876c358d3f7fc31ddb598503f67be58ea1e798c0bb19eb9796',
    'secret': '5b9cd775e64b437a2335cf499361b2e0d5e444d5cb41a8a53336d8fe402282c6',
    'key': 'ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91',
    'base_nonce': '5c4d98150661b848853b547f',
    'exporter_secret': 'a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922',
    'pt': '4265617574792069732074727574682c20747275746820626561757479',
    'aad': '436f756e742d30',
    'ct': '1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28',
}


def check_rfc_vector():
    hx = lambda key: bytes.fromhex(RFC_VECTOR[key])
    assert public_key(hx('skEm')) == hx('pkEm') and public_key(hx('skRm')) == hx('pkRm')
    state = schedule(shared_secret(hx('skEm'), hx('pkRm'), hx('pkEm'), hx('pkRm')), hx('info'))
    for name, value in state.items():
        assert value.hex() == RFC_VECTOR[name], f'RFC 9180 mismatch: {name}'
    enc, ct = seal(hx('pkRm'), hx('skEm'), hx('info'), hx('aad'), hx('pt'))
    assert enc == hx('pkEm') and ct == hx('ct'), 'RFC 9180 ciphertext mismatch'
    assert open_hpke(hx('skRm'), enc, hx('info'), hx('aad'), ct) == hx('pt')


def check_envelope(envelope, definition):
    schema_check(envelope, definition)
    try:
        parse_strict_json(json.dumps(envelope, ensure_ascii=True))
        verify_event_hash(envelope)
    except AgentProtocolError as exc:
        raise Reject('event_hash') from exc
    try:
        verify_signature(envelope)
    except AgentProtocolError as exc:
        raise Reject('signature') from exc
    event, payload = envelope['event'], envelope['event']['payload']
    if event['type'] == 'mailbox.publish':
        require(event['created_at'] < payload['expires_at'] <= event['created_at'] + MAX_TTL, 'lifetime')
        require(payload['expires_at'] <= payload['receive_until'] <= payload['expires_at'] + MAX_TTL, 'receive_until')
        for origin in payload['routes']:
            try:
                validate_origin(origin)
            except AgentProtocolError as exc:
                raise Reject('origin') from exc
        try:
            X25519PrivateKey.from_private_bytes(bytes([42]) * 32).exchange(X25519PublicKey.from_public_bytes(unb64(payload['public_key'])))
        except ValueError as exc:
            raise Reject('x25519') from exc
    else:
        require(event['created_at'] < payload['header']['expires_at'] <= event['created_at'] + MAX_TTL + SKEW, 'packet_lifetime')


def check_message(payload):
    schema_check(payload, 'messagePayload')
    require(payload['created_at'] < payload['expires_at'] <= payload['created_at'] + MAX_TTL, 'lifetime')
    for part in payload['parts']:
        data = unb64(part['data'])
        if part['media_type'].startswith('text/'):
            try:
                data.decode('utf-8')
            except UnicodeDecodeError as exc:
                raise Reject('text_utf8') from exc
    if 'reply_card' in payload:
        check_envelope(payload['reply_card'], 'mailboxCardEnvelope')
        require(payload['reply_card']['event']['actor'] == payload['from'], 'reply_card_owner')


def check_sender_card(card, owner, now):
    check_envelope(card, 'mailboxCardEnvelope')
    p = card['event']['payload']
    require(card['event']['actor'] == owner, 'card_owner')
    require(card['event']['created_at'] <= now + SKEW, 'future')
    require(p['routes'], 'closed')
    require(now < p['expires_at'], 'card_expired')


def frame(data):
    size = 1024 * ((4 + len(data) + 1023) // 1024)
    return len(data).to_bytes(4, 'big') + data + bytes(size - 4 - len(data))


def unframe(plaintext):
    require(len(plaintext) >= 1024 and len(plaintext) % 1024 == 0, 'framing')
    n = int.from_bytes(plaintext[:4], 'big')
    require(0 < n <= len(plaintext) - 4, 'length')
    require(len(plaintext) == 1024 * ((4 + n + 1023) // 1024), 'nonminimal_padding')
    require(not any(plaintext[4 + n:]), 'nonzero_padding')
    data = plaintext[4:4 + n]
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise Reject('utf8') from exc
    try:
        message = parse_strict_json(text)
    except AgentProtocolError as exc:
        raise Reject('strict_json') from exc
    require(jcs(message) == data, 'noncanonical_json')
    return message


def packet_aad(event):
    return jcs({**{k: event[k] for k in ('protocol', 'type', 'actor', 'created_at', 'nonce')}, 'header': event['payload']['header']})


def make_packet(card, message, ephemeral, *, signer=None, nonce=200, created_at=NOW, plaintext=None, header=None, info=INFO, aad=None):
    signer = signer or AgentSigner.from_seed(bytes([7]) * 32)
    c = card['event']['payload']
    if header is None:
        header = {'mailbox_id': c['mailbox_id'], 'card_hash': card['hash'], 'expires_at': message['expires_at']}
    event = {'protocol': PROTOCOL, 'type': 'mail.submit', 'actor': signer.agent_id(), 'created_at': created_at,
             'nonce': nonce, 'payload': {'header': header}}
    enc, ct = seal(unb64(c['public_key']), ephemeral, info, packet_aad(event) if aad is None else aad,
                   frame(jcs(message)) if plaintext is None else plaintext)
    event['payload'].update(enc=b64(enc), ciphertext=b64(ct))
    return signer.sign_event(event)


def check_packet_shape(packet, packet_id=None):
    check_envelope(packet, 'packetEnvelope')
    p = packet['event']['payload']
    unb64(p['enc'])
    ct = unb64(p['ciphertext'])
    require(len(ct) >= 1040 and len(ct) % 1024 == 16, 'ciphertext_length')
    require(len(jcs(packet)) <= 1048576, 'packet_size')
    if packet_id is not None:
        require(packet['hash'] == packet_id, 'packet_id')


def open_packet(packet, card, secret, owner, now, packet_id=None):
    check_packet_shape(packet, packet_id)
    check_envelope(card, 'mailboxCardEnvelope')
    e = packet['event']; p = e['payload']; c, h = card['event']['payload'], p['header']
    require(e['created_at'] <= now + SKEW, 'future')
    require(card['event']['actor'] == owner, 'card_owner')
    require(h['card_hash'] == card['hash'], 'card_hash')
    require(h['mailbox_id'] == c['mailbox_id'], 'mailbox_id')
    require(len(jcs(packet)) <= c['max_packet_bytes'], 'packet_size')
    require(h['expires_at'] <= c['receive_until'], 'receive_until')
    require(b64(public_key(secret)) == c['public_key'], 'recipient_key')
    message = unframe(open_hpke(secret, unb64(p['enc']), INFO, packet_aad(e), unb64(p['ciphertext'])))
    check_message(message)
    require(message['from'] == e['actor'], 'sender')
    require(message['to'] == owner, 'recipient')
    require(message['expires_at'] == h['expires_at'], 'expiry_binding')
    require(message['created_at'] <= min(now, e['created_at']) + SKEW, 'future')
    return message


def check_reply(reply, parent):
    check_message(reply); check_message(parent)
    require(reply['from'] == parent['to'] and reply['to'] == parent['from']
            and reply.get('in_reply_to') == parent['message_id']
            and reply['thread_id'] == parent['thread_id'], 'reply_binding')


def check_discovery(document, origin):
    schema_check(document, 'discoveryDocument')
    require(document['service'] == origin, 'discovery_origin')


ADDRESS = re.compile(r'(did:agent:[A-Za-z0-9_-]{43})/mail/([A-Za-z0-9_-]{22})(?:\?(route=[^&#?]+(?:&route=[^&#?]+)*))?')


def parse_address(value):
    """Independent check of Mail §3.3: did:agent:<key>/mail/<mailbox_id>[?route=<origin>...]."""
    match = ADDRESS.fullmatch(value)
    require(match, 'address')
    owner, mailbox, query = match.groups()
    try:
        validate_agent_id(owner)
    except AgentProtocolError as exc:
        raise Reject('address') from exc
    require(len(unb64(mailbox)) == 16, 'address')
    routes = [item[len('route='):] for item in query.split('&')] if query else []
    for route in routes:
        try:
            validate_origin(route)
        except AgentProtocolError as exc:
            raise Reject('address') from exc
    require(len(routes) <= 8 and len(set(routes)) == len(routes), 'address')
    return {'owner': owner, 'mailbox_id': mailbox, 'routes': routes}


def check_owner_token(token, owner, origin, now):
    try:
        claims = verify_request_jwt(token, audience=origin, now_secs=now // 1000)
    except AgentProtocolError as exc:
        raise Reject('invalid_token') from exc
    require(claims['iss'] == claims['sub'] == owner, 'permission_denied')


class RecipientModel:
    def __init__(self):
        self.accepted = {}

    def accept(self, packet, card, secret, owner, now):
        message = open_packet(packet, card, secret, owner, now)
        key = (message['from'], message['message_id'])
        if key in self.accepted:
            require(self.accepted[key] == digest(jcs(message)), 'message_conflict')
            return 'duplicate'
        require(now < message['expires_at'], 'expired')
        self.accepted[key] = digest(jcs(message))
        return 'accepted'


class CardCacheModel:
    def __init__(self):
        self.pin = None

    def observe(self, card, owner, now):
        check_envelope(card, 'mailboxCardEnvelope')
        require(card['event']['actor'] == owner and card['event']['created_at'] <= now + SKEW, 'card_owner')
        if self.pin is not None and card['hash'] != self.pin['hash']:
            require(card['event']['nonce'] > self.pin['event']['nonce'], 'rollback')
        self.pin = card
        check_sender_card(card, owner, now)
        return 'usable'

    def prune(self, now):
        if self.pin is not None and now >= self.pin['event']['created_at'] + MAX_TTL + SKEW:
            self.pin = None


class RelayModel:
    def __init__(self):
        self.boxes, self.nonces = {}, {}

    def publish(self, card, now):
        check_envelope(card, 'mailboxCardEnvelope')
        e, p = card['event'], card['event']['payload']
        box = self.boxes.get(p['mailbox_id'])
        if box:
            require(box['record']['envelope']['event']['actor'] == e['actor'], 'mailbox_conflict')
            if box['record']['envelope']['hash'] == card['hash']:
                return 'idempotent', box['record']
            require(e['nonce'] > box['record']['envelope']['event']['nonce'], 'nonce_not_greater')
        else:
            require(RELAY in p['routes'], 'permission_denied')
        require(abs(e['created_at'] - now) <= SKEW, 'timestamp_out_of_window')
        require(e['nonce'] > self.nonces.get(e['actor'], 0), 'nonce_not_greater')
        self.nonces[e['actor']] = e['nonce']
        record = {'envelope': card, 'accepted_at': now}
        if box:
            box['record'] = record
        else:
            self.boxes[p['mailbox_id']] = {'record': record, 'seq': 0, 'stored': {}, 'tombs': {}}
        return 'accepted', record

    def deliver(self, mailbox, packet, now):
        check_packet_shape(packet)
        require(packet['event']['payload']['header']['mailbox_id'] == mailbox, 'invalid_packet')
        box = self.boxes.get(mailbox)
        require(box, 'mailbox_unavailable')
        pid = packet['hash']
        if pid in box['tombs']:
            return 'idempotent', box['tombs'][pid]
        card, h = box['record']['envelope'], packet['event']['payload']['header']
        c = card['event']['payload']
        require(RELAY in c['routes'], 'mailbox_unavailable')
        require(h['card_hash'] == card['hash'] and now < c['expires_at'], 'stale_card')
        require(now < h['expires_at'], 'packet_expired')
        require(h['expires_at'] <= min(c['receive_until'], now + MAX_TTL + SKEW), 'invalid_packet')
        # Packets are not live writes: only a future-dated packet is rejected, and no nonce maximum applies.
        require(packet['event']['created_at'] <= now + SKEW, 'timestamp_out_of_window')
        require(len(jcs(packet)) <= c['max_packet_bytes'], 'payload_too_large')
        box['seq'] += 1
        result = {'packet_id': pid, 'accepted_at': now}
        box['tombs'][pid] = result
        box['stored'][pid] = box['seq']
        return 'accepted', result


def signed(signer, event_type, payload, nonce, created_at=NOW):
    return signer.sign_event({'protocol': PROTOCOL, 'type': event_type, 'actor': signer.agent_id(),
                              'created_at': created_at, 'nonce': nonce, 'payload': payload})


def change(value, path, replacement):
    value = copy.deepcopy(value)
    target = value
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    return value


def generate():
    sender, recipient = AgentSigner.from_seed(bytes([7]) * 32), AgentSigner.from_seed(bytes([8]) * 32)
    owner = recipient.agent_id()
    sk, rotated_sk = bytes([9]) * 32, bytes([10]) * 32
    p = {'mailbox_id': b64(bytes(range(16))), 'expires_at': NOW + DAY, 'receive_until': NOW + 2 * DAY,
         'public_key': b64(public_key(sk)), 'routes': [RELAY, MIRROR], 'max_packet_bytes': 65536}
    rotated_p = {**p, 'public_key': b64(public_key(rotated_sk))}
    card = signed(recipient, 'mailbox.publish', p, 100)
    envelopes = {
        'card': card,
        'conflicting_card': signed(recipient, 'mailbox.publish', {**p, 'max_packet_bytes': 32768}, 100),
        'rotated_card': signed(recipient, 'mailbox.publish', rotated_p, 101),
        'moved_card': signed(recipient, 'mailbox.publish', {**rotated_p, 'routes': [MIRROR]}, 102),
        'closed_card': signed(recipient, 'mailbox.publish', {**rotated_p, 'routes': []}, 103),
        'reopened_card': signed(recipient, 'mailbox.publish', p, 104),
        'long_lived_card': signed(recipient, 'mailbox.publish', {**p, 'expires_at': NOW + MAX_TTL, 'receive_until': NOW + 2 * MAX_TTL}, 110),
        'short_closed_card': signed(recipient, 'mailbox.publish', {**p, 'routes': [], 'expires_at': NOW + 2 * DAY, 'receive_until': NOW + 2 * DAY}, 111),
        'small_limit_card': signed(recipient, 'mailbox.publish', {**p, 'max_packet_bytes': 4096}, 112),
        'foreign_card': signed(sender, 'mailbox.publish', p, 300),
    }
    message_content = {
        'to': owner, 'expires_at': NOW + DAY + 1000, 'thread_id': b64(bytes(range(48, 64))),
        'subject': 'A private question / 私信',
        'parts': [{'media_type': 'text/plain', 'data': b64('Can we compare our evidence?\n我们可以核对证据吗？'.encode())},
                  {'media_type': 'application/octet-stream', 'name': 'evidence.bin', 'data': b64(bytes([0, 1, 254, 255]))}],
    }
    letter = {**message_content, 'message_id': b64(bytes([31]) * 32), 'from': sender.agent_id(), 'created_at': NOW}
    messages = {'message': letter,
                'lower_nonce_message': {**letter, 'message_id': b64(bytes([32]) * 32), 'created_at': NOW - DAY, 'subject': 'Earlier message, delivered later'},
                'reply_message': {'message_id': b64(bytes([33]) * 32), 'from': owner, 'created_at': NOW,
                    'to': sender.agent_id(), 'expires_at': NOW + DAY, 'thread_id': letter['thread_id'],
                    'in_reply_to': letter['message_id'], 'parts': [{'media_type': 'text/plain', 'data': b64(b'Received, thank you.')}]}}
    messages['conflicting_message'] = {**letter, 'subject': 'Different content with the same logical ID'}
    for message in messages.values(): check_message(message)
    for envelope in envelopes.values(): check_envelope(envelope, 'envelope')
    keys = {'sender_seed_hex': (bytes([7]) * 32).hex(), 'recipient_seed_hex': (bytes([8]) * 32).hex(),
            'recipient_secret_hex': sk.hex(), 'rotated_recipient_secret_hex': rotated_sk.hex(),
            'sender_agent_id': sender.agent_id(), 'recipient_agent_id': owner}

    encryptions = {}
    for name, card_name, message_name, eph in [('original', 'card', 'message', 11), ('reencrypted', 'card', 'message', 12),
                                               ('rotated', 'rotated_card', 'message', 13), ('lower_nonce', 'card', 'lower_nonce_message', 14),
                                               ('reopened', 'reopened_card', 'message', 15), ('long_lived', 'long_lived_card', 'message', 16), ('conflicting', 'card', 'conflicting_message', 17)]:
        c, l, ephemeral = envelopes[card_name], messages[message_name], bytes([eph]) * 32
        nonce = 199 if name == 'lower_nonce' else 200 + len(encryptions)
        packet = make_packet(c, l, ephemeral, nonce=nonce)
        envelopes[name + '_packet'] = packet
        secret = rotated_sk if card_name == 'rotated_card' else sk
        assert open_packet(packet, c, secret, owner, NOW, packet['hash']) == l
        encryptions[name] = {'card': card_name, 'message': message_name, 'ephemeral_secret_hex': ephemeral.hex(),
                             'plaintext_b64': b64(frame(jcs(l))), 'info_hex': INFO.hex(), 'aad_jcs': packet_aad(packet['event']).decode(),
                             'packet': packet, 'packet_jcs': jcs(packet).decode(), 'packet_id': packet['hash']}
    original = encryptions['original']['packet']
    original_id = encryptions['original']['packet_id']

    schema_cases = []
    def sc(name, definition, value, valid):
        assert (outcome(lambda: schema_check(value, definition)) == 'valid') == valid, name
        schema_cases.append({'name': name, 'definition': definition, 'value': value, 'valid': valid})
    for name in ['card', 'rotated_card', 'closed_card', 'original_packet']:
        sc(name, 'envelope', envelopes[name], True)
    sc('message', 'messagePayload', letter, True)
    sc('message ID is not an id16', 'messagePayload', change(letter, ['message_id'], b64(bytes(16))), False)
    sc('missing sender', 'messagePayload', {k:v for k,v in letter.items() if k!='from'}, False)
    sc('packet payload', 'packetPayload', original['event']['payload'], True)
    sc('unknown packet member', 'packetEnvelope', {**original, 'sender': sender.agent_id()}, False)
    sc('removed header key_id', 'packetEnvelope', change(original, ['event', 'payload', 'header', 'key_id'], p['mailbox_id']), False)
    sc('removed header protocol', 'packetEnvelope', change(original, ['event', 'payload', 'header', 'protocol'], PROTOCOL), False)
    sc('removed card enabled field', 'mailboxCardEnvelope', change(card, ['event', 'payload', 'enabled'], True), False)
    sc('nine routes', 'mailboxCardEnvelope', change(card, ['event', 'payload', 'routes'], [f'https://r{i}.example' for i in range(9)]), False)
    sc('duplicate routes', 'mailboxCardEnvelope', change(card, ['event', 'payload', 'routes'], [RELAY] * 2), False)
    sc('unknown message field', 'messagePayload', change(letter, ['bcc'], [sender.agent_id()]), False)
    sc('unsigned plaintext cannot be submitted', 'packetEnvelope', letter, False)
    sc('old message envelope type rejected', 'packetEnvelope', change(original, ['event', 'type'], 'mail.message'), False)
    sc('null subject', 'messagePayload', change(letter, ['subject'], None), False)
    sc('no parts', 'messagePayload', change(letter, ['parts'], []), False)
    sc('noncanonical base64 trailing bits', 'messagePayload', change(letter, ['parts'], [{'media_type': 'text/plain', 'data': 'Zh'}]), False)
    sc('media parameters', 'messagePayload', change(letter, ['parts'], [{'media_type': 'text/plain;charset=utf-8', 'data': ''}]), False)
    sc('empty opaque part', 'part', {'media_type': 'application/octet-stream', 'data': ''}, True)
    sc('base64 newline suffix', 'part', {'media_type': 'text/plain', 'data': 'Zg\n'}, False)
    sc('media type newline suffix', 'part', {'media_type': 'text/plain\n', 'data': ''}, False)
    sc('id newline suffix', 'packetEnvelope', change(original, ['event', 'payload', 'header', 'mailbox_id'], p['mailbox_id'] + '\n'), False)
    sc('valid punctuation in origin', 'httpsOrigin', 'https://host!name.example', True)
    sc('unsafe integer', 'packetEnvelope', change(original, ['event', 'payload', 'header', 'expires_at'], 9007199254740992), False)
    sc('delivery result', 'deliveryResult', {'packet_id': original_id, 'accepted_at': NOW}, True)
    sc('delivery result never reveals seq', 'deliveryResult', {'packet_id': original_id, 'accepted_at': NOW, 'seq': 1}, False)
    record = {'packet_id': original_id, 'packet': original, 'accepted_at': NOW, 'seq': 1}
    sc('packet record', 'packetRecord', record, True)
    sc('zero sequence', 'packetRecord', {**record, 'seq': 0}, False)
    sc('card accepted record', 'cardAcceptedRecord', {'envelope': card, 'accepted_at': NOW}, True)
    sc('Identity list extension', 'packetList', {'result': [record], 'next_cursor': '1', 'future_extension': {}}, True)
    discovery = {'protocol': PROTOCOL, 'service': RELAY, 'features': ['future-capability'],
                 'endpoints': {'mailboxes': RELAY + '/custom'}, 'future_extension': {}}
    sc('discovery extension', 'discoveryDocument', discovery, True)
    sc('discovery protocol', 'discoveryDocument', {**discovery, 'protocol': 'agent-mail/2.0'}, False)

    rejections = []
    def bad(name, packet, expected, **kwargs):
        actual = outcome(lambda: open_packet(packet, envelopes[kwargs.get('card', 'card')],
                                             bytes.fromhex(kwargs.get('secret_hex', sk.hex())),
                                             kwargs.get('owner', owner), NOW, kwargs.get('packet_id')))
        assert actual == expected, (name, actual, expected)
        codes = {'event_hash':'invalid_event_hash','signature':'invalid_signature','schema':'invalid_event',
                 'card_owner':'invalid_actor','recipient_key':'invalid_private_key','packet_size':'payload_too_large',
                 'text_utf8':'invalid_event','reply_card_owner':'invalid_actor','future':'timestamp_out_of_window',
                 'lifetime':'invalid_event','strict_json':'invalid_event'}
        rejections.append({'name': name, 'packet': packet, 'expected': expected, 'code':codes.get(expected,'invalid_packet'), **kwargs})
    def resign(value, by=sender):
        event = copy.deepcopy(value['event']); event['actor'] = by.agent_id()
        return by.sign_event(event)
    for field, replacement in [('mailbox_id', b64(bytes([77]) * 16)), ('card_hash', b64(bytes([79]) * 32)), ('expires_at', NOW + DAY + 999)]:
        bad('tampered ' + field, change(original, ['event', 'payload', 'header', field], replacement), 'event_hash')
    ciphertext = bytearray(unb64(original['event']['payload']['ciphertext'])); ciphertext[0] ^= 1
    bad('tampered ciphertext', change(original, ['event', 'payload', 'ciphertext'], b64(ciphertext)), 'event_hash')
    bad('invalid outer signature', change(original, ['signature'], b64(bytes(64))), 'signature')
    bad('valid different signer rewraps ciphertext', resign(original, recipient), 'aead')
    bad('valid signature with changed nonce', resign(change(original, ['event', 'nonce'], 900)), 'aead')
    bad('valid signature with changed time', resign(change(original, ['event', 'created_at'], NOW + 1)), 'aead')
    bad('valid signature with changed expiration', resign(change(original, ['event', 'payload', 'header', 'expires_at'], NOW + DAY + 999)), 'aead')
    bad('ciphertext length not 16 modulo 1024', resign(change(original, ['event', 'payload', 'ciphertext'], b64(unb64(original['event']['payload']['ciphertext']) + b'\0'))), 'ciphertext_length')
    oversized = {**letter, 'parts': [{'media_type': 'application/octet-stream', 'data': b64(bytes(3000))}]}
    bad('card packet size limit', make_packet(envelopes['small_limit_card'], oversized, bytes([61]) * 32), 'packet_size', card='small_limit_card')
    bad('packet past receive_until', make_packet(card, letter, bytes([62]) * 32, header={**original['event']['payload']['header'], 'expires_at': p['receive_until'] + 1}), 'receive_until')
    bad('wrong encapsulated key', resign(change(original, ['event', 'payload', 'enc'], b64(public_key(bytes([99]) * 32)))), 'aead')
    bad('all-zero encapsulated key', resign(change(original, ['event', 'payload', 'enc'], b64(bytes(32)))), 'x25519')
    bad('wrong recipient secret', original, 'recipient_key', secret_hex=rotated_sk.hex())
    bad('wrong local identity', original, 'card_owner', owner=sender.agent_id())
    bad('wrong packet id', original, 'packet_id', packet_id=b64(bytes([80]) * 32))
    next_eph = 20
    def craft(name, expected, *, use_message=letter, plaintext=None, header=None, info=INFO, aad=None):
        nonlocal next_eph
        ephemeral = bytes([next_eph]) * 32
        next_eph += 1
        bad(name, make_packet(card, use_message, ephemeral, plaintext=plaintext, header=header, info=info, aad=aad), expected)
    craft('wrong HPKE info', 'aead', info=b'wrong protocol context')
    craft('wrong HPKE AAD', 'aead', aad=b'{}')
    padded = bytearray(frame(jcs(letter)))
    padded[-1] = 1
    craft('nonzero padding', 'nonzero_padding', plaintext=bytes(padded))
    craft('nonminimal padding', 'nonminimal_padding', plaintext=frame(jcs(letter)) + bytes(1024))
    craft('out of bounds frame length', 'length', plaintext=(2**32 - 1).to_bytes(4, 'big') + frame(jcs(letter))[4:])
    craft('zero frame length', 'length', plaintext=bytes(1024))
    craft('invalid UTF-8', 'utf8', plaintext=frame(b'\xff'))
    craft('duplicate JSON keys', 'strict_json', plaintext=frame(b'{"event":{},"event":{}}'))
    craft('noncanonical JSON whitespace', 'noncanonical_json', plaintext=frame(json.dumps(letter, ensure_ascii=False).encode()))
    craft('unpaired surrogate', 'strict_json', plaintext=frame(b'{"x":"\\ud800"}'))
    craft('signed wrong recipient', 'recipient', use_message={**letter, 'to': sender.agent_id()})
    craft('authenticated unequal expiration', 'expiry_binding', header={**original['event']['payload']['header'], 'expires_at': NOW + DAY + 999})
    craft('signed invalid text part', 'text_utf8', use_message={**letter, 'parts': [{'media_type': 'text/plain', 'data': b64(b'\xff')}]})
    craft('signed wrong reply card owner', 'reply_card_owner', use_message={**letter, 'reply_card': card})
    craft('future signed message', 'future', use_message={**letter, 'created_at': NOW + SKEW + 1})
    craft('invalid message lifetime', 'lifetime', use_message={**letter, 'created_at': NOW + DAY + 1000})
    craft('authenticated wrong sender', 'sender', use_message={**letter, 'from': owner})

    sender_cards = []
    def card_case(name, payload, expected, now=NOW):
        value = signed(recipient, 'mailbox.publish', payload, 400 + len(sender_cards))
        assert outcome(lambda: check_sender_card(value, owner, now)) == expected, name
        sender_cards.append({'name': name, 'card': value, 'now': now, 'expected': expected})
    card_case('expired card', p, 'card_expired', now=NOW + DAY)
    card_case('closed card', {**p, 'routes': []}, 'closed')
    card_case('receive_until before expires_at', {**p, 'receive_until': NOW + DAY - 1}, 'receive_until')
    card_case('unusable X25519 public key', {**p, 'public_key': b64(bytes(32))}, 'x25519')
    card_case('noncanonical numeric origin', {**p, 'routes': ['https://127.1']}, 'origin')
    card_case('TTL too long', {**p, 'expires_at': NOW + MAX_TTL + 1, 'receive_until': NOW + MAX_TTL + 1}, 'lifetime')

    discovery_cases = [
        {'name': 'minimal document', 'value': {'protocol': PROTOCOL, 'service': RELAY}, 'expected': 'valid'},
        {'name': 'inert features and members', 'value': discovery, 'expected': 'valid'},
        {'name': 'service mismatch', 'value': {**discovery, 'service': MIRROR}, 'expected': 'discovery_origin'},
        {'name': 'wrong protocol', 'value': {**discovery, 'protocol': 'agent-mail/2.0'}, 'expected': 'schema'},
    ]
    for case in discovery_cases:
        assert outcome(lambda: check_discovery(case['value'], RELAY)) == case['expected'], case['name']

    stable = f'{owner}/mail/{p["mailbox_id"]}'
    address_cases = [
        {'name': 'stable address', 'value': stable, 'expected': 'valid',
         'parsed': {'owner': owner, 'mailbox_id': p['mailbox_id'], 'routes': []}},
        {'name': 'contact address', 'value': f'{stable}?route={RELAY}&route={MIRROR}', 'expected': 'valid',
         'parsed': {'owner': owner, 'mailbox_id': p['mailbox_id'], 'routes': [RELAY, MIRROR]}},
        {'name': 'bare agent id is not a mailbox address', 'value': owner, 'expected': 'address'},
        {'name': 'other protocol resource', 'value': f'{owner}/knowledge/{p["mailbox_id"]}', 'expected': 'address'},
        {'name': 'mailbox_id is not an id16', 'value': f'{owner}/mail/{card["hash"]}', 'expected': 'address'},
        {'name': 'wrong owner key length', 'value': f'{owner[:-1]}/mail/{p["mailbox_id"]}', 'expected': 'address'},
        {'name': 'route is not an origin', 'value': f'{stable}?route={RELAY}/v1/mailboxes', 'expected': 'address'},
        {'name': 'nine routes', 'value': stable + '?' + '&'.join(f'route=https://r{i}.example' for i in range(9)), 'expected': 'address'},
        {'name': 'email-like form', 'value': f'{p["mailbox_id"]}@relay.example', 'expected': 'address'},
    ]
    for case in address_cases:
        assert outcome(lambda: parse_address(case['value'])) == case['expected'], case['name']
        assert case['expected'] != 'valid' or parse_address(case['value']) == case['parsed'], case['name']

    token_cases = []
    for name, signer, audience, expected in [('owner read/delete', recipient, RELAY, 'valid'),
                                             ('different identity read/delete', sender, RELAY, 'permission_denied'),
                                             ('wrong relay audience', recipient, MIRROR, 'invalid_token')]:
        claims = {'iss': signer.agent_id(), 'sub': signer.agent_id(), 'aud': audience, 'iat': NOW // 1000,
                  'exp': NOW // 1000 + 300, 'jti': b64(bytes([51]) * 16)}
        token = signer.sign_request_jwt(claims)
        assert outcome(lambda: check_owner_token(token, owner, RELAY, NOW)) == expected, name
        token_cases.append({'name': name, 'token': token, 'expected': expected})

    card_cache = [{'card': 'card', 'expected': 'usable'}, {'card': 'conflicting_card', 'expected': 'rollback'},
                  {'card': 'card', 'expected': 'usable'}, {'card': 'rotated_card', 'expected': 'usable'},
                  {'card': 'card', 'expected': 'rollback'}, {'card': 'closed_card', 'expected': 'closed'},
                  {'card': 'rotated_card', 'expected': 'rollback'}]
    persistent_pin = [{'card': 'long_lived_card', 'now': NOW, 'expected': 'usable'},
                      {'card': 'short_closed_card', 'now': NOW, 'expected': 'closed'},
                      {'card': 'long_lived_card', 'now': NOW + 3 * DAY, 'expected': 'rollback'},
                      {'prune': NOW + MAX_TTL + SKEW},
                      {'card': 'long_lived_card', 'now': NOW + MAX_TTL + SKEW, 'expected': 'card_expired'}]
    for steps in (card_cache, persistent_pin):
        cache = CardCacheModel()
        for step in steps:
            if 'prune' in step:
                cache.prune(step['prune'])
                continue
            actual = outcome(lambda: cache.observe(envelopes[step['card']], owner, step.get('now', NOW)))
            assert actual.replace('valid', 'usable') == step['expected'], step

    recipient_steps = [{'packet': 'original', 'now': NOW, 'expected': 'accepted', 'items': 1},
                       {'packet': 'reencrypted', 'now': NOW + 1, 'expected': 'duplicate', 'items': 1},
                       {'packet': 'rotated', 'now': NOW + 2, 'expected': 'duplicate', 'items': 1},
                       {'packet': 'lower_nonce', 'now': NOW + 3, 'expected': 'accepted', 'items': 2},
                       {'packet': 'original', 'now': NOW + DAY + 1000, 'expected': 'duplicate', 'items': 2}]
    historical = {'packet': 'original', 'now': NOW + DAY + 500, 'expected': 'accepted',
                  'note': 'Card expired 500 ms earlier, but retained key and queued message are still valid.'}
    expired = {'packet': 'original', 'now': NOW + DAY + 1000, 'expected': 'expired'}
    def receive(model, step):
        entry = encryptions[step['packet']]
        secret = rotated_sk if entry['card'] == 'rotated_card' else sk
        try:
            return model.accept(entry['packet'], envelopes[entry['card']], secret, owner, step['now'])
        except Reject as exc:
            return str(exc)
    model = RecipientModel()
    for step in recipient_steps:
        assert receive(model, step) == step['expected'] and len(model.accepted) == step['items'], step
    assert receive(RecipientModel(), historical) == 'accepted' and receive(RecipientModel(), expired) == 'expired'

    relay_steps = [
        {'op': 'publish', 'card': 'card', 'now': NOW, 'expected': 'accepted', 'accepted_at': NOW},
        {'op': 'publish', 'card': 'card', 'now': NOW + 1, 'expected': 'idempotent', 'accepted_at': NOW},
        {'op': 'publish', 'card': 'foreign_card', 'now': NOW, 'expected': 'mailbox_conflict'},
        {'op': 'deliver', 'packet': 'original', 'now': NOW, 'expected': 'accepted', 'accepted_at': NOW, 'stored': 1},
        {'op': 'deliver', 'packet': 'reencrypted', 'now': NOW - SKEW - 1, 'expected': 'timestamp_out_of_window', 'stored': 1},
        # Packets are not live writes: a lower nonce, signed outside the live-write window, is still accepted.
        {'op': 'deliver', 'packet': 'lower_nonce', 'now': NOW + 2 * SKEW, 'expected': 'accepted', 'accepted_at': NOW + 2 * SKEW, 'stored': 2},
        {'op': 'delete', 'packet': 'original', 'stored': 1},
        {'op': 'delete', 'packet': 'lower_nonce', 'stored': 0},
        {'op': 'publish', 'card': 'moved_card', 'now': NOW, 'expected': 'accepted', 'accepted_at': NOW},
        {'op': 'deliver', 'packet': 'original', 'now': NOW + 1, 'expected': 'idempotent', 'accepted_at': NOW, 'stored': 0},
        {'op': 'deliver', 'packet': 'reencrypted', 'now': NOW + 2, 'expected': 'mailbox_unavailable', 'stored': 0},
        {'op': 'publish', 'card': 'rotated_card', 'now': NOW, 'expected': 'nonce_not_greater'},
        {'op': 'publish', 'card': 'reopened_card', 'now': NOW, 'expected': 'accepted', 'accepted_at': NOW},
        {'op': 'deliver', 'packet': 'reencrypted', 'now': NOW + 3, 'expected': 'stale_card', 'stored': 0},
        {'op': 'deliver', 'packet': 'reopened', 'now': NOW + 4, 'expected': 'accepted', 'accepted_at': NOW + 4, 'stored': 1, 'seqs': [3]},
        {'op': 'publish', 'card': 'long_lived_card', 'now': NOW, 'expected': 'accepted', 'accepted_at': NOW},
        # The card is current and unexpired, but the packet's own deadline has passed.
        {'op': 'deliver', 'packet': 'long_lived', 'now': NOW + DAY + 1000, 'expected': 'packet_expired'},
    ]
    relay = RelayModel()
    mailbox = p['mailbox_id']
    for step in relay_steps:
        if step['op'] == 'delete':
            relay.boxes[mailbox]['stored'].pop(encryptions[step['packet']]['packet_id'], None)
        else:
            try:
                if step['op'] == 'publish':
                    actual, result = relay.publish(envelopes[step['card']], step['now'])
                else:
                    actual, result = relay.deliver(mailbox, encryptions[step['packet']]['packet'], step['now'])
            except Reject as exc:
                actual, result = str(exc), None
            assert actual == step['expected'], step
            if 'accepted_at' in step:
                assert result['accepted_at'] == step['accepted_at'], step
        if 'stored' in step:
            assert len(relay.boxes[mailbox]['stored']) == step['stored'], step
        if 'seqs' in step:
            assert sorted(relay.boxes[mailbox]['stored'].values()) == step['seqs'], step
    registration = [{'card': 'moved_card', 'expected': 'permission_denied'},
                    {'card': 'closed_card', 'expected': 'permission_denied'}]
    for step in registration:
        assert outcome(lambda: RelayModel().publish(envelopes[step['card']], NOW)) == step['expected'], step

    conflict_model = RecipientModel()
    assert receive(conflict_model, {'packet':'original','now':NOW}) == 'accepted'
    assert receive(conflict_model, {'packet':'conflicting','now':NOW}) == 'message_conflict'

    reply = {'valid': 'reply_message', 'parent': 'message', 'wrong_parent': 'lower_nonce_message', 'expected_wrong_parent': 'reply_binding'}
    assert outcome(lambda: check_reply(messages['reply_message'], letter)) == 'valid'
    assert outcome(lambda: check_reply(messages['reply_message'], messages['lower_nonce_message'])) == 'reply_binding'
    # Different packets and cards must preserve a single immutable logical message ID.
    assert len({encryptions[n]['packet_id'] for n in ['original', 'reencrypted', 'rotated']}) == 3

    return {
        'protocol': PROTOCOL,
        'description': 'Normative deterministic vectors for the named checks; public test keys must never be used in production. '
                       'Expected rejection labels are local test diagnostics; relay lifecycle labels are wire error codes. '
                       'Schema cases only test shape; semantic and stateful requirements are tested separately. '
                       'Generated by tests/gen_mail_vectors.py.',
        'now': NOW, 'rfc9180_known_answer': RFC_VECTOR, 'keys': keys, 'envelopes': envelopes, 'messages': messages,
        'signing': {name: {'seed_hex': keys['sender_seed_hex'] if env['event']['actor'] == sender.agent_id() else keys['recipient_seed_hex'],
                           'event_jcs': jcs(env['event']).decode(), 'envelope_jcs': jcs(env).decode()} for name, env in envelopes.items()},
        'encryptions': encryptions, 'schema_cases': schema_cases, 'recipient_rejections': rejections, 'sender_card_cases': sender_cards,
        'framing_boundaries': [{'json_byte_length': n, 'frame_byte_length': 1024 * ((4 + n + 1023) // 1024),
                                'length_prefix_hex': n.to_bytes(4, 'big').hex(),
                                'padding_byte_length': 1024 * ((4 + n + 1023) // 1024) - 4 - n,
                                'plaintext_sha3_256': digest(frame(b'x' * n))} for n in [1, 1020, 1021, 2044, 2045]],
        'strict_json_rejections': ['{"x":1,"x":2}', '{"x":NaN}', '{"x":9007199254740992}', '{"x":"\\ud800"}'],
        'discovery_cases': discovery_cases,
        'address_cases': address_cases,
        'owner_jwt_cases': token_cases,
        'lifecycle': {
            'card_cache': card_cache, 'persistent_card_pin': persistent_pin,
            'recipient': recipient_steps, 'historical_card': historical, 'expired_new_message': expired,
            'relay': relay_steps, 'relay_registration': registration, 'reply': reply,
            'message_conflict': {'first':'original','second':'conflicting','expected':'invalid_event'},
        },
    }


def main():
    check_rfc_vector()  # Independent known-answer gate, before any generation.
    path = DOCS / '1.0.vectors.json'
    path.write_text(json.dumps(generate(), indent=2, ensure_ascii=False) + '\n')
    print(f'wrote {path.relative_to(ROOT)}')


if __name__ == '__main__':
    main()
