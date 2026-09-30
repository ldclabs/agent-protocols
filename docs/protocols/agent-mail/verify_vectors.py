#!/usr/bin/env python3
"""Development-only Agent Mail 1.0 vector generator/checker; NOT a Mail SDK.

From the repository root, with Python >= 3.10:
  python -m pip install -e ./python/agent-protocols jsonschema
  python docs/protocols/agent-mail/verify_vectors.py
Or use the existing environment:
  .venv/bin/python docs/protocols/agent-mail/verify_vectors.py

Dependencies: the repository's Agent Identity Python SDK, cryptography, rfc8785,
and jsonschema. --write-vectors explicitly regenerates the JSON fixtures.
The checker first compares its deliberately minimal, sequence-zero HPKE test
implementation with RFC 9180 Appendix A.2.1 (including intermediate values and
an independently published ciphertext). Only then does it generate/check Mail
vectors. Deterministic private/ephemeral keys below are PUBLIC TEST MATERIAL.

Checks: structural schemas; strict Identity JSON/JCS/hash/signatures; canonical
encodings; Mail time/binding/size/media rules; HPKE/framing; discovery origins;
selected card-cache, relay-history, recipient-dedup, receipt, and JWT scenarios.
The in-memory state models exercise the listed cases, not storage durability,
concurrency, HTTP, quotas, pagination, network policy, secret erasure, side-channel
resistance, or a complete implementation. Error labels in vectors are local test
labels, not remotely exposed decryption errors or required HTTP error precedence.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import hmac
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'python/agent-protocols/src'))
import jsonschema
import rfc8785
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from agent_protocols.identity import (
    AgentSigner, parse_strict_json, verify_event_hash, verify_signature,
    validate_origin, verify_request_jwt,
)
from agent_protocols.errors import AgentProtocolError

HERE = Path(__file__).resolve().parent
PROTOCOL = 'agent-mail/1.0'
DAY = 86_400_000
MAX_TTL = 30 * DAY
SKEW = 300_000
NOW = 1_790_726_400_000
SCHEMA = json.loads((HERE / '1.0.schema.json').read_text())
KEM_SUITE = b'KEM\x00\x20'
HPKE_SUITE = b'HPKE\x00\x20\x00\x01\x00\x03'


class Reject(ValueError):
    """Local diagnostic category, never a decryption response to the sender."""


def require(condition, reason):
    if not condition:
        raise Reject(reason)


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


def extract(salt, ikm):
    return hmac.digest(salt or bytes(32), ikm, 'sha256')


def expand(prk, info, length):
    require(0 <= length <= 255 * 32, 'hkdf_length')
    output, block = b'', b''
    for counter in range(1, (length + 31) // 32 + 1):
        block = hmac.digest(prk, block + info + bytes([counter]), 'sha256')
        output += block
    return output[:length]


def labeled_extract(suite, salt, label, ikm):
    return extract(salt, b'HPKE-v1' + suite + label + ikm)


def labeled_expand(suite, prk, label, info, length):
    return expand(prk, length.to_bytes(2, 'big') + b'HPKE-v1' + suite + label + info, length)


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
    psk_hash = labeled_extract(HPKE_SUITE, b'', b'psk_id_hash', b'')
    info_hash = labeled_extract(HPKE_SUITE, b'', b'info_hash', info)
    context = b'\x00' + psk_hash + info_hash
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
    pk = public_key(recipient_secret)
    state = schedule(shared_secret(recipient_secret, enc, enc, pk), info)
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
    v = RFC_VECTOR
    hx = lambda key: bytes.fromhex(v[key])
    assert public_key(hx('skEm')) == hx('pkEm')
    assert public_key(hx('skRm')) == hx('pkRm')
    state = schedule(shared_secret(hx('skEm'), hx('pkRm'), hx('pkEm'), hx('pkRm')), hx('info'))
    for name, value in state.items():
        assert value.hex() == v[name], f'RFC 9180 mismatch: {name}'
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
    require(event['created_at'] < payload['expires_at'] <= event['created_at'] + MAX_TTL, 'lifetime')
    if event['type'] == 'mailbox.publish':
        require(payload['expires_at'] <= payload['receive_until'] <= payload['expires_at'] + MAX_TTL, 'receive_until')
        for origin in payload['routes']:
            try:
                validate_origin(origin)
            except AgentProtocolError as exc:
                raise Reject('origin') from exc
        # Test only: a disposable fixed scalar checks for unusable peer keys.
        try:
            X25519PrivateKey.from_private_bytes(bytes([42]) * 32).exchange(X25519PublicKey.from_public_bytes(unb64(payload['public_key'])))
        except ValueError as exc:
            raise Reject('x25519') from exc
    elif event['type'] == 'mail.message':
        for part in payload['parts']:
            data = unb64(part['data'])
            if part['media_type'].startswith('text/'):
                try:
                    data.decode('utf-8')
                except UnicodeDecodeError as exc:
                    raise Reject('text_utf8') from exc
        if 'reply_card' in payload:
            check_envelope(payload['reply_card'], 'mailboxCardEnvelope')
            require(payload['reply_card']['event']['actor'] == event['actor'], 'reply_card_owner')


def check_sender_card(card, owner, now):
    check_envelope(card, 'mailboxCardEnvelope')
    require(card['event']['actor'] == owner, 'card_owner')
    p = card['event']['payload']
    require(card['event']['created_at'] <= now + SKEW, 'future')
    require(p['enabled'], 'disabled')
    require(now < p['expires_at'], 'card_expired')


def frame(data):
    size = 1024 * ((4 + len(data) + 1023) // 1024)
    return len(data).to_bytes(4, 'big') + data + bytes(size - 4 - len(data))


def unframe(plaintext):
    require(len(plaintext) >= 1024 and len(plaintext) % 1024 == 0, 'framing')
    n = int.from_bytes(plaintext[:4], 'big')
    require(0 < n <= len(plaintext) - 4, 'length')
    require(len(plaintext) == 1024 * ((4 + n + 1023) // 1024), 'nonminimal_padding')
    require(not any(plaintext[4+n:]), 'nonzero_padding')
    data = plaintext[4:4+n]
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise Reject('utf8') from exc
    try:
        letter = parse_strict_json(text)
    except AgentProtocolError as exc:
        raise Reject('strict_json') from exc
    require(jcs(letter) == data, 'noncanonical_json')
    return letter


def packet_info(header):
    return PROTOCOL.encode() + b'\0' + unb64(header['card_hash'])


def make_packet(card, letter, ephemeral, *, plaintext=None, header=None, info=None, aad=None):
    c = card['event']['payload']
    if header is None:
        header = {'protocol': PROTOCOL, 'mailbox_id': c['mailbox_id'], 'card_hash': card['hash'], 'key_id': c['key_id'], 'expires_at': letter['event']['payload']['expires_at']}
    enc, ct = seal(unb64(c['public_key']), ephemeral, packet_info(header) if info is None else info, jcs(header) if aad is None else aad, frame(jcs(letter)) if plaintext is None else plaintext)
    return {'header': header, 'enc': b64(enc), 'ciphertext': b64(ct)}


def check_packet_shape(packet, packet_id=None):
    schema_check(packet, 'packet')
    unb64(packet['enc'])
    ct = unb64(packet['ciphertext'])
    require(len(ct) >= 1040 and len(ct) % 1024 == 16, 'ciphertext_length')
    require(len(jcs(packet)) <= 1048576, 'packet_size')
    if packet_id is not None:
        require(digest(jcs(packet)) == packet_id, 'packet_id')


def open_packet(packet, card, secret, owner, now, packet_id=None):
    check_packet_shape(packet, packet_id)
    check_envelope(card, 'mailboxCardEnvelope')
    c, h = card['event']['payload'], packet['header']
    require(card['event']['actor'] == owner, 'card_owner')
    require(c['enabled'], 'disabled')
    require(h['card_hash'] == card['hash'], 'card_hash')
    require(h['mailbox_id'] == c['mailbox_id'], 'mailbox_id')
    require(h['key_id'] == c['key_id'], 'key_id')
    require(len(jcs(packet)) <= c['max_packet_bytes'], 'packet_size')
    require(h['expires_at'] <= c['receive_until'], 'receive_until')
    require(b64(public_key(secret)) == c['public_key'], 'recipient_key')
    letter = unframe(open_hpke(secret, unb64(packet['enc']), packet_info(h), jcs(h), unb64(packet['ciphertext'])))
    check_envelope(letter, 'letterEnvelope')
    e, p = letter['event'], letter['event']['payload']
    require(p['to'] == owner, 'recipient')
    require(p['expires_at'] == h['expires_at'], 'expiry_binding')
    require(e['created_at'] <= now + SKEW, 'future')
    return letter  # New acceptance expiration is checked after durable dedup lookup.


def check_discovery(document, origin, card):
    schema_check(document, 'discoveryDocument')
    try:
        validate_origin(document['service'])
    except AgentProtocolError as exc:
        raise Reject('origin') from exc
    require(document['service'] == origin and origin in card['event']['payload']['routes'], 'discovery_origin')
    endpoint = document.get('endpoints', {}).get('mailboxes', origin + '/v1/mailboxes')
    parsed = urlsplit(endpoint)
    require(parsed.scheme == 'https' and parsed.netloc == urlsplit(origin).netloc and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment and '?' not in endpoint and '#' not in endpoint and not endpoint.endswith('/') and '\\' not in endpoint, 'endpoint')
    return endpoint


def check_receipt(receipt, original):
    check_envelope(receipt, 'receiptEnvelope')
    r, m = receipt['event'], original['event']
    require(m['type'] == 'mail.message' and r['actor'] == m['payload']['to'] and r['payload']['to'] == m['actor'] and r['payload']['message_hash'] == original['hash'], 'receipt_binding')


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
        letter = open_packet(packet, card, secret, owner, now)
        key = (owner, letter['hash'])
        if key in self.accepted:
            return 'duplicate'
        require(now < letter['event']['payload']['expires_at'], 'expired')
        self.accepted[key] = letter
        return 'accepted'


class CardCacheModel:
    def __init__(self):
        self.latest = None
        self.equivocation = False
        self.keys = {}

    def observe(self, card, owner, now):
        check_envelope(card, 'mailboxCardEnvelope')
        e, p = card['event'], card['event']['payload']
        require(e['actor'] == owner, 'card_owner')
        require(e['created_at'] <= now + SKEW, 'future')
        key = (owner, p['mailbox_id'], p['key_id'])
        require(key not in self.keys or self.keys[key] == p['public_key'], 'key_reuse')
        self.keys[key] = p['public_key']
        if self.latest is not None:
            require(p['mailbox_id'] == self.latest['event']['payload']['mailbox_id'], 'mailbox_id')
            if e['nonce'] < self.latest['event']['nonce']:
                raise Reject('rollback')
            if e['nonce'] == self.latest['event']['nonce'] and card['hash'] != self.latest['hash']:
                self.equivocation = True
            if e['nonce'] > self.latest['event']['nonce']:
                self.equivocation = False
        self.latest = card
        require(not self.equivocation, 'equivocation')
        check_sender_card(card, owner, now)
        return 'usable'


class RelayModel:
    """Selected post-publication acceptance cases; NOT live control/HTTP implementation."""
    def __init__(self, card):
        self.current = card
        self.history = {}
        self.stored = set()
        self.seq = 0

    def deliver(self, packet, now):
        check_packet_shape(packet)
        pid = digest(jcs(packet))
        if pid in self.history:
            return 'idempotent', self.history[pid]
        c, h = self.current['event']['payload'], packet['header']
        require(h['mailbox_id'] == c['mailbox_id'], 'mailbox_id')
        require(c['enabled'], 'disabled')
        require(h['card_hash'] == self.current['hash'] and h['key_id'] == c['key_id'] and now < c['expires_at'], 'stale_card')
        require(now < h['expires_at'], 'expired')
        require(h['expires_at'] <= min(c['receive_until'], now + MAX_TTL + SKEW), 'receive_until')
        require(len(jcs(packet)) <= c['max_packet_bytes'], 'packet_size')
        self.seq += 1
        record = {'packet_id': pid, 'accepted_at': now, 'seq': self.seq}
        self.history[pid] = record
        self.stored.add(pid)
        return 'accepted', record


def outcome(callback):
    try:
        callback()
        return 'valid'
    except Reject as exc:
        return str(exc)


def signed(signer, event_type, payload, nonce, created_at=NOW):
    return signer.sign_event({'protocol': PROTOCOL, 'type': event_type, 'actor': signer.agent_id(), 'created_at': created_at, 'nonce': nonce, 'payload': payload})


def change(value, path, replacement):
    value = copy.deepcopy(value)
    target = value
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    return value


def generate_vectors():
    sender, recipient = AgentSigner.from_seed(bytes([7]) * 32), AgentSigner.from_seed(bytes([8]) * 32)
    sk, rotated_sk = bytes([9]) * 32, bytes([10]) * 32
    p = {'mailbox_id': b64(bytes(range(16))), 'enabled': True, 'expires_at': NOW + DAY, 'receive_until': NOW + 2 * DAY, 'key_id': b64(bytes(range(16, 32))), 'public_key': b64(public_key(sk)), 'routes': ['https://relay.example', 'https://mirror.example'], 'max_packet_bytes': 65536}
    card = signed(recipient, 'mailbox.publish', p, 100)
    rotated = signed(recipient, 'mailbox.publish', {**p, 'key_id': b64(bytes(range(32,48))), 'public_key': b64(public_key(rotated_sk))}, 101)
    disabled = signed(recipient, 'mailbox.publish', {**rotated['event']['payload'], 'enabled': False}, 102)
    reenabled = signed(recipient, 'mailbox.publish', {**p}, 104)
    equivocation = signed(recipient, 'mailbox.publish', {**p, 'max_packet_bytes': 32768}, 100)
    key_reuse = signed(recipient, 'mailbox.publish', {**p, 'public_key': b64(public_key(rotated_sk))}, 103)
    long_card = signed(recipient, 'mailbox.publish', {**p, 'expires_at': NOW + 30 * DAY, 'receive_until': NOW + 60 * DAY}, 110)
    short_disabled = signed(recipient, 'mailbox.publish', {**p, 'enabled': False, 'expires_at': NOW + 2 * DAY, 'receive_until': NOW + 2 * DAY}, 111)
    small_card = signed(recipient, 'mailbox.publish', {**p, 'max_packet_bytes': 4096}, 112)
    letter_payload = {'to': recipient.agent_id(), 'expires_at': NOW + DAY + 1000, 'thread_id': b64(bytes(range(48,64))), 'subject': 'A private question / 私信', 'parts': [{'media_type': 'text/plain', 'data': b64('Can we compare our evidence?\n我们可以核对证据吗？'.encode())}, {'media_type': 'application/octet-stream', 'name': 'evidence.bin', 'data': b64(bytes([0,1,254,255]))}], 'receipt_requested': True}
    letter = signed(sender, 'mail.message', letter_payload, 200)
    lower = signed(sender, 'mail.message', {**letter_payload, 'subject': 'Earlier letter, delivered later'}, 199, NOW - DAY)
    # Keep its complete lifetime within MAX_TTL despite a day of offline delay.
    receipt = signed(recipient, 'mail.receipt', {'to': sender.agent_id(), 'expires_at': NOW + DAY, 'message_hash': letter['hash'], 'status': 'received'}, 201)
    envelopes = {'card': card, 'rotated_card': rotated, 'disabled_card': disabled, 'reenabled_card': reenabled, 'equivocating_card': equivocation, 'key_reuse_card': key_reuse, 'long_lived_card': long_card, 'short_disabled_card': short_disabled, 'small_limit_card': small_card, 'letter': letter, 'lower_nonce_letter': lower, 'receipt': receipt}
    keys = {'sender_seed_hex': (bytes([7])*32).hex(), 'recipient_seed_hex': (bytes([8])*32).hex(), 'recipient_secret_hex': sk.hex(), 'rotated_recipient_secret_hex': rotated_sk.hex(), 'sender_agent_id': sender.agent_id(), 'recipient_agent_id': recipient.agent_id()}
    encryptions = {}
    for name, card_name, letter_name, eph in [('original','card','letter',11), ('reencrypted','card','letter',12), ('rotated','rotated_card','letter',13), ('lower_nonce','card','lower_nonce_letter',14), ('reenabled','reenabled_card','letter',15)]:
        c, l, ephemeral = envelopes[card_name], envelopes[letter_name], bytes([eph])*32
        packet = make_packet(c, l, ephemeral)
        encryptions[name] = {'card': card_name, 'letter': letter_name, 'ephemeral_secret_hex': ephemeral.hex(), 'plaintext_b64': b64(frame(jcs(l))), 'info_hex': packet_info(packet['header']).hex(), 'aad_jcs': jcs(packet['header']).decode(), 'packet': packet, 'packet_jcs': jcs(packet).decode(), 'packet_id': digest(jcs(packet))}
    original = encryptions['original']['packet']
    schema_cases = []
    def sc(name, definition, value, valid):
        schema_cases.append({'name':name, 'definition':definition, 'value':value, 'valid':valid})
    for name in ['card','rotated_card','disabled_card','letter','lower_nonce_letter','receipt']:
        sc(name, 'envelope', envelopes[name], True)
    sc('packet', 'packet', original, True)
    sc('unknown packet member', 'packet', {**original, 'sender': sender.agent_id()}, False)
    sc('unknown letter payload field', 'messageEnvelope', change(letter,['event','payload','bcc'],[sender.agent_id()]),False)
    sc('unknown event type','messageEnvelope',change(letter,['event','type'],'mail.command'),False)
    sc('null subject','messageEnvelope',change(letter,['event','payload','subject'],None),False)
    sc('no parts','messageEnvelope',change(letter,['event','payload','parts'],[]),False)
    sc('noncanonical base64 trailing bits','messageEnvelope',change(letter,['event','payload','parts'],[{'media_type':'text/plain','data':'Zh'}]),False)
    sc('media parameters','messageEnvelope',change(letter,['event','payload','parts'],[{'media_type':'text/plain;charset=utf-8','data':''}]),False)
    sc('empty opaque part','part',{'media_type':'application/octet-stream','data':''},True)
    sc('base64 newline suffix','part',{'media_type':'text/plain','data':'Zg\n'},False)
    sc('media type newline suffix','part',{'media_type':'text/plain\n','data':''},False)
    sc('id newline suffix','packet',change(original,['header','mailbox_id'],p['mailbox_id']+'\n'),False)
    sc('valid punctuation in origin','httpsOrigin','https://host!name.example',True)
    sc('receipt cannot request receipt','receiptEnvelope',change(receipt,['event','payload','receipt_requested'],True),False)
    sc('duplicate routes','mailboxCardEnvelope',change(card,['event','payload','routes'],['https://relay.example']*2),False)
    sc('unsafe integer','packet',change(original,['header','expires_at'],9007199254740992),False)
    sc('zero sequence','deliveryResult',{'packet_id':encryptions['original']['packet_id'],'accepted_at':NOW,'seq':0},False)
    record = {'packet_id':encryptions['original']['packet_id'],'packet':original,'accepted_at':NOW,'seq':1}
    sc('packet record','packetRecord',record,True)
    sc('card accepted record','cardAcceptedRecord',{'envelope':card,'accepted_at':NOW},True)
    sc('Identity list extension','packetList',{'result':[record],'next_cursor':'opaque','future_extension':{}},True)
    discovery = {'protocol':PROTOCOL,'service':'https://relay.example','endpoints':{'mailboxes':'https://relay.example/custom/mailboxes'},'features':['future-capability'],'future_extension':{}}
    sc('discovery extension','discoveryDocument',discovery,True)
    sc('wrong discovery endpoint name','discoveryDocument',change(discovery,['endpoints'],{'letters':'https://relay.example/custom'}),False)
    negative = []
    def bad(name, packet, expected, **kwargs):
        negative.append({'name':name,'packet':packet,'expected':expected, **kwargs})
    for field, replacement, expected in [('mailbox_id',b64(bytes([77])*16),'mailbox_id'),('key_id',b64(bytes([78])*16),'key_id'),('card_hash',b64(bytes([79])*32),'card_hash'),('expires_at',NOW+DAY+999,'aead')]:
        bad('tampered '+field,change(original,['header',field],replacement),expected)
    ciphertext = bytearray(unb64(original['ciphertext'])); ciphertext[0] ^= 1
    bad('tampered ciphertext',change(original,['ciphertext'],b64(ciphertext)),'aead')
    bad('ciphertext length not 16 modulo 1024',change(original,['ciphertext'],b64(unb64(original['ciphertext'])+b'\0')),'ciphertext_length')
    bad('encryption using a disabled card',make_packet(disabled,letter,bytes([60])*32),'disabled',card='disabled_card',secret_hex=rotated_sk.hex())
    oversized_letter = signed(sender,'mail.message',{**letter_payload,'parts':[{'media_type':'application/octet-stream','data':b64(bytes(3000))}]},215)
    bad('card packet size limit',make_packet(small_card,oversized_letter,bytes([61])*32),'packet_size',card='small_limit_card')
    excessive_header = {**original['header'], 'expires_at':p['receive_until']+1}
    bad('packet past receive_until',make_packet(card,letter,bytes([62])*32,header=excessive_header),'receive_until')
    bad('wrong encapsulated key',change(original,['enc'],b64(public_key(bytes([99])*32))),'aead')
    bad('all-zero encapsulated key',change(original,['enc'],b64(bytes(32))),'x25519')
    bad('wrong recipient secret',original,'recipient_key',secret_hex=rotated_sk.hex())
    bad('wrong local identity',original,'card_owner',owner=sender.agent_id())
    bad('wrong packet id',original,'packet_id',packet_id=b64(bytes([80])*32))
    # Every crafted packet uses a distinct deterministic ephemeral scalar.
    next_eph = 20
    def craft(name, expected, *, use_letter=letter, plaintext=None, header=None, info=None, aad=None):
        nonlocal next_eph
        ephem = bytes([next_eph])*32; next_eph += 1
        packet = make_packet(card,use_letter,ephem,plaintext=plaintext,header=header,info=info,aad=aad)
        bad(name,packet,expected)
    craft('wrong HPKE info','aead',info=b'wrong protocol context')
    craft('wrong HPKE AAD','aead',aad=b'{}')
    padded = bytearray(frame(jcs(letter))); padded[-1] = 1
    craft('nonzero padding','nonzero_padding',plaintext=bytes(padded))
    craft('nonminimal padding','nonminimal_padding',plaintext=frame(jcs(letter))+bytes(1024))
    craft('out of bounds frame length','length',plaintext=(2**32-1).to_bytes(4,'big')+frame(jcs(letter))[4:])
    craft('zero frame length','length',plaintext=bytes(1024))
    craft('invalid UTF-8','utf8',plaintext=frame(b'\xff'))
    craft('duplicate JSON keys','strict_json',plaintext=frame(b'{"event":{},"event":{}}'))
    craft('noncanonical JSON whitespace','noncanonical_json',plaintext=frame(json.dumps(letter,ensure_ascii=False).encode()))
    craft('unpaired surrogate','strict_json',plaintext=frame(b'{"x":"\\ud800"}'))
    craft('invalid event hash','event_hash',use_letter=change(letter,['hash'],b64(bytes(32))))
    craft('invalid signature','signature',use_letter=change(letter,['signature'],b64(bytes(64))))
    wrong_to = signed(sender,'mail.message',{**letter_payload,'to':sender.agent_id()},210)
    craft('signed wrong recipient','recipient',use_letter=wrong_to)
    header = {**original['header'],'expires_at':NOW+DAY+999}
    craft('authenticated unequal expiration','expiry_binding',header=header)
    invalid_text = signed(sender,'mail.message',{**letter_payload,'parts':[{'media_type':'text/plain','data':b64(b'\xff')}]},211)
    craft('signed invalid text part','text_utf8',use_letter=invalid_text)
    invalid_reply = signed(sender,'mail.message',{**letter_payload,'reply_card':card},212)
    craft('signed wrong reply card owner','reply_card_owner',use_letter=invalid_reply)
    future = signed(sender,'mail.message',letter_payload,213,NOW+SKEW+1)
    craft('future signed letter','future',use_letter=future)
    invalid_lifetime = signed(sender,'mail.message',{**letter_payload,'expires_at':NOW},214)
    craft('invalid letter lifetime','lifetime',use_letter=invalid_lifetime)
    semantic_cards = []
    def card_case(name,payload,expected,now=NOW,created=NOW):
        semantic_cards.append({'name':name,'card':signed(recipient,'mailbox.publish',payload,300+len(semantic_cards),created),'now':now,'expected':expected})
    card_case('expired card',p,'card_expired',now=NOW+DAY)
    card_case('disabled card',{**p,'enabled':False},'disabled')
    card_case('receive_until before expires_at',{**p,'receive_until':NOW+DAY-1},'receive_until')
    card_case('unusable X25519 public key',{**p,'public_key':b64(bytes(32))},'x25519')
    card_case('noncanonical numeric origin',{**p,'routes':['https://127.1']},'origin')
    card_case('TTL too long',{**p,'expires_at':NOW+MAX_TTL+1,'receive_until':NOW+MAX_TTL+1},'lifetime')
    token_cases=[]
    for name,signer,audience,expected in [('owner read/delete',recipient,'https://relay.example','valid'),('different identity read/delete',sender,'https://relay.example','permission_denied'),('wrong relay audience',recipient,'https://mirror.example','invalid_token')]:
        claims={'iss':signer.agent_id(),'sub':signer.agent_id(),'aud':audience,'iat':NOW//1000,'exp':NOW//1000+300,'jti':b64(bytes([51])*16)}
        token_cases.append({'name':name,'token':signer.sign_request_jwt(claims),'expected':expected})
    return {
        'protocol':PROTOCOL,
        'description':'Normative deterministic vectors for the named checks; public test keys must never be used in production. Expected rejection labels are local test diagnostics, not wire error precedence. Schema cases only test shape; semantic and stateful requirements are tested separately. State models cover selected transitions and do not certify a complete Mail implementation.',
        'now':NOW,'rfc9180_known_answer':RFC_VECTOR,'keys':keys,'envelopes':envelopes,
        'signing':{name:{'seed_hex':keys['sender_seed_hex'] if env['event']['actor']==sender.agent_id() else keys['recipient_seed_hex'],'event_jcs':jcs(env['event']).decode(),'envelope_jcs':jcs(env).decode()} for name,env in envelopes.items()},
        'encryptions':encryptions,'schema_cases':schema_cases,'recipient_rejections':negative,'sender_card_cases':semantic_cards,
        'framing_boundaries':[{'json_byte_length':n,'frame_byte_length':1024*((4+n+1023)//1024),'length_prefix_hex':n.to_bytes(4,'big').hex(),'padding_byte_length':1024*((4+n+1023)//1024)-4-n,'plaintext_sha3_256':digest(frame(b'x'*n))} for n in [1,1020,1021,2044,2045]],
        'strict_json_rejections':['{"x":1,"x":2}','{"x":NaN}','{"x":9007199254740992}','{"x":"\\ud800"}'],
        'discovery_cases':[
            {'name':'same origin override and inert unknown features','value':discovery,'expected':'valid'},
            {'name':'default endpoint','value':{'protocol':PROTOCOL,'service':'https://relay.example'},'expected':'valid'},
            {'name':'cross-origin endpoint','value':change(discovery,['endpoints','mailboxes'],'https://other.example/mailboxes'),'expected':'endpoint'},
            {'name':'unadvertised service','value':change(discovery,['service'],'https://other.example'),'expected':'discovery_origin'},
            {'name':'endpoint with credentials','value':change(discovery,['endpoints','mailboxes'],'https://user@relay.example/mailboxes'),'expected':'schema'},
            {'name':'endpoint with query','value':change(discovery,['endpoints','mailboxes'],'https://relay.example/mailboxes?x=1'),'expected':'schema'},
        ],
        'owner_jwt_cases':token_cases,
        'lifecycle':{
            'card_cache':[
                {'card':'card','expected':'usable'}, {'card':'equivocating_card','expected':'equivocation'},
                {'card':'card','expected':'equivocation'}, {'card':'rotated_card','expected':'usable'},
                {'card':'card','expected':'rollback'}, {'card':'disabled_card','expected':'disabled'},
                {'card':'rotated_card','expected':'rollback'}, {'card':'key_reuse_card','expected':'key_reuse'},
            ],
            'persistent_card_pin':[
                {'card':'long_lived_card','now':NOW,'expected':'usable'},
                {'card':'short_disabled_card','now':NOW,'expected':'disabled'},
                {'card':'long_lived_card','now':NOW+3*DAY,'expected':'rollback'},
            ],
            'recipient':[
                {'packet':'original','now':NOW,'expected':'accepted','items':1},
                {'packet':'reencrypted','now':NOW+1,'expected':'duplicate','items':1},
                {'packet':'rotated','now':NOW+2,'expected':'duplicate','items':1},
                {'packet':'lower_nonce','now':NOW+3,'expected':'accepted','items':2},
                {'packet':'original','now':NOW+DAY+1000,'expected':'duplicate','items':2},
            ],
            'historical_card':{'packet':'original','now':NOW+DAY+500,'expected':'accepted','note':'Card expired 500 ms earlier, but retained key and queued letter are still valid.'},
            'expired_new_letter':{'packet':'original','now':NOW+DAY+1000,'expected':'expired'},
            'relay':[
                {'op':'deliver','packet':'original','now':NOW,'expected':'accepted','seq':1,'accepted_at':NOW,'stored':1},
                {'op':'delete','packet':'original','stored':0},
                {'op':'set_current','card':'disabled_card'},
                {'op':'deliver','packet':'original','now':NOW+1,'expected':'idempotent','seq':1,'accepted_at':NOW,'stored':0},
                {'op':'deliver','packet':'reencrypted','now':NOW+2,'expected':'disabled','stored':0},
                {'op':'set_current','card':'reenabled_card'},
                {'op':'deliver','packet':'reencrypted','now':NOW+3,'expected':'stale_card','stored':0},
                {'op':'deliver','packet':'reenabled','now':NOW+4,'expected':'accepted','seq':2,'accepted_at':NOW+4,'stored':1},
            ],
            'relay_model_boundary':'set_current represents an independently validated live publication; these cases do not test control-write persistence or nonce admission.',
            'receipt':{'valid':'receipt','original':'letter','wrong_original':'lower_nonce_letter','expected_wrong_original':'receipt_binding'},
        },
    }


def verify_vectors(v):
    require(v['protocol']==PROTOCOL and v['rfc9180_known_answer']==RFC_VECTOR,'vector_metadata')
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    envs, encs, keys = v['envelopes'],v['encryptions'],v['keys']
    owner=keys['recipient_agent_id']
    for name,entry in v['signing'].items():
        envelope=envs[name]
        assert AgentSigner.from_seed(bytes.fromhex(entry['seed_hex'])).sign_event(envelope['event'])==envelope,name
        assert jcs(envelope['event']).decode()==entry['event_jcs'],name
        assert jcs(envelope).decode()==entry['envelope_jcs'],name
        check_envelope(envelope,'envelope')
    for name,entry in encs.items():
        card,letter=envs[entry['card']],envs[entry['letter']]
        packet=entry['packet']
        assert make_packet(card,letter,bytes.fromhex(entry['ephemeral_secret_hex']))==packet,name
        assert jcs(packet).decode()==entry['packet_jcs'] and digest(jcs(packet))==entry['packet_id'],name
        assert packet_info(packet['header']).hex()==entry['info_hex'] and jcs(packet['header']).decode()==entry['aad_jcs'],name
        assert frame(jcs(letter))==unb64(entry['plaintext_b64']),name
        secret=bytes.fromhex(keys['rotated_recipient_secret_hex' if entry['card']=='rotated_card' else 'recipient_secret_hex'])
        assert open_packet(packet,card,secret,owner,v['now'],entry['packet_id'])==letter,name
    for case in v['schema_cases']:
        assert (outcome(lambda:schema_check(case['value'],case['definition']))=='valid')==case['valid'],case['name']
    for case in v['recipient_rejections']:
        actual=outcome(lambda:open_packet(case['packet'],envs[case.get('card','card')],bytes.fromhex(case.get('secret_hex',keys['recipient_secret_hex'])),case.get('owner',owner),v['now'],case.get('packet_id')))
        assert actual==case['expected'],(case['name'],actual,case['expected'])
    for case in v['sender_card_cases']:
        assert outcome(lambda:check_sender_card(case['card'],owner,case['now']))==case['expected'],case['name']
    for case in v['framing_boundaries']:
        data=frame(b'x'*case['json_byte_length'])
        assert len(data)==case['frame_byte_length'] and data[:4].hex()==case['length_prefix_hex'],case
        assert len(data)-4-case['json_byte_length']==case['padding_byte_length'] and digest(data)==case['plaintext_sha3_256'],case
    for raw in v['strict_json_rejections']:
        try:
            parse_strict_json(raw)
        except AgentProtocolError:
            continue
        raise AssertionError('strict JSON accepted '+raw)
    for case in v['discovery_cases']:
        assert outcome(lambda:check_discovery(case['value'],'https://relay.example',envs['card']))==case['expected'],case['name']
    for case in v['owner_jwt_cases']:
        assert outcome(lambda:check_owner_token(case['token'],owner,'https://relay.example',v['now']))==case['expected'],case['name']
    state=v['lifecycle']
    for scenario in ['card_cache','persistent_card_pin']:
        cache=CardCacheModel()
        for step in state[scenario]:
            try:
                actual=cache.observe(envs[step['card']],owner,step.get('now',v['now']))
            except Reject as exc:
                actual=str(exc)
            assert actual==step['expected'],step
    def receive(model,step):
        entry=encs[step['packet']]
        secret=bytes.fromhex(keys['rotated_recipient_secret_hex' if entry['card']=='rotated_card' else 'recipient_secret_hex'])
        try:
            return model.accept(entry['packet'],envs[entry['card']],secret,owner,step['now'])
        except Reject as exc:
            return str(exc)
    recipient=RecipientModel()
    for step in state['recipient']:
        assert receive(recipient,step)==step['expected'] and len(recipient.accepted)==step['items'],step
    for name in ['historical_card','expired_new_letter']:
        assert receive(RecipientModel(),state[name])==state[name]['expected'],name
    relay=RelayModel(envs['card'])
    for step in state['relay']:
        if step['op']=='set_current':
            relay.current=envs[step['card']]
        elif step['op']=='delete':
            relay.stored.discard(encs[step['packet']]['packet_id'])
        else:
            try:
                actual,record=relay.deliver(encs[step['packet']]['packet'],step['now'])
            except Reject as exc:
                actual,record=str(exc),None
            assert actual==step['expected'],step
            if 'seq' in step:
                assert record['seq']==step['seq'] and record['accepted_at']==step['accepted_at'],step
        if 'stored' in step:
            assert len(relay.stored)==step['stored'],step
    receipt=state['receipt']
    check_receipt(envs[receipt['valid']],envs[receipt['original']])
    assert outcome(lambda:check_receipt(envs[receipt['valid']],envs[receipt['wrong_original']]))==receipt['expected_wrong_original']
    # Different packets and cards must preserve a single inner signed letter ID.
    assert len({encs[n]['packet_id'] for n in ['original','reencrypted','rotated']})==3
    assert len({envs[encs[n]['letter']]['hash'] for n in ['original','reencrypted','rotated']})==1
    return len(v['schema_cases']),len(v['recipient_rejections'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write-vectors',action='store_true',help='regenerate public test fixtures, then verify them')
    args=parser.parse_args()
    check_rfc_vector()  # Mandatory independent known-answer gate, before any generation.
    path=HERE/'1.0.vectors.json'
    if args.write_vectors:
        path.write_text(json.dumps(generate_vectors(),indent=2,ensure_ascii=False)+'\n')
    # The test container intentionally includes malformed protocol values.
    vectors=json.loads(path.read_text())
    counts=verify_vectors(vectors)
    print(f'PASS: RFC 9180 A.2.1; {len(vectors["signing"])} signed envelopes; {len(vectors["encryptions"])} HPKE packets; {counts[0]} schema cases; {counts[1]} recipient rejections; sender/discovery/JWT and selected lifecycle cases.')


if __name__=='__main__':
    main()
