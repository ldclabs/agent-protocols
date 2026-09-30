"""Mail conformance through SDK functions, never the development checker."""
import copy
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pyhpke import KEMKey, KEMKeyPair

from agent_protocols import mail
from agent_protocols.errors import AgentProtocolError
from agent_protocols.identity import AgentSigner, parse_strict_json
from agent_protocols.mail_state import MailCardCache, MailInbox, MailKeyring, MailRelayStore

ROOT = Path(__file__).resolve().parents[3]
V = json.loads((ROOT / 'docs/protocols/agent-mail/1.0.vectors.json').read_text())
ENVS = V['envelopes']
NOW = V['now']
OWNER = V['keys']['recipient_agent_id']
ORIGIN = 'https://relay.example'
MAILBOX = ENVS['card']['event']['payload']['mailbox_id']
TOKEN = V['owner_jwt_cases'][0]['token']


def key_for(card):
    for name in ('recipient_secret_hex', 'rotated_recipient_secret_hex'):
        key = mail.MailEncryptionKey.from_private_bytes(bytes.fromhex(V['keys'][name]))
        if key.public_key() == card['event']['payload']['public_key']:
            return key
    raise AssertionError('missing fixture secret')


def fixed_suite(secret):
    suite = mail._suite()
    sk = X25519PrivateKey.from_private_bytes(secret)
    pair = KEMKeyPair(KEMKey.from_pyca_cryptography_key(sk), KEMKey.from_pyca_cryptography_key(sk.public_key()))
    original = suite.create_sender_context
    suite.create_sender_context = lambda key, info=b'': original(key, info=info, eks=pair)
    return suite


def test_packaged_schema_matches_normative_schema():
    assert mail.MAIL_SCHEMA == json.loads((ROOT / 'docs/protocols/agent-mail/1.0.schema.json').read_text())


def test_rfc9180_official_known_ciphertext_via_native_dependency():
    v = V['rfc9180_known_answer']
    hx = lambda name: bytes.fromhex(v[name])
    recipient = X25519PrivateKey.from_private_bytes(hx('skRm'))
    suite = fixed_suite(hx('skEm'))
    enc, context = suite.create_sender_context(KEMKey.from_pyca_cryptography_key(recipient.public_key()), info=hx('info'))
    assert enc == hx('pkEm')
    assert context.seal(hx('pt'), hx('aad')) == hx('ct')
    receiver = mail._suite().create_recipient_context(enc, KEMKey.from_pyca_cryptography_key(recipient), info=hx('info'))
    assert receiver.open(hx('ct'), hx('aad')) == hx('pt')


@pytest.mark.parametrize('name', list(V['signing']))
def test_signed_vectors(name):
    item, expected = ENVS[name], V['signing'][name]
    signer = AgentSigner.from_seed(bytes.fromhex(expected['seed_hex']))
    assert mail.sign_mail_event(signer, item['event']) == item
    assert mail._jcs(item['event']).decode() == expected['event_jcs']
    assert mail._jcs(item).decode() == expected['envelope_jcs']
    assert mail.parse_mail_envelope(expected['envelope_jcs']) == item


@pytest.mark.parametrize('name', list(V['encryptions']))
def test_hpke_vectors_match_entire_packet_and_plaintext(name, monkeypatch):
    vector = V['encryptions'][name]
    card, letter = ENVS[vector['card']], ENVS[vector['letter']]
    suite = fixed_suite(bytes.fromhex(vector['ephemeral_secret_hex']))
    monkeypatch.setattr(mail, '_suite', lambda: suite)
    packet = mail.encrypt_mail(letter, card, now_ms=NOW)
    assert packet == vector['packet']
    assert mail.mail_packet_id(packet) == vector['packet_id']
    assert mail._jcs(packet).decode() == vector['packet_jcs']
    assert mail._jcs(packet['header']).decode() == vector['aad_jcs']
    assert mail._info(packet['header']).hex() == vector['info_hex']
    assert mail.encode_mail_plaintext(letter) == mail._decode(vector['plaintext_b64'])
    assert mail.decrypt_mail(packet, card, key_for(card), OWNER, now_ms=NOW, packet_id=vector['packet_id']) == letter


@pytest.mark.parametrize('case', V['schema_cases'], ids=lambda c: c['name'])
def test_structural_vectors(case):
    if case['valid']:
        mail.validate_mail_schema(case['value'], case['definition'])
    else:
        with pytest.raises(AgentProtocolError):
            mail.validate_mail_schema(case['value'], case['definition'])


@pytest.mark.parametrize('case', V['recipient_rejections'], ids=lambda c: c['name'])
def test_all_recipient_rejections(case):
    card = ENVS[case.get('card', 'card')]
    key = mail.MailEncryptionKey.from_private_bytes(bytes.fromhex(case['secret_hex'])) if 'secret_hex' in case else key_for(card)
    with pytest.raises(AgentProtocolError):
        mail.decrypt_mail(case['packet'], card, key, case.get('owner', OWNER), now_ms=NOW, packet_id=case.get('packet_id'))


@pytest.mark.parametrize('case', V['sender_card_cases'], ids=lambda c: c['name'])
def test_sender_card_rejections(case):
    with pytest.raises(AgentProtocolError):
        mail.validate_mailbox_card(case['card'], OWNER, now_ms=case['now'], for_sending=True)


@pytest.mark.parametrize('case', V['framing_boundaries'])
def test_framing_boundaries(case):
    framed = mail._frame_json(b'x' * case['json_byte_length'])
    assert len(framed) == case['frame_byte_length']
    assert framed[:4].hex() == case['length_prefix_hex']
    assert len(framed) - 4 - case['json_byte_length'] == case['padding_byte_length']
    assert mail._b64(hashlib.sha3_256(framed).digest()) == case['plaintext_sha3_256']


@pytest.mark.parametrize('raw', V['strict_json_rejections'])
def test_strict_json_rejections(raw):
    with pytest.raises(AgentProtocolError):
        mail.parse_mail_packet(raw)


@pytest.mark.parametrize('case', V['discovery_cases'], ids=lambda c: c['name'])
def test_discovery_cases(case):
    if case['expected'] == 'valid':
        mail.validate_mail_discovery(case['value'], ORIGIN, ENVS['card'])
    else:
        with pytest.raises(AgentProtocolError):
            mail.validate_mail_discovery(case['value'], ORIGIN, ENVS['card'])


@pytest.mark.parametrize('case', V['owner_jwt_cases'], ids=lambda c: c['name'])
def test_owner_jwt_vectors(case):
    if case['expected'] == 'valid':
        mail.verify_mail_owner_jwt(case['token'], OWNER, ORIGIN, now_ms=NOW)
    else:
        with pytest.raises(AgentProtocolError):
            mail.verify_mail_owner_jwt(case['token'], OWNER, ORIGIN, now_ms=NOW)


@pytest.mark.parametrize('scenario', ['card_cache', 'persistent_card_pin'])
def test_card_cache_lifecycle(scenario):
    cache = MailCardCache()
    for step in V['lifecycle'][scenario]:
        if step['expected'] == 'usable':
            cache.observe(ENVS[step['card']], OWNER, now_ms=step.get('now', NOW))
        else:
            with pytest.raises(AgentProtocolError):
                cache.observe(ENVS[step['card']], OWNER, now_ms=step.get('now', NOW))
        # Restart between every operation, including failures that mutate pins.
        cache = MailCardCache.from_snapshot(json.loads(json.dumps(cache.snapshot())))


def ring():
    keys = MailKeyring(OWNER)
    for vector in V['encryptions'].values():
        card = ENVS[vector['card']]
        keys.add(card, key_for(card))
    return keys


def test_recipient_lifecycle_with_restart_between_packets():
    inbox = MailInbox(ring())
    for step in V['lifecycle']['recipient']:
        result = inbox.accept(V['encryptions'][step['packet']]['packet'], now_ms=step['now'])
        assert result['kind'] == step['expected']
        assert len(inbox.snapshot()['accepted']) == step['items']
        inbox = MailInbox.from_snapshot(MailKeyring.from_snapshot(inbox.keyring.snapshot()), inbox.snapshot())
    historical = V['lifecycle']['historical_card']
    assert MailInbox(ring()).accept(V['encryptions'][historical['packet']]['packet'], now_ms=historical['now'])['kind'] == historical['expected']
    expired = V['lifecycle']['expired_new_letter']
    with pytest.raises(AgentProtocolError, match='expired'):
        MailInbox(ring()).accept(V['encryptions'][expired['packet']]['packet'], now_ms=expired['now'])


def test_relay_lifecycle_uses_actual_publication_and_authorization():
    relay = MailRelayStore(ORIGIN)
    relay.publish(ENVS['card'], now_ms=NOW)
    for step in V['lifecycle']['relay']:
        if step['op'] == 'set_current':
            relay.publish(ENVS[step['card']], now_ms=NOW)
        elif step['op'] == 'delete':
            relay.delete(MAILBOX, V['encryptions'][step['packet']]['packet_id'], TOKEN, now_ms=NOW)
        else:
            packet = V['encryptions'][step['packet']]['packet']
            if step['expected'] in ('accepted', 'idempotent'):
                record = relay.deliver(MAILBOX, packet, now_ms=step['now'])
                assert record['seq'] == step['seq'] and record['accepted_at'] == step['accepted_at']
            else:
                with pytest.raises(AgentProtocolError):
                    relay.deliver(MAILBOX, packet, now_ms=step['now'])
        if 'stored' in step:
            assert len(relay.list_packets(MAILBOX, TOKEN, now_ms=NOW)['result']) == step['stored']
        relay = MailRelayStore.from_snapshot(json.loads(json.dumps(relay.snapshot())))


def test_receipt_binding_vectors():
    case = V['lifecycle']['receipt']
    mail.validate_mail_receipt(ENVS[case['valid']], ENVS[case['original']])
    with pytest.raises(AgentProtocolError):
        mail.validate_mail_receipt(ENVS[case['valid']], ENVS[case['wrong_original']])
