import copy
import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_protocols import (
    AgentSigner, AgentProtocolError, MailCardCache, MailEncryptionKey, MailInbox,
    MailKeyring, MailNonceStore, MailOutbox, MailRelayStore, MailSender,
    decrypt_mail, encrypt_mail, mail_message_event, mailbox_publish_event,
    mail_part, new_mail_id, sign_mail_event, validate_mail_reply, verify_mail_owner_jwt,
)
from agent_protocols import mail
from test_mail_vectors import ENVS, MAILBOX, NOW, ORIGIN, OWNER, TOKEN, V, key_for, ring

SENDER = AgentSigner.from_seed(bytes.fromhex(V['keys']['sender_seed_hex']))
RECIPIENT = AgentSigner.from_seed(bytes.fromhex(V['keys']['recipient_seed_hex']))
DAY = 86_400_000


def signed_change(original, signer=RECIPIENT, *, nonce=None, created_at=None, **payload):
    event = copy.deepcopy(original['event'])
    event['payload'].update(payload)
    if nonce is not None:
        event['nonce'] = nonce
    if created_at is not None:
        event['created_at'] = created_at
    return signer.sign_event(event)


def token(signer=RECIPIENT, now=NOW, **changes):
    claims = {'iss': signer.agent_id(), 'sub': signer.agent_id(), 'aud': ORIGIN,
              'iat': now // 1000, 'exp': now // 1000 + 300}
    claims.update(changes)
    return signer.sign_request_jwt(claims)


def test_independent_random_keys_parts_and_sign_helpers():
    a, b = MailEncryptionKey.generate(), MailEncryptionKey.generate()
    assert a.public_key() != b.public_key()
    assert MailEncryptionKey.from_private_bytes(a.private_bytes()).public_key() == a.public_key()
    assert len({new_mail_id() for _ in range(100)}) == 100
    part = mail_part('text/plain', '私信 👋')
    assert mail.decode_mail_part(part).decode() == '私信 👋'
    assert mail.decode_mail_part(mail_part('application/octet-stream', b'\xff')) == b'\xff'
    with pytest.raises(AgentProtocolError):
        mail_part('text/plain', b'\xff')
    with pytest.raises(AgentProtocolError):
        mail_part('text/plain; charset=UTF-8', b'abc')
    with pytest.raises(AgentProtocolError):
        sign_mail_event(RECIPIENT, ENVS['letter']['event'])
    source = copy.deepcopy(ENVS['letter']['event']['payload'])
    event = mail_message_event(SENDER.agent_id(), NOW, 400, source)
    source['to'] = 'changed'
    assert event['payload']['to'] == OWNER
    assert sign_mail_event(SENDER, event)['event'] == event


def test_crypto_randomness_exact_expiration_and_malformed_card():
    one = encrypt_mail(ENVS['letter'], ENVS['card'], now_ms=NOW)
    two = encrypt_mail(ENVS['letter'], ENVS['card'], now_ms=NOW)
    assert one != two and one['enc'] != two['enc']
    assert decrypt_mail(one, ENVS['card'], key_for(ENVS['card']), OWNER, now_ms=NOW) == ENVS['letter']
    for malformed in ({}, {'event': {}}, {'event': {'payload': None}}, None):
        with pytest.raises(AgentProtocolError):
            encrypt_mail(ENVS['letter'], malformed, now_ms=NOW)
    expires = ENVS['letter']['event']['payload']['expires_at']
    with pytest.raises(AgentProtocolError) as err:
        decrypt_mail(one, ENVS['card'], key_for(ENVS['card']), OWNER, now_ms=expires)
    assert err.value.code == 'packet_expired'
    assert decrypt_mail(one, ENVS['card'], key_for(ENVS['card']), OWNER, now_ms=expires, allow_expired=True) == ENVS['letter']


def test_encryption_recipient_size_and_time_checks_happen_before_hpke(monkeypatch):
    monkeypatch.setattr(mail, '_suite', lambda: pytest.fail('must not encrypt invalid input'))
    with pytest.raises(AgentProtocolError):
        encrypt_mail(ENVS['letter'], ENVS['disabled_card'], now_ms=NOW)
    other = signed_change(ENVS['letter'], SENDER, to=SENDER.agent_id())
    with pytest.raises(AgentProtocolError):
        encrypt_mail(other, ENVS['card'], now_ms=NOW)
    large = signed_change(ENVS['letter'], SENDER, parts=[mail_part('application/octet-stream', bytes(5000))])
    with pytest.raises(AgentProtocolError) as err:
        encrypt_mail(large, ENVS['small_limit_card'], now_ms=NOW)
    assert err.value.code == 'payload_too_large'
    long = signed_change(ENVS['letter'], SENDER, expires_at=NOW+3*DAY)
    with pytest.raises(AgentProtocolError):
        encrypt_mail(long, ENVS['card'], now_ms=NOW)


def test_snapshot_pins_survive_expiry_equivocation_and_key_history():
    cache = MailCardCache()
    cache.observe(ENVS['card'], OWNER, now_ms=NOW)
    with pytest.raises(AgentProtocolError):
        cache.observe(ENVS['equivocating_card'], OWNER, now_ms=NOW)
    restored = MailCardCache.from_snapshot(cache.snapshot())
    with pytest.raises(AgentProtocolError):
        restored.get(OWNER, MAILBOX, now_ms=NOW)
    restored.observe(ENVS['rotated_card'], OWNER, now_ms=NOW)
    with pytest.raises(AgentProtocolError):
        restored.observe(ENVS['key_reuse_card'], OWNER, now_ms=NOW)
    exposed = restored.get(OWNER, MAILBOX, now_ms=NOW)
    exposed['event']['payload']['enabled'] = False
    assert restored.get(OWNER, MAILBOX, now_ms=NOW)['event']['payload']['enabled'] is True
    with pytest.raises(AgentProtocolError):
        restored.observe(ENVS['disabled_card'], OWNER, now_ms=NOW)
    with pytest.raises(AgentProtocolError):
        MailCardCache.from_snapshot(restored.snapshot()).observe(ENVS['rotated_card'], OWNER, now_ms=NOW+4*DAY)


def test_sender_preserves_letter_id_and_refuses_expired_renewal():
    sender = MailSender(MailCardCache(), MailOutbox(SENDER.agent_id()))
    first = sender.prepare(ENVS['letter'], ENVS['card'], now_ms=NOW)
    second = sender.retry(ENVS['letter']['hash'], ENVS['rotated_card'], now_ms=NOW+1)
    assert first['header']['card_hash'] != second['header']['card_hash']
    assert sender.outbox.letter(ENVS['letter']['hash']) == ENVS['letter']
    outbox = MailOutbox.from_snapshot(sender.outbox.snapshot())
    assert outbox.letter(ENVS['letter']['hash']) == ENVS['letter']
    with pytest.raises(AgentProtocolError):
        sender.retry(ENVS['letter']['hash'], ENVS['card'], now_ms=NOW+DAY+1000)
    with pytest.raises(AgentProtocolError):
        outbox.verify_receipt(ENVS['receipt'])
    outbox.mark_sent(ENVS['letter']['hash'])
    outbox.verify_receipt(ENVS['receipt'])
    outbox.letter(ENVS['letter']['hash'])['event']['payload']['to'] = 'mutated'
    outbox.verify_receipt(ENVS['receipt'])


def test_inbox_atomic_dedup_and_poisoned_packet_does_not_block_next():
    inbox = MailInbox(ring())
    bad = V['recipient_rejections'][0]['packet']
    with pytest.raises(AgentProtocolError):
        inbox.accept(bad, now_ms=NOW)
    packets = [V['encryptions'][name]['packet'] for name in ('original','reencrypted','rotated')]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda n: inbox.accept(packets[n % 3], now_ms=NOW), range(24)))
    assert sum(r['kind'] == 'accepted' for r in results) == 1
    assert len(inbox.snapshot()['accepted']) == 1
    results[0]['letter']['event']['payload']['subject'] = 'mutated'
    assert inbox.letter(ENVS['letter']['hash']) == ENVS['letter']
    other = MailInbox(ring())
    with pytest.raises(AgentProtocolError) as err:
        other.accept(packets[0], now_ms=NOW, policy=lambda _: False)
    assert err.value.code == 'permission_denied'
    assert other.snapshot()['accepted'] == []


def test_keyring_old_secret_retention_and_prune_keeps_key_history():
    keys = MailKeyring(OWNER)
    keys.add(ENVS['card'], key_for(ENVS['card']))
    keys.add(ENVS['rotated_card'], key_for(ENVS['rotated_card']))
    keys.add(ENVS['disabled_card'], key_for(ENVS['disabled_card']))
    assert keys.prune(now_ms=NOW+DAY) == 0
    assert keys.decrypt(V['encryptions']['original']['packet'], now_ms=NOW+DAY+500) == ENVS['letter']
    restored = MailKeyring.from_snapshot(keys.snapshot())
    assert restored.prune(now_ms=NOW+2*DAY) == 3
    with pytest.raises(AgentProtocolError):
        restored.decrypt(V['encryptions']['original']['packet'], now_ms=NOW)
    with pytest.raises(AgentProtocolError):
        MailKeyring.from_snapshot(restored.snapshot()).add(ENVS['key_reuse_card'], key_for(ENVS['rotated_card']))


def receipt_inbox():
    sender_key = MailEncryptionKey.generate()
    payload = {**ENVS['card']['event']['payload'], 'mailbox_id': new_mail_id(), 'key_id': new_mail_id(), 'public_key': sender_key.public_key()}
    card = sign_mail_event(SENDER, mailbox_publish_event(SENDER.agent_id(), NOW, 500, payload))
    keys = MailKeyring(SENDER.agent_id())
    keys.add(card, sender_key)
    return keys, card


def test_inbox_enforces_actual_sent_message_receipt_binding_and_restore():
    keys, card = receipt_inbox()
    packet = encrypt_mail(ENVS['receipt'], card, now_ms=NOW)
    with pytest.raises(AgentProtocolError):
        MailInbox(keys).accept(packet, now_ms=NOW)
    outbox = MailOutbox(SENDER.agent_id())
    inbox = MailInbox(keys, outbox)
    outbox.retain(ENVS['letter'])
    with pytest.raises(AgentProtocolError):
        inbox.accept(packet, now_ms=NOW)
    outbox.mark_sent(ENVS['letter']['hash'])
    assert inbox.accept(packet, now_ms=NOW)['kind'] == 'accepted'
    restored = MailInbox.from_snapshot(keys, inbox.snapshot(), outbox)
    assert restored.accept(packet, now_ms=NOW)['kind'] == 'duplicate'
    with pytest.raises(AgentProtocolError):
        MailInbox.from_snapshot(keys, inbox.snapshot())
    forged = SENDER.sign_event({**ENVS['receipt']['event'], 'actor': SENDER.agent_id()})
    with pytest.raises(AgentProtocolError):
        inbox.accept(encrypt_mail(forged, card, now_ms=NOW), now_ms=NOW)
    unknown = signed_change(ENVS['receipt'], nonce=301, message_hash=ENVS['lower_nonce_letter']['hash'])
    with pytest.raises(AgentProtocolError):
        inbox.accept(encrypt_mail(unknown, card, now_ms=NOW), now_ms=NOW)


def test_reply_links_require_participants_and_thread():
    parent = ENVS['letter']
    payload = {**parent['event']['payload'], 'to': SENDER.agent_id(), 'in_reply_to': parent['hash']}
    reply = sign_mail_event(RECIPIENT, mail_message_event(OWNER, NOW, 501, payload))
    validate_mail_reply(reply, parent)
    for changes in ({'thread_id': new_mail_id()}, {'to': OWNER}, {'in_reply_to': ENVS['lower_nonce_letter']['hash']}):
        with pytest.raises(AgentProtocolError):
            validate_mail_reply(signed_change(reply, **changes), parent)


def test_relay_publication_atomic_nonce_ownership_retry_and_history():
    shared = MailNonceStore()
    relay = MailRelayStore(ORIGIN, nonce_store=shared)
    accepted = relay.publish(ENVS['card'], now_ms=NOW)
    assert relay.publish(ENVS['card'], now_ms=NOW+50*DAY) == accepted
    relay.publish(ENVS['rotated_card'], now_ms=NOW)
    assert relay.publish(ENVS['card'], now_ms=NOW)['envelope'] == ENVS['card']
    assert relay.card(MAILBOX)['envelope'] == ENVS['rotated_card']
    replacement = signed_change(ENVS['card'], nonce=99, created_at=NOW+DAY, expires_at=NOW+2*DAY, receive_until=NOW+3*DAY)
    with pytest.raises(AgentProtocolError) as err:
        relay.publish(replacement, now_ms=NOW+DAY)
    assert err.value.code == 'nonce_not_greater' and err.value.data['max_nonce'] == 101
    foreign = SENDER.sign_event({**replacement['event'], 'actor': SENDER.agent_id(), 'nonce': 700})
    with pytest.raises(AgentProtocolError) as err:
        relay.publish(foreign, now_ms=NOW+DAY)
    assert err.value.code == 'mailbox_conflict'
    with pytest.raises(AgentProtocolError):
        relay.publish(ENVS['key_reuse_card'], now_ms=NOW)
    assert shared.max_nonce(OWNER, NOW) == 101
    other_box = signed_change(ENVS['card'], nonce=101, mailbox_id=new_mail_id())
    with pytest.raises(AgentProtocolError):
        relay.publish(other_box, now_ms=NOW)
    assert relay.card(MAILBOX)['envelope'] == ENVS['rotated_card']
    with pytest.raises(AgentProtocolError):
        MailRelayStore.from_snapshot(relay.snapshot())
    restored = MailRelayStore.from_snapshot(relay.snapshot(), nonce_store=MailNonceStore.from_snapshot(shared.snapshot()))
    assert restored.card(MAILBOX) == relay.card(MAILBOX)


def test_relay_nonce_store_can_coordinate_two_services():
    shared = MailNonceStore()
    first, second = MailRelayStore(ORIGIN, nonce_store=shared), MailRelayStore('https://mirror.example', nonce_store=shared)
    first.publish(ENVS['card'], now_ms=NOW)
    with pytest.raises(AgentProtocolError) as err:
        second.publish(ENVS['card'], now_ms=NOW)
    assert err.value.code == 'nonce_not_greater'
    # Separate origins normally use distinct nonce stores; sharing is explicit.
    independent = MailRelayStore('https://mirror.example')
    independent.publish(ENVS['card'], now_ms=NOW)


def test_relay_concurrent_delivery_delete_tombstone_and_quota_are_atomic():
    relay = MailRelayStore(ORIGIN, max_packets_per_mailbox=1)
    relay.publish(ENVS['card'], now_ms=NOW)
    packet = V['encryptions']['original']['packet']
    with ThreadPoolExecutor(max_workers=8) as pool:
        accepted = list(pool.map(lambda _: relay.deliver(MAILBOX, packet, now_ms=NOW), range(30)))
    assert all(r == accepted[0] for r in accepted)
    with pytest.raises(AgentProtocolError) as err:
        relay.deliver(MAILBOX, V['encryptions']['reencrypted']['packet'], now_ms=NOW)
    assert err.value.code == 'quota_exceeded'
    relay.delete(MAILBOX, accepted[0]['packet_id'], TOKEN, now_ms=NOW)
    relay.delete(MAILBOX, accepted[0]['packet_id'], TOKEN, now_ms=NOW)
    assert relay.deliver(MAILBOX, packet, now_ms=NOW+1) == accepted[0]
    assert relay.list_packets(MAILBOX, TOKEN, now_ms=NOW)['result'] == []
    next_result = relay.deliver(MAILBOX, V['encryptions']['reencrypted']['packet'], now_ms=NOW+2)
    assert next_result['seq'] == 2
    snapshot = relay.snapshot()
    snapshot['current'].clear()
    assert relay.card(MAILBOX)['envelope'] == ENVS['card']


def test_relay_pagination_checkpoint_owner_binding_and_restart():
    relay = MailRelayStore(ORIGIN)
    relay.publish(ENVS['card'], now_ms=NOW)
    for name in ('original', 'reencrypted', 'lower_nonce'):
        relay.deliver(MAILBOX, V['encryptions'][name]['packet'], now_ms=NOW)
    first = relay.list_packets(MAILBOX, TOKEN, limit=1, now_ms=NOW)
    cursor = first['next_cursor']
    relay = MailRelayStore.from_snapshot(relay.snapshot())
    fourth = encrypt_mail(ENVS['letter'], ENVS['card'], now_ms=NOW)
    relay.deliver(MAILBOX, fourth, now_ms=NOW)
    second = relay.list_packets(MAILBOX, TOKEN, limit=2, cursor=cursor, now_ms=NOW)
    assert [r['seq'] for r in second['result']] == [2, 3]
    assert 'next_cursor' not in second
    assert len(relay.list_packets(MAILBOX, TOKEN, now_ms=NOW)['result']) == 4
    other_card = signed_change(ENVS['card'], nonce=800, mailbox_id=new_mail_id())
    relay.publish(other_card, now_ms=NOW)
    with pytest.raises(AgentProtocolError) as err:
        relay.list_packets(other_card['event']['payload']['mailbox_id'], TOKEN, cursor=cursor, now_ms=NOW)
    assert err.value.code == 'invalid_cursor'
    with pytest.raises(AgentProtocolError):
        relay.list_packets(MAILBOX, TOKEN, cursor=cursor[:-1]+'!', now_ms=NOW)
    with pytest.raises(AgentProtocolError) as err:
        relay.list_packets(MAILBOX, token(SENDER), now_ms=NOW)
    assert err.value.code == 'permission_denied'
    with pytest.raises(AgentProtocolError):
        relay.delete(MAILBOX, first['result'][0]['packet_id'], token(SENDER), now_ms=NOW)


def test_relay_raw_bounds_strict_json_and_packet_path_binding():
    relay = MailRelayStore(ORIGIN)
    relay.publish(json.dumps(ENVS['card']), now_ms=NOW)
    raw = json.dumps(V['encryptions']['original']['packet'])
    assert relay.deliver(MAILBOX, raw, now_ms=NOW)['seq'] == 1
    with pytest.raises(AgentProtocolError):
        relay.deliver(MAILBOX, raw + ' ' * relay.max_body_bytes, now_ms=NOW)
    with pytest.raises(AgentProtocolError):
        relay.deliver(MAILBOX, raw[:-1] + ',"enc":"bad"}', now_ms=NOW)
    with pytest.raises(AgentProtocolError):
        relay.deliver(new_mail_id(), raw, now_ms=NOW)
    # Relay remains opaque: well-shaped attacker ciphertext can be accepted.
    bad = next(c['packet'] for c in V['recipient_rejections'] if c['name']=='tampered ciphertext')
    assert relay.deliver(MAILBOX, bad, now_ms=NOW)['seq'] == 2


def test_future_skew_max_ttl_relay_upper_boundary():
    card = signed_change(ENVS['card'], nonce=900, created_at=NOW+mail.MAIL_FUTURE_SKEW_MS,
                         expires_at=NOW+mail.MAIL_FUTURE_SKEW_MS+mail.MAIL_MAX_TTL_MS,
                         receive_until=NOW+mail.MAIL_FUTURE_SKEW_MS+mail.MAIL_MAX_TTL_MS)
    letter = signed_change(ENVS['letter'], SENDER, nonce=901, created_at=NOW+mail.MAIL_FUTURE_SKEW_MS,
                           expires_at=NOW+mail.MAIL_FUTURE_SKEW_MS+mail.MAIL_MAX_TTL_MS)
    packet = encrypt_mail(letter, card, now_ms=NOW)
    relay = MailRelayStore(ORIGIN)
    relay.publish(card, now_ms=NOW)
    assert relay.deliver(MAILBOX, packet, now_ms=NOW)['seq'] == 1
    packet['header']['expires_at'] += 1
    with pytest.raises(AgentProtocolError):
        relay.deliver(MAILBOX, packet, now_ms=NOW)


@pytest.mark.parametrize('claims', [
    {'exp': NOW//1000}, {'iat': True}, {'exp': float('nan')}, {'exp': NOW//1000 + 0.5},
    {'iat': NOW//1000+1}, {'exp': NOW//1000+301}, {'aud': ORIGIN+'/path'},
])
def test_strict_jwt_boundary_rejections(claims):
    with pytest.raises(AgentProtocolError):
        verify_mail_owner_jwt(token(**claims), OWNER, ORIGIN, now_ms=NOW)


def test_owner_jwt_rejects_signed_duplicate_json_members():
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(V['keys']['recipient_seed_hex']))
    header = mail._b64(json.dumps({'alg':'EdDSA','typ':'JWT','kid':OWNER}).encode())
    payload = ('{"iss":'+json.dumps(OWNER)+',"sub":'+json.dumps(OWNER)+',"aud":'+json.dumps(ORIGIN)
               +',"iat":'+str(NOW//1000)+',"exp":'+str(NOW//1000+300)+',"exp":'+str(NOW//1000+299)+'}')
    unsigned = header+'.'+mail._b64(payload.encode())
    jwt = unsigned+'.'+mail._b64(key.sign(unsigned.encode()))
    with pytest.raises(AgentProtocolError) as err:
        verify_mail_owner_jwt(jwt, OWNER, ORIGIN, now_ms=NOW)
    assert err.value.code == 'invalid_token'
