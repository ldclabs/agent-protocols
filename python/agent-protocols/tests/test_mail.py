import copy
import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_protocols import (
    AgentSigner, AgentProtocolError, MailCardCache, MailEncryptionKey, MailInbox,
    MailKeyring, MailRelayStore, MemoryNonceStore, decrypt_mail, encrypt_mail as sdk_encrypt_mail,
    create_mail_message, mail_part, new_mail_id, sign_mail_event, validate_mail_reply,
    verify_mail_owner_jwt,
)
from agent_protocols import mail
from test_mail_vectors import ENVS, MAILBOX, NOW, ORIGIN, OWNER, TOKEN, V, code_of, key_for, packet, ring

SENDER = AgentSigner.from_seed(bytes.fromhex(V['keys']['sender_seed_hex']))
RECIPIENT = AgentSigner.from_seed(bytes.fromhex(V['keys']['recipient_seed_hex']))
DAY = 86_400_000
from itertools import count
NONCES = count(1000)

def encrypt_mail(message, card, **options):
    return sdk_encrypt_mail(message, card, SENDER, next(NONCES), **options)



def signed_change(original, signer=RECIPIENT, *, nonce=None, created_at=None, **payload):
    if 'event' not in original:
        result = {**copy.deepcopy(original), **payload}
        if created_at is not None: result['created_at'] = created_at
        return result
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
        sdk_encrypt_mail(ENVS['message'], ENVS['card'], RECIPIENT, 400, now_ms=NOW)
    source = {k: copy.deepcopy(v) for k,v in ENVS['message'].items() if k not in ('message_id','from','created_at')}
    message = create_mail_message(SENDER.agent_id(), NOW, source)
    source['to'] = 'changed'
    assert message['to'] == OWNER and message['from'] == SENDER.agent_id()
    assert len(mail._decode(message['message_id'])) == 16
    mail.validate_mail_message(message)


def test_crypto_randomness_and_malformed_card():
    one = encrypt_mail(ENVS['message'], ENVS['card'], now_ms=NOW)
    two = encrypt_mail(ENVS['message'], ENVS['card'], now_ms=NOW)
    assert one != two and one['event']['payload']['enc'] != two['event']['payload']['enc']
    assert decrypt_mail(one, ENVS['card'], key_for(ENVS['card']), OWNER, now_ms=NOW) == ENVS['message']
    for malformed in ({}, {'event': {}}, {'event': {'payload': None}}, None):
        with pytest.raises(AgentProtocolError):
            encrypt_mail(ENVS['message'], malformed, now_ms=NOW)


def test_encryption_checks_happen_before_hpke(monkeypatch):
    monkeypatch.setattr(mail, '_suite', lambda: pytest.fail('must not encrypt invalid input'))
    assert code_of(lambda: encrypt_mail(ENVS['message'], ENVS['closed_card'], now_ms=NOW)) == 'mailbox_unavailable'
    other = signed_change(ENVS['message'], SENDER, to=SENDER.agent_id())
    assert code_of(lambda: encrypt_mail(other, ENVS['card'], now_ms=NOW)) == 'invalid_actor'
    large = signed_change(ENVS['message'], SENDER, parts=[mail_part('application/octet-stream', bytes(5000))])
    assert code_of(lambda: encrypt_mail(large, ENVS['small_limit_card'], now_ms=NOW)) == 'payload_too_large'
    long = signed_change(ENVS['message'], SENDER, expires_at=NOW+3*DAY)
    assert code_of(lambda: encrypt_mail(long, ENVS['card'], now_ms=NOW)) == 'invalid_packet'
    assert code_of(lambda: encrypt_mail(ENVS['message'], ENVS['card'], now_ms=NOW+DAY+1000)) == 'stale_card'


def test_card_cache_seal_pins_and_prunes():
    cache = MailCardCache()
    sealed = cache.seal(ENVS['message'], ENVS['card'], SENDER, next(NONCES), now_ms=NOW)
    assert ring().open(sealed, now_ms=NOW) == ENVS['message']
    cache.observe(ENVS['rotated_card'], OWNER, now_ms=NOW)
    assert code_of(lambda: cache.seal(ENVS['message'], ENVS['card'], SENDER, next(NONCES), now_ms=NOW)) == 'stale_card'
    exposed = cache.observe(ENVS['rotated_card'], OWNER, now_ms=NOW)
    exposed['event']['payload']['routes'] = []
    assert cache.observe(ENVS['rotated_card'], OWNER, now_ms=NOW)['event']['payload']['routes']
    cache.prune(now_ms=NOW + mail.MAIL_MAX_TTL_MS + mail.MAIL_FUTURE_SKEW_MS)
    assert cache.snapshot()['pins'] == []


def test_inbox_atomic_dedup_and_poisoned_packet_does_not_block_next():
    inbox = MailInbox(ring())
    with pytest.raises(AgentProtocolError):
        inbox.accept(V['recipient_rejections'][0]['packet'], now_ms=NOW)
    packets = [packet(name) for name in ('original', 'reencrypted', 'rotated')]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda n: inbox.accept(packets[n % 3], now_ms=NOW), range(24)))
    assert sum(r['kind'] == 'accepted' for r in results) == 1
    assert inbox.has(SENDER.agent_id(), ENVS['message']['message_id'])
    inbox.prune(now_ms=ENVS['message']['expires_at'])
    assert not inbox.has(SENDER.agent_id(), ENVS['message']['message_id'])


def test_keyring_old_secret_retention_and_prune():
    keys = ring()
    assert keys.prune(now_ms=NOW+DAY) == 0
    assert keys.open(packet('original'), now_ms=NOW+DAY+500) == ENVS['message']
    restored = MailKeyring.from_snapshot(keys.snapshot())
    assert restored.prune(now_ms=NOW+2*DAY) == 3
    assert code_of(lambda: restored.open(packet('original'), now_ms=NOW)) == 'invalid_packet'
    assert code_of(lambda: MailKeyring(OWNER).add(ENVS['card'], key_for(ENVS['rotated_card']))) == 'invalid_private_key'


def test_reply_links_require_participants_and_thread():
    parent = ENVS['message']
    payload = {**parent, 'to': SENDER.agent_id(), 'in_reply_to': parent['message_id']}
    reply = {**payload, 'from': OWNER, 'message_id': mail.new_mail_id()}
    validate_mail_reply(reply, parent)
    for changes in ({'thread_id': new_mail_id()}, {'to': OWNER}, {'in_reply_to': ENVS['lower_nonce_message']['message_id']}):
        with pytest.raises(AgentProtocolError):
            validate_mail_reply(signed_change(reply, **changes), parent)


def test_relay_publication_atomic_nonce_ownership_and_retry():
    shared = MemoryNonceStore()
    relay = MailRelayStore(ORIGIN, nonce_store=shared)
    accepted = relay.publish(ENVS['card'], now_ms=NOW)
    assert relay.publish(ENVS['card'], now_ms=NOW+50*DAY) == accepted
    relay.publish(ENVS['rotated_card'], now_ms=NOW)
    err = pytest.raises(AgentProtocolError, relay.publish, ENVS['card'], now_ms=NOW).value
    assert err.code == 'nonce_not_greater' and err.data['max_nonce'] == 101
    assert code_of(lambda: relay.publish(ENVS['foreign_card'], now_ms=NOW)) == 'mailbox_conflict'
    stale = signed_change(ENVS['card'], nonce=999, mailbox_id=new_mail_id(), created_at=NOW-mail.MAIL_FUTURE_SKEW_MS-1)
    assert code_of(lambda: relay.publish(stale, now_ms=NOW)) == 'timestamp_out_of_window'
    assert shared.max_nonce(OWNER, NOW) == 101
    other_box = signed_change(ENVS['card'], nonce=101, mailbox_id=new_mail_id())
    assert code_of(lambda: relay.publish(other_box, now_ms=NOW)) == 'nonce_not_greater'
    assert relay.card(MAILBOX)['envelope'] == ENVS['rotated_card']
    restored = MailRelayStore.from_snapshot(relay.snapshot(), nonce_store=shared)
    assert restored.card(MAILBOX) == relay.card(MAILBOX)


def test_relay_concurrent_delivery_delete_tombstone_and_quota_are_atomic():
    relay = MailRelayStore(ORIGIN, max_packets=1)
    relay.publish(ENVS['card'], now_ms=NOW)
    with ThreadPoolExecutor(max_workers=8) as pool:
        accepted = list(pool.map(lambda _: relay.deliver(MAILBOX, packet('original'), now_ms=NOW), range(30)))
    assert all(r == accepted[0] for r in accepted) and set(accepted[0]) == {'packet_id', 'accepted_at'}
    assert code_of(lambda: relay.deliver(MAILBOX, packet('reencrypted'), now_ms=NOW)) == 'rate_limited'
    relay.delete(MAILBOX, accepted[0]['packet_id'], TOKEN, now_ms=NOW)
    relay.delete(MAILBOX, accepted[0]['packet_id'], TOKEN, now_ms=NOW)
    assert relay.deliver(MAILBOX, packet('original'), now_ms=NOW+1) == accepted[0]
    assert relay.list(MAILBOX, TOKEN, now_ms=NOW)['result'] == []
    relay.deliver(MAILBOX, packet('reencrypted'), now_ms=NOW+2)
    assert [r['seq'] for r in relay.list(MAILBOX, TOKEN, now_ms=NOW)['result']] == [2]


def test_relay_prune_forgets_mailbox_after_receive_until():
    relay = MailRelayStore(ORIGIN)
    relay.publish(ENVS['card'], now_ms=NOW)
    relay.deliver(MAILBOX, packet('original'), now_ms=NOW)
    receive_until = ENVS['card']['event']['payload']['receive_until']
    relay.prune(now_ms=receive_until - 1)
    assert relay.card(MAILBOX)['envelope'] == ENVS['card'] and relay.snapshot()['mailboxes'][0]['packets'] == []
    relay.prune(now_ms=receive_until)
    assert code_of(lambda: relay.card(MAILBOX)) == 'mailbox_unavailable'
    assert code_of(lambda: relay.deliver(MAILBOX, packet('original'), now_ms=NOW)) == 'mailbox_unavailable'
    # A later card is a new registration and must list this relay again.
    assert code_of(lambda: relay.publish(ENVS['moved_card'], now_ms=NOW)) == 'permission_denied'
    assert relay.publish(ENVS['rotated_card'], now_ms=NOW)['accepted_at'] == NOW


def test_relay_pagination_owner_binding_and_restart():
    relay = MailRelayStore(ORIGIN)
    relay.publish(ENVS['card'], now_ms=NOW)
    for name in ('lower_nonce', 'original', 'reencrypted'):
        relay.deliver(MAILBOX, packet(name), now_ms=NOW)
    first = relay.list(MAILBOX, TOKEN, limit=1, now_ms=NOW)
    assert first['next_cursor'] == '1'
    relay = MailRelayStore.from_snapshot(relay.snapshot())
    relay.delete(MAILBOX, first['result'][0]['packet_id'], TOKEN, now_ms=NOW)
    second = relay.list(MAILBOX, TOKEN, limit=2, cursor=first['next_cursor'], now_ms=NOW)
    assert [r['seq'] for r in second['result']] == [2, 3] and 'next_cursor' not in second
    for cursor in ('', '-1', '01', 'x', '1' * 17, '9' * 5000):
        assert code_of(lambda: relay.list(MAILBOX, TOKEN, cursor=cursor, now_ms=NOW)) == 'invalid_request'
    assert code_of(lambda: relay.list(MAILBOX, 'bad', now_ms=NOW)) == 'invalid_token'
    assert code_of(lambda: relay.list(MAILBOX, token(SENDER), now_ms=NOW)) == 'permission_denied'
    assert code_of(lambda: relay.list(new_mail_id(), TOKEN, now_ms=NOW)) == 'mailbox_unavailable'
    assert code_of(lambda: relay.delete(MAILBOX, second['result'][0]['packet_id'], token(SENDER), now_ms=NOW)) == 'permission_denied'


def test_relay_raw_bounds_strict_json_route_change_and_path_binding():
    relay = MailRelayStore(ORIGIN)
    relay.publish(json.dumps(ENVS['card']), now_ms=NOW)
    raw = json.dumps(V['encryptions']['original']['packet'])
    assert relay.deliver(MAILBOX, raw, now_ms=NOW)['accepted_at'] == NOW
    with pytest.raises(AgentProtocolError):
        relay.deliver(MAILBOX, raw + ' ' * relay.max_body_bytes, now_ms=NOW)
    with pytest.raises(AgentProtocolError):
        relay.deliver(MAILBOX, raw[:-1] + ',"enc":"bad"}', now_ms=NOW)
    assert code_of(lambda: relay.deliver(new_mail_id(), raw, now_ms=NOW)) == 'invalid_packet'
    # A valid sender signature still cannot prove ciphertext decryptability.
    assert code_of(lambda: relay.deliver(MAILBOX, V['recipient_rejections'][0]['packet'], now_ms=NOW)) == 'invalid_event_hash'
    bad = signed_change(next(c['packet'] for c in V['recipient_rejections'] if c['name'] == 'wrong HPKE AAD'), SENDER, nonce=900)
    assert relay.deliver(MAILBOX, bad, now_ms=NOW)['accepted_at'] == NOW
    relay.publish(ENVS['moved_card'], now_ms=NOW)
    assert code_of(lambda: relay.deliver(MAILBOX, packet('reencrypted'), now_ms=NOW)) == 'mailbox_unavailable'
    assert len(relay.list(MAILBOX, TOKEN, now_ms=NOW)['result']) == 2


def test_future_skew_max_ttl_relay_upper_boundary():
    card = signed_change(ENVS['card'], nonce=900, created_at=NOW+mail.MAIL_FUTURE_SKEW_MS,
                         expires_at=NOW+mail.MAIL_FUTURE_SKEW_MS+mail.MAIL_MAX_TTL_MS,
                         receive_until=NOW+mail.MAIL_FUTURE_SKEW_MS+mail.MAIL_MAX_TTL_MS)
    message = signed_change(ENVS['message'], SENDER, nonce=901, created_at=NOW+mail.MAIL_FUTURE_SKEW_MS,
                           expires_at=NOW+mail.MAIL_FUTURE_SKEW_MS+mail.MAIL_MAX_TTL_MS)
    sealed = encrypt_mail(message, card, now_ms=NOW)
    relay = MailRelayStore(ORIGIN)
    relay.publish(card, now_ms=NOW)
    assert relay.deliver(MAILBOX, sealed, now_ms=NOW)['accepted_at'] == NOW
    sealed['event']['payload']['header']['expires_at'] += 1
    assert code_of(lambda: relay.deliver(MAILBOX, sealed, now_ms=NOW)) == 'invalid_event_hash'


@pytest.mark.parametrize('claims', [
    {'exp': NOW//1000}, {'iat': True}, {'exp': NOW//1000 + 0.5},
    {'iat': NOW//1000+1}, {'exp': NOW//1000+301}, {'aud': ORIGIN+'/path'},
])
def test_strict_jwt_boundary_rejections(claims):
    assert code_of(lambda: verify_mail_owner_jwt(token(**claims), OWNER, ORIGIN, now_ms=NOW)) == 'invalid_token'


def test_owner_jwt_rejects_signed_duplicate_json_members():
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(V['keys']['recipient_seed_hex']))
    header = mail._b64(json.dumps({'alg': 'EdDSA', 'typ': 'JWT', 'kid': OWNER}).encode())
    payload = ('{"iss":'+json.dumps(OWNER)+',"sub":'+json.dumps(OWNER)+',"aud":'+json.dumps(ORIGIN)
               +',"iat":'+str(NOW//1000)+',"exp":'+str(NOW//1000+300)+',"exp":'+str(NOW//1000+299)+'}')
    unsigned = header+'.'+mail._b64(payload.encode())
    jwt = unsigned+'.'+mail._b64(key.sign(unsigned.encode()))
    assert code_of(lambda: verify_mail_owner_jwt(jwt, OWNER, ORIGIN, now_ms=NOW)) == 'invalid_token'


def test_outer_sender_policy_before_decryption_and_relay_policy(monkeypatch):
    inbox = MailInbox(MailKeyring(OWNER))  # No key available: blocking must happen first.
    inbox.set_sender_blocked(SENDER.agent_id())
    assert code_of(lambda: inbox.accept(packet('original'), now_ms=NOW)) == 'permission_denied'
    broken = packet('original'); broken['signature'] = mail._b64(bytes(64))
    assert code_of(lambda: inbox.accept(broken, now_ms=NOW)) == 'invalid_signature'
    restored = MailInbox.from_snapshot(inbox.keyring, inbox.snapshot())
    assert code_of(lambda: restored.accept(packet('original'), now_ms=NOW)) == 'permission_denied'

    relay = MailRelayStore(ORIGIN)
    assert code_of(lambda: relay.set_sender_blocked(MAILBOX, SENDER.agent_id(), True)) == 'mailbox_unavailable'
    relay.publish(ENVS['card'], now_ms=NOW)
    relay.set_sender_blocked(MAILBOX, SENDER.agent_id(), True)
    assert code_of(lambda: relay.deliver(MAILBOX, packet('original'), now_ms=NOW)) == 'permission_denied'
    relay.set_sender_blocked(MAILBOX, SENDER.agent_id(), False)
    accepted = relay.deliver(MAILBOX, packet('original'), now_ms=NOW)
    relay.set_sender_blocked(MAILBOX, SENDER.agent_id(), True)
    relay.delete(MAILBOX, accepted['packet_id'], TOKEN, now_ms=NOW)
    relay = MailRelayStore.from_snapshot(relay.snapshot())
    assert relay.deliver(MAILBOX, packet('original'), now_ms=NOW+1) == accepted
    assert code_of(lambda: relay.deliver(MAILBOX, packet('reencrypted'), now_ms=NOW)) == 'permission_denied'
    assert relay.list(MAILBOX, TOKEN, now_ms=NOW)['result'] == []


def test_packets_are_not_live_writes_at_relays_or_recipients():
    nonces = MemoryNonceStore()
    relay = MailRelayStore(ORIGIN, nonce_store=nonces)
    relay.publish(ENVS['card'], now_ms=NOW)
    first = relay.deliver(MAILBOX, packet('original'), now_ms=NOW)
    relay = MailRelayStore.from_snapshot(relay.snapshot(), nonce_store=nonces)
    # A lower nonce signed well outside the live-write window is still new mail.
    late = NOW + 2 * mail.MAIL_FUTURE_SKEW_MS
    relay.deliver(MAILBOX, packet('lower_nonce'), now_ms=late)
    relay.deliver(MAILBOX, packet('reencrypted'), now_ms=late)
    assert relay.deliver(MAILBOX, packet('original'), now_ms=late) == first
    assert nonces.max_nonce(SENDER.agent_id(), NOW) is None
    assert len(relay.list(MAILBOX, TOKEN, now_ms=NOW)['result']) == 3
    inbox = MailInbox(ring())
    assert inbox.accept(packet('reencrypted'),now_ms=NOW+DAY)['kind'] == 'accepted'
    assert inbox.accept(packet('original'),now_ms=NOW+DAY)['kind'] == 'duplicate'
    assert inbox.accept(packet('lower_nonce'),now_ms=NOW+DAY)['kind'] == 'accepted'


def test_logical_id_conflict_is_not_an_overwrite_and_id_is_scoped_to_sender():
    case=V['lifecycle']['message_conflict']
    inbox=MailInbox(ring());inbox.accept(packet(case['first']),now_ms=NOW)
    before=inbox.snapshot()
    assert code_of(lambda: inbox.accept(packet(case['second']),now_ms=NOW)) == case['expected']
    assert inbox.snapshot()==before
    same_id_other_sender={**ENVS['message'],'from':OWNER}
    other=sdk_encrypt_mail(same_id_other_sender,ENVS['card'],RECIPIENT,1000,now_ms=NOW)
    assert inbox.accept(other,now_ms=NOW)['kind']=='accepted'
    assert len(inbox.snapshot()['accepted'])==2
