import copy
import io
import json
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
from requests.adapters import BaseAdapter

from agent_protocols import AgentProtocolError, MailRelayStore
from agent_protocols.http_client import HttpResponseError, MailClient, mail_public_network_policy
from test_mail import token
from test_mail_vectors import ENVS, MAILBOX, NOW, ORIGIN, OWNER, TOKEN, V


class Adapter(BaseAdapter):
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def send(self, request, **options):
        self.calls.append((request, options))
        entry = self.responses.pop(0)
        value, status, headers = entry if isinstance(entry, tuple) else (entry, 200, {})
        data = value if isinstance(value, bytes) else json.dumps(value).encode()
        response = requests.Response()
        response.request = request
        response.url = request.url
        response.status_code = status
        response.headers.update(headers)
        response.raw = io.BytesIO(data)
        return response

    def close(self):
        pass


def transport(*responses):
    session = requests.Session()
    adapter = Adapter(responses)
    session.mount('https://', adapter)
    return session, adapter


def populated():
    relay = MailRelayStore(ORIGIN)
    card = relay.publish(ENVS['card'], now_ms=NOW)
    delivery = relay.deliver(MAILBOX, V['encryptions']['original']['packet'], now_ms=NOW)
    return relay, card, delivery


def test_all_http_operations_use_fixed_paths_and_validate_bound_responses():
    relay, card, delivery = populated()
    page = relay.list(MAILBOX, TOKEN, now_ms=NOW)
    discovery = {'protocol': 'agent-mail/1.0', 'service': ORIGIN, 'endpoints': {'mailboxes': ORIGIN + '/ignored'}}
    session, adapter = transport(discovery, card, card, (delivery, 202, {}), page, (b'', 204, {}))
    checked = []
    client = MailClient(ORIGIN, session, network_policy=lambda url: checked.append(url) or True)
    client.protocol()
    assert client.publish(ENVS['card']) == card
    assert client.card(MAILBOX, OWNER, now_ms=NOW) == card
    assert client.deliver(V['encryptions']['original']['packet']) == delivery
    assert client.list(MAILBOX, OWNER, TOKEN, now_ms=NOW) == page
    client.delete(MAILBOX, delivery['packet_id'], OWNER, TOKEN, now_ms=NOW)
    assert len(checked) == len(adapter.calls) == 6
    assert [(request.method, urlsplit(request.url).path) for request, _ in adapter.calls] == [
        ('GET', '/.well-known/agent-mail'), ('POST', '/v1/mailboxes'),
        ('GET', '/v1/mailboxes/'+MAILBOX+'/card'),
        ('POST', '/v1/mailboxes/'+MAILBOX+'/packets'),
        ('GET', '/v1/mailboxes/'+MAILBOX+'/packets'),
        ('DELETE', '/v1/mailboxes/'+MAILBOX+'/packets/'+delivery['packet_id']),
    ]
    for index, (request, options) in enumerate(adapter.calls):
        assert ('Authorization' in request.headers) == (index in (4, 5))
        assert options['proxies'] == {} and options['cert'] is None and options['verify'] is True
        assert options['timeout'] == 30 and options['stream'] is True
    assert parse_qs(urlsplit(adapter.calls[4][0].url).query) == {'limit': ['100']}


def test_anonymous_delivery_drops_real_session_auth_cookies_headers_params_netrc_and_cert(monkeypatch):
    _, _, delivery = populated()
    session, adapter = transport((delivery, 202, {}))
    session.auth = ('secret-user', 'secret-password')
    session.cookies.set('login', 'secret-cookie', domain='relay.example')
    session.headers.update({'Authorization': 'Bearer ambient-identity', 'Cookie': 'login=ambient', 'Proxy-Authorization': 'secret-proxy', 'X-Api-Key': 'secret-key'})
    session.params = {'api_key': 'secret-query'}
    session.cert = '/secret/client-identity.pem'
    session.proxies = {'https': 'https://user:password@proxy.example'}
    session.trust_env = True
    monkeypatch.setattr(requests.sessions, 'get_netrc_auth', lambda *_: pytest.fail('netrc must never be consulted'))
    MailClient(ORIGIN, session).deliver(V['encryptions']['original']['packet'])
    request, options = adapter.calls[0]
    assert not any(name in request.headers for name in ('Authorization', 'Cookie', 'Proxy-Authorization', 'X-Api-Key'))
    assert 'secret' not in request.url and '?' not in request.url
    assert options['cert'] is None and options['proxies'] == {} and options['verify'] is True
    assert session.auth == ('secret-user', 'secret-password')  # Caller session not mutated.


def test_owner_token_is_explicit_and_cannot_be_overridden_by_session_auth():
    relay, _, _ = populated()
    session, adapter = transport(relay.list(MAILBOX, TOKEN, now_ms=NOW))
    session.auth = ('other', 'identity')
    session.headers['Authorization'] = 'Bearer ambient'
    client = MailClient(ORIGIN, session)
    client.list(MAILBOX, OWNER, TOKEN, now_ms=NOW)
    assert adapter.calls[0][0].headers['Authorization'] == 'Bearer '+TOKEN
    with pytest.raises(AgentProtocolError):
        client.list(MAILBOX, OWNER, token(exp=NOW//1000), now_ms=NOW)
    assert len(adapter.calls) == 1


@pytest.mark.parametrize('method', ['protocol', 'deliver', 'list', 'delete'])
def test_redirects_never_follow_or_forward_credentials(method):
    session, adapter = transport((b'', 302, {'Location': 'https://attacker.example/collect'}))
    client = MailClient(ORIGIN, session)
    with pytest.raises(HttpResponseError) as err:
        if method == 'protocol':
            client.protocol()
        elif method == 'deliver':
            client.deliver(V['encryptions']['original']['packet'])
        elif method == 'list':
            client.list(MAILBOX, OWNER, TOKEN, now_ms=NOW)
        else:
            client.delete(MAILBOX, V['encryptions']['original']['packet_id'], OWNER, TOKEN, now_ms=NOW)
    assert err.value.status == 302 and len(adapter.calls) == 1


@pytest.mark.parametrize('case', V['discovery_cases'], ids=lambda c: c['name'])
def test_discovery_vectors_over_http(case):
    session, _ = transport(case['value'])
    client = MailClient(ORIGIN, session)
    if case['expected'] == 'valid':
        client.protocol()
    else:
        with pytest.raises(AgentProtocolError):
            client.protocol()


def test_card_read_pins_moved_and_closed_cards_and_rejects_rollback():
    moved = {'envelope': ENVS['moved_card'], 'accepted_at': NOW}
    closed = {'envelope': ENVS['closed_card'], 'accepted_at': NOW}
    old = {'envelope': ENVS['rotated_card'], 'accepted_at': NOW}
    session, _ = transport(moved, closed, old)
    client = MailClient(ORIGIN, session)
    assert client.card(MAILBOX, OWNER, now_ms=NOW)['envelope']['event']['payload']['routes'] == ['https://mirror.example']
    client.card(MAILBOX, OWNER, now_ms=NOW)
    with pytest.raises(AgentProtocolError) as err:
        client.card(MAILBOX, OWNER, now_ms=NOW)
    assert err.value.code == 'stale_card'
    for bad in ({'envelope': ENVS['foreign_card'], 'accepted_at': NOW},
                {'envelope': ENVS['letter'], 'accepted_at': NOW}):
        session, _ = transport(bad)
        with pytest.raises(AgentProtocolError):
            MailClient(ORIGIN, session).card(MAILBOX, OWNER, now_ms=NOW)


@pytest.mark.parametrize('raw', [b'{"result":[],"result":[]}', b'{"result":[NaN]}', b'\xff', b'{"result":"wrong"}'])
def test_strict_json_and_response_shape(raw):
    session, _ = transport(raw)
    with pytest.raises(AgentProtocolError):
        MailClient(ORIGIN, session).list(MAILBOX, OWNER, TOKEN, now_ms=NOW)


def test_delivery_result_binding_and_size_limit():
    _, _, delivery = populated()
    packet = V['encryptions']['original']['packet']
    for bad in ({**delivery, 'packet_id': ENVS['letter']['hash']}, {**delivery, 'seq': 1},
                {**delivery, 'accepted_at': packet['header']['expires_at']}):
        session, _ = transport((bad, 202, {}))
        with pytest.raises(AgentProtocolError):
            MailClient(ORIGIN, session).deliver(packet)
    session, _ = transport(b' '*4097)
    with pytest.raises(AgentProtocolError) as err:
        MailClient(ORIGIN, session, max_response_bytes=4096).protocol()
    assert err.value.code == 'payload_too_large'


def test_client_pages_follow_cursors_and_detect_rewinds():
    relay, _, _ = populated()
    relay.deliver(MAILBOX, V['encryptions']['reencrypted']['packet'], now_ms=NOW)
    first = relay.list(MAILBOX, TOKEN, limit=1, now_ms=NOW)
    second = relay.list(MAILBOX, TOKEN, limit=1, cursor=first['next_cursor'], now_ms=NOW)
    session, _ = transport(first, second)
    minted = []
    pages = list(MailClient(ORIGIN, session).pages(MAILBOX, OWNER, lambda: minted.append(TOKEN) or TOKEN, limit=1, now_ms=NOW))
    assert [r['seq'] for p in pages for r in p['result']] == [1, 2] and len(minted) == 2
    session, _ = transport(first, first)
    rewound = MailClient(ORIGIN, session).pages(MAILBOX, OWNER, TOKEN, limit=1, now_ms=NOW)
    next(rewound)
    with pytest.raises(AgentProtocolError):
        next(rewound)
    corrupt = copy.deepcopy(first['result'][0])
    corrupt['packet']['header']['mailbox_id'] = 'AAAAAAAAAAAAAAAAAAAAAA'
    session, _ = transport({'result': [corrupt]})
    with pytest.raises(AgentProtocolError):
        MailClient(ORIGIN, session).list(MAILBOX, OWNER, TOKEN, now_ms=NOW)


def test_local_network_policy_runs_before_transport(monkeypatch):
    session, adapter = transport()
    for policy in (lambda _: False, lambda _: None):  # Any false value rejects, like the TS allowUrl option.
        client = MailClient(ORIGIN, session, network_policy=policy)
        with pytest.raises(AgentProtocolError) as err:
            client.protocol()
        assert err.value.code == 'permission_denied' and not adapter.calls
    monkeypatch.setattr('socket.getaddrinfo', lambda *_args, **_kwargs: [(2, 1, 6, '', ('127.0.0.1', 443))])
    with pytest.raises(AgentProtocolError):
        mail_public_network_policy(ORIGIN+'/.well-known/agent-mail')
    monkeypatch.setattr('socket.getaddrinfo', lambda *_args, **_kwargs: [(2, 1, 6, '', ('8.8.8.8', 443))])
    mail_public_network_policy(ORIGIN+'/.well-known/agent-mail')


def test_non2xx_errors_and_delete_body_contract():
    error = {'error': {'code': 'nonce_not_greater', 'message': 'old', 'data': {'max_nonce': 123}}}
    session, _ = transport((error, 409, {'Max-Seen-Nonce': '123'}))
    with pytest.raises(HttpResponseError) as caught:
        MailClient(ORIGIN, session).publish(ENVS['card'])
    assert caught.value.code == 'nonce_not_greater' and caught.value.max_seen_nonce == '123'
    session, _ = transport((b'not-empty', 204, {}))
    with pytest.raises(AgentProtocolError):
        MailClient(ORIGIN, session).delete(MAILBOX, V['encryptions']['original']['packet_id'], OWNER, TOKEN, now_ms=NOW)
