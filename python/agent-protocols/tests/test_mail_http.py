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
        if callable(entry):
            entry = entry(request)
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


def discovery():
    return {'protocol': 'agent-mail/1.0', 'service': ORIGIN,
            'endpoints': {'mailboxes': ORIGIN+'/custom/mailboxes'},
            'features': ['unknown-future-capability'], 'future_metadata': True}


def test_all_http_operations_validate_bound_responses_and_discovery_override():
    relay, card, delivery = populated()
    page = relay.list_packets(MAILBOX, TOKEN, now_ms=NOW)
    session, adapter = transport(discovery(), card, card, (delivery, 202, {}), page, (b'', 204, {}))
    checked = []
    client = MailClient.discover(ORIGIN, session, network_policy=lambda url: checked.append(url))
    assert client.publish(ENVS['card']) == card
    assert client.card(MAILBOX, OWNER, now_ms=NOW) == card
    assert client.deliver(V['encryptions']['original']['packet'], ENVS['card']) == delivery
    assert client.packets(MAILBOX, OWNER, TOKEN, now_ms=NOW) == page
    client.delete(MAILBOX, delivery['packet_id'], OWNER, TOKEN, now_ms=NOW)
    assert len(checked) == len(adapter.calls) == 6
    assert [(request.method, urlsplit(request.url).path) for request, _ in adapter.calls] == [
        ('GET', '/.well-known/agent-mail'), ('POST', '/custom/mailboxes'),
        ('GET', '/custom/mailboxes/'+MAILBOX+'/card'),
        ('POST', '/custom/mailboxes/'+MAILBOX+'/packets'),
        ('GET', '/custom/mailboxes/'+MAILBOX+'/packets'),
        ('DELETE', '/custom/mailboxes/'+MAILBOX+'/packets/'+delivery['packet_id']),
    ]
    for index, (request, options) in enumerate(adapter.calls):
        assert ('Authorization' in request.headers) == (index in (4,5))
        assert options['proxies'] == {} and options['cert'] is None and options['verify'] is True
        assert options['timeout'] == 30 and options['stream'] is True
    assert parse_qs(urlsplit(adapter.calls[4][0].url).query) == {'limit':['100']}
    changed = client.discovery
    changed['endpoints']['mailboxes'] = 'https://other.example/a'
    assert client.discovery == discovery()


def test_anonymous_delivery_drops_real_session_auth_cookies_headers_params_netrc_and_cert(monkeypatch):
    _, _, delivery = populated()
    session, adapter = transport((delivery, 202, {}))
    session.auth = ('secret-user','secret-password')
    session.cookies.set('login', 'secret-cookie', domain='relay.example')
    session.headers.update({'Authorization':'Bearer ambient-identity', 'Cookie':'login=ambient', 'Proxy-Authorization':'secret-proxy', 'X-Api-Key':'secret-key'})
    session.params = {'api_key': 'secret-query'}
    session.cert = '/secret/client-identity.pem'
    session.proxies = {'https': 'https://user:password@proxy.example'}
    session.trust_env = True
    monkeypatch.setattr(requests.sessions, 'get_netrc_auth', lambda *_: pytest.fail('netrc must never be consulted'))
    client = MailClient(ORIGIN, session, network_policy=lambda _: True)
    client.deliver(V['encryptions']['original']['packet'], ENVS['card'])
    request, options = adapter.calls[0]
    assert not any(name in request.headers for name in ('Authorization','Cookie','Proxy-Authorization','X-Api-Key'))
    assert 'secret' not in request.url and '?' not in request.url
    assert options['cert'] is None and options['proxies'] == {} and options['verify'] is True
    assert session.auth == ('secret-user','secret-password')  # Caller session not mutated.


def test_owner_token_is_explicit_and_cannot_be_overridden_by_session_auth():
    relay, _, _ = populated()
    session, adapter = transport(relay.list_packets(MAILBOX, TOKEN, now_ms=NOW))
    session.auth = ('other','identity')
    session.headers['Authorization'] = 'Bearer ambient'
    client = MailClient(ORIGIN, session, network_policy=lambda _: True)
    client.packets(MAILBOX, OWNER, TOKEN, now_ms=NOW)
    assert adapter.calls[0][0].headers['Authorization'] == 'Bearer '+TOKEN
    with pytest.raises(AgentProtocolError):
        client.packets(MAILBOX, OWNER, token(exp=NOW//1000), now_ms=NOW)
    assert len(adapter.calls) == 1


@pytest.mark.parametrize('method', ['protocol','deliver','packets','delete'])
def test_redirects_never_follow_or_forward_credentials(method):
    session, adapter = transport((b'', 302, {'Location':'https://attacker.example/collect'}))
    client = MailClient(ORIGIN, session, network_policy=lambda _: True)
    with pytest.raises(HttpResponseError) as err:
        if method == 'protocol':
            client.protocol()
        elif method == 'deliver':
            client.deliver(V['encryptions']['original']['packet'], ENVS['card'])
        elif method == 'packets':
            client.packets(MAILBOX, OWNER, TOKEN, now_ms=NOW)
        else:
            client.delete(MAILBOX, V['encryptions']['original']['packet_id'], OWNER, TOKEN, now_ms=NOW)
    assert err.value.status == 302 and len(adapter.calls) == 1


def test_discovery_cannot_change_origin_or_apply_unknown_fields_as_endpoints():
    for document in [
        {**discovery(),'service':'https://other.example'},
        {**discovery(),'endpoints':{'mailboxes':'https://other.example/mailboxes'}},
        {**discovery(),'endpoints':{'mailboxes':ORIGIN+'/v1/mailboxes?redirect=other'}},
        {**discovery(),'endpoints':{'mailboxes':ORIGIN+'/v1/mailboxes/'}},
    ]:
        session, adapter = transport(document)
        with pytest.raises(AgentProtocolError):
            MailClient.discover(ORIGIN, session, network_policy=lambda _: True)
        assert len(adapter.calls) == 1


def test_card_read_validates_owner_mailbox_route_and_pins_disabled_card():
    _, card, _ = populated()
    disabled = {'envelope':ENVS['disabled_card'],'accepted_at':NOW}
    session, _ = transport(card, disabled, card)
    client = MailClient(ORIGIN, session, network_policy=lambda _: True)
    client.card(MAILBOX, OWNER, now_ms=NOW)
    client.card(MAILBOX, OWNER, now_ms=NOW)
    with pytest.raises(AgentProtocolError):
        client.card(MAILBOX, OWNER, now_ms=NOW)
    bad = copy.deepcopy(card)
    bad['envelope']['event']['payload']['mailbox_id'] = V['encryptions']['original']['packet_id'][:22]
    session, _ = transport(bad)
    with pytest.raises(AgentProtocolError):
        MailClient(ORIGIN, session, network_policy=lambda _: True).card(MAILBOX, OWNER, now_ms=NOW)


@pytest.mark.parametrize('raw', [b'{"result":[],"result":[]}', b'{"result":[NaN]}', b'\xff', b'{"result":"wrong"}'])
def test_strict_json_and_response_shape(raw):
    session, _ = transport(raw)
    with pytest.raises(AgentProtocolError):
        MailClient(ORIGIN, session, network_policy=lambda _: True).packets(MAILBOX, OWNER, TOKEN, now_ms=NOW)


def test_delivery_wrong_packet_id_and_size_limit_fail():
    _, _, delivery = populated()
    session, _ = transport(({**delivery,'packet_id':ENVS['letter']['hash']}, 202, {}))
    with pytest.raises(AgentProtocolError):
        MailClient(ORIGIN, session, network_policy=lambda _: True).deliver(V['encryptions']['original']['packet'], ENVS['card'])
    session, _ = transport(b' '*4097)
    with pytest.raises(AgentProtocolError) as err:
        MailClient(ORIGIN, session, network_policy=lambda _: True, max_response_bytes=4096).protocol()
    assert err.value.code == 'payload_too_large'


def test_client_page_tracker_detects_cross_page_replays_and_cursor_cycles():
    relay, _, _ = populated()
    record = relay.list_packets(MAILBOX, TOKEN, now_ms=NOW)['result'][0]
    page = {'result':[record], 'next_cursor':'same-cursor'}
    session, _ = transport(page,page)
    client = MailClient(ORIGIN, session, network_policy=lambda _: True)
    pages = client.packet_pages(MAILBOX, OWNER, TOKEN, limit=1, now_ms=NOW)
    assert next(pages) == page
    with pytest.raises(AgentProtocolError):
        next(pages)
    corrupt = copy.deepcopy(record)
    corrupt['packet']['header']['mailbox_id'] = 'AAAAAAAAAAAAAAAAAAAAAA'
    session, _ = transport({'result':[corrupt]})
    with pytest.raises(AgentProtocolError):
        MailClient(ORIGIN, session, network_policy=lambda _: True).packets(MAILBOX, OWNER, TOKEN, now_ms=NOW)


def test_local_network_policy_runs_before_transport(monkeypatch):
    session, adapter = transport()
    client = MailClient(ORIGIN, session, network_policy=lambda _: False)
    with pytest.raises(AgentProtocolError) as err:
        client.protocol()
    assert err.value.code == 'permission_denied' and not adapter.calls
    monkeypatch.setattr('socket.getaddrinfo', lambda *_args, **_kwargs: [(2,1,6,'',('127.0.0.1',443))])
    with pytest.raises(AgentProtocolError):
        mail_public_network_policy(ORIGIN+'/.well-known/agent-mail')
    monkeypatch.setattr('socket.getaddrinfo', lambda *_args, **_kwargs: [(2,1,6,'',('8.8.8.8',443))])
    mail_public_network_policy(ORIGIN+'/.well-known/agent-mail')


def test_non2xx_errors_and_delete_body_contract():
    error = {'error':{'code':'nonce_not_greater','message':'old','data':{'max_nonce':123}}}
    session, _ = transport((error,409,{'Max-Seen-Nonce':'123'}))
    with pytest.raises(HttpResponseError) as caught:
        MailClient(ORIGIN, session, network_policy=lambda _: True).publish(ENVS['card'])
    assert caught.value.code == 'nonce_not_greater' and caught.value.max_seen_nonce == '123'
    session, _ = transport((b'not-empty',204,{}))
    with pytest.raises(AgentProtocolError):
        MailClient(ORIGIN, session, network_policy=lambda _: True).delete(MAILBOX,V['encryptions']['original']['packet_id'],OWNER,TOKEN,now_ms=NOW)
