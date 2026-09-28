import copy
import json
from urllib.parse import parse_qs, urlsplit

import pytest
from agent_protocols.errors import AgentProtocolError
from agent_protocols.http_client import KnowledgeClient, HttpResponseError
from agent_protocols.identity import AgentSigner, RequestBinding, create_request_jwt_claims, unix_secs
from agent_protocols.knowledge import KnowledgeStore, knowledge_publish_event

ORIGIN = 'https://knowledge.example.com'
NOW = 1_800_000_000_000
SIGNER = AgentSigner.from_seed(bytes([12]) * 32)


def item(n=1):
    return SIGNER.sign_event(knowledge_publish_event(SIGNER.agent_id(), NOW, n, {
        'visibility': 'public', 'license': 'https://example.com/license', 'kind': 'observation',
        'title': 'Cache', 'statement': 'Cache language matters', 'language': 'en',
        'context': {'scope': 'test', 'conditions': [], 'limitations': []}, 'basis': 'Two reads.',
    }))


def token(origin=ORIGIN):
    signer = AgentSigner.from_seed(bytes([13]) * 32)  # Transport importer differs from event actor.
    claims = create_request_jwt_claims(signer.agent_id(), RequestBinding.create(origin), unix_secs(), 300)
    return signer.sign_request_jwt(claims)


class Response:
    def __init__(self, value=None, *, text=None, status=200, url='', headers=None):
        self.text = json.dumps(value) if text is None else text
        self.status_code, self.url = status, url
        self.headers = headers or {}
    def json(self):
        raise AssertionError('HTTP SDK must parse raw text strictly, never response.json()')


class Session:
    def __init__(self, *responses): self.responses, self.calls = list(responses), []
    def _call(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)
    def get(self, url, **kwargs): return self._call('GET', url, **kwargs)
    def post(self, url, **kwargs): return self._call('POST', url, **kwargs)


def populated():
    store = KnowledgeStore(ORIGIN, clock=lambda: NOW, search_modes=('lexical', 'semantic'))
    first, second = item(), item(2)
    a, b = store.import_event(first), store.import_event(second)
    return store, first, second, a, b


def test_every_http_operation_discovery_override_and_unsigned_reads():
    store, first, second, a, b = populated()
    document = store.discovery()
    document['endpoints'] = {key: ORIGIN + '/custom/' + key for key in document['endpoints']}
    search = {'text': 'cache', 'mode': 'lexical'}
    session = Session(Response(document), Response(a), Response(a), Response(b),
                      Response(store.query()), Response(store.batch({'hashes': [first['hash']]})),
                      Response(store.changes()), Response(store.search(search)))
    client = KnowledgeClient.discover(ORIGIN, session)
    assert client.submit(first, jwt=token()) == a
    assert client.import_event(first, jwt=token()) == a
    assert client.event(second['hash']) == b
    assert len(client.query()['result']) == 2
    assert len(client.batch([first['hash']])['result']) == 1
    assert len(client.changes()['result']) == 2
    assert len(client.search(search)['result']) == 2
    assert [(method, urlsplit(url).path) for method, url, _ in session.calls] == [
        ('GET', '/.well-known/agent-knowledge'), ('POST', '/custom/events'),
        ('POST', '/custom/import'), ('GET', '/custom/events'), ('GET', '/custom/query'),
        ('POST', '/custom/batch'), ('GET', '/custom/changes'), ('POST', '/custom/search')]
    for index, (_, _, options) in enumerate(session.calls):
        assert options['allow_redirects'] is False and options['timeout'] == 30.0
        assert bool(options['headers'].get('Authorization')) == (index in (1, 2))
    assert session.calls[1][2]['json'] == first  # No receipt is submitted.
    assert parse_qs(urlsplit(session.calls[3][1]).query) == {'hash': [second['hash']]}
    exposed = client.discovery; exposed['endpoints']['events'] = 'https://other.example/a'
    assert client.discovery['endpoints']['events'] == ORIGIN + '/custom/events'


def test_defaults_only_core_endpoints_and_features_never_assumed():
    store, first, _, record, _ = populated()
    session = Session(Response(record))
    client = KnowledgeClient(ORIGIN, session)
    client.event(first['hash'])
    assert urlsplit(session.calls[0][1]).path == '/knowledge/events'
    with pytest.raises(AgentProtocolError): client.import_event(first)
    with pytest.raises(AgentProtocolError) as exc: client.search({'text': 'cache', 'mode': 'semantic'})
    assert exc.value.code == 'unsupported_search_mode'
    assert len(session.calls) == 1


def test_discovery_rejects_cross_origin_and_query_fragment_endpoints():
    for endpoint in ('https://other.example/events', ORIGIN+'/events?x=1', ORIGIN+'/events#x'):
        session = Session(Response({'protocol': 'agent-knowledge/1.0', 'service': ORIGIN, 'endpoints': {'events': endpoint}}))
        with pytest.raises(AgentProtocolError) as exc: KnowledgeClient.discover(ORIGIN, session)
        assert exc.value.code == 'invalid_discovery'
        assert len(session.calls) == 1


@pytest.mark.parametrize('text', ['{"result":[],"result":[]}', '{"result":[],"number":9007199254740992}', '{"result":[],"x":NaN}'])
def test_http_parses_strict_json_before_response_validation(text):
    session = Session(Response(text=text))
    with pytest.raises(AgentProtocolError) as exc: KnowledgeClient(ORIGIN, session).query()
    assert exc.value.code == 'invalid_response'


def test_no_redirects_foreign_final_origin_and_jwt_audience_checked_before_sending():
    session = Session(Response(status=307, headers={'Location': 'https://other.example/query'}))
    with pytest.raises(HttpResponseError): KnowledgeClient(ORIGIN, session).query()
    assert session.calls[0][2]['allow_redirects'] is False
    session = Session(Response({}, url='https://other.example/query'))
    with pytest.raises(AgentProtocolError) as exc: KnowledgeClient(ORIGIN, session).query()
    assert exc.value.code == 'invalid_response'
    session = Session()
    with pytest.raises(AgentProtocolError): KnowledgeClient(ORIGIN, session).submit(item(), jwt=token('https://other.example'))
    assert session.calls == []


@pytest.mark.parametrize('mutation', ['hash', 'signature', 'scope', 'filter', 'order'])
def test_http_verifies_read_envelopes_ids_scope_filters_and_order(mutation):
    store, first, _, a, b = populated()
    if mutation == 'hash':
        session = Session(Response(b))
        with pytest.raises(AgentProtocolError): KnowledgeClient(ORIGIN, session).event(first['hash'])
        return
    response = store.query()
    request = {}
    if mutation == 'signature': response['result'][0]['envelope']['signature'] = 'A'*86
    elif mutation == 'scope': response['service'] = 'https://other.example'
    elif mutation == 'filter': request = {'kind': 'question'}
    elif mutation == 'order': response['result'].reverse()
    with pytest.raises(AgentProtocolError): KnowledgeClient(ORIGIN, Session(Response(response))).query(request)


def test_iterator_checks_scope_across_pages_and_keeps_parameters():
    store, _, _, _, _ = populated()
    request = {'q': 'cache', 'limit': 1}
    first = store.query(request)
    second = store.query({**request, 'cursor': first['next_cursor']})
    session = Session(Response(first), Response(second))
    assert len(list(KnowledgeClient(ORIGIN, session).iter_pages('query', request))) == 2
    params = parse_qs(urlsplit(session.calls[1][1]).query)
    assert params == {'q': ['cache'], 'limit': ['1'], 'cursor': [first['next_cursor']]}
    second['as_of'] += 1
    with pytest.raises(AgentProtocolError) as exc:
        list(KnowledgeClient(ORIGIN, Session(Response(first), Response(second))).iter_pages('query', request))
    assert exc.value.code == 'invalid_response'


def test_changes_ignores_unknown_time_fields_across_pages():
    store, _, _, _, _ = populated()
    first = store.changes({'limit': 1})
    second = store.changes({'limit': 1, 'cursor': first['next_cursor']})
    second['as_of'] = 'ignored extension'; second['service'] = 'ignored extension'
    assert len(list(KnowledgeClient(ORIGIN, Session(Response(first), Response(second))).iter_pages('changes', {'limit': 1}))) == 2


def test_http_error_preserves_nonce_header_and_structured_error():
    response = Response({'error': {'code': 'nonce_not_greater', 'message': 'stale', 'data': {'max_nonce': 9}}},
                        status=409, headers={'Max-Seen-Nonce': '9'})
    with pytest.raises(HttpResponseError) as exc: KnowledgeClient(ORIGIN, Session(response)).submit(item())
    assert exc.value.code == 'nonce_not_greater' and exc.value.max_seen_nonce == '9'


def test_ipv6_service_origin_and_explicit_default_port_endpoint():
    origin = 'https://[::1]'
    document = {'protocol': 'agent-knowledge/1.0', 'service': origin,
                'endpoints': {'query': 'https://[0:0:0:0:0:0:0:1]:443/custom/query'}}
    response = {'result': [], 'service': origin, 'checkpoint': 0, 'as_of': NOW}
    session = Session(Response(document), Response(response, url='https://[::1]/custom/query'))
    client = KnowledgeClient.discover(origin, session)
    assert client.query() == response


def test_batch_validates_against_frozen_request_after_caller_mutation():
    store, first, second, _, _ = populated()
    requested = [first['hash']]
    response = store.batch({'hashes': [second['hash']]})
    class MutatingSession(Session):
        def post(self, url, **kwargs):
            assert kwargs['json']['hashes'] == [first['hash']]
            requested[:] = [second['hash']]
            return super().post(url, **kwargs)
    with pytest.raises(AgentProtocolError) as exc:
        KnowledgeClient(ORIGIN, MutatingSession(Response(response))).batch(requested)
    assert exc.value.code == 'invalid_response'


@pytest.mark.parametrize('mutation', ['delete', 'replace'])
def test_iterator_freezes_next_cursor_before_yielding_mutable_page(mutation):
    store, _, _, _, _ = populated()
    first = store.query({'limit': 1})
    expected_cursor = first['next_cursor']
    second = store.query({'limit': 1, 'cursor': expected_cursor})
    session = Session(Response(first), Response(second))
    pages = KnowledgeClient(ORIGIN, session).iter_pages('query', {'limit': 1})
    yielded = next(pages)
    if mutation == 'delete': del yielded['next_cursor']
    else: yielded['next_cursor'] = 'attacker-chosen'
    assert next(pages)['result'] == second['result']
    with pytest.raises(StopIteration): next(pages)
    assert parse_qs(urlsplit(session.calls[1][1]).query)['cursor'] == [expected_cursor]


def test_http_integral_numbers_use_canonical_query_parameters_and_preserve_envelopes():
    store, first, _, record, _ = populated()
    record['envelope']['event']['nonce'] = 1.0
    record['envelope']['event']['created_at'] = float(NOW)
    record['seq'] = 1.0; record['accepted_at'] = float(NOW)
    response = {'result': [record], 'service': ORIGIN, 'checkpoint': 2.0, 'as_of': float(NOW)}
    session = Session(Response(record), Response(response), Response(response))
    client = KnowledgeClient(ORIGIN, session)
    assert type(client.event(first['hash'])['envelope']['event']['nonce']) is float
    client.query({'limit': 1.0})
    client.changes({'after': 0.0, 'limit': 1.0})
    assert parse_qs(urlsplit(session.calls[1][1]).query) == {'limit': ['1']}
    assert parse_qs(urlsplit(session.calls[2][1]).query) == {'after': ['0'], 'limit': ['1']}
