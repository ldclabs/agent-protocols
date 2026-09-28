import base64
import copy
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from importlib.resources import files
from pathlib import Path

import pytest
from agent_protocols.errors import AgentProtocolError
from agent_protocols import knowledge as k
from agent_protocols.identity import AgentSigner, canonical_event_bytes, parse_strict_json

ORIGIN = 'https://knowledge.example.com'
NOW = 1_800_000_000_000
SIGNER = AgentSigner.from_seed(bytes([11]) * 32)
OTHER = AgentSigner.from_seed(bytes([12]) * 32)


def payload(**changes):
    value = {'license': 'https://example.com/license', 'kind': 'observation',
             'title': 'Cache observation', 'statement': 'Cache language matters.', 'language': 'en',
             'context': {'scope': 'fixture', 'conditions': [], 'limitations': []}, 'basis': 'Two requests.'}
    value.update(changes)
    return value


def signed(nonce=1, *, now=NOW, signer=SIGNER, **changes):
    return signer.sign_event(k.knowledge_publish_event(signer.agent_id(), now, nonce, payload(**changes)))


def code(fn):
    with pytest.raises(AgentProtocolError) as exc:
        fn()
    return exc.value.code


def test_schema_is_packaged_and_constants_match_spec():
    source = Path(__file__).resolve().parents[3] / 'docs/protocols/agent-knowledge/1.0.schema.json'
    assert files('agent_protocols').joinpath('knowledge.schema.json').read_bytes() == source.read_bytes()
    definitions = json.loads(source.read_bytes())['$defs']
    assert list(k.KNOWLEDGE_RELATIONS) == definitions['relation']['properties']['relation']['enum']
    assert list(k.KNOWLEDGE_KINDS) == definitions['publishPayload']['properties']['kind']['enum']
    assert list(k.KNOWLEDGE_VERDICTS) == definitions['assessPayload']['properties']['verdict']['enum']
    assert list(k.KNOWLEDGE_SEARCH_MODES) == definitions['searchMode']['enum']


def test_builder_and_store_detach_all_input_and_output_values():
    source = payload()
    event = k.knowledge_publish_event(SIGNER.agent_id(), NOW, 1, source)
    source['context']['conditions'].append('injected')
    assert event['payload']['context']['conditions'] == []
    envelope = SIGNER.sign_event(event)
    expected = copy.deepcopy(envelope)
    store = k.KnowledgeStore(ORIGIN, clock=lambda: NOW,
                             admit=lambda incoming: incoming['event']['payload'].update(title='injected'))
    receipt = store.submit(envelope)
    envelope['event']['payload']['title'] = 'injected'
    receipt['envelope']['event']['payload']['title'] = 'also injected'
    store.known_envelopes()[expected['hash']]['event']['payload']['title'] = 'injected again'
    page = store.query({'limit': 1})
    page['result'][0]['envelope']['event']['payload']['title'] = 'changed response'
    assert store.event(expected['hash'])['envelope'] == expected


def test_acceptance_ignores_live_nonce_state_and_accepts_old_events():
    store = k.KnowledgeStore(ORIGIN, clock=lambda: NOW)
    assert store.submit(signed(20))['seq'] == 1
    assert store.submit(signed(5))['seq'] == 2
    assert store.submit(signed(5, statement='Same nonce, different event.'))['seq'] == 3
    assert store.submit(signed(1, now=NOW - 10**9))['seq'] == 4
    assert code(lambda: store.submit(signed(2, now=NOW + k.DEFAULT_FUTURE_SKEW_MS + 1))) == 'timestamp_out_of_window'
    assert store.submit(signed(3, now=NOW + k.DEFAULT_FUTURE_SKEW_MS))['seq'] == 5


def test_hide_retry_prune_and_new_sequence():
    store = k.KnowledgeStore(ORIGIN, clock=lambda: NOW)
    item = signed()
    receipt = store.submit(item)
    store.hide(item['hash'])
    assert store.query()['result'] == []
    assert store.batch({'hashes': [item['hash']]})['missing'] == [item['hash']]
    assert store.submit(item, now_ms=NOW + 900_000) == receipt
    assert code(lambda: store.event(item['hash'])) == 'not_found'
    store.unhide(item['hash'])
    assert store.event(item['hash']) == receipt
    store.prune(item['hash'])
    assert store.checkpoint == 1
    assert store.submit(item, now_ms=NOW + 900_000)['seq'] == 2


def test_withheld_dependencies_resolve_and_exact_receipts_bypass_admission():
    first = signed()
    store = k.KnowledgeStore(ORIGIN, clock=lambda: NOW)
    store.submit(first)
    store.hide(first['hash'])
    second = signed(2, relations=[{'relation': 'derived_from', 'target': first['hash']}])
    record = store.submit(second)
    retraction = SIGNER.sign_event(k.knowledge_retract_event(SIGNER.agent_id(), NOW, 3, {
        'license': 'https://example.com/license', 'target': first['hash'], 'reason': 'mistake'}))
    assert store.submit(retraction)['seq'] == 3
    store.admit = lambda _: (_ for _ in ()).throw(AgentProtocolError('permission_denied', 'closed'))
    assert store.submit(second) == record
    assert code(lambda: store.submit(signed(4))) == 'permission_denied'


def test_relationships_may_cite_or_dispute_assessments():
    original = signed()
    assessment = OTHER.sign_event(k.knowledge_assess_event(OTHER.agent_id(), NOW, 1, {
        'license': 'https://example.com/license', 'target': original['hash'], 'verdict': 'supports',
        'summary': 'Looks right.', 'context': {'scope': 'fixture', 'conditions': [], 'limitations': []},
        'basis': 'Reran it.'}))
    known = {original['hash']: original, assessment['hash']: assessment}
    for relation in ('derived_from', 'supports', 'contradicts'):
        k.validate_knowledge_dependencies(signed(2, relations=[{'relation': relation, 'target': assessment['hash']}]), known)
    for relation in ('extends', 'supersedes'):
        item = signed(2, relations=[{'relation': relation, 'target': assessment['hash']}])
        assert code(lambda: k.validate_knowledge_dependencies(item, known)) == 'invalid_target'


def test_known_set_validation_rejects_unresolved_forged_and_wrong_keys():
    item = signed()
    withdrawal = SIGNER.sign_event(k.knowledge_retract_event(SIGNER.agent_id(), NOW, 2, {
        'license': 'https://example.com/license', 'target': item['hash'], 'reason': 'mistake'}))
    assert code(lambda: k.materialize_knowledge({withdrawal['hash']: withdrawal})) == 'missing_dependency'
    with pytest.raises(AgentProtocolError):
        k.materialize_knowledge({'wrong': item})
    bad = copy.deepcopy(withdrawal)
    bad['event']['payload']['reason'] = 'forged'
    with pytest.raises(AgentProtocolError):
        k.materialize_knowledge({item['hash']: item, bad['hash']: bad})
    assert k.materialize_knowledge({withdrawal['hash']: withdrawal, item['hash']: item})[item['hash']]['status'] == 'retracted'


def test_cursors_bind_checkpoint_and_survive_hide_prune_and_reacceptance():
    store = k.KnowledgeStore(ORIGIN, clock=lambda: NOW)
    items = [signed(n) for n in range(1, 5)]
    for item in items[:3]:
        store.submit(item)
    tracker = k.KnowledgePageTracker(ORIGIN)
    first = store.query({'limit': 1})
    tracker.accept({'limit': 1}, first)
    assert tracker.checkpoint is None
    store.prune(items[1]['hash'])
    store.submit(items[1])
    store.submit(items[3])
    request = {'limit': 1, 'cursor': first['next_cursor']}
    second = store.query(request)
    tracker.accept(request, second)
    assert [record['envelope']['hash'] for record in second['result']] == [items[2]['hash']]
    assert tracker.complete and tracker.checkpoint == 3
    assert [record['seq'] for record in store.query({'after_seq': 3})['result']] == [4, 5]
    assert code(lambda: store.query({'after_seq': 6})) == 'invalid_request'
    assert code(lambda: store.query({'limit': 2, 'cursor': first['next_cursor']})) == 'invalid_cursor'
    assert code(lambda: store.query({'limit': 1, 'cursor': first['next_cursor'] + 'x'})) == 'invalid_cursor'
    assert code(lambda: k.KnowledgeStore(ORIGIN, clock=lambda: NOW).query(request)) == 'invalid_cursor'


@pytest.mark.parametrize('mutation', ['scope', 'duplicate', 'request', 'cursor'])
def test_page_tracker_rejects_cross_page_drift(mutation):
    store = k.KnowledgeStore(ORIGIN, clock=lambda: NOW)
    for n in range(1, 4):
        store.submit(signed(n))
    request = {'q': 'cache', 'limit': 1}
    first = store.query(request)
    tracker = k.KnowledgePageTracker(ORIGIN)
    tracker.accept(request, first)
    request = {**request, 'cursor': first['next_cursor']}
    second = store.query(request)
    if mutation == 'scope':
        second['as_of'] += 1
    elif mutation == 'duplicate':
        second['result'] = first['result']
    elif mutation == 'request':
        request['q'] = 'Cache'
    elif mutation == 'cursor':
        request['cursor'] = 'other'
    with pytest.raises(AgentProtocolError) as exc:
        tracker.accept(request, second)
    assert exc.value.code == 'invalid_response'


def test_search_is_one_page_of_caller_ranked_candidates():
    store = k.KnowledgeStore(ORIGIN, clock=lambda: NOW)
    items = [signed(n) for n in range(1, 4)]
    for item in items:
        store.submit(item)
    ids = [item['hash'] for item in reversed(items)]
    page = store.search({'text': 'cache', 'mode': 'lexical', 'limit': 2}, candidates=ids,
                        ranking={'mode': 'lexical', 'id': 'test-v1'},
                        coverage={'exhaustive': False, 'reasons': ['candidate_limit']})
    assert [hit['record']['envelope']['hash'] for hit in page['result']] == ids[:2]
    assert 'next_cursor' not in page
    k.validate_knowledge_search_response(page, {'text': 'cache', 'mode': 'lexical', 'limit': 2}, ORIGIN)
    assert code(lambda: store.search({'text': 'cache', 'mode': 'lexical', 'limit': 2}, candidates=ids,
                                     ranking={'mode': 'lexical', 'id': 'test-v1'},
                                     coverage={'exhaustive': True, 'reasons': []})) == 'invalid_response'
    assert code(lambda: store.search({'text': 'cache', 'mode': 'semantic'}, candidates=ids,
                                     ranking={'mode': 'semantic', 'id': 'test-v1'},
                                     coverage={'exhaustive': False, 'reasons': ['approximate']},
                                     modes=['lexical'])) == 'unsupported_search_mode'


def test_serialized_concurrent_acceptance_and_retry():
    store = k.KnowledgeStore(ORIGIN, clock=lambda: NOW)
    items = [signed(n) for n in range(1, 25)]
    with ThreadPoolExecutor(max_workers=6) as workers:
        receipts = list(workers.map(store.submit, items + items))
    assert store.checkpoint == len(items)
    assert sorted(record['seq'] for record in receipts[:len(items)]) == list(range(1, len(items) + 1))
    assert receipts[:len(items)] == receipts[len(items):]


def test_evidence_statuses_and_envelope_limit():
    raw = b'original\r\nbytes'
    digest = base64.urlsafe_b64encode(hashlib.sha3_256(raw).digest()).rstrip(b'=').decode()
    assert k.verify_knowledge_evidence(digest, raw) == 'matched'
    assert k.verify_knowledge_evidence(digest, raw[:4]) == 'mismatched'
    assert k.verify_knowledge_evidence(digest, None) == 'unavailable'
    assert k.verify_knowledge_evidence(None, raw) == 'unchecked'
    store = k.KnowledgeStore(ORIGIN, clock=lambda: NOW, max_envelope_bytes=100)
    assert code(lambda: store.submit(signed())) == 'payload_too_large'


def test_invalid_python_read_inputs_never_coerced_to_empty_query():
    store = k.KnowledgeStore(ORIGIN, clock=lambda: NOW)
    for bad in ([], '', 0, False):
        with pytest.raises(AgentProtocolError):
            store.query(bad)


def test_integral_json_numbers_preserve_signed_objects():
    integral = signed(10)
    original_bytes = canonical_event_bytes(integral['event'])
    integral['event']['nonce'] = 10.0
    integral['event']['created_at'] = float(NOW)
    parsed = parse_strict_json(json.dumps(integral))
    before = copy.deepcopy(parsed)
    k.validate_knowledge_envelope(parsed)
    assert canonical_event_bytes(parsed['event']) == original_bytes
    store = k.KnowledgeStore(ORIGIN, clock=lambda: NOW)
    record = store.submit(parsed)
    assert record['envelope'] == before and parsed == before
    assert type(record['envelope']['event']['nonce']) is float
    assert store.submit(signed(10)) == record
    assert k.materialize_knowledge(store.known_envelopes())[integral['hash']]['status'] == 'active'


def test_integral_read_numbers_and_response_metadata_are_json_equivalent():
    store = k.KnowledgeStore(ORIGIN, clock=lambda: NOW)
    store.submit(signed())
    request = k.parse_knowledge_read_json('{"limit":1.0,"after_seq":0.0}')
    assert k.validate_knowledge_query(request) == {'limit': 1, 'after_seq': 0}
    page = store.query(request)
    page['result'][0]['seq'] = 1.0
    page['checkpoint'] = 1.0
    page['as_of'] = float(NOW)
    tracker = k.KnowledgePageTracker(ORIGIN)
    tracker.accept(request, page)
    assert tracker.checkpoint == 1
    search = k.parse_knowledge_read_json('{"text":"cache","mode":"lexical","limit":1.0}')
    assert type(k.validate_knowledge_search_request(search, ['lexical'])['limit']) is int


@pytest.mark.parametrize('field', ['nonce', 'created_at'])
def test_fractional_event_integer_fields_remain_invalid(field):
    event = signed()
    event['event'][field] = 1.5
    with pytest.raises(AgentProtocolError):
        k.validate_knowledge_envelope(event)
    with pytest.raises(AgentProtocolError):
        k.KnowledgeStore(ORIGIN, clock=lambda: NOW).submit(event)


def test_fractional_read_integer_fields_remain_invalid():
    store = k.KnowledgeStore(ORIGIN, clock=lambda: NOW)
    for value in (1.5, True):
        with pytest.raises(AgentProtocolError):
            store.query({'limit': value})
        with pytest.raises(AgentProtocolError):
            store.query({'after_seq': value})
        with pytest.raises(AgentProtocolError):
            store.search({'mode': 'lexical', 'text': 'cache', 'limit': value}, candidates=[],
                         ranking={'mode': 'lexical', 'id': 'x'}, coverage={'exhaustive': True, 'reasons': []})
