import copy
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from importlib.resources import files
from pathlib import Path

import pytest
from agent_protocols.errors import AgentProtocolError
from agent_protocols.identity import AgentSigner, MemoryNonceStore, create_event, verify_submission
from agent_protocols import knowledge as k

ORIGIN = 'https://knowledge.example.com'
NOW = 1_800_000_000_000
SIGNER = AgentSigner.from_seed(bytes([11]) * 32)


def payload():
    return {'visibility': 'public', 'license': 'https://example.com/license', 'kind': 'observation',
            'title': 'Cache observation', 'statement': 'Cache language matters.', 'language': 'en',
            'context': {'scope': 'fixture', 'conditions': [], 'limitations': []}, 'basis': 'Two requests.'}


def signed(nonce=1, *, now=NOW):
    return SIGNER.sign_event(k.knowledge_publish_event(SIGNER.agent_id(), now, nonce, payload()))


def error(code):
    return pytest.raises(AgentProtocolError, match='')


def test_schema_is_packaged_and_constants_match_spec():
    source = Path(__file__).resolve().parents[3] / 'docs/protocols/agent-knowledge/1.0.schema.json'
    assert files('agent_protocols').joinpath('knowledge.schema.json').read_bytes() == source.read_bytes()
    definitions = json.loads(source.read_bytes())['$defs']
    assert set(k.KNOWLEDGE_RELATIONS) == set(definitions['relation']['properties']['relation']['enum'])
    assert set(k.KNOWLEDGE_KINDS) == set(definitions['publishPayload']['properties']['kind']['enum'])
    assert set(k.KNOWLEDGE_VERDICTS) == set(definitions['assessPayload']['properties']['verdict']['enum'])
    assert 'invalid_cursor' in k.KNOWLEDGE_ERROR_CODES


def test_builder_and_store_detach_all_input_and_output_values():
    source = payload()
    event = k.knowledge_publish_event(SIGNER.agent_id(), NOW, 1, source)
    source['context']['conditions'].append('injected')
    assert event['payload']['context']['conditions'] == []
    envelope = SIGNER.sign_event(event)
    expected = copy.deepcopy(envelope)
    store = k.KnowledgeStore(ORIGIN, clock=lambda: NOW,
                             admit=lambda incoming, _: incoming['event']['payload'].update(title='injected'))
    receipt = store.submit(envelope)
    envelope['event']['payload']['title'] = 'injected'
    receipt['envelope']['event']['payload']['title'] = 'also injected'
    returned = store.records
    returned.clear()
    retained = store.retained
    retained[expected['hash']]['event']['payload']['title'] = 'injected again'
    assert store.event(expected['hash'])['envelope'] == expected
    page = store.query({'limit': 1})
    page['result'][0]['envelope']['event']['payload']['title'] = 'changed response'
    assert store.event(expected['hash'])['envelope'] == expected


def test_shared_actor_nonce_with_other_protocol_and_import_no_pollution():
    nonces = MemoryNonceStore()
    foreign = SIGNER.sign_event(create_event('other/1.0', 'sample', SIGNER.agent_id(), NOW, 20, {}))
    verify_submission(foreign, nonces, now_ms=NOW)
    before = copy.deepcopy(nonces.__dict__)
    store = k.KnowledgeStore(ORIGIN, nonce_store=nonces, clock=lambda: NOW)
    with pytest.raises(AgentProtocolError) as exc:
        store.submit(signed(1))
    assert exc.value.code == 'nonce_not_greater' and exc.value.data == {'max_nonce': 20}
    store.import_event(signed(1))
    assert nonces.__dict__ == before
    assert store.submit(signed(21))['seq'] == 2


def test_hide_retry_prune_and_new_sequence():
    store = k.KnowledgeStore(ORIGIN, clock=lambda: NOW)
    item = signed()
    receipt = store.submit(item)
    store.hide(item['hash'])
    assert store.query()['result'] == []
    assert store.batch({'hashes': [item['hash']]})['missing'] == [item['hash']]
    assert store.submit(item, now_ms=NOW+900_000) == receipt
    with pytest.raises(AgentProtocolError) as exc:
        store.event(item['hash'])
    assert exc.value.code == 'not_found'
    store.unhide(item['hash'])
    assert store.event(item['hash']) == receipt
    store.prune(item['hash'])
    assert store.seq == 1
    with pytest.raises(AgentProtocolError) as exc:
        store.submit(item, now_ms=NOW+900_000)
    assert exc.value.code == 'timestamp_out_of_window'
    assert store.import_event(item, now_ms=NOW+900_000)['seq'] == 2


def test_exact_receipt_bypasses_limits_admission_and_missing_dependency():
    first = signed()
    store = k.KnowledgeStore(ORIGIN, clock=lambda: NOW, max_records=2)
    store.submit(first)
    p = payload(); p['relations'] = [{'relation': 'derived_from', 'target': first['hash']}]
    second = SIGNER.sign_event(k.knowledge_publish_event(SIGNER.agent_id(), NOW, 2, p))
    record = store.submit(second)
    store.hide(first['hash'])
    store.admit = lambda *_: (_ for _ in ()).throw(AgentProtocolError('permission_denied', 'closed'))
    assert store.submit(second) == record


def test_known_set_validation_rejects_unresolved_forged_and_wrong_keys():
    item = signed()
    p = {'visibility': 'public', 'license': 'https://example.com/license', 'target': item['hash'], 'reason': 'mistake'}
    withdrawal = SIGNER.sign_event(k.knowledge_retract_event(SIGNER.agent_id(), NOW, 2, p))
    with pytest.raises(AgentProtocolError) as exc:
        k.materialize_knowledge({withdrawal['hash']: withdrawal})
    assert exc.value.code == 'missing_dependency'
    with pytest.raises(AgentProtocolError):
        k.materialize_knowledge({'wrong': item})
    bad = copy.deepcopy(withdrawal); bad['event']['payload']['reason'] = 'forged'
    with pytest.raises(AgentProtocolError):
        k.materialize_knowledge({item['hash']: item, bad['hash']: bad})
    assert k.materialize_knowledge({withdrawal['hash']: withdrawal, item['hash']: item})[item['hash']]['status'] == 'retracted'


def test_changes_freezes_range_and_handles_hidden_pruned_reimported_ids():
    store = k.KnowledgeStore(ORIGIN, clock=lambda: NOW)
    items = [signed(n) for n in range(1, 5)]
    for item in items[:3]: store.import_event(item)
    first = store.changes({'limit': 1})
    tracker = k.KnowledgePageTracker(ORIGIN, 'changes'); tracker.accept(first, {'limit': 1})
    assert tracker.checkpoint is None
    store.prune(items[1]['hash']); store.import_event(items[1]); store.import_event(items[3])
    request = {'limit': 1, 'cursor': first['next_cursor']}
    second = store.changes(request); tracker.accept(second, request)
    assert [record['envelope']['hash'] for record in second['result']] == [items[2]['hash']]
    assert tracker.checkpoint == 3
    assert [record['seq'] for record in store.changes({'after': 3})['result']] == [4, 5]
    with pytest.raises(AgentProtocolError) as exc: store.changes({'after': 6})
    assert exc.value.code == 'invalid_request'


def test_snapshot_ttl_capacity_parameter_binding_and_visibility():
    clock = [NOW]
    store = k.KnowledgeStore(ORIGIN, clock=lambda: clock[0], max_snapshots=1, snapshot_ttl_ms=20)
    for n in range(1, 4): store.import_event(signed(n))
    first = store.query({'limit': 1})
    store.query({'limit': 2})
    with pytest.raises(AgentProtocolError) as exc: store.query({'limit': 1, 'cursor': first['next_cursor']})
    assert exc.value.code == 'invalid_cursor'
    first = store.query({'limit': 1})
    with pytest.raises(AgentProtocolError) as exc: store.query({'limit': 2, 'cursor': first['next_cursor']})
    assert exc.value.code == 'invalid_cursor'
    clock[0] += 20
    with pytest.raises(AgentProtocolError) as exc: store.query({'limit': 1, 'cursor': first['next_cursor']})
    assert exc.value.code == 'invalid_cursor'


@pytest.mark.parametrize('mutation', ['scope', 'duplicate', 'request', 'cursor', 'ranking', 'coverage'])
def test_page_tracker_rejects_cross_page_drift(mutation):
    store = k.KnowledgeStore(ORIGIN, clock=lambda: NOW, search_modes=('lexical',))
    for n in range(1, 4): store.import_event(signed(n))
    request = {'mode': 'lexical', 'text': 'cache', 'limit': 1}
    first = store.search(request)
    tracker = k.KnowledgePageTracker(ORIGIN, 'search'); tracker.accept(first, request)
    request = {**request, 'cursor': first['next_cursor']}
    second = store.search(request)
    if mutation == 'scope': second['as_of'] += 1
    elif mutation == 'duplicate': second['result'][0]['record'] = first['result'][0]['record']
    elif mutation == 'request': request['text'] = 'Cache'
    elif mutation == 'cursor': second['next_cursor'] = first['next_cursor']
    elif mutation == 'ranking': second['ranking']['id'] = 'new-v2'
    elif mutation == 'coverage': second['coverage'] = {'exhaustive': False, 'reasons': ['timeout']}
    with pytest.raises(AgentProtocolError) as exc: tracker.accept(second, request)
    assert exc.value.code == 'invalid_response'


def test_serialized_concurrent_import_and_retry_acceptance():
    store = k.KnowledgeStore(ORIGIN, clock=lambda: NOW)
    items = [signed(n) for n in range(1, 25)]
    with ThreadPoolExecutor(max_workers=6) as workers:
        receipts = list(workers.map(store.import_event, items + items))
    assert store.seq == len(items)
    assert sorted(record['seq'] for record in store.records.values()) == list(range(1, len(items)+1))
    assert receipts[:len(items)] == receipts[len(items):]


def test_evidence_partial_bytes_and_profiles_never_auto_conform():
    import base64
    raw = b'original\r\nbytes'
    digest = base64.urlsafe_b64encode(hashlib.sha3_256(raw).digest()).rstrip(b'=').decode()
    assert k.knowledge_evidence_status(digest, raw, fetched=True, complete=True) == 'matched'
    assert k.knowledge_evidence_status(digest, raw, fetched=True) == 'unavailable'
    assert k.knowledge_evidence_status(None, raw, fetched=True, complete=True) == 'unchecked'
    bindings = [{'profile': {'url': 'https://example.com/profile', 'digest': digest}, 'data': {'unknown': [1, 1]}}]
    k.validate_knowledge_profiles(bindings)
    with pytest.raises(AgentProtocolError): k.validate_knowledge_profiles(bindings + bindings)


def test_live_window_nonce_ttl_and_future_boundary():
    with pytest.raises(ValueError, match='twice'):
        k.KnowledgeStore(ORIGIN, window_ms=100, nonce_ttl_ms=199)
    store = k.KnowledgeStore(ORIGIN, window_ms=100, nonce_ttl_ms=200, clock=lambda: NOW)
    assert store.submit(signed(1, now=NOW+100))['seq'] == 1
    with pytest.raises(AgentProtocolError) as exc:
        store.submit(signed(2, now=NOW+101))
    assert exc.value.code == 'timestamp_out_of_window'
    assert store.nonce_store.max_nonce(SIGNER.agent_id(), NOW+199) == 1


def test_invalid_python_read_inputs_never_coerced_to_empty_query():
    store = k.KnowledgeStore(ORIGIN, clock=lambda: NOW)
    for bad in ([], '', 0, False):
        with pytest.raises(AgentProtocolError): store.query(bad)
        with pytest.raises(AgentProtocolError): store.changes(bad)


def test_public_schema_validator_cannot_mutate_sdk_validation():
    validator = k.knowledge_schema_validator()
    validator.schema.clear()
    bad = signed(); bad['event']['payload']['visibility'] = 'private'
    with pytest.raises(AgentProtocolError): k.validate_knowledge_envelope(bad)


@pytest.mark.parametrize('mode', ['live', 'import'])
def test_integral_json_numbers_preserve_signed_objects_and_nonce_semantics(mode):
    from agent_protocols.identity import parse_strict_json, canonical_event_bytes
    integral = signed(10)
    original_bytes = canonical_event_bytes(integral['event'])
    integral['event']['nonce'] = 10.0
    integral['event']['created_at'] = float(NOW)
    raw = json.dumps(integral)
    assert '"nonce": 10.0' in raw
    parsed = parse_strict_json(raw)
    before = copy.deepcopy(parsed)
    k.validate_knowledge_envelope(parsed)
    assert canonical_event_bytes(parsed['event']) == original_bytes
    store = k.KnowledgeStore(ORIGIN, clock=lambda: NOW)
    record = store.submit(parsed, mode=mode)
    assert record['envelope'] == before and parsed == before
    assert type(parsed['event']['nonce']) is float
    assert type(record['envelope']['event']['nonce']) is float
    assert type(record['envelope']['event']['created_at']) is float
    assert store.submit(signed(10), mode=mode) == record
    if mode == 'live':
        assert store.nonce_store.max_nonce(SIGNER.agent_id(), NOW) == 10
        assert type(store.nonce_store.max_nonce(SIGNER.agent_id(), NOW)) is int
    else:
        assert store.nonce_store.max_nonce(SIGNER.agent_id(), NOW) is None
    assert k.materialize_knowledge(store.retained)[integral['hash']]['status'] == 'active'


def test_integral_read_numbers_and_response_metadata_are_json_equivalent():
    store = k.KnowledgeStore(ORIGIN, clock=lambda: NOW, search_modes=('lexical',))
    store.import_event(signed())
    request = k.parse_knowledge_read_json('{"limit":1.0}')
    assert type(k.validate_knowledge_query(request)['limit']) is int
    query = store.query(request)
    query['result'][0]['seq'] = 1.0
    query['result'][0]['accepted_at'] = float(NOW)
    query['checkpoint'] = 1.0; query['as_of'] = float(NOW)
    k.validate_knowledge_query_response(query, request, ORIGIN)
    tracker = k.KnowledgePageTracker(ORIGIN); tracker.accept(query, request)
    assert tracker.checkpoint == 1 and type(tracker.checkpoint) is int
    changes = k.parse_knowledge_read_json('{"after":0.0,"limit":1.0}')
    assert store.changes(changes)['result'][0]['seq'] == 1
    k.validate_knowledge_changes_response(query, changes, ORIGIN)
    assert k.validate_knowledge_changes(changes) == {'after': 0, 'limit': 1}
    search = k.parse_knowledge_read_json('{"text":"cache","mode":"lexical","limit":1.0}')
    assert type(k.validate_knowledge_search(search, ['lexical'])['limit']) is int
    assert store.search(search)['result'][0]['rank'] == 1


@pytest.mark.parametrize('field', ['nonce', 'created_at'])
def test_fractional_event_integer_fields_remain_invalid(field):
    event = signed()
    event['event'][field] = 1.5
    with pytest.raises(AgentProtocolError): k.validate_knowledge_envelope(event)
    with pytest.raises(AgentProtocolError): k.KnowledgeStore(ORIGIN, clock=lambda: NOW).import_event(event)


def test_fractional_read_integer_fields_remain_invalid():
    store = k.KnowledgeStore(ORIGIN, clock=lambda: NOW, search_modes=('lexical',))
    for value in (1.5, True):
        with pytest.raises(AgentProtocolError): store.query({'limit': value})
        with pytest.raises(AgentProtocolError): store.changes({'after': value})
        with pytest.raises(AgentProtocolError): store.search({'mode': 'lexical', 'text': 'cache', 'limit': value})
    page = store.query()
    page['checkpoint'] = 1.5
    with pytest.raises(AgentProtocolError): k.validate_knowledge_changes_response(page, {}, ORIGIN)
