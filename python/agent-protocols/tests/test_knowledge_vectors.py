"""Execute every shared Knowledge fixture through the installed SDK.

Test adapters only translate fixture names and clock values to public SDK
arguments; validation, acceptance, matching, pagination, and response checks
are SDK code.
"""
import copy
import json
from pathlib import Path

from agent_protocols.knowledge import *
from agent_protocols.identity import AgentSigner, canonical_event_bytes, parse_strict_json, verify_envelope
from agent_protocols.errors import AgentProtocolError

ROOT = Path(__file__).resolve().parents[3]
VECTORS = json.loads((ROOT / 'docs/protocols/agent-knowledge/1.0.vectors.json').read_text())
FIXTURES = VECTORS['fixtures']
SERVICE = 'https://knowledge.example.com'


def envelope(name):
    return FIXTURES[name]['envelope']


def outcome(fn):
    try:
        fn()
        return 'valid'
    except AgentProtocolError as exc:
        return exc.code


def apply_changes(value, changes):
    value = copy.deepcopy(value)
    for change in changes:
        keys = change['path'].lstrip('/').split('/')
        parent = value
        for key in keys[:-1]:
            parent = parent[int(key)] if isinstance(parent, list) else parent[key]
        key = int(keys[-1]) if isinstance(parent, list) else keys[-1]
        if change['op'] == 'remove':
            del parent[key]
        else:
            assert change['op'] == 'set', 'unknown fixture mutation'
            parent[key] = change['value']
    return value


class Model:
    def __init__(self, accepted=(), hidden=()):
        self.clock = VECTORS['now']
        self.store = KnowledgeStore(SERVICE, clock=lambda: self.clock)
        for name in accepted:
            self.store.submit(envelope(name))
        for name in hidden:
            self.store.hide(envelope(name)['hash'])

    def state(self):
        return self.store.checkpoint, self.store.known_envelopes()


def test_signatures():
    for name, fixture in FIXTURES.items():
        item = fixture['envelope']
        verify_envelope(item)
        assert canonical_event_bytes(item['event']).decode() == fixture['canonical_event_utf8'], name
        signer = AgentSigner.from_seed(bytes.fromhex(VECTORS['seeds'][fixture['signer']]))
        assert item['event']['actor'] == signer.agent_id(), name
        assert signer.sign_event(item['event']) == item, name


def test_identity_cases():
    for case in VECTORS['identity_cases']:
        def run():
            if 'raw_json' in case:
                parse_strict_json(case['raw_json'])
            else:
                validate_knowledge_envelope(apply_changes(envelope(case['fixture']), case['changes']))
        assert outcome(run) == case['expected'], case['name']


def test_schema_cases():
    for case in VECTORS['schema_cases']:
        value = case['value'] if 'value' in case else apply_changes(envelope(case['fixture']), case['changes'])
        valid = outcome(lambda: validate_knowledge_schema(value, case['definition'])) == 'valid'
        assert valid == case['valid'], case['name']


def test_object_cases():
    for case in VECTORS['object_cases']:
        retained = {}
        for name in case['accepted']:
            item = envelope(name)
            validate_knowledge_envelope(item)
            validate_knowledge_dependencies(item, retained)
            retained[item['hash']] = item
        try:
            validate_knowledge_envelope(envelope(case['fixture']))
            validate_knowledge_dependencies(envelope(case['fixture']), retained)
            result = 'valid'
        except AgentProtocolError as exc:
            result = exc.code
            if result == 'missing_dependency':
                assert exc.data == {'missing': case['missing']}, case['name']
        assert result == case['expected'], case['name']


def test_views():
    for case in VECTORS['view_cases']:
        for order in case['arrival_orders']:
            assert sorted(order) == sorted(case['known'])
            model, pending = Model(), []
            for name in order:
                pending.append(name)
                progress = True
                while progress:
                    progress = False
                    for candidate in pending[:]:
                        before = model.state()
                        result = outcome(lambda: model.store.submit(envelope(candidate)))
                        if result == 'missing_dependency':
                            assert model.state() == before, 'unresolved event changed state'
                            continue
                        assert result == 'valid', candidate
                        pending.remove(candidate)
                        progress = True
            assert not pending
            known = model.store.known_envelopes()
            assert materialize_knowledge(known) == case['expected'], case['name']
            for name, links in case.get('expected_relations', {}).items():
                assert known[envelope(name)['hash']]['event']['payload']['relations'] == links, name


def test_acceptance():
    for case in VECTORS['acceptance_cases']:
        model, receipts = Model(), {}
        for step in case['steps']:
            if 'withhold' in step:
                model.store.hide(envelope(step['withhold'])['hash'])
                continue
            item = envelope(step['fixture'])
            before = model.state()
            try:
                record = model.store.submit(item, now_ms=step['now'])
                result = 'resubmission' if item['hash'] in receipts else 'accepted'
                if result == 'resubmission':
                    assert record == receipts[item['hash']], 'retry must return the original record'
                else:
                    assert record['accepted_at'] == step['now']
                    receipts[item['hash']] = record
            except AgentProtocolError as exc:
                result = exc.code
            assert result == step['expected'], case['name'] + '/' + step['fixture'] + ': ' + result
            assert model.store.checkpoint == step['seq'], case['name'] + '/' + step['fixture']
            if result != 'accepted':
                assert model.state() == before, 'rejection or retry changed state'


def test_evidence():
    for case in VECTORS['evidence_cases']:
        raw = bytes.fromhex(case['representation_hex']) if case.get('representation_hex') is not None else None
        assert verify_knowledge_evidence(case.get('digest'), raw) == case['expected'], case['name']


def test_queries():
    for case in VECTORS['query_cases']:
        def run():
            request = parse_knowledge_query(case['parameters'])
            matches = [name for name in case['accepted'] if knowledge_query_matches(envelope(name), request)]
            assert matches == case['matches'], case['name']
        assert outcome(run) == case['expected'], case['name']


def test_text_cases():
    for case in VECTORS['text_cases']:
        def run():
            assert knowledge_text_terms(case['text'], case.get('lexical', True)) == case['terms'], case['name']
            if 'fixture' in case:
                assert knowledge_text_matches(envelope(case['fixture']), case['text']) == case['matches'], case['name']
        assert outcome(run) == case['expected'], case['name']


def test_batch_cases():
    for case in VECTORS['batch_cases']:
        model = Model(case.get('accepted', []), case.get('hidden', []))
        before = model.state()
        def run():
            request = parse_knowledge_read_json(case['raw_json']) if 'raw_json' in case else case['request']
            response = apply_changes(model.store.batch(request), case.get('response_changes', []))
            validate_knowledge_batch_response(response, request['hashes'], SERVICE)
            assert [record['envelope']['hash'] for record in response['result']] == case['result'], case['name']
            assert response['missing'] == case['missing'], case['name']
            assert response['checkpoint'] == model.store.checkpoint and response['as_of'] == VECTORS['now']
        assert outcome(run) == case['expected'], case['name']
        assert model.state() == before, 'batch changed state'


def test_search_cases():
    for case in VECTORS['search_cases']:
        model = Model(case.get('accepted', []), case.get('hidden', []))
        before = model.state()
        def run():
            request = parse_knowledge_read_json(case['raw_json']) if 'raw_json' in case else case['request']
            modes = case.get('modes', KNOWLEDGE_SEARCH_MODES)
            validate_knowledge_search_request(request, modes)
            response = model.store.search(
                request, candidates=[envelope(name)['hash'] for name in case.get('candidates', [])],
                ranking=case.get('ranking', {'mode': request['mode'], 'id': 'fixture-v1'}),
                coverage=case.get('coverage', {'exhaustive': True, 'reasons': []}), modes=modes)
            response = apply_changes(response, case.get('response_changes', []))
            validate_knowledge_search_response(response, request, SERVICE)
            assert [hit['record']['envelope']['hash'] for hit in response['result']] == case.get('result', []), case['name']
        assert outcome(run) == case['expected'], case['name']
        assert model.state() == before, 'search changed state'


def test_pagination_cases():
    for case in VECTORS['pagination_cases']:
        model = Model(case['accepted'], case.get('hidden', []))
        previous = tracker = None
        for step in case['steps']:
            for name in step.get('add', []):
                model.store.submit(envelope(name))
            for name in step.get('hide', []):
                model.store.hide(envelope(name)['hash'])
            model.clock += step.get('advance_ms', 0)
            def run():
                nonlocal previous, tracker
                request = parse_knowledge_query(step['parameters'])
                if step.get('continue'):
                    request['cursor'] = previous['next_cursor']
                else:
                    tracker = KnowledgePageTracker(SERVICE)
                response = apply_changes(model.store.query(request), step.get('response_changes', []))
                tracker.accept(request, response)
                assert [r['envelope']['hash'] for r in response['result']] == [envelope(n)['hash'] for n in step['matches']], case['name']
                assert ('next_cursor' in response) == step['more'], case['name']
                previous = response
            assert outcome(run) == step['expected'], case['name']


def test_discovery_cases():
    for case in VECTORS['discovery_cases']:
        result = outcome(lambda: validate_knowledge_discovery(case['document'], case.get('origin', SERVICE)))
        assert result == case['expected'], case['name']
