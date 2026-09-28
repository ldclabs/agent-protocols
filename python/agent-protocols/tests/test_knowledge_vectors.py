"""Execute every shared Knowledge fixture through the installed SDK.

Test adapters only translate fixture names/clock values to public SDK arguments;
validation, acceptance, matching, snapshots, and response checks are SDK code.
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


def require(condition, message):
    assert condition, message


def fail(code, message):
    raise AgentProtocolError(code, message)


def _snapshot(service):
    return {'records': service.records, 'retained': service.retained, 'seq': service.seq, 'nonces': copy.deepcopy(service.nonces)}


class FixtureService:
    def __init__(self, store=None):
        self.store = store or KnowledgeStore(SERVICE, clock=lambda: VECTORS['now'])
    @property
    def records(self): return self.store.records
    @property
    def retained(self): return self.store.retained
    @property
    def seq(self): return self.store.seq
    @property
    def nonces(self): return self.store.nonce_store
    def submit(self, item, mode, now):
        return self.store.submit_with_outcome(item, mode=mode, now_ms=now)


class ReadModel:
    def __init__(self, accepted, hidden=()):
        self.clock = VECTORS['now']
        self.store = KnowledgeStore(SERVICE, clock=lambda: self.clock, search_modes=('lexical','semantic','hybrid'), snapshot_ttl_ms=9007199254740991)
        self.service = FixtureService(self.store)
        for name in accepted: self.add(name)
        self.hide(hidden)
    def add(self, name): self.store.import_event(envelope(name), now_ms=VECTORS['now'])
    def hide(self, names):
        for name in names: self.store.hide(envelope(name)['hash'])
    def reveal(self, names):
        for name in names: self.store.unhide(envelope(name)['hash'])
    def batch(self, request): return self.store.batch(request)
    def page(self, request, search=False, candidates=None, ranking=None, coverage=None, available=True):
        if search:
            return self.store.search(request, candidates=[envelope(name)['hash'] for name in candidates] if candidates is not None else None, ranking=ranking, coverage=coverage)
        return self.store.query(request, available=available)


def validate_query_response(response, request):
    validate_knowledge_query_response(response, request, SERVICE)


def validate_batch_response(response, requested):
    validate_knowledge_batch_response(response, requested, SERVICE)


def validate_search_response(response, request):
    validate_knowledge_search_response(response, request, SERVICE)


def envelope(name):
    return FIXTURES[name]["envelope"]

def apply_changes(value, changes):
    value = copy.deepcopy(value)
    for change in changes:
        keys = change["path"].lstrip("/").split("/")
        parent = value
        for key in keys[:-1]:
            parent = parent[int(key)] if isinstance(parent, list) else parent[key]
        key = int(keys[-1]) if isinstance(parent, list) else keys[-1]
        if change["op"] == "remove":
            del parent[key]
        else:
            require(change["op"] == "set", "unknown fixture mutation")
            parent[key] = change["value"]
    return value

def test_signatures():
    for name, fixture in FIXTURES.items():
        item = fixture["envelope"]
        verify_envelope(item)
        require(canonical_event_bytes(item["event"]).decode() == fixture["canonical_event_utf8"], name + ": JCS bytes")
        signer = AgentSigner.from_seed(bytes.fromhex(VECTORS["seeds"][fixture["signer"]]))
        require(item["event"]["actor"] == signer.agent_id(), name + ": actor")
        require(signer.sign_event(item["event"]) == item, name + ": deterministic signature/hash")

def test_identity_cases():
    for case in VECTORS["identity_cases"]:
        try:
            if "raw_json" in case:
                parse_strict_json(case["raw_json"])
            else:
                validate_knowledge_envelope(apply_changes(envelope(case["fixture"]), case["changes"]))
            outcome = "valid"
        except AgentProtocolError as exc:
            outcome = exc.code
        require(outcome == case["expected"], case["name"] + ": " + outcome)

def test_schema_cases():
    for case in VECTORS["schema_cases"]:
        value = case.get("value")
        if value is None:
            value = apply_changes(envelope(case["fixture"]), case["changes"])
        require(knowledge_schema_validator(case["definition"]).is_valid(value) == case["valid"], case["name"])

def test_object_cases():
    for case in VECTORS["object_cases"]:
        retained = {}
        for name in case["accepted"]:
            item = envelope(name)
            validate_knowledge_envelope(item)
            validate_knowledge_dependencies(item, retained)
            retained[item["hash"]] = item
        try:
            validate_knowledge_envelope(envelope(case["fixture"]))
            validate_knowledge_dependencies(envelope(case["fixture"]), retained)
            outcome = "valid"
        except AgentProtocolError as exc:
            outcome = exc.code
            if outcome == "missing_dependency":
                require(exc.data == {"missing": case["missing"]}, case["name"] + ": sorted missing IDs")
        require(outcome == case["expected"], case["name"] + ": " + outcome)

def test_views():
    for case in VECTORS["view_cases"]:
        for order in case["arrival_orders"]:
            require(set(order) == set(case["known"]) and len(order) == len(case["known"]), "arrival order must contain same known set")
            service, pending = FixtureService(), []
            for name in order:
                pending.append(name)
                progress = True
                while progress:
                    progress = False
                    for candidate in pending[:]:
                        before = _snapshot(service)
                        try:
                            service.submit(envelope(candidate), "import", VECTORS["now"])
                        except AgentProtocolError as exc:
                            require(exc.code == "missing_dependency", candidate + ": unexpected view rejection")
                            require(service.retained == before["retained"] and service.records == before["records"] and service.seq == before["seq"], "unresolved event changed view")
                            continue
                        pending.remove(candidate)
                        progress = True
            require(not pending, "dependency-closed fixture left unresolved objects")
            require(materialize_knowledge(service.retained) == case["expected"], case["name"] + ": arrival-order divergence")
            for name, expected_links in case.get("expected_relations", {}).items():
                retained_links = service.retained[envelope(name)["hash"]]["event"]["payload"]["relations"]
                require(retained_links == expected_links, name + ": correction/retraction rewrote signed relationships")

def test_acceptance():
    for case in VECTORS["acceptance_cases"]:
        service = FixtureService()
        for step in case["steps"]:
            if "withhold" in step:
                service.store.hide(envelope(step["withhold"])["hash"])
                continue
            item = envelope(step["fixture"])
            before = _snapshot(service)
            try:
                outcome, record = service.submit(item, step["mode"], step["now"])
                require(record["seq"] == step["seq"], case["name"] + ": record seq")
                if outcome == "resubmission":
                    require(record == before["records"][item["hash"]], "retry must return original complete record")
                else:
                    require(record["accepted_at"] == step["now"], "first acceptance uses local clock")
            except AgentProtocolError as exc:
                outcome = exc.code
                require(service.seq == step["seq"], "rejection changed sequence")
                if "max_nonce" in step:
                    require(exc.data == {"max_nonce": step["max_nonce"]}, "wrong Max-Seen-Nonce error detail")
            require(outcome == step["expected"], case["name"] + "/" + step["fixture"] + ": " + outcome)
            if outcome != "accepted":
                require(service.retained == before["retained"] and service.records == before["records"] and service.seq == before["seq"], "rejection/retry changed accepted state")
                require(service.nonces.__dict__ == before["nonces"].__dict__, "rejection/retry changed live nonce state")
            elif step["mode"] == "import":
                require(service.nonces.__dict__ == before["nonces"].__dict__, "import changed live nonce state/expiry")
            require(service.nonces.max_nonce(item["event"]["actor"], step["now"]) == step["live_max"], "wrong live nonce maximum")

def test_evidence():
    for case in VECTORS['evidence_cases']:
        raw = bytes.fromhex(case['representation_hex']) if case.get('representation_hex') is not None else None
        outcome = knowledge_evidence_status(case.get('digest'), raw, fetched=case.get('fetched', True), complete=case.get('complete', False))
        assert outcome == case['expected'], case['name']


def test_queries():
    for case in VECTORS['query_cases']:
        service = FixtureService()
        for name in case['accepted']:
            service.submit(envelope(name), 'import', VECTORS['now'])
        try:
            filters = parse_knowledge_query(case['parameters'])
            results = [name for name in case['accepted'] if knowledge_query_matches(envelope(name), filters)]
            require(results == case['matches'], case['name'] + ': wrong query matches')
            outcome = 'valid'
        except AgentProtocolError as exc:
            outcome = exc.code
        require(outcome == case['expected'], case['name'] + ': ' + outcome)

def test_text_cases():
    for case in VECTORS['text_cases']:
        try:
            terms = knowledge_text_terms(case['text'], case.get('lexical', True))
            require(terms == case['terms'], case['name'] + ': terms')
            if 'fixture' in case:
                require(knowledge_text_matches(envelope(case['fixture']), case['text']) == case['matches'], case['name'] + ': matching')
            outcome = 'valid'
        except AgentProtocolError as exc:
            outcome = exc.code
        require(outcome == case['expected'], case['name'] + ': ' + outcome)

def test_batch_cases():
    for case in VECTORS['batch_cases']:
        model = ReadModel(case.get('accepted', []), case.get('hidden', []))
        before = _snapshot(model.service)
        try:
            request = parse_knowledge_read_json(case['raw_json']) if 'raw_json' in case else case['request']
            response = model.batch(request)
            response = apply_changes(response, case.get('response_changes', []))
            validate_batch_response(response, request['hashes'])
            require([record['envelope']['hash'] for record in response['result']] == case['result'], case['name'] + ': result')
            require(response['missing'] == case['missing'], case['name'] + ': missing')
            require(response['service'] == SERVICE and response['checkpoint'] == model.service.seq and response['as_of'] == VECTORS['now'], case['name'] + ': scope')
            outcome = 'valid'
        except AgentProtocolError as exc:
            outcome = exc.code
        require(outcome == case['expected'], case['name'] + ': ' + outcome)
        require(model.service.records == before['records'] and model.service.retained == before['retained']
                and model.service.seq == before['seq'] and model.service.nonces.__dict__ == before['nonces'].__dict__, 'batch changed acceptance/nonces')

def test_search_cases():
    for case in VECTORS['search_cases']:
        model = ReadModel(case.get('accepted', []), case.get('hidden', []))
        before = _snapshot(model.service)
        try:
            request = parse_knowledge_read_json(case['raw_json']) if 'raw_json' in case else case['request']
            validate_knowledge_search(request, case.get('modes', ['lexical', 'semantic', 'hybrid']))
            response = model.page(request, search=True, candidates=case.get('candidates', []),
                                  ranking=case.get('ranking', {'mode': request['mode'], 'id': 'fixture-v1'}),
                                  coverage=case.get('coverage', {'exhaustive': True, 'reasons': []}))
            response = apply_changes(response, case.get('response_changes', []))
            validate_search_response(response, request)
            require([hit['record']['envelope']['hash'] for hit in response['result']] == case.get('result', []), case['name'] + ': result')
            outcome = 'valid'
        except AgentProtocolError as exc:
            outcome = exc.code
        require(outcome == case['expected'], case['name'] + ': ' + outcome)
        require(model.service.records == before['records'] and model.service.retained == before['retained']
                and model.service.seq == before['seq'] and model.service.nonces.__dict__ == before['nonces'].__dict__, 'search changed acceptance/nonces')

def test_snapshot_cases():
    for case in VECTORS['query_snapshot_cases']:
        model = ReadModel(case['accepted'], case.get('hidden', []))
        previous = None
        frozen = None
        for step in case['steps']:
            for name in step.get('add', []):
                model.add(name)
            model.hide(step.get('hide', []))
            model.reveal(step.get('reveal', []))
            model.clock += step.get('advance_ms', 0)
            if step.get('expire'):
                model.store.expire_snapshots()
            try:
                search = case.get('operation') == 'search'
                request = (validate_knowledge_search(copy.deepcopy(step['request']), case.get('modes', ['lexical', 'semantic']))
                           if search else parse_knowledge_query(step['parameters']))
                if step.get('continue'):
                    request['cursor'] = previous['next_cursor']
                response = model.page(request, search=search, candidates=step.get('candidates', case.get('candidates')),
                                      ranking=step.get('ranking', case.get('ranking')), coverage=step.get('coverage', case.get('coverage')),
                                      available=step.get('available', True))
                response = apply_changes(response, step.get('response_changes', []))
                if search:
                    validate_search_response(response, request)
                else:
                    validate_query_response(response, request)
                records = [hit['record'] for hit in response['result']] if search else response['result']
                require([record['envelope']['hash'] for record in records] == [envelope(name)['hash'] for name in step['matches']], case['name'] + ': snapshot matches')
                require(('next_cursor' in response) == step['more'], case['name'] + ': next cursor')
                scope = {key: response[key] for key in ('service', 'checkpoint', 'as_of')}
                if step.get('continue'):
                    if scope != frozen:
                        fail('invalid_response', 'snapshot scope changed across pages')
                else:
                    frozen = scope
                if search:
                    require([hit['rank'] for hit in response['result']] == step['ranks'], case['name'] + ': ranks changed')
                    require(response['ranking'] == case['ranking'] and response['coverage'] == case['coverage'], case['name'] + ': ranking/coverage changed')
                previous = response
                outcome = 'valid'
            except AgentProtocolError as exc:
                outcome = exc.code
            require(outcome == step['expected'], case['name'] + ': ' + outcome)

def test_discovery_cases():
    for case in VECTORS['discovery_cases']:
        try:
            validate_knowledge_discovery(case['document'], case.get('origin', SERVICE))
            outcome = 'valid'
        except AgentProtocolError as exc:
            outcome = exc.code
        require(outcome == case['expected'], case['name'] + ': ' + outcome)
