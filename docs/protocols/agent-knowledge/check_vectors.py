#!/usr/bin/env python3
"""Development check for the Agent Knowledge draft, not a production SDK.

Run from any directory with a Python environment containing the repository's
Identity dependencies and jsonschema, for example:
    .venv/bin/python docs/protocols/agent-knowledge/check_vectors.py

This deliberately small model executes structural, object, known-set, evidence,
text/filter, batch-partition, discovery, snapshot/candidate-pagination, ranked-search
contract, and live/import fixtures. Its finite read model does not implement HTTP,
persistence, authorization, concurrency, ranking or embedding algorithms, service
resource enforcement, removal policy, discovery networking, artifact fetching, or
disciplinary profile validation/execution. invalid_response and invalid_discovery
are local checker diagnoses, not additional wire error codes.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "python/agent-protocols/src"))
try:
    from jsonschema import Draft202012Validator, FormatChecker
    from agent_protocols.errors import AgentProtocolError
    from agent_protocols.identity import (
        AgentSigner,
        MemoryNonceStore,
        canonical_event_bytes,
        parse_strict_json,
        verify_envelope,
        verify_submission,
        validate_origin,
    )
except ImportError as exc:
    raise SystemExit("Use an environment with the Python Identity dependencies and jsonschema: " + str(exc))

HERE = Path(__file__).resolve().parent
SCHEMA = parse_strict_json(HERE.joinpath("1.0.schema.json").read_bytes())
# The vector container deliberately includes invalid numeric/JSON values in
# structural mutations; strict parsing is applied to the signed fixtures.
VECTORS = json.loads(HERE.joinpath("1.0.vectors.json").read_bytes())
Draft202012Validator.check_schema(SCHEMA)
FIXTURES = VECTORS["fixtures"]
WINDOW = 300_000
TTL = 2 * WINDOW


def require(condition, message):
    # Explicit checks remain effective under python -O.
    if not condition:
        raise AssertionError(message)


def fail(code, message, data=None):
    raise AgentProtocolError(code, message, data)


def validator(definition="signedEnvelope"):
    return Draft202012Validator(
        {"$ref": "#/$defs/" + definition, "$defs": SCHEMA["$defs"]},
        format_checker=FormatChecker(),
    )


def envelope(name):
    return FIXTURES[name]["envelope"]


def canonical_digest(value):
    try:
        raw = base64.urlsafe_b64decode(value + "=")
    except (ValueError, TypeError):
        fail("invalid_event", "invalid digest encoding")
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        fail("invalid_event", "digest must encode exactly 32 bytes canonically")


def https_url(value):
    try:
        parsed = urlsplit(value)
        valid = (parsed.scheme == "https" and bool(parsed.hostname)
                 and parsed.username is None and parsed.password is None
                 and "\\" not in value and not any(ord(c) <= 32 for c in value))
        # Access validates port syntax/range in urllib; no fetching is performed.
        _ = parsed.port
    except ValueError:
        valid = False
    if not valid:
        fail("invalid_event", "URL must be absolute HTTPS with a host and no userinfo")


def common_validation(item):
    # Exercise the existing strict I-JSON parser, JCS and deterministic verifier.
    parse_strict_json(json.dumps(item, ensure_ascii=False))
    if not validator().is_valid(item):
        fail("invalid_event", "schema violation")
    verify_envelope(item)
    event, payload = item["event"], item["event"]["payload"]
    canonical_digest(item["hash"])
    https_url(payload["license"])
    for evidence in payload.get("evidence", []):
        https_url(evidence["url"])
        if "digest" in evidence:
            canonical_digest(evidence["digest"])
    profile_digests = set()
    for binding in payload.get("profiles", []):
        profile = binding["profile"]
        https_url(profile["url"])
        canonical_digest(profile["digest"])
        if profile["digest"] in profile_digests:
            fail("invalid_event", "profile bindings must be unique by digest")
        profile_digests.add(profile["digest"])
        # Binding validity says nothing about the profile's data conformance.
        # Unknown artifacts are preserved; this model never fetches or runs them.
    for target in dependencies(item):
        canonical_digest(target)
    if payload.get("learned_at", 0) > event["created_at"]:
        fail("invalid_event", "learned_at exceeds created_at")


def dependencies(item):
    event, payload = item["event"], item["event"]["payload"]
    if event["type"] == "knowledge.publish":
        return sorted({relation["target"] for relation in payload.get("relations", [])})
    return [payload["target"]]


def validate_targets(item, retained):
    missing = sorted(set(dependencies(item)) - retained.keys())
    if missing:
        fail("missing_dependency", "unresolved targets", {"missing": missing})
    event, payload = item["event"], item["event"]["payload"]
    links = (payload.get("relations", []) if event["type"] == "knowledge.publish"
             else [{"relation": event["type"], "target": payload["target"]}])
    for link in links:
        target = retained[link["target"]]["event"]
        allowed = ("knowledge.publish", "knowledge.assess") if link["relation"] == "knowledge.retract" else ("knowledge.publish",)
        if target["type"] not in allowed:
            fail("invalid_target", "wrong target type")
        target_kind = {"addresses": "question", "tests": "hypothesis"}.get(link["relation"])
        if target_kind is not None and target["payload"]["kind"] != target_kind:
            fail("invalid_target", "wrong target contribution kind")
        if link["relation"] in ("supersedes", "knowledge.retract"):
            if target["actor"] != event["actor"] or target["nonce"] >= event["nonce"]:
                fail("invalid_target", "target must have same actor and smaller nonce")


class FixtureService:
    """Single-threaded acceptance model limited to the declared vector cases."""

    def __init__(self):
        self.retained = {}
        self.records = {}
        self.nonces = MemoryNonceStore()
        self.seq = 0

    def submit(self, item, mode, now):
        common_validation(item)
        # Identity verification precedes lookup; retries precede dependency,
        # freshness and nonce checks, even when a dependency was later withheld.
        if item["hash"] in self.records:
            return "resubmission", self.records[item["hash"]]
        validate_targets(item, self.retained)
        if mode == "live":
            verify_submission(item, self.nonces, now_ms=now, window_ms=WINDOW, nonce_ttl_ms=TTL)
        elif mode == "import":
            if item["event"]["created_at"] > now + WINDOW:
                fail("timestamp_out_of_window", "unknown historical object is too far in the future")
        else:
            raise AssertionError("unknown fixture mode " + mode)
        self.seq += 1
        record = {"envelope": item, "seq": self.seq, "accepted_at": now}
        require(validator("acceptanceRecord").is_valid(record), "invalid generated acceptance record")
        self.records[item["hash"]] = record
        self.retained[item["hash"]] = item
        return "accepted", record


def materialize(retained):
    withdrawn = {item["event"]["payload"]["target"] for item in retained.values()
                 if item["event"]["type"] == "knowledge.retract"}
    result = {}
    for event_id, item in retained.items():
        kind = item["event"]["type"]
        if kind == "knowledge.retract":
            continue
        view = {"status": "retracted" if event_id in withdrawn else "active"}
        if kind == "knowledge.publish":
            view["successors"] = sorted({candidate_id for candidate_id, candidate in retained.items()
                if candidate["event"]["type"] == "knowledge.publish"
                and {"relation": "supersedes", "target": event_id} in candidate["event"]["payload"].get("relations", [])})
            view["assessments"] = sorted(candidate_id for candidate_id, candidate in retained.items()
                if candidate["event"]["type"] == "knowledge.assess"
                and candidate["event"]["payload"]["target"] == event_id)
            view["active_assessments"] = sorted(set(view["assessments"]) - withdrawn)
        result[event_id] = view
    return result


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


def check_signatures():
    for name, fixture in FIXTURES.items():
        item = fixture["envelope"]
        verify_envelope(item)
        require(canonical_event_bytes(item["event"]).decode() == fixture["canonical_event_utf8"], name + ": JCS bytes")
        signer = AgentSigner.from_seed(bytes.fromhex(VECTORS["seeds"][fixture["signer"]]))
        require(item["event"]["actor"] == signer.agent_id(), name + ": actor")
        require(signer.sign_event(item["event"]) == item, name + ": deterministic signature/hash")


def check_identity_cases():
    for case in VECTORS["identity_cases"]:
        try:
            if "raw_json" in case:
                parse_strict_json(case["raw_json"])
            else:
                common_validation(apply_changes(envelope(case["fixture"]), case["changes"]))
            outcome = "valid"
        except AgentProtocolError as exc:
            outcome = exc.code
        require(outcome == case["expected"], case["name"] + ": " + outcome)


def check_schema_cases():
    for case in VECTORS["schema_cases"]:
        value = case.get("value")
        if value is None:
            value = apply_changes(envelope(case["fixture"]), case["changes"])
        require(validator(case["definition"]).is_valid(value) == case["valid"], case["name"])


def check_object_cases():
    for case in VECTORS["object_cases"]:
        retained = {}
        for name in case["accepted"]:
            item = envelope(name)
            common_validation(item)
            validate_targets(item, retained)
            retained[item["hash"]] = item
        try:
            common_validation(envelope(case["fixture"]))
            validate_targets(envelope(case["fixture"]), retained)
            outcome = "valid"
        except AgentProtocolError as exc:
            outcome = exc.code
            if outcome == "missing_dependency":
                require(exc.data == {"missing": case["missing"]}, case["name"] + ": sorted missing IDs")
        require(outcome == case["expected"], case["name"] + ": " + outcome)


def check_views():
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
                        before = copy.deepcopy(service.__dict__)
                        try:
                            service.submit(envelope(candidate), "import", VECTORS["now"])
                        except AgentProtocolError as exc:
                            require(exc.code == "missing_dependency", candidate + ": unexpected view rejection")
                            require(service.retained == before["retained"] and service.records == before["records"] and service.seq == before["seq"], "unresolved event changed view")
                            continue
                        pending.remove(candidate)
                        progress = True
            require(not pending, "dependency-closed fixture left unresolved objects")
            require(materialize(service.retained) == case["expected"], case["name"] + ": arrival-order divergence")
            for name, expected_links in case.get("expected_relations", {}).items():
                retained_links = service.retained[envelope(name)["hash"]]["event"]["payload"]["relations"]
                require(retained_links == expected_links, name + ": correction/retraction rewrote signed relationships")


def check_acceptance():
    for case in VECTORS["acceptance_cases"]:
        service = FixtureService()
        for step in case["steps"]:
            if "withhold" in step:
                del service.retained[envelope(step["withhold"])["hash"]]
                continue
            item = envelope(step["fixture"])
            before = copy.deepcopy(service.__dict__)
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


def check_evidence():
    for case in VECTORS["evidence_cases"]:
        if not case.get("fetched", True) or "digest" not in case:
            outcome = "unchecked"
        elif case.get("representation_hex") is None or not case.get("complete", False):
            outcome = "unavailable"
        else:
            raw = bytes.fromhex(case["representation_hex"])
            digest = base64.urlsafe_b64encode(hashlib.sha3_256(raw).digest()).rstrip(b"=").decode()
            outcome = "matched" if digest == case["digest"] else "mismatched"
        require(outcome == case["expected"], case["name"] + ": " + outcome)


ASCII_FOLD = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')
SERVICE = 'https://knowledge.example.com'


def ascii_fold(value):
    return value.translate(ASCII_FOLD)


def text_terms(value, lexical=True):
    if (not isinstance(value, str) or not 1 <= len(value) <= 1024
            or any(0xD800 <= ord(char) <= 0xDFFF for char in value)):
        fail('invalid_request', 'text must contain 1..1024 Unicode scalar values')
    terms = [part for part in re.split(r'[\x09-\x0d\x20]+', value) if part]
    if not terms or (lexical and len(terms) > 16):
        fail('invalid_request', 'empty text or too many lexical terms')
    return [ascii_fold(term) for term in terms]


def eligible_text(item):
    event, payload = item['event'], item['event']['payload']
    if event['type'] == 'knowledge.retract':
        return [payload['reason']]
    names = ('title', 'statement', 'basis') if event['type'] == 'knowledge.publish' else ('summary', 'basis')
    fields = [payload[name] for name in names]
    for value in payload['context'].values():
        fields.extend(value if isinstance(value, list) else [value])
    return fields


def text_matches(item, text):
    fields = [ascii_fold(field) for field in eligible_text(item)]
    return all(any(term in field for field in fields) for term in text_terms(text))


def validate_filter_object(filters):
    if not validator('searchFilters').is_valid(filters):
        fail('invalid_request', 'malformed filter')
    for key in ('actor', 'target', 'profile'):
        if key in filters:
            try:
                canonical_digest(filters[key].removeprefix('did:agent:') if key == 'actor' else filters[key])
            except AgentProtocolError:
                fail('invalid_request', 'noncanonical filter')
    if ('created_from' in filters and 'created_before' in filters
            and filters['created_from'] >= filters['created_before']):
        fail('invalid_request', 'time range must be nonempty')
    return filters


def query_filters(parameters):
    """Parse decoded HTTP parameter pairs; duplicate keys remain observable."""
    filters = {}
    for key, value in parameters:
        if key in filters or key not in SCHEMA['$defs']['queryRequest']['properties']:
            fail('invalid_request', 'unknown or repeated parameter')
        if key in ('created_from', 'created_before', 'limit'):
            if not isinstance(value, str) or re.fullmatch(r'[0-9]+', value) is None:
                fail('invalid_request', 'HTTP integers use decimal digits only')
            # Bound input before converting to avoid huge-integer parser costs.
            digits = value.lstrip('0') or '0'
            if len(digits) > 16:
                fail('invalid_request', 'integer exceeds safe range')
            value = int(digits)
        filters[key] = value
    if not validator('queryRequest').is_valid(filters):
        fail('invalid_request', 'malformed query')
    validate_filter_object({k: v for k, v in filters.items() if k not in ('q', 'limit', 'cursor')})
    if 'q' in filters:
        text_terms(filters['q'])
    return filters


def query_matches(item, filters):
    event, payload = item['event'], item['event']['payload']
    is_publication = event['type'] == 'knowledge.publish'
    for key in ('actor', 'type'):
        if key in filters and event[key] != filters[key]:
            return False
    if 'q' in filters and not text_matches(item, filters['q']):
        return False
    if 'language' in filters and (not is_publication or ascii_fold(payload['language']) != ascii_fold(filters['language'])):
        return False
    if 'verdict' in filters and (event['type'] != 'knowledge.assess' or payload['verdict'] != filters['verdict']):
        return False
    if 'created_from' in filters and event['created_at'] < filters['created_from']:
        return False
    if 'created_before' in filters and event['created_at'] >= filters['created_before']:
        return False
    if 'kind' in filters and (not is_publication or payload['kind'] != filters['kind']):
        return False
    if 'tag' in filters and (not is_publication or filters['tag'] not in payload.get('tags', [])):
        return False
    if 'profile' in filters and not any(binding['profile']['digest'] == filters['profile']
                                         for binding in payload.get('profiles', [])):
        return False
    if 'relation' in filters:
        if not is_publication or not any(
            link['relation'] == filters['relation']
            and ('target' not in filters or link['target'] == filters['target'])
            for link in payload.get('relations', [])
        ):
            return False
    elif 'target' in filters:
        if filters['target'] not in dependencies(item):
            return False
    return True


def parse_read_json(raw):
    try:
        return parse_strict_json(raw)
    except AgentProtocolError:
        fail('invalid_request', 'read body violates strict I-JSON')


def search_request(value, modes):
    parse_read_json(json.dumps(value, ensure_ascii=True))
    if not isinstance(value, dict):
        fail('invalid_request', 'request must be an object')
    if isinstance(value.get('mode'), str) and (value['mode'] not in ('lexical', 'semantic', 'hybrid') or value['mode'] not in modes):
        fail('unsupported_search_mode', 'explicit search mode is not advertised')
    if not validator('searchRequest').is_valid(value):
        fail('invalid_request', 'malformed search request')
    text_terms(value['text'], lexical=value['mode'] == 'lexical')
    validate_filter_object(value.get('filters', {}))
    return value


def batch_request(value):
    parse_read_json(json.dumps(value, ensure_ascii=True))
    if not validator('batchRequest').is_valid(value):
        fail('invalid_request', 'malformed batch request')
    try:
        for event_id in value['hashes']:
            canonical_digest(event_id)
    except AgentProtocolError:
        fail('invalid_request', 'noncanonical event ID')
    return value['hashes']


def check_response_shape(response, definition):
    if not validator(definition).is_valid(response):
        fail('invalid_response', 'response schema violation')
    try:
        validate_origin(response['service'])
    except AgentProtocolError:
        fail('invalid_response', 'noncanonical response service')
    if response['service'] != SERVICE:
        fail('invalid_response', 'response service does not match receiving origin')
    records = ([hit['record'] for hit in response['result']]
               if definition == 'searchResponse' else response['result'])
    ids = [record['envelope']['hash'] for record in records]
    if len(ids) != len(set(ids)) or any(record['seq'] > response['checkpoint'] for record in records):
        fail('invalid_response', 'duplicate ID or record beyond snapshot')
    for record in records:
        verify_envelope(record['envelope'])


def validate_query_response(response, request):
    check_response_shape(response, 'queryResponse')
    records = response['result']
    if len(records) > request.get('limit', 100):
        fail('invalid_response', 'query page exceeds requested limit')
    sequences = [record['seq'] for record in records]
    if sequences != sorted(set(sequences)) or any(not query_matches(record['envelope'], request) for record in records):
        fail('invalid_response', 'query results violate order or exact filters')


def validate_batch_response(response, requested):
    check_response_shape(response, 'batchResponse')
    result = [record['envelope']['hash'] for record in response['result']]
    missing = response['missing']
    if (set(result) & set(missing) or set(result) | set(missing) != set(requested)
            or result != [event_id for event_id in requested if event_id in result]
            or missing != [event_id for event_id in requested if event_id in missing]):
        fail('invalid_response', 'batch must be a complete ordered partition')


def validate_search_response(response, request):
    check_response_shape(response, 'searchResponse')
    if len(response['result']) > request.get('limit', 20):
        fail('invalid_response', 'search page exceeds requested limit')
    if response['ranking']['mode'] != request['mode']:
        fail('invalid_response', 'search mode substitution')
    ranks = [hit['rank'] for hit in response['result']]
    if ranks != sorted(set(ranks)):
        fail('invalid_response', 'nonincreasing or duplicate ranks')
    for hit in response['result']:
        item = hit['record']['envelope']
        if not query_matches(item, request.get('filters', {})):
            fail('invalid_response', 'search ignored exact filters')
        if request['mode'] == 'lexical' and not text_matches(item, request['text']):
            fail('invalid_response', 'lexical hit does not match text')


def validate_discovery(value, origin):
    if not validator('discoveryDocument').is_valid(value):
        fail('invalid_discovery', 'discovery schema violation')
    try:
        validate_origin(value['service'])
        if value['service'] != origin:
            fail('invalid_discovery', 'discovery served by wrong origin')
        for endpoint in value.get('endpoints', {}).values():
            https_url(endpoint)
            parsed = urlsplit(endpoint)
            host = parsed.hostname
            authority = '[' + host + ']' if ':' in host else host
            endpoint_origin = 'https://' + authority + (':' + str(parsed.port) if parsed.port not in (None, 443) else '')
            if endpoint_origin != origin:
                fail('invalid_discovery', 'cross-origin endpoint')
        for peer in value.get('peers', []):
            validate_origin(peer)
            if peer == origin:
                fail('invalid_discovery', 'self peer')
        scope = value.get('collection_scope', {})
        languages = [ascii_fold(language) for language in scope.get('languages', [])]
        if len(languages) != len(set(languages)):
            fail('invalid_discovery', 'duplicate language hint')
        for digest in scope.get('profiles', []):
            canonical_digest(digest)
    except AgentProtocolError as exc:
        fail('invalid_discovery', str(exc))


class ReadModel:
    """Finite in-memory read/snapshot model, not an HTTP or ranking implementation."""

    def __init__(self, accepted, hidden=()):
        self.service = FixtureService()
        for name in accepted:
            self.add(name)
        self.hide(hidden)
        self.snapshots = {}
        self.clock = VECTORS['now']

    def add(self, name):
        self.service.submit(envelope(name), 'import', VECTORS['now'])

    def hide(self, names):
        for name in names:
            self.service.retained.pop(envelope(name)['hash'], None)

    def reveal(self, names):
        for name in names:
            event_id = envelope(name)['hash']
            self.service.retained[event_id] = self.service.records[event_id]['envelope']

    def metadata(self):
        return {'service': SERVICE, 'checkpoint': self.service.seq, 'as_of': self.clock}

    def batch(self, request):
        requested = batch_request(request)
        response = {'result': [], 'missing': [], **self.metadata()}
        for event_id in requested:
            record = self.service.records.get(event_id)
            if event_id in self.service.retained and record['seq'] <= response['checkpoint']:
                response['result'].append(copy.deepcopy(record))
            else:
                response['missing'].append(event_id)
        validate_batch_response(response, requested)
        return response

    def page(self, request, search=False, candidates=None, ranking=None, coverage=None, available=True):
        limit = request.get('limit', 20 if search else 100)
        binding = {k: v for k, v in request.items() if k != 'cursor'}
        binding['limit'] = limit
        if search:
            binding.setdefault('filters', {})
        if 'cursor' in request:
            snapshot = self.snapshots.get(request['cursor'])
            if snapshot is None or snapshot['binding'] != binding or snapshot['search'] != search:
                fail('invalid_cursor', 'expired or incompatible cursor')
            snapshot = copy.deepcopy(snapshot)
        else:
            if not available:
                fail('query_unavailable', 'exact enumeration unavailable')
            eligible = [event_id for event_id, record in self.service.records.items()
                        if event_id in self.service.retained
                        and query_matches(record['envelope'], request.get('filters', {}) if search else request)
                        and (not search or request['mode'] != 'lexical' or text_matches(record['envelope'], request['text']))]
            ids = [envelope(name)['hash'] for name in candidates] if search else eligible
            if len(ids) != len(set(ids)) or any(event_id not in eligible for event_id in ids):
                fail('invalid_response', 'candidate list violates exact filters or repeats IDs')
            if search and coverage['exhaustive'] and set(ids) != set(eligible):
                fail('invalid_response', 'false exhaustive enumeration')
            snapshot = {'binding': binding, 'search': search, 'ids': ids, 'offset': 0,
                        'metadata': self.metadata(), 'ranking': copy.deepcopy(ranking),
                        'coverage': copy.deepcopy(coverage)}
        response = {'result': [], **snapshot['metadata']}
        while snapshot['offset'] < len(snapshot['ids']) and len(response['result']) < limit:
            index = snapshot['offset']
            snapshot['offset'] += 1
            event_id = snapshot['ids'][index]
            if event_id not in self.service.retained:
                continue
            record = copy.deepcopy(self.service.records[event_id])
            response['result'].append({'record': record, 'rank': index + 1,
                                       'explanation': 'Fixture candidate selected under ' + snapshot['ranking']['id']}
                                      if search else record)
        if any(event_id in self.service.retained for event_id in snapshot['ids'][snapshot['offset']:]):
            token = 'fixture-cursor-' + str(len(self.snapshots) + 1)
            self.snapshots[token] = snapshot
            response['next_cursor'] = token
        if search:
            response.update(ranking=snapshot['ranking'], coverage=snapshot['coverage'])
            validate_search_response(response, request)
        else:
            validate_query_response(response, request)
        return response


def check_queries():
    for case in VECTORS['query_cases']:
        service = FixtureService()
        for name in case['accepted']:
            service.submit(envelope(name), 'import', VECTORS['now'])
        try:
            filters = query_filters(case['parameters'])
            results = [name for name in case['accepted'] if query_matches(envelope(name), filters)]
            require(results == case['matches'], case['name'] + ': wrong query matches')
            outcome = 'valid'
        except AgentProtocolError as exc:
            outcome = exc.code
        require(outcome == case['expected'], case['name'] + ': ' + outcome)


def check_text_cases():
    for case in VECTORS['text_cases']:
        try:
            terms = text_terms(case['text'], case.get('lexical', True))
            require(terms == case['terms'], case['name'] + ': terms')
            if 'fixture' in case:
                require(text_matches(envelope(case['fixture']), case['text']) == case['matches'], case['name'] + ': matching')
            outcome = 'valid'
        except AgentProtocolError as exc:
            outcome = exc.code
        require(outcome == case['expected'], case['name'] + ': ' + outcome)


def check_batch_cases():
    for case in VECTORS['batch_cases']:
        model = ReadModel(case.get('accepted', []), case.get('hidden', []))
        before = copy.deepcopy(model.service.__dict__)
        try:
            request = parse_read_json(case['raw_json']) if 'raw_json' in case else case['request']
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


def check_search_cases():
    for case in VECTORS['search_cases']:
        model = ReadModel(case.get('accepted', []), case.get('hidden', []))
        before = copy.deepcopy(model.service.__dict__)
        try:
            request = parse_read_json(case['raw_json']) if 'raw_json' in case else case['request']
            search_request(request, case.get('modes', ['lexical', 'semantic', 'hybrid']))
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


def check_snapshot_cases():
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
                model.snapshots.clear()
            try:
                search = case.get('operation') == 'search'
                request = (search_request(copy.deepcopy(step['request']), case.get('modes', ['lexical', 'semantic']))
                           if search else query_filters(step['parameters']))
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


def check_discovery_cases():
    for case in VECTORS['discovery_cases']:
        try:
            validate_discovery(case['document'], case.get('origin', SERVICE))
            outcome = 'valid'
        except AgentProtocolError as exc:
            outcome = exc.code
        require(outcome == case['expected'], case['name'] + ': ' + outcome)


def main():
    check_signatures()
    check_identity_cases()
    check_schema_cases()
    check_object_cases()
    check_views()
    check_acceptance()
    check_evidence()
    check_queries()
    check_text_cases()
    check_batch_cases()
    check_search_cases()
    check_snapshot_cases()
    check_discovery_cases()
    print("Agent Knowledge draft development checks passed: "
          f"{len(FIXTURES)} signed fixtures, "
          + ", ".join(f"{len(VECTORS[key])} {key.replace('_cases', '')} cases"
                      for key in ("identity_cases", "schema_cases", "object_cases", "view_cases", "acceptance_cases", "evidence_cases", "query_cases", "text_cases", "batch_cases", "search_cases", "query_snapshot_cases", "discovery_cases"))
          + ". This is not a complete SDK or HTTP conformance suite.")


if __name__ == "__main__":
    main()
