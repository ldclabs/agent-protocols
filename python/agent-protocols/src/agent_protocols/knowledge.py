"""Agent Knowledge 1.0 signed contributions, exact discovery, and an in-memory store.

Knowledge events are immutable, portable objects: acceptance verifies them and
their dependencies but never consults a live-write nonce cache. The store is a
process-local reference implementation, not durable storage. No evidence,
profiles, or procedures are fetched or executed. Public methods return detached
copies of mutable state.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import ipaddress
import json
import re
import threading
from collections.abc import Mapping as MappingABC
from importlib.resources import files
from typing import Any, Callable, Iterable, Iterator, Literal, Mapping, TypedDict
from urllib.parse import urlsplit

import rfc8785
from jsonschema import Draft202012Validator, FormatChecker

from .errors import AgentProtocolError
from .identity import (
    MAX_SAFE_NONCE, Envelope, Event, create_event, parse_strict_json, unix_ms,
    validate_origin, verify_envelope,
)

KNOWLEDGE_PROTOCOL = "agent-knowledge/1.0"
KNOWLEDGE_PUBLISH = "knowledge.publish"
KNOWLEDGE_ASSESS = "knowledge.assess"
KNOWLEDGE_RETRACT = "knowledge.retract"
KNOWLEDGE_EVENT_TYPES = (KNOWLEDGE_PUBLISH, KNOWLEDGE_ASSESS, KNOWLEDGE_RETRACT)
KNOWLEDGE_KINDS = ("question", "hypothesis", "definition", "observation", "inference", "procedure", "resource", "negative_result", "synthesis", "collection")
KNOWLEDGE_RELATIONS = ("derived_from", "addresses", "tests", "extends", "supports", "contradicts", "supersedes", "contains")
KNOWLEDGE_VERDICTS = ("supports", "challenges", "reproduced", "not_reproduced", "applied", "inconclusive")
KNOWLEDGE_SEARCH_MODES = ("lexical", "semantic", "hybrid")
KNOWLEDGE_ERROR_CODES = ("missing_dependency", "invalid_target", "invalid_cursor", "query_too_broad", "query_unavailable", "unsupported_search_mode")
DEFAULT_FUTURE_SKEW_MS = 300_000
DEFAULT_MAX_ENVELOPE_BYTES = 262_144
EvidenceStatus = Literal["unchecked", "matched", "mismatched", "unavailable"]
SCHEMA = parse_strict_json(files(__package__).joinpath("knowledge.schema.json").read_bytes())
ASCII_FOLD = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')
# Relationships that may point at an assessment as well as a publication.
_ASSESSMENT_RELATIONS = ("derived_from", "supports", "contradicts")
_READ_ONLY = ("q", "cursor", "limit", "after_seq")
_VALIDATORS = {name: Draft202012Validator({"$ref": "#/$defs/" + name, "$defs": SCHEMA["$defs"]}, format_checker=FormatChecker()) for name in SCHEMA["$defs"]}


def fail(code: str, message: str, data: dict | None = None) -> None:
    raise AgentProtocolError(code, message, data)


def validate_knowledge_schema(value: Any, definition: str = "signedEnvelope", code: str = "invalid_event") -> None:
    """Check one bundled structural definition; signatures need separate checks."""
    _json_value(value, code)
    if not _VALIDATORS[definition].is_valid(value):
        fail(code, definition + " schema violation")


def _json_value(value: Any, code: str) -> None:
    try:
        parse_strict_json(json.dumps(value, ensure_ascii=False))
    except (AgentProtocolError, ValueError, TypeError, OverflowError) as exc:
        fail(code, "value violates strict I-JSON: " + str(exc))


def _identity_envelope(item: Envelope) -> Envelope:
    """Give Identity safe-integer fields without changing the signed JSON object."""
    normalized = copy.deepcopy(item)
    normalized['event']['nonce'] = int(normalized['event']['nonce'])
    normalized['event']['created_at'] = int(normalized['event']['created_at'])
    return normalized


def _normalize_read_numbers(value: Mapping[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(dict(value))
    for key in ('created_from', 'created_before', 'limit', 'after_seq'):
        if key in normalized:
            normalized[key] = int(normalized[key])
    if 'filters' in normalized:
        normalized['filters'] = _normalize_read_numbers(normalized['filters'])
    return normalized


def validate_knowledge_id(value: Any, code: str = "invalid_event") -> None:
    """Require a canonical unpadded base64url encoding of exactly 32 bytes."""
    try:
        raw = base64.urlsafe_b64decode(value + "=")
    except (ValueError, TypeError):
        fail(code, "invalid digest encoding")
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        fail(code, "ID must canonically encode 32 bytes")


def _https_url(value: Any, code: str = "invalid_event") -> None:
    try:
        parsed = urlsplit(value)
        valid = (parsed.scheme == "https" and bool(parsed.hostname)
                 and parsed.username is None and parsed.password is None
                 and "\\" not in value and not any(ord(c) <= 32 for c in value))
        # Access validates port syntax/range in urllib; no fetching is performed.
        _ = parsed.port
    except (ValueError, TypeError, AttributeError):
        valid = False
    if not valid:
        fail(code, "URL must be absolute HTTPS with a host and no userinfo")


def _knowledge_origin(url: str) -> str:
    """Normalize an HTTPS URL origin, including IPv6 and internationalized hosts."""
    _https_url(url)
    parsed = urlsplit(url)
    try:
        host = parsed.hostname.encode('idna').decode('ascii')
        if ':' in host:
            host = '[' + ipaddress.IPv6Address(host).compressed + ']'
        origin = 'https://' + host + (':' + str(parsed.port) if parsed.port not in (None, 443) else '')
        validate_origin(origin)
    except (UnicodeError, ValueError) as exc:
        fail('invalid_event', 'invalid URL origin: ' + str(exc))
    return origin


def knowledge_publish_event(actor: str, created_at: int, nonce: int, payload: dict[str, Any]) -> Event:
    return create_event(KNOWLEDGE_PROTOCOL, KNOWLEDGE_PUBLISH, actor, created_at, nonce, copy.deepcopy(payload))


def knowledge_assess_event(actor: str, created_at: int, nonce: int, payload: dict[str, Any]) -> Event:
    return create_event(KNOWLEDGE_PROTOCOL, KNOWLEDGE_ASSESS, actor, created_at, nonce, copy.deepcopy(payload))


def knowledge_retract_event(actor: str, created_at: int, nonce: int, payload: dict[str, Any]) -> Event:
    return create_event(KNOWLEDGE_PROTOCOL, KNOWLEDGE_RETRACT, actor, created_at, nonce, copy.deepcopy(payload))


def validate_knowledge_envelope(item: Envelope) -> None:
    """Structure, Identity hash/signature, URLs, canonical IDs and profile uniqueness.

    Dependencies are checked separately; nothing is fetched."""
    validate_knowledge_schema(item)
    verify_envelope(_identity_envelope(item))
    payload = item["event"]["payload"]
    validate_knowledge_id(item["hash"])
    _https_url(payload["license"])
    for evidence in payload.get("evidence", []):
        _https_url(evidence["url"])
        if "digest" in evidence:
            validate_knowledge_id(evidence["digest"])
    profile_digests = set()
    for binding in payload.get("profiles", []):
        profile = binding["profile"]
        _https_url(profile["url"])
        validate_knowledge_id(profile["digest"])
        if profile["digest"] in profile_digests:
            fail("invalid_event", "profile bindings must be unique by digest")
        profile_digests.add(profile["digest"])
    for target in knowledge_dependencies(item):
        validate_knowledge_id(target)


def parse_knowledge_envelope(raw: str | bytes) -> Envelope:
    item = parse_strict_json(raw)
    validate_knowledge_envelope(item)
    return item


def knowledge_dependencies(item: Envelope) -> list[str]:
    """Sorted, distinct direct dependencies."""
    payload = item["event"]["payload"]
    if item["event"]["type"] == KNOWLEDGE_PUBLISH:
        return sorted({relation["target"] for relation in payload.get("relations", [])})
    return [payload["target"]]


def validate_knowledge_dependencies(item: Envelope, retained: Mapping[str, Envelope]) -> None:
    """Check target rules against retained, already validated envelopes."""
    missing = sorted(set(knowledge_dependencies(item)) - set(retained.keys()))
    if missing:
        fail("missing_dependency", "unresolved targets", {"missing": missing})
    event, payload = item["event"], item["event"]["payload"]
    links = (payload.get("relations", []) if event["type"] == KNOWLEDGE_PUBLISH
             else [{"relation": event["type"], "target": payload["target"]}])
    for link in links:
        target = retained[link["target"]]["event"]
        relation = link["relation"]
        allowed = ((KNOWLEDGE_PUBLISH, KNOWLEDGE_ASSESS) if relation in (KNOWLEDGE_RETRACT, *_ASSESSMENT_RELATIONS)
                   else (KNOWLEDGE_PUBLISH,))
        if target["type"] not in allowed:
            fail("invalid_target", "wrong target type")
        kind = {"addresses": "question", "tests": "hypothesis"}.get(relation)
        if kind is not None and target["payload"]["kind"] != kind:
            fail("invalid_target", "wrong target contribution kind")
        if relation in ("supersedes", KNOWLEDGE_RETRACT) and (
                target["actor"] != event["actor"] or target["nonce"] >= event["nonce"]):
            fail("invalid_target", "target must have same actor and smaller nonce")


def materialize_knowledge(known: Mapping[str, Envelope]) -> dict[str, Any]:
    """Derive order-independent lifecycle facts from a dependency-closed known set."""
    known = copy.deepcopy(dict(known))
    for event_id, item in known.items():
        validate_knowledge_envelope(item)
        if item['hash'] != event_id:
            fail('invalid_event', 'known-set key differs from envelope hash')
    for item in known.values():
        validate_knowledge_dependencies(item, known)
    withdrawn, successors, assessments = set(), {}, {}
    for event_id, item in known.items():
        kind, payload = item['event']['type'], item['event']['payload']
        if kind == KNOWLEDGE_RETRACT:
            withdrawn.add(payload['target'])
        elif kind == KNOWLEDGE_ASSESS:
            assessments.setdefault(payload['target'], set()).add(event_id)
        else:
            for relation in payload.get('relations', []):
                if relation['relation'] == 'supersedes':
                    successors.setdefault(relation['target'], set()).add(event_id)
    result = {}
    for event_id in sorted(known):
        kind = known[event_id]['event']['type']
        if kind == KNOWLEDGE_RETRACT:
            continue
        view = {'status': 'retracted' if event_id in withdrawn else 'active'}
        if kind == KNOWLEDGE_PUBLISH:
            reports = assessments.get(event_id, set())
            view.update(successors=sorted(successors.get(event_id, set())),
                        assessments=sorted(reports), active_assessments=sorted(reports - withdrawn))
        result[event_id] = view
    return result


def verify_knowledge_evidence(digest: str | None, representation: bytes | None) -> EvidenceStatus:
    """Compare a digest with complete decoded representation bytes; fetches nothing.

    Pass ``None`` when the complete representation could not be obtained."""
    if digest is None:
        return 'unchecked'
    validate_knowledge_id(digest)
    if representation is None:
        return 'unavailable'
    if not isinstance(representation, bytes):
        raise TypeError('representation must be bytes, before character or newline conversion')
    actual = base64.urlsafe_b64encode(hashlib.sha3_256(representation).digest()).rstrip(b'=').decode()
    return 'matched' if actual == digest else 'mismatched'


def _ascii_fold(value: str) -> str:
    return value.translate(ASCII_FOLD)


def knowledge_text_terms(value: str, lexical: bool = True) -> list[str]:
    if (not isinstance(value, str) or not 1 <= len(value) <= 1024
            or any(0xD800 <= ord(char) <= 0xDFFF for char in value)):
        fail('invalid_request', 'text must contain 1..1024 Unicode scalar values')
    terms = [part for part in re.split(r'[\x09-\x0d\x20]+', value) if part]
    if not terms or (lexical and len(terms) > 16):
        fail('invalid_request', 'empty text or too many lexical terms')
    return [_ascii_fold(term) for term in terms]


def _eligible_text(item: Envelope) -> list[str]:
    event, payload = item['event'], item['event']['payload']
    if event['type'] == KNOWLEDGE_RETRACT:
        return [payload['reason']]
    names = ('title', 'statement', 'basis') if event['type'] == KNOWLEDGE_PUBLISH else ('summary', 'basis')
    fields = [payload[name] for name in names]
    for value in payload['context'].values():
        fields.extend(value if isinstance(value, list) else [value])
    return fields


def knowledge_text_matches(item: Envelope, text: str) -> bool:
    fields = [_ascii_fold(field) for field in _eligible_text(item)]
    return all(any(term in field for field in fields) for term in knowledge_text_terms(text))


def _validate_filters(filters: dict[str, Any]) -> None:
    if not _VALIDATORS['searchFilters'].is_valid(filters):
        fail('invalid_request', 'malformed filter')
    for key in ('actor', 'target', 'profile'):
        if key in filters:
            validate_knowledge_id(filters[key].removeprefix('did:agent:') if key == 'actor' else filters[key], 'invalid_request')
    if ('created_from' in filters and 'created_before' in filters
            and filters['created_from'] >= filters['created_before']):
        fail('invalid_request', 'time range must be nonempty')


def validate_knowledge_query(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a parsed query and return a normalized copy."""
    validate_knowledge_schema(value, 'queryRequest', 'invalid_request')
    _validate_filters({k: v for k, v in value.items() if k not in _READ_ONLY})
    if 'q' in value:
        knowledge_text_terms(value['q'])
    return _normalize_read_numbers(value)


def parse_knowledge_query(parameters: Iterable[tuple[str, str]]) -> dict[str, Any]:
    """Parse decoded HTTP parameter pairs; duplicate keys remain observable."""
    request: dict[str, Any] = {}
    for key, value in parameters:
        if key in request or key not in SCHEMA['$defs']['queryRequest']['properties']:
            fail('invalid_request', 'unknown or repeated parameter')
        if key in ('created_from', 'created_before', 'limit', 'after_seq'):
            if not isinstance(value, str) or re.fullmatch(r'[0-9]+', value) is None:
                fail('invalid_request', 'HTTP integers use decimal digits only')
            # Bound input before converting to avoid huge-integer parser costs.
            digits = value.lstrip('0') or '0'
            if len(digits) > 16:
                fail('invalid_request', 'integer exceeds safe range')
            value = int(digits)
        request[key] = value
    return validate_knowledge_query(request)


def knowledge_query_matches(item: Envelope, filters: Mapping[str, Any]) -> bool:
    """Exact filter and text predicate; `after_seq`, `limit` and `cursor` are not payload filters."""
    event, payload = item['event'], item['event']['payload']
    is_publication = event['type'] == KNOWLEDGE_PUBLISH
    for key in ('actor', 'type'):
        if key in filters and event[key] != filters[key]:
            return False
    if 'q' in filters and not knowledge_text_matches(item, filters['q']):
        return False
    if 'language' in filters and (not is_publication or _ascii_fold(payload['language']) != _ascii_fold(filters['language'])):
        return False
    if 'verdict' in filters and (event['type'] != KNOWLEDGE_ASSESS or payload['verdict'] != filters['verdict']):
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
        if filters['target'] not in knowledge_dependencies(item):
            return False
    return True


def parse_knowledge_read_json(raw: str | bytes) -> Any:
    try:
        return parse_strict_json(raw)
    except AgentProtocolError:
        fail('invalid_request', 'read body violates strict I-JSON')


def validate_knowledge_batch_request(value: Any) -> list[str]:
    validate_knowledge_schema(value, 'batchRequest', 'invalid_request')
    for event_id in value['hashes']:
        validate_knowledge_id(event_id, 'invalid_request')
    return list(value['hashes'])


def validate_knowledge_search_request(value: Any, modes: Iterable[str] = KNOWLEDGE_SEARCH_MODES) -> dict[str, Any]:
    """Validate an unsigned search request; an unadvertised mode is never substituted."""
    _json_value(value, "invalid_request")
    if not isinstance(value, dict):
        fail('invalid_request', 'request must be an object')
    mode = value.get('mode')
    if isinstance(mode, str) and (mode not in KNOWLEDGE_SEARCH_MODES or mode not in tuple(modes)):
        fail('unsupported_search_mode', 'explicit search mode is not advertised')
    validate_knowledge_schema(value, 'searchRequest', 'invalid_request')
    knowledge_text_terms(value['text'], lexical=mode == 'lexical')
    _validate_filters(value.get('filters', {}))
    return _normalize_read_numbers(value)


def validate_knowledge_discovery(value: Any, origin: str) -> None:
    validate_knowledge_schema(value, 'discoveryDocument', 'invalid_discovery')
    try:
        validate_origin(origin)
        validate_origin(value['service'])
        if value['service'] != origin:
            fail('invalid_discovery', 'discovery served by wrong origin')
        for endpoint in value.get('endpoints', {}).values():
            if _knowledge_origin(endpoint) != origin:
                fail('invalid_discovery', 'cross-origin endpoint')
        for peer in value.get('peers', []):
            validate_origin(peer)
            if peer == origin:
                fail('invalid_discovery', 'self peer')
    except AgentProtocolError as exc:
        fail('invalid_discovery', str(exc))


def validate_knowledge_record(record: Any, expected_hash: str | None = None) -> None:
    validate_knowledge_schema(record, 'acceptanceRecord', 'invalid_response')
    try:
        validate_knowledge_envelope(record['envelope'])
    except AgentProtocolError as exc:
        fail('invalid_response', 'invalid returned envelope: ' + str(exc))
    if expected_hash is not None and record['envelope']['hash'] != expected_hash:
        fail('invalid_response', 'returned event ID differs from requested ID')


def _response_records(response: Any, definition: str, service: str) -> list[dict[str, Any]]:
    validate_knowledge_schema(response, definition, 'invalid_response')
    try:
        validate_origin(response['service'])
    except AgentProtocolError:
        fail('invalid_response', 'noncanonical response service')
    if response['service'] != service:
        fail('invalid_response', 'response service differs from receiving origin')
    records = [hit['record'] for hit in response['result']] if definition == 'searchResponse' else response['result']
    ids = [record['envelope']['hash'] for record in records]
    if len(set(ids)) != len(ids) or any(record['seq'] > response['checkpoint'] for record in records):
        fail('invalid_response', 'duplicate event ID or record beyond checkpoint')
    for record in records:
        validate_knowledge_record(record)
    return records


def validate_knowledge_query_response(response: Any, request: Mapping[str, Any], service: str) -> None:
    records = _response_records(response, 'queryResponse', service)
    previous = request.get('after_seq', 0)
    if len(records) > request.get('limit', 100):
        fail('invalid_response', 'query page exceeds limit')
    for record in records:
        if record['seq'] <= previous or not knowledge_query_matches(record['envelope'], request):
            fail('invalid_response', 'query results violate order or exact filters')
        previous = record['seq']


def validate_knowledge_batch_response(response: Any, requested: Iterable[str], service: str) -> None:
    records = _response_records(response, 'batchResponse', service)
    requested = list(requested)
    ids = [record['envelope']['hash'] for record in records]
    missing = response['missing']
    if (set(ids) & set(missing) or set(ids) | set(missing) != set(requested)
            or ids != [event_id for event_id in requested if event_id in ids]
            or missing != [event_id for event_id in requested if event_id in missing]):
        fail('invalid_response', 'batch must be an ordered complete partition')


def validate_knowledge_search_response(response: Any, request: Mapping[str, Any], service: str) -> None:
    records = _response_records(response, 'searchResponse', service)
    if len(records) > request.get('limit', 20):
        fail('invalid_response', 'search result exceeds requested limit')
    if response['ranking']['mode'] != request['mode']:
        fail('invalid_response', 'search substituted another mode')
    for record in records:
        item = record['envelope']
        if not knowledge_query_matches(item, request.get('filters', {})):
            fail('invalid_response', 'search ignored exact filters')
        if request['mode'] == 'lexical' and not knowledge_text_matches(item, request['text']):
            fail('invalid_response', 'lexical hit does not match text')


def _query_binding(request: Mapping[str, Any]) -> dict[str, Any]:
    binding = {k: v for k, v in _normalize_read_numbers(request).items() if k != 'cursor'}
    binding.setdefault('limit', 100)
    binding.setdefault('after_seq', 0)
    return binding


class KnowledgePageTracker:
    """Verify that a sequence of query pages forms one complete, consistent enumeration."""
    def __init__(self, service: str):
        validate_origin(service)
        self.service = service
        self._binding: dict[str, Any] | None = None
        self._scope: dict[str, Any] | None = None
        self._seen: set[str] = set()
        self._last = 0
        self._next: str | None = None

    def accept(self, request: Mapping[str, Any], response: Any) -> None:
        request = validate_knowledge_query(request)
        validate_knowledge_query_response(response, request, self.service)
        binding = _query_binding(request)
        scope = {key: response[key] for key in ('service', 'checkpoint', 'as_of')}
        if self._binding is None:
            if 'cursor' in request:
                fail('invalid_response', 'a traversal must start without a cursor')
            self._last = binding['after_seq']
        elif (self._next is None or request.get('cursor') != self._next
                or binding != self._binding or scope != self._scope):
            fail('invalid_response', 'pagination request or checkpoint scope changed')
        ids = [record['envelope']['hash'] for record in response['result']]
        sequences = [record['seq'] for record in response['result']]
        if any(event_id in self._seen for event_id in ids) or (sequences and sequences[0] <= self._last):
            fail('invalid_response', 'pagination repeated an event or moved backwards')
        self._binding, self._scope = binding, scope
        self._seen.update(ids)
        if sequences:
            self._last = sequences[-1]
        self._next = response.get('next_cursor')

    @property
    def complete(self) -> bool:
        return self._binding is not None and self._next is None

    @property
    def checkpoint(self) -> int | None:
        """A persistable `after_seq` for the next poll, only after every page was consumed."""
        return self._scope['checkpoint'] if self.complete else None


class _RetainedEnvelopes(MappingABC):
    def __init__(self, records: dict[str, KnowledgeAcceptanceRecord]):
        self._records = records

    def __getitem__(self, key: str) -> Envelope:
        return self._records[key]['envelope']

    def __iter__(self) -> Iterator[str]:
        return iter(self._records)

    def __len__(self) -> int:
        return len(self._records)


def _digest(value: Any) -> str:
    return base64.urlsafe_b64encode(hashlib.sha3_256(rfc8785.dumps(value)).digest()).rstrip(b'=').decode()


class KnowledgeStore:
    """Process-local Knowledge service engine with checkpoint-bound query cursors.

    ``admit`` runs for each new acceptance after every protocol check; raising an
    AgentProtocolError refuses an otherwise valid object. Cursors are stateless:
    they encode the checkpoint, snapshot time, last returned sequence and a digest
    of the request, so no read state is retained between pages.
    """
    def __init__(self, service: str, *, clock: Callable[[], int] = unix_ms,
                 future_skew_ms: int = DEFAULT_FUTURE_SKEW_MS,
                 max_envelope_bytes: int = DEFAULT_MAX_ENVELOPE_BYTES,
                 admit: Callable[[Envelope], None] | None = None):
        validate_origin(service)
        for name, value in (('future_skew_ms', future_skew_ms), ('max_envelope_bytes', max_envelope_bytes)):
            if type(value) is not int or not 0 <= value <= MAX_SAFE_NONCE:
                raise ValueError(name + ' must be a nonnegative safe integer')
        self.service, self.clock, self.admit = service, clock, admit
        self.future_skew_ms, self.max_envelope_bytes = future_skew_ms, max_envelope_bytes
        self._lock = threading.RLock()
        self._seq = 0
        # Insertion order is ascending seq: new records always get a larger seq.
        self._records: dict[str, KnowledgeAcceptanceRecord] = {}
        self._hidden: set[str] = set()

    @property
    def checkpoint(self) -> int:
        with self._lock:
            return self._seq

    def known_envelopes(self) -> dict[str, Envelope]:
        """Publicly visible envelopes keyed by event ID."""
        with self._lock:
            return copy.deepcopy({key: record['envelope'] for key, record in self._records.items() if key not in self._hidden})

    def _now(self, now_ms: int | None = None) -> int:
        now = self.clock() if now_ms is None else now_ms
        if type(now) is not int or not 0 <= now <= MAX_SAFE_NONCE:
            raise ValueError('clock must return a nonnegative safe integer timestamp')
        return now

    def submit(self, envelope: Envelope, *, now_ms: int | None = None) -> KnowledgeAcceptanceRecord:
        """Accept a signed event, or return the original record of an exact resubmission."""
        item = copy.deepcopy(envelope)
        validate_knowledge_envelope(item)
        now = self._now(now_ms)
        with self._lock:
            if item['hash'] in self._records:
                return copy.deepcopy(self._records[item['hash']])
            if item['event']['created_at'] > now + self.future_skew_ms:
                fail('timestamp_out_of_window', 'created_at is too far in the future')
            validate_knowledge_dependencies(item, _RetainedEnvelopes(self._records))
            if len(json.dumps(item, ensure_ascii=False, separators=(',', ':')).encode()) > self.max_envelope_bytes:
                fail('payload_too_large', 'knowledge envelope exceeds byte limit')
            if self._seq >= MAX_SAFE_NONCE:
                fail('permission_denied', 'sequence space exhausted')
            if self.admit is not None:
                self.admit(copy.deepcopy(item))
            self._seq += 1
            record: KnowledgeAcceptanceRecord = {'envelope': item, 'accepted_at': now, 'seq': self._seq}
            self._records[item['hash']] = record
            return copy.deepcopy(record)

    def event(self, event_id: str) -> KnowledgeAcceptanceRecord:
        validate_knowledge_id(event_id, 'invalid_request')
        with self._lock:
            if event_id not in self._records or event_id in self._hidden:
                fail('not_found', 'event unavailable')
            return copy.deepcopy(self._records[event_id])

    def hide(self, event_id: str) -> None:
        """Withhold from public reads; the record still answers exact retries and resolves dependencies."""
        with self._lock:
            if event_id in self._records:
                self._hidden.add(event_id)

    def unhide(self, event_id: str) -> None:
        with self._lock:
            self._hidden.discard(event_id)

    def prune(self, event_id: str) -> None:
        """Drop content and record while preserving the sequence high-water mark."""
        with self._lock:
            self._records.pop(event_id, None)
            self._hidden.discard(event_id)

    def _scope(self, checkpoint: int, as_of: int) -> dict[str, Any]:
        return {'service': self.service, 'checkpoint': checkpoint, 'as_of': as_of}

    def batch(self, request: Mapping[str, Any]) -> dict[str, Any]:
        requested = validate_knowledge_batch_request(copy.deepcopy(request))
        now = self._now()
        with self._lock:
            response: dict[str, Any] = {'result': [], 'missing': [], **self._scope(self._seq, now)}
            for event_id in requested:
                if event_id in self._records and event_id not in self._hidden:
                    response['result'].append(copy.deepcopy(self._records[event_id]))
                else:
                    response['missing'].append(event_id)
            return response

    def query(self, request: Mapping[str, Any] | None = None) -> dict[str, Any]:
        request = validate_knowledge_query({} if request is None else request)
        binding = _query_binding(request)
        digest = _digest(binding)
        now = self._now()
        with self._lock:
            if 'cursor' in request:
                checkpoint, as_of, last = self._decode_cursor(request['cursor'], digest, binding['after_seq'])
            else:
                if binding['after_seq'] > self._seq:
                    fail('invalid_request', 'after_seq is greater than the current checkpoint')
                checkpoint, as_of, last = self._seq, now, binding['after_seq']
            result, more = [], False
            for event_id, record in self._records.items():
                if record['seq'] <= last or record['seq'] > checkpoint or event_id in self._hidden:
                    continue
                if not knowledge_query_matches(record['envelope'], request):
                    continue
                if len(result) == binding['limit']:
                    more = True
                    break
                result.append(copy.deepcopy(record))
            response: dict[str, Any] = {'result': result, **self._scope(checkpoint, as_of)}
            if more:
                response['next_cursor'] = f"{checkpoint}.{as_of}.{result[-1]['seq']}.{digest}"
            return response

    def _decode_cursor(self, cursor: str, digest: str, after_seq: int) -> tuple[int, int, int]:
        parts = cursor.split('.')
        if (len(parts) != 4 or parts[3] != digest
                or any(re.fullmatch(r'[0-9]{1,16}', part) is None for part in parts[:3])):
            fail('invalid_cursor', 'malformed cursor or different request')
        checkpoint, as_of, last = (int(part) for part in parts[:3])
        if not after_seq <= last <= checkpoint <= self._seq or as_of > MAX_SAFE_NONCE:
            fail('invalid_cursor', 'cursor does not belong to this service state')
        return checkpoint, as_of, last

    def search(self, request: Mapping[str, Any], *, candidates: Iterable[str], ranking: Mapping[str, Any],
               coverage: Mapping[str, Any], explanations: Mapping[str, str] | None = None,
               modes: Iterable[str] = KNOWLEDGE_SEARCH_MODES) -> dict[str, Any]:
        """Return one page of caller-ranked candidates; no ranking model is implied.

        Candidates must be visible and satisfy the exact filters (and lexical text).
        Only a lexical page containing every match may claim exhaustive coverage."""
        request = validate_knowledge_search_request(request, modes)
        limit, filters = request.get('limit', 20), request.get('filters', {})
        ids = list(candidates)
        explanations = dict(explanations or {})
        now = self._now()
        with self._lock:
            eligible = {event_id for event_id, record in self._records.items()
                        if event_id not in self._hidden and knowledge_query_matches(record['envelope'], filters)
                        and (request['mode'] != 'lexical' or knowledge_text_matches(record['envelope'], request['text']))}
            if (any(not isinstance(event_id, str) for event_id in ids) or len(ids) != len(set(ids))
                    or not set(ids) <= eligible):
                fail('invalid_response', 'candidate list violates exact filters or repeats IDs')
            if coverage.get('exhaustive') and (set(ids) != eligible or len(ids) > limit):
                fail('invalid_response', 'false exhaustive coverage')
            response = {
                'result': [{'record': copy.deepcopy(self._records[event_id]),
                            **({'explanation': explanations[event_id]} if event_id in explanations else {})}
                           for event_id in ids[:limit]],
                **self._scope(self._seq, now),
                'ranking': copy.deepcopy(dict(ranking)), 'coverage': copy.deepcopy(dict(coverage)),
            }
            validate_knowledge_schema(response, 'searchResponse', 'invalid_response')
            if response['ranking']['mode'] != request['mode']:
                fail('invalid_response', 'ranking mode differs from requested mode')
            return response


class KnowledgeContext(TypedDict):
    scope: str
    conditions: list[str]
    limitations: list[str]


class KnowledgeEvidenceRequired(TypedDict):
    url: str
    description: str


class KnowledgeEvidence(KnowledgeEvidenceRequired, total=False):
    digest: str
    media_type: str
    role: Literal['source', 'input', 'output', 'environment', 'validation']


class KnowledgeProfileReference(TypedDict):
    url: str
    digest: str


class KnowledgeProfileBinding(TypedDict):
    profile: KnowledgeProfileReference
    data: dict[str, Any]


class KnowledgeRelation(TypedDict):
    relation: Literal['derived_from', 'addresses', 'tests', 'extends', 'supports', 'contradicts', 'supersedes', 'contains']
    target: str


class KnowledgeReproductionRequired(TypedDict):
    environment: str
    steps: list[str]
    expected: str


class KnowledgeReproduction(KnowledgeReproductionRequired, total=False):
    observed: str


class KnowledgePublishRequired(TypedDict):
    license: str
    kind: Literal['question', 'hypothesis', 'definition', 'observation', 'inference', 'procedure', 'resource', 'negative_result', 'synthesis', 'collection']
    title: str
    statement: str
    language: str
    context: KnowledgeContext
    basis: str


class KnowledgePublishPayload(KnowledgePublishRequired, total=False):
    evidence: list[KnowledgeEvidence]
    reproduction: KnowledgeReproduction
    relations: list[KnowledgeRelation]
    tags: list[str]
    profiles: list[KnowledgeProfileBinding]
    extra: dict[str, Any]


class KnowledgeAssessRequired(TypedDict):
    license: str
    target: str
    verdict: Literal['supports', 'challenges', 'reproduced', 'not_reproduced', 'applied', 'inconclusive']
    summary: str
    context: KnowledgeContext
    basis: str


class KnowledgeAssessPayload(KnowledgeAssessRequired, total=False):
    evidence: list[KnowledgeEvidence]
    reproduction: KnowledgeReproduction
    profiles: list[KnowledgeProfileBinding]
    extra: dict[str, Any]


class KnowledgeRetractRequired(TypedDict):
    license: str
    target: str
    reason: str


class KnowledgeRetractPayload(KnowledgeRetractRequired, total=False):
    extra: dict[str, Any]


class KnowledgeAcceptanceRecord(TypedDict):
    envelope: Envelope
    accepted_at: int
    seq: int


__all__ = [
    'KNOWLEDGE_PROTOCOL', 'KNOWLEDGE_PUBLISH', 'KNOWLEDGE_ASSESS', 'KNOWLEDGE_RETRACT',
    'KNOWLEDGE_EVENT_TYPES', 'KNOWLEDGE_KINDS', 'KNOWLEDGE_RELATIONS', 'KNOWLEDGE_VERDICTS',
    'KNOWLEDGE_SEARCH_MODES', 'KNOWLEDGE_ERROR_CODES', 'DEFAULT_FUTURE_SKEW_MS', 'DEFAULT_MAX_ENVELOPE_BYTES',
    'EvidenceStatus', 'KnowledgeContext', 'KnowledgeAcceptanceRecord',
    'KnowledgeEvidence', 'KnowledgeProfileReference', 'KnowledgeProfileBinding',
    'KnowledgeRelation', 'KnowledgeReproduction', 'KnowledgePublishPayload',
    'KnowledgeAssessPayload', 'KnowledgeRetractPayload', 'KnowledgeStore', 'KnowledgePageTracker',
    'knowledge_publish_event', 'knowledge_assess_event', 'knowledge_retract_event',
    'validate_knowledge_schema', 'validate_knowledge_envelope', 'parse_knowledge_envelope',
    'validate_knowledge_dependencies', 'validate_knowledge_id', 'knowledge_dependencies',
    'materialize_knowledge', 'verify_knowledge_evidence',
    'knowledge_text_terms', 'knowledge_text_matches', 'knowledge_query_matches',
    'parse_knowledge_read_json', 'parse_knowledge_query', 'validate_knowledge_query',
    'validate_knowledge_batch_request', 'validate_knowledge_search_request', 'validate_knowledge_discovery',
    'validate_knowledge_record', 'validate_knowledge_query_response',
    'validate_knowledge_batch_response', 'validate_knowledge_search_response',
]
