"""Agent Knowledge 1.0 signed objects, exact discovery, and an in-memory service.

The store serializes acceptance and read snapshots. It is a process-local reference
implementation, not durable storage. Callers provide a shared nonce store when the
same service accepts other protocols, and persist sequence history before exposing
an origin from a durable deployment. No evidence, profiles, or procedures are fetched
or executed implicitly. Public methods return detached copies of mutable state.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import ipaddress
import json
import re
import secrets
import threading
from collections import OrderedDict
from importlib.resources import files
from typing import Any, Callable, Iterable, Literal, Mapping, TypedDict
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker
from .errors import AgentProtocolError
from .identity import (
    Envelope, Event, MemoryNonceStore, NonceStore, MAX_SAFE_NONCE,
    create_event, parse_strict_json, verify_envelope, verify_submission,
    validate_origin, validate_agent_id, service_origin, unix_ms,
)

KNOWLEDGE_PROTOCOL = "agent-knowledge/1.0"
KNOWLEDGE_PUBLISH = "knowledge.publish"
KNOWLEDGE_ASSESS = "knowledge.assess"
KNOWLEDGE_RETRACT = "knowledge.retract"
KNOWLEDGE_EVENT_TYPES = (KNOWLEDGE_PUBLISH, KNOWLEDGE_ASSESS, KNOWLEDGE_RETRACT)
KNOWLEDGE_KINDS = ("question", "hypothesis", "definition", "observation", "inference", "procedure", "resource", "negative_result", "synthesis", "collection")
KNOWLEDGE_RELATIONS = ("derived_from", "supports", "contradicts", "supersedes", "extends", "addresses", "tests", "contains")
KNOWLEDGE_VERDICTS = ("supports", "challenges", "reproduced", "not_reproduced", "applied", "inconclusive")
KNOWLEDGE_ERROR_CODES = ("missing_dependency", "invalid_target", "invalid_cursor", "query_unavailable", "query_too_broad", "unsupported_search_mode")
EvidenceStatus = Literal["unchecked", "matched", "mismatched", "unavailable"]
SCHEMA = parse_strict_json(files(__package__).joinpath("knowledge.schema.json").read_bytes())
ASCII_FOLD = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')
_VALIDATORS = {name: Draft202012Validator({"$ref": "#/$defs/" + name, "$defs": SCHEMA["$defs"]}, format_checker=FormatChecker()) for name in SCHEMA["$defs"]}


class KnowledgeContext(TypedDict):
    scope: str
    conditions: list[str]
    limitations: list[str]


class KnowledgeAcceptanceRecord(TypedDict):
    envelope: Envelope
    accepted_at: int
    seq: int


def fail(code: str, message: str, data: dict | None = None) -> None:
    raise AgentProtocolError(code, message, data)


def _validator(definition: str = "signedEnvelope") -> Draft202012Validator:
    return _VALIDATORS[definition]


def knowledge_schema_validator(definition: str = "signedEnvelope") -> Draft202012Validator:
    """Return a detached structural validator; signatures need separate checks."""
    return Draft202012Validator(copy.deepcopy(_VALIDATORS[definition].schema), format_checker=FormatChecker())


def _json_value(value: Any, code: str) -> None:
    try:
        parse_strict_json(json.dumps(value, ensure_ascii=False))
    except (AgentProtocolError, ValueError, TypeError, OverflowError) as exc:
        fail(code, "value violates strict I-JSON: " + str(exc))


def _shape(value: Any, definition: str, code: str = "invalid_request") -> None:
    _json_value(value, code)
    if not _validator(definition).is_valid(value):
        fail(code, definition + " schema violation")



def _is_safe_integer(value: Any, minimum: int = 0, maximum: int = MAX_SAFE_NONCE) -> bool:
    # JSON's number model and JCS treat 1 and 1.0 identically. Reject bools,
    # fractions and nonfinite/out-of-range values before Python int conversion.
    return (type(value) in (int, float) and minimum <= value <= maximum
            and value == int(value))


def _identity_envelope(item: Envelope) -> Envelope:
    """Give Identity safe-integer fields without changing the signed JSON object."""
    normalized = copy.deepcopy(item)
    normalized['event']['nonce'] = int(normalized['event']['nonce'])
    normalized['event']['created_at'] = int(normalized['event']['created_at'])
    return normalized


def _normalize_read_numbers(value: Mapping[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(dict(value))
    for key in ('created_from', 'created_before', 'limit', 'after'):
        if key in normalized:
            normalized[key] = int(normalized[key])
    if 'filters' in normalized:
        normalized['filters'] = _normalize_read_numbers(normalized['filters'])
    return normalized

def validate_knowledge_id(value: str) -> None:
    try:
        raw = base64.urlsafe_b64decode(value + "=")
    except (ValueError, TypeError):
        fail("invalid_event", "invalid digest encoding")
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        fail("invalid_event", "digest must encode exactly 32 bytes canonically")

def _https_url(value: Any) -> None:
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
        fail("invalid_event", "URL must be absolute HTTPS with a host and no userinfo")


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

def validate_knowledge_envelope(item: Envelope) -> None:
    _json_value(item, "invalid_event")
    if not _validator().is_valid(item):
        fail("invalid_event", "schema violation")
    verify_envelope(_identity_envelope(item))
    event, payload = item["event"], item["event"]["payload"]
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
        # Binding validity says nothing about the profile's data conformance.
        # Unknown artifacts are preserved without fetching or executing them.
    for target in knowledge_dependencies(item):
        validate_knowledge_id(target)
    if payload.get("learned_at", 0) > event["created_at"]:
        fail("invalid_event", "learned_at exceeds created_at")

def knowledge_dependencies(item: Envelope) -> list[str]:
    event, payload = item["event"], item["event"]["payload"]
    if event["type"] == "knowledge.publish":
        return sorted({relation["target"] for relation in payload.get("relations", [])})
    return [payload["target"]]

def validate_knowledge_dependencies(item: Envelope, retained: Mapping[str, Envelope]) -> None:
    """Validate target semantics against locally validated, retained envelopes."""
    missing = sorted(set(knowledge_dependencies(item)) - retained.keys())
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

def materialize_knowledge(retained: Mapping[str, Envelope]) -> dict[str, Any]:
    """Derive lifecycle facts only from a validated dependency-closed known set."""
    known = copy.deepcopy(dict(retained))
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
    for event_id, item in known.items():
        kind = item['event']['type']
        if kind == KNOWLEDGE_RETRACT:
            continue
        view = {'status': 'retracted' if event_id in withdrawn else 'active'}
        if kind == KNOWLEDGE_PUBLISH:
            reports = assessments.get(event_id, set())
            view.update(successors=sorted(successors.get(event_id, set())),
                        assessments=sorted(reports), active_assessments=sorted(reports - withdrawn))
        result[event_id] = view
    return result

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
    if event['type'] == 'knowledge.retract':
        return [payload['reason']]
    names = ('title', 'statement', 'basis') if event['type'] == 'knowledge.publish' else ('summary', 'basis')
    fields = [payload[name] for name in names]
    for value in payload['context'].values():
        fields.extend(value if isinstance(value, list) else [value])
    return fields

def knowledge_text_matches(item: Envelope, text: str) -> bool:
    fields = [_ascii_fold(field) for field in _eligible_text(item)]
    return all(any(term in field for field in fields) for term in knowledge_text_terms(text))

def _validate_filter_object(filters: dict[str, Any]) -> dict[str, Any]:
    if not _validator('searchFilters').is_valid(filters):
        fail('invalid_request', 'malformed filter')
    for key in ('actor', 'target', 'profile'):
        if key in filters:
            try:
                validate_knowledge_id(filters[key].removeprefix('did:agent:') if key == 'actor' else filters[key])
            except AgentProtocolError:
                fail('invalid_request', 'noncanonical filter')
    if ('created_from' in filters and 'created_before' in filters
            and filters['created_from'] >= filters['created_before']):
        fail('invalid_request', 'time range must be nonempty')
    return filters

def parse_knowledge_query(parameters: Iterable[tuple[str, str]]) -> dict[str, Any]:
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
    if not _validator('queryRequest').is_valid(filters):
        fail('invalid_request', 'malformed query')
    _validate_filter_object({k: v for k, v in filters.items() if k not in ('q', 'limit', 'cursor')})
    if 'q' in filters:
        knowledge_text_terms(filters['q'])
    return filters

def knowledge_query_matches(item: Envelope, filters: Mapping[str, Any]) -> bool:
    event, payload = item['event'], item['event']['payload']
    is_publication = event['type'] == 'knowledge.publish'
    for key in ('actor', 'type'):
        if key in filters and event[key] != filters[key]:
            return False
    if 'q' in filters and not knowledge_text_matches(item, filters['q']):
        return False
    if 'language' in filters and (not is_publication or _ascii_fold(payload['language']) != _ascii_fold(filters['language'])):
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
        if filters['target'] not in knowledge_dependencies(item):
            return False
    return True

def parse_knowledge_read_json(raw: str | bytes) -> Any:
    try:
        return parse_strict_json(raw)
    except AgentProtocolError:
        fail('invalid_request', 'read body violates strict I-JSON')

def validate_knowledge_search(value: Any, modes: Iterable[str]) -> dict[str, Any]:
    _json_value(value, "invalid_request")
    if not isinstance(value, dict):
        fail('invalid_request', 'request must be an object')
    if isinstance(value.get('mode'), str) and (value['mode'] not in ('lexical', 'semantic', 'hybrid') or value['mode'] not in modes):
        fail('unsupported_search_mode', 'explicit search mode is not advertised')
    if not _validator('searchRequest').is_valid(value):
        fail('invalid_request', 'malformed search request')
    knowledge_text_terms(value['text'], lexical=value['mode'] == 'lexical')
    _validate_filter_object(value.get('filters', {}))
    return _normalize_read_numbers(value)

def validate_knowledge_batch(value: Any) -> list[str]:
    _json_value(value, "invalid_request")
    if not _validator('batchRequest').is_valid(value):
        fail('invalid_request', 'malformed batch request')
    try:
        for event_id in value['hashes']:
            validate_knowledge_id(event_id)
    except AgentProtocolError:
        fail('invalid_request', 'noncanonical event ID')
    return value['hashes']

def validate_knowledge_discovery(value: Any, origin: str) -> None:
    _json_value(value, 'invalid_discovery')
    if not _validator('discoveryDocument').is_valid(value):
        fail('invalid_discovery', 'discovery schema violation')
    try:
        validate_origin(value['service'])
        if value['service'] != origin:
            fail('invalid_discovery', 'discovery served by wrong origin')
        for endpoint in value.get('endpoints', {}).values():
            _https_url(endpoint)
            endpoint_origin = _knowledge_origin(endpoint)
            if endpoint_origin != origin:
                fail('invalid_discovery', 'cross-origin endpoint')
        for peer in value.get('peers', []):
            validate_origin(peer)
            if peer == origin:
                fail('invalid_discovery', 'self peer')
        scope = value.get('collection_scope', {})
        languages = [_ascii_fold(language) for language in scope.get('languages', [])]
        if len(languages) != len(set(languages)):
            fail('invalid_discovery', 'duplicate language hint')
        for digest in scope.get('profiles', []):
            validate_knowledge_id(digest)
    except AgentProtocolError as exc:
        fail('invalid_discovery', str(exc))


def validate_knowledge_event(event: Event) -> None:
    """Validate an unsigned Knowledge event, including canonical references."""
    _shape(event, 'knowledgeEvent', 'invalid_event')
    validate_agent_id(event['actor'])
    payload = event['payload']
    _https_url(payload['license'])
    for evidence in payload.get('evidence', []):
        _https_url(evidence['url'])
        if 'digest' in evidence:
            validate_knowledge_id(evidence['digest'])
    validate_knowledge_profiles(payload.get('profiles', []))
    for target in knowledge_dependencies({'event': event}):
        validate_knowledge_id(target)
    if payload.get('learned_at', 0) > event['created_at']:
        fail('invalid_event', 'learned_at exceeds created_at')


def validate_knowledge_profiles(bindings: list[dict[str, Any]]) -> None:
    """Check signed bindings only; unknown profile data is never claimed conformant."""
    _shape(bindings, 'profiles', 'invalid_event')
    seen = set()
    for binding in bindings:
        profile = binding['profile']
        _https_url(profile['url'])
        validate_knowledge_id(profile['digest'])
        if profile['digest'] in seen:
            fail('invalid_event', 'profile digests must be unique')
        seen.add(profile['digest'])


def knowledge_event(event_type: str, actor: str, created_at: int, nonce: int, payload: dict[str, Any]) -> Event:
    if not _is_safe_integer(nonce, 1) or not _is_safe_integer(created_at):
        fail('invalid_event', 'nonce and created_at must be safe integers')
    event = create_event(KNOWLEDGE_PROTOCOL, event_type, actor, int(created_at), int(nonce), copy.deepcopy(payload))
    validate_knowledge_event(event)
    return event


def knowledge_publish_event(actor: str, created_at: int, nonce: int, payload: dict[str, Any]) -> Event:
    return knowledge_event(KNOWLEDGE_PUBLISH, actor, created_at, nonce, payload)


def knowledge_assess_event(actor: str, created_at: int, nonce: int, payload: dict[str, Any]) -> Event:
    return knowledge_event(KNOWLEDGE_ASSESS, actor, created_at, nonce, payload)


def knowledge_retract_event(actor: str, created_at: int, nonce: int, payload: dict[str, Any]) -> Event:
    return knowledge_event(KNOWLEDGE_RETRACT, actor, created_at, nonce, payload)


def knowledge_evidence_status(digest: str | None, representation: bytes | None = None, *, fetched: bool = False, complete: bool = False) -> EvidenceStatus:
    """Check complete decoded HTTP representation bytes, without fetching anything."""
    if digest is None or not fetched:
        return 'unchecked'
    validate_knowledge_id(digest)
    if representation is None or not complete:
        return 'unavailable'
    if not isinstance(representation, bytes):
        raise TypeError('representation must be bytes, before character or newline conversion')
    actual = base64.urlsafe_b64encode(hashlib.sha3_256(representation).digest()).rstrip(b'=').decode()
    return 'matched' if actual == digest else 'mismatched'


def validate_knowledge_query(value: Mapping[str, Any]) -> dict[str, Any]:
    _shape(value, 'queryRequest')
    _validate_filter_object({k: v for k, v in value.items() if k not in ('q', 'cursor', 'limit')})
    if 'q' in value:
        knowledge_text_terms(value['q'])
    return _normalize_read_numbers(value)


def parse_knowledge_changes(parameters: Iterable[tuple[str, str]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in parameters:
        if key not in ('after', 'limit', 'cursor') or key in result:
            fail('invalid_request', 'unknown or repeated changes parameter')
        if key != 'cursor':
            if not isinstance(value, str) or re.fullmatch(r'[0-9]+', value) is None:
                fail('invalid_request', 'HTTP integers use decimal digits only')
            digits = value.lstrip('0') or '0'
            if len(digits) > 16:
                fail('invalid_request', 'integer exceeds safe range')
            value = int(digits)
        result[key] = value
    return validate_knowledge_changes(result)


def validate_knowledge_changes(value: Mapping[str, Any]) -> dict[str, Any]:
    _json_value(value, 'invalid_request')
    if not isinstance(value, dict) or set(value) - {'after', 'limit', 'cursor'}:
        fail('invalid_request', 'invalid changes request')
    if not _is_safe_integer(value.get('after', 0)):
        fail('invalid_request', 'invalid changes checkpoint')
    if not _is_safe_integer(value.get('limit', 100), 1, 1000):
        fail('invalid_request', 'invalid changes limit')
    if 'cursor' in value and (not isinstance(value['cursor'], str) or not value['cursor']):
        fail('invalid_request', 'invalid cursor')
    return _normalize_read_numbers(value)


def validate_knowledge_record(record: Any, *, expected_hash: str | None = None) -> None:
    _shape(record, 'acceptanceRecord', 'invalid_response')
    try:
        validate_knowledge_envelope(record['envelope'])
    except AgentProtocolError as exc:
        fail('invalid_response', 'invalid returned envelope: ' + str(exc))
    if expected_hash is not None and record['envelope']['hash'] != expected_hash:
        fail('invalid_response', 'returned event ID differs from requested ID')


def _response_shape(response: Any, definition: str, service: str) -> list[dict[str, Any]]:
    _shape(response, definition, 'invalid_response')
    try:
        validate_origin(response['service'])
    except AgentProtocolError:
        fail('invalid_response', 'noncanonical response service')
    if response['service'] != service:
        fail('invalid_response', 'response service differs from receiving origin')
    records = [hit['record'] for hit in response['result']] if definition == 'searchResponse' else response['result']
    ids = [record['envelope']['hash'] for record in records]
    sequences = [record['seq'] for record in records]
    if len(set(ids)) != len(ids) or len(set(sequences)) != len(sequences) or any(record['seq'] > response['checkpoint'] for record in records):
        fail('invalid_response', 'duplicate event ID or record beyond snapshot')
    for record in records:
        validate_knowledge_record(record)
    return records


def validate_knowledge_query_response(response: Any, request: Mapping[str, Any], service: str) -> None:
    records = _response_shape(response, 'queryResponse', service)
    sequences = [record['seq'] for record in records]
    if len(records) > request.get('limit', 100) or sequences != sorted(set(sequences)):
        fail('invalid_response', 'query results violate order or limit')
    if any(not knowledge_query_matches(record['envelope'], request) for record in records):
        fail('invalid_response', 'query results violate exact filters')


def validate_knowledge_batch_response(response: Any, requested: Iterable[str], service: str) -> None:
    records = _response_shape(response, 'batchResponse', service)
    requested = list(requested)
    ids = [record['envelope']['hash'] for record in records]
    missing = response['missing']
    if (set(ids) & set(missing) or set(ids) | set(missing) != set(requested)
            or ids != [event_id for event_id in requested if event_id in ids]
            or missing != [event_id for event_id in requested if event_id in missing]):
        fail('invalid_response', 'batch must be an ordered complete partition')


def validate_knowledge_search_response(response: Any, request: Mapping[str, Any], service: str) -> None:
    _response_shape(response, 'searchResponse', service)
    if len(response['result']) > request.get('limit', 20):
        fail('invalid_response', 'search page exceeds requested limit')
    if response['ranking']['mode'] != request['mode']:
        fail('invalid_response', 'search substituted another mode')
    ranks = [hit['rank'] for hit in response['result']]
    if ranks != sorted(set(ranks)):
        fail('invalid_response', 'search ranks must strictly increase')
    for hit in response['result']:
        item = hit['record']['envelope']
        if not knowledge_query_matches(item, request.get('filters', {})):
            fail('invalid_response', 'search ignored exact filters')
        if request['mode'] == 'lexical' and not knowledge_text_matches(item, request['text']):
            fail('invalid_response', 'lexical hit does not match text')


def validate_knowledge_changes_response(response: Any, request: Mapping[str, Any], service: str) -> None:
    # Changes requires only checkpoint; unknown service/time fields are ignored.
    _json_value(response, 'invalid_response')
    if not isinstance(response, dict) or not isinstance(response.get('result'), list):
        fail('invalid_response', 'invalid changes response')
    checkpoint = response.get('checkpoint')
    if not _is_safe_integer(checkpoint) or checkpoint < request.get('after', 0):
        fail('invalid_response', 'invalid changes checkpoint')
    if 'next_cursor' in response and (not isinstance(response['next_cursor'], str) or not response['next_cursor']):
        fail('invalid_response', 'invalid changes cursor')
    if len(response['result']) > request.get('limit', 100):
        fail('invalid_response', 'changes exceeds requested limit')
    previous, seen = request.get('after', 0), set()
    for record in response['result']:
        validate_knowledge_record(record)
        event_id = record['envelope']['hash']
        if not previous < record['seq'] <= checkpoint or event_id in seen:
            fail('invalid_response', 'changes outside checkpoint or repeated ID')
        previous = record['seq']
        seen.add(event_id)


def _request_binding(request: Mapping[str, Any], operation: str) -> dict[str, Any]:
    binding = {k: copy.deepcopy(v) for k, v in request.items() if k != 'cursor'}
    binding.setdefault('limit', 20 if operation == 'search' else 100)
    if operation == 'search':
        binding.setdefault('filters', {})
    if operation == 'changes':
        binding.setdefault('after', 0)
    return binding


class KnowledgePageTracker:
    """Verify a complete traversal's scope, request, identity, and ordering."""
    def __init__(self, service: str, operation: Literal['query', 'search', 'changes'] = 'query'):
        validate_origin(service)
        if operation not in ('query', 'search', 'changes'):
            raise ValueError('unknown knowledge operation')
        self.service, self.operation = service, operation
        self._binding = self._scope = None
        self._seen: set[str] = set()
        self._seen_sequences: set[int] = set()
        self._cursors: set[str] = set()
        self._last = 0
        self._next: str | None = None

    def accept(self, response: Any, request: Mapping[str, Any]) -> None:
        validators = {'query': validate_knowledge_query_response, 'search': validate_knowledge_search_response, 'changes': validate_knowledge_changes_response}
        validators[self.operation](response, request, self.service)
        binding = _request_binding(request, self.operation)
        scope = ({'checkpoint': response['checkpoint']} if self.operation == 'changes' else
                 {key: response[key] for key in ('service', 'checkpoint', 'as_of')})
        if self.operation == 'search':
            scope.update(ranking=response['ranking'], coverage=response['coverage'])
        if self._binding is not None:
            if self._next is None or request.get('cursor') != self._next or binding != self._binding or scope != self._scope:
                fail('invalid_response', 'pagination request, scope, or configuration changed')
        elif 'cursor' in request:
            fail('invalid_response', 'a traversal must start without a cursor')
        positions, ids, sequences = [], [], []
        for entry in response['result']:
            record = entry['record'] if self.operation == 'search' else entry
            positions.append(entry['rank'] if self.operation == 'search' else record['seq'])
            ids.append(record['envelope']['hash'])
            sequences.append(record['seq'])
        if (any(event_id in self._seen for event_id in ids) or any(seq in self._seen_sequences for seq in sequences)
                or (positions and positions[0] <= self._last)):
            fail('invalid_response', 'pagination repeated an ID or moved backwards')
        cursor = response.get('next_cursor')
        if cursor is not None and cursor in self._cursors:
            fail('invalid_response', 'pagination cursor loop')
        self._binding, self._scope = copy.deepcopy(binding), copy.deepcopy(scope)
        self._seen.update(ids)
        self._seen_sequences.update(sequences)
        if positions:
            self._last = positions[-1]
        self._next = cursor
        if cursor is not None:
            self._cursors.add(cursor)

    @property
    def complete(self) -> bool:
        return self._binding is not None and self._next is None

    @property
    def checkpoint(self) -> int | None:
        """Only expose a persistable checkpoint after every page has been consumed."""
        return int(self._scope['checkpoint']) if self.complete else None


class KnowledgeStore:
    """Bounded process-local Knowledge service with exact, frozen read snapshots.

    Share ``nonce_store`` and, for concurrent multi-protocol writes, ``lock``
    with the enclosing service. Custom nonce stores must atomically reject
    without mutation and update only on success. ``admit`` runs before nonce
    mutation; raising an AgentProtocolError rejects an otherwise valid object.
    Historical import never reads or changes the live nonce cache.
    """
    def __init__(self, service: str, *, nonce_store: NonceStore | None = None,
                 clock: Callable[[], int] = unix_ms, window_ms: int = 300_000,
                 nonce_ttl_ms: int = 600_000, snapshot_ttl_ms: int = 300_000,
                 max_snapshots: int = 256, max_records: int = 100_000,
                 max_envelope_bytes: int = 262_144, high_water: int = 0,
                 import_enabled: bool = True, search_modes: Iterable[str] = (),
                 admit: Callable[[Envelope, str], None] | None = None,
                 lock: Any | None = None):
        validate_origin(service)
        for name, value in [('window_ms', window_ms), ('nonce_ttl_ms', nonce_ttl_ms),
                            ('snapshot_ttl_ms', snapshot_ttl_ms), ('max_snapshots', max_snapshots),
                            ('max_records', max_records), ('max_envelope_bytes', max_envelope_bytes)]:
            if type(value) is not int or not 1 <= value <= MAX_SAFE_NONCE:
                raise ValueError(name + ' must be a positive safe integer')
        if nonce_ttl_ms < 2 * window_ms:
            raise ValueError('nonce_ttl_ms must be at least twice window_ms')
        if type(high_water) is not int or not 0 <= high_water <= MAX_SAFE_NONCE:
            raise ValueError('high_water must be a nonnegative safe integer')
        modes = tuple(search_modes)
        if (len(set(modes)) != len(modes) or any(mode not in ('lexical', 'semantic', 'hybrid') for mode in modes)
                or (modes and 'lexical' not in modes)):
            raise ValueError('search_modes must be unique recognized modes including lexical')
        self.service, self.clock = service, clock
        self.nonce_store = nonce_store if nonce_store is not None else MemoryNonceStore()
        self.window_ms, self.nonce_ttl_ms = window_ms, nonce_ttl_ms
        self.snapshot_ttl_ms, self.max_snapshots = snapshot_ttl_ms, max_snapshots
        self.max_records, self.max_envelope_bytes = max_records, max_envelope_bytes
        self.import_enabled, self.search_modes, self.admit = import_enabled, modes, admit
        self._lock = lock if lock is not None else threading.RLock()
        self._seq = high_water
        self._records: dict[str, KnowledgeAcceptanceRecord] = {}
        self._hidden: set[str] = set()
        self._snapshots: OrderedDict[str, dict[str, Any]] = OrderedDict()

    @property
    def seq(self) -> int:
        with self._lock:
            return self._seq

    @property
    def records(self) -> dict[str, KnowledgeAcceptanceRecord]:
        with self._lock:
            return copy.deepcopy(self._records)

    @property
    def retained(self) -> dict[str, Envelope]:
        with self._lock:
            return copy.deepcopy({event_id: record['envelope'] for event_id, record in self._records.items() if event_id not in self._hidden})

    def _now(self, now_ms: int | None = None) -> int:
        now = self.clock() if now_ms is None else now_ms
        if type(now) is not int or not 0 <= now <= MAX_SAFE_NONCE:
            raise ValueError('clock must return a nonnegative safe integer timestamp')
        return now

    def submit(self, envelope: Envelope, *, mode: Literal['live', 'import'] = 'live', now_ms: int | None = None) -> KnowledgeAcceptanceRecord:
        """Accept a signed event, or return its original retained retry receipt."""
        return self.submit_with_outcome(envelope, mode=mode, now_ms=now_ms)[1]

    def submit_with_outcome(self, envelope: Envelope, *, mode: Literal['live', 'import'] = 'live', now_ms: int | None = None) -> tuple[str, KnowledgeAcceptanceRecord]:
        item = copy.deepcopy(envelope)
        if mode not in ('live', 'import'):
            fail('invalid_request', 'mode must be live or import')
        validate_knowledge_envelope(item)
        now = self._now(now_ms)
        with self._lock:
            # Exact receipts precede dependencies, time, resource and admission checks.
            if item['hash'] in self._records:
                return 'resubmission', copy.deepcopy(self._records[item['hash']])
            if mode == 'import' and not self.import_enabled:
                fail('permission_denied', 'historical import is not enabled')
            visible = {key: record['envelope'] for key, record in self._records.items() if key not in self._hidden}
            validate_knowledge_dependencies(item, visible)
            if len(self._records) >= self.max_records or self._seq >= MAX_SAFE_NONCE:
                fail('permission_denied', 'knowledge store capacity exhausted')
            if len(json.dumps(item, ensure_ascii=False, separators=(',', ':')).encode()) > self.max_envelope_bytes:
                fail('payload_too_large', 'knowledge envelope exceeds byte limit')
            if self.admit is not None:
                self.admit(copy.deepcopy(item), mode)
            record: KnowledgeAcceptanceRecord = {'envelope': item, 'seq': self._seq + 1, 'accepted_at': now}
            if mode == 'live':
                verify_submission(_identity_envelope(item), self.nonce_store, now_ms=now, window_ms=self.window_ms, nonce_ttl_ms=self.nonce_ttl_ms)
            elif item['event']['created_at'] > now + self.window_ms:
                fail('timestamp_out_of_window', 'unknown historical event is too far in the future')
            self._seq += 1
            self._records[item['hash']] = record
            return 'accepted', copy.deepcopy(record)

    def import_event(self, envelope: Envelope, *, now_ms: int | None = None) -> KnowledgeAcceptanceRecord:
        return self.submit(envelope, mode='import', now_ms=now_ms)

    def event(self, event_id: str) -> KnowledgeAcceptanceRecord:
        try:
            validate_knowledge_id(event_id)
        except AgentProtocolError:
            fail('invalid_request', 'malformed event ID')
        with self._lock:
            if event_id not in self._records or event_id in self._hidden:
                fail('not_found', 'event unavailable')
            return copy.deepcopy(self._records[event_id])

    def hide(self, event_id: str) -> None:
        """Withhold public reads; retain the original receipt for exact retries."""
        validate_knowledge_id(event_id)
        with self._lock:
            if event_id in self._records:
                self._hidden.add(event_id)

    def unhide(self, event_id: str) -> None:
        validate_knowledge_id(event_id)
        with self._lock:
            self._hidden.discard(event_id)

    def prune(self, event_id: str) -> None:
        """Drop content and receipt, preserving the sequence high-water mark."""
        validate_knowledge_id(event_id)
        with self._lock:
            self._records.pop(event_id, None)
            self._hidden.discard(event_id)

    def expire_snapshots(self) -> None:
        with self._lock:
            self._snapshots.clear()

    def discovery(self, *, peers: Iterable[str] = (), collection_scope: Mapping[str, Any] | None = None) -> dict[str, Any]:
        result: dict[str, Any] = {
            'protocol': KNOWLEDGE_PROTOCOL, 'service': self.service,
            'endpoints': {name: self.service + '/knowledge/' + name for name in ('events', 'query', 'batch', 'changes')},
            'features': [], 'limits': {'max_envelope_bytes': self.max_envelope_bytes},
        }
        if self.import_enabled:
            result['features'].append('import')
            result['endpoints']['import'] = self.service + '/knowledge/import'
        if self.search_modes:
            result['features'].append('ranked-search')
            result['endpoints']['search'] = self.service + '/knowledge/search'
            result['search_modes'] = list(self.search_modes)
        if peers:
            result['peers'] = list(peers)
        if collection_scope is not None:
            result['collection_scope'] = copy.deepcopy(dict(collection_scope))
        validate_knowledge_discovery(result, self.service)
        return result

    def _metadata(self, now: int) -> dict[str, Any]:
        return {'service': self.service, 'checkpoint': self._seq, 'as_of': now}

    def batch(self, request: dict[str, Any]) -> dict[str, Any]:
        requested = validate_knowledge_batch(copy.deepcopy(request))
        with self._lock:
            result: dict[str, Any] = {'result': [], 'missing': [], **self._metadata(self._now())}
            for event_id in requested:
                if event_id in self._records and event_id not in self._hidden:
                    result['result'].append(copy.deepcopy(self._records[event_id]))
                else:
                    result['missing'].append(event_id)
            return result

    def query(self, request: Mapping[str, Any] | None = None, *, available: bool = True) -> dict[str, Any]:
        request = validate_knowledge_query({} if request is None else request)
        return self._page(request, 'query', available=available)

    def changes(self, request: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return self._page(validate_knowledge_changes({} if request is None else request), 'changes')

    def search(self, request: Mapping[str, Any], *, candidates: Iterable[str] | None = None,
               ranking: Mapping[str, Any] | None = None, coverage: Mapping[str, Any] | None = None,
               explanations: Mapping[str, str] | None = None) -> dict[str, Any]:
        """Freeze caller-ranked IDs; semantic/hybrid ranking is supplied by the application.

        Lexical search without candidates uses all exact matches in sequence order.
        No embedding model is assumed. Each provided candidate must satisfy exact
        filters, and lexical candidates must also satisfy portable text matching.
        """
        request = validate_knowledge_search(request, self.search_modes)
        return self._page(request, 'search', candidates=candidates, ranking=ranking,
                          coverage=coverage, explanations=explanations)

    def _page(self, request: dict[str, Any], operation: str, *, available: bool = True,
              candidates: Iterable[str] | None = None, ranking: Mapping[str, Any] | None = None,
              coverage: Mapping[str, Any] | None = None, explanations: Mapping[str, str] | None = None) -> dict[str, Any]:
        with self._lock:
            now = self._now()
            for token in list(self._snapshots):
                if self._snapshots[token]['expires_at'] <= now:
                    del self._snapshots[token]
            binding = _request_binding(request, operation)
            if 'cursor' in request:
                old = self._snapshots.get(request['cursor'])
                if old is None or old['binding'] != binding or old['operation'] != operation:
                    fail('invalid_cursor', 'expired or incompatible cursor')
                snapshot = copy.deepcopy(old)
            else:
                if not available:
                    fail('query_unavailable', 'exact enumeration unavailable')
                if operation == 'changes' and request.get('after', 0) > self._seq:
                    fail('invalid_request', 'after is greater than current checkpoint')
                eligible = []
                for event_id, record in self._records.items():
                    if event_id in self._hidden:
                        continue
                    if operation == 'changes':
                        match = record['seq'] > request.get('after', 0)
                    else:
                        match = knowledge_query_matches(record['envelope'], request.get('filters', {}) if operation == 'search' else request)
                        if operation == 'search' and request['mode'] == 'lexical':
                            match = match and knowledge_text_matches(record['envelope'], request['text'])
                    if match:
                        eligible.append(event_id)
                ids = eligible
                if operation == 'search':
                    if candidates is None and request['mode'] != 'lexical':
                        fail('query_unavailable', 'semantic and hybrid modes require caller-provided candidates')
                    ids = list(candidates) if candidates is not None else eligible
                    if any(not isinstance(event_id, str) for event_id in ids) or len(ids) != len(set(ids)) or any(event_id not in eligible for event_id in ids):
                        fail('invalid_response', 'candidate list violates exact filters or repeats IDs')
                    ranking = copy.deepcopy(dict(ranking)) if ranking is not None else {'mode': request['mode'], 'id': 'knowledge-sequence-v1'}
                    if coverage is None:
                        coverage = ({'exhaustive': True, 'reasons': []} if request['mode'] == 'lexical' and set(ids) == set(eligible)
                                    else {'exhaustive': False, 'reasons': ['candidate_limit'] if request['mode'] == 'lexical' else ['approximate']})
                    coverage = copy.deepcopy(dict(coverage))
                    _shape(ranking, 'ranking', 'invalid_response')
                    _shape(coverage, 'coverage', 'invalid_response')
                    if coverage.get('exhaustive') and set(ids) != set(eligible):
                        fail('invalid_response', 'false exhaustive candidate enumeration')
                snapshot = {'binding': binding, 'operation': operation,
                            'ids': [(event_id, self._records[event_id]['seq']) for event_id in ids],
                            'offset': 0, 'metadata': self._metadata(now),
                            'ranking': copy.deepcopy(ranking), 'coverage': copy.deepcopy(coverage),
                            'explanations': copy.deepcopy(dict(explanations or {})),
                            'expires_at': now + self.snapshot_ttl_ms}
            response: dict[str, Any] = {'result': [], **snapshot['metadata']}
            def visible(pair: tuple[str, int]) -> bool:
                event_id, seq = pair
                return event_id in self._records and event_id not in self._hidden and self._records[event_id]['seq'] == seq
            while snapshot['offset'] < len(snapshot['ids']) and len(response['result']) < binding['limit']:
                index = snapshot['offset']
                snapshot['offset'] += 1
                pair = snapshot['ids'][index]
                if not visible(pair):
                    continue
                record = copy.deepcopy(self._records[pair[0]])
                response['result'].append({'record': record, 'rank': index + 1,
                    'explanation': snapshot['explanations'].get(pair[0], 'Selected by ranking configuration ' + str(snapshot['ranking'].get('id', '')))}
                    if operation == 'search' else record)
            if operation == 'search':
                response.update(ranking=snapshot['ranking'], coverage=snapshot['coverage'])
                validate_knowledge_search_response(response, request, self.service)
            elif operation == 'query':
                validate_knowledge_query_response(response, request, self.service)
            else:
                validate_knowledge_changes_response(response, request, self.service)
            if any(visible(pair) for pair in snapshot['ids'][snapshot['offset']:]):
                while len(self._snapshots) >= self.max_snapshots:
                    self._snapshots.popitem(last=False)
                token = secrets.token_urlsafe(24)
                self._snapshots[token] = snapshot
                response['next_cursor'] = token
            return copy.deepcopy(response)


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
    visibility: Literal['public']
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
    learned_at: int
    extra: dict[str, Any]


class KnowledgeAssessRequired(TypedDict):
    visibility: Literal['public']
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
    visibility: Literal['public']
    license: str
    target: str
    reason: str


class KnowledgeRetractPayload(KnowledgeRetractRequired, total=False):
    extra: dict[str, Any]


__all__ = [
    'KNOWLEDGE_PROTOCOL', 'KNOWLEDGE_PUBLISH', 'KNOWLEDGE_ASSESS', 'KNOWLEDGE_RETRACT',
    'KNOWLEDGE_EVENT_TYPES', 'KNOWLEDGE_KINDS', 'KNOWLEDGE_RELATIONS', 'KNOWLEDGE_VERDICTS',
    'KNOWLEDGE_ERROR_CODES', 'EvidenceStatus', 'KnowledgeContext', 'KnowledgeAcceptanceRecord',
    'KnowledgeEvidence', 'KnowledgeProfileReference', 'KnowledgeProfileBinding',
    'KnowledgeRelation', 'KnowledgeReproduction', 'KnowledgePublishPayload',
    'KnowledgeAssessPayload', 'KnowledgeRetractPayload', 'KnowledgeStore', 'KnowledgePageTracker',
    'knowledge_schema_validator', 'knowledge_event', 'knowledge_publish_event', 'knowledge_assess_event',
    'knowledge_retract_event', 'validate_knowledge_event', 'validate_knowledge_envelope',
    'validate_knowledge_dependencies', 'validate_knowledge_id', 'validate_knowledge_profiles',
    'knowledge_dependencies', 'materialize_knowledge', 'knowledge_evidence_status',
    'knowledge_text_terms', 'knowledge_text_matches', 'knowledge_query_matches',
    'parse_knowledge_read_json', 'parse_knowledge_query', 'parse_knowledge_changes',
    'validate_knowledge_query', 'validate_knowledge_changes', 'validate_knowledge_batch',
    'validate_knowledge_search', 'validate_knowledge_discovery', 'validate_knowledge_record',
    'validate_knowledge_query_response', 'validate_knowledge_changes_response',
    'validate_knowledge_batch_response', 'validate_knowledge_search_response',
]
