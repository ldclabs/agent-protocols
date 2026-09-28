from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote, urlencode, urljoin, urlparse

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore[assignment]

from .delegation import (
    validate_delegation_id,
    validate_delegation_query_request,
    validate_principal_document,
    validate_principal_resolution,
)
from .identity import MAX_NONCE_HEADER, AgentId, Envelope


class HttpResponseError(Exception):
    """A non-2xx response. ``code`` and ``data`` come from the Agent Identity
    error body (Section 8.1) when the service sent one; ``max_seen_nonce`` from
    the ``Max-Seen-Nonce`` header."""

    def __init__(self, status: int, body: str, max_seen_nonce: str | None = None):
        super().__init__(f"HTTP {status}: {body}")
        self.status = status
        self.body = body
        self.code: str | None = None
        self.data: dict[str, Any] | None = None
        self.max_seen_nonce = max_seen_nonce
        try:
            parsed = json.loads(body)
        except ValueError:
            return  # Not an Agent Identity error body.
        error = parsed.get("error") if isinstance(parsed, dict) else None
        if isinstance(error, dict) and isinstance(error.get("code"), str):
            self.code = error["code"]
            self.data = error.get("data")


def _read_json(response: Any) -> Any:
    status = getattr(response, "status_code", 200)
    if status >= 400:
        headers = getattr(response, "headers", None) or {}
        raise HttpResponseError(status, getattr(response, "text", ""), headers.get(MAX_NONCE_HEADER))
    return response.json()


def _query(path: str, params: dict[str, Any]) -> str:
    query = urlencode({key: value for key, value in params.items() if value is not None}, quote_via=quote)
    return f"{path}?{query}" if query else path


class ProfileClient:
    def __init__(self, base_url: str, session: Any | None = None):
        self.base_url = base_url.rstrip("/")
        self.session = session or _requests_session()

    def get_profile(self, agent_id: AgentId) -> dict[str, Any]:
        return self._get(f"/v1/profiles/{agent_id}")

    def get_profiles(self, agent_ids: list[AgentId]) -> dict[str, Any]:
        return self._post("/v1/profiles/batch", {"ids": agent_ids})

    def profile_events(
        self, agent_id: AgentId, limit: int = 1, cursor: str | None = None
    ) -> dict[str, Any]:
        return self._get(_query(f"/v1/profiles/{agent_id}/events", {"limit": limit, "cursor": cursor}))

    def submit_profile_update(self, envelope: Envelope) -> dict[str, Any]:
        return self._post("/v1/profiles", envelope)

    def _get(self, path: str) -> Any:
        return _read_json(self.session.get(self.base_url + path))

    def _post(self, path: str, body: Any) -> Any:
        return _read_json(self.session.post(self.base_url + path, json=body))


class DiscourseClient:
    def __init__(self, base_url: str, session: Any | None = None):
        self.base_url = base_url.rstrip("/")
        self.session = session or _requests_session()

    def protocol(self) -> dict[str, Any]:
        return self._get("/.well-known/agent-discourse")

    def create_room(self, envelope: Envelope) -> dict[str, Any]:
        return self._post("/v1/rooms", envelope)

    def room(self, room_id: str, jwt: str | None = None) -> dict[str, Any]:
        return self._get(f"/v1/rooms/{room_id}", jwt=jwt)

    def public_rooms(
        self,
        *,
        status: str | None = None,
        tag: str | None = None,
        keyword: str | None = None,
        creator: str | None = None,
        starts_after: int | None = None,
        ends_before: int | None = None,
        language: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        return self._get(
            _query(
                "/v1/rooms",
                {
                    "status": status,
                    "tag": tag,
                    "keyword": keyword,
                    "creator": creator,
                    "starts_after": starts_after,
                    "ends_before": ends_before,
                    "language": language,
                    "limit": limit,
                    "cursor": cursor,
                },
            )
        )

    def my_rooms(
        self,
        jwt: str,
        *,
        status: str | None = None,
        membership: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        return self._get(
            _query(
                "/v1/me/rooms",
                {"status": status, "membership": membership, "limit": limit, "cursor": cursor},
            ),
            jwt=jwt,
        )

    def request_join(self, room_id: str, envelope: Envelope) -> dict[str, Any]:
        """Submits a signed `room.join.request`; the signature authenticates the applicant."""
        return self._post(f"/v1/rooms/{room_id}/join-requests", envelope)

    def join_request(self, room_id: str, request_id: str, jwt: str) -> dict[str, Any]:
        return self._get(f"/v1/rooms/{room_id}/join-requests/{request_id}", jwt=jwt)

    def join_requests(
        self,
        room_id: str,
        jwt: str,
        *,
        status: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        return self._get(
            _query(f"/v1/rooms/{room_id}/join-requests", {"status": status, "limit": limit, "cursor": cursor}),
            jwt=jwt,
        )

    def join_room(self, room_id: str, envelope: Envelope) -> dict[str, Any]:
        return self._post(f"/v1/rooms/{room_id}", envelope)

    def leave_room(self, room_id: str, envelope: Envelope) -> dict[str, Any]:
        return self._post(f"/v1/rooms/{room_id}", envelope)

    def submit_event(self, room_id: str, envelope: Envelope) -> dict[str, Any]:
        return self._post(f"/v1/rooms/{room_id}", envelope)

    def events(
        self,
        room_id: str,
        *,
        after_seq: int | None = None,
        limit: int | None = None,
        cursor: str | None = None,
        jwt: str | None = None,
    ) -> dict[str, Any]:
        return self._get(
            _query(f"/v1/rooms/{room_id}/events", {"after_seq": after_seq, "limit": limit, "cursor": cursor}),
            jwt=jwt,
        )

    def agent_statuses(self, room_id: str, jwt: str | None = None) -> dict[str, Any]:
        return self._get(f"/v1/rooms/{room_id}/agent-status", jwt=jwt)

    def agent_status(self, room_id: str, agent_id: AgentId, jwt: str | None = None) -> dict[str, Any]:
        return self._get(f"/v1/rooms/{room_id}/agent-status/{agent_id}", jwt=jwt)

    def set_agent_status(self, room_id: str, jwt: str, status: dict[str, Any]) -> dict[str, Any]:
        return self._put(f"/v1/rooms/{room_id}/agent-status", status, jwt=jwt)

    def sse_events_url(self, room_id: str) -> str:
        return sse_events_url(self.base_url, room_id)

    def archive(self, room_id: str) -> dict[str, Any]:
        return self._get(f"/v1/rooms/{room_id}/archive")

    def _get(self, path: str, jwt: str | None = None) -> Any:
        return _read_json(self.session.get(self.base_url + path, headers=_auth_headers(jwt)))

    def _post(self, path: str, body: Any, jwt: str | None = None) -> Any:
        return _read_json(self.session.post(self.base_url + path, json=body, headers=_auth_headers(jwt)))

    def _put(self, path: str, body: Any, jwt: str | None = None) -> Any:
        return _read_json(self.session.put(self.base_url + path, json=body, headers=_auth_headers(jwt)))


class DelegationClient:
    """Agent Delegation client. Without ``endpoints`` it uses the RECOMMENDED
    paths under ``base_url``; :meth:`discover` reads the service's discovery
    document instead, whose endpoints clients MUST prefer."""

    def __init__(self, base_url: str, session: Any | None = None, endpoints: dict[str, str] | None = None):
        self.base_url = base_url.rstrip("/")
        self.session = session or _requests_session()
        endpoints = endpoints or {}
        self.delegations_url = (endpoints.get("delegations") or f"{self.base_url}/v1/delegations").rstrip("/")
        self.query_url = endpoints.get("query") or f"{self.delegations_url}/query"

    @classmethod
    def discover(cls, origin: str, session: Any | None = None) -> "DelegationClient":
        """Builds a client for the service at ``origin`` from its discovery
        document, falling back to the default paths when the service publishes none."""
        session = session or _requests_session()
        base = origin.rstrip("/")
        try:
            discovery = _read_json(session.get(f"{base}/.well-known/agent-delegation"))
            endpoints = discovery.get("endpoints") if isinstance(discovery, dict) else None
            return cls(base, session, endpoints if isinstance(endpoints, dict) else None)
        except Exception:  # Discovery is optional; the default paths apply.
            return cls(base, session)

    def protocol(self) -> dict[str, Any]:
        return _read_json(self.session.get(f"{self.base_url}/.well-known/agent-delegation"))

    def principal(self, principal_url: str | None = None) -> dict[str, Any]:
        """Resolves a principal document per Agent Delegation Section 3. A
        document is authoritative only when read at its own `id`, so one served
        elsewhere (an alias hosting a copy rather than redirecting) is discarded
        and `document["id"]` is resolved once more."""
        document, resolved_url = self._read_principal(principal_url or self.base_url)
        if document.get("id") == resolved_url:
            return document
        canonical, resolved_url = self._read_principal(document["id"])
        validate_principal_resolution(canonical, resolved_url)
        return canonical

    def delegation(self, delegation_id: str) -> dict[str, Any]:
        validate_delegation_id(delegation_id)
        return _read_json(self.session.get(f"{self.delegations_url}/{delegation_id}"))

    def delegation_events(self, delegation_id: str, cursor: str | None = None) -> dict[str, Any]:
        validate_delegation_id(delegation_id)
        return _read_json(self.session.get(_query(f"{self.delegations_url}/{delegation_id}/events", {"cursor": cursor})))

    def all_delegation_events(self, delegation_id: str) -> list[dict[str, Any]]:
        """Every accepted record of a credential, following `next_cursor`."""
        records: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            page = self.delegation_events(delegation_id, cursor)
            records.extend(page.get("result", []))
            cursor = page.get("next_cursor")
            if cursor is None:
                return records

    def submit_delegation_event(self, envelope: Envelope) -> dict[str, Any]:
        return _read_json(self.session.post(self.delegations_url, json=envelope))

    def query_delegations(
        self,
        request: dict[str, Any],
        jwt: str | None = None,
    ) -> dict[str, Any]:
        """Public queries are existence checks and carry both `subject` and
        `principal_id`. Passing a request JWT authorizes an enumeration query,
        which a service must otherwise refuse."""
        return self.query_delegations_at(self.query_url, request, jwt)

    def query_delegations_at(
        self,
        query_url: str,
        request: dict[str, Any],
        jwt: str | None = None,
    ) -> dict[str, Any]:
        """Queries the endpoint a principal document names in its
        `delegation_query_url`. That is how a relying party reaches the
        authoritative service for a principal without trusting a URL supplied
        by whoever presented the credential."""
        validate_delegation_query_request(request, allow_enumeration=jwt is not None)
        return _read_json(self.session.post(query_url, json=request, headers=_auth_headers(jwt)))

    def _read_principal(self, url: str) -> tuple[dict[str, Any], str]:
        for redirects in range(6):
            if urlparse(url).scheme != "https":
                raise ValueError("principal resolution requires HTTPS")
            response = self.session.get(url, headers={"Accept": "application/json"}, allow_redirects=False)
            if 300 <= getattr(response, "status_code", 200) < 400:
                location = response.headers.get("location")
                if not location or redirects >= 5:
                    raise ValueError("invalid principal redirect chain")
                url = urljoin(url, location)
                continue
            document = _read_json(response)
            resolved = getattr(response, "url", None) or url
            if (not isinstance(document, dict) or not isinstance(document.get("id"), str)
                or urlparse(document["id"]).scheme != "https" or not urlparse(document["id"]).hostname
                or urlparse(resolved).scheme != "https"):
                raise ValueError("invalid principal HTTPS URL")
            # Copies contribute only the canonical ID, never authority fields.
            if document["id"] == resolved:
                validate_principal_document(document)
            return document, resolved
        raise ValueError("invalid principal redirect chain")


def sse_events_url(base_url: str, room_id: str) -> str:
    return f"{base_url.rstrip('/')}/v1/rooms/{quote(room_id, safe='')}/events/live"


def _auth_headers(jwt: str | None) -> dict[str, str] | None:
    return {"Authorization": f"Bearer {jwt}"} if jwt else None


def _requests_session() -> Any:
    if requests is None:
        raise RuntimeError("Install agent-protocols[http] to use HTTP clients")
    return requests.Session()


class KnowledgeClient:
    """Public Knowledge reads and explicitly authenticated writes.

    Discovery endpoints override recommended paths. Requests never follow
    redirects, so a peer or redirect cannot receive a query, envelope, or JWT.
    Public reads never attach an SDK Authorization header. Use a dedicated
    session without default credentials for public discovery.
    """
    def __init__(self, base_url: str, session: Any | None = None, *,
                 endpoints: dict[str, str] | None = None, features: tuple[str, ...] | list[str] = (),
                 search_modes: tuple[str, ...] | list[str] = (), timeout: float = 30.0):
        from .knowledge import KNOWLEDGE_PROTOCOL, validate_knowledge_discovery
        from .identity import validate_origin
        validate_origin(base_url)
        self.base_url = base_url
        self.session = session if session is not None else _requests_session()
        self.timeout = timeout
        document: dict[str, Any] = {'protocol': KNOWLEDGE_PROTOCOL, 'service': base_url,
                                    'endpoints': dict(endpoints or {}), 'features': list(features)}
        if search_modes:
            document['search_modes'] = list(search_modes)
        validate_knowledge_discovery(document, base_url)
        self._discovery = document
        self._endpoints = {key: base_url + '/knowledge/' + key for key in ('events', 'query', 'batch', 'changes')}
        self._endpoints.update(document['endpoints'])

    @classmethod
    def discover(cls, origin: str, session: Any | None = None, *, timeout: float = 30.0) -> 'KnowledgeClient':
        from .knowledge import validate_knowledge_discovery
        client = cls(origin, session, timeout=timeout)
        document = client.protocol()
        validate_knowledge_discovery(document, origin)
        discovered = cls(origin, client.session, endpoints=document.get('endpoints'),
                         features=document.get('features', []), search_modes=document.get('search_modes', []), timeout=timeout)
        import copy
        discovered._discovery = copy.deepcopy(document)
        return discovered

    @property
    def discovery(self) -> dict[str, Any]:
        import copy
        return copy.deepcopy(self._discovery)

    def _request(self, method: str, url: str, *, body: Any = None, jwt: str | None = None) -> Any:
        from .errors import AgentProtocolError
        from .identity import parse_strict_json, verify_request_jwt
        from .knowledge import _knowledge_origin
        if _knowledge_origin(url) != self.base_url:
            raise AgentProtocolError('invalid_request', 'cross-origin Knowledge endpoint')
        headers: dict[str, Any] = {'Authorization': None}
        # requests uses None to suppress a session-level default Authorization.
        # Session authentication/cookies are caller-owned; use a dedicated session.
        if jwt is not None:
            verify_request_jwt(jwt, audience=self.base_url)
            headers['Authorization'] = 'Bearer ' + jwt
        kwargs: dict[str, Any] = {'headers': headers, 'allow_redirects': False, 'timeout': self.timeout}
        if body is not None:
            kwargs['json'] = body
        response = getattr(self.session, method.lower())(url, **kwargs)
        final_url = getattr(response, 'url', None)
        if final_url:
            try:
                final_origin = _knowledge_origin(final_url)
            except (AgentProtocolError, ValueError) as exc:
                raise AgentProtocolError('invalid_response', 'Knowledge response has an invalid origin') from exc
            if final_origin != self.base_url:
                raise AgentProtocolError('invalid_response', 'Knowledge response came from a different origin')
        status = getattr(response, 'status_code', 200)
        if status != 200:
            raise HttpResponseError(status, getattr(response, 'text', ''), (getattr(response, 'headers', {}) or {}).get(MAX_NONCE_HEADER))
        try:
            return parse_strict_json(response.text)
        except (AgentProtocolError, TypeError, ValueError) as exc:
            raise AgentProtocolError('invalid_response', 'Knowledge response violates strict I-JSON') from exc

    def protocol(self) -> dict[str, Any]:
        from .knowledge import validate_knowledge_discovery
        document = self._request('GET', self.base_url + '/.well-known/agent-knowledge')
        validate_knowledge_discovery(document, self.base_url)
        return document

    def submit(self, envelope: Envelope, *, jwt: str | None = None) -> dict[str, Any]:
        return self._write(envelope, 'events', jwt)

    def submit_event(self, envelope: Envelope, *, jwt: str | None = None) -> dict[str, Any]:
        return self.submit(envelope, jwt=jwt)

    def import_event(self, envelope: Envelope, *, jwt: str | None = None) -> dict[str, Any]:
        from .errors import AgentProtocolError
        if 'import' not in self._discovery.get('features', []):
            raise AgentProtocolError('invalid_request', 'service has not advertised historical import')
        return self._write(envelope, 'import', jwt)

    def _write(self, envelope: Envelope, endpoint: str, jwt: str | None) -> dict[str, Any]:
        from .knowledge import validate_knowledge_envelope, validate_knowledge_record
        import copy
        envelope = copy.deepcopy(envelope)
        validate_knowledge_envelope(envelope)
        result = self._request('POST', self._endpoints[endpoint], body=envelope, jwt=jwt)
        validate_knowledge_record(result, expected_hash=envelope['hash'])
        return result

    def event(self, event_id: str) -> dict[str, Any]:
        from .errors import AgentProtocolError
        from .knowledge import validate_knowledge_id, validate_knowledge_record
        try:
            validate_knowledge_id(event_id)
        except AgentProtocolError as exc:
            raise AgentProtocolError('invalid_request', 'malformed Knowledge event ID') from exc
        result = self._request('GET', _query(self._endpoints['events'], {'hash': event_id}))
        validate_knowledge_record(result, expected_hash=event_id)
        return result

    def query(self, request: dict[str, Any] | None = None) -> dict[str, Any]:
        from .knowledge import validate_knowledge_query, validate_knowledge_query_response
        request = validate_knowledge_query({} if request is None else request)
        result = self._request('GET', _query(self._endpoints['query'], request))
        validate_knowledge_query_response(result, request, self.base_url)
        return result

    def batch(self, hashes: list[str]) -> dict[str, Any]:
        from .knowledge import validate_knowledge_batch, validate_knowledge_batch_response
        requested = tuple(hashes)
        body = {'hashes': list(requested)}
        validate_knowledge_batch(body)
        result = self._request('POST', self._endpoints['batch'], body=body)
        validate_knowledge_batch_response(result, requested, self.base_url)
        return result

    def changes(self, request: dict[str, Any] | None = None) -> dict[str, Any]:
        from .knowledge import validate_knowledge_changes, validate_knowledge_changes_response
        request = validate_knowledge_changes({} if request is None else request)
        result = self._request('GET', _query(self._endpoints['changes'], request))
        validate_knowledge_changes_response(result, request, self.base_url)
        return result

    def search(self, request: dict[str, Any]) -> dict[str, Any]:
        from .knowledge import validate_knowledge_search, validate_knowledge_search_response
        from .errors import AgentProtocolError
        import copy
        request = copy.deepcopy(request)
        request = validate_knowledge_search(request, self._discovery.get('search_modes', []))
        if 'ranked-search' not in self._discovery.get('features', []):
            raise AgentProtocolError('unsupported_search_mode', 'service has not advertised ranked search')
        result = self._request('POST', self._endpoints['search'], body=request)
        validate_knowledge_search_response(result, request, self.base_url)
        return result

    def iter_pages(self, operation: str = 'query', request: dict[str, Any] | None = None):
        """Yield validated pages, rejecting scope/configuration drift or repeated IDs.

        Persist a changes checkpoint only after the iterator is exhausted. A
        failed/expired continuation must restart at the last completed checkpoint.
        """
        import copy
        from .knowledge import KnowledgePageTracker
        tracker = KnowledgePageTracker(self.base_url, operation)
        request = copy.deepcopy(request or {})
        if 'cursor' in request:
            from .errors import AgentProtocolError
            raise AgentProtocolError('invalid_request', 'iter_pages must start without a cursor')
        while True:
            page = getattr(self, operation)(request)
            tracker.accept(page, request)
            next_cursor = page.get('next_cursor')
            yield page
            if next_cursor is None:
                break
            request['cursor'] = next_cursor
