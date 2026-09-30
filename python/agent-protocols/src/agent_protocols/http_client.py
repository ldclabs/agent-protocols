from __future__ import annotations

import copy
import json
from typing import Any, Iterator
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
from .errors import AgentProtocolError
from .identity import (
    MAX_NONCE_HEADER, AgentId, Envelope, parse_strict_json, validate_origin, verify_request_jwt,
)
from .knowledge import (
    KnowledgePageTracker, _knowledge_origin, validate_knowledge_batch_request,
    validate_knowledge_batch_response, validate_knowledge_discovery, validate_knowledge_envelope,
    validate_knowledge_id, validate_knowledge_query, validate_knowledge_query_response,
    validate_knowledge_record, validate_knowledge_search_request, validate_knowledge_search_response,
)


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
    """Public Knowledge reads and optionally authenticated submissions.

    Discovery endpoints override the recommended paths. Requests never follow
    redirects, so a peer or redirect cannot receive a query, envelope, or JWT.
    Public reads never attach an SDK Authorization header; use a dedicated
    session without default credentials for public discovery.
    """
    def __init__(self, base_url: str, session: Any | None = None, *,
                 discovery: dict[str, Any] | None = None, timeout: float = 30.0):
        validate_origin(base_url)
        if discovery is not None:
            validate_knowledge_discovery(discovery, base_url)
        self.base_url = base_url
        self.session = session if session is not None else _requests_session()
        self.timeout = timeout
        self._discovery = copy.deepcopy(discovery)
        self._endpoints = {key: base_url + '/v1/knowledge/' + key for key in ('events', 'query', 'batch')}
        self._endpoints.update((discovery or {}).get('endpoints', {}))

    @classmethod
    def discover(cls, origin: str, session: Any | None = None, *, timeout: float = 30.0) -> 'KnowledgeClient':
        client = cls(origin, session, timeout=timeout)
        return cls(origin, client.session, discovery=client.protocol(), timeout=timeout)

    @property
    def discovery(self) -> dict[str, Any] | None:
        return copy.deepcopy(self._discovery)

    def _request(self, method: str, url: str, *, body: Any = None, jwt: str | None = None) -> Any:
        if _knowledge_origin(url) != self.base_url:
            raise AgentProtocolError('invalid_request', 'cross-origin Knowledge endpoint')
        # requests uses None to suppress a session-level default Authorization.
        headers: dict[str, Any] = {'Authorization': None}
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
        document = self._request('GET', self.base_url + '/.well-known/agent-knowledge')
        validate_knowledge_discovery(document, self.base_url)
        return document

    def submit(self, envelope: Envelope, *, jwt: str | None = None) -> dict[str, Any]:
        envelope = copy.deepcopy(envelope)
        validate_knowledge_envelope(envelope)
        result = self._request('POST', self._endpoints['events'], body=envelope, jwt=jwt)
        validate_knowledge_record(result, envelope['hash'])
        return result

    def event(self, event_id: str) -> dict[str, Any]:
        validate_knowledge_id(event_id, 'invalid_request')
        result = self._request('GET', self._endpoints['events'] + '/' + event_id)
        validate_knowledge_record(result, event_id)
        return result

    def query(self, request: dict[str, Any] | None = None) -> dict[str, Any]:
        request = validate_knowledge_query({} if request is None else request)
        result = self._request('GET', _query(self._endpoints['query'], request))
        validate_knowledge_query_response(result, request, self.base_url)
        return result

    def query_pages(self, request: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
        """Yield validated pages of one checkpoint-bound enumeration.

        Persist ``page['checkpoint']`` as the next ``after_seq`` only after the
        iterator is exhausted; an interrupted scan restarts from the old value.
        """
        tracker = KnowledgePageTracker(self.base_url)
        request = copy.deepcopy(request or {})
        if 'cursor' in request:
            raise AgentProtocolError('invalid_request', 'query_pages must start without a cursor')
        while True:
            page = self.query(request)
            tracker.accept(request, page)
            next_cursor = page.get('next_cursor')
            yield page
            if next_cursor is None:
                return
            request['cursor'] = next_cursor

    def batch(self, hashes: list[str]) -> dict[str, Any]:
        requested = list(hashes)
        body = {'hashes': requested}
        validate_knowledge_batch_request(body)
        result = self._request('POST', self._endpoints['batch'], body=body)
        validate_knowledge_batch_response(result, requested, self.base_url)
        return result

    def search(self, request: dict[str, Any]) -> dict[str, Any]:
        discovery = self._discovery or {}
        request = validate_knowledge_search_request(request, discovery.get('search_modes', []))
        if 'ranked-search' not in discovery.get('features', []):
            raise AgentProtocolError('unsupported_search_mode', 'service has not advertised ranked search')
        result = self._request('POST', self._endpoints['search'], body=request)
        validate_knowledge_search_response(result, request, self.base_url)
        return result


def mail_public_network_policy(url: str) -> None:
    """Default Mail URL policy: reject non-public addresses, including DNS answers.

    Rebinding-resistant routing needs the deployment's resolver/egress controls.
    A caller-provided policy can deliberately permit private infrastructure.
    """
    import ipaddress
    import socket
    parsed = urlparse(url)
    try:
        addresses = socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(item[4][0].split('%', 1)[0]).is_global for item in addresses):
            raise ValueError('non-public destination')
    except (ValueError, OSError) as exc:
        raise AgentProtocolError('permission_denied', 'Mail network policy rejected destination') from exc


class MailClient:
    """Same-origin Mail HTTP client with anonymous delivery and explicit owner JWTs.

    A fresh PreparedRequest bypasses ambient Session auth, headers, params,
    cookies and netrc. send() gets explicit TLS/proxy/redirect settings. Injected
    adapters remain trusted transport code. URL policy runs before every request;
    custom network policies must enforce the application's local access rules.
    """
    def __init__(self, base_url: str, session: Any | None = None, *,
                 discovery: dict[str, Any] | None = None, card_cache: Any | None = None,
                 network_policy: Any | None = None, timeout: float = 30.0,
                 max_response_bytes: int = 16 * 1024 * 1024):
        from .mail import validate_mail_discovery
        from .mail_state import MailCardCache
        validate_origin(base_url)
        if requests is None:
            raise RuntimeError('Install agent-protocols[http] to use MailClient')
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout < float('inf'):
            raise AgentProtocolError('invalid_request', 'timeout must be finite and positive')
        if type(max_response_bytes) is not int or max_response_bytes <= 0:
            raise AgentProtocolError('invalid_request', 'response limit must be positive')
        self.base_url = base_url
        self.session = session if session is not None else _requests_session()
        self.card_cache = card_cache if card_cache is not None else MailCardCache()
        self.network_policy = network_policy if network_policy is not None else mail_public_network_policy
        self.timeout, self.max_response_bytes = timeout, max_response_bytes
        self._discovery = copy.deepcopy(discovery)
        self._mailboxes = (validate_mail_discovery(discovery, base_url) if discovery is not None
                           else base_url + '/v1/mailboxes')

    @classmethod
    def discover(cls, origin: str, session: Any | None = None, **kwargs: Any) -> 'MailClient':
        client = cls(origin, session, **kwargs)
        document = client.protocol()
        from .mail import validate_mail_discovery
        client._discovery = copy.deepcopy(document)
        client._mailboxes = validate_mail_discovery(document, origin)
        return client

    @property
    def discovery(self) -> dict[str, Any] | None:
        return copy.deepcopy(self._discovery)

    def _request(self, method: str, url: str, *, status: int = 200, body: Any = None,
                 jwt: str | None = None, owner: str | None = None, now_ms: int | None = None) -> Any:
        from .mail import _jcs, verify_mail_owner_jwt
        parsed = urlparse(url)
        if parsed.scheme != 'https' or parsed.netloc != urlparse(self.base_url).netloc or parsed.username is not None:
            raise AgentProtocolError('invalid_request', 'cross-origin Mail request')
        if self.network_policy(url) is False:
            raise AgentProtocolError('permission_denied', 'Mail network policy rejected destination')
        headers = {'Accept': 'application/json'}
        if jwt is not None:
            verify_mail_owner_jwt(jwt, owner, self.base_url, now_ms=now_ms)
            headers['Authorization'] = 'Bearer ' + jwt
        if body is not None:
            headers['Content-Type'] = 'application/json'
        # Do not use session.prepare_request/request: those merge ambient auth,
        # cookies, URL parameters and netrc, leaking the sender's identity.
        prepared = requests.Request(method, url, headers=headers,
                                    data=_jcs(body) if body is not None else None).prepare()
        response = self.session.send(prepared, allow_redirects=False, timeout=self.timeout,
                                     verify=True, cert=None, proxies={}, stream=True)
        try:
            final_url = getattr(response, 'url', None)
            if final_url and final_url != prepared.url:
                raise AgentProtocolError('invalid_response', 'Mail response URL differs from requested URL')
            chunks, count = [], 0
            for chunk in response.iter_content(chunk_size=65536):
                count += len(chunk)
                if count > self.max_response_bytes:
                    raise AgentProtocolError('payload_too_large', 'Mail response exceeds configured limit')
                chunks.append(chunk)
            data = b''.join(chunks)
            if response.status_code != status:
                raise HttpResponseError(response.status_code, data.decode('utf-8', errors='replace'),
                                        response.headers.get(MAX_NONCE_HEADER))
            if status == 204:
                if data:
                    raise AgentProtocolError('invalid_response', '204 deletion response must have no body')
                return None
            try:
                return parse_strict_json(data.decode('utf-8'))
            except (AgentProtocolError, UnicodeError, ValueError, RecursionError) as exc:
                raise AgentProtocolError('invalid_response', 'Mail response is not strict UTF-8 JSON') from exc
        finally:
            response.close()

    def protocol(self) -> dict[str, Any]:
        from .mail import validate_mail_discovery
        document = self._request('GET', self.base_url + '/.well-known/agent-mail')
        validate_mail_discovery(document, self.base_url)
        return document

    def publish(self, card: Envelope) -> dict[str, Any]:
        from .mail import validate_mail_card_record, validate_mail_schema, validate_mail_envelope
        card = copy.deepcopy(card)
        validate_mail_schema(card, 'mailboxCardEnvelope')
        validate_mail_envelope(card)
        if self.base_url not in card['event']['payload']['routes']:
            raise AgentProtocolError('invalid_request', 'relay origin is not in card routes')
        record = self._request('POST', self._mailboxes, body=card)
        validate_mail_card_record(record, card['event']['actor'], card['event']['payload']['mailbox_id'])
        if record['envelope'] != card:
            raise AgentProtocolError('invalid_response', 'publication response does not contain the submitted card')
        return record

    def card(self, mailbox_id: str, owner: str, *, now_ms: int | None = None) -> dict[str, Any]:
        from .mail import validate_mail_card_record, validate_mail_id
        validate_mail_id(mailbox_id, size=16)
        record = self._request('GET', self._mailboxes + '/' + mailbox_id + '/card')
        validate_mail_card_record(record, owner, mailbox_id)
        if self.base_url not in record['envelope']['event']['payload']['routes']:
            raise AgentProtocolError('invalid_response', 'card does not authorize this relay origin')
        # Observe disabled/expired cards too, so later old enabled cards cannot win.
        self.card_cache.observe(record['envelope'], owner, now_ms=now_ms, require_usable=False)
        return record

    def deliver(self, packet: dict[str, Any], card: Envelope) -> dict[str, Any]:
        """Anonymous delivery; exact retries can use an expired historical card."""
        from .mail import _check_packet_card, mail_packet_id, validate_mail_delivery_result, validate_mail_packet, validate_mail_schema
        packet, card = copy.deepcopy(packet), copy.deepcopy(card)
        validate_mail_schema(card, 'mailboxCardEnvelope')
        validate_mail_packet(packet)
        _check_packet_card(packet, card, card['event']['actor'])
        if self.base_url not in card['event']['payload']['routes']:
            raise AgentProtocolError('invalid_request', 'relay origin is not in card routes')
        pid = mail_packet_id(packet)
        result = self._request('POST', self._mailboxes + '/' + packet['header']['mailbox_id'] + '/packets', status=202, body=packet)
        validate_mail_delivery_result(result, pid)
        if result['accepted_at'] >= packet['header']['expires_at']:
            raise AgentProtocolError('invalid_response', 'relay claims acceptance after expiration')
        return result

    def packets(self, mailbox_id: str, owner: str, jwt: str, *, limit: int = 100,
                cursor: str | None = None, now_ms: int | None = None) -> dict[str, Any]:
        from .mail import validate_mail_id, validate_mail_packet_list
        validate_mail_id(mailbox_id, size=16)
        if type(limit) is not int or not 1 <= limit <= 1000 or (cursor is not None and (not isinstance(cursor, str) or not cursor)):
            raise AgentProtocolError('invalid_request', 'invalid Mail pagination request')
        url = _query(self._mailboxes + '/' + mailbox_id + '/packets', {'limit': limit, 'cursor': cursor})
        page = self._request('GET', url, jwt=jwt, owner=owner, now_ms=now_ms)
        validate_mail_packet_list(page, mailbox_id, limit=limit)
        return page

    def packet_pages(self, mailbox_id: str, owner: str, jwt: str, *, limit: int = 100,
                     now_ms: int | None = None) -> Iterator[dict[str, Any]]:
        cursor, last_seq, seen_ids, cursors = None, 0, set(), set()
        while True:
            page = self.packets(mailbox_id, owner, jwt, limit=limit, cursor=cursor, now_ms=now_ms)
            for record in page['result']:
                if record['seq'] <= last_seq or record['packet_id'] in seen_ids:
                    raise AgentProtocolError('invalid_response', 'Mail pagination repeated or reordered records')
                last_seq = record['seq']
                seen_ids.add(record['packet_id'])
            cursor = page.get('next_cursor')
            if cursor is not None:
                if cursor in cursors:
                    raise AgentProtocolError('invalid_response', 'Mail pagination cursor cycle')
                cursors.add(cursor)
            yield page
            if cursor is None:
                return

    def delete(self, mailbox_id: str, packet_id: str, owner: str, jwt: str, *, now_ms: int | None = None) -> None:
        from .mail import validate_mail_id
        validate_mail_id(mailbox_id, size=16)
        validate_mail_id(packet_id)
        self._request('DELETE', self._mailboxes + '/' + mailbox_id + '/packets/' + packet_id,
                      status=204, jwt=jwt, owner=owner, now_ms=now_ms)
