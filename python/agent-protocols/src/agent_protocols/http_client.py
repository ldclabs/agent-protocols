from __future__ import annotations

from typing import Any
from urllib.parse import quote, urlencode

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore[assignment]

from .delegation import (
    validate_delegation_query_request,
    validate_principal_document,
    validate_principal_resolution,
)
from .identity import AgentId, Envelope


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
        query = urlencode(
            {key: value for key, value in {"limit": limit, "cursor": cursor}.items() if value is not None},
            quote_via=quote,
        )
        return self._get(f"/v1/profiles/{agent_id}/events?{query}")

    def submit_profile_update(self, envelope: Envelope) -> dict[str, Any]:
        return self._post("/v1/profiles", envelope)

    def _get(self, path: str) -> Any:
        response = self.session.get(self.base_url + path)
        response.raise_for_status()
        return response.json()

    def _post(self, path: str, body: Any) -> dict[str, Any]:
        response = self.session.post(self.base_url + path, json=body)
        response.raise_for_status()
        return response.json()


class DiscourseClient:
    def __init__(self, base_url: str, session: Any | None = None):
        self.base_url = base_url.rstrip("/")
        self.session = session or _requests_session()

    def protocol(self) -> dict[str, Any]:
        return self._get("/.well-known/agent-discourse")

    def create_room(self, envelope: Envelope) -> dict[str, Any]:
        return self._post("/v1/rooms", envelope)

    def room(self, room_id: str) -> dict[str, Any]:
        return self._get(f"/v1/rooms/{room_id}")

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
    ) -> list[dict[str, Any]]:
        query = urlencode(
            {
                key: value
                for key, value in {
                    "status": status,
                    "tag": tag,
                    "keyword": keyword,
                    "creator": creator,
                    "starts_after": starts_after,
                    "ends_before": ends_before,
                    "language": language,
                    "limit": limit,
                    "cursor": cursor,
                }.items()
                if value is not None
            },
            quote_via=quote,
        )
        suffix = f"?{query}" if query else ""
        return self._get(f"/v1/rooms/public{suffix}")

    def my_rooms(
        self,
        jwt: str,
        *,
        status: str | None = None,
        membership: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> list[dict[str, Any]]:
        query = urlencode(
            {
                key: value
                for key, value in {
                    "status": status,
                    "membership": membership,
                    "limit": limit,
                    "cursor": cursor,
                }.items()
                if value is not None
            },
            quote_via=quote,
        )
        suffix = f"?{query}" if query else ""
        return self._get(f"/v1/me/rooms{suffix}", jwt=jwt)

    def request_join(self, room_id: str, jwt: str, request: dict[str, Any]) -> dict[str, Any]:
        return self._post(f"/v1/rooms/{room_id}/join-requests", request, jwt=jwt)

    def join_request(self, room_id: str, request_id: str, jwt: str) -> dict[str, Any]:
        return self._get(f"/v1/rooms/{room_id}/join-requests/{request_id}", jwt=jwt)

    def join_requests(self, room_id: str, jwt: str) -> list[dict[str, Any]]:
        return self._get(f"/v1/rooms/{room_id}/join-requests", jwt=jwt)

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
    ) -> list[dict[str, Any]]:
        query = urlencode(
            {
                key: value
                for key, value in {
                    "after_seq": after_seq,
                    "limit": limit,
                    "cursor": cursor,
                }.items()
                if value is not None
            },
            quote_via=quote,
        )
        suffix = f"?{query}" if query else ""
        return self._get(f"/v1/rooms/{room_id}/events{suffix}", jwt=jwt)

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
        response = self.session.get(self.base_url + path, headers=_auth_headers(jwt))
        response.raise_for_status()
        return response.json()

    def _post(self, path: str, body: Any, jwt: str | None = None) -> Any:
        response = self.session.post(self.base_url + path, json=body, headers=_auth_headers(jwt))
        response.raise_for_status()
        return response.json()

    def _put(self, path: str, body: Any, jwt: str | None = None) -> Any:
        response = self.session.put(self.base_url + path, json=body, headers=_auth_headers(jwt))
        response.raise_for_status()
        return response.json()


class DelegationClient:
    def __init__(self, base_url: str, session: Any | None = None):
        self.base_url = base_url.rstrip("/")
        self.session = session or _requests_session()

    def protocol(self) -> dict[str, Any]:
        return self._get("/.well-known/agent-delegation")

    def principal(self, principal_url: str | None = None) -> dict[str, Any]:
        """Resolves a principal document per Agent Delegation Section 5.3. A
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
        return self._get(f"/v1/delegations/{delegation_id}")

    def delegation_status(self, delegation_id: str) -> dict[str, Any]:
        return self._get(f"/v1/delegations/{delegation_id}/status")

    def delegation_events(self, delegation_id: str) -> dict[str, Any]:
        return self._get(f"/v1/delegations/{delegation_id}/events")

    def submit_delegation_event(self, envelope: Envelope) -> dict[str, Any]:
        return self._post("/v1/delegations", envelope)

    def query_delegations(
        self,
        request: dict[str, Any],
        *,
        allow_enumeration: bool = False,
    ) -> dict[str, Any]:
        """Public queries are existence checks and carry both `subject` and
        `principal_id`. Pass `allow_enumeration` only for a request the service
        has authorized to enumerate one side."""
        validate_delegation_query_request(request, allow_enumeration=allow_enumeration)
        return self._post("/v1/delegations/query", request)

    def _read_principal(self, url: str) -> tuple[dict[str, Any], str]:
        response = self.session.get(url, headers={"Accept": "application/json"})
        response.raise_for_status()
        document = response.json()
        validate_principal_document(document)
        return document, getattr(response, "url", None) or url

    def _get(self, path: str) -> Any:
        response = self.session.get(self.base_url + path)
        response.raise_for_status()
        return response.json()

    def _post(self, path: str, body: Any) -> dict[str, Any]:
        response = self.session.post(self.base_url + path, json=body)
        response.raise_for_status()
        return response.json()


def sse_events_url(base_url: str, room_id: str) -> str:
    return f"{base_url.rstrip('/')}/v1/rooms/{quote(room_id, safe='')}/events/live"


def _auth_headers(jwt: str | None) -> dict[str, str] | None:
    return {"Authorization": f"Bearer {jwt}"} if jwt else None


def _requests_session() -> Any:
    if requests is None:
        raise RuntimeError("Install agent-protocols[http] to use HTTP clients")
    return requests.Session()
