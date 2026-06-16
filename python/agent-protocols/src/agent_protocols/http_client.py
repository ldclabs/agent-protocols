from __future__ import annotations

from typing import Any
from urllib.parse import quote, urlencode

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore[assignment]

from .identity import AgentId, Envelope


class ProfileClient:
    def __init__(self, base_url: str, session: Any | None = None):
        self.base_url = base_url.rstrip("/")
        self.session = session or _requests_session()

    def get_profile(self, agent_id: AgentId) -> dict[str, Any]:
        return self._get(f"/v1/profiles/{agent_id}")

    def get_profiles(self, agent_ids: list[AgentId]) -> dict[str, Any]:
        return self._post("/v1/profiles/batch", {"ids": agent_ids})

    def profile_events(self, agent_id: AgentId, limit: int = 1) -> dict[str, Any]:
        return self._get(f"/v1/profiles/{agent_id}/events?limit={limit}")

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

    def websocket_events_url(self, room_id: str, jwt: str) -> str:
        return websocket_events_url(self.base_url, room_id, jwt)

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


def websocket_events_url(base_url: str, room_id: str, jwt: str) -> str:
    websocket_base = base_url.rstrip("/")
    if websocket_base.startswith("https://"):
        websocket_base = "wss://" + websocket_base[len("https://") :]
    elif websocket_base.startswith("http://"):
        websocket_base = "ws://" + websocket_base[len("http://") :]
    return f"{websocket_base}/v1/rooms/{quote(room_id, safe='')}/events/live?access_token={quote(jwt, safe='')}"


def _auth_headers(jwt: str | None) -> dict[str, str] | None:
    return {"Authorization": f"Bearer {jwt}"} if jwt else None


def _requests_session() -> Any:
    if requests is None:
        raise RuntimeError("Install agent-protocols[http] to use HTTP clients")
    return requests.Session()
