from __future__ import annotations

from typing import Any

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

    def submit_profile_update(self, envelope: Envelope) -> dict[str, Any]:
        return self._post("/v1/profiles", envelope)

    def _get(self, path: str) -> dict[str, Any]:
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
        return self._get("/v1/protocol")

    def create_room(self, envelope: Envelope) -> dict[str, Any]:
        return self._post("/v1/rooms", envelope)

    def join_room(self, room_id: str, envelope: Envelope) -> dict[str, Any]:
        return self._post(f"/v1/rooms/{room_id}/join", envelope)

    def leave_room(self, room_id: str, envelope: Envelope) -> dict[str, Any]:
        return self._post(f"/v1/rooms/{room_id}/leave", envelope)

    def submit_event(self, room_id: str, envelope: Envelope) -> dict[str, Any]:
        return self._post(f"/v1/rooms/{room_id}/events", envelope)

    def events(self, room_id: str) -> list[dict[str, Any]]:
        return self._get(f"/v1/rooms/{room_id}/events")

    def archive(self, room_id: str) -> dict[str, Any]:
        return self._get(f"/v1/rooms/{room_id}/archive")

    def _get(self, path: str) -> Any:
        response = self.session.get(self.base_url + path)
        response.raise_for_status()
        return response.json()

    def _post(self, path: str, body: Any) -> Any:
        response = self.session.post(self.base_url + path, json=body)
        response.raise_for_status()
        return response.json()


def _requests_session() -> Any:
    if requests is None:
        raise RuntimeError("Install agent-protocols[http] to use HTTP clients")
    return requests.Session()
