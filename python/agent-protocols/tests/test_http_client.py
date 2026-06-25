import unittest

import agent_protocols.http_client as http_client
from agent_protocols.http_client import (
    DiscourseClient,
    ProfileClient,
    sse_events_url,
)
from agent_protocols.identity import AgentSigner

AGENT_ID = AgentSigner.from_seed(bytes([1]) * 32).agent_id()


class FakeResponse:
    def __init__(self, payload, *, ok=True):
        self._payload = payload
        self._ok = ok

    def json(self):
        return self._payload

    def raise_for_status(self):
        if not self._ok:
            raise RuntimeError("HTTP error")


class FakeSession:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def get(self, url, headers=None):
        self.calls.append(("GET", url, headers, None))
        return self._responses.pop(0)

    def post(self, url, json=None, headers=None):
        self.calls.append(("POST", url, headers, json))
        return self._responses.pop(0)


class ProfileClientTests(unittest.TestCase):
    def test_every_endpoint_uses_the_expected_method_and_path(self):
        session = FakeSession(
            [
                FakeResponse({"id": AGENT_ID, "name": "A"}),
                FakeResponse({"result": []}),
                FakeResponse({"result": []}),
                FakeResponse({"id": AGENT_ID, "name": "A"}),
            ]
        )
        # trailing slash should be normalized away
        client = ProfileClient("https://api.example.com/", session=session)

        self.assertEqual(client.get_profile(AGENT_ID)["name"], "A")
        client.get_profiles([AGENT_ID])
        client.profile_events(AGENT_ID, limit=5)
        client.submit_profile_update({"hash": "h", "event": {}, "signature": "s"})

        methods = [(call[0], call[1]) for call in session.calls]
        self.assertEqual(methods[0], ("GET", f"https://api.example.com/v1/profiles/{AGENT_ID}"))
        self.assertEqual(methods[1], ("POST", "https://api.example.com/v1/profiles/batch"))
        self.assertEqual(
            methods[2],
            ("GET", f"https://api.example.com/v1/profiles/{AGENT_ID}/events?limit=5"),
        )
        self.assertEqual(methods[3], ("POST", "https://api.example.com/v1/profiles"))
        self.assertEqual(session.calls[1][3], {"ids": [AGENT_ID]})

    def test_profile_events_defaults_to_one(self):
        session = FakeSession([FakeResponse({"result": []})])
        client = ProfileClient("https://api.example.com", session=session)
        client.profile_events(AGENT_ID)
        self.assertTrue(session.calls[0][1].endswith("/events?limit=1"))

    def test_raise_for_status_propagates(self):
        session = FakeSession([FakeResponse(None, ok=False)])
        client = ProfileClient("https://api.example.com", session=session)
        with self.assertRaises(RuntimeError):
            client.get_profile(AGENT_ID)


class DiscourseClientTests(unittest.TestCase):
    def test_every_endpoint_and_bearer_tokens(self):
        session = FakeSession([FakeResponse({"ok": True}) for _ in range(12)])
        client = DiscourseClient("https://api.example.com", session=session)
        envelope = {"hash": "h", "event": {}, "signature": "s"}

        client.protocol()
        client.create_room(envelope)
        client.room("room1")
        client.request_join("room1", "jwt-a", {"role": "speaker"})
        client.join_request("room1", "req1", "jwt-b")
        client.join_requests("room1", "jwt-c")
        client.join_room("room1", envelope)
        client.leave_room("room1", envelope)
        client.submit_event("room1", envelope)
        client.events("room1")
        client.events("room1", after_seq=7, limit=10, cursor="a b", jwt="jwt-d")
        client.archive("room1")

        urls = [call[1] for call in session.calls]
        self.assertEqual(urls[0], "https://api.example.com/.well-known/agent-discourse")
        self.assertEqual(urls[1], "https://api.example.com/v1/rooms")
        self.assertEqual(urls[2], "https://api.example.com/v1/rooms/room1")
        # bearer tokens forwarded
        self.assertEqual(session.calls[3][2], {"Authorization": "Bearer jwt-a"})
        self.assertEqual(
            urls[4], "https://api.example.com/v1/rooms/room1/join-requests/req1"
        )
        self.assertEqual(session.calls[4][2], {"Authorization": "Bearer jwt-b"})
        self.assertEqual(session.calls[5][2], {"Authorization": "Bearer jwt-c"})
        # plain reads carry no auth header
        self.assertIsNone(session.calls[2][2])
        self.assertEqual(urls[9], "https://api.example.com/v1/rooms/room1/events")
        self.assertEqual(
            urls[10],
            "https://api.example.com/v1/rooms/room1/events?after_seq=7&limit=10&cursor=a%20b",
        )
        self.assertEqual(session.calls[10][2], {"Authorization": "Bearer jwt-d"})
        self.assertEqual(urls[11], "https://api.example.com/v1/rooms/room1/archive")

    def test_sse_events_url_method(self):
        session = FakeSession([])
        client = DiscourseClient("https://api.example.com", session=session)
        self.assertEqual(
            client.sse_events_url("room1"),
            sse_events_url("https://api.example.com", "room1"),
        )


class HelperTests(unittest.TestCase):
    def test_sse_events_url_preserves_http_schemes(self):
        self.assertEqual(
            sse_events_url("https://api.example.com", "room123"),
            "https://api.example.com/v1/rooms/room123/events/live",
        )
        self.assertEqual(
            sse_events_url("http://api.example.com/", "room 1"),
            "http://api.example.com/v1/rooms/room%201/events/live",
        )
        self.assertEqual(
            sse_events_url("ftp://api.example.com", "r"),
            "ftp://api.example.com/v1/rooms/r/events/live",
        )

    def test_requests_session_factory(self):
        original = http_client.requests
        try:
            http_client.requests = None
            with self.assertRaises(RuntimeError):
                ProfileClient("https://api.example.com")

            class _FakeRequests:
                class Session:
                    pass

            http_client.requests = _FakeRequests
            client = ProfileClient("https://api.example.com")
            self.assertIsInstance(client.session, _FakeRequests.Session)
        finally:
            http_client.requests = original


if __name__ == "__main__":
    unittest.main()
