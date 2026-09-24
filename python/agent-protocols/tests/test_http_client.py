import json
import unittest

import agent_protocols.http_client as http_client
from agent_protocols.http_client import (
    DelegationClient,
    DiscourseClient,
    HttpResponseError,
    ProfileClient,
    sse_events_url,
)
from agent_protocols.identity import AgentSigner

AGENT_ID = AgentSigner.from_seed(bytes([1]) * 32).agent_id()


class FakeResponse:
    status_code = 200

    def __init__(self, payload, *, status=None, headers=None, text=None):
        self._payload = payload
        if status is not None:
            self.status_code = status
        self.headers = headers or {}
        self.text = text if text is not None else json.dumps(payload)

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def get(self, url, headers=None, **kwargs):
        self.calls.append(("GET", url, headers, None))
        return self._responses.pop(0)

    def post(self, url, json=None, headers=None):
        self.calls.append(("POST", url, headers, json))
        return self._responses.pop(0)

    def put(self, url, json=None, headers=None):
        self.calls.append(("PUT", url, headers, json))
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

    def test_error_responses_carry_code_data_and_max_seen_nonce(self):
        body = {"error": {"code": "nonce_not_greater", "message": "stale", "data": {"max_nonce": 10}}}
        session = FakeSession(
            [
                FakeResponse(None, status=500, text="boom"),
                FakeResponse(body, status=409, headers={"Max-Seen-Nonce": "10"}),
            ]
        )
        client = ProfileClient("https://api.example.com", session=session)
        with self.assertRaises(HttpResponseError) as plain:
            client.get_profile(AGENT_ID)
        self.assertEqual((plain.exception.status, plain.exception.code), (500, None))
        with self.assertRaises(HttpResponseError) as coded:
            client.get_profile(AGENT_ID)
        self.assertEqual(coded.exception.code, "nonce_not_greater")
        self.assertEqual(coded.exception.data, {"max_nonce": 10})
        self.assertEqual(coded.exception.max_seen_nonce, "10")


class DiscourseClientTests(unittest.TestCase):
    def test_every_endpoint_and_bearer_tokens(self):
        session = FakeSession([FakeResponse({"ok": True}) for _ in range(12)])
        client = DiscourseClient("https://api.example.com", session=session)
        envelope = {"hash": "h", "event": {}, "signature": "s"}

        client.protocol()
        client.create_room(envelope)
        client.room("room1")
        client.request_join("room1", envelope)
        client.join_request("room1", "req1", "jwt-b")
        client.join_requests("room1", "jwt-c", status="pending")
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
        # The signed join request authenticates the applicant; no JWT is sent.
        self.assertEqual(urls[3], "https://api.example.com/v1/rooms/room1/join-requests")
        self.assertIsNone(session.calls[3][2])
        self.assertEqual(session.calls[3][3], envelope)
        self.assertEqual(
            urls[4], "https://api.example.com/v1/rooms/room1/join-requests/req1"
        )
        self.assertEqual(session.calls[4][2], {"Authorization": "Bearer jwt-b"})
        self.assertEqual(urls[5], "https://api.example.com/v1/rooms/room1/join-requests?status=pending")
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

    def test_public_rooms_my_rooms_and_agent_status_endpoints(self):
        session = FakeSession([FakeResponse({"ok": True}) for _ in range(5)])
        client = DiscourseClient("https://api.example.com/", session=session)

        client.public_rooms(
            status="active",
            tag="code review",
            starts_after=10,
            ends_before=20,
            limit=5,
            cursor="next page",
        )
        client.my_rooms("jwt-me")
        client.agent_statuses("room1", jwt="jwt-statuses")
        client.agent_status("room1", AGENT_ID, jwt="jwt-status")
        client.set_agent_status("room1", "jwt-set", {"state": "idle", "expires_at": 2})

        urls = [call[1] for call in session.calls]
        self.assertEqual(
            urls[0],
            "https://api.example.com/v1/rooms/public?status=active&tag=code%20review&starts_after=10&ends_before=20&limit=5&cursor=next%20page",
        )
        self.assertEqual(urls[1], "https://api.example.com/v1/me/rooms")
        self.assertEqual(session.calls[1][2], {"Authorization": "Bearer jwt-me"})
        self.assertEqual(urls[2], "https://api.example.com/v1/rooms/room1/agent-status")
        self.assertEqual(session.calls[2][2], {"Authorization": "Bearer jwt-statuses"})
        self.assertEqual(urls[3], f"https://api.example.com/v1/rooms/room1/agent-status/{AGENT_ID}")
        self.assertEqual(session.calls[4][0], "PUT")
        self.assertEqual(session.calls[4][2], {"Authorization": "Bearer jwt-set"})
        self.assertEqual(session.calls[4][3], {"state": "idle", "expires_at": 2})


PRINCIPAL_ID = "https://api.al.ink/d9c6a99cne5g00a6scn0"
PRINCIPAL_DOCUMENT = {"id": PRINCIPAL_ID, "protocol": "agent-delegation/1.0", "updated_at": 1000, "controllers": [{"id": AGENT_ID, "source": "local", "valid_from": 0}], "aliases": ["https://al.ink/yan"]}
DISCOVERY = {"protocol": "agent-delegation/1.0", "service": "https://api.al.ink", "endpoints": {"delegations": "https://api.al.ink/api/grants", "query": "https://api.al.ink/api/find"}}


class DelegationClientTests(unittest.TestCase):
    def test_every_endpoint_uses_expected_method_and_path(self):
        responses = [FakeResponse({"ok": True}) for _ in range(6)]
        responses[1] = FakeResponse(PRINCIPAL_DOCUMENT)
        session = FakeSession(responses)
        client = DelegationClient("https://api.al.ink/", session=session)
        envelope = {
            "hash": "h",
            "event": {
                "protocol": "agent-delegation/1.0",
                "type": "delegation.revoke",
                "actor": AGENT_ID,
                "created_at": 1,
                "nonce": 1,
                "payload": {"id": "del_1", "principal_id": PRINCIPAL_ID},
            },
            "signature": "s",
        }

        client.protocol()
        client.principal(PRINCIPAL_ID)
        client.delegation("del_1")
        client.delegation_events("del_1")
        client.submit_delegation_event(envelope)
        client.query_delegations(
            {"subject": AGENT_ID, "principal_id": PRINCIPAL_ID, "status": "active", "limit": 20}
        )

        urls = [call[1] for call in session.calls]
        self.assertEqual(urls[0], "https://api.al.ink/.well-known/agent-delegation")
        self.assertEqual(urls[1], PRINCIPAL_ID)
        self.assertEqual(session.calls[1][2], {"Accept": "application/json"})
        self.assertEqual(urls[2], "https://api.al.ink/v1/delegations/del_1")
        self.assertEqual(urls[3], "https://api.al.ink/v1/delegations/del_1/events")
        self.assertEqual((session.calls[4][0], urls[4]), ("POST", "https://api.al.ink/v1/delegations"))
        self.assertEqual(
            (session.calls[5][0], urls[5]), ("POST", "https://api.al.ink/v1/delegations/query")
        )
        self.assertEqual(session.calls[5][3]["status"], "active")

    def test_discovered_endpoints_win_and_history_pages_are_followed(self):
        session = FakeSession(
            [
                FakeResponse(DISCOVERY),
                FakeResponse({"result": [{"accepted_at": 1}], "next_cursor": "c1"}),
                FakeResponse({"result": [{"accepted_at": 2}]}),
                FakeResponse({"result": []}),
            ]
        )
        client = DelegationClient.discover("https://api.al.ink/", session=session)
        records = client.all_delegation_events("del_1")
        self.assertEqual([record["accepted_at"] for record in records], [1, 2])
        client.query_delegations({"subject": AGENT_ID, "principal_id": PRINCIPAL_ID})
        self.assertEqual(
            [call[1] for call in session.calls],
            [
                "https://api.al.ink/.well-known/agent-delegation",
                "https://api.al.ink/api/grants/del_1/events",
                "https://api.al.ink/api/grants/del_1/events?cursor=c1",
                "https://api.al.ink/api/find",
            ],
        )
        # Invalid IDs never leave the client.
        for delegation_id in ("a/b", ".", "..", "", "a" * 129):
            with self.assertRaisesRegex(Exception, "delegation id"):
                client.delegation(delegation_id)
        self.assertEqual(len(session.calls), 4)

    def test_discovery_falls_back_to_default_paths(self):
        session = FakeSession([FakeResponse({"error": {"code": "not_found", "message": "none"}}, status=404), FakeResponse({})])
        client = DelegationClient.discover("https://api.example.com", session=session)
        client.delegation("del_1")
        self.assertEqual(session.calls[1][1], "https://api.example.com/v1/delegations/del_1")

    def test_enumeration_requires_a_jwt_and_queries_the_principal_endpoint(self):
        session = FakeSession([FakeResponse({"result": []}), FakeResponse({"result": []})])
        client = DelegationClient("https://api.al.ink/", session=session)

        # Enumerating one side without authorization never leaves the client.
        with self.assertRaisesRegex(Exception, "must include both subject and principal_id"):
            client.query_delegations({"subject": AGENT_ID})

        client.query_delegations({"subject": AGENT_ID}, "jwt-enumerate")
        self.assertEqual(session.calls[0][1], "https://api.al.ink/v1/delegations/query")
        self.assertEqual(session.calls[0][2], {"Authorization": "Bearer jwt-enumerate"})

        # A principal-anchored query goes to the endpoint the principal names.
        client.query_delegations_at(
            "https://delegations.example.com/query",
            {"subject": AGENT_ID, "principal_id": PRINCIPAL_ID},
        )
        self.assertEqual(session.calls[1][1], "https://delegations.example.com/query")

    def test_principal_served_away_from_its_id_is_re_resolved(self):
        session = FakeSession([FakeResponse(PRINCIPAL_DOCUMENT), FakeResponse(PRINCIPAL_DOCUMENT)])
        client = DelegationClient("https://api.al.ink/", session=session)

        # The alias hosts a copy instead of redirecting, so the canonical id is read.
        resolved = client.principal("https://al.ink/yan")

        self.assertEqual(resolved["id"], PRINCIPAL_ID)
        self.assertEqual([call[1] for call in session.calls], ["https://al.ink/yan", PRINCIPAL_ID])

        impostor = FakeSession(
            [
                FakeResponse(PRINCIPAL_DOCUMENT),
                FakeResponse({"id": "https://impostor.example.com/yan", "protocol": "agent-delegation/1.0", "updated_at": 1000, "controllers": [{"id": AGENT_ID, "source": "local", "valid_from": 0}]}),
            ]
        )
        with self.assertRaisesRegex(Exception, "was served at"):
            DelegationClient("https://api.al.ink/", session=impostor).principal("https://al.ink/yan")


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

class DelegationResolutionRevisionTests(unittest.TestCase):
    def test_copy_authority_is_discarded(self):
        session = FakeSession([
            FakeResponse({"id": PRINCIPAL_ID, "controllers": "untrusted junk"}),
            FakeResponse(PRINCIPAL_DOCUMENT),
        ])
        self.assertEqual(DelegationClient("https://al.ink/yan", session).principal(), PRINCIPAL_DOCUMENT)

    def test_redirects_stay_https_and_bounded(self):
        class Redirect(FakeResponse):
            status_code = 302
            def __init__(self, location):
                super().__init__({})
                self.headers = {"location": location}
        session = FakeSession([Redirect("http://insecure.example/p")])
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            DelegationClient("https://al.ink/yan", session).principal()
        self.assertEqual(len(session.calls), 1)
        session = FakeSession([Redirect("https://al.ink/yan") for _ in range(6)])
        with self.assertRaisesRegex(ValueError, "redirect"):
            DelegationClient("https://al.ink/yan", session).principal()
        self.assertEqual(len(session.calls), 6)
