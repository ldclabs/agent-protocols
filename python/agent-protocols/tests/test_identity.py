import unittest

from agent_protocols.identity import (
    AgentSigner,
    MemoryNonceStore,
    RequestBinding,
    create_event,
    create_request_jwt_claims,
    verify_envelope,
    verify_live_envelope,
    verify_request_jwt_live,
)


class IdentityTests(unittest.TestCase):
    def test_signs_and_verifies_event_envelopes(self):
        signer = AgentSigner.from_seed(bytes([7]) * 32)
        event = create_event(
            "agent-profile/1.0",
            "profile.update",
            signer.agent_id(),
            1_779_753_600_000,
            "n_test",
            {"agent_id": signer.agent_id(), "name": "ResearchAgent"},
        )

        envelope = signer.sign_event(event)

        self.assertTrue(envelope["event_id"].startswith("evt_z"))
        verify_envelope(envelope)

    def test_rejects_tampered_payloads(self):
        signer = AgentSigner.from_seed(bytes([8]) * 32)
        envelope = signer.sign_event(
            create_event("agent-profile/1.0", "profile.update", signer.agent_id(), 1000, "n_test", {"name": "before"})
        )
        envelope["event"]["payload"] = {"name": "after"}

        with self.assertRaises(Exception):
            verify_envelope(envelope)

    def test_rejects_nonce_reuse(self):
        signer = AgentSigner.from_seed(bytes([9]) * 32)
        envelope = signer.sign_event(
            create_event("agent-profile/1.0", "profile.update", signer.agent_id(), 1000, "n_reused", {"name": "ResearchAgent"})
        )
        store = MemoryNonceStore()

        verify_live_envelope(envelope, store, now_ms=1000, window_ms=1000)
        with self.assertRaises(Exception):
            verify_live_envelope(envelope, store, now_ms=1000, window_ms=1000)

    def test_signs_and_verifies_request_jwts(self):
        signer = AgentSigner.from_seed(bytes([10]) * 32)
        binding = RequestBinding.create("https://api.example.com")
        claims = create_request_jwt_claims(signer.agent_id(), binding, 100, 300, "jwt_nonce")
        token = signer.sign_request_jwt(claims)
        store = MemoryNonceStore()

        verified = verify_request_jwt_live(
            token,
            store,
            audience=binding.audience,
            now_secs=120,
            max_ttl_secs=300,
        )

        self.assertEqual(verified["jti"], "jwt_nonce")
        with self.assertRaises(Exception):
            verify_request_jwt_live(
                token,
                store,
                audience=binding.audience,
                now_secs=120,
                max_ttl_secs=300,
            )


if __name__ == "__main__":
    unittest.main()
