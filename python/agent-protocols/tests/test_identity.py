import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_protocols.identity import (
    AgentSigner,
    ClientNonceManager,
    MAX_SAFE_NONCE,
    MemoryNonceStore,
    RequestBinding,
    create_event,
    create_request_jwt_claims,
    event_hash_bytes,
    sign_event_hash,
    verify_envelope,
    verify_event_hash_signature,
    verify_live_envelope,
    verify_request_jwt,
)


class IdentityTests(unittest.TestCase):
    def test_signs_and_verifies_event_envelopes(self):
        signer = AgentSigner.from_seed(bytes([7]) * 32)
        event = create_event(
            "agent-profile/1.0",
            "profile.update",
            signer.agent_id(),
            1_779_753_600_000,
            1,
            {"id": signer.agent_id(), "name": "ResearchAgent"},
        )

        envelope = signer.sign_event(event)

        self.assertEqual(len(envelope["hash"]), 43)
        self.assertFalse(envelope["hash"].startswith("evt_"))
        verify_envelope(envelope)

    def test_signs_and_verifies_raw_event_hash_bytes(self):
        seed = bytes([18]) * 32
        signer = AgentSigner.from_seed(seed)
        private_key = Ed25519PrivateKey.from_private_bytes(seed)
        event = create_event(
            "agent-profile/1.0",
            "profile.update",
            signer.agent_id(),
            1_779_753_600_000,
            1,
            {"id": signer.agent_id(), "name": "ResearchAgent"},
        )

        digest = event_hash_bytes(event)
        signature = sign_event_hash(private_key, digest)

        self.assertEqual(signer.sign_event(event)["signature"], signature)
        verify_event_hash_signature(private_key.public_key(), digest, signature)

    def test_rejects_tampered_payloads(self):
        signer = AgentSigner.from_seed(bytes([8]) * 32)
        envelope = signer.sign_event(
            create_event("agent-profile/1.0", "profile.update", signer.agent_id(), 1000, 1, {"name": "before"})
        )
        envelope["event"]["payload"] = {"name": "after"}

        with self.assertRaises(Exception):
            verify_envelope(envelope)

    def test_rejects_nonce_reuse(self):
        signer = AgentSigner.from_seed(bytes([9]) * 32)
        envelope = signer.sign_event(
            create_event("agent-profile/1.0", "profile.update", signer.agent_id(), 1000, 1, {"name": "ResearchAgent"})
        )
        store = MemoryNonceStore()

        self.assertEqual(verify_live_envelope(envelope, store, now_ms=1000, window_ms=1000), 1)
        with self.assertRaises(Exception):
            verify_live_envelope(envelope, store, now_ms=1000, window_ms=1000)

    def test_client_nonce_manager_observes_server_max(self):
        manager = ClientNonceManager()

        self.assertEqual(manager.next_nonce(), 1)
        manager.observe_max_nonce("5")

        self.assertEqual(manager.peek(), 6)
        self.assertEqual(manager.next_nonce(), 6)

    def test_rejects_nonce_values_outside_safe_json_integer_range(self):
        signer = AgentSigner.from_seed(bytes([16]) * 32)

        with self.assertRaises(Exception):
            create_event(
                "agent-profile/1.0",
                "profile.update",
                signer.agent_id(),
                1000,
                MAX_SAFE_NONCE + 1,
                {"id": signer.agent_id(), "name": "ResearchAgent"},
            )

    def test_signs_and_verifies_request_jwts(self):
        signer = AgentSigner.from_seed(bytes([10]) * 32)
        binding = RequestBinding.create("https://api.example.com")
        claims = create_request_jwt_claims(signer.agent_id(), binding, 100, 300)
        token = signer.sign_request_jwt(claims)

        verified = verify_request_jwt(
            token,
            audience=binding.audience,
            now_secs=120,
            max_ttl_secs=300,
        )

        self.assertEqual(verified["iss"], signer.agent_id())

    def test_rejects_request_jwts_with_non_positive_ttl(self):
        signer = AgentSigner.from_seed(bytes([17]) * 32)
        binding = RequestBinding.create("https://api.example.com")
        claims = create_request_jwt_claims(signer.agent_id(), binding, 100, 0)
        token = signer.sign_request_jwt(claims)

        with self.assertRaises(Exception):
            verify_request_jwt(
                token,
                audience=binding.audience,
                now_secs=100,
                max_ttl_secs=300,
            )


if __name__ == "__main__":
    unittest.main()


class Revision20260704IdentityTests(unittest.TestCase):
    ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    def test_base64url_decoding_rejects_non_canonical_encodings(self):
        from agent_protocols.errors import AgentProtocolError
        from agent_protocols.identity import (
            AGENT_ID_PREFIX,
            AgentSigner,
            create_event,
            validate_agent_id,
            verify_envelope,
        )

        signer = AgentSigner.from_seed(bytes([60]) * 32)
        agent_id = signer.agent_id()
        suffix = agent_id[len(AGENT_ID_PREFIX):]
        validate_agent_id(agent_id)

        # Padding characters are rejected even when the decoded bytes match.
        with self.assertRaisesRegex(AgentProtocolError, "canonical base64url"):
            validate_agent_id(f"{AGENT_ID_PREFIX}{suffix}==")

        # Non-zero trailing bits give the same key a second string form:
        # replace the final character with one sharing its used bits but
        # different trailing bits (the last char of a 32-byte value uses 4 of
        # its 6 bits).
        index = self.ALPHABET.index(suffix[-1])
        non_canonical = self.ALPHABET[(index & ~3) | ((index & 3) ^ 1)]
        with self.assertRaisesRegex(AgentProtocolError, "canonical base64url"):
            validate_agent_id(f"{AGENT_ID_PREFIX}{suffix[:-1]}{non_canonical}")

        # Non-alphabet characters are rejected.
        with self.assertRaisesRegex(AgentProtocolError, "canonical base64url"):
            validate_agent_id(f"{AGENT_ID_PREFIX}{suffix[:-1]}+")

        # Signatures must be canonical base64url too.
        event = create_event(
            "agent-profile/1.0",
            "profile.update",
            agent_id,
            1000,
            1,
            {"id": agent_id, "name": "Agent"},
        )
        envelope = signer.sign_event(event)
        tampered = {**envelope, "signature": envelope["signature"] + "="}
        with self.assertRaisesRegex(AgentProtocolError, "canonical base64url"):
            verify_envelope(tampered)

    def test_service_origin_derives_request_jwt_audience(self):
        from agent_protocols.errors import AgentProtocolError
        from agent_protocols.identity import service_origin

        self.assertEqual(
            service_origin("https://api.example.com/v1/rooms/room1"),
            "https://api.example.com",
        )
        self.assertEqual(
            service_origin("https://api.example.com:8443/path?q=1"),
            "https://api.example.com:8443",
        )
        self.assertEqual(
            service_origin("https://API.Example.com:443/"),
            "https://api.example.com",
        )
        with self.assertRaises(AgentProtocolError):
            service_origin("not a url")
        with self.assertRaises(AgentProtocolError):
            service_origin("ftp://example.com")

    def test_nonce_not_greater_errors_carry_the_effective_maximum(self):
        from agent_protocols.errors import AgentProtocolError
        from agent_protocols.identity import AgentSigner, MemoryNonceStore

        actor = AgentSigner.from_seed(bytes([61]) * 32).agent_id()
        store = MemoryNonceStore()
        store.check_and_update(actor, 7, 1000, 1000)
        with self.assertRaises(AgentProtocolError) as caught:
            store.check_and_update(actor, 7, 1100, 1000)
        self.assertEqual(caught.exception.code, "nonce_not_greater")
        self.assertEqual(caught.exception.data, {"max_nonce": 7})
