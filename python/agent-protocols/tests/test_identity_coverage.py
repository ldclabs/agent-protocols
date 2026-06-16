import base64
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_protocols.identity import (
    AGENT_ID_PREFIX,
    AgentSigner,
    ClientNonceManager,
    MemoryNonceStore,
    RequestBinding,
    agent_id_from_public_key,
    create_event,
    create_request_jwt_claims,
    event_hash,
    event_hash_bytes,
    public_key_bytes,
    sign_event,
    sign_event_hash,
    unix_ms,
    unix_secs,
    validate_agent_id,
    verify_event_hash_signature,
    verify_request_jwt,
    verify_timestamp,
    with_room_id,
)
from agent_protocols.errors import AgentProtocolError


def _b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


def encode_token(header, claims):
    signature = base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode()
    return f"{_b64(header)}.{_b64(claims)}.{signature}"


class AgentIdTests(unittest.TestCase):
    def test_helpers_validate_prefix_length_and_encoding(self):
        signer = AgentSigner.from_seed(bytes([20]) * 32)
        agent_id = signer.agent_id()
        self.assertEqual(agent_id_from_public_key(signer.public_key()), agent_id)
        self.assertEqual(public_key_bytes(agent_id), signer.public_key())
        self.assertEqual(validate_agent_id(agent_id), agent_id)

        with self.assertRaises(AgentProtocolError):
            agent_id_from_public_key(b"short")
        with self.assertRaises(AgentProtocolError):
            public_key_bytes("did:web:example")
        with self.assertRaises(AgentProtocolError):
            public_key_bytes(f"{AGENT_ID_PREFIX}!!!")
        with self.assertRaises(AgentProtocolError):
            public_key_bytes(f"{AGENT_ID_PREFIX}AAAA")

    def test_generate_and_seed_validation(self):
        signer = AgentSigner.generate()
        self.assertTrue(signer.agent_id().startswith(AGENT_ID_PREFIX))
        with self.assertRaises(AgentProtocolError):
            AgentSigner.from_seed(bytes(16))


class EventTests(unittest.TestCase):
    def test_create_event_and_with_room_id(self):
        signer = AgentSigner.from_seed(bytes([21]) * 32)
        event = create_event("p", "t", signer.agent_id(), 1000, 1, {"a": 1})
        self.assertEqual(with_room_id(event, "room1")["room_id"], "room1")
        with self.assertRaises(AgentProtocolError):
            create_event("p", "t", "bad-actor", 1, 1, {})

    def test_free_sign_event_and_event_hash(self):
        seed = bytes([22]) * 32
        signer = AgentSigner.from_seed(seed)
        private_key = Ed25519PrivateKey.from_private_bytes(seed)
        event = create_event("p", "t", signer.agent_id(), 1000, 1, {"a": 1})
        self.assertEqual(sign_event(private_key, event), signer.sign_event(event)["signature"])
        self.assertEqual(event_hash(event), signer.sign_event(event)["hash"])

    def test_signature_helpers_enforce_lengths(self):
        signer = AgentSigner.from_seed(bytes([23]) * 32)
        event = create_event("p", "t", signer.agent_id(), 1000, 1, {"a": 1})
        digest = event_hash_bytes(event)
        private_key = Ed25519PrivateKey.from_private_bytes(bytes([23]) * 32)
        signature = sign_event_hash(private_key, digest)

        with self.assertRaises(AgentProtocolError):
            sign_event_hash(private_key, bytes(10))  # wrong hash length
        with self.assertRaises(AgentProtocolError):
            verify_event_hash_signature(private_key.public_key(), digest, "AAAA")  # short sig
        other = AgentSigner.from_seed(bytes([24]) * 32)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        wrong_key = Ed25519PublicKey.from_public_bytes(other.public_key())
        with self.assertRaises(AgentProtocolError):
            verify_event_hash_signature(wrong_key, digest, signature)  # bad signature


class TimeAndNonceTests(unittest.TestCase):
    def test_verify_timestamp_window(self):
        verify_timestamp(1000, 1200, 1000)
        with self.assertRaises(AgentProtocolError):
            verify_timestamp(0, 1_000_000, 1000)
        with self.assertRaises(AgentProtocolError):
            verify_timestamp(100, 100, -1)

    def test_memory_nonce_store(self):
        actor = AgentSigner.from_seed(bytes([25]) * 32).agent_id()
        store = MemoryNonceStore()
        with self.assertRaises(AgentProtocolError):
            store.check_and_update(actor, 1, 1000, -1)
        self.assertEqual(store.check_and_update(actor, 4, 1000, 1000), 4)
        self.assertEqual(store.check_and_update(actor, 5, 1100, 1000), 5)
        self.assertEqual(store.max_nonce(actor, 1500), 5)
        self.assertIsNone(store.max_nonce(actor, 5000))
        self.assertIsNone(store.max_nonce("did:agent:none", 1500))

    def test_client_nonce_manager_observe(self):
        manager = ClientNonceManager(5)
        self.assertEqual(manager.peek(), 5)
        manager.observe_max_nonce(None)
        manager.observe_max_nonce("")
        self.assertEqual(manager.peek(), 5)
        manager.observe_max_nonce("9")
        self.assertEqual(manager.peek(), 10)
        manager.observe_max_nonce(3)  # lower values ignored
        self.assertEqual(manager.peek(), 10)
        with self.assertRaises(AgentProtocolError):
            manager.observe_max_nonce("not-a-number")
        with self.assertRaises(AgentProtocolError):
            ClientNonceManager(0)

    def test_unix_helpers(self):
        self.assertGreater(unix_ms(), 0)
        self.assertGreater(unix_secs(), 0)
        self.assertGreaterEqual(unix_ms(), unix_secs() * 1000)


class RequestJwtTests(unittest.TestCase):
    def test_sign_request_jwt_rejects_foreign_claims(self):
        signer = AgentSigner.from_seed(bytes([26]) * 32)
        other = AgentSigner.from_seed(bytes([27]) * 32)
        claims = create_request_jwt_claims(
            other.agent_id(), RequestBinding.create("https://api.example.com"), 100, 300
        )
        with self.assertRaises(AgentProtocolError):
            signer.sign_request_jwt(claims)

    def test_verify_request_jwt_rejects_malformed_tokens(self):
        signer = AgentSigner.from_seed(bytes([28]) * 32)
        agent_id = signer.agent_id()
        other = AgentSigner.from_seed(bytes([29]) * 32).agent_id()
        claims = {
            "iss": agent_id,
            "sub": agent_id,
            "aud": "https://api.example.com",
            "iat": 100,
            "exp": 400,
        }

        with self.assertRaises(AgentProtocolError):
            verify_request_jwt("only.two", audience="https://api.example.com", now_secs=200)
        with self.assertRaises(AgentProtocolError):
            verify_request_jwt(
                encode_token({"alg": "HS256", "typ": "JWT", "kid": agent_id}, claims),
                audience="https://api.example.com",
                now_secs=200,
            )
        with self.assertRaises(AgentProtocolError):
            verify_request_jwt(
                encode_token({"alg": "EdDSA", "typ": "JWS", "kid": agent_id}, claims),
                audience="https://api.example.com",
                now_secs=200,
            )
        with self.assertRaises(AgentProtocolError):
            verify_request_jwt(
                encode_token({"alg": "EdDSA", "typ": "JWT", "kid": other}, claims),
                audience="https://api.example.com",
                now_secs=200,
            )
        with self.assertRaises(AgentProtocolError):
            # valid alg/typ/kid but bogus signature
            verify_request_jwt(
                encode_token({"alg": "EdDSA", "typ": "JWT", "kid": agent_id}, claims),
                audience="https://api.example.com",
                now_secs=200,
            )

    def test_verify_request_jwt_enforces_audience_and_window(self):
        signer = AgentSigner.from_seed(bytes([30]) * 32)
        binding = RequestBinding.create("https://api.example.com")

        token = signer.sign_request_jwt(create_request_jwt_claims(signer.agent_id(), binding, 100, 300))
        with self.assertRaises(AgentProtocolError):
            verify_request_jwt(token, audience="https://other", now_secs=200)

        expired = signer.sign_request_jwt(create_request_jwt_claims(signer.agent_id(), binding, 1000, 300))
        with self.assertRaises(AgentProtocolError):
            verify_request_jwt(expired, audience=binding.audience, now_secs=5000)

        long_ttl = signer.sign_request_jwt(create_request_jwt_claims(signer.agent_id(), binding, 100, 400))
        with self.assertRaises(AgentProtocolError):
            verify_request_jwt(long_ttl, audience=binding.audience, now_secs=200, max_ttl_secs=300)


if __name__ == "__main__":
    unittest.main()
