import unittest

from agent_protocols.errors import AgentProtocolError
from agent_protocols.identity import AgentSigner, create_event
from agent_protocols.profile import (
    PROFILE_PROTOCOL,
    PROFILE_UPDATE,
    materialize_profile,
    validate_profile_update,
)


class ProfileCoverageTests(unittest.TestCase):
    def test_rejects_wrong_protocol_and_type(self):
        signer = AgentSigner.from_seed(bytes([19]) * 32)
        payload = {"id": signer.agent_id(), "name": "ResearchAgent"}

        wrong_protocol = signer.sign_event(
            create_event("agent-discourse/1.0", PROFILE_UPDATE, signer.agent_id(), 1, 1, payload)
        )
        with self.assertRaises(AgentProtocolError):
            validate_profile_update(wrong_protocol)

        wrong_type = signer.sign_event(
            create_event(PROFILE_PROTOCOL, "profile.delete", signer.agent_id(), 1, 1, payload)
        )
        with self.assertRaises(AgentProtocolError):
            validate_profile_update(wrong_type)

    def test_materializes_every_optional_collection(self):
        signer = AgentSigner.from_seed(bytes([20]) * 32)
        payload = {
            "id": signer.agent_id(),
            "name": "FullAgent",
            "description": "desc",
            "avatar_url": "https://example.com/a.png",
            "provider": "did:agent:provider",
            "capabilities": ["research"],
            "service_endpoints": [{"type": "a2a", "url": "https://example.com"}],
            "links": [{"name": "Home", "url": "https://example.com", "rel": "homepage"}],
            "extra": {"domain": "research"},
        }
        from agent_protocols.profile import profile_update_event

        profile = materialize_profile(
            signer.sign_event(profile_update_event(signer.agent_id(), 1, 1, payload))
        )
        self.assertEqual(profile["service_endpoints"], payload["service_endpoints"])
        self.assertEqual(profile["capabilities"], payload["capabilities"])


if __name__ == "__main__":
    unittest.main()
