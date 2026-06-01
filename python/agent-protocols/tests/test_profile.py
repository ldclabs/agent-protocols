import unittest

from agent_protocols.identity import AgentSigner
from agent_protocols.profile import materialize_profile, profile_update_event, validate_profile_update


class ProfileTests(unittest.TestCase):
    def test_materializes_valid_profile_update(self):
        signer = AgentSigner.from_seed(bytes([11]) * 32)
        payload = {"id": signer.agent_id(), "name": "ResearchAgent-v3", "capabilities": ["research"]}
        envelope = signer.sign_event(profile_update_event(signer.agent_id(), 1_779_753_600_000, "n_profile", payload))

        profile = materialize_profile(envelope)

        self.assertEqual(profile["id"], signer.agent_id())
        self.assertEqual(profile["name"], "ResearchAgent-v3")
        self.assertEqual(profile["updated_at"], 1_779_753_600_000)
        self.assertEqual(profile["profile_event_id"], envelope["event_id"])

    def test_rejects_actor_payload_mismatch(self):
        signer = AgentSigner.from_seed(bytes([12]) * 32)
        other = AgentSigner.from_seed(bytes([13]) * 32)
        payload = {"id": other.agent_id(), "name": "Imposter"}
        envelope = signer.sign_event(profile_update_event(signer.agent_id(), 1_779_753_600_000, "n_profile", payload))

        with self.assertRaises(Exception):
            validate_profile_update(envelope)

    def test_materializes_legacy_agent_id_payload(self):
        signer = AgentSigner.from_seed(bytes([14]) * 32)
        payload = {"agent_id": signer.agent_id(), "name": "LegacyAgent"}
        envelope = signer.sign_event(profile_update_event(signer.agent_id(), 1_779_753_600_001, "n_legacy", payload))

        profile = materialize_profile(envelope)

        self.assertEqual(profile["id"], signer.agent_id())
        self.assertEqual(profile["name"], "LegacyAgent")


if __name__ == "__main__":
    unittest.main()
