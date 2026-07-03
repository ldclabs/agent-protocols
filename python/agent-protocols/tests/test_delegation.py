import unittest

from agent_protocols.delegation import (
    DELEGATION_GRANT,
    DELEGATION_PROTOCOL,
    DELEGATION_REVOKE,
    delegation_grant_event,
    delegation_revoke_event,
    materialize_delegation_credential,
    validate_delegation_envelope,
    validate_delegation_grant_payload,
    validate_principal_document,
)
from agent_protocols.identity import AgentSigner, create_event


class DelegationTests(unittest.TestCase):
    def test_grant_event_materializes_credential(self):
        controller = AgentSigner.from_seed(bytes([31]) * 32)
        subject = AgentSigner.from_seed(bytes([32]) * 32)
        payload = {
            "id": "del_01J8ZM7A3G2T9B4Q6X8R0N1P2Q",
            "principal": {
                "id": "https://al.ink/yan",
                "type": "person",
                "name": "Yan",
            },
            "subject": subject.agent_id(),
            "relationship": "primary_delegate",
            "scopes": ["inbox.screen", "meeting.propose"],
            "constraints": {"requires_human_approval": ["meeting.accept"]},
            "not_before": 1_779_753_600_000,
            "expires_at": 1_790_000_000_000,
        }
        envelope = controller.sign_event(
            delegation_grant_event(controller.agent_id(), 1_779_753_600_000, 1, payload)
        )

        validate_delegation_envelope(envelope)
        credential = materialize_delegation_credential(
            envelope,
            status_url="https://al.ink/v1/delegations/del/status",
        )

        self.assertEqual(envelope["event"]["type"], DELEGATION_GRANT)
        self.assertEqual(credential["protocol"], DELEGATION_PROTOCOL)
        self.assertEqual(credential["controller"], controller.agent_id())
        self.assertEqual(credential["subject"], subject.agent_id())
        self.assertEqual(credential["status"], "active")
        self.assertEqual(credential["event_id"], envelope["hash"])

    def test_revoke_event_and_invalid_payloads(self):
        controller = AgentSigner.from_seed(bytes([33]) * 32)
        envelope = controller.sign_event(
            delegation_revoke_event(
                controller.agent_id(),
                1_779_753_700_000,
                2,
                {
                    "id": "del_01J8ZM7A3G2T9B4Q6X8R0N1P2Q",
                    "principal_id": "https://al.ink/yan",
                    "reason": "rotated_primary_agent",
                },
            )
        )

        self.assertEqual(envelope["event"]["type"], DELEGATION_REVOKE)
        validate_delegation_envelope(envelope)
        with self.assertRaisesRegex(Exception, "HTTPS|scopes"):
            validate_delegation_grant_payload(
                {
                    "id": "del",
                    "principal": {"id": "http://example.com"},
                    "subject": controller.agent_id(),
                    "scopes": [],
                }
            )

    def test_principal_document_and_event_type_validation(self):
        controller = AgentSigner.from_seed(bytes([34]) * 32)
        validate_principal_document(
            {
                "id": "https://profiles.example.com/org/acme",
                "controllers": [controller.agent_id()],
                "delegations_url": "https://profiles.example.com/v1/delegations/query",
            }
        )
        with self.assertRaises(Exception):
            validate_principal_document(
                {
                    "id": "https://profiles.example.com/org/acme",
                    "controllers": [],
                }
            )

        wrong = controller.sign_event(
            create_event(
                DELEGATION_PROTOCOL,
                "delegation.unknown",
                controller.agent_id(),
                1,
                1,
                {"id": "del"},
            )
        )
        with self.assertRaisesRegex(Exception, "delegation.grant"):
            validate_delegation_envelope(wrong)

    def test_rejects_malformed_https_like_principal_urls(self):
        signer = AgentSigner.from_seed(bytes([35]) * 32)
        for principal_id in ("https://", "https://[::1", "http://example.com"):
            with self.assertRaises(Exception):
                validate_delegation_grant_payload(
                    {
                        "id": "del",
                        "principal": {"id": principal_id},
                        "subject": signer.agent_id(),
                        "scopes": ["scope"],
                    }
                )


if __name__ == "__main__":
    unittest.main()
