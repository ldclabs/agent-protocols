import unittest
from base64 import urlsafe_b64encode
from hashlib import sha3_256

from agent_protocols.errors import AgentProtocolError
from agent_protocols.identity import AgentSigner
from agent_protocols.discourse import (
    DISCOURSE_PROTOCOL,
    MESSAGE_CREATE,
    PACK_REACTIONS,
    ROOM_CREATE,
    TypeRegistry,
    build_server_record,
    can_submit_event,
    default_kind_roles,
    discourse_event,
    event_requires_room_id,
    validate_discourse_envelope,
    validate_event_against_registry,
    validate_message_create_payload,
    validate_pack_import,
    validate_room_path,
    validate_room_write,
    validate_type_declaration,
    validate_type_def,
    verify_pack_digest,
    verify_server_record_chain,
)

FINDING_DEF = {
    "type": "review.finding",
    "kind": "message",
    "title": "Review finding",
    "schema": {"type": "object"},
}


class HelperBranchTests(unittest.TestCase):
    def test_event_requires_room_id_and_discourse_event(self):
        signer = AgentSigner.from_seed(bytes([60]) * 32)
        self.assertTrue(event_requires_room_id(MESSAGE_CREATE))
        self.assertFalse(event_requires_room_id(ROOM_CREATE))
        event = discourse_event(MESSAGE_CREATE, signer.agent_id(), 1, 1, "room1", 1, "room-create-head", {"a": 1})
        self.assertEqual(event["room_id"], "room1")
        self.assertEqual(event["base_seq"], 1)
        self.assertEqual(event["base_hash"], "room-create-head")
        self.assertEqual(event["protocol"], DISCOURSE_PROTOCOL)

    def test_validate_discourse_envelope_rejects_foreign_protocol(self):
        signer = AgentSigner.from_seed(bytes([61]) * 32)
        event = discourse_event(MESSAGE_CREATE, signer.agent_id(), 1, 1, "room1", 1, "room-create-head", {"a": 1})
        event["protocol"] = "other/1.0"
        envelope = signer.sign_event(event)
        with self.assertRaises(AgentProtocolError):
            validate_discourse_envelope(envelope)

    def test_validate_room_path_matches_mismatches_and_requires_room_id(self):
        signer = AgentSigner.from_seed(bytes([62]) * 32)
        in_room = signer.sign_event(
            discourse_event(MESSAGE_CREATE, signer.agent_id(), 1, 1, "room1", 1, "room-create-head", {"a": 1})
        )
        validate_room_path(in_room, "room1")
        with self.assertRaises(AgentProtocolError):
            validate_room_path(in_room, "room2")

        no_room = {
            "hash": "h",
            "event": {"type": MESSAGE_CREATE, "protocol": DISCOURSE_PROTOCOL, "base_seq": 1, "base_hash": "room-create-head"},
            "signature": "s",
        }
        with self.assertRaises(AgentProtocolError):
            validate_room_path(no_room, "room1")


class ValidationTests(unittest.TestCase):
    def test_validate_type_def_rejects_each_field(self):
        cases = [
            {**FINDING_DEF, "kind": "bogus"},
            {**FINDING_DEF, "title": "  "},
            {**FINDING_DEF, "schema": "not-a-dict"},
            {**FINDING_DEF, "roles": []},
            {**FINDING_DEF, "status": "bogus"},
            {**FINDING_DEF, "rate_hint": 0},
            {**FINDING_DEF, "max_payload_hint": -1},
            {**FINDING_DEF, "schema": {"type": 123}},  # invalid JSON Schema
        ]
        for case in cases:
            with self.assertRaises(AgentProtocolError):
                validate_type_def(case)

    def test_validate_pack_import_covers_each_arm(self):
        validate_pack_import({"use": PACK_REACTIONS})
        validate_pack_import({"pack": "https://example.com/p.json", "digest": "sha256:abc"})
        with self.assertRaises(AgentProtocolError):
            validate_pack_import({"pack": "https://example.com/p.json", "digest": "  "})
        with self.assertRaises(AgentProtocolError):
            validate_pack_import({})
        with self.assertRaises(AgentProtocolError):
            validate_pack_import({"use": "adp:Bad/1.0"})
        with self.assertRaises(AgentProtocolError):
            validate_pack_import({"use": PACK_REACTIONS, "types": []})

    def test_validate_type_declaration_routes_and_rejects(self):
        validate_type_declaration(FINDING_DEF)
        validate_type_declaration({"use": PACK_REACTIONS})
        with self.assertRaises(AgentProtocolError):
            validate_type_declaration("not-a-dict")
        with self.assertRaises(AgentProtocolError):
            validate_type_declaration({"unrelated": True})

    def test_validate_message_create_payload(self):
        validate_message_create_payload({"content_type": "text/plain", "content": "hi"})
        with self.assertRaises(AgentProtocolError):
            validate_message_create_payload({"content_type": " ", "content": "hi"})

    def test_verify_pack_digest_supports_sha3_256(self):
        data = b"pack document bytes"
        digest = "sha3-256:" + urlsafe_b64encode(sha3_256(data).digest()).rstrip(b"=").decode()
        verify_pack_digest(data, digest)
        with self.assertRaises(AgentProtocolError):
            verify_pack_digest(b"tampered", digest)


class RegistryTests(unittest.TestCase):
    def test_registry_rejects_unknown_subset_and_unknown_declarations(self):
        packs = {
            "adp:custom/1.0": {
                "id": "adp:custom/1.0",
                "title": "Custom",
                "types": [FINDING_DEF],
            }
        }
        with self.assertRaises(AgentProtocolError):
            TypeRegistry.from_declarations(
                [{"use": "adp:custom/1.0", "types": ["does.not.exist"]}], packs
            )

        registry = TypeRegistry()
        registry.define(FINDING_DEF)
        self.assertEqual(len(registry.definitions()), 1)
        with self.assertRaises(AgentProtocolError):
            registry.apply({"unrelated": True})

    def test_validate_event_against_registry_bypasses_builtins(self):
        registry = TypeRegistry()
        validate_event_against_registry(MESSAGE_CREATE, {"anything": True}, registry)


class PermissionTests(unittest.TestCase):
    def test_default_kind_roles_rejects_unknown_kind(self):
        self.assertEqual(default_kind_roles("control"), ("moderator",))
        with self.assertRaises(AgentProtocolError):
            default_kind_roles("bogus")

    def test_can_submit_event_custom_edges_and_room_write(self):
        registry = TypeRegistry()
        registry.define(FINDING_DEF)
        registry.define({**FINDING_DEF, "type": "review.disabled", "status": "disabled"})

        self.assertFalse(can_submit_event("review.disabled", {"is_creator": True}, registry))
        self.assertFalse(can_submit_event("review.finding", {}, registry))

        validate_room_write(MESSAGE_CREATE, "active", {"role": "speaker"}, registry)
        with self.assertRaises(AgentProtocolError):
            validate_room_write(MESSAGE_CREATE, "ended", {"role": "speaker"}, registry)


class ServerRecordChainTests(unittest.TestCase):
    def test_chain_violations(self):
        signer = AgentSigner.from_seed(bytes([63]) * 32)

        def make(seq, nonce, pre_hash):
            envelope = signer.sign_event(
                discourse_event(
                    MESSAGE_CREATE,
                    signer.agent_id(),
                    100,
                    nonce,
                    "room1",
                    1 if seq == 1 else seq - 1,
                    pre_hash or "room-create-head",
                    {"a": 1},
                )
            )
            return build_server_record("room1", seq, pre_hash, 100 + seq, envelope)

        first = make(1, 1, None)
        with self.assertRaises(AgentProtocolError):
            verify_server_record_chain([first, make(3, 2, first["hash"])])  # seq gap
        with self.assertRaises(AgentProtocolError):
            verify_server_record_chain([first, make(2, 3, "wrong")])  # pre_hash mismatch
        with self.assertRaises(AgentProtocolError):
            verify_server_record_chain([make(1, 4, "unexpected")])  # first pre_hash not null


if __name__ == "__main__":
    unittest.main()
