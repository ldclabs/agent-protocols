import json
import unittest
from base64 import urlsafe_b64encode
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

from jsonschema import ValidationError
from jsonschema.validators import Draft202012Validator

from agent_protocols.discourse import (
    MESSAGE_CREATE,
    PACK_CURATION,
    PACK_DELIBERATION,
    PACK_REACTIONS,
    ROOM_CANCEL,
    ROOM_CLOSE,
    ROOM_CREATE,
    ROOM_JOIN,
    ROOM_JOIN_REVIEW,
    ROOM_LEAVE,
    ROOM_MEMBER_ROLE_UPDATE,
    TYPE_DEFINE,
    TypeRegistry,
    archive_events_digest,
    build_server_record,
    can_accept_room_write,
    can_submit_event,
    can_write_in_state,
    discourse_event,
    pack_map,
    room_create_event,
    server_record_hash,
    type_define_event,
    validate_custom_event_type_name,
    validate_discourse_envelope,
    validate_event_against_registry,
    validate_pack_import,
    validate_room_create_payload,
    validate_room_path,
    verify_pack_digest,
    verify_server_record,
    verify_server_record_chain,
)
from agent_protocols import discourse
from agent_protocols.errors import AgentProtocolError
from agent_protocols.http_client import sse_events_url
from agent_protocols.identity import AgentSigner, create_event

PACKS_PATH = Path(__file__).resolve().parents[3] / "docs/protocols/agent-discourse/1.0.packs.json"
PACKS_DOCUMENT = json.loads(PACKS_PATH.read_text())
PACKS = pack_map(PACKS_DOCUMENT)
SCHEMA_PATH = Path(__file__).resolve().parents[3] / "docs/protocols/agent-discourse/1.0.schema.json"

FINDING_DEF = {
    "type": "review.finding",
    "kind": "message",
    "title": "Review finding",
    "schema": {
        "type": "object",
        "required": ["severity", "summary"],
        "properties": {
            "severity": {"type": "string", "enum": ["low", "medium", "high"]},
            "summary": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    },
}


class DiscourseTests(unittest.TestCase):
    def test_loads_registered_packs_document(self):
        self.assertEqual(PACKS_DOCUMENT["protocol"], "agent-discourse/1.0")
        self.assertEqual(len(PACKS), 5)
        self.assertIn(PACK_REACTIONS, PACKS)

    def test_validates_room_create_without_room_id(self):
        signer = AgentSigner.from_seed(bytes([14]) * 32)
        event = room_create_event(
            signer.agent_id(),
            100,
            1,
            {"topic": "Research room", "visibility": "public", "start_time": 1000, "end_time": 2000},
        )
        envelope = signer.sign_event(event)

        validate_discourse_envelope(envelope)
        validate_room_path(envelope, "d8ftedhpqhsusbg001tg")

    def test_rejects_room_create_with_room_id(self):
        signer = AgentSigner.from_seed(bytes([14]) * 32)
        event = room_create_event(
            signer.agent_id(),
            100,
            1,
            {"topic": "Research room", "visibility": "public", "start_time": 1000, "end_time": 2000},
        )
        event["room_id"] = "d8ftedhpqhsusbg001tg"
        envelope = signer.sign_event(event)

        with self.assertRaisesRegex(AgentProtocolError, "room_id"):
            validate_discourse_envelope(envelope)
        with self.assertRaisesRegex(AgentProtocolError, "room_id"):
            validate_room_path(envelope, "d8ftedhpqhsusbg001tg")

    def test_rejects_room_event_without_room_id(self):
        signer = AgentSigner.from_seed(bytes([15]) * 32)
        event = create_event(
            "agent-discourse/1.0",
            MESSAGE_CREATE,
            signer.agent_id(),
            100,
            1,
            {"content_type": "text/plain", "content": "hello"},
        )
        envelope = signer.sign_event(event)

        with self.assertRaises(AgentProtocolError):
            validate_discourse_envelope(envelope)

    def test_schema_requires_join_review_canonical_request(self):
        moderator = AgentSigner.from_seed(bytes([21]) * 32)
        applicant = AgentSigner.from_seed(bytes([22]) * 32)
        event = create_event(
            "agent-discourse/1.0",
            ROOM_JOIN_REVIEW,
            moderator.agent_id(),
            1_779_757_250_000,
            1,
            {
                "request": {
                    "id": "jr_01J8ZM7A3G2T9B4Q6X8R0N1P2Q",
                    "room_id": "d8ftedhpqhsusbg001tg",
                    "applicant": applicant.agent_id(),
                    "role": "speaker",
                    "perspective": "distributed-systems reviewer",
                    "reason": "I can cover replication and failure-mode tradeoffs.",
                    "created_at": 1_779_757_210_000,
                    "expires_at": 1_779_760_810_000,
                    "extra": {},
                },
                "decision": "approve",
                "role": "speaker",
                "reason": "relevant expertise",
            },
        )
        event["room_id"] = "d8ftedhpqhsusbg001tg"
        event["base_seq"] = 17
        event["base_hash"] = "GDt8oHZQfQ3jl5ZUfyNxKZu07yAJdDYuaw_jf_JjLYs"
        envelope = moderator.sign_event(event)
        validator = Draft202012Validator(json.loads(SCHEMA_PATH.read_text()))

        validator.validate(envelope)
        legacy = deepcopy(envelope)
        legacy["event"]["payload"]["member"] = applicant.agent_id()
        with self.assertRaises(ValidationError):
            validator.validate(legacy)
        legacy_with_request_id = deepcopy(envelope)
        legacy_with_request_id["event"]["payload"]["request_id"] = "jr_01J8ZM7A3G2T9B4Q6X8R0N1P2Q"
        with self.assertRaises(ValidationError):
            validator.validate(legacy_with_request_id)
        missing_request = deepcopy(envelope)
        del missing_request["event"]["payload"]["request"]
        with self.assertRaises(ValidationError):
            validator.validate(missing_request)

    def test_validates_custom_event_type_names(self):
        validate_custom_event_type_name("review.finding")
        validate_custom_event_type_name("poll.vote")
        for bad in ("freeform", "room.custom", "type.new", "message.create", "Bad.Name"):
            with self.assertRaises(AgentProtocolError):
                validate_custom_event_type_name(bad)

    def test_materializes_registry_from_packs_and_inline_defs(self):
        registry = TypeRegistry.from_declarations(
            [
                {"use": PACK_REACTIONS},
                {
                    "use": PACK_DELIBERATION,
                    "overrides": {"poll.vote": {"roles": ["moderator", "speaker", "observer"]}},
                },
                FINDING_DEF,
            ],
            PACKS,
        )

        self.assertEqual(len(registry), 6)
        self.assertIn("reaction.create", registry)
        self.assertIn("poll.create", registry)
        self.assertIn("review.finding", registry)
        self.assertEqual(registry.get("poll.vote")["roles"], ["moderator", "speaker", "observer"])

        subset = TypeRegistry.from_declarations(
            [{"use": PACK_DELIBERATION, "types": ["poll.create", "poll.vote"]}], PACKS
        )
        self.assertEqual(len(subset), 2)
        self.assertNotIn("question.create", subset)

    def test_rejects_bad_pack_imports(self):
        with self.assertRaisesRegex(AgentProtocolError, "pack"):
            TypeRegistry.from_declarations([{"use": "adp:unknown/1.0"}], PACKS)
        with self.assertRaisesRegex(AgentProtocolError, "override"):
            TypeRegistry.from_declarations(
                [{"use": PACK_REACTIONS, "overrides": {"poll.vote": {}}}], PACKS
            )
        with self.assertRaises(AgentProtocolError):
            validate_pack_import(
                {"use": PACK_REACTIONS, "pack": "https://example.com/p.json", "digest": "sha256:abc"}
            )

    def test_latest_type_definition_wins(self):
        registry = TypeRegistry()
        registry.define(dict(FINDING_DEF))
        registry.define({**FINDING_DEF, "status": "disabled"})
        self.assertEqual(registry.get("review.finding")["status"], "disabled")

    def test_validates_custom_payloads_against_pack_schemas(self):
        registry = TypeRegistry.from_declarations([{"use": PACK_DELIBERATION}], PACKS)
        event_hash = "GDt8oHZQfQ3jl5ZUfyNxKZu07yAJdDYuaw_jf_JjLYs"

        registry.validate_payload("poll.vote", {"poll_event_id": event_hash, "option_ids": ["a"]})
        with self.assertRaisesRegex(AgentProtocolError, "option_ids|required"):
            registry.validate_payload("poll.vote", {"poll_event_id": event_hash})
        with self.assertRaisesRegex(AgentProtocolError, "turn.update"):
            validate_event_against_registry("turn.update", {}, registry)

        disabled = TypeRegistry()
        disabled.define({**FINDING_DEF, "status": "disabled"})
        with self.assertRaisesRegex(AgentProtocolError, "disabled"):
            disabled.validate_payload("review.finding", {"severity": "high", "summary": "s"})

    def test_applies_kind_based_permissions(self):
        registry = TypeRegistry.from_declarations(
            [
                {"use": PACK_REACTIONS},
                {
                    "use": PACK_DELIBERATION,
                    "overrides": {"poll.vote": {"roles": ["moderator", "speaker", "observer"]}},
                },
                {"use": PACK_CURATION},
            ],
            PACKS,
        )

        observer = {"role": "observer"}
        speaker = {"role": "speaker"}
        moderator = {"role": "moderator"}
        creator = {"role": "observer", "is_creator": True}

        # signal kind: all members, including observers
        self.assertTrue(can_submit_event("reaction.create", observer, registry))
        # poll.vote default excludes observers, but this room overrode roles
        self.assertTrue(can_submit_event("poll.vote", observer, registry))
        # message kind: speakers and moderators only
        self.assertTrue(can_submit_event("resource.add", speaker, registry))
        self.assertFalse(can_submit_event("resource.add", observer, registry))
        # control kind: moderators only
        self.assertTrue(can_submit_event("graph.update", moderator, registry))
        self.assertFalse(can_submit_event("graph.update", speaker, registry))
        # creator passes every role check regardless of current role
        self.assertTrue(can_submit_event("graph.update", creator, registry))
        self.assertTrue(can_submit_event(MESSAGE_CREATE, creator, registry))
        # undefined types are rejected
        self.assertFalse(can_submit_event("session.offer", speaker, registry))

        # built-in lifecycle rules
        self.assertTrue(can_submit_event(ROOM_JOIN_REVIEW, moderator, registry))
        self.assertFalse(can_submit_event(ROOM_JOIN_REVIEW, speaker, registry))
        self.assertTrue(can_submit_event(ROOM_MEMBER_ROLE_UPDATE, moderator, registry))
        self.assertTrue(can_submit_event(ROOM_CANCEL, moderator, registry))
        self.assertTrue(can_submit_event(TYPE_DEFINE, moderator, registry))
        self.assertFalse(can_submit_event(TYPE_DEFINE, speaker, registry))
        self.assertTrue(can_submit_event(MESSAGE_CREATE, speaker, registry))
        self.assertFalse(can_submit_event(MESSAGE_CREATE, observer, registry))
        self.assertTrue(can_submit_event(ROOM_LEAVE, observer, registry))
        self.assertFalse(can_submit_event(ROOM_JOIN, observer, registry))
        self.assertTrue(can_submit_event(ROOM_JOIN, {"join_request_approved": True}, registry))
        self.assertTrue(can_submit_event(ROOM_CREATE, {}, registry))

    def test_applies_state_restrictions(self):
        speaker = {"role": "speaker"}
        moderator = {"role": "moderator"}

        self.assertTrue(can_accept_room_write(MESSAGE_CREATE, "active", speaker))
        self.assertFalse(can_accept_room_write(MESSAGE_CREATE, "scheduled", speaker))
        # scheduled allows pre-start setup: reviews, role updates, leave, type.define
        self.assertTrue(can_write_in_state(ROOM_JOIN_REVIEW, "scheduled"))
        self.assertTrue(can_write_in_state(ROOM_MEMBER_ROLE_UPDATE, "scheduled"))
        self.assertTrue(can_write_in_state(ROOM_LEAVE, "scheduled"))
        self.assertTrue(can_write_in_state(TYPE_DEFINE, "scheduled"))
        self.assertTrue(can_write_in_state(ROOM_CANCEL, "scheduled"))
        self.assertFalse(can_write_in_state(ROOM_CLOSE, "scheduled"))
        self.assertTrue(can_accept_room_write(TYPE_DEFINE, "scheduled", moderator))
        # ended rooms are strictly read-only
        self.assertFalse(can_write_in_state("reaction.create", "ended"))
        self.assertFalse(can_write_in_state(ROOM_LEAVE, "ended"))
        self.assertFalse(can_write_in_state(ROOM_JOIN, "cancelled"))
        # cancel only while scheduled, close only while active
        self.assertTrue(can_write_in_state(ROOM_CLOSE, "active"))
        self.assertFalse(can_write_in_state(ROOM_CANCEL, "active"))

    def test_validates_room_creation_payloads(self):
        validate_room_create_payload(
            {
                "topic": "Research room",
                "guidance": "Cite sources.",
                "visibility": "public",
                "start_time": 1000,
                "end_time": 2000,
                "policy": {"max_speakers": 2},
                "types": [{"use": PACK_REACTIONS}, FINDING_DEF],
            }
        )
        with self.assertRaises(AgentProtocolError):
            validate_room_create_payload({"topic": " ", "visibility": "public", "start_time": 1000, "end_time": 2000})
        with self.assertRaises(AgentProtocolError):
            validate_room_create_payload(
                {"topic": "Research room", "visibility": "public", "start_time": 2000, "end_time": 1000}
            )
        with self.assertRaisesRegex(AgentProtocolError, "max_speakers"):
            validate_room_create_payload(
                {
                    "topic": "Research room",
                    "visibility": "public",
                    "start_time": 1000,
                    "end_time": 2000,
                    "policy": {"max_speakers": 0},
                }
            )
        with self.assertRaisesRegex(AgentProtocolError, "reserved"):
            validate_room_create_payload(
                {
                    "topic": "Research room",
                    "visibility": "public",
                    "start_time": 1000,
                    "end_time": 2000,
                    "types": [{**FINDING_DEF, "type": "room.custom"}],
                }
            )

    def test_signs_and_validates_type_define_envelopes(self):
        signer = AgentSigner.from_seed(bytes([16]) * 32)
        event = type_define_event(
            signer.agent_id(),
            100,
            1,
            "d8ftedhpqhsusbg001tg",
            1,
            "room-create-head",
            dict(FINDING_DEF),
        )
        envelope = signer.sign_event(event)
        validate_discourse_envelope(envelope)

    def test_verifies_pack_digests(self):
        data = b"pack document bytes"
        digest = "sha256:" + urlsafe_b64encode(sha256(data).digest()).rstrip(b"=").decode()
        verify_pack_digest(data, digest)
        with self.assertRaisesRegex(AgentProtocolError, "digest"):
            verify_pack_digest(b"tampered", digest)
        with self.assertRaisesRegex(AgentProtocolError, "algorithm"):
            verify_pack_digest(data, "md5:abc")
        with self.assertRaisesRegex(AgentProtocolError, "format"):
            verify_pack_digest(data, "not-a-digest")

    def test_builds_and_verifies_server_record_chains(self):
        signer = AgentSigner.from_seed(bytes([18]) * 32)
        envelope1 = signer.sign_event(
            room_create_event(
                signer.agent_id(),
                100,
                1,
                {"topic": "Research room", "visibility": "public", "start_time": 1000, "end_time": 2000},
            )
        )
        record1 = build_server_record("room123", 1, None, 110, envelope1)
        event2 = create_event(
            "agent-discourse/1.0",
            MESSAGE_CREATE,
            signer.agent_id(),
            120,
            2,
            {"content_type": "text/plain", "content": "hello"},
        )
        event2["room_id"] = "room123"
        event2["base_seq"] = 1
        event2["base_hash"] = record1["hash"]
        envelope2 = signer.sign_event(event2)
        record2 = build_server_record("room123", 2, record1["hash"], 130, envelope2)

        self.assertEqual(record1["hash"], server_record_hash("room123", 1, None, envelope1["hash"], 110))
        verify_server_record(record1)
        verify_server_record_chain([record1, record2])
        self.assertEqual(len(archive_events_digest([record1, record2])), 43)
        with self.assertRaisesRegex(AgentProtocolError, "first seq"):
            verify_server_record_chain([record2])
        with self.assertRaises(AgentProtocolError):
            verify_server_record_chain([{**record2, "pre_hash": "bad"}])

    def test_builds_sse_event_stream_url(self):
        self.assertEqual(
            sse_events_url("https://api.example.com", "room123"),
            "https://api.example.com/v1/rooms/room123/events/live",
        )

class Revision20260704Tests(unittest.TestCase):
    def test_kernel_defines_eleven_builtins_with_membership_signals(self):
        self.assertEqual(len(discourse.BUILTIN_EVENT_TYPES), 11)
        self.assertIn("room.update", discourse.BUILTIN_EVENT_TYPES)
        self.assertIn("room.member.remove", discourse.BUILTIN_EVENT_TYPES)

        for membership in discourse.MEMBERSHIP_EVENT_TYPES:
            self.assertEqual(discourse.builtin_event_class(membership), "signal")
            self.assertFalse(discourse.event_advances_room_head(membership))
        for advancing in (
            discourse.ROOM_CREATE,
            discourse.ROOM_UPDATE,
            discourse.ROOM_CLOSE,
            discourse.ROOM_CANCEL,
            discourse.TYPE_DEFINE,
            discourse.MESSAGE_CREATE,
        ):
            self.assertTrue(discourse.event_advances_room_head(advancing))
        self.assertIsNone(discourse.builtin_event_class("review.finding"))

        registry = discourse.TypeRegistry()
        registry.define(
            {
                "type": "reaction.create",
                "kind": "signal",
                "title": "Reaction",
                "schema": {"type": "object"},
            }
        )
        self.assertFalse(discourse.event_advances_room_head("reaction.create", registry))
        self.assertTrue(discourse.event_advances_room_head("unknown.type", registry))

        self.assertIn("member_banned", discourse.DISCOURSE_ERROR_CODES)
        self.assertIn("role_not_allowed", discourse.DISCOURSE_ERROR_CODES)
        self.assertIn("max_speakers_exceeded", discourse.DISCOURSE_ERROR_CODES)

    def test_room_update_and_member_remove_follow_moderator_rules(self):
        for builtin in (discourse.ROOM_UPDATE, discourse.ROOM_MEMBER_REMOVE):
            self.assertTrue(discourse.can_submit_event(builtin, {"role": "moderator"}))
            self.assertTrue(discourse.can_submit_event(builtin, {"is_creator": True}))
            self.assertFalse(discourse.can_submit_event(builtin, {"role": "speaker"}))
            self.assertTrue(discourse.can_write_in_state(builtin, "scheduled"))
            self.assertTrue(discourse.can_write_in_state(builtin, "active"))
            self.assertFalse(discourse.can_write_in_state(builtin, "ended"))
            self.assertFalse(discourse.can_write_in_state(builtin, "cancelled"))

    def test_validates_room_update_payloads(self):
        discourse.validate_room_update_payload(
            {"topic": "New topic", "guidance": "", "end_time": 2000}
        )
        with self.assertRaisesRegex(AgentProtocolError, "must not be empty"):
            discourse.validate_room_update_payload({})
        with self.assertRaisesRegex(AgentProtocolError, "not updatable"):
            discourse.validate_room_update_payload({"visibility": "private"})
        with self.assertRaisesRegex(AgentProtocolError, "topic"):
            discourse.validate_room_update_payload({"topic": "  "})
        with self.assertRaisesRegex(AgentProtocolError, "before end_time"):
            discourse.validate_room_update_payload({"start_time": 5, "end_time": 5})
        with self.assertRaisesRegex(AgentProtocolError, "max_speakers"):
            discourse.validate_room_update_payload({"policy": {"max_speakers": 0}})

    def test_validates_room_member_remove_payloads(self):
        member = AgentSigner.from_seed(bytes([41]) * 32).agent_id()
        discourse.validate_room_member_remove_payload({"member": member})
        discourse.validate_room_member_remove_payload({"member": member, "ban": True})
        with self.assertRaises(AgentProtocolError):
            discourse.validate_room_member_remove_payload({"member": "not-an-id"})
        with self.assertRaisesRegex(AgentProtocolError, "ban must be a boolean"):
            discourse.validate_room_member_remove_payload({"member": member, "ban": "yes"})

    def test_mentions_are_capped_at_32_unique_agent_ids(self):
        signer = AgentSigner.from_seed(bytes([42]) * 32)
        others = [AgentSigner.from_seed(bytes([100 + index]) * 32).agent_id() for index in range(33)]

        def envelope_with(mentions):
            event = discourse_event(
                MESSAGE_CREATE,
                signer.agent_id(),
                100,
                1,
                "room1",
                1,
                "room-create-head",
                {"content_type": "text/plain", "content": "hi"},
            )
            event["mentions"] = mentions
            return signer.sign_event(event)

        validate_discourse_envelope(envelope_with(others[:32]))
        with self.assertRaisesRegex(AgentProtocolError, "must not exceed 32"):
            validate_discourse_envelope(envelope_with(others))
        with self.assertRaisesRegex(AgentProtocolError, "unique"):
            validate_discourse_envelope(envelope_with([others[0], others[0]]))
        # A non-string mention yields a clean protocol error, not a raw
        # TypeError from set() hashing.
        with self.assertRaises(AgentProtocolError):
            validate_discourse_envelope(envelope_with([{"not": "a string"}]))

    def test_type_redefinition_cannot_change_kind(self):
        definition = {
            "type": "review.finding",
            "kind": "message",
            "title": "Finding",
            "schema": {"type": "object"},
        }
        registry = discourse.TypeRegistry()
        registry.define(definition)
        registry.define({**definition, "title": "Finding v2"})
        self.assertEqual(registry.get("review.finding")["title"], "Finding v2")
        with self.assertRaisesRegex(AgentProtocolError, "cannot change kind"):
            registry.define({**definition, "kind": "signal"})


if __name__ == "__main__":
    unittest.main()
