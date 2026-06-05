import unittest

from agent_protocols.discourse import (
    MESSAGE_CREATE,
    REACTION_CREATE,
    ROOM_CANCEL,
    ROOM_CREATE,
    ROOM_JOIN,
    ROOM_JOIN_REVIEW,
    SESSION_CANDIDATE,
    SESSION_OFFER,
    archive_events_digest,
    build_server_record,
    can_accept_room_write,
    can_submit_event,
    room_create_event,
    server_record_hash,
    validate_poll_create_payload,
    validate_poll_vote_payload,
    validate_discourse_envelope,
    validate_room_create_payload,
    validate_room_path,
    validate_session_answer_payload,
    validate_session_candidate_payload,
    validate_session_offer_payload,
    verify_server_record,
    verify_server_record_chain,
)
from agent_protocols.http_client import websocket_events_url
from agent_protocols.identity import AgentSigner, create_event


class DiscourseTests(unittest.TestCase):
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

        with self.assertRaises(Exception):
            validate_discourse_envelope(envelope)

    def test_applies_permission_matrix(self):
        self.assertTrue(can_submit_event(REACTION_CREATE, {"role": "observer"}))
        self.assertFalse(can_submit_event(MESSAGE_CREATE, {"role": "observer"}))
        self.assertFalse(can_submit_event(ROOM_JOIN, {"role": "observer"}))
        self.assertTrue(can_submit_event(ROOM_JOIN, {"join_request_approved": True}))
        self.assertTrue(can_submit_event(ROOM_JOIN_REVIEW, {"role": "moderator"}))
        self.assertFalse(can_submit_event(ROOM_JOIN_REVIEW, {"role": "participant"}))
        self.assertFalse(can_submit_event(ROOM_CANCEL, {"role": "moderator"}))
        self.assertTrue(can_submit_event(ROOM_CANCEL, {"role": "moderator", "moderator_authorized": True}))
        self.assertTrue(can_submit_event(SESSION_OFFER, {"role": "participant"}))
        self.assertFalse(can_submit_event(SESSION_CANDIDATE, {"role": "observer"}))
        self.assertTrue(can_submit_event(ROOM_CREATE, {}))

    def test_applies_state_restrictions(self):
        self.assertTrue(can_accept_room_write(MESSAGE_CREATE, "active", {"role": "participant"}))
        self.assertFalse(can_accept_room_write(MESSAGE_CREATE, "scheduled", {"role": "participant"}))
        self.assertTrue(can_accept_room_write(ROOM_JOIN_REVIEW, "scheduled", {"role": "moderator"}))
        self.assertTrue(can_accept_room_write(ROOM_JOIN, "scheduled", {"join_request_approved": True}))
        self.assertFalse(can_accept_room_write(REACTION_CREATE, "ended", {"role": "participant"}))
        self.assertTrue(can_accept_room_write(REACTION_CREATE, "ended", {"role": "participant"}, post_end_reaction_allowed=True))

    def test_validates_room_creation_payloads(self):
        validate_room_create_payload(
            {
                "topic": "Research room",
                "visibility": "public",
                "start_time": 1000,
                "end_time": 2000,
                "policy": {"max_participants": 2},
            }
        )
        with self.assertRaises(Exception):
            validate_room_create_payload({"topic": " ", "visibility": "public", "start_time": 1000, "end_time": 2000})
        with self.assertRaises(Exception):
            validate_room_create_payload(
                {"topic": "Research room", "visibility": "public", "start_time": 2000, "end_time": 1000}
            )

    def test_validates_poll_payloads_and_votes(self):
        poll = {
            "poll_id": "poll_review_order",
            "question": "Which review order?",
            "options": [{"id": "a", "label": "Correctness first"}, {"id": "b", "label": "Security first"}],
            "min_choices": 1,
            "max_choices": 1,
        }

        validate_poll_create_payload(poll)
        validate_poll_vote_payload({"event_id": "evt", "option_ids": ["a"]}, poll)
        with self.assertRaises(Exception):
            validate_poll_vote_payload({"event_id": "evt", "option_ids": ["a", "b"]}, poll)
        with self.assertRaises(Exception):
            validate_poll_create_payload(
                {
                    **poll,
                    "options": [{"id": "a", "label": "Correctness first"}, {"id": "a", "label": "Duplicate"}],
                }
            )

    def test_validates_webrtc_session_payloads(self):
        offer = {
            "session_id": "sess_live_review",
            "session_type": "webrtc",
            "media": ["audio", "video", "file"],
            "description": {"type": "offer", "sdp": "v=0\r\n..."},
            "transfers": [
                {
                    "transfer_id": "file_1",
                    "file_name": "trace.har",
                    "size_bytes": 1024,
                    "mime_type": "application/json",
                    "content_digest": "sha256:abc",
                }
            ],
        }

        validate_session_offer_payload(offer)
        validate_session_answer_payload(
            {
                "session_id": "sess_live_review",
                "offer_event_id": "evt_offer",
                "description": {"type": "answer", "sdp": "v=0\r\n..."},
                "accepted_media": ["audio", "file"],
            }
        )
        validate_session_candidate_payload(
            {
                "session_id": "sess_live_review",
                "candidate": {"candidate": "candidate:1 1 udp 1 127.0.0.1 3478 typ host"},
            }
        )
        validate_session_candidate_payload({"session_id": "sess_live_review", "end_of_candidates": True})

        with self.assertRaisesRegex(Exception, "offer"):
            validate_session_offer_payload({**offer, "description": {"type": "answer", "sdp": "v=0\r\n..."}})
        with self.assertRaisesRegex(Exception, "candidate"):
            validate_session_candidate_payload({"session_id": "sess_live_review"})

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
        envelope2 = signer.sign_event(event2)
        record2 = build_server_record("room123", 2, record1["hash"], 130, envelope2)

        self.assertEqual(record1["hash"], server_record_hash("room123", 1, None, envelope1["hash"], 110))
        verify_server_record(record1)
        verify_server_record_chain([record1, record2])
        self.assertEqual(len(archive_events_digest([record1, record2])), 43)
        with self.assertRaisesRegex(Exception, "first seq"):
            verify_server_record_chain([record2])
        with self.assertRaises(Exception):
            verify_server_record_chain([{**record2, "pre_hash": "bad"}])

    def test_builds_websocket_event_stream_url(self):
        self.assertEqual(
            websocket_events_url("https://api.example.com", "room123", "jwt.token"),
            "wss://api.example.com/v1/rooms/room123/events/live?access_token=jwt.token",
        )


if __name__ == "__main__":
    unittest.main()
