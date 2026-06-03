import unittest

from agent_protocols.discourse import (
    MESSAGE_CREATE,
    REACTION_CREATE,
    ROOM_CANCEL,
    ROOM_CREATE,
    ROOM_JOIN,
    ROOM_JOIN_REVIEW,
    can_accept_room_write,
    can_submit_event,
    room_create_event,
    validate_discourse_envelope,
    validate_room_path,
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
        self.assertTrue(can_submit_event(ROOM_CREATE, {}))

    def test_applies_state_restrictions(self):
        self.assertTrue(can_accept_room_write(MESSAGE_CREATE, "active", {"role": "participant"}))
        self.assertFalse(can_accept_room_write(MESSAGE_CREATE, "scheduled", {"role": "participant"}))
        self.assertTrue(can_accept_room_write(ROOM_JOIN_REVIEW, "scheduled", {"role": "moderator"}))
        self.assertTrue(can_accept_room_write(ROOM_JOIN, "scheduled", {"join_request_approved": True}))
        self.assertFalse(can_accept_room_write(REACTION_CREATE, "ended", {"role": "participant"}))
        self.assertTrue(can_accept_room_write(REACTION_CREATE, "ended", {"role": "participant"}, post_end_reaction_allowed=True))

    def test_builds_websocket_event_stream_url(self):
        self.assertEqual(
            websocket_events_url("https://api.example.com", "room123", "jwt.token"),
            "wss://api.example.com/v1/rooms/room123/events/live?access_token=jwt.token",
        )


if __name__ == "__main__":
    unittest.main()
