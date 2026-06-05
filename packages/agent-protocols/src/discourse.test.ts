import assert from "node:assert/strict";
import test from "node:test";

import { AgentSigner, createEvent } from "./identity.js";
import {
  archiveEventsDigest,
  buildServerRecord,
  canAcceptRoomWrite,
  canSubmitEvent,
  eventType,
  roomCreateEvent,
  serverRecordHash,
  validatePollCreatePayload,
  validatePollVotePayload,
  validateDiscourseEnvelope,
  validateRoomCreatePayload,
  validateRoomPath,
  validateSessionAnswerPayload,
  validateSessionCandidatePayload,
  validateSessionOfferPayload,
  verifyServerRecord,
  verifyServerRecordChain,
} from "./discourse.js";
import { websocketEventsUrl } from "./http-client.js";

test("validates room.create without room_id", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(14));
  const event = roomCreateEvent(signer.agentId(), 100, 1, {
    topic: "Research room",
    visibility: "public",
    start_time: 1000,
    end_time: 2000,
  });
  const envelope = signer.signEvent(event);

  assert.doesNotThrow(() => validateDiscourseEnvelope(envelope));
  assert.doesNotThrow(() => validateRoomPath(envelope, "d8ftedhpqhsusbg001tg"));
});

test("rejects room events without room_id", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(15));
  const event = createEvent(
    "agent-discourse/1.0",
    eventType.MESSAGE_CREATE,
    signer.agentId(),
    100,
    1,
    { content_type: "text/plain", content: "hello" },
  );
  const envelope = signer.signEvent(event);

  assert.throws(() => validateDiscourseEnvelope(envelope), /room_id/);
});

test("applies permission matrix", () => {
  assert.equal(
    canSubmitEvent(eventType.REACTION_CREATE, { role: "observer" }),
    true,
  );
  assert.equal(
    canSubmitEvent(eventType.MESSAGE_CREATE, { role: "observer" }),
    false,
  );
  assert.equal(
    canSubmitEvent(eventType.ROOM_JOIN, { role: "observer" }),
    false,
  );
  assert.equal(
    canSubmitEvent(eventType.ROOM_JOIN, { joinRequestApproved: true }),
    true,
  );
  assert.equal(
    canSubmitEvent(eventType.ROOM_JOIN_REVIEW, { role: "moderator" }),
    true,
  );
  assert.equal(
    canSubmitEvent(eventType.ROOM_JOIN_REVIEW, { role: "participant" }),
    false,
  );
  assert.equal(
    canSubmitEvent(eventType.ROOM_CANCEL, { role: "moderator" }),
    false,
  );
  assert.equal(
    canSubmitEvent(eventType.ROOM_CANCEL, {
      role: "moderator",
      moderatorAuthorized: true,
    }),
    true,
  );
  assert.equal(
    canSubmitEvent(eventType.SESSION_OFFER, { role: "participant" }),
    true,
  );
  assert.equal(
    canSubmitEvent(eventType.SESSION_CANDIDATE, { role: "observer" }),
    false,
  );
});

test("applies state restrictions", () => {
  assert.equal(
    canAcceptRoomWrite(eventType.MESSAGE_CREATE, "active", {
      role: "participant",
    }),
    true,
  );
  assert.equal(
    canAcceptRoomWrite(eventType.MESSAGE_CREATE, "scheduled", {
      role: "participant",
    }),
    false,
  );
  assert.equal(
    canAcceptRoomWrite(eventType.ROOM_JOIN_REVIEW, "scheduled", {
      role: "moderator",
    }),
    true,
  );
  assert.equal(
    canAcceptRoomWrite(eventType.ROOM_JOIN, "scheduled", {
      joinRequestApproved: true,
    }),
    true,
  );
  assert.equal(
    canAcceptRoomWrite(eventType.REACTION_CREATE, "ended", {
      role: "participant",
    }),
    false,
  );
  assert.equal(
    canAcceptRoomWrite(
      eventType.REACTION_CREATE,
      "ended",
      { role: "participant" },
      { postEndReactionAllowed: true },
    ),
    true,
  );
});

test("validates room creation payloads", () => {
  assert.doesNotThrow(() =>
    validateRoomCreatePayload({
      topic: "Research room",
      visibility: "public",
      start_time: 1000,
      end_time: 2000,
      policy: { max_participants: 2 },
    }),
  );
  assert.throws(
    () =>
      validateRoomCreatePayload({
        topic: " ",
        visibility: "public",
        start_time: 1000,
        end_time: 2000,
      }),
    /topic/,
  );
  assert.throws(
    () =>
      validateRoomCreatePayload({
        topic: "Research room",
        visibility: "public",
        start_time: 2000,
        end_time: 1000,
      }),
    /start_time/,
  );
});

test("validates poll payloads and votes", () => {
  const poll = {
    poll_id: "poll_review_order",
    question: "Which review order?",
    options: [
      { id: "a", label: "Correctness first" },
      { id: "b", label: "Security first" },
    ],
    min_choices: 1,
    max_choices: 1,
  };

  assert.doesNotThrow(() => validatePollCreatePayload(poll));
  assert.doesNotThrow(() =>
    validatePollVotePayload({ event_id: "evt", option_ids: ["a"] }, poll),
  );
  assert.throws(
    () =>
      validatePollVotePayload({ event_id: "evt", option_ids: ["a", "b"] }, poll),
    /options/,
  );
  assert.throws(
    () =>
      validatePollCreatePayload({
        ...poll,
        options: [
          { id: "a", label: "Correctness first" },
          { id: "a", label: "Duplicate" },
        ],
      }),
    /unique/,
  );
});

test("validates WebRTC session payloads", () => {
  const offer = {
    session_id: "sess_live_review",
    session_type: "webrtc" as const,
    media: ["audio", "video", "file"] as const,
    description: { type: "offer" as const, sdp: "v=0\r\n..." },
    transfers: [
      {
        transfer_id: "file_1",
        file_name: "trace.har",
        size_bytes: 1024,
        mime_type: "application/json",
        content_digest: "sha256:abc",
      },
    ],
  };
  assert.doesNotThrow(() => validateSessionOfferPayload(offer));
  assert.doesNotThrow(() =>
    validateSessionAnswerPayload({
      session_id: "sess_live_review",
      offer_event_id: "evt_offer",
      description: { type: "answer", sdp: "v=0\r\n..." },
      accepted_media: ["audio", "file"],
    }),
  );
  assert.doesNotThrow(() =>
    validateSessionCandidatePayload({
      session_id: "sess_live_review",
      candidate: { candidate: "candidate:1 1 udp 1 127.0.0.1 3478 typ host" },
    }),
  );
  assert.doesNotThrow(() =>
    validateSessionCandidatePayload({
      session_id: "sess_live_review",
      end_of_candidates: true,
    }),
  );

  assert.throws(
    () =>
      validateSessionOfferPayload({
        ...offer,
        description: { type: "answer", sdp: "v=0\r\n..." },
      }),
    /offer/,
  );
  assert.throws(
    () =>
      validateSessionCandidatePayload({
        session_id: "sess_live_review",
      }),
    /candidate/,
  );
});

test("builds and verifies server record chains", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(18));
  const envelope1 = signer.signEvent(
    roomCreateEvent(signer.agentId(), 100, 1, {
      topic: "Research room",
      visibility: "public",
      start_time: 1000,
      end_time: 2000,
    }),
  );
  const record1 = buildServerRecord("room123", 1, null, 110, envelope1);
  const envelope2 = signer.signEvent(
    createEvent(
      "agent-discourse/1.0",
      eventType.MESSAGE_CREATE,
      signer.agentId(),
      120,
      2,
      { content_type: "text/plain", content: "hello" },
    ),
  );
  envelope2.event.room_id = "room123";
  const record2 = buildServerRecord(
    "room123",
    2,
    record1.hash,
    130,
    envelope2,
  );

  assert.equal(
    record1.hash,
    serverRecordHash("room123", 1, null, envelope1.hash, 110),
  );
  assert.doesNotThrow(() => verifyServerRecord(record1));
  assert.doesNotThrow(() => verifyServerRecordChain([record1, record2]));
  assert.equal(archiveEventsDigest([record1, record2]).length, 43);
  assert.throws(() => verifyServerRecordChain([record2]), /first seq/);
  assert.throws(
    () => verifyServerRecordChain([{ ...record2, pre_hash: "bad" }]),
    /hash|chain/,
  );
});

test("builds websocket event stream URLs", () => {
  assert.equal(
    websocketEventsUrl("https://api.example.com", "room123", "jwt.token"),
    "wss://api.example.com/v1/rooms/room123/events/live?access_token=jwt.token",
  );
});
