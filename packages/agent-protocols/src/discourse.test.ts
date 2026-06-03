import assert from "node:assert/strict";
import test from "node:test";

import { AgentSigner, createEvent } from "./identity.js";
import {
  canAcceptRoomWrite,
  canSubmitEvent,
  eventType,
  roomCreateEvent,
  validateDiscourseEnvelope,
  validateRoomPath,
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

test("builds websocket event stream URLs", () => {
  assert.equal(
    websocketEventsUrl("https://api.example.com", "room123", "jwt.token"),
    "wss://api.example.com/v1/rooms/room123/events/live?access_token=jwt.token",
  );
});
