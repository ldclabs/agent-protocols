import assert from "node:assert/strict";
import test from "node:test";

import { AgentSigner, createEvent } from "./identity.js";
import {
  canAcceptRoomWrite,
  canSubmitEvent,
  eventType,
  roomCreateEvent,
  validateDiscourseEnvelope,
} from "./discourse.js";

test("validates room.create without room_id", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(14));
  const event = roomCreateEvent(signer.agentId(), 100, "n_room", {
    topic: "Research room",
    visibility: "public",
    start_time: 1000,
    end_time: 2000,
  });
  const envelope = signer.signEvent(event);

  assert.doesNotThrow(() => validateDiscourseEnvelope(envelope));
});

test("rejects room events without room_id", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(15));
  const event = createEvent(
    "agent-discourse/1.0",
    eventType.MESSAGE_TEXT,
    signer.agentId(),
    100,
    "n_message",
    { text: "hello" },
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
    canSubmitEvent(eventType.MESSAGE_TEXT, { role: "observer" }),
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
    canAcceptRoomWrite(eventType.MESSAGE_TEXT, "active", {
      role: "participant",
    }),
    true,
  );
  assert.equal(
    canAcceptRoomWrite(eventType.MESSAGE_TEXT, "scheduled", {
      role: "participant",
    }),
    false,
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
