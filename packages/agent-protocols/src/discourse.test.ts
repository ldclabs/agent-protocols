import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

import { AgentSigner, createEvent } from "./identity.js";
import {
  PackDocument,
  PermissionContext,
  RoomJoinReviewPayload,
  TypeDef,
  TypeRegistry,
  archiveEventsDigest,
  buildServerRecord,
  canAcceptRoomWrite,
  canSubmitEvent,
  canWriteInState,
  eventType,
  packId,
  packMap,
  roomCreateEvent,
  serverRecordHash,
  typeDefineEvent,
  validateCustomEventTypeName,
  validateDiscourseEnvelope,
  validateEventAgainstRegistry,
  validatePackImport,
  validateRoomCreatePayload,
  validateRoomPath,
  verifyPackDigest,
  verifyServerRecord,
  verifyServerRecordChain,
} from "./discourse.js";
import { sseEventsUrl } from "./http-client.js";

const packsDocument = JSON.parse(
  readFileSync(
    new URL(
      "../../../docs/protocols/agent-discourse/1.0.packs.json",
      import.meta.url,
    ),
    "utf8",
  ),
) as PackDocument;
const packs = packMap(packsDocument);

const findingDef: TypeDef = {
  type: "review.finding",
  kind: "message",
  title: "Review finding",
  schema: {
    type: "object",
    required: ["severity", "summary"],
    properties: {
      severity: { type: "string", enum: ["low", "medium", "high"] },
      summary: { type: "string", minLength: 1 },
    },
    additionalProperties: false,
  },
};

test("loads the registered packs document", () => {
  assert.equal(packsDocument.protocol, "agent-discourse/1.0");
  assert.deepEqual(Object.keys(packs).sort(), [
    packId.CURATION,
    packId.DELIBERATION,
    packId.MODERATION,
    packId.REACTIONS,
    packId.REALTIME,
  ].sort());
});

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

test("rejects room.create with room_id", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(14));
  const event = roomCreateEvent(signer.agentId(), 100, 1, {
    topic: "Research room",
    visibility: "public",
    start_time: 1000,
    end_time: 2000,
  });
  event.room_id = "d8ftedhpqhsusbg001tg";
  const envelope = signer.signEvent(event);

  assert.throws(() => validateDiscourseEnvelope(envelope), /room_id/);
  assert.throws(() => validateRoomPath(envelope, "d8ftedhpqhsusbg001tg"), /room_id/);
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

test("validates room.join.review envelopes with canonical requests", () => {
  const moderator = AgentSigner.fromSeed(new Uint8Array(32).fill(21));
  const applicant = AgentSigner.fromSeed(new Uint8Array(32).fill(22));
  const payload: RoomJoinReviewPayload = {
    request: {
      id: "jr_01J8ZM7A3G2T9B4Q6X8R0N1P2Q",
      room_id: "d8ftedhpqhsusbg001tg",
      applicant: applicant.agentId(),
      role: "speaker",
      perspective: "distributed-systems reviewer",
      reason: "I can cover replication and failure-mode tradeoffs.",
      created_at: 1_779_757_210_000,
      expires_at: 1_779_760_810_000,
      extra: {},
    },
    decision: "approve",
    role: "speaker",
    reason: "relevant expertise",
  };
  const event = createEvent(
    "agent-discourse/1.0",
    eventType.ROOM_JOIN_REVIEW,
    moderator.agentId(),
    1_779_757_250_000,
    1,
    payload,
  );
  event.room_id = "d8ftedhpqhsusbg001tg";
  const envelope = moderator.signEvent(event);

  assert.doesNotThrow(() => validateDiscourseEnvelope(envelope));
  assert.equal(envelope.event.payload.request.applicant, applicant.agentId());
  assert.equal(envelope.event.payload.request.role, "speaker");
  assert.equal("member" in envelope.event.payload, false);
});

test("validates custom event type names", () => {
  assert.doesNotThrow(() => validateCustomEventTypeName("review.finding"));
  assert.doesNotThrow(() => validateCustomEventTypeName("poll.vote"));
  assert.throws(() => validateCustomEventTypeName("freeform"));
  assert.throws(() => validateCustomEventTypeName("room.custom"));
  assert.throws(() => validateCustomEventTypeName("type.new"));
  assert.throws(() => validateCustomEventTypeName("message.create"));
  assert.throws(() => validateCustomEventTypeName("Bad.Name"));
});

test("materializes a type registry from packs and inline defs", () => {
  const registry = TypeRegistry.fromDeclarations(
    [
      { use: packId.REACTIONS },
      {
        use: packId.DELIBERATION,
        overrides: {
          "poll.vote": { roles: ["moderator", "speaker", "observer"] },
        },
      },
      findingDef,
    ],
    packs,
  );

  assert.equal(registry.size, 6);
  assert.ok(registry.has("reaction.create"));
  assert.ok(registry.has("poll.create"));
  assert.ok(registry.has("review.finding"));
  assert.deepEqual(registry.get("poll.vote")?.roles, [
    "moderator",
    "speaker",
    "observer",
  ]);

  const subset = TypeRegistry.fromDeclarations(
    [{ use: packId.DELIBERATION, types: ["poll.create", "poll.vote"] }],
    packs,
  );
  assert.equal(subset.size, 2);
  assert.ok(!subset.has("question.create"));
});

test("rejects bad pack imports", () => {
  assert.throws(
    () => TypeRegistry.fromDeclarations([{ use: "adp:unknown/1.0" }], packs),
    /pack/,
  );
  assert.throws(
    () =>
      TypeRegistry.fromDeclarations(
        [{ use: packId.REACTIONS, overrides: { "poll.vote": {} } }],
        packs,
      ),
    /override/,
  );
  assert.throws(() =>
    validatePackImport({
      use: packId.REACTIONS,
      pack: "https://example.com/p.json",
      digest: "sha256:abc",
    }),
  );
});

test("latest type definition wins", () => {
  const registry = new TypeRegistry();
  registry.define(findingDef);
  registry.define({ ...findingDef, status: "disabled" });
  assert.equal(registry.get("review.finding")?.status, "disabled");
});

test("validates custom payloads against pack schemas", () => {
  const registry = TypeRegistry.fromDeclarations(
    [{ use: packId.DELIBERATION }],
    packs,
  );
  const hash = "GDt8oHZQfQ3jl5ZUfyNxKZu07yAJdDYuaw_jf_JjLYs";

  assert.doesNotThrow(() =>
    registry.validatePayload("poll.vote", {
      poll_event_id: hash,
      option_ids: ["a"],
    }),
  );
  assert.throws(
    () => registry.validatePayload("poll.vote", { poll_event_id: hash }),
    /option_ids|required/,
  );
  assert.throws(
    () => validateEventAgainstRegistry("turn.update", {}, registry),
    /turn.update/,
  );

  const disabled = new TypeRegistry();
  disabled.define({ ...findingDef, status: "disabled" });
  assert.throws(
    () =>
      disabled.validatePayload("review.finding", {
        severity: "high",
        summary: "s",
      }),
    /review.finding/,
  );
});

test("applies kind-based permissions", () => {
  const registry = TypeRegistry.fromDeclarations(
    [
      { use: packId.REACTIONS },
      {
        use: packId.DELIBERATION,
        overrides: {
          "poll.vote": { roles: ["moderator", "speaker", "observer"] },
        },
      },
      { use: packId.CURATION },
    ],
    packs,
  );

  const observer: PermissionContext = { role: "observer" };
  const speaker: PermissionContext = { role: "speaker" };
  const moderator: PermissionContext = { role: "moderator" };
  const creator: PermissionContext = { role: "observer", isCreator: true };

  // signal kind: all members, including observers
  assert.equal(canSubmitEvent("reaction.create", observer, registry), true);
  // poll.vote default excludes observers, but this room overrode roles
  assert.equal(canSubmitEvent("poll.vote", observer, registry), true);
  // message kind: speakers and moderators only
  assert.equal(canSubmitEvent("resource.add", speaker, registry), true);
  assert.equal(canSubmitEvent("resource.add", observer, registry), false);
  // control kind: moderators only
  assert.equal(canSubmitEvent("graph.update", moderator, registry), true);
  assert.equal(canSubmitEvent("graph.update", speaker, registry), false);
  // creator passes every role check regardless of current role
  assert.equal(canSubmitEvent("graph.update", creator, registry), true);
  assert.equal(canSubmitEvent(eventType.MESSAGE_CREATE, creator, registry), true);
  // undefined types are rejected
  assert.equal(canSubmitEvent("session.offer", speaker, registry), false);

  // built-in lifecycle rules
  assert.equal(canSubmitEvent(eventType.ROOM_JOIN_REVIEW, moderator, registry), true);
  assert.equal(canSubmitEvent(eventType.ROOM_JOIN_REVIEW, speaker, registry), false);
  assert.equal(
    canSubmitEvent(eventType.ROOM_MEMBER_ROLE_UPDATE, moderator, registry),
    true,
  );
  assert.equal(canSubmitEvent(eventType.ROOM_CANCEL, moderator, registry), true);
  assert.equal(canSubmitEvent(eventType.TYPE_DEFINE, moderator, registry), true);
  assert.equal(canSubmitEvent(eventType.TYPE_DEFINE, speaker, registry), false);
  assert.equal(canSubmitEvent(eventType.MESSAGE_CREATE, speaker, registry), true);
  assert.equal(canSubmitEvent(eventType.MESSAGE_CREATE, observer, registry), false);
  assert.equal(canSubmitEvent(eventType.ROOM_LEAVE, observer, registry), true);
  assert.equal(canSubmitEvent(eventType.ROOM_JOIN, observer, registry), false);
  assert.equal(
    canSubmitEvent(eventType.ROOM_JOIN, { joinRequestApproved: true }, registry),
    true,
  );
});

test("applies state restrictions", () => {
  const speaker: PermissionContext = { role: "speaker" };
  const moderator: PermissionContext = { role: "moderator" };

  assert.equal(
    canAcceptRoomWrite(eventType.MESSAGE_CREATE, "active", speaker),
    true,
  );
  assert.equal(
    canAcceptRoomWrite(eventType.MESSAGE_CREATE, "scheduled", speaker),
    false,
  );
  // scheduled allows pre-start setup: reviews, role updates, leave, type.define
  assert.equal(canWriteInState(eventType.ROOM_JOIN_REVIEW, "scheduled"), true);
  assert.equal(
    canWriteInState(eventType.ROOM_MEMBER_ROLE_UPDATE, "scheduled"),
    true,
  );
  assert.equal(canWriteInState(eventType.ROOM_LEAVE, "scheduled"), true);
  assert.equal(canWriteInState(eventType.TYPE_DEFINE, "scheduled"), true);
  assert.equal(canWriteInState(eventType.ROOM_CANCEL, "scheduled"), true);
  assert.equal(canWriteInState(eventType.ROOM_CLOSE, "scheduled"), false);
  assert.equal(
    canAcceptRoomWrite(eventType.TYPE_DEFINE, "scheduled", moderator),
    true,
  );
  // ended rooms are strictly read-only
  assert.equal(canWriteInState("reaction.create", "ended"), false);
  assert.equal(canWriteInState(eventType.ROOM_LEAVE, "ended"), false);
  assert.equal(canWriteInState(eventType.ROOM_JOIN, "cancelled"), false);
  // cancel only while scheduled, close only while active
  assert.equal(canWriteInState(eventType.ROOM_CLOSE, "active"), true);
  assert.equal(canWriteInState(eventType.ROOM_CANCEL, "active"), false);
});

test("validates room creation payloads", () => {
  assert.doesNotThrow(() =>
    validateRoomCreatePayload({
      topic: "Research room",
      guidance: "Cite sources.",
      visibility: "public",
      start_time: 1000,
      end_time: 2000,
      policy: { max_speakers: 2 },
      types: [{ use: packId.REACTIONS }, findingDef],
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
  assert.throws(
    () =>
      validateRoomCreatePayload({
        topic: "Research room",
        visibility: "public",
        start_time: 1000,
        end_time: 2000,
        policy: { max_speakers: 0 },
      }),
    /max_speakers/,
  );
  assert.throws(
    () =>
      validateRoomCreatePayload({
        topic: "Research room",
        visibility: "public",
        start_time: 1000,
        end_time: 2000,
        types: [{ ...findingDef, type: "room.custom" }],
      }),
    /reserved/,
  );
});

test("signs and validates type.define envelopes", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(16));
  const event = typeDefineEvent(
    signer.agentId(),
    100,
    1,
    "d8ftedhpqhsusbg001tg",
    findingDef,
  );
  const envelope = signer.signEvent(event);
  assert.doesNotThrow(() => validateDiscourseEnvelope(envelope));
});

test("verifies pack digests", () => {
  const bytes = new TextEncoder().encode("pack document bytes");
  const expected = `sha256:${createHash("sha256").update(bytes).digest("base64url")}`;
  assert.doesNotThrow(() => verifyPackDigest(bytes, expected));
  assert.throws(
    () => verifyPackDigest(new TextEncoder().encode("tampered"), expected),
    /digest/,
  );
  assert.throws(() => verifyPackDigest(bytes, "md5:abc"), /algorithm/);
  assert.throws(() => verifyPackDigest(bytes, "not-a-digest"), /format/);
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

test("builds SSE event stream URLs", () => {
  assert.equal(
    sseEventsUrl("https://api.example.com", "room123"),
    "https://api.example.com/v1/rooms/room123/events/live",
  );
});
