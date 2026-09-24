import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

import { AgentSigner, createEvent } from "./identity.js";
import * as discourse from "./discourse.js";
import {
  PackDocument,
  PermissionContext,
  RoomCreatePayload,
  RoomJoinReviewPayload,
  TypeDef,
  TypeRegistry,
  buildServerRecord,
  canAcceptRoomWrite,
  canJoinDirectly,
  canSubmitEvent,
  canWriteInState,
  effectiveOpenRoles,
  eventRequiresRoomHead,
  eventType,
  packId,
  packMap,
  redactServerRecord,
  roomCreateEvent,
  roomJoinRequestEvent,
  serverRecordHash,
  typeDefineEvent,
  validateCustomEventTypeName,
  validateDiscourseEnvelope,
  validateEventAgainstRegistry,
  validatePackImport,
  validatePortablePattern,
  validateRoomCreateHost,
  validateRoomCreatePayload,
  validateRoomJoinReviewPayload,
  validateRoomPath,
  validateTypeSchemaProfile,
  verifyArchiveRecords,
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
const HOST = "https://api.example.com";

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

function roomPayload(overrides: Partial<RoomCreatePayload> = {}): RoomCreatePayload {
  return {
    host: HOST,
    topic: "Research room",
    visibility: "public",
    start_time: 1000,
    end_time: 2000,
    ...overrides,
  };
}

test("loads the registered packs document", () => {
  assert.equal(packsDocument.protocol, "agent-discourse/1.0");
  assert.deepEqual(Object.keys(packs).sort(), [
    packId.CURATION,
    packId.DELIBERATION,
    packId.MODERATION,
    packId.REACTIONS,
    packId.REALTIME,
  ].sort());
  // Registered schemas follow the type schema profile and use integers only.
  for (const pack of packsDocument.packs) {
    for (const def of pack.types) validateTypeSchemaProfile(def.schema);
  }
  assert.ok(packs[packId.MODERATION].types.some((def) => def.type === "claim.update"));
  assert.ok(!packs[packId.REALTIME].types.some((def) => def.type === "session.candidate"));
});

test("validates room.create without room fields and binds it to a host", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(14));
  const envelope = signer.signEvent(roomCreateEvent(signer.agentId(), 100, 1, roomPayload()));

  assert.doesNotThrow(() => validateDiscourseEnvelope(envelope));
  assert.doesNotThrow(() => validateRoomPath(envelope, "d8ftedhpqhsusbg001tg"));
  validateRoomCreateHost(envelope.event.payload, HOST);
  assert.throws(() => validateRoomCreateHost(envelope.event.payload, "https://other.example"), /names/);
  assert.throws(() => validateRoomCreatePayload(roomPayload({ host: "https://api.example.com/v1" })), /origin/);
});

test("rejects room.create with room_id and unknown event fields", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(14));
  const event = roomCreateEvent(signer.agentId(), 100, 1, roomPayload());
  event.room_id = "d8ftedhpqhsusbg001tg";
  const envelope = signer.signEvent(event);
  assert.throws(() => validateDiscourseEnvelope(envelope), /room_id/);
  assert.throws(() => validateRoomPath(envelope, "d8ftedhpqhsusbg001tg"), /room_id/);

  const extra = signer.signEvent({ ...roomCreateEvent(signer.agentId(), 100, 1, roomPayload()), audience: "x" });
  assert.throws(() => validateDiscourseEnvelope(extra), /unknown event field: audience/);
});

test("rejects room events without room_id or with a malformed one", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(15));
  const event = createEvent(
    "agent-discourse/1.0",
    eventType.MESSAGE_CREATE,
    signer.agentId(),
    100,
    1,
    { content_type: "text/plain", content: "hello" },
  );
  assert.throws(() => validateDiscourseEnvelope(signer.signEvent(event)), /room_id/);
  const bad = discourse.discourseEvent(eventType.MESSAGE_CREATE, signer.agentId(), 100, 1, "room/../x", 1, "h", { content_type: "text/plain", content: "x" });
  assert.throws(() => validateDiscourseEnvelope(signer.signEvent(bad)), /room_id/);
});

test("join requests are signed, unanchored, and embedded by reviews", () => {
  const moderator = AgentSigner.fromSeed(new Uint8Array(32).fill(21));
  const applicant = AgentSigner.fromSeed(new Uint8Array(32).fill(22));
  const roomId = "d8ftedhpqhsusbg001tg";
  const request = applicant.signEvent(roomJoinRequestEvent(applicant.agentId(), 1_779_757_210_000, 1, roomId, {
    role: "speaker",
    perspective: "distributed-systems reviewer",
    reason: "I can cover replication and failure-mode tradeoffs.",
  }));
  validateDiscourseEnvelope(request);
  // A join request carries no base: its author may not be able to read the room.
  const anchored = applicant.signEvent({ ...roomJoinRequestEvent(applicant.agentId(), 1, 2, roomId, { role: "speaker" }), base_seq: 1, base_hash: "h" });
  assert.throws(() => validateDiscourseEnvelope(anchored), /unknown event field: base_seq/);

  const payload: RoomJoinReviewPayload = { request, decision: "approve", role: "speaker", reason: "relevant expertise" };
  const review = moderator.signEvent(discourse.discourseEvent(eventType.ROOM_JOIN_REVIEW, moderator.agentId(), 1_779_757_250_000, 1, roomId, 17, "previous-record-hash", payload));
  validateDiscourseEnvelope(review);
  validateRoomJoinReviewPayload(review.event.payload, roomId);
  assert.equal(review.event.payload.request.event.actor, applicant.agentId());
  assert.throws(() => validateRoomJoinReviewPayload({ ...payload, role: undefined }, roomId), /requires a role/);
  assert.throws(() => validateRoomJoinReviewPayload(payload, "other-room"), /another room/);
  const tampered = { ...payload, request: { ...request, event: { ...request.event, payload: { role: "moderator" as const } } } };
  assert.throws(() => validateRoomJoinReviewPayload(tampered, roomId), /hash/);
});

test("direct join follows invites and open roles", () => {
  const invited = AgentSigner.fromSeed(new Uint8Array(32).fill(23)).agentId();
  const stranger = AgentSigner.fromSeed(new Uint8Array(32).fill(24)).agentId();
  const policy = { invites: { [invited]: "moderator" as const }, open_roles: ["observer" as const] };
  assert.equal(canJoinDirectly("private", policy, invited, "moderator"), true);
  assert.equal(canJoinDirectly("private", policy, invited, "speaker"), false);
  assert.equal(canJoinDirectly("private", policy, stranger, "observer"), false);
  assert.equal(canJoinDirectly("public", policy, stranger, "observer"), true);
  assert.equal(canJoinDirectly("public", policy, stranger, "speaker"), false);
  assert.deepEqual(effectiveOpenRoles(undefined), ["speaker", "observer"]);
  assert.deepEqual(effectiveOpenRoles({ observer_allowed: false }), ["speaker"]);
  assert.throws(() => validateRoomCreatePayload(roomPayload({ policy: { open_roles: ["moderator"] } })), /open_roles/);
  assert.throws(() => validateRoomCreatePayload(roomPayload({ policy: { observer_allowed: false, open_roles: ["observer"] } })), /observers/);
  assert.throws(() => validateRoomCreatePayload(roomPayload({ policy: { invites: { [invited]: "owner" as never } } })), /invited role/);
  assert.throws(() => validateRoomCreatePayload(roomPayload({ policy: { moderator_agent_ids: [invited] } as never })), /unknown policy field/);
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

test("rejects bad pack imports and declaration conflicts", () => {
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
  assert.throws(() => validatePackImport({ pack: "http://example.com/p.json", digest: `sha256:${"A".repeat(43)}` }), /HTTPS/);
  assert.throws(() => validatePackImport({ pack: "https://example.com/p.json", digest: "sha256:abc" }), /digest/);
  // room.create declarations may not name a type twice.
  assert.throws(
    () => TypeRegistry.fromDeclarations([findingDef, { ...findingDef, title: "Again" }]),
    /declared twice/,
  );
  assert.throws(
    () => TypeRegistry.fromDeclarations([{ use: packId.REACTIONS }, { use: packId.REACTIONS }], packs),
    /declared twice/,
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
    [{ use: packId.DELIBERATION }, { use: packId.CURATION }],
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
  // `format` is an annotation: a non-URI string is not a schema violation.
  registry.validatePayload("resource.add", { resource_type: "web", uri: "not a uri" });

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

test("type schemas follow the portable profile", () => {
  for (const pattern of ["^[A-Za-z0-9_-]{43}$", "^did:agent:[A-Za-z0-9_-]{43}$", "a|b", "(ab)+c?", "[^,]{1,3}", "x{2,}", "\\.\\-"]) {
    validatePortablePattern(pattern);
  }
  for (const pattern of ["\\d+", "a.b", "(?:a)", "(?=a)", "a*?", "\\p{L}", "[]a]", "[a[b]]", "a^b", "\\1", "{2}", "a{x}"]) {
    assert.throws(() => validatePortablePattern(pattern), /not portable/, pattern);
  }
  validateTypeSchemaProfile({ type: "object", properties: { a: { $ref: "#/$defs/x" } }, $defs: { x: { type: "string", pattern: "^a$" } } });
  for (const schema of [
    { $ref: "https://example.com/schema.json" },
    { $dynamicRef: "#x" },
    { $schema: "http://json-schema.org/draft-07/schema#" },
    { properties: { a: { pattern: "\\w" } } },
    { patternProperties: { "\\d": {} } },
    { allOf: [{ items: { pattern: "." } }] },
  ]) {
    assert.throws(() => validateTypeSchemaProfile(schema as Record<string, unknown>), /not allowed|dialect|fragment|portable/);
  }
  assert.throws(() => new TypeRegistry().define({ ...findingDef, schema: { type: "string", pattern: "\\s" } }), /portable/);
});

test("freshness classes decide which writes are head-bound", () => {
  const registry = TypeRegistry.fromDeclarations([{ use: packId.REACTIONS }, { use: packId.MODERATION }], packs);
  for (const type of [eventType.MESSAGE_CREATE, "turn.update", "claim.update", "unknown.custom"]) {
    assert.equal(eventRequiresRoomHead(type, registry), true, type);
  }
  for (const type of [...discourse.CONTRACT_EVENT_TYPES, ...discourse.MEMBERSHIP_EVENT_TYPES, "reaction.create", "steer.create", eventType.ROOM_CREATE, eventType.ROOM_JOIN_REQUEST]) {
    assert.equal(eventRequiresRoomHead(type, registry), false, type);
  }
  for (const type of discourse.CONTRACT_EVENT_TYPES) {
    assert.equal(discourse.builtinEventClass(type), "contract");
    assert.equal(discourse.eventAdvancesRoomHead(type), true);
  }
  assert.equal(discourse.recordClass(eventType.ROOM_JOIN_REQUEST), undefined);
  assert.equal(discourse.recordClass("claim.update", registry), "control");
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

  // built-in rules
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
  // The creator is a member until the room ends.
  assert.equal(canSubmitEvent(eventType.ROOM_LEAVE, { isCreator: true, role: "moderator" }, registry), false);
  assert.equal(canSubmitEvent(eventType.ROOM_JOIN, observer, registry), false);
  assert.equal(canSubmitEvent(eventType.ROOM_JOIN, { directJoinAllowed: true }, registry), true);
  assert.equal(canSubmitEvent(eventType.ROOM_JOIN, {}, registry), false);
  assert.equal(canSubmitEvent(eventType.ROOM_JOIN_REQUEST, {}, registry), true);
  assert.equal(canSubmitEvent(eventType.ROOM_JOIN_REQUEST, speaker, registry), false);
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
  // scheduled allows pre-start setup: requests, reviews, role updates, leave, type.define
  assert.equal(canWriteInState(eventType.ROOM_JOIN_REQUEST, "scheduled"), true);
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
  assert.equal(canWriteInState(eventType.ROOM_JOIN_REQUEST, "ended"), false);
  // cancel only while scheduled, close only while active
  assert.equal(canWriteInState(eventType.ROOM_CLOSE, "active"), true);
  assert.equal(canWriteInState(eventType.ROOM_CANCEL, "active"), false);
});

test("validates room creation payloads", () => {
  assert.doesNotThrow(() =>
    validateRoomCreatePayload(roomPayload({
      guidance: "Cite sources.",
      policy: { max_speakers: 2 },
      types: [{ use: packId.REACTIONS }, findingDef],
    })),
  );
  assert.throws(() => validateRoomCreatePayload(roomPayload({ topic: " " })), /topic/);
  assert.throws(() => validateRoomCreatePayload(roomPayload({ start_time: 2000, end_time: 1000 })), /start_time/);
  assert.throws(() => validateRoomCreatePayload(roomPayload({ policy: { max_speakers: 0 } })), /max_speakers/);
  assert.throws(
    () => validateRoomCreatePayload(roomPayload({ types: [{ ...findingDef, type: "room.custom" }] })),
    /reserved/,
  );
});

test("message content is a string or an object", () => {
  discourse.validateMessageCreatePayload({ content_type: "text/plain", content: "hi" });
  discourse.validateMessageCreatePayload({ content_type: "application/json", content: { a: 1 } });
  for (const content of [1, [], null, true]) {
    assert.throws(() => discourse.validateMessageCreatePayload({ content_type: "application/json", content } as never), /string or an object/);
  }
});

test("signs and validates type.define envelopes", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(16));
  const event = typeDefineEvent(
    signer.agentId(),
    100,
    1,
    "d8ftedhpqhsusbg001tg",
    1,
    "room-create-head",
    findingDef,
  );
  const envelope = signer.signEvent(event);
  assert.doesNotThrow(() => validateDiscourseEnvelope(envelope));
});

test("verifies pack digests", () => {
  const bytes = new TextEncoder().encode("pack document bytes");
  const expected = `sha256:${createHash("sha256").update(bytes).digest("base64url")}`;
  assert.doesNotThrow(() => verifyPackDigest(bytes, expected));
  const sha3 = `sha3-256:${createHash("sha3-256").update(bytes).digest("base64url")}`;
  assert.doesNotThrow(() => verifyPackDigest(bytes, sha3));
  assert.throws(
    () => verifyPackDigest(new TextEncoder().encode("tampered"), expected),
    /digest/,
  );
  assert.throws(() => verifyPackDigest(bytes, "md5:abc"), /format/);
  assert.throws(() => verifyPackDigest(bytes, "not-a-digest"), /format/);
});

test("builds, redacts, and verifies server record chains and archives", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(18));
  const envelope1 = signer.signEvent(roomCreateEvent(signer.agentId(), 100, 1, roomPayload()));
  const record1 = buildServerRecord("room123", 1, null, 110, envelope1);
  const event2 = discourse.discourseEvent(eventType.MESSAGE_CREATE, signer.agentId(), 120, 2, "room123", 1, record1.hash, { content_type: "text/plain", content: "hello" });
  const envelope2 = signer.signEvent(event2);
  const record2 = buildServerRecord("room123", 2, record1.hash, 130, envelope2);

  assert.equal(
    record1.hash,
    serverRecordHash("room123", 1, null, envelope1.hash, 110),
  );
  assert.equal(record1.accepted_at, 110);
  assert.doesNotThrow(() => verifyServerRecord(record1));
  assert.doesNotThrow(() => verifyServerRecordChain([record1, record2]));
  assert.throws(() => verifyServerRecordChain([record2]), /first seq/);
  assert.throws(
    () => verifyServerRecordChain([{ ...record2, pre_hash: "bad" }]),
    /hash|chain/,
  );

  // Redaction keeps the chain: the record hash commits to the envelope hash.
  const redacted = redactServerRecord(record2);
  assert.deepEqual(redacted.envelope, { hash: envelope2.hash, redacted: true, type: eventType.MESSAGE_CREATE });
  verifyServerRecordChain([record1, redacted]);
  assert.throws(() => redactServerRecord(record1), /cannot be redacted/);

  const manifest: discourse.ArchiveManifest = {
    protocol: "agent-discourse/1.0", type: "room.archive", room_id: "room123",
    url: `${HOST}/v1/rooms/room123`, generated_at: 200, last_seq: 2, last_hash: record2.hash,
  };
  assert.deepEqual(verifyArchiveRecords(manifest, [record1, record2]), []);
  assert.deepEqual(verifyArchiveRecords(manifest, [record1, redacted]), [2]);
  assert.throws(() => verifyArchiveRecords({ ...manifest, last_hash: record1.hash }, [record1, record2]), /last_hash/);
  assert.throws(() => verifyArchiveRecords(manifest, [record1]), /last_seq/);
});

test("builds SSE event stream URLs", () => {
  assert.equal(
    sseEventsUrl("https://api.example.com", "room123"),
    "https://api.example.com/v1/rooms/room123/events/live",
  );
});

test("kernel defines twelve built-in types with membership events as signals", () => {
  const {
    BUILTIN_EVENT_TYPES,
    MEMBERSHIP_EVENT_TYPES,
    builtinEventClass,
    eventAdvancesRoomHead,
  } = discourse;
  assert.equal(BUILTIN_EVENT_TYPES.length, 12);
  assert.ok(BUILTIN_EVENT_TYPES.includes("room.update"));
  assert.ok(BUILTIN_EVENT_TYPES.includes("room.join.request"));
  assert.ok(BUILTIN_EVENT_TYPES.includes("room.member.remove"));

  assert.deepEqual(MEMBERSHIP_EVENT_TYPES, [
    "room.join",
    "room.join.review",
    "room.leave",
    "room.member.role.update",
    "room.member.remove",
  ]);
  for (const type of MEMBERSHIP_EVENT_TYPES) {
    assert.equal(builtinEventClass(type), "signal");
    assert.equal(eventAdvancesRoomHead(type), false);
  }
  assert.equal(builtinEventClass(eventType.ROOM_CREATE), "genesis");
  assert.equal(builtinEventClass(eventType.ROOM_UPDATE), "contract");
  assert.equal(builtinEventClass(eventType.TYPE_DEFINE), "contract");
  assert.equal(builtinEventClass(eventType.MESSAGE_CREATE), "message");
  assert.equal(builtinEventClass("review.finding"), undefined);

  const registry = new TypeRegistry();
  registry.define({
    type: "reaction.create",
    kind: "signal",
    title: "Reaction",
    schema: { type: "object" },
  });
  assert.equal(eventAdvancesRoomHead("reaction.create", registry), false);
  assert.equal(eventAdvancesRoomHead("unknown.type", registry), true);

  for (const code of ["member_banned", "role_not_allowed", "max_speakers_exceeded", "host_mismatch", "type_conflict", "invalid_type_schema", "join_request_not_pending"]) {
    assert.ok(discourse.DISCOURSE_ERROR_CODES.includes(code), code);
  }
});

test("room.update and room.member.remove follow moderator permissions and state rules", () => {
  const moderator: PermissionContext = { role: "moderator" };
  const speaker: PermissionContext = { role: "speaker" };
  const creator: PermissionContext = { isCreator: true };

  for (const type of [eventType.ROOM_UPDATE, eventType.ROOM_MEMBER_REMOVE]) {
    assert.equal(canSubmitEvent(type, moderator), true);
    assert.equal(canSubmitEvent(type, creator), true);
    assert.equal(canSubmitEvent(type, speaker), false);
    assert.equal(canWriteInState(type, "scheduled"), true);
    assert.equal(canWriteInState(type, "active"), true);
    assert.equal(canWriteInState(type, "ended"), false);
    assert.equal(canWriteInState(type, "cancelled"), false);
  }
});

test("validateRoomUpdatePayload enforces the updatable field set", () => {
  discourse.validateRoomUpdatePayload({
    topic: "New topic",
    end_time: 2000,
    guidance: "",
  });
  assert.throws(() => discourse.validateRoomUpdatePayload({}), /must not be empty/);
  for (const field of ["visibility", "host"]) {
    assert.throws(
      () => discourse.validateRoomUpdatePayload({ [field]: "x" } as never),
      /not updatable/,
    );
  }
  assert.throws(
    () => discourse.validateRoomUpdatePayload({ topic: "  " }),
    /topic/,
  );
  assert.throws(
    () => discourse.validateRoomUpdatePayload({ start_time: 5, end_time: 5 }),
    /before end_time/,
  );
  assert.throws(
    () => discourse.validateRoomUpdatePayload({ policy: { max_speakers: 0 } }),
    /max_speakers/,
  );
});

test("validateRoomMemberRemovePayload checks member and ban shape", () => {
  const member = AgentSigner.fromSeed(new Uint8Array(32).fill(41)).agentId();
  discourse.validateRoomMemberRemovePayload({ member });
  discourse.validateRoomMemberRemovePayload({ member, ban: true, reason: "spam" });
  assert.throws(
    () => discourse.validateRoomMemberRemovePayload({ member: "not-an-id" }),
    /agent id/i,
  );
  assert.throws(
    () =>
      discourse.validateRoomMemberRemovePayload({
        member,
        ban: "yes",
      } as never),
    /ban must be a boolean/,
  );
});

test("mentions are capped at 32 unique agent ids", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(42));
  const others = Array.from({ length: 33 }, (_, index) =>
    AgentSigner.fromSeed(new Uint8Array(32).fill(100 + index)).agentId(),
  );
  const makeEnvelope = (mentions: string[]) =>
    signer.signEvent({
      ...discourse.discourseEvent(
        eventType.MESSAGE_CREATE,
        signer.agentId(),
        100,
        1,
        "room1",
        1,
        "room-create-head",
        { content_type: "text/plain", content: "hi" },
      ),
      mentions,
    });

  validateDiscourseEnvelope(makeEnvelope(others.slice(0, 32)));
  assert.throws(
    () => validateDiscourseEnvelope(makeEnvelope(others)),
    /must not exceed 32/,
  );
  assert.throws(
    () => validateDiscourseEnvelope(makeEnvelope([others[0], others[0]])),
    /unique/,
  );
});

test("type redefinition cannot change the kind", () => {
  const registry = new TypeRegistry();
  registry.define({
    type: "review.finding",
    kind: "message",
    title: "Finding",
    schema: { type: "object" },
  });
  registry.define({
    type: "review.finding",
    kind: "message",
    title: "Finding v2",
    schema: { type: "object" },
  });
  assert.equal(registry.get("review.finding")?.title, "Finding v2");
  assert.throws(
    () =>
      registry.define({
        type: "review.finding",
        kind: "signal",
        title: "Finding v3",
        schema: { type: "object" },
      }),
    /cannot change kind/,
  );
});

const discourseVectors = JSON.parse(
  readFileSync(new URL("../../../docs/protocols/agent-discourse/1.0.vectors.json", import.meta.url), "utf8"),
);

test("discourse vectors: record hashes, chains, redaction, and head progression", () => {
  const records = discourseVectors.records as discourse.ServerRecord[];
  for (const record of records) {
    assert.equal(serverRecordHash(record.room_id, record.seq, record.pre_hash, record.envelope.hash, record.accepted_at), record.hash);
    validateDiscourseEnvelope(record.envelope);
  }
  verifyServerRecordChain(records);
  verifyServerRecordChain(discourseVectors.redacted_records);
  const manifest: discourse.ArchiveManifest = {
    protocol: "agent-discourse/1.0", type: "room.archive", room_id: discourseVectors.room_id, url: `${HOST}/v1/rooms/${discourseVectors.room_id}`,
    generated_at: 0, last_seq: discourseVectors.last_seq, last_hash: discourseVectors.last_hash,
  };
  assert.deepEqual(verifyArchiveRecords(manifest, records), []);
  assert.deepEqual(verifyArchiveRecords(manifest, discourseVectors.redacted_records), [3]);
  const registry = TypeRegistry.fromDeclarations(records[0].envelope.event.payload.types ?? [], packs);
  let head = 0;
  records.forEach((record, index) => {
    if (discourse.eventAdvancesRoomHead(record.envelope.event.type, registry)) head = record.seq;
    assert.equal(head, discourseVectors.head_seq_after[index]);
  });
});

test("discourse vectors: freshness classes and portable patterns", () => {
  const registry = TypeRegistry.fromDeclarations(discourseVectors.freshness.registry, packs);
  for (const [type, cls] of Object.entries(discourseVectors.freshness.classes)) {
    assert.equal(discourse.recordClass(type, registry), cls, type);
    assert.equal(eventRequiresRoomHead(type, registry), discourseVectors.freshness.head_bound.includes(type), type);
  }
  for (const pattern of discourseVectors.patterns.valid) validatePortablePattern(pattern);
  for (const pattern of discourseVectors.patterns.invalid) {
    assert.throws(() => validatePortablePattern(pattern), /not portable/, pattern);
  }
});
