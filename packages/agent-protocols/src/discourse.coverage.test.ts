import assert from "node:assert/strict";
import test from "node:test";

import { AgentSigner } from "./identity.js";
import {
  TypeDef,
  TypeRegistry,
  archiveEventsDigest,
  buildServerRecord,
  canSubmitEvent,
  defaultKindRoles,
  discourseEvent,
  eventRequiresRoomId,
  eventType,
  roomCreateEvent,
  isPackImport,
  isTypeDef,
  packId,
  serverRecordHashPayload,
  validateDiscourseEnvelope,
  validateEventAgainstRegistry,
  validateMessageCreatePayload,
  validatePackImport,
  validateRoomPath,
  validateRoomWrite,
  validateTypeDeclaration,
  validateTypeDef,
  verifyServerRecordChain,
} from "./discourse.js";

const findingDef: TypeDef = {
  type: "review.finding",
  kind: "message",
  title: "Review finding",
  schema: { type: "object" },
};

test("eventRequiresRoomId distinguishes room.create", () => {
  assert.equal(eventRequiresRoomId(eventType.MESSAGE_CREATE), true);
  assert.equal(eventRequiresRoomId(eventType.ROOM_CREATE), false);
});

test("roomCreateEvent builds a room.create event and validateRoomPath accepts it", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(60));
  const event = roomCreateEvent(signer.agentId(), 100, 1, {
    topic: "Room",
    visibility: "public",
    start_time: 1000,
    end_time: 2000,
  });
  assert.equal(event.type, eventType.ROOM_CREATE);
  assert.equal(event.protocol, "agent-discourse/1.0");
  assert.equal(event.room_id, undefined);

  const envelope = signer.signEvent(event);
  assert.doesNotThrow(() => validateRoomPath(envelope, "room1"));

  const withRoomId = { ...envelope, event: { ...envelope.event, room_id: "room1" } };
  assert.throws(() => validateRoomPath(withRoomId, "room1"), /must not include room_id/);
});

test("isPackImport and isTypeDef classify declarations", () => {
  assert.equal(isPackImport({ use: packId.REACTIONS }), true);
  assert.equal(isPackImport(findingDef), false);
  assert.equal(isPackImport("nope" as never), false);
  assert.equal(isTypeDef(findingDef), true);
  assert.equal(isTypeDef({ use: packId.REACTIONS }), false);
});

test("validateTypeDeclaration routes and rejects unknown shapes", () => {
  assert.doesNotThrow(() => validateTypeDeclaration(findingDef));
  assert.doesNotThrow(() => validateTypeDeclaration({ use: packId.REACTIONS }));
  assert.throws(() => validateTypeDeclaration({} as never), /inline definition/);
});

test("validateTypeDef rejects each malformed field", () => {
  assert.throws(
    () => validateTypeDef({ ...findingDef, kind: "bogus" as never }),
    /type kind/,
  );
  assert.throws(() => validateTypeDef({ ...findingDef, title: "  " }), /title/);
  assert.throws(
    () => validateTypeDef({ ...findingDef, schema: [] as never }),
    /JSON Schema object/,
  );
  assert.throws(() => validateTypeDef({ ...findingDef, roles: [] }), /roles/);
  assert.throws(
    () => validateTypeDef({ ...findingDef, roles: ["owner" as never] }),
    /role list/,
  );
  assert.throws(
    () => validateTypeDef({ ...findingDef, status: "bogus" as never }),
    /type status/,
  );
  assert.throws(
    () => validateTypeDef({ ...findingDef, rate_hint: 0 }),
    /positive integers/,
  );
  assert.throws(
    () => validateTypeDef({ ...findingDef, max_payload_hint: -1 }),
    /positive integers/,
  );
});

test("validatePackImport covers each arm", () => {
  assert.doesNotThrow(() => validatePackImport({ use: packId.REACTIONS }));
  assert.doesNotThrow(() =>
    validatePackImport({ pack: "https://example.com/p.json", digest: "sha256:abc" }),
  );
  assert.throws(
    () => validatePackImport({ pack: "https://example.com/p.json", digest: "  " }),
    /digest must not be empty/,
  );
  assert.throws(() => validatePackImport({}), /pack import requires/);
  assert.throws(
    () => validatePackImport({ use: "adp:Bad/1.0" }),
    /invalid registered pack id/,
  );
  assert.throws(
    () => validatePackImport({ use: packId.REACTIONS, types: [] }),
    /subset must not be empty/,
  );
});

test("validateMessageCreatePayload requires a content type", () => {
  assert.doesNotThrow(() =>
    validateMessageCreatePayload({ content_type: "text/plain", content: "hi" }),
  );
  assert.throws(
    () => validateMessageCreatePayload({ content_type: " ", content: "hi" }),
    /content_type/,
  );
});

test("validateTypeDef surfaces schema compilation failures", () => {
  // a schema object whose keys cannot be read makes the JSON Schema compiler throw
  const hostileSchema = new Proxy(
    {},
    {
      ownKeys() {
        throw new Error("unreadable schema");
      },
      get() {
        throw new Error("unreadable schema");
      },
    },
  );
  assert.throws(
    () => validateTypeDef({ ...findingDef, schema: hostileSchema as never }),
    /invalid type schema/,
  );
});

test("canSubmitEvent always permits room.create", () => {
  assert.equal(canSubmitEvent(eventType.ROOM_CREATE, {}), true);
});

test("registry rejects unknown subset types and exposes definitions", () => {
  const packs = {
    "adp:custom/1.0": {
      id: "adp:custom/1.0",
      title: "Custom",
      types: [findingDef],
    },
  };
  assert.throws(
    () =>
      TypeRegistry.fromDeclarations(
        [{ use: "adp:custom/1.0", types: ["does.not.exist"] }],
        packs,
      ),
    /not in pack/,
  );

  const registry = new TypeRegistry();
  registry.define(findingDef);
  assert.equal(registry.definitions().length, 1);
  assert.throws(() => registry.apply({} as never), /inline definition/);
});

test("validateEventAgainstRegistry bypasses built-in types", () => {
  const registry = new TypeRegistry();
  assert.doesNotThrow(() =>
    validateEventAgainstRegistry(eventType.MESSAGE_CREATE, { anything: true }, registry),
  );
});

test("canSubmitEvent and validateRoomWrite handle custom-type edges", () => {
  const registry = new TypeRegistry();
  registry.define(findingDef);
  registry.define({ ...findingDef, type: "review.disabled", status: "disabled" });

  // disabled custom types are never submittable, even for the creator
  assert.equal(canSubmitEvent("review.disabled", { isCreator: true }, registry), false);
  // a member with no role cannot submit a custom type
  assert.equal(canSubmitEvent("review.finding", {}, registry), false);

  assert.doesNotThrow(() =>
    validateRoomWrite(eventType.MESSAGE_CREATE, "active", { role: "speaker" }, registry),
  );
  assert.throws(
    () => validateRoomWrite(eventType.MESSAGE_CREATE, "ended", { role: "speaker" }, registry),
    /permission/,
  );
});

test("defaultKindRoles returns the expected roles per kind", () => {
  assert.deepEqual(defaultKindRoles("message"), ["moderator", "speaker"]);
  assert.deepEqual(defaultKindRoles("signal"), ["moderator", "speaker", "observer"]);
  assert.deepEqual(defaultKindRoles("control"), ["moderator"]);
});

test("validateDiscourseEnvelope rejects a foreign protocol", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(41));
  const envelope = signer.signEvent(
    discourseEventWithProtocol("other/1.0", signer, "room1"),
  );
  assert.throws(() => validateDiscourseEnvelope(envelope), /got other/);
});

test("validateRoomPath matches, mismatches, and requires room ids", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(42));
  const inRoom = signer.signEvent(
    discourseEvent(
      eventType.MESSAGE_CREATE,
      signer.agentId(),
      1,
      1,
      "room1",
      1,
      "room-create-head",
      {
        content_type: "text/plain",
        content: "hi",
      },
    ),
  );
  assert.doesNotThrow(() => validateRoomPath(inRoom, "room1"));
  assert.throws(() => validateRoomPath(inRoom, "room2"), /expected room2/);

  // validateRoomPath only inspects the event shape, so an unsigned envelope is fine
  const noRoom = {
    hash: "h",
    event: {
      protocol: "agent-discourse/1.0",
      type: eventType.MESSAGE_CREATE,
      actor: signer.agentId(),
      created_at: 1,
      nonce: 1,
      base_seq: 1,
      base_hash: "room-create-head",
      payload: {},
    },
    signature: "s",
  };
  assert.throws(() => validateRoomPath(noRoom, "room1"), /requires a room_id/);
});

test("verifyServerRecordChain rejects structural violations", () => {
  const signer = AgentSigner.fromSeed(new Uint8Array(32).fill(43));
  const make = (seq: number, nonce: number, preHash: string | null) => {
    const envelope = signer.signEvent(
      discourseEvent(
        eventType.MESSAGE_CREATE,
        signer.agentId(),
        100,
        nonce,
        "room1",
        seq === 1 ? 1 : seq - 1,
        preHash ?? "room-create-head",
        {
          content_type: "text/plain",
          content: "hi",
        },
      ),
    );
    return buildServerRecord("room1", seq, preHash, 100 + seq, envelope);
  };

  const first = make(1, 1, null);
  assert.throws(
    () => verifyServerRecordChain([first, make(3, 2, first.hash)]),
    /seq must increase/,
  );
  assert.throws(
    () => verifyServerRecordChain([first, make(2, 3, "not-the-previous-hash")]),
    /pre_hash mismatch/,
  );
  assert.throws(
    () => verifyServerRecordChain([make(1, 4, "unexpected")]),
    /first pre_hash must be null/,
  );
});

test("hash helpers reject values without a canonical form", () => {
  assert.throws(() => archiveEventsDigest(undefined as never), /canonical JSON/);
  assert.deepEqual(serverRecordHashPayload("room1", 1, undefined, "h", 10).pre_hash, null);
});

function discourseEventWithProtocol(
  protocol: string,
  signer: AgentSigner,
  roomId: string,
) {
  return {
    protocol,
    type: eventType.MESSAGE_CREATE,
    actor: signer.agentId(),
    created_at: 1,
    nonce: 1,
    room_id: roomId,
    payload: { content_type: "text/plain", content: "hi" },
  };
}
