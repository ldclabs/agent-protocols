// Verified historical reads use an independent projection: reading an old page
// must not move live state, inbox leases, or the session's presented head.
import { Validator, type Schema } from "@cfworker/json-schema";
import {
  TypeRegistry,
  validateRoomCreatePayload,
  canJoinDirectly,
  isRedactedRecord,
  validateDiscourseEnvelope,
  validateRoomPath,
  validateRoomWrite,
  validateRoomJoinReviewPayload,
  verifyServerRecordChain,
  type ArchiveRecord,
  type Pack,
  type Role,
  type RoomCreatePayload,
  type RoomJoinReviewPayload,
  type RoomResponse,
  type TypeDeclaration,
} from "../discourse.js";
import type { AgentId } from "../identity.js";
import { CONNECTOR_CATALOG } from "./catalog-data.js";
import {
  applyRecordProjection,
  materializeCreator,
  recordAdvancesRoomHead,
  validateRecordBasePrecondition,
} from "./projection.js";
import { invalidPayload } from "./internal.js";
import type { LocalRoomState } from "./state.js";
import { timelineItemFromRecord, type TimelineItem } from "./views.js";

export function replayHistory(
  records: ArchiveRecord[],
  host: string,
  packs: Record<string, Pack>,
): { items: TimelineItem[]; room: LocalRoomState; stateVerified: boolean } {
  verifyServerRecordChain(records);
  const first = records[0];
  if (
    !first ||
    isRedactedRecord(first) ||
    first.envelope.event.type !== "room.create"
  )
    throw invalidPayload("history requires an unredacted room.create genesis");
  const payload = first.envelope.event.payload as RoomCreatePayload;
  validateRoomCreatePayload(payload);
  if (payload.host !== host)
    throw invalidPayload("history genesis host mismatch");
  const response: RoomResponse = {
    ...payload,
    id: first.room_id,
    url: `${host}/v1/rooms/${first.room_id}`,
    creator: first.envelope.event.actor,
    created_at: first.envelope.event.created_at,
    status: "scheduled",
    seq: 0,
    hash: "",
    pre_hash: null,
    accepted_at: first.accepted_at,
    types: [],
  };
  const room: LocalRoomState = {
    host,
    room: response,
    headSeq: 0,
    syncedSeq: 0,
    subscribed: false,
    members: new Map(),
    timeline: [],
    records: [],
    readSeq: 0,
  };
  materializeCreator(room);
  let registry = new TypeRegistry();
  let stateVerified = true;
  const eventSchema = new Validator(
    CONNECTOR_CATALOG.schemas["agent-discourse/1.0"] as unknown as Schema,
    "2020-12",
    false,
  );
  for (const record of records) {
    if (record.room_id !== first.room_id)
      throw invalidPayload("history room mismatch");
    if (isRedactedRecord(record)) stateVerified = false;
    else {
      const event = record.envelope.event;
      validateDiscourseEnvelope(record.envelope);
      validateRoomPath(record.envelope, first.room_id);
      const checked = eventSchema.validate(record.envelope);
      if (!checked.valid)
        throw invalidPayload(
          `history envelope schema: ${checked.errors.map((e) => e.error).join("; ")}`,
        );
      if (record.seq === 1) {
        registry = TypeRegistry.fromDeclarations(payload.types ?? [], packs);
        room.room.types = registry.definitions();
      } else if (stateVerified) {
        if (room.room.status !== "ended" && room.room.status !== "cancelled")
          room.room.status =
            record.accepted_at < room.room.start_time!
              ? "scheduled"
              : record.accepted_at >= room.room.end_time!
                ? "ended"
                : "active";
        const member = room.members.get(event.actor);
        const role = member?.status === "active" ? member.role : undefined;
        const body = event.payload as Record<string, unknown>;
        const join =
          event.type === "room.join" &&
          canJoinDirectly(
            room.room.visibility!,
            room.room.policy,
            event.actor,
            body.role as Role,
          ) &&
          member?.status !== "banned";
        validateRoomWrite(
          event.type,
          room.room.status,
          {
            role,
            isCreator: event.actor === response.creator,
            directJoinAllowed: join,
          },
          registry,
        );
        validateRecordBasePrecondition(room, record);
        if (event.type === "room.join.review")
          validateRoomJoinReviewPayload(
            event.payload as RoomJoinReviewPayload,
            first.room_id,
          );
        if (
          !Object.values(
            CONNECTOR_CATALOG.schemas["agent-discourse/1.0"].$defs
              .builtinEventType.enum,
          ).includes(event.type)
        )
          registry.validatePayload(event.type, event.payload);
        if (event.type === "type.define")
          registry.apply(event.payload as TypeDeclaration, packs);
      }
    }
    const item = timelineItemFromRecord(record, room.room.types ?? []);
    applyRecordProjection(
      room,
      record,
      item,
      first.envelope.event.actor as AgentId,
      [],
    );
    if (stateVerified) room.room.types = registry.definitions();
    if (recordAdvancesRoomHead(room, record)) {
      room.headSeq = record.seq;
      room.headHash = record.hash;
    }
    room.syncedSeq = record.seq;
    room.syncedHash = record.hash;
    room.records.push(record);
    room.timeline.push(item);
  }
  return { items: room.timeline, room, stateVerified };
}

/** Every external import is bound to signed raw-byte digest, not manifest metadata. */
export function referencedPacks(records: ArchiveRecord[]): Map<string, string> {
  const references = new Map<string, string>();
  for (const record of records) {
    if (isRedactedRecord(record)) continue;
    const event = record.envelope.event;
    const declarations =
      event.type === "room.create"
        ? ((event.payload as RoomCreatePayload).types ?? [])
        : event.type === "type.define"
          ? [event.payload as TypeDeclaration]
          : [];
    for (const declaration of declarations)
      if ("pack" in declaration && declaration.pack && declaration.digest) {
        if (
          references.has(declaration.pack) &&
          references.get(declaration.pack) !== declaration.digest
        )
          throw invalidPayload(
            "conflicting external pack versions need separate pack URLs",
          );
        references.set(declaration.pack, declaration.digest);
      }
  }
  return references;
}
