// Pure room-state projection: the ADP Section 5.1 rules that turn an accepted
// record into member, timeline, contract, and inbox changes on a
// LocalRoomState, plus the local-chain validation that gates them and the
// read-side predicates over room state. Every function is a plain transform
// over borrowed state — no signing, no network — which is what makes the
// connector's projection behaviour testable in isolation.

import {
  ArchiveRecord,
  RoleUpdatePayload,
  RoomJoinPayload,
  RoomJoinReviewPayload,
  RoomMemberRemovePayload,
  RoomUpdatePayload,
  TypeDeclaration,
  eventAdvancesRoomHead,
  eventRequiresRoomHead,
  eventType,
  isRedactedRecord,
  isTypeDef,
} from "../discourse.js";
import { AgentId } from "../identity.js";

import { TOOL_ROOM_SEND_MESSAGE } from "./catalog.js";
import { invalidPayload, isRecord } from "./internal.js";
import type { InboxEntry, LocalRoomState } from "./state.js";
import type {
  ActiveTurn,
  InboxItem,
  InboxKind,
  InboxPriority,
  RoomMemberStatus,
  RoomsListMembership,
  TimelineItem,
} from "./views.js";

/** Type of a record's event, including a redacted record's kept type. */
export function recordType(record: ArchiveRecord): string {
  return isRedactedRecord(record) ? record.envelope.type : record.envelope.event.type;
}

export function recordAdvancesRoomHead(
  room: LocalRoomState,
  record: ArchiveRecord,
): boolean {
  return eventTypeAdvancesRoomHead(room, recordType(record));
}

/** `genesis`, `contract`, and `control` records advance the room head. */
export function eventTypeAdvancesRoomHead(
  room: LocalRoomState,
  type: string,
): boolean {
  return eventAdvancesRoomHead(type, room.room.types ?? []);
}

/** Message and control writes — `message.create` and `message`/`control` kinds — must be based at or after the head. */
export function eventTypeRequiresRoomHead(
  room: LocalRoomState,
  type: string,
): boolean {
  return eventRequiresRoomHead(type, room.room.types ?? []);
}

/**
 * Whether a message or control write based on `base` still passes the ADP
 * Section 5.1 head check against the verified local head: the base is the
 * head itself or a later record.
 */
export function baseIsCurrent(room: LocalRoomState, base: readonly [number, string]): boolean {
  return base[0] > room.headSeq || (base[0] === room.headSeq && base[1] === room.headHash);
}

export function materializeCreator(room: LocalRoomState): void {
  const creator = room.room.creator ?? room.room.envelope?.event.actor;
  if (creator === undefined) return;
  if (!room.members.has(creator)) {
    room.members.set(creator, {
      agent_id: creator,
      role: "moderator",
      status: "active",
      is_creator: true,
      joined_seq: 1,
      last_event_seq: 1,
    });
  }
}

/** A present field replaces the current value; an empty value clears it. */
function applyRoomUpdate(
  room: LocalRoomState,
  payload: RoomUpdatePayload,
  acceptedAt: number,
): void {
  const response = room.room;
  if (payload.topic !== undefined) response.topic = payload.topic;
  if (payload.agenda !== undefined) {
    response.agenda = payload.agenda === "" ? undefined : payload.agenda;
  }
  if (payload.guidance !== undefined) {
    response.guidance = payload.guidance === "" ? undefined : payload.guidance;
  }
  if (payload.tags !== undefined) response.tags = payload.tags;
  if (payload.language !== undefined) {
    response.language = payload.language === "" ? undefined : payload.language;
  }
  if (payload.policy !== undefined) {
    // An all-default policy is still an explicit revision: store it verbatim.
    response.policy = payload.policy;
  }
  if (payload.start_time !== undefined) {
    response.start_time = payload.start_time;
    // A scheduled room whose new start_time is at or before acceptance becomes
    // active.
    if (response.status === "scheduled" && payload.start_time <= acceptedAt) {
      response.status = "active";
    }
  }
  if (payload.end_time !== undefined) response.end_time = payload.end_time;
}

export function isDuplicateRecord(
  room: LocalRoomState,
  record: ArchiveRecord,
): boolean {
  return (
    record.seq <= room.syncedSeq &&
    room.records.some(
      (existing) => existing.seq === record.seq && existing.hash === record.hash,
    )
  );
}

export function validateNextRecord(
  room: LocalRoomState,
  record: ArchiveRecord,
): void {
  if (room.syncedSeq === 0) {
    if (record.seq !== 1 || record.pre_hash !== null) {
      throw invalidPayload(
        "first local record must have seq 1 and null pre_hash",
      );
    }
    return;
  }
  if (record.seq !== room.syncedSeq + 1) {
    throw invalidPayload("record seq must continue local chain");
  }
  if ((record.pre_hash ?? null) !== (room.syncedHash ?? null)) {
    throw invalidPayload("record pre_hash mismatch");
  }
}

/**
 * Section 5.1 base check against local state: head-bound records must name
 * the current head; contract and signal records must name an earlier accepted
 * record. A redacted record's base is not visible and is not checked.
 */
export function validateRecordBasePrecondition(
  room: LocalRoomState,
  record: ArchiveRecord,
): void {
  if (isRedactedRecord(record)) return;
  const event = record.envelope.event;
  if (event.type === eventType.ROOM_CREATE) return;
  if (event.type === eventType.ROOM_JOIN_REQUEST) {
    throw invalidPayload("a room.join.request is never a record");
  }
  const baseSeq = event.base_seq;
  if (baseSeq === undefined) {
    throw invalidPayload("record event requires base_seq");
  }
  const baseHash = event.base_hash;
  if (baseHash === undefined) {
    throw invalidPayload("record event requires base_hash");
  }
  if (baseSeq >= record.seq) {
    throw invalidPayload(
      "record base_seq must reference an earlier accepted record",
    );
  }
  if (eventTypeRequiresRoomHead(room, event.type) && baseSeq < room.headSeq) {
    throw invalidPayload("record base_seq must be at or after the room head");
  }
  if (baseSeq === room.headSeq) {
    if (room.headHash !== baseHash) {
      throw invalidPayload("record base_hash does not match the anchored record");
    }
    return;
  }
  const anchor = room.records.find((existing) => existing.seq === baseSeq);
  if (anchor && anchor.hash !== baseHash) {
    throw invalidPayload("record base_hash does not match the anchored record");
  }
}

export function applyRecordProjection(
  room: LocalRoomState,
  record: ArchiveRecord,
  item: TimelineItem,
  activeAgent: AgentId,
  inbox: InboxItem[],
): void {
  if (isRedactedRecord(record)) return;
  const event = record.envelope.event;
  switch (event.type) {
    case eventType.ROOM_JOIN: {
      const payload = event.payload as RoomJoinPayload;
      room.members.set(event.actor, {
        agent_id: event.actor,
        role: payload.role,
        status: "active",
        is_creator: false,
        perspective: payload.perspective,
        joined_seq: record.seq,
        last_event_seq: record.seq,
      });
      break;
    }
    case eventType.ROOM_LEAVE: {
      const member = room.members.get(event.actor);
      if (member) {
        member.status = "left";
        member.left_seq = record.seq;
        member.last_event_seq = record.seq;
      }
      break;
    }
    case eventType.ROOM_MEMBER_ROLE_UPDATE: {
      const payload = event.payload as RoleUpdatePayload;
      const member = room.members.get(payload.member);
      if (member) {
        member.role = payload.role;
        member.last_event_seq = record.seq;
        if (payload.member === activeAgent) {
          inbox.push(
            inboxFromItem(
              "room.role.changed",
              "normal",
              item,
              "role_changed",
              false,
            ),
          );
        }
      }
      break;
    }
    case eventType.ROOM_UPDATE: {
      const payload = event.payload as RoomUpdatePayload;
      applyRoomUpdate(room, payload, record.accepted_at);
      inbox.push(
        inboxFromItem(
          "room.state.changed",
          "normal",
          item,
          "room_updated",
          false,
        ),
      );
      break;
    }
    case eventType.ROOM_MEMBER_REMOVE: {
      const payload = event.payload as RoomMemberRemovePayload;
      const banning = payload.ban === true;
      const status: RoomMemberStatus = banning ? "banned" : "removed";
      const member = room.members.get(payload.member);
      if (member) {
        member.status = status;
        member.left_seq = record.seq;
        member.last_event_seq = record.seq;
      } else {
        room.members.set(payload.member, {
          // A `ban: true` remove may target a non-member as a pre-emptive ban;
          // it never had a real role.
          agent_id: payload.member,
          role: "observer",
          status,
          is_creator: false,
          left_seq: record.seq,
          last_event_seq: record.seq,
        });
      }
      if (payload.member === activeAgent) {
        inbox.push(
          inboxFromItem(
            "room.member.removed",
            "high",
            item,
            banning ? "member_banned" : "member_removed",
            false,
          ),
        );
      }
      break;
    }
    case eventType.ROOM_CLOSE: {
      room.room.status = "ended";
      inbox.push(
        inboxFromItem(
          "room.state.changed",
          "normal",
          item,
          "room_closed",
          false,
        ),
      );
      break;
    }
    case eventType.ROOM_CANCEL: {
      room.room.status = "cancelled";
      inbox.push(
        inboxFromItem(
          "room.state.changed",
          "normal",
          item,
          "room_cancelled",
          false,
        ),
      );
      break;
    }
    case eventType.TYPE_DEFINE: {
      const declaration = event.payload as TypeDeclaration;
      if (isTypeDef(declaration)) {
        if (!room.room.types) room.room.types = [];
        room.room.types = room.room.types.filter(
          (existing) => existing.type !== declaration.type,
        );
        room.room.types.push(declaration);
      }
      inbox.push(
        inboxFromItem(
          "room.state.changed",
          "normal",
          item,
          "type_registry_changed",
          false,
        ),
      );
      break;
    }
    case eventType.ROOM_JOIN_REVIEW: {
      const payload = event.payload as RoomJoinReviewPayload;
      const request = payload.request.event;
      if (payload.decision === "approve" && payload.role !== undefined) {
        // The review record is the approved applicant's membership event.
        room.members.set(request.actor, {
          agent_id: request.actor,
          role: payload.role,
          status: "active",
          is_creator: false,
          perspective: request.payload.perspective,
          joined_seq: record.seq,
          last_event_seq: record.seq,
        });
        if (request.actor === activeAgent) {
          inbox.push(
            inboxFromItem(
              "room.join.approved",
              "high",
              item,
              "join_approved",
              false,
            ),
          );
        }
      }
      break;
    }
    case eventType.MESSAGE_CREATE: {
      if ((item.mentions ?? []).includes(activeAgent)) {
        inbox.push(
          inboxFromItem("room.mention", "high", item, "mentioned", true),
        );
      } else if (event.actor !== activeAgent) {
        inbox.push(
          inboxFromItem(
            "room.message.new",
            "normal",
            item,
            "new_message",
            false,
          ),
        );
      }
      break;
    }
    case "turn.update": {
      const turn = activeTurnFromItem(item);
      if (turn) {
        const assignedToSelf = turn.speaker === activeAgent;
        room.activeTurn = turn;
        if (assignedToSelf) {
          inbox.push(
            inboxFromItem(
              "room.turn.assigned",
              "high",
              item,
              "turn_assigned",
              true,
            ),
          );
        }
      }
      break;
    }
    case "steer.create": {
      if (steerTargetsAgent(item.mentions ?? [], activeAgent)) {
        inbox.push(inboxFromItem("room.steer", "high", item, "steer", true));
      }
      break;
    }
    default:
      break;
  }
}

function activeTurnFromItem(item: TimelineItem): ActiveTurn | undefined {
  const payload = item.payload;
  if (!isRecord(payload)) return undefined;
  const speaker = payload.speaker;
  const turnId = payload.turn_id;
  if (typeof speaker !== "string" || typeof turnId !== "number") return undefined;
  return {
    turn_id: turnId,
    speaker,
    assigned_seq: item.seq,
    expires_at:
      typeof payload.expires_at === "number" ? payload.expires_at : undefined,
    intent: typeof payload.intent === "string" ? payload.intent : undefined,
    topic: typeof payload.topic === "string" ? payload.topic : undefined,
    source_event_id: item.event_id,
  };
}

/** A steer addresses every member when its `mentions` are empty, and otherwise only the mentioned agents. */
function steerTargetsAgent(mentions: readonly AgentId[], activeAgent: AgentId): boolean {
  return mentions.length === 0 || mentions.includes(activeAgent);
}

function inboxFromItem(
  kind: InboxKind,
  priority: InboxPriority,
  item: TimelineItem,
  reason: string,
  requiresResponse: boolean,
): InboxItem {
  return {
    id: `${item.room_id}:${kind}:${item.seq}:${item.event_id}`,
    kind,
    priority,
    room_id: item.room_id,
    seq: item.seq,
    event_id: item.event_id,
    actor: item.actor,
    created_at: item.accepted_at,
    requires_response: requiresResponse,
    reason,
    suggested_tools: requiresResponse ? [TOOL_ROOM_SEND_MESSAGE] : [],
    message: { summary: item.summary },
  };
}

/** Pending, due deferred, and claimed-but-expired entries are ready. */
export function inboxEntryReady(entry: InboxEntry, nowMs: number): boolean {
  switch (entry.state.kind) {
    case "pending":
      return true;
    case "deferred":
    case "claimed":
      return entry.state.until <= nowMs;
    default:
      return false;
  }
}

export function membershipFilter(
  room: LocalRoomState,
  agentId: AgentId,
  membership: RoomsListMembership | undefined,
  pending: boolean,
): boolean {
  switch (membership ?? "all") {
    case "all":
      return true;
    case "member":
      return room.members.get(agentId)?.status === "active";
    case "creator":
      return room.members.get(agentId)?.is_creator ?? false;
    case "moderator":
      return room.members.get(agentId)?.role === "moderator";
    case "pending":
      return pending;
    default:
      return true;
  }
}
