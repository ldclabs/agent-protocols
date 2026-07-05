// Pure room-state projection: the ADP Section 6.1 rules that turn an accepted
// ServerRecord into member, timeline, contract, and inbox changes on a
// LocalRoomState, plus the local-chain validation that gates them and the
// read-side predicates over room state. Every function is a plain transform
// over borrowed state — no signing, no network — which is what makes the
// connector's projection behaviour testable in isolation.

import {
  RoleUpdatePayload,
  RoomJoinPayload,
  RoomJoinReviewPayload,
  RoomMemberRemovePayload,
  RoomUpdatePayload,
  ServerRecord,
  TypeDeclaration,
  builtinEventClass,
  eventType,
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
  RoomMemberView,
  RoomsListMembership,
  TimelineItem,
} from "./views.js";

export function recordAdvancesRoomHead(
  room: LocalRoomState,
  record: ServerRecord,
): boolean {
  return eventTypeAdvancesRoomHead(room, record.envelope.event.type);
}

/** Lifecycle, `message`-, and `control`-kind records advance the room head;
 * `signal`-kind records — including the membership events — only anchor. */
export function eventTypeAdvancesRoomHead(
  room: LocalRoomState,
  type: string,
): boolean {
  const cls = builtinEventClass(type);
  if (cls !== undefined) return cls !== "signal";
  const def = room.room.types?.find((definition) => definition.type === type);
  return def === undefined || def.kind !== "signal";
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
  receivedAt: number,
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
    if (response.status === "scheduled" && payload.start_time <= receivedAt) {
      response.status = "active";
    }
  }
  if (payload.end_time !== undefined) response.end_time = payload.end_time;
}

export function isDuplicateRecord(
  room: LocalRoomState,
  record: ServerRecord,
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
  record: ServerRecord,
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

export function validateRecordBasePrecondition(
  room: LocalRoomState,
  record: ServerRecord,
): void {
  const event = record.envelope.event;
  if (event.type === eventType.ROOM_CREATE) return;
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
  if (!recordAdvancesRoomHead(room, record)) return;
  if (room.headSeq !== baseSeq || room.headHash !== baseHash) {
    throw invalidPayload(
      "record base_seq/base_hash must match current room head",
    );
  }
}

export function applyRecordProjection(
  room: LocalRoomState,
  record: ServerRecord,
  item: TimelineItem,
  activeAgent: AgentId,
  inbox: InboxItem[],
): void {
  const event = record.envelope.event;
  switch (event.type) {
    case eventType.ROOM_JOIN: {
      const payload = event.payload as RoomJoinPayload;
      room.members.set(event.actor, {
        agent_id: event.actor,
        role: payload.role,
        status: "active",
        is_creator: false,
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
      applyRoomUpdate(room, payload, record.received_at);
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
        inbox.push(
          inboxFromItem(
            "room.state.changed",
            "normal",
            item,
            "type_registry_changed",
            false,
          ),
        );
      }
      break;
    }
    case eventType.ROOM_JOIN_REVIEW: {
      const payload = event.payload as RoomJoinReviewPayload;
      if (
        payload.request.applicant === activeAgent &&
        payload.decision === "approve"
      ) {
        inbox.push(
          inboxFromItem(
            "room.join.approved",
            "high",
            item,
            "join_approved",
            true,
          ),
        );
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
      if (steerTargetsAgent(event.payload, activeAgent)) {
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
  if (typeof speaker !== "string") return undefined;
  const turnRaw = payload.turn_id;
  if (turnRaw === undefined) return undefined;
  const turnId = typeof turnRaw === "string" ? turnRaw : JSON.stringify(turnRaw);
  const instructionRaw = payload.intent ?? payload.topic ?? payload.reason;
  return {
    turn_id: turnId,
    speaker,
    assigned_seq: item.seq,
    expires_at:
      typeof payload.expires_at === "number" ? payload.expires_at : undefined,
    instruction:
      typeof instructionRaw === "string" ? instructionRaw : undefined,
    source_event_id: item.event_id,
  };
}

function steerTargetsAgent(payload: unknown, activeAgent: AgentId): boolean {
  if (!isRecord(payload)) return true;
  const target = payload.target;
  if (typeof target !== "string") return true;
  return target === activeAgent;
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
    created_at: item.received_at,
    requires_response: requiresResponse,
    reason,
    suggested_tools: requiresResponse ? [TOOL_ROOM_SEND_MESSAGE] : [],
    message: { summary: item.summary },
  };
}

export function inboxEntryReady(entry: InboxEntry, nowMs: number): boolean {
  switch (entry.state.kind) {
    case "pending":
      return true;
    case "deferred":
      return entry.state.until <= nowMs;
    default:
      return false;
  }
}

export function membershipFilter(
  room: LocalRoomState,
  agentId: AgentId,
  membership: RoomsListMembership | undefined,
): boolean {
  switch (membership ?? "all") {
    case "all":
      return true;
    case "member":
      return room.members.has(agentId);
    case "creator":
      return room.members.get(agentId)?.is_creator ?? false;
    case "moderator":
      return room.members.get(agentId)?.role === "moderator";
    case "pending":
      return false;
    default:
      return true;
  }
}
