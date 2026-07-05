// Structured result types the connector returns to callers, plus the pure
// projection that turns a ServerRecord into a TimelineItem. These are the
// shapes a caller reads back; they carry no signing keys or live handles.

import {
  AgentStatus,
  MessageCreatePayload,
  Role,
  RoomPolicy,
  RoomResponse,
  RoomState,
  ServerRecord,
  TypeDef,
  Visibility,
  eventType,
} from "../discourse.js";
import { AgentId } from "../identity.js";

import { LocalConnectorToolName } from "./catalog.js";
import { isRecord, normalizeHost } from "./internal.js";

/**
 * Connector sync marker for one room. Connectors key local room state by
 * `(host, room_id)`: ADP room IDs are only recommended to be globally unique
 * and a connector can be configured with multiple hosts. `head_seq` /
 * `head_hash` are the latest locally verified head-advancing record per ADP
 * Section 6.1.
 */
export interface SyncState {
  host: string;
  room_id: string;
  head_seq: number;
  head_hash: string;
  synced_seq: number;
  remote_seq: number;
  subscribed: boolean;
  unread_count: number;
  pending_inbox_count: number;
}

export interface AgentProtocolsHost {
  host: string;
  label?: string;
  allowed: boolean;
  features?: string[];
  profile_service?: string;
  last_checked_at?: number;
}

/** `removed` and `banned` are produced by accepted `room.member.remove` records. */
export type RoomMemberStatus = "active" | "left" | "removed" | "banned" | "unknown";

export interface RoomMemberProfile {
  name?: string;
  description?: string;
  avatar_url?: string;
}

export interface RoomMemberView {
  agent_id: AgentId;
  role: Role;
  status: RoomMemberStatus;
  is_creator: boolean;
  perspective?: string;
  joined_seq?: number;
  left_seq?: number | null;
  last_event_seq?: number;
  profile?: RoomMemberProfile;
  extra?: Record<string, unknown>;
}

export interface TimelineItem {
  room_id: string;
  seq: number;
  event_id: string;
  type: string;
  kind: string;
  actor: AgentId;
  created_at: number;
  received_at: number;
  summary: string;
  content_type?: string;
  content?: unknown;
  mentions?: AgentId[];
  references?: string[];
  payload: unknown;
}

export type InboxKind =
  | "room.message.new"
  | "room.mention"
  | "room.turn.assigned"
  | "room.steer"
  | "room.join.requested"
  | "room.join.approved"
  | "room.role.changed"
  | "room.member.removed"
  | "room.state.changed"
  | "room.event.custom";

export type InboxPriority = "low" | "normal" | "high";

export interface InboxItem {
  id: string;
  kind: InboxKind;
  priority: InboxPriority;
  room_id?: string;
  seq?: number;
  event_id?: string;
  actor?: AgentId;
  created_at: number;
  requires_response: boolean;
  deadline?: number | null;
  reason: string;
  suggested_tools?: LocalConnectorToolName[];
  message?: unknown;
}

export type HeadMismatchPolicy = "hold" | "reject" | "send_anyway";
export type HeldDraftKind = "message" | "event";
export type DraftAction = "revise" | "send_as_is" | "stay_silent" | "send_anyway";

export interface HeldDraft {
  id: string;
  room_id: string;
  kind: HeldDraftKind;
  created_at: number;
  base_seq?: number;
  base_hash?: string;
  current_sync: SyncState;
  draft: unknown;
  reason: string;
  options?: DraftAction[];
}

export interface ActiveTurn {
  turn_id: string;
  speaker: AgentId;
  assigned_seq: number;
  expires_at?: number | null;
  instruction?: string;
  source_event_id: string;
}

export interface RoomSummary {
  room_id: string;
  host: string;
  topic?: string;
  status: RoomState;
  visibility?: Visibility;
  start_time?: number;
  end_time?: number;
  tags?: string[];
  language?: string;
  role?: Role;
  unread_count: number;
  pending_inbox_count: number;
}

export interface RoomStateView {
  host: string;
  room_id: string;
  status: RoomState;
  visibility?: Visibility;
  topic?: string;
  agenda?: string;
  guidance?: string;
  creator?: AgentId;
  created_at?: number;
  start_time?: number;
  end_time?: number;
  tags?: string[];
  language?: string;
  policy?: RoomPolicy;
  types?: TypeDef[];
  self_member?: RoomMemberView;
  members_count: number;
  active_turn?: ActiveTurn;
  unread_count: number;
  pending_inbox_count: number;
}

export type RoomsListMembership =
  | "member"
  | "creator"
  | "moderator"
  | "pending"
  | "all";

export interface RoomWriteResult {
  status: "sent" | "held" | "rejected";
  /** Present on `held` and `rejected` results, e.g. `room_head_mismatch`. */
  reason?: string;
  record?: ServerRecord;
  item?: TimelineItem;
  draft?: HeldDraft;
  changes?: TimelineItem[];
  sync: SyncState;
}

export interface AgentStatusToolResult {
  statuses?: AgentStatus[];
  status?: AgentStatus;
  sync?: SyncState;
}

export function syncStateFromRoomResponse(
  host: string,
  room: RoomResponse,
  options: {
    subscribed?: boolean;
    unreadCount?: number;
    pendingInboxCount?: number;
    remoteSeq?: number;
  } = {},
): SyncState {
  const head = room.head ?? { seq: room.seq, hash: room.hash };
  return {
    host: normalizeHost(host),
    room_id: room.id,
    head_seq: head.seq,
    head_hash: head.hash,
    synced_seq: room.seq,
    remote_seq: options.remoteSeq ?? room.seq,
    subscribed: options.subscribed ?? false,
    unread_count: options.unreadCount ?? 0,
    pending_inbox_count: options.pendingInboxCount ?? 0,
  };
}

export function roomSummaryFromResponse(
  host: string,
  room: RoomResponse,
  options: {
    role?: Role;
    unreadCount?: number;
    pendingInboxCount?: number;
  } = {},
): RoomSummary {
  const payload = room.envelope?.event.payload;
  return {
    room_id: room.id,
    host: normalizeHost(host),
    topic: room.topic ?? payload?.topic,
    status: room.status,
    visibility: room.visibility ?? payload?.visibility,
    start_time: room.start_time ?? payload?.start_time,
    end_time: room.end_time ?? payload?.end_time,
    tags: room.tags ?? payload?.tags,
    language: room.language ?? payload?.language,
    role: options.role,
    unread_count: options.unreadCount ?? 0,
    pending_inbox_count: options.pendingInboxCount ?? 0,
  };
}

export function timelineItemFromRecord(record: ServerRecord): TimelineItem {
  const event = record.envelope.event;
  const payload = event.payload;
  const message = messagePayload(payload);
  return {
    room_id: record.room_id,
    seq: record.seq,
    event_id: record.envelope.hash,
    type: event.type,
    kind: timelineKind(event.type),
    actor: event.actor,
    created_at: event.created_at,
    received_at: record.received_at,
    summary: summarizePayload(event.type, payload),
    content_type: message?.content_type,
    content: message?.content,
    mentions: event.mentions ?? [],
    references: message?.references ?? [],
    payload,
  };
}

function timelineKind(type: string): string {
  if (type === eventType.MESSAGE_CREATE) return "message";
  if (type.startsWith("room.")) return "room";
  if (type.startsWith("type.")) return "type";
  return "custom";
}

function summarizePayload(type: string, payload: unknown): string {
  if (type === eventType.MESSAGE_CREATE) {
    const message = messagePayload(payload);
    if (typeof message?.content === "string") return truncate(message.content, 200);
  }
  if (isRecord(payload)) {
    const summary = payload.summary ?? payload.reason ?? payload.title ?? payload.state;
    if (typeof summary === "string" && summary.trim() !== "") {
      return truncate(summary, 200);
    }
  }
  return type;
}

function messagePayload(payload: unknown): MessageCreatePayload | undefined {
  if (!isRecord(payload)) return undefined;
  if (typeof payload.content_type !== "string") return undefined;
  return {
    content_type: payload.content_type,
    content: payload.content,
    references: Array.isArray(payload.references)
      ? payload.references.filter((value): value is string => typeof value === "string")
      : undefined,
    extra: isRecord(payload.extra) ? payload.extra : undefined,
  };
}

function truncate(value: string, maxLength: number): string {
  return value.length <= maxLength ? value : `${value.slice(0, maxLength - 1)}...`;
}
