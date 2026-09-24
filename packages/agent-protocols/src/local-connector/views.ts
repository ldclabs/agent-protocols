// Structured result types the connector returns to callers, plus the pure
// projection that turns a ServerRecord into a TimelineItem. These are the
// shapes a caller reads back; they carry no signing keys or live handles.

import {
  AgentStatus,
  ArchiveRecord,
  RecordClass,
  Role,
  RoomPolicy,
  RoomResponse,
  RoomState,
  ServerRecord,
  TypeDef,
  Visibility,
  eventType,
  isRedactedRecord,
  recordClass,
} from "../discourse.js";
import { AgentId } from "../identity.js";

import { LocalConnectorToolName } from "./catalog.js";
import { isRecord, normalizeHost } from "./internal.js";

export type { DelegationVerdict } from "../delegation.js";

/**
 * Connector sync marker for one room. Connectors key local room state by
 * `(host, room_id)`: ADP room IDs are only recommended to be globally unique
 * and a connector can be configured with multiple hosts. `head_seq` /
 * `head_hash` are the latest locally verified head-advancing record per ADP
 * Section 5.1; `presented_seq` / `presented_hash` are the latest head the agent
 * has been shown with every record before it, the default write base.
 */
export interface SyncState {
  host: string;
  room_id: string;
  head_seq: number;
  head_hash: string;
  presented_seq?: number;
  presented_hash?: string;
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
  /** The record's ADP class: freshness class for built-ins, registry kind for custom types. */
  kind: RecordClass;
  /** Absent on redacted records. */
  actor?: AgentId;
  /** Absent on redacted records. */
  created_at?: number;
  accepted_at: number;
  /** Informative excerpt; its derivation is connector-defined. */
  summary: string;
  content_type?: string;
  content?: unknown;
  mentions?: AgentId[];
  references?: string[];
  /** Absent on redacted records. */
  payload?: unknown;
  redacted?: true;
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
export type DraftAction = "revise" | "send" | "drop";

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

/** The latest accepted `turn.update`; fields are copied from its payload. */
export interface ActiveTurn {
  turn_id: number;
  speaker: AgentId;
  assigned_seq: number;
  expires_at?: number;
  intent?: string;
  topic?: string;
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

/**
 * Projects a record into a timeline item. `types` is the room's materialized
 * registry; a custom type missing from it is reported as `message`.
 */
export function timelineItemFromRecord(
  record: ArchiveRecord,
  types: readonly TypeDef[] = [],
): TimelineItem {
  if (isRedactedRecord(record)) {
    const type = record.envelope.type;
    return {
      room_id: record.room_id,
      seq: record.seq,
      event_id: record.envelope.hash,
      type,
      kind: recordClass(type, types) ?? "message",
      accepted_at: record.accepted_at,
      summary: "[redacted]",
      redacted: true,
    };
  }
  const event = record.envelope.event;
  const payload = event.payload;
  const message = event.type === eventType.MESSAGE_CREATE ? messagePayload(payload) : undefined;
  return {
    room_id: record.room_id,
    seq: record.seq,
    event_id: record.envelope.hash,
    type: event.type,
    kind: recordClass(event.type, types) ?? "message",
    actor: event.actor,
    created_at: event.created_at,
    accepted_at: record.accepted_at,
    summary: summarizePayload(event.type, payload),
    content_type: message?.content_type,
    content: message?.content,
    mentions: event.mentions ?? [],
    references: referencesOf(payload),
    payload,
  };
}

/** Maximum summary length in Unicode code points. */
export const SUMMARY_MAX_CHARS = 160;
const SUMMARY_FIELDS = ["summary", "title", "instruction", "intent", "question", "reason", "state"];

/**
 * Informative summary shared by the SDK connectors: a string message body, or
 * the first non-empty summary-like payload field, truncated to 160 code points
 * with a trailing ellipsis; otherwise the event type.
 */
export function summarizePayload(type: string, payload: unknown): string {
  if (type === eventType.MESSAGE_CREATE) {
    const message = messagePayload(payload);
    if (typeof message?.content === "string" && message.content.trim() !== "") {
      return truncate(message.content, SUMMARY_MAX_CHARS);
    }
  }
  if (isRecord(payload)) {
    for (const field of SUMMARY_FIELDS) {
      const value = payload[field];
      if (typeof value === "string" && value.trim() !== "") {
        return truncate(value, SUMMARY_MAX_CHARS);
      }
    }
  }
  return type;
}

function messagePayload(payload: unknown): { content_type: string; content: unknown } | undefined {
  if (!isRecord(payload)) return undefined;
  if (typeof payload.content_type !== "string") return undefined;
  return { content_type: payload.content_type, content: payload.content };
}

function referencesOf(payload: unknown): string[] {
  if (!isRecord(payload) || !Array.isArray(payload.references)) return [];
  return payload.references.filter((value): value is string => typeof value === "string");
}

function truncate(value: string, maxChars: number): string {
  const chars = [...value];
  return chars.length <= maxChars ? value : `${chars.slice(0, maxChars - 1).join("")}…`;
}
