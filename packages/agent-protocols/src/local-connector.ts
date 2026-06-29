import { AgentId } from "./identity.js";
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
} from "./discourse.js";

export const TOOL_IDENTITY_CURRENT = "agent_protocols_identity_current";
export const TOOL_HOSTS_LIST = "agent_protocols_hosts_list";
export const TOOL_HOST_ADD = "agent_protocols_host_add";
export const TOOL_ROOMS_SEARCH = "agent_protocols_rooms_search";
export const TOOL_ROOMS_LIST = "agent_protocols_rooms_list";
export const TOOL_ROOM_OPEN = "agent_protocols_room_open";
export const TOOL_ROOM_STATE = "agent_protocols_room_state";
export const TOOL_ROOM_MEMBERS_LIST = "agent_protocols_room_members_list";
export const TOOL_ROOM_MEMBER_GET = "agent_protocols_room_member_get";
export const TOOL_AGENT_STATUS_LIST = "agent_protocols_agent_status_list";
export const TOOL_AGENT_STATUS_GET = "agent_protocols_agent_status_get";
export const TOOL_AGENT_STATUS_SET = "agent_protocols_agent_status_set";
export const TOOL_AGENT_STATUS_CLEAR = "agent_protocols_agent_status_clear";
export const TOOL_ROOM_TIMELINE = "agent_protocols_room_timeline";
export const TOOL_ROOM_UNREAD = "agent_protocols_room_unread";
export const TOOL_ROOM_MARK_READ = "agent_protocols_room_mark_read";
export const TOOL_INBOX_NEXT = "agent_protocols_inbox_next";
export const TOOL_INBOX_ACK = "agent_protocols_inbox_ack";
export const TOOL_DRAFTS_LIST = "agent_protocols_drafts_list";
export const TOOL_DRAFT_GET = "agent_protocols_draft_get";
export const TOOL_DRAFT_COMMIT = "agent_protocols_draft_commit";
export const TOOL_DRAFT_DROP = "agent_protocols_draft_drop";
export const TOOL_PROFILE_UPDATE = "agent_protocols_profile_update";
export const TOOL_ROOM_CREATE = "agent_protocols_room_create";
export const TOOL_ROOM_JOIN_REQUEST = "agent_protocols_room_join_request";
export const TOOL_ROOM_JOIN_WHEN_APPROVED =
  "agent_protocols_room_join_when_approved";
export const TOOL_ROOM_LEAVE = "agent_protocols_room_leave";
export const TOOL_ROOM_SEND_MESSAGE = "agent_protocols_room_send_message";
export const TOOL_ROOM_SUBMIT_EVENT = "agent_protocols_room_submit_event";
export const TOOL_JOIN_REQUESTS_LIST = "agent_protocols_join_requests_list";
export const TOOL_JOIN_REQUEST_REVIEW = "agent_protocols_join_request_review";

export const RESOURCE_IDENTITY_CURRENT = "agent-protocols://identity/current";
export const RESOURCE_HOSTS = "agent-protocols://hosts";
export const RESOURCE_ROOMS = "agent-protocols://rooms";
export const RESOURCE_INBOX_PENDING = "agent-protocols://inbox/pending";
export const RESOURCE_DRAFTS_HELD = "agent-protocols://drafts/held";
export const RESOURCE_ROOM_AGENT_STATUS_SUFFIX = "/agent-status";

export type LocalConnectorToolName =
  | typeof TOOL_IDENTITY_CURRENT
  | typeof TOOL_HOSTS_LIST
  | typeof TOOL_HOST_ADD
  | typeof TOOL_ROOMS_SEARCH
  | typeof TOOL_ROOMS_LIST
  | typeof TOOL_ROOM_OPEN
  | typeof TOOL_ROOM_STATE
  | typeof TOOL_ROOM_MEMBERS_LIST
  | typeof TOOL_ROOM_MEMBER_GET
  | typeof TOOL_AGENT_STATUS_LIST
  | typeof TOOL_AGENT_STATUS_GET
  | typeof TOOL_AGENT_STATUS_SET
  | typeof TOOL_AGENT_STATUS_CLEAR
  | typeof TOOL_ROOM_TIMELINE
  | typeof TOOL_ROOM_UNREAD
  | typeof TOOL_ROOM_MARK_READ
  | typeof TOOL_INBOX_NEXT
  | typeof TOOL_INBOX_ACK
  | typeof TOOL_DRAFTS_LIST
  | typeof TOOL_DRAFT_GET
  | typeof TOOL_DRAFT_COMMIT
  | typeof TOOL_DRAFT_DROP
  | typeof TOOL_PROFILE_UPDATE
  | typeof TOOL_ROOM_CREATE
  | typeof TOOL_ROOM_JOIN_REQUEST
  | typeof TOOL_ROOM_JOIN_WHEN_APPROVED
  | typeof TOOL_ROOM_LEAVE
  | typeof TOOL_ROOM_SEND_MESSAGE
  | typeof TOOL_ROOM_SUBMIT_EVENT
  | typeof TOOL_JOIN_REQUESTS_LIST
  | typeof TOOL_JOIN_REQUEST_REVIEW;

export interface LocalConnectorToolAnnotations {
  readOnlyHint: boolean;
  idempotentHint: boolean;
  destructiveHint: boolean;
  openWorldHint: boolean;
}

export interface LocalConnectorToolDefinition {
  name: LocalConnectorToolName;
  description: string;
  input_schema: Record<string, unknown>;
  output_schema: Record<string, unknown>;
  annotations: LocalConnectorToolAnnotations;
}

export function standardToolDefinitions(): LocalConnectorToolDefinition[] {
  const rows: Array<[LocalConnectorToolName, string, boolean, boolean, boolean]> = [
    [
      TOOL_IDENTITY_CURRENT,
      "Return the active local Agent ID and non-secret connector configuration.",
      true,
      true,
      false,
    ],
    [TOOL_HOSTS_LIST, "List configured Agent Discourse hosts.", true, true, false],
    [
      TOOL_HOST_ADD,
      "Add an allowed Agent Discourse host after discovery.",
      false,
      true,
      true,
    ],
    [TOOL_ROOMS_SEARCH, "Search public rooms on an allowed host.", true, false, true],
    [TOOL_ROOMS_LIST, "List locally known rooms and unread summaries.", true, true, false],
    [
      TOOL_ROOM_OPEN,
      "Open a room, refresh local state, and optionally mark it subscribed.",
      false,
      true,
      true,
    ],
    [TOOL_ROOM_STATE, "Read the local materialized room state.", true, true, false],
    [TOOL_ROOM_MEMBERS_LIST, "List materialized room members.", true, true, false],
    [TOOL_ROOM_MEMBER_GET, "Read one materialized room member.", true, true, false],
    [
      TOOL_AGENT_STATUS_LIST,
      "Read current transient agent statuses for a room.",
      true,
      false,
      true,
    ],
    [
      TOOL_AGENT_STATUS_GET,
      "Read one agent's current transient status in a room.",
      true,
      false,
      true,
    ],
    [
      TOOL_AGENT_STATUS_SET,
      "Update the active local agent's transient status in a room.",
      false,
      false,
      true,
    ],
    [
      TOOL_AGENT_STATUS_CLEAR,
      "Clear the active local agent's transient status in a room.",
      false,
      true,
      true,
    ],
    [TOOL_ROOM_TIMELINE, "Read simplified timeline items from the local cache.", true, true, false],
    [
      TOOL_ROOM_UNREAD,
      "Read unread timeline items, optionally marking them read.",
      false,
      true,
      false,
    ],
    [TOOL_ROOM_MARK_READ, "Mark a room timeline read through a sequence number.", false, true, false],
    [TOOL_INBOX_NEXT, "Read or claim pending actionable inbox items.", false, true, false],
    [TOOL_INBOX_ACK, "Acknowledge, dismiss, or defer inbox items.", false, true, false],
    [
      TOOL_DRAFTS_LIST,
      "List local held drafts that need explicit agent action.",
      true,
      true,
      false,
    ],
    [
      TOOL_DRAFT_GET,
      "Read one local held draft with room changes since it was held.",
      true,
      true,
      false,
    ],
    [TOOL_DRAFT_COMMIT, "Revise, send, or silence a local held draft.", false, false, true],
    [TOOL_DRAFT_DROP, "Drop a local held draft without submitting it.", false, true, false],
    [TOOL_PROFILE_UPDATE, "Sign and submit a profile.update envelope.", false, false, true],
    [TOOL_ROOM_CREATE, "Sign and submit a room.create envelope.", false, false, true],
    [TOOL_ROOM_JOIN_REQUEST, "Create an authenticated room join request.", false, false, true],
    [TOOL_ROOM_JOIN_WHEN_APPROVED, "Sign and submit room.join after approval.", false, true, true],
    [TOOL_ROOM_LEAVE, "Sign and submit room.leave.", false, false, true],
    [TOOL_ROOM_SEND_MESSAGE, "Sign and submit message.create.", false, false, true],
    [TOOL_ROOM_SUBMIT_EVENT, "Sign and submit a room-defined event.", false, false, true],
    [TOOL_JOIN_REQUESTS_LIST, "List visible join requests for a room.", true, false, true],
    [TOOL_JOIN_REQUEST_REVIEW, "Sign and submit room.join.review.", false, false, true],
  ];
  return rows.map(([name, description, readOnly, idempotent, openWorld]) => ({
    name,
    description,
    input_schema: { type: "object" },
    output_schema: { type: "object" },
    annotations: {
      readOnlyHint: readOnly,
      idempotentHint: idempotent,
      destructiveHint: false,
      openWorldHint: openWorld,
    },
  }));
}

export interface SyncState {
  host: string;
  room_id: string;
  head_seq: number;
  remote_head_seq: number;
  head_hash?: string;
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

export type RoomMemberStatus = "active" | "left" | "removed" | "unknown";

export interface RoomMemberProfile {
  name?: string;
  username?: string;
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

export interface RoomSendMessageInput {
  room_id: string;
  content: string;
  content_type?: string;
  mentions?: AgentId[];
  references?: string[];
  extra?: Record<string, unknown>;
  base_seq?: number;
  base_hash?: string;
  on_head_mismatch?: HeadMismatchPolicy;
}

export interface RoomSubmitEventInput {
  room_id: string;
  type: string;
  payload: Record<string, unknown>;
  mentions?: AgentId[];
  references?: string[];
  base_seq?: number;
  base_hash?: string;
  on_head_mismatch?: HeadMismatchPolicy;
}

export interface RoomWriteResult {
  status: "sent" | "held" | "rejected";
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
    remoteHeadSeq?: number;
  } = {},
): SyncState {
  return {
    host: normalizeHost(host),
    room_id: room.id,
    head_seq: room.seq,
    remote_head_seq: options.remoteHeadSeq ?? room.seq,
    head_hash: room.hash,
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

function normalizeHost(host: string): string {
  return host.replace(/\/$/, "");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
