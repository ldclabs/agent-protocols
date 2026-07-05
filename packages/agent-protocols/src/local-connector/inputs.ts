// Deserialization shapes for each local connector tool call: the parse
// boundary between untyped tool JSON and the typed handlers on LocalConnector.

import {
  JoinDecision,
  RoomPolicy,
  Role,
  TypeDeclaration,
  Visibility,
} from "../discourse.js";
import { AgentId } from "../identity.js";

import {
  DraftAction,
  HeadMismatchPolicy,
  RoomMemberStatus,
  RoomsListMembership,
} from "./views.js";

export interface RoomSendMessageInput {
  room_id: string;
  /** Disambiguates when `room_id` matches rooms on more than one host. */
  host?: string;
  content: string;
  content_type?: string;
  mentions?: AgentId[];
  references?: string[];
  extra?: Record<string, unknown>;
  base_seq?: number;
  base_hash?: string;
  on_head_mismatch?: HeadMismatchPolicy;
}

/**
 * Also covers the built-in events without a dedicated tool: `room.update`,
 * `room.close`, `room.cancel`, `room.member.role.update`,
 * `room.member.remove`, and `type.define`. For `signal`-kind writes —
 * including the membership events — the base is only an anchor: the connector
 * never holds the draft and ignores `on_head_mismatch`.
 */
export interface RoomSubmitEventInput {
  room_id: string;
  /** Disambiguates when `room_id` matches rooms on more than one host. */
  host?: string;
  type: string;
  payload: Record<string, unknown>;
  mentions?: AgentId[];
  references?: string[];
  base_seq?: number;
  base_hash?: string;
  on_head_mismatch?: HeadMismatchPolicy;
}

export interface RoomsSearchInput {
  host: string;
  status?: string;
  tag?: string;
  keyword?: string;
  creator?: string;
  starts_after?: number;
  ends_before?: number;
  language?: string;
  limit?: number;
  cursor?: string;
}

export interface RoomsListInput {
  status?: string;
  membership?: RoomsListMembership;
  limit?: number;
  cursor?: string;
}

export interface RoomOpenInput {
  host: string;
  room_id: string;
  subscribe?: boolean;
  refresh?: boolean;
}

export interface RoomStateInput {
  room_id: string;
  host?: string;
  refresh?: boolean;
  include_types?: boolean;
}

export interface RoomMembersListInput {
  room_id: string;
  host?: string;
  status?: RoomMemberStatus;
  role?: Role;
  include_profiles?: boolean;
  limit?: number;
  cursor?: string;
}

export interface RoomMemberGetInput {
  room_id: string;
  host?: string;
  agent_id: AgentId;
  include_profile?: boolean;
  include_recent_activity?: boolean;
}

export interface AgentStatusListInput {
  room_id: string;
  host?: string;
  refresh?: boolean;
}

export interface AgentStatusGetInput {
  room_id: string;
  host?: string;
  agent_id: AgentId;
  refresh?: boolean;
}

export interface AgentStatusSetInput {
  room_id: string;
  host?: string;
  state: string;
  summary?: string;
  seen_seq?: number;
  seen_hash?: string;
  claim_id?: string;
  activity?: string;
  expires_at?: number;
  extra?: Record<string, unknown>;
}

export interface AgentStatusClearInput {
  room_id: string;
  host?: string;
}

export interface RoomTimelineInput {
  room_id: string;
  host?: string;
  after_seq?: number;
  before_seq?: number;
  limit?: number;
  types?: string[];
  actors?: AgentId[];
  unread_only?: boolean;
  refresh?: boolean;
  include_records?: boolean;
}

export interface RoomUnreadInput {
  room_id: string;
  host?: string;
  limit?: number;
  mark_read?: boolean;
}

export interface RoomMarkReadInput {
  room_id: string;
  host?: string;
  through_seq: number;
}

export interface InboxNextInput {
  room_id?: string;
  kinds?: string[];
  limit?: number;
  wait_ms?: number;
  claim?: boolean;
}

export type InboxAckAction = "handled" | "dismissed" | "defer";

export interface InboxAckInput {
  ids: string[];
  action: InboxAckAction;
  defer_until?: number;
}

export interface DraftsListInput {
  room_id?: string;
  host?: string;
  limit?: number;
  cursor?: string;
}

export interface DraftGetInput {
  draft_id: string;
}

export interface DraftCommitInput {
  draft_id: string;
  action: DraftAction;
  content?: string;
  content_type?: string;
  mentions?: AgentId[];
  references?: string[];
  extra?: Record<string, unknown>;
  /** Replacement event type on `revise` for an event draft. */
  type?: string;
  payload?: Record<string, unknown>;
  base_seq?: number;
  base_hash?: string;
  on_head_mismatch?: HeadMismatchPolicy;
}

export interface DraftDropInput {
  draft_id: string;
}

export interface ProfileUpdateInput {
  profile_service: string;
  profile: Record<string, unknown>;
}

export interface RoomCreateInput {
  host: string;
  topic: string;
  visibility: Visibility;
  start_time: number;
  end_time: number;
  agenda?: string;
  guidance?: string;
  tags?: string[];
  language?: string;
  policy?: RoomPolicy;
  types?: TypeDeclaration[];
}

export interface RoomJoinInput {
  host?: string;
  room_id: string;
  role: Role;
  perspective?: string;
  reason?: string;
  request_id?: string;
  extra?: Record<string, unknown>;
}

export interface RoomJoinRequestToolInput {
  host: string;
  room_id: string;
  role: Role;
  perspective?: string;
  reason?: string;
  extra?: Record<string, unknown>;
}

export interface RoomJoinWhenApprovedInput {
  room_id: string;
  host?: string;
  request_id: string;
}

export interface RoomLeaveInput {
  room_id: string;
  host?: string;
  reason?: string;
}

export interface JoinRequestsListInput {
  room_id: string;
  host?: string;
  status?: string;
  limit?: number;
  cursor?: string;
}

export interface JoinRequestReviewInput {
  room_id: string;
  host?: string;
  request_id: string;
  decision: JoinDecision;
  role?: Role;
  reason?: string;
}
