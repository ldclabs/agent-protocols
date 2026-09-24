// Deserialization shapes for each local connector tool call: the parse
// boundary between untyped tool JSON and the typed handlers on LocalConnector.

import {
  JoinDecision,
  RoomPolicy,
  Role,
  TypeDeclaration,
  Visibility,
} from "../discourse.js";
import { DelegationStatus } from "../delegation.js";
import { AgentId } from "../identity.js";

import { invalidPayload } from "./internal.js";
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
 * `room.member.remove`, and `type.define`. For contract and signal writes —
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

/** Source of `agent_protocols_rooms_list`: locally known rooms, or a host's public room discovery. */
export type RoomsListScope = "known" | "public";

export interface RoomsListInput {
  scope?: RoomsListScope;
  /** Filters known rooms; required for `public`, where it names the host. */
  host?: string;
  status?: string;
  /** `known` only. */
  membership?: RoomsListMembership;
  /** `public` only, like the remaining discovery filters. */
  tag?: string;
  keyword?: string;
  creator?: string;
  starts_after?: number;
  ends_before?: number;
  language?: string;
  limit?: number;
  cursor?: string;
}

/** Rejects a filter that belongs to the other scope. */
export function validateRoomsListScope(input: RoomsListInput): void {
  const scope = input.scope ?? "known";
  if (scope !== "known" && scope !== "public") throw invalidPayload(`invalid rooms list scope: ${String(scope)}`);
  if (scope === "known") {
    const publicOnly = [input.tag, input.keyword, input.creator, input.starts_after, input.ends_before, input.language];
    if (publicOnly.some((value) => value !== undefined)) {
      throw invalidPayload("tag, keyword, creator, starts_after, ends_before, and language require scope public");
    }
  } else {
    if (input.membership !== undefined) throw invalidPayload("membership requires scope known");
    if (input.host === undefined) throw invalidPayload("scope public requires host");
  }
}

/** Opens the room on first use (then `host` is required) or when `refresh` is set. */
export interface RoomStateInput {
  room_id: string;
  host?: string;
  refresh?: boolean;
  subscribe?: boolean;
}

export interface RoomMembersListInput {
  room_id: string;
  host?: string;
  /** Narrows the result to one member. */
  agent_id?: AgentId;
  status?: RoomMemberStatus | "all";
  role?: Role;
  include_profiles?: boolean;
  /** With `agent_id`: also return that member's most recent timeline items. */
  include_recent_activity?: boolean;
  limit?: number;
  cursor?: string;
}

export interface AgentStatusListInput {
  room_id: string;
  host?: string;
  agent_id?: AgentId;
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

export interface RoomTimelineInput {
  room_id: string;
  host?: string;
  after_seq?: number;
  before_seq?: number;
  limit?: number;
  types?: string[];
  actors?: AgentId[];
  unread_only?: boolean;
  /** Advances the local read cursor through the last returned item. */
  mark_read?: boolean;
  refresh?: boolean;
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
  /** Reads one draft together with the room changes since its base. */
  draft_id?: string;
  limit?: number;
  cursor?: string;
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
  on_head_mismatch?: HeadMismatchPolicy;
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
  extra?: Record<string, unknown>;
}

export interface RoomJoinInput {
  host?: string;
  room_id: string;
  role: Role;
  perspective?: string;
  reason?: string;
  extra?: Record<string, unknown>;
}

export interface JoinRequestsListInput {
  room_id: string;
  host?: string;
  status?: string;
  limit?: number;
  cursor?: string;
}

export interface PrincipalResolveInput {
  url: string;
}

export interface DelegationCheckInput {
  principal_id: string;
  /** The relying application's origin the delegation must be usable for. */
  audience: string;
  subject?: AgentId;
  id?: string;
}

export interface DelegationsListInput {
  delegation_service: string;
  status?: DelegationStatus;
  limit?: number;
  cursor?: string;
}

export interface DelegationGrantInput {
  id: string;
  principal_id: string;
  subject: AgentId;
  relationship?: string;
  scopes: string[];
  audiences: string[];
  constraints?: Record<string, unknown>;
  not_before?: number;
  expires_at?: number;
}

export interface DelegationRevokeInput {
  id: string;
  principal_id: string;
  reason?: string;
}

export interface JoinRequestReviewInput {
  room_id: string;
  host?: string;
  request_id: string;
  decision: JoinDecision;
  role?: Role;
  reason?: string;
}
