// In-memory store the connector projects records into. The public
// LocalConnectorState is the durable snapshot a host persists and restores; the
// room, inbox, and draft entries are the working set the handlers mutate.

import {
  AgentStatus,
  RoomJoinRequestStatus,
  RoomResponse,
  ServerRecord,
} from "../discourse.js";
import { AgentId } from "../identity.js";
import { AgentProfile } from "../profile.js";

import {
  ActiveTurn,
  AgentProtocolsHost,
  HeldDraft,
  InboxItem,
  RoomMemberView,
  TimelineItem,
} from "./views.js";
import { RoomSendMessageInput, RoomSubmitEventInput } from "./inputs.js";

/** `[host, roomId]`. Local room state is keyed by both: ADP room IDs are only
 * recommended to be globally unique and one connector can span hosts. */
export type RoomKey = { host: string; roomId: string };

/** Latest verified head-advancing record and locally applied chain tip. */
export interface LocalRoomState {
  host: string;
  room: RoomResponse;
  headSeq: number;
  headHash?: string;
  syncedSeq: number;
  syncedHash?: string;
  subscribed: boolean;
  members: Map<AgentId, RoomMemberView>;
  timeline: TimelineItem[];
  records: ServerRecord[];
  readSeq: number;
  activeTurn?: ActiveTurn;
}

export type InboxEntryState =
  | { kind: "pending" }
  | { kind: "claimed" }
  | { kind: "deferred"; until: number }
  | { kind: "acknowledged" };

export interface InboxEntry {
  item: InboxItem;
  state: InboxEntryState;
}

export type HeldDraftRequest =
  | { kind: "message"; input: RoomSendMessageInput }
  | { kind: "event"; input: RoomSubmitEventInput };

export interface HeldDraftEntry {
  draft: HeldDraft;
  request: HeldDraftRequest;
}

/**
 * Durable working set the connector projects records into. `hosts` is operator
 * configuration; the room, inbox, and draft maps are the materialized state a
 * host persists and restores through {@link LocalConnector} `state`.
 */
export class LocalConnectorState {
  hosts = new Map<string, AgentProtocolsHost>();
  rooms = new Map<string, LocalRoomState>();
  profiles = new Map<AgentId, AgentProfile>();
  joinRequests = new Map<string, RoomJoinRequestStatus[]>();
  agentStatuses = new Map<string, Map<AgentId, AgentStatus>>();
  inbox = new Map<string, InboxEntry>();
  drafts = new Map<string, HeldDraftEntry>();
}
