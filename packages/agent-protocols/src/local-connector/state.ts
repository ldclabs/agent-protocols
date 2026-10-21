// In-memory store the connector projects records into. LocalConnectorState
// holds the room, inbox, draft, and mail entries the handlers mutate;
// LocalConnectorSnapshot is its durable form, which LocalConnector.snapshot
// writes with the next nonce.

import {
  AgentStatus,
  ArchiveRecord,
  RoomJoinRequest,
  RoomResponse,
} from "../discourse.js";
import { AgentId } from "../identity.js";
import {
  MailCardCache,
  MailboxCard,
  MailMessagePayload,
  MailPacket,
} from "../mail.js";
import { AgentProfile } from "../profile.js";

import {
  ActiveTurn,
  AgentProtocolsHost,
  HeldDraft,
  InboxItem,
  MailDelivery,
  MailDirection,
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
  /** Presented head for this connector session (local connector Section 4.2). */
  presentedSeq?: number;
  presentedHash?: string;
  syncedSeq: number;
  syncedHash?: string;
  subscribed: boolean;
  watch_types?: string[];
  members: Map<AgentId, RoomMemberView>;
  timeline: TimelineItem[];
  records: ArchiveRecord[];
  readSeq: number;
  activeTurn?: ActiveTurn;
}

export type InboxEntryState =
  | { kind: "pending" }
  | { kind: "claimed"; until: number }
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

/** A received or sent message, kept until it expires. */
export interface StoredMailMessage {
  direction: MailDirection;
  message: MailMessagePayload;
  /** The receiving mailbox, or the recipient's mailbox for a sent message. */
  mailbox_id: string;
  received_at?: number;
  read: boolean;
  /** A sent message's latest packet, retried byte-for-byte. */
  packet?: MailPacket;
  delivery?: MailDelivery;
}

/**
 * Agent Mail state. Decryption keys are not part of it: the connector keeps
 * them apart, for the host's key store.
 */
export class MailState {
  /** The active Agent ID's mailboxes: every card retained until its
   * `receive_until`, in signing order, the last one current. */
  mailboxes = new Map<string, MailboxCard[]>();
  /** Sender-side card pins (Agent Mail Section 3.2). */
  pins = new MailCardCache();
  /** Operator sender policy, applied before decryption. */
  blockedSenders = new Set<AgentId>();
  /** Received and sent messages in local order. */
  messages: StoredMailMessage[] = [];
}

/**
 * Working set the connector projects records into. `hosts` is operator
 * configuration; the room, inbox, and draft maps are the materialized state a
 * host persists through {@link LocalConnector.snapshot}.
 */
export class LocalConnectorState {
  hosts = new Map<string, AgentProtocolsHost>();
  rooms = new Map<string, LocalRoomState>();
  profiles = new Map<AgentId, AgentProfile>();
  /** Join requests visible to this agent as a reviewer, by room key. */
  joinRequests = new Map<string, RoomJoinRequest[]>();
  /** This agent's own join requests, by room key. */
  ownJoinRequests = new Map<string, RoomJoinRequest>();
  agentStatuses = new Map<string, Map<AgentId, AgentStatus>>();
  inbox = new Map<string, InboxEntry>();
  drafts = new Map<string, HeldDraftEntry>();
  mail = new MailState();
}

/** Version of the document {@link LocalConnector.snapshot} produces. */
export const LOCAL_CONNECTOR_SNAPSHOT_VERSION = 2;

/** Persisted form of a {@link LocalRoomState}, with snake_case fields. */
export interface LocalRoomSnapshot {
  host: string;
  room: RoomResponse;
  head_seq: number;
  head_hash?: string;
  presented_seq?: number;
  presented_hash?: string;
  synced_seq: number;
  synced_hash?: string;
  subscribed: boolean;
  watch_types?: string[];
  members: Record<AgentId, RoomMemberView>;
  timeline: TimelineItem[];
  records: ArchiveRecord[];
  read_seq: number;
  active_turn?: ActiveTurn;
}

/**
 * Persisted form of a connector: its Agent ID, next nonce, and every map of
 * {@link LocalConnectorState}. Maps keyed by host and room ID become lists whose
 * entries carry both; the other maps keep their string keys. The Rust SDK's
 * `LocalConnector::snapshot` uses the same layout.
 */
export interface LocalConnectorSnapshot {
  version: number;
  agent_id: AgentId;
  next_nonce: number;
  hosts: Record<string, AgentProtocolsHost>;
  rooms: LocalRoomSnapshot[];
  profiles: Record<AgentId, AgentProfile>;
  join_requests: {
    host: string;
    room_id: string;
    requests: RoomJoinRequest[];
  }[];
  own_join_requests: {
    host: string;
    room_id: string;
    request: RoomJoinRequest;
  }[];
  agent_statuses: {
    host: string;
    room_id: string;
    statuses: Record<AgentId, AgentStatus>;
  }[];
  inbox: Record<string, InboxEntry>;
  drafts: Record<string, HeldDraftEntry>;
  mail: {
    mailboxes: { mailbox_id: string; cards: MailboxCard[] }[];
    pins: MailboxCard[];
    blocked_senders: AgentId[];
    messages: StoredMailMessage[];
  };
}
