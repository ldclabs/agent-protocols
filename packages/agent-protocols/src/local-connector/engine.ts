// The stateful local connector engine. `LocalConnector` is transport-neutral:
// it signs on the active agent's behalf, calls Agent Protocols services over
// HTTP, materializes local room state by projecting accepted records, derives
// an actionable inbox, tracks the head presented to the agent, and holds
// head-bound drafts on a room-head mismatch — all behind a single `callTool`
// dispatcher. The agent never sees the signing key or a reusable request JWT.
// This is one deep module; its methods are mutually recursive over `this`, so
// the class stays whole here while the data shapes and pure projection live in
// sibling submodules.

import {
  AgentStatus,
  AgentStatusInput,
  ArchiveRecord,
  MessageCreatePayload,
  RoomCreatePayload,
  RoomJoinPayload,
  RoomJoinRequest,
  RoomJoinRequestPayload,
  RoomJoinReviewPayload,
  RoomMemberRemovePayload,
  RoomPolicy,
  RoomResponse,
  ServerRecord,
  Visibility,
  canJoinDirectly,
  discourseEvent,
  eventType,
  isRedactedRecord,
  roomCreateEvent,
  roomJoinRequestEvent,
  validateDiscourseEnvelope,
  validateRoomPath,
  verifyServerRecord,
} from "../discourse.js";
import { base64UrlDecodeCanonical, base64UrlEncode } from "../encoding.js";
import {
  AgentId,
  AgentSigner,
  ClientNonceManager,
  DEFAULT_REQUEST_JWT_TTL_SECS,
  Envelope,
  createEvent,
  createRequestBinding,
  createRequestJwtClaims,
  publicKeyBytes,
  serviceOrigin,
  unixTimeMillis,
  unixTimeSecs,
  validateOrigin,
  withMentions,
} from "../identity.js";
import {
  DelegationClient,
  DiscourseClient,
  FetchLike,
  HttpResponseError,
  KnowledgeClient,
  ProfileClient,
} from "../http-client.js";
import {
  KNOWLEDGE_EVENT_TYPES,
  KNOWLEDGE_PROTOCOL,
  KnowledgePageTracker,
  validateKnowledgeEnvelope,
  validateKnowledgeId,
  type KnowledgeEnvelope,
  type KnowledgeQuery,
  type KnowledgeQueryResponse,
  type KnowledgeRecord,
} from "../knowledge.js";
import {
  MAIL_MAX_TTL_MS,
  MailCardCache,
  MailEncryptionKey,
  MailKeyring,
  createMailMessage,
  mailboxPublishEvent,
  mailTextPart,
  newMailId,
  parseMailAddress,
  sealMailPacket,
  validateMailboxCard,
  validateMailReply,
  validateMailSenderCard,
  type MailboxCard,
  type MailboxCardPayload,
  type MailMessagePayload,
  type MailPacketRecord,
} from "../mail.js";
import { MailClient } from "../mail-client.js";
import {
  DelegationCredential,
  DelegationGrantPayload,
  DelegationPayload,
  DelegationVerdict,
  PrincipalDocument,
  delegationGrantEvent,
  delegationRevokeEvent,
  isPrincipalAlias,
  validateDelegationEventAuthority,
  verifyDelegationCredential,
} from "../delegation.js";
import {
  AgentProfile,
  ProfileUpdatePayload,
  profileUpdateEvent,
} from "../profile.js";

import {
  TOOL_AGENT_STATUS_LIST,
  TOOL_AGENT_STATUS_SET,
  TOOL_DELEGATIONS_LIST,
  TOOL_DELEGATION_CHECK,
  TOOL_DELEGATION_GRANT,
  TOOL_DELEGATION_REVOKE,
  TOOL_DRAFTS_LIST,
  TOOL_DRAFT_COMMIT,
  TOOL_IDENTITY_CURRENT,
  TOOL_INBOX_ACK,
  TOOL_INBOX_NEXT,
  TOOL_JOIN_REQUESTS_LIST,
  TOOL_JOIN_REQUEST_REVIEW,
  TOOL_KNOWLEDGE_GET,
  TOOL_KNOWLEDGE_QUERY,
  TOOL_KNOWLEDGE_SEARCH,
  TOOL_KNOWLEDGE_STATUS,
  TOOL_KNOWLEDGE_SUBMIT,
  TOOL_MAIL_LIST,
  TOOL_MAIL_MAILBOXES_LIST,
  TOOL_MAIL_MAILBOX_PUBLISH,
  TOOL_MAIL_SEND,
  TOOL_MAIL_SYNC,
  TOOL_PRINCIPAL_RESOLVE,
  TOOL_PROFILE_UPDATE,
  TOOL_ROOMS_LIST,
  TOOL_ROOM_CREATE,
  TOOL_ROOM_JOIN,
  TOOL_ROOM_MEMBERS_LIST,
  TOOL_ROOM_SEND_MESSAGE,
  TOOL_ROOM_STATE,
  TOOL_ROOM_SUBMIT_EVENT,
  TOOL_ROOM_TIMELINE,
} from "./catalog.js";
import {
  invalidPayload,
  isRecord,
  normalizeHost,
  permissionDenied,
} from "./internal.js";
import {
  AgentStatusListInput,
  AgentStatusSetInput,
  DelegationCheckInput,
  DelegationGrantInput,
  DelegationRevokeInput,
  DelegationsListInput,
  DraftCommitInput,
  DraftsListInput,
  InboxAckInput,
  InboxNextInput,
  JoinRequestReviewInput,
  JoinRequestsListInput,
  KnowledgeGetInput,
  KnowledgeQueryInput,
  KnowledgeSearchInput,
  KnowledgeStatusInput,
  KnowledgeSubmitInput,
  MailListInput,
  MailMailboxPublishInput,
  MailSendInput,
  MailSyncInput,
  PrincipalResolveInput,
  ProfileUpdateInput,
  RoomCreateInput,
  RoomJoinInput,
  RoomMembersListInput,
  RoomSendMessageInput,
  RoomStateInput,
  RoomSubmitEventInput,
  RoomTimelineInput,
  RoomsListInput,
  validateRoomsListScope,
} from "./inputs.js";
import {
  applyRecordProjection,
  baseIsCurrent,
  eventTypeRequiresRoomHead,
  inboxEntryReady,
  isDuplicateRecord,
  materializeCreator,
  membershipFilter,
  recordAdvancesRoomHead,
  validateNextRecord,
  validateRecordBasePrecondition,
} from "./projection.js";
import { protocolError } from "../errors.js";
import {
  HeldDraftRequest,
  LOCAL_CONNECTOR_SNAPSHOT_VERSION,
  LocalConnectorSnapshot,
  LocalConnectorState,
  LocalRoomSnapshot,
  LocalRoomState,
  RoomKey,
  StoredMailMessage,
} from "./state.js";
import {
  checkedRoutes,
  errorJson,
  isQueued,
  isTransient,
  isUnread,
  knowledgeItem,
  mailInboxItem,
  mailMessageView,
  mailboxView,
  routeError,
  sameMessage,
  scoped,
} from "./services.js";
import {
  AgentProtocolsHost,
  DraftAction,
  HeadMismatchPolicy,
  HeldDraft,
  InboxItem,
  MailboxView,
  MailMessageView,
  RouteError,
  RoomMemberProfile,
  RoomStateView,
  RoomSummary,
  RoomWriteResult,
  SyncState,
  TimelineItem,
  roomSummaryFromResponse,
  timelineItemFromRecord,
} from "./views.js";

/** Automatic `send_anyway` re-sign attempts before a draft is held. */
export const SEND_ANYWAY_MAX_ATTEMPTS = 3;
/** Lease on an inbox item claimed with `claim: true`. */
export const INBOX_CLAIM_LEASE_MS = 60_000;
/** `max_packet_bytes` of a new mailbox. */
const DEFAULT_MAX_PACKET_BYTES = 262_144;
/** Default message lifetime, bounded by the card's `receive_until`. */
const MESSAGE_TTL_MS = 7 * 86_400_000;
/** Packet list pages read per mailbox route in one sync. */
const SYNC_MAX_PAGES = 10;
const SYNC_PAGE_LIMIT = 100;
const MAX_KNOWLEDGE_SERVICES = 8;
/** Reverse-link query pages a status check reads before reporting `complete: false`. */
const STATUS_MAX_PAGES = 10;
const STATUS_PAGE_LIMIT = 1000;

function roomKeyString(key: RoomKey): string {
  return `${key.host} ${key.roomId}`;
}

function roomKeyFromString(key: string): { host: string; room_id: string } {
  const space = key.indexOf(" ");
  return { host: key.slice(0, space), room_id: key.slice(space + 1) };
}

function newLocalRoomState(host: string, room: RoomResponse): LocalRoomState {
  return {
    host,
    room,
    headSeq: 0,
    syncedSeq: 0,
    subscribed: false,
    members: new Map(),
    timeline: [],
    records: [],
    readSeq: 0,
  };
}

function roomToSnapshot(room: LocalRoomState): LocalRoomSnapshot {
  return {
    host: room.host,
    room: room.room,
    head_seq: room.headSeq,
    head_hash: room.headHash,
    presented_seq: room.presentedSeq,
    presented_hash: room.presentedHash,
    synced_seq: room.syncedSeq,
    synced_hash: room.syncedHash,
    subscribed: room.subscribed,
    members: Object.fromEntries(room.members),
    timeline: room.timeline,
    records: room.records,
    read_seq: room.readSeq,
    active_turn: room.activeTurn,
  };
}

function roomFromSnapshot(room: LocalRoomSnapshot): LocalRoomState {
  return {
    host: room.host,
    room: room.room,
    headSeq: room.head_seq,
    headHash: room.head_hash,
    presentedSeq: room.presented_seq,
    presentedHash: room.presented_hash,
    syncedSeq: room.synced_seq,
    syncedHash: room.synced_hash,
    subscribed: room.subscribed,
    members: new Map(Object.entries(room.members)),
    timeline: room.timeline,
    records: room.records,
    readSeq: room.read_seq,
    activeTurn: room.active_turn,
  };
}

function unreadCount(room: LocalRoomState): number {
  return room.timeline.filter((item) => item.seq > room.readSeq).length;
}

// ── Room metadata getters: prefer the host-materialized value, fall back to
// the signed room.create payload (older hosts may omit derived fields).

function roomCreatePayload(room: RoomResponse): RoomCreatePayload | undefined {
  return room.envelope?.event.payload;
}

function roomTopic(room: RoomResponse): string | undefined {
  return room.topic ?? roomCreatePayload(room)?.topic;
}

function roomAgenda(room: RoomResponse): string | undefined {
  return room.agenda ?? roomCreatePayload(room)?.agenda;
}

function roomGuidance(room: RoomResponse): string | undefined {
  return room.guidance ?? roomCreatePayload(room)?.guidance;
}

function roomVisibility(room: RoomResponse): Visibility | undefined {
  return room.visibility ?? roomCreatePayload(room)?.visibility;
}

function roomStartTime(room: RoomResponse): number | undefined {
  return room.start_time ?? roomCreatePayload(room)?.start_time;
}

function roomEndTime(room: RoomResponse): number | undefined {
  return room.end_time ?? roomCreatePayload(room)?.end_time;
}

function roomTags(room: RoomResponse): string[] {
  if (room.tags && room.tags.length > 0) return room.tags;
  return roomCreatePayload(room)?.tags ?? [];
}

function roomLanguage(room: RoomResponse): string | undefined {
  return room.language ?? roomCreatePayload(room)?.language;
}

function roomPolicy(room: RoomResponse): RoomPolicy | undefined {
  return room.policy ?? roomCreatePayload(room)?.policy;
}

function roomResponseHead(room: RoomResponse): [number, string] {
  return room.head ? [room.head.seq, room.head.hash] : [room.seq, room.hash];
}

function payloadWithReferences(
  payload: Record<string, unknown>,
  references: string[],
): Record<string, unknown> {
  if (references.length === 0) return payload;
  const extra = isRecord(payload.extra) ? payload.extra : {};
  extra.references = references;
  payload.extra = extra;
  return payload;
}

function messageDraftValue(input: RoomSendMessageInput): unknown {
  return {
    room_id: input.room_id,
    content: input.content,
    content_type: input.content_type ?? "text/plain",
    mentions: input.mentions ?? [],
    references: input.references ?? [],
    extra: input.extra ?? {},
  };
}

function eventDraftValue(input: RoomSubmitEventInput): unknown {
  return {
    room_id: input.room_id,
    type: input.type,
    payload: input.payload,
    mentions: input.mentions ?? [],
    references: input.references ?? [],
  };
}

function heldDraftOptions(): DraftAction[] {
  return ["revise", "send", "drop"];
}

function profileToMemberProfile(profile: AgentProfile): RoomMemberProfile {
  return {
    name: profile.name,
    description: profile.description,
    avatar_url: profile.avatar_url,
  };
}

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function parseCursor(cursor: string | undefined): number {
  if (cursor === undefined) return 0;
  const parsed = Number.parseInt(cursor, 10);
  return Number.isNaN(parsed) ? 0 : parsed;
}

/** Offset-cursor page over a sorted list, with `next_cursor` when more follow. */
function page<T>(items: T[], cursor: string | undefined, limit: number): { items: T[]; next_cursor?: string } {
  const offset = parseCursor(cursor);
  const slice = items.slice(offset, offset + limit);
  return offset + limit < items.length
    ? { items: slice, next_cursor: String(offset + limit) }
    : { items: slice };
}

function sortedAgentStatuses(
  statuses: Map<AgentId, AgentStatus>,
): AgentStatus[] {
  return [...statuses.entries()]
    .sort((a, b) => compareStrings(a[0], b[0]))
    .map(([, status]) => status);
}

function isHttpError(error: unknown, code: string): error is HttpResponseError {
  return error instanceof HttpResponseError && error.code === code;
}

export interface LocalConnectorOptions {
  /** Restore a previously persisted working set. Defaults to empty. */
  state?: LocalConnectorState;
  /** Injected `fetch`, e.g. for tests or a custom transport. */
  fetchImpl?: FetchLike;
}

export class LocalConnector {
  readonly state: LocalConnectorState;
  private nonces = new ClientNonceManager();
  private readonly fetchImpl: FetchLike;
  /** Discourse clients built from each host's discovery document, once per session. */
  private readonly discourseClients = new Map<string, DiscourseClient>();
  /** Knowledge clients built from each service's discovery document, once per session. */
  private readonly knowledgeClients = new Map<string, KnowledgeClient>();
  /** Agent Mail decryption keys by public key: key-store material, never in the snapshot. */
  private readonly mailKeys = new Map<string, MailEncryptionKey>();

  constructor(
    private readonly signer: AgentSigner,
    options: LocalConnectorOptions = {},
  ) {
    this.state = options.state ?? new LocalConnectorState();
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  /**
   * Restores a connector from {@link LocalConnector.snapshot}. The snapshot is
   * trusted local state, so only its version, Agent ID, and shape are checked;
   * it must belong to `signer`'s Agent ID.
   */
  static fromSnapshot(
    signer: AgentSigner,
    snapshot: LocalConnectorSnapshot,
    options: Omit<LocalConnectorOptions, "state"> = {},
  ): LocalConnector {
    const doc = JSON.parse(JSON.stringify(snapshot)) as LocalConnectorSnapshot;
    if (!isRecord(doc) || doc.version !== LOCAL_CONNECTOR_SNAPSHOT_VERSION) {
      throw protocolError("invalid_request", "unsupported local connector snapshot version");
    }
    if (doc.agent_id !== signer.agentId()) {
      throw protocolError("invalid_request", "local connector snapshot belongs to another Agent ID");
    }
    const maps = [doc.hosts, doc.profiles, doc.inbox, doc.drafts, doc.mail];
    const lists = [doc.rooms, doc.join_requests, doc.own_join_requests, doc.agent_statuses];
    const mail = [doc.mail?.mailboxes, doc.mail?.pins, doc.mail?.blocked_senders, doc.mail?.messages];
    if (!maps.every(isRecord) || !lists.every(Array.isArray) || !mail.every(Array.isArray)) {
      throw protocolError("invalid_request", "malformed local connector snapshot");
    }
    const nonces = new ClientNonceManager(doc.next_nonce);
    const state = new LocalConnectorState();
    state.hosts = new Map(Object.entries(doc.hosts));
    for (const room of doc.rooms) {
      state.rooms.set(roomKeyString({ host: room.host, roomId: room.room.id }), roomFromSnapshot(room));
    }
    state.profiles = new Map(Object.entries(doc.profiles));
    for (const entry of doc.join_requests) {
      state.joinRequests.set(roomKeyString({ host: entry.host, roomId: entry.room_id }), entry.requests);
    }
    for (const entry of doc.own_join_requests) {
      state.ownJoinRequests.set(roomKeyString({ host: entry.host, roomId: entry.room_id }), entry.request);
    }
    for (const entry of doc.agent_statuses) {
      state.agentStatuses.set(
        roomKeyString({ host: entry.host, roomId: entry.room_id }),
        new Map(Object.entries(entry.statuses)),
      );
    }
    state.inbox = new Map(Object.entries(doc.inbox));
    state.drafts = new Map(Object.entries(doc.drafts));
    for (const box of doc.mail.mailboxes) state.mail.mailboxes.set(box.mailbox_id, box.cards);
    state.mail.pins = new MailCardCache({ version: 1, pins: doc.mail.pins });
    state.mail.blockedSenders = new Set(doc.mail.blocked_senders);
    state.mail.messages = doc.mail.messages;
    const connector = new LocalConnector(signer, { ...options, state });
    connector.nonces = nonces;
    return connector;
  }

  /**
   * The durable state local connector Section 4.1 requires a host to persist:
   * the next nonce, hosts, rooms with their records, members, timeline, read
   * and presented heads, join requests, agent statuses, profiles, the inbox
   * with its leases, held drafts, and mail state (mailbox cards, card pins,
   * blocked senders, and messages). Save it after every tool call and restore
   * it with {@link LocalConnector.fromSnapshot}. It holds private
   * correspondence and room content but no keys.
   */
  snapshot(): LocalConnectorSnapshot {
    const doc: LocalConnectorSnapshot = {
      version: LOCAL_CONNECTOR_SNAPSHOT_VERSION,
      agent_id: this.agentId(),
      next_nonce: this.nonces.peek(),
      hosts: Object.fromEntries(this.state.hosts),
      rooms: [...this.state.rooms.values()].map(roomToSnapshot),
      profiles: Object.fromEntries(this.state.profiles),
      join_requests: [...this.state.joinRequests].map(([key, requests]) => ({ ...roomKeyFromString(key), requests })),
      own_join_requests: [...this.state.ownJoinRequests].map(([key, request]) => ({ ...roomKeyFromString(key), request })),
      agent_statuses: [...this.state.agentStatuses].map(([key, statuses]) => ({
        ...roomKeyFromString(key),
        statuses: Object.fromEntries(statuses),
      })),
      inbox: Object.fromEntries(this.state.inbox),
      drafts: Object.fromEntries(this.state.drafts),
      mail: {
        mailboxes: [...this.state.mail.mailboxes.entries()]
          .sort((a, b) => compareStrings(a[0], b[0]))
          .map(([mailbox_id, cards]) => ({ mailbox_id, cards })),
        pins: this.state.mail.pins.snapshot().pins,
        blocked_senders: [...this.state.mail.blockedSenders].sort(compareStrings),
        messages: this.state.mail.messages,
      },
    };
    return JSON.parse(JSON.stringify(doc)) as LocalConnectorSnapshot;
  }

  /**
   * SENSITIVE: the Agent Mail decryption keys of the mailboxes' retained
   * cards, as `{ version, agent_id, keys: { public_key: secret } }`. Keep it in
   * the key store, apart from {@link LocalConnector.snapshot}; save it after a
   * mailbox publish and restore it with {@link LocalConnector.restoreMailKeys}.
   */
  mailKeysSnapshot(): { version: 1; agent_id: AgentId; keys: Record<string, string> } {
    const keys: Record<string, string> = {};
    for (const [publicKey, key] of [...this.mailKeys.entries()].sort((a, b) => compareStrings(a[0], b[0]))) {
      keys[publicKey] = base64UrlEncode(key.exportSecret());
    }
    return { version: 1, agent_id: this.agentId(), keys };
  }

  /** Restores {@link LocalConnector.mailKeysSnapshot}; every secret must match its public key. */
  restoreMailKeys(value: { version: number; agent_id: AgentId; keys: Record<string, string> }): void {
    if (!isRecord(value) || value.version !== 1 || value.agent_id !== this.agentId() || !isRecord(value.keys)) {
      throw protocolError("invalid_request", "mail keys belong to another version or Agent ID");
    }
    for (const [publicKey, secret] of Object.entries(value.keys)) {
      const bytes = typeof secret === "string" ? base64UrlDecodeCanonical(secret) : undefined;
      if (bytes === undefined) throw protocolError("invalid_private_key", "malformed mail key");
      const key = MailEncryptionKey.fromBytes(bytes);
      bytes.fill(0);
      if (key.publicKey() !== publicKey) {
        throw protocolError("invalid_private_key", "mail key does not match its public key");
      }
      this.mailKeys.set(publicKey, key);
    }
  }

  /** Operator sender policy (Agent Mail Section 7.2): packets from a blocked sender are deleted unopened. No tool changes it. */
  setMailSenderBlocked(sender: AgentId, blocked: boolean): void {
    if (blocked) this.state.mail.blockedSenders.add(sender);
    else this.state.mail.blockedSenders.delete(sender);
  }

  agentId(): AgentId {
    return this.signer.agentId();
  }

  addHost(host: AgentProtocolsHost): void {
    this.state.hosts.set(normalizeHost(host.host), host);
  }

  observeRoom(host: string, room: RoomResponse): void {
    const normalized = normalizeHost(host);
    this.ensureHost(normalized);
    const key: RoomKey = { host: normalized, roomId: room.id };
    const keyStr = roomKeyString(key);
    let entry = this.state.rooms.get(keyStr);
    if (!entry) {
      entry = newLocalRoomState(normalized, room);
      this.state.rooms.set(keyStr, entry);
    }
    entry.host = normalized;
    entry.room = room;
    materializeCreator(entry);
  }

  acceptRoomResponse(host: string, room: RoomResponse): void {
    const normalized = normalizeHost(host);
    const key: RoomKey = { host: normalized, roomId: room.id };
    this.observeRoom(normalized, room);
    const entry = this.state.rooms.get(roomKeyString(key));
    if (entry) {
      const [headSeq, headHash] = roomResponseHead(entry.room);
      entry.headSeq = headSeq;
      entry.headHash = headHash;
      entry.syncedSeq = entry.room.seq;
      entry.syncedHash = entry.room.hash;
    }
  }

  /** Applies a verified record to the room named by its `room_id` alone. Throws
   * an ambiguity error when the room ID is open on more than one host. */
  applyRecord(record: ArchiveRecord): void {
    const key = this.resolveRoomKey(undefined, record.room_id);
    this.applyRecordTo(key, record);
  }

  /** Applies a verified record to the room on the given host. */
  applyHostRecord(host: string, record: ArchiveRecord): void {
    const key: RoomKey = { host: normalizeHost(host), roomId: record.room_id };
    this.applyRecordTo(key, record);
  }

  private applyRecordTo(key: RoomKey, record: ArchiveRecord): void {
    if (!isRedactedRecord(record)) {
      validateDiscourseEnvelope(record.envelope);
      validateRoomPath(record.envelope, record.room_id);
    }
    verifyServerRecord(record);

    const activeAgent = this.agentId();
    const room = this.state.rooms.get(roomKeyString(key));
    if (!room) {
      throw invalidPayload(`room is not open locally: ${key.roomId}`);
    }
    if (isDuplicateRecord(room, record)) return;
    validateNextRecord(room, record);
    validateRecordBasePrecondition(room, record);

    const item = timelineItemFromRecord(record, room.room.types ?? []);
    const newInbox: InboxItem[] = [];
    applyRecordProjection(room, record, item, activeAgent, newInbox);

    let clearedStatus: AgentId | undefined;
    if (!isRedactedRecord(record) && record.envelope.event.type === eventType.ROOM_MEMBER_REMOVE) {
      const payload = record.envelope.event.payload as RoomMemberRemovePayload;
      clearedStatus = payload?.member;
    }
    if (recordAdvancesRoomHead(room, record)) {
      room.headSeq = record.seq;
      room.headHash = record.hash;
    }
    room.syncedSeq = record.seq;
    room.syncedHash = record.hash;
    room.records.push(record);
    room.timeline.push(item);

    // Removal ends membership; the host clears the member's transient status,
    // so drop the local cache entry too.
    if (clearedStatus !== undefined) {
      this.state.agentStatuses.get(roomKeyString(key))?.delete(clearedStatus);
    }
    for (const inboxItem of newInbox) this.insertInbox(inboxItem);
  }

  private resolveRoomKey(
    host: string | undefined,
    roomId: string,
  ): RoomKey {
    if (host !== undefined) return { host: normalizeHost(host), roomId };
    const hosts = [...this.state.rooms.values()]
      .filter((room) => room.room.id === roomId)
      .map((room) => room.host);
    if (hosts.length === 1) return { host: hosts[0], roomId };
    if (hosts.length > 1) {
      throw invalidPayload(
        `room id ${roomId} matches rooms on more than one host; pass host`,
      );
    }
    throw invalidPayload(`room is not open locally: ${roomId}`);
  }

  async callTool(name: string, input: unknown): Promise<unknown> {
    switch (name) {
      case TOOL_IDENTITY_CURRENT:
        return this.identityCurrent();
      case TOOL_PRINCIPAL_RESOLVE:
        return this.principalResolve(input as PrincipalResolveInput);
      case TOOL_DELEGATION_CHECK:
        return this.delegationCheck(input as DelegationCheckInput);
      case TOOL_DELEGATIONS_LIST:
        return this.delegationsList(input as DelegationsListInput);
      case TOOL_DELEGATION_GRANT:
        return this.delegationGrant(input as DelegationGrantInput);
      case TOOL_DELEGATION_REVOKE:
        return this.delegationRevoke(input as DelegationRevokeInput);
      case TOOL_ROOMS_LIST:
        return this.roomsList(input as RoomsListInput);
      case TOOL_ROOM_STATE:
        return this.roomState(input as RoomStateInput);
      case TOOL_ROOM_MEMBERS_LIST:
        return this.roomMembersList(input as RoomMembersListInput);
      case TOOL_AGENT_STATUS_LIST:
        return this.agentStatusList(input as AgentStatusListInput);
      case TOOL_AGENT_STATUS_SET:
        return this.agentStatusSet(input as AgentStatusSetInput);
      case TOOL_ROOM_TIMELINE:
        return this.roomTimeline(input as RoomTimelineInput);
      case TOOL_INBOX_NEXT:
        return this.inboxNext(input as InboxNextInput);
      case TOOL_INBOX_ACK:
        return this.inboxAck(input as InboxAckInput);
      case TOOL_DRAFTS_LIST:
        return this.draftsList(input as DraftsListInput);
      case TOOL_DRAFT_COMMIT:
        return this.draftCommit(input as DraftCommitInput);
      case TOOL_PROFILE_UPDATE:
        return this.profileUpdate(input as ProfileUpdateInput);
      case TOOL_ROOM_CREATE:
        return this.roomCreate(input as RoomCreateInput);
      case TOOL_ROOM_JOIN:
        return this.roomJoin(input as RoomJoinInput);
      case TOOL_ROOM_SEND_MESSAGE:
        return this.roomSendMessage(input as RoomSendMessageInput);
      case TOOL_ROOM_SUBMIT_EVENT:
        return this.roomSubmitEvent(input as RoomSubmitEventInput);
      case TOOL_JOIN_REQUESTS_LIST:
        return this.joinRequestsList(input as JoinRequestsListInput);
      case TOOL_JOIN_REQUEST_REVIEW:
        return this.joinRequestReview(input as JoinRequestReviewInput);
      case TOOL_MAIL_MAILBOXES_LIST:
        return this.mailMailboxesList();
      case TOOL_MAIL_MAILBOX_PUBLISH:
        return this.mailMailboxPublish(input as MailMailboxPublishInput);
      case TOOL_MAIL_SEND:
        return this.mailSend(input as MailSendInput);
      case TOOL_MAIL_SYNC:
        return this.mailSync((input ?? {}) as MailSyncInput);
      case TOOL_MAIL_LIST:
        return this.mailList((input ?? {}) as MailListInput);
      case TOOL_KNOWLEDGE_SUBMIT:
        return this.knowledgeSubmit(input as KnowledgeSubmitInput);
      case TOOL_KNOWLEDGE_QUERY:
        return this.knowledgeQuery(input as KnowledgeQueryInput);
      case TOOL_KNOWLEDGE_GET:
        return this.knowledgeGet(input as KnowledgeGetInput);
      case TOOL_KNOWLEDGE_SEARCH:
        return this.knowledgeSearch(input as KnowledgeSearchInput);
      case TOOL_KNOWLEDGE_STATUS:
        return this.knowledgeStatus(input as KnowledgeStatusInput);
      default:
        throw invalidPayload(`unknown local connector tool: ${name}`);
    }
  }

  private identityCurrent(): unknown {
    const agentId = this.agentId();
    return {
      agent_id: agentId,
      public_key: base64UrlEncode(publicKeyBytes(agentId)),
      profiles: [...this.state.profiles.keys()].sort(compareStrings),
      hosts: this.sortedHosts(),
    };
  }

  private async roomsList(input: RoomsListInput): Promise<unknown> {
    validateRoomsListScope(input);
    return (input.scope ?? "known") === "public" ? this.publicRooms(input) : this.knownRooms(input);
  }

  private async publicRooms(input: RoomsListInput): Promise<unknown> {
    const host = normalizeHost(input.host!);
    this.requireAllowedHost(host);
    const response = await (await this.discourse(host)).publicRooms({
      status: input.status,
      tag: input.tag,
      keyword: input.keyword,
      creator: input.creator,
      startsAfter: input.starts_after,
      endsBefore: input.ends_before,
      language: input.language,
      limit: input.limit,
      cursor: input.cursor,
    });
    for (const room of response.result) this.observeRoom(host, room);
    const rooms = response.result.map((room) => this.summaryForResponse(host, room));
    return response.next_cursor !== undefined
      ? { rooms, next_cursor: response.next_cursor }
      : { rooms };
  }

  private knownRooms(input: RoomsListInput): unknown {
    const agentId = this.agentId();
    const host = input.host === undefined ? undefined : normalizeHost(input.host);
    const rooms = [...this.state.rooms.entries()]
      .filter(([, room]) => host === undefined || room.host === host)
      .sort(
        ([, a], [, b]) =>
          compareStrings(a.host, b.host) ||
          compareStrings(a.room.id, b.room.id),
      )
      .filter(([, room]) =>
        input.status !== undefined ? room.room.status === input.status : true,
      )
      .filter(([keyStr, room]) =>
        membershipFilter(
          room,
          agentId,
          input.membership,
          this.state.ownJoinRequests.get(keyStr)?.status === "pending",
        ),
      )
      .map(([, room]) => this.summaryForRoom(room));
    const result = page(rooms, input.cursor, input.limit ?? 50);
    return { rooms: result.items, ...(result.next_cursor ? { next_cursor: result.next_cursor } : {}) };
  }

  /** Reads the room resource and every record after the local tip, then verifies and applies them. */
  private async syncRoom(key: RoomKey): Promise<void> {
    const client = await this.discourse(key.host);
    const jwt = this.requestJwt(key.host);
    const room = await client.room(key.roomId, jwt);
    this.observeRoom(key.host, room);
    // The cursor continues the first query, so its after_seq stays fixed.
    const syncedSeq = this.localRoom(key).syncedSeq;
    let cursor: string | undefined;
    for (;;) {
      const response = await client.events(key.roomId, {
        afterSeq: syncedSeq > 0 ? syncedSeq : undefined,
        cursor,
        jwt,
      });
      for (const record of response.result) this.applyHostRecord(key.host, record);
      cursor = response.next_cursor;
      if (cursor === undefined) break;
    }
  }

  private async roomState(input: RoomStateInput): Promise<unknown> {
    let key: RoomKey;
    if (input.host !== undefined) {
      key = { host: normalizeHost(input.host), roomId: input.room_id };
    } else {
      key = this.resolveRoomKey(undefined, input.room_id);
    }
    this.requireAllowedHost(key.host);
    const known = (this.state.rooms.get(roomKeyString(key))?.syncedSeq ?? 0) > 0;
    if (!known || input.refresh) await this.syncRoom(key);
    const room = this.localRoom(key);
    if (input.subscribe !== undefined) room.subscribed = input.subscribe;
    // The first state read in a session is the agent's starting view.
    if (room.presentedSeq === undefined) this.presentHead(room, room.headSeq);
    return {
      room: this.roomStateView(room),
      sync: this.syncState(key),
      active_turn: room.activeTurn,
    };
  }

  private roomMembersList(input: RoomMembersListInput): unknown {
    const key = this.resolveRoomKey(input.host, input.room_id);
    const room = this.localRoom(key);
    const members = [...room.members.values()]
      .sort((a, b) => compareStrings(a.agent_id, b.agent_id))
      .filter((member) =>
        input.agent_id !== undefined ? member.agent_id === input.agent_id : true,
      )
      .filter((member) =>
        input.status !== undefined && input.status !== "all"
          ? member.status === input.status
          : true,
      )
      .filter((member) =>
        input.role !== undefined ? member.role === input.role : true,
      )
      .map((member) => ({ ...member }));
    if (input.agent_id !== undefined && members.length === 0) {
      throw invalidPayload("room member not found");
    }
    if (input.include_profiles) {
      for (const member of members) {
        if (member.profile === undefined) {
          const profile = this.state.profiles.get(member.agent_id);
          if (profile) member.profile = profileToMemberProfile(profile);
        }
      }
    }
    const result = page(members, input.cursor, input.limit ?? 100);
    const recent =
      input.agent_id !== undefined && input.include_recent_activity
        ? room.timeline
            .filter((item) => item.actor === input.agent_id)
            .slice(-10)
            .reverse()
        : undefined;
    return {
      members: result.items,
      ...(recent !== undefined ? { recent } : {}),
      ...(result.next_cursor ? { next_cursor: result.next_cursor } : {}),
      sync: this.syncState(key),
    };
  }

  private async agentStatusList(input: AgentStatusListInput): Promise<unknown> {
    const key = this.resolveRoomKey(input.host, input.room_id);
    const keyStr = roomKeyString(key);
    const cached = this.state.agentStatuses.get(keyStr);
    if (input.agent_id !== undefined) {
      const hit = input.refresh ? undefined : cached?.get(input.agent_id);
      if (hit) return { statuses: [hit], sync: this.syncState(key) };
      const host = this.allowedRoomHost(key);
      let status: AgentStatus;
      try {
        status = await (await this.discourse(host)).agentStatus(input.room_id, input.agent_id, this.requestJwt(host));
      } catch (error) {
        if (isHttpError(error, "agent_status_not_found")) return { statuses: [], sync: this.syncState(key) };
        throw error;
      }
      this.cacheAgentStatus(keyStr, status);
      return { statuses: [status], sync: this.syncState(key) };
    }
    if (!input.refresh && cached) {
      return { statuses: sortedAgentStatuses(cached), sync: this.syncState(key) };
    }
    const host = this.allowedRoomHost(key);
    const response = await (await this.discourse(host)).agentStatuses(input.room_id, this.requestJwt(host));
    const statuses = new Map<AgentId, AgentStatus>();
    for (const status of response.result) statuses.set(status.agent_id, status);
    this.state.agentStatuses.set(keyStr, statuses);
    return { statuses: sortedAgentStatuses(statuses), sync: this.syncState(key) };
  }

  private async agentStatusSet(input: AgentStatusSetInput): Promise<unknown> {
    const key = this.resolveRoomKey(input.host, input.room_id);
    const keyStr = roomKeyString(key);
    const host = this.allowedRoomHost(key);
    const room = this.localRoom(key);
    const request: AgentStatusInput = {
      state: input.state,
      summary: input.summary,
      seen_seq: input.seen_seq ?? (room.syncedSeq > 0 ? room.syncedSeq : undefined),
      seen_hash: input.seen_hash ?? (input.seen_seq === undefined ? room.syncedHash : undefined),
      claim_id: input.claim_id,
      activity: input.activity,
      expires_at: input.expires_at,
      extra: input.extra,
    };
    const status = await (await this.discourse(host)).setAgentStatus(
      input.room_id,
      this.requestJwt(host),
      request,
    );
    if (status.expires_at <= unixTimeMillis()) {
      this.state.agentStatuses.get(keyStr)?.delete(status.agent_id);
    } else {
      this.cacheAgentStatus(keyStr, status);
    }
    return { status, sync: this.syncState(key) };
  }

  private cacheAgentStatus(keyStr: string, status: AgentStatus): void {
    let statuses = this.state.agentStatuses.get(keyStr);
    if (!statuses) {
      statuses = new Map();
      this.state.agentStatuses.set(keyStr, statuses);
    }
    statuses.set(status.agent_id, status);
  }

  private async roomTimeline(input: RoomTimelineInput): Promise<unknown> {
    const key = this.resolveRoomKey(input.host, input.room_id);
    if (input.refresh) await this.syncRoom(key);
    const room = this.localRoom(key);
    const items = room.timeline
      .filter((item) =>
        input.after_seq !== undefined ? item.seq > input.after_seq : true,
      )
      .filter((item) =>
        input.before_seq !== undefined ? item.seq < input.before_seq : true,
      )
      .filter((item) =>
        input.types !== undefined ? input.types.includes(item.type) : true,
      )
      .filter((item) =>
        input.actors !== undefined
          ? item.actor !== undefined && input.actors.includes(item.actor)
          : true,
      )
      .filter((item) => !input.unread_only || item.seq > room.readSeq)
      .slice(0, input.limit ?? 50);
    const lastSeq = items.length > 0 ? items[items.length - 1].seq : undefined;
    if (input.mark_read && lastSeq !== undefined) {
      room.readSeq = Math.max(room.readSeq, lastSeq);
    }
    // An unfiltered, gap-free read from the presented head presents the latest
    // head it reaches (local connector Section 4.2).
    if (input.types === undefined && input.actors === undefined && items.length > 0) {
      const base = room.presentedSeq ?? 0;
      const contiguous = items.every((item, index) => index === 0 || item.seq === items[index - 1].seq + 1);
      if (contiguous && items[0].seq <= base + 1) this.presentThrough(room, lastSeq!);
    }
    return {
      items,
      sync: this.syncState(key),
      ...(lastSeq !== undefined ? { next_after_seq: lastSeq } : {}),
      unread_count: unreadCount(room),
    };
  }

  private inboxNext(input: InboxNextInput): unknown {
    void input.wait_ms;
    const now = unixTimeMillis();
    const ids = [...this.state.inbox.entries()]
      .sort((a, b) => compareStrings(a[0], b[0]))
      .filter(([, entry]) => inboxEntryReady(entry, now))
      .filter(([, entry]) =>
        input.room_id !== undefined
          ? entry.item.room_id === input.room_id
          : true,
      )
      .filter(([, entry]) =>
        input.kinds !== undefined
          ? input.kinds.includes(entry.item.kind)
          : true,
      )
      .map(([id]) => id)
      .slice(0, input.limit ?? 10);
    const items: InboxItem[] = [];
    for (const id of ids) {
      const entry = this.state.inbox.get(id);
      if (entry) {
        items.push(entry.item);
        // A claim is a lease, so a crashed session cannot hold the item forever.
        if (input.claim) entry.state = { kind: "claimed", until: now + INBOX_CLAIM_LEASE_MS };
      }
    }
    return { items, pending_count: this.pendingInboxCount() };
  }

  private inboxAck(input: InboxAckInput): unknown {
    const acknowledged: string[] = [];
    for (const id of input.ids) {
      const entry = this.state.inbox.get(id);
      if (entry) {
        entry.state =
          input.action === "defer"
            ? { kind: "deferred", until: input.defer_until ?? unixTimeMillis() }
            : { kind: "acknowledged" };
        acknowledged.push(id);
      }
    }
    return { acknowledged, pending_count: this.pendingInboxCount() };
  }

  private draftsList(input: DraftsListInput): unknown {
    if (input.draft_id !== undefined) {
      const entry = this.state.drafts.get(input.draft_id);
      if (!entry) throw invalidPayload("draft not found");
      const key: RoomKey = {
        host: entry.draft.current_sync.host,
        roomId: entry.draft.room_id,
      };
      const room = this.localRoom(key);
      const changes = this.roomChangesSince(key, entry.draft.base_seq);
      // The changes reach the current head, which is now presented.
      this.presentHead(room, room.headSeq);
      return { drafts: [entry.draft], changes, sync: this.syncState(key) };
    }
    const host = input.host !== undefined ? normalizeHost(input.host) : undefined;
    const drafts = [...this.state.drafts.values()]
      .sort((a, b) => compareStrings(a.draft.id, b.draft.id))
      .filter((entry) =>
        input.room_id !== undefined
          ? entry.draft.room_id === input.room_id
          : true,
      )
      .filter((entry) =>
        host !== undefined ? entry.draft.current_sync.host === host : true,
      )
      .map((entry) => entry.draft);
    const result = page(drafts, input.cursor, input.limit ?? 50);
    return { drafts: result.items, ...(result.next_cursor ? { next_cursor: result.next_cursor } : {}) };
  }

  private async draftCommit(input: DraftCommitInput): Promise<unknown> {
    const entry = this.state.drafts.get(input.draft_id);
    if (!entry) throw invalidPayload("draft not found");
    if (input.action === "drop") {
      this.state.drafts.delete(input.draft_id);
      return { status: "dropped", draft_id: input.draft_id };
    }
    if (input.action !== "revise" && input.action !== "send") {
      throw invalidPayload(`invalid draft action: ${input.action}`);
    }
    // Both actions sign against the presented head; a further mismatch is
    // handled by on_head_mismatch.
    let request: HeldDraftRequest;
    if (entry.request.kind === "message") {
      const message: RoomSendMessageInput = { ...entry.request.input };
      if (input.action === "revise") {
        if (input.content !== undefined) message.content = input.content;
        if (input.content_type !== undefined) message.content_type = input.content_type;
        if (input.mentions !== undefined) message.mentions = input.mentions;
        if (input.references !== undefined) message.references = input.references;
        if (input.extra !== undefined) message.extra = input.extra;
      }
      message.base_seq = undefined;
      message.base_hash = undefined;
      message.on_head_mismatch = input.on_head_mismatch;
      request = { kind: "message", input: message };
    } else {
      const event: RoomSubmitEventInput = { ...entry.request.input };
      if (input.action === "revise") {
        if (input.type !== undefined) event.type = input.type;
        if (input.payload !== undefined) event.payload = input.payload;
        if (input.mentions !== undefined) event.mentions = input.mentions;
        if (input.references !== undefined) event.references = input.references;
      }
      event.base_seq = undefined;
      event.base_hash = undefined;
      event.on_head_mismatch = input.on_head_mismatch;
      request = { kind: "event", input: event };
    }
    const result = await this.submitRoomWrite(request);
    if (result.status === "sent" || result.status === "held") {
      this.state.drafts.delete(input.draft_id);
    }
    return result;
  }

  /**
   * Resolves a principal per Agent Delegation Section 3 and reports whether
   * the requested URL is an alias the principal acknowledges. Any origin can
   * redirect to any principal, so an unlisted URL is never presented as a name
   * for it.
   */
  private async resolvePrincipal(
    url: string,
  ): Promise<{ document: PrincipalDocument; alias: boolean }> {
    const document = await new DelegationClient(url, this.fetchImpl).principal(url);
    return {
      document,
      alias: document.id !== url && isPrincipalAlias(document, url),
    };
  }

  /** The principal's authoritative delegation service, located from its `delegation_service` origin. */
  private async principalDelegationService(document: PrincipalDocument): Promise<DelegationClient> {
    const origin = document.delegation_service;
    if (origin === undefined) {
      throw invalidPayload(`principal ${document.id} publishes no delegation_service`);
    }
    this.requireAllowedHost(origin);
    return DelegationClient.discover(origin, this.fetchImpl);
  }

  /**
   * Resolves the principal and refuses when the active Agent ID is not one of
   * its current controller keys with delegation authority, so a grant that
   * could never be accepted is not signed or transmitted.
   */
  private async controllerPrincipal(
    principalId: string,
  ): Promise<PrincipalDocument> {
    const { document } = await this.resolvePrincipal(principalId);
    const active = this.agentId();
    if (!document.controllers.some(c => c.id === active && c.delegation !== undefined && c.valid_from <= unixTimeMillis())) {
      throw invalidPayload(
        `active agent ${active} is not a controller key of ${document.id}`,
      );
    }
    return document;
  }

  private async principalResolve(
    input: PrincipalResolveInput,
  ): Promise<unknown> {
    const { document, alias } = await this.resolvePrincipal(input.url);
    return {
      canonical_id: document.id,
      requested_url: input.url,
      alias,
      principal: document,
    };
  }

  private async delegationCheck(input: DelegationCheckInput): Promise<unknown> {
    if (typeof input.audience !== "string") throw invalidPayload("audience is required");
    const { document } = await this.resolvePrincipal(input.principal_id);
    // The authoritative service is the one the principal names, never one
    // supplied by whoever presented a credential.
    const service = await this.principalDelegationService(document);
    const response = await service.queryDelegations({
      subject: input.subject ?? this.agentId(),
      principal_id: document.id,
      id: input.id,
    });
    const now = unixTimeMillis();
    const delegations: DelegationVerdict[] = [];
    for (const credential of response.result) {
      let records: Awaited<ReturnType<DelegationClient["allDelegationEvents"]>> = [];
      try {
        records = await service.allDelegationEvents(credential.id);
      } catch (error) {
        delegations.push({ credential, verified: false, usable: false, reasons: [`history unavailable: ${error instanceof Error ? error.message : error}`] });
        continue;
      }
      delegations.push(verifyDelegationCredential(credential, records, document, document.id, input.audience, now));
    }
    return { canonical_id: document.id, query_url: service.queryUrl, delegations };
  }

  private async delegationsList(input: DelegationsListInput): Promise<unknown> {
    // Enumerating one subject requires authorization; the connector proves the
    // active identity and never enumerates anyone else.
    const origin = serviceOrigin(input.delegation_service);
    const jwt = this.requestJwt(origin);
    const service = await DelegationClient.discover(origin, this.fetchImpl);
    const response = await service.queryDelegations(
      {
        subject: this.agentId(),
        status: input.status,
        limit: input.limit,
        cursor: input.cursor,
      },
      jwt,
    );
    return response.next_cursor !== undefined
      ? { delegations: response.result, next_cursor: response.next_cursor }
      : { delegations: response.result };
  }

  private async delegationPrevious(service: DelegationClient, id: string): Promise<DelegationCredential | undefined> {
    try { return await service.delegation(id); }
    catch (error) { if (error instanceof HttpResponseError && error.status === 404) return undefined; throw error; }
  }

  private async submitDelegation(
    service: DelegationClient,
    sign: () => Envelope<DelegationPayload>,
  ): Promise<{ credential: DelegationCredential; envelope: Envelope<DelegationPayload> }> {
    let envelope = sign();
    try {
      return { credential: await service.submitDelegationEvent(envelope), envelope };
    } catch (error) {
      if (!this.resyncNonce(error)) throw error;
      envelope = sign();
      return { credential: await service.submitDelegationEvent(envelope), envelope };
    }
  }

  private async delegationGrant(input: DelegationGrantInput): Promise<unknown> {
    const principal = await this.controllerPrincipal(input.principal_id);
    const service = await this.principalDelegationService(principal);
    const previous = await this.delegationPrevious(service, input.id);
    const payload: DelegationGrantPayload = {
      id: input.id, principal_id: principal.id, subject: input.subject,
      relationship: input.relationship, scopes: input.scopes, audiences: input.audiences,
      constraints: input.constraints, not_before: input.not_before, expires_at: input.expires_at,
    };
    for (const field of ["relationship", "constraints", "not_before", "expires_at"] as const) {
      if (payload[field] === undefined) delete payload[field];
    }
    return this.submitDelegation(service, () => {
      const createdAt = unixTimeMillis();
      const event = delegationGrantEvent(this.agentId(), createdAt, this.nonces.nextNonce(createdAt), payload);
      validateDelegationEventAuthority(event, principal, createdAt, previous);
      return this.signer.signEvent(event) as Envelope<DelegationPayload>;
    });
  }

  private async delegationRevoke(input: DelegationRevokeInput): Promise<unknown> {
    const principal = await this.controllerPrincipal(input.principal_id);
    const service = await this.principalDelegationService(principal);
    const previous = await this.delegationPrevious(service, input.id);
    return this.submitDelegation(service, () => {
      const createdAt = unixTimeMillis();
      const event = delegationRevokeEvent(this.agentId(), createdAt, this.nonces.nextNonce(createdAt), {
        id: input.id, principal_id: principal.id, ...(input.reason !== undefined ? { reason: input.reason } : {}),
      });
      validateDelegationEventAuthority(event, principal, createdAt, previous);
      return this.signer.signEvent(event) as Envelope<DelegationPayload>;
    });
  }

  private async profileUpdate(input: ProfileUpdateInput): Promise<unknown> {
    if (!isRecord(input.profile)) {
      throw invalidPayload("profile must be an object");
    }
    this.requireAllowedOrigin(input.profile_service);
    const profile: Record<string, unknown> = { ...input.profile };
    // payload.id is always the active Agent ID; reject an input that names a
    // different agent instead of silently rewriting it.
    const activeId = this.agentId();
    if (profile.id === undefined) {
      profile.id = activeId;
    } else if (profile.id !== activeId) {
      throw invalidPayload("profile.id must be the active Agent ID");
    }
    const client = await this.profileClient(input.profile_service);
    let envelope = this.signProfileUpdate(profile as unknown as ProfileUpdatePayload);
    let materialized: AgentProfile;
    try {
      materialized = await client.submitProfileUpdate(envelope);
    } catch (error) {
      if (!this.resyncNonce(error)) throw error;
      envelope = this.signProfileUpdate(profile as unknown as ProfileUpdatePayload);
      materialized = await client.submitProfileUpdate(envelope);
    }
    this.state.profiles.set(materialized.id, materialized);
    return { profile: materialized, envelope };
  }

  private async roomCreate(input: RoomCreateInput): Promise<unknown> {
    const host = normalizeHost(input.host);
    this.requireAllowedHost(host);
    const payload: RoomCreatePayload = {
      // Binds the signed event to this host (ADP Section 8.1).
      host: serviceOrigin(host),
      topic: input.topic,
      visibility: input.visibility,
      start_time: input.start_time,
      end_time: input.end_time,
      agenda: input.agenda,
      guidance: input.guidance,
      tags: input.tags,
      language: input.language,
      policy: input.policy,
      types: input.types,
      extra: input.extra,
    };
    for (const field of ["agenda", "guidance", "tags", "language", "policy", "types", "extra"] as const) {
      if (payload[field] === undefined) delete payload[field];
    }
    const client = await this.discourse(host);
    let envelope = this.signRoomCreate(payload);
    let room: RoomResponse;
    try {
      room = await client.createRoom(envelope);
    } catch (error) {
      if (!this.resyncNonce(error)) throw error;
      envelope = this.signRoomCreate(payload);
      room = await client.createRoom(envelope);
    }
    if (!room.envelope) room.envelope = envelope;
    this.acceptRoomResponse(host, room);
    const key: RoomKey = { host, roomId: room.id };
    const local = this.localRoom(key);
    // The creator has seen its own room.
    this.presentHead(local, local.headSeq);
    return {
      room: this.roomStateView(local),
      envelope,
      sync: this.syncState(key),
    };
  }

  private async roomJoin(input: RoomJoinInput): Promise<unknown> {
    const roomId = input.room_id;
    const key: RoomKey = input.host !== undefined
      ? { host: normalizeHost(input.host), roomId }
      : this.resolveRoomKey(undefined, roomId);
    const host = key.host;
    this.requireAllowedHost(host);
    const keyStr = roomKeyString(key);
    const agentId = this.agentId();

    // A stored request decides the outcome until it resolves.
    const own = this.state.ownJoinRequests.get(keyStr);
    if (own && own.status === "pending") {
      const current = await (await this.discourse(host)).joinRequest(roomId, own.id, this.requestJwt(host));
      this.state.ownJoinRequests.set(keyStr, current);
      if (current.status === "pending") return { status: "approval_required", join_request: current, sync: this.maybeSync(key) };
      if (current.status === "rejected") return { status: "rejected", join_request: current, sync: this.maybeSync(key) };
      if (current.status === "approved") {
        // The approving review record is the membership event.
        await this.syncRoom(key);
        const member = this.localRoom(key).members.get(agentId);
        if (member?.status !== "active") throw invalidPayload("approved membership is not yet visible");
        return { status: "joined", member, join_request: current, sync: this.syncState(key) };
      }
    }

    // Read the room when possible: invitees and public rooms are readable.
    if (!this.state.rooms.has(keyStr)) {
      try {
        const room = await (await this.discourse(host)).room(roomId, this.requestJwt(host));
        this.acceptRoomResponse(host, room);
      } catch (error) {
        if (!(error instanceof HttpResponseError)) throw error;
      }
    }
    const local = this.state.rooms.get(keyStr);
    const visibility = local ? roomVisibility(local.room) : undefined;
    const direct =
      local !== undefined &&
      visibility !== undefined &&
      local.members.get(agentId)?.status !== "banned" &&
      canJoinDirectly(visibility, roomPolicy(local.room), agentId, input.role);
    if (direct) {
      const payload: RoomJoinPayload = { role: input.role };
      if (input.perspective !== undefined) payload.perspective = input.perspective;
      let record: ServerRecord<RoomJoinPayload> | undefined;
      try {
        record = await this.submitSigned(
          () => this.signRoomEvent(eventType.ROOM_JOIN, key, undefined, undefined, [], payload),
          async (envelope) => (await this.discourse(host)).joinRoom(roomId, envelope),
        );
      } catch (error) {
        // A ban may have arrived since the local snapshot; request review below.
        if (!isHttpError(error, "member_banned")) throw error;
      }
      if (record) {
        await this.applyOwnRecord(key, record as ServerRecord);
        const member = this.localRoom(key).members.get(agentId);
        if (!member) throw invalidPayload("joined member not materialized");
        return { status: "joined", record, member, sync: this.syncState(key) };
      }
    }

    const requestPayload: RoomJoinRequestPayload = { role: input.role };
    if (input.perspective !== undefined) requestPayload.perspective = input.perspective;
    if (input.reason !== undefined) requestPayload.reason = input.reason;
    if (input.extra !== undefined) requestPayload.extra = input.extra;
    const request = await this.submitSigned(
      () => this.signJoinRequest(roomId, requestPayload),
      async (envelope) => (await this.discourse(host)).requestJoin(roomId, envelope),
    );
    this.state.ownJoinRequests.set(keyStr, request);
    return { status: "approval_required", join_request: request, sync: this.maybeSync(key) };
  }

  private async roomSendMessage(
    input: RoomSendMessageInput,
  ): Promise<RoomWriteResult> {
    return this.submitRoomWrite({ kind: "message", input: { ...input } });
  }

  private async roomSubmitEvent(
    input: RoomSubmitEventInput,
  ): Promise<RoomWriteResult> {
    return this.submitRoomWrite({ kind: "event", input: { ...input } });
  }

  /**
   * One room write under the Section 5.1 freshness rules. Contract and signal
   * writes only anchor, so they are signed against the base and never held.
   * Message and control writes apply `on_head_mismatch` when the local head
   * moved past their base or the host returns `room_head_mismatch`.
   */
  private async submitRoomWrite(request: HeldDraftRequest): Promise<RoomWriteResult> {
    const input = request.input;
    const key = this.resolveRoomKey(input.host, input.room_id);
    const host = this.allowedRoomHost(key);
    const type = request.kind === "message" ? eventType.MESSAGE_CREATE : request.input.type;
    const headBound = eventTypeRequiresRoomHead(this.localRoom(key), type);
    if ((input.base_seq === undefined) !== (input.base_hash === undefined)) {
      throw invalidPayload("base_seq and base_hash must be provided together");
    }
    let base: [number, string] = this.writeBase(key, input.base_seq, input.base_hash);
    const policy: HeadMismatchPolicy = input.on_head_mismatch ?? "hold";
    for (let attempts = 0; ; attempts++) {
      if (headBound) {
        const room = this.localRoom(key);
        if (!baseIsCurrent(room, base)) {
          if (policy === "send_anyway" && attempts < SEND_ANYWAY_MAX_ATTEMPTS) {
            base = [room.headSeq, room.headHash!];
          } else {
            return policy === "reject"
              ? this.rejectedHeadMismatch(key, base[0])
              : this.holdDraft(key, request, base);
          }
        }
      }
      const presentedSeq = this.localRoom(key).presentedSeq;
      const previousHeadSeq = this.localRoom(key).headSeq;
      try {
        const record = await this.submitSigned(
          () => this.signWrite(request, key, base),
          async (envelope) => (await this.discourse(host)).submitEvent(input.room_id, envelope),
        );
        await this.applyOwnRecord(key, record as ServerRecord);
        const after = this.localRoom(key);
        // The agent's own write extends what it saw only when nothing it has
        // not seen advanced the head in between.
        if (after.headSeq === record.seq && this.headBefore(after, record.seq, previousHeadSeq) === presentedSeq) {
          this.presentHead(after, record.seq);
        }
        return {
          status: "sent",
          record: record as ServerRecord,
          item: this.timelineItemByEvent(key, record.envelope.hash),
          sync: this.syncState(key),
        };
      } catch (error) {
        if (!headBound || !isHttpError(error, "room_head_mismatch")) throw error;
        await this.syncRoom(key);
        // A host that reports a mismatch the verified history does not show
        // cannot be resolved by retrying.
        if (baseIsCurrent(this.localRoom(key), base)) throw error;
      }
    }
  }

  /**
   * Applies the record the host returned for the agent's own write, first
   * syncing any records accepted before it that the connector has not seen.
   */
  private async applyOwnRecord(key: RoomKey, record: ArchiveRecord): Promise<void> {
    const room = this.localRoom(key);
    if (record.seq > room.syncedSeq + 1) await this.syncRoom(key);
    else this.applyHostRecord(key.host, record);
  }

  /** Seq of the latest head-advancing record before `seq`, or 0. */
  private headBefore(room: LocalRoomState, seq: number, previousHeadSeq: number): number {
    for (let s = seq - 1; s > 0; s--) {
      const record = room.records.find((candidate) => candidate.seq === s);
      if (record && recordAdvancesRoomHead(room, record)) return s;
    }
    // A room snapshot may provide a verified head without its older records.
    return previousHeadSeq < seq ? previousHeadSeq : 0;
  }

  /** Signs and submits once, re-signing a single time after a bounded Max-Seen-Nonce resync. */
  private async submitSigned<P, T>(
    sign: () => Envelope<P>,
    submit: (envelope: Envelope<P>) => Promise<T>,
  ): Promise<T> {
    try {
      return await submit(sign());
    } catch (error) {
      if (!this.resyncNonce(error)) throw error;
      return submit(sign());
    }
  }

  /** Applies `Max-Seen-Nonce` from a `nonce_not_greater` rejection; reports whether to retry. */
  private resyncNonce(error: unknown): boolean {
    if (!isHttpError(error, "nonce_not_greater") || error.maxSeenNonce === undefined) return false;
    this.nonces.observeMaxNonce(error.maxSeenNonce);
    return true;
  }

  private signWrite(
    request: HeldDraftRequest,
    key: RoomKey,
    base: [number, string],
  ): Envelope<unknown> {
    if (request.kind === "message") {
      const input = request.input;
      const payload: MessageCreatePayload = {
        content_type: input.content_type ?? "text/plain",
        content: input.content,
      };
      if (input.references && input.references.length > 0) payload.references = input.references;
      if (input.extra && Object.keys(input.extra).length > 0) payload.extra = input.extra;
      return this.signRoomEvent(eventType.MESSAGE_CREATE, key, base[0], base[1], input.mentions ?? [], payload);
    }
    const input = request.input;
    const payload = payloadWithReferences({ ...input.payload }, input.references ?? []);
    return this.signRoomEvent(input.type, key, base[0], base[1], input.mentions ?? [], payload);
  }

  private async joinRequestsList(
    input: JoinRequestsListInput,
  ): Promise<unknown> {
    const key = this.resolveRoomKey(input.host, input.room_id);
    const host = this.allowedRoomHost(key);
    const response = await (await this.discourse(host)).joinRequests(input.room_id, this.requestJwt(host), {
      status: input.status,
      limit: input.limit,
      cursor: input.cursor,
    });
    this.state.joinRequests.set(roomKeyString(key), response.result);
    return response.next_cursor !== undefined
      ? { join_requests: response.result, next_cursor: response.next_cursor }
      : { join_requests: response.result };
  }

  private async joinRequestReview(
    input: JoinRequestReviewInput,
  ): Promise<unknown> {
    const key = this.resolveRoomKey(input.host, input.room_id);
    const host = this.allowedRoomHost(key);
    if (input.decision === "approve" && input.role === undefined) {
      throw invalidPayload("approving a join request requires a role");
    }
    const joinRequest = await (await this.discourse(host)).joinRequest(
      input.room_id,
      input.request_id,
      this.requestJwt(host),
    );
    const payload: RoomJoinReviewPayload = {
      request: joinRequest.request,
      decision: input.decision,
    };
    if (input.role !== undefined) payload.role = input.role;
    if (input.reason !== undefined) payload.reason = input.reason;
    const record = await this.submitSigned(
      () => this.signRoomEvent(eventType.ROOM_JOIN_REVIEW, key, undefined, undefined, [], payload),
      async (envelope) => (await this.discourse(host)).submitEvent(input.room_id, envelope),
    );
    await this.applyOwnRecord(key, record as ServerRecord);
    return { record, sync: this.syncState(key) };
  }

  // ── Signing.

  private signProfileUpdate(
    payload: ProfileUpdatePayload,
  ): Envelope<ProfileUpdatePayload> {
    const createdAt = unixTimeMillis();
    const event = profileUpdateEvent(
      this.agentId(),
      createdAt,
      this.nonces.nextNonce(createdAt),
      payload,
    );
    return this.signer.signEvent(event);
  }

  private signRoomCreate(
    payload: RoomCreatePayload,
  ): Envelope<RoomCreatePayload> {
    const createdAt = unixTimeMillis();
    const event = roomCreateEvent(
      this.agentId(),
      createdAt,
      this.nonces.nextNonce(createdAt),
      payload,
    );
    const envelope = this.signer.signEvent(event);
    validateDiscourseEnvelope(envelope);
    return envelope;
  }

  private signJoinRequest(
    roomId: string,
    payload: RoomJoinRequestPayload,
  ): Envelope<RoomJoinRequestPayload> {
    const createdAt = unixTimeMillis();
    const event = roomJoinRequestEvent(
      this.agentId(),
      createdAt,
      this.nonces.nextNonce(createdAt),
      roomId,
      payload,
    );
    const envelope = this.signer.signEvent(event);
    validateDiscourseEnvelope(envelope);
    return envelope;
  }

  signRoomEvent<P>(
    type: string,
    key: RoomKey,
    baseSeq: number | undefined,
    baseHash: string | undefined,
    mentions: AgentId[],
    payload: P,
  ): Envelope<P> {
    const host = this.localRoom(key).host;
    this.requireAllowedHost(host);
    const [resolvedSeq, resolvedHash] = this.writeBase(key, baseSeq, baseHash);
    const createdAt = unixTimeMillis();
    let event = discourseEvent(
      type,
      this.agentId(),
      createdAt,
      this.nonces.nextNonce(createdAt),
      key.roomId,
      resolvedSeq,
      resolvedHash,
      payload,
    );
    if (mentions.length > 0) event = withMentions(event, mentions);
    const envelope = this.signer.signEvent(event);
    validateDiscourseEnvelope(envelope);
    return envelope;
  }

  /**
   * The base for a write: the explicit base, else the presented head, else the
   * current verified head (local connector Section 4.2).
   */
  private writeBase(
    key: RoomKey,
    baseSeq: number | undefined,
    baseHash: string | undefined,
  ): [number, string] {
    if (baseSeq !== undefined && baseHash !== undefined) {
      if (baseSeq > 0 && baseHash.trim() !== "") return [baseSeq, baseHash];
      throw invalidPayload(
        "base_seq and base_hash must identify a valid room head",
      );
    }
    if (baseSeq !== undefined || baseHash !== undefined) {
      throw invalidPayload("base_seq and base_hash must be provided together");
    }
    const room = this.localRoom(key);
    if (room.presentedSeq !== undefined && room.presentedHash !== undefined) {
      return [room.presentedSeq, room.presentedHash];
    }
    const sync = this.syncState(key);
    if (sync.head_seq === 0 || sync.head_hash.trim() === "") {
      throw invalidPayload("current room head is not known locally");
    }
    return [sync.head_seq, sync.head_hash];
  }

  private requestJwt(host: string): string {
    // The request JWT aud is always the origin of the host API.
    const normalized = normalizeHost(host);
    this.requireAllowedHost(normalized);
    const audience = serviceOrigin(normalized);
    const claims = createRequestJwtClaims(
      this.agentId(),
      createRequestBinding(audience),
      unixTimeSecs(),
      DEFAULT_REQUEST_JWT_TTL_SECS,
    );
    return this.signer.signRequestJwt(claims);
  }

  // ── Presented head.

  /** Presents the head at `seq`, which must be a known head-advancing record or the current head. */
  private presentHead(room: LocalRoomState, seq: number): void {
    if (seq <= 0) return;
    const hash = seq === room.headSeq
      ? room.headHash
      : room.records.find((record) => record.seq === seq)?.hash;
    if (hash === undefined) return;
    room.presentedSeq = seq;
    room.presentedHash = hash;
  }

  /** Presents the latest head-advancing record at or before `seq`, if it moves the presented head forward. */
  private presentThrough(room: LocalRoomState, seq: number): void {
    const base = room.presentedSeq ?? 0;
    for (let s = Math.min(seq, room.syncedSeq); s > base; s--) {
      const record = room.records.find((candidate) => candidate.seq === s);
      if (record && recordAdvancesRoomHead(room, record)) {
        room.presentedSeq = s;
        room.presentedHash = record.hash;
        return;
      }
    }
  }

  // ── Head-mismatch handling and draft holding.

  private rejectedHeadMismatch(key: RoomKey, baseSeq: number): RoomWriteResult {
    const room = this.localRoom(key);
    const changes = this.roomChangesSince(key, baseSeq);
    this.presentHead(room, room.headSeq);
    return {
      status: "rejected",
      reason: "room_head_mismatch",
      changes,
      sync: this.syncState(key),
    };
  }

  private holdDraft(key: RoomKey, request: HeldDraftRequest, base: [number, string]): RoomWriteResult {
    const room = this.localRoom(key);
    const changes = this.roomChangesSince(key, base[0]);
    // The held result shows every change up to the current head.
    this.presentHead(room, room.headSeq);
    const sync = this.syncState(key);
    const input = { ...request.input, host: sync.host, base_seq: base[0], base_hash: base[1] };
    const draftId = this.nextDraftId(input.room_id);
    const draft: HeldDraft = {
      id: draftId,
      room_id: input.room_id,
      kind: request.kind,
      created_at: unixTimeMillis(),
      base_seq: base[0],
      base_hash: base[1],
      current_sync: sync,
      draft: request.kind === "message"
        ? messageDraftValue(input as RoomSendMessageInput)
        : eventDraftValue(input as RoomSubmitEventInput),
      reason: "room_head_mismatch",
      options: heldDraftOptions(),
    };
    this.state.drafts.set(draftId, {
      draft,
      request: request.kind === "message"
        ? { kind: "message", input: input as RoomSendMessageInput }
        : { kind: "event", input: input as RoomSubmitEventInput },
    });
    return {
      status: "held",
      reason: "room_head_mismatch",
      draft,
      changes,
      sync,
    };
  }

  private roomChangesSince(
    key: RoomKey,
    baseSeq: number | undefined,
  ): TimelineItem[] {
    const room = this.localRoom(key);
    if (baseSeq !== undefined) {
      return room.timeline.filter((item) => item.seq > baseSeq);
    }
    return room.timeline.slice(-20);
  }

  private nextDraftId(roomId: string): string {
    const room = [...roomId]
      .map((ch) => (/[A-Za-z0-9_-]/.test(ch) ? ch : "_"))
      .join("");
    let n = this.state.drafts.size + 1;
    while (this.state.drafts.has(`draft_${room}_${n}`)) n += 1;
    return `draft_${room}_${n}`;
  }

  // ── Views.

  private syncState(key: RoomKey): SyncState {
    const room = this.localRoom(key);
    const headHash =
      room.headHash ?? room.room.head?.hash ?? room.room.hash;
    return {
      host: room.host,
      room_id: key.roomId,
      head_seq: room.headSeq,
      head_hash: headHash,
      ...(room.presentedSeq !== undefined
        ? { presented_seq: room.presentedSeq, presented_hash: room.presentedHash }
        : {}),
      synced_seq: room.syncedSeq,
      remote_seq: Math.max(room.room.seq, room.syncedSeq),
      subscribed: room.subscribed,
      unread_count: unreadCount(room),
      pending_inbox_count: this.pendingInboxCount(key.roomId),
    };
  }

  private maybeSync(key: RoomKey): SyncState | undefined {
    return this.state.rooms.has(roomKeyString(key)) ? this.syncState(key) : undefined;
  }

  private roomStateView(room: LocalRoomState): RoomStateView {
    const selfMember = room.members.get(this.agentId());
    return {
      host: room.host,
      room_id: room.room.id,
      status: room.room.status,
      visibility: roomVisibility(room.room),
      topic: roomTopic(room.room),
      agenda: roomAgenda(room.room),
      guidance: roomGuidance(room.room),
      creator: room.room.creator ?? room.room.envelope?.event.actor,
      created_at: room.room.created_at ?? room.room.envelope?.event.created_at,
      start_time: roomStartTime(room.room),
      end_time: roomEndTime(room.room),
      tags: roomTags(room.room),
      language: roomLanguage(room.room),
      policy: roomPolicy(room.room),
      types: room.room.types ?? [],
      self_member: selfMember,
      members_count: room.members.size,
      active_turn: room.activeTurn,
      unread_count: unreadCount(room),
      pending_inbox_count: this.pendingInboxCount(room.room.id),
    };
  }

  private summaryForRoom(room: LocalRoomState): RoomSummary {
    return roomSummaryFromResponse(room.host, room.room, {
      role: room.members.get(this.agentId())?.role,
      unreadCount: unreadCount(room),
      pendingInboxCount: this.pendingInboxCount(room.room.id),
    });
  }

  private summaryForResponse(host: string, room: RoomResponse): RoomSummary {
    const existing = this.state.rooms.get(
      roomKeyString({ host, roomId: room.id }),
    );
    if (existing) return this.summaryForRoom(existing);
    return roomSummaryFromResponse(host, room);
  }

  private timelineItemByEvent(key: RoomKey, eventId: string): TimelineItem {
    const item = this.localRoom(key).timeline.find(
      (entry) => entry.event_id === eventId,
    );
    if (!item) throw invalidPayload("timeline item not materialized");
    return item;
  }

  // ── Agent Mail (local connector Section 4.3).

  private mailMailboxesList(): unknown {
    const now = unixTimeMillis();
    const mailboxes: MailboxView[] = [];
    for (const [mailboxId, cards] of this.state.mail.mailboxes) {
      const card = cards.at(-1);
      if (card) mailboxes.push(this.mailboxView(mailboxId, card, now));
    }
    return { mailboxes };
  }

  private async mailMailboxPublish(input: MailMailboxPublishInput): Promise<unknown> {
    const now = unixTimeMillis();
    this.pruneMail(now);
    const routes = checkedRoutes(input.routes);
    for (const route of routes) this.requireAllowedHost(route);
    let mailboxId: string;
    let previous: MailboxCard | undefined;
    let newKey: MailEncryptionKey | undefined;
    if (input.mailbox_id === undefined) {
      if (routes.length === 0) throw invalidPayload("a new mailbox needs routes");
      mailboxId = newMailId();
      newKey = MailEncryptionKey.generate();
    } else {
      mailboxId = input.mailbox_id;
      previous = this.state.mail.mailboxes.get(mailboxId)?.at(-1);
      if (!previous) throw invalidPayload("unknown mailbox");
      if (input.rotate_key) newKey = MailEncryptionKey.generate();
      else if (!this.mailKeys.has(previous.event.payload.public_key)) {
        throw invalidPayload("the mailbox key is not loaded; restore mail keys or rotate the key");
      }
    }
    const expiresAt = input.expires_at ?? now + MAIL_MAX_TTL_MS;
    const payload: MailboxCardPayload = {
      mailbox_id: mailboxId,
      expires_at: expiresAt,
      receive_until: input.receive_until ?? expiresAt + MAIL_MAX_TTL_MS,
      public_key: newKey?.publicKey() ?? previous!.event.payload.public_key,
      routes,
      max_packet_bytes: input.max_packet_bytes ?? previous?.event.payload.max_packet_bytes ?? DEFAULT_MAX_PACKET_BYTES,
    };

    // Publish to every route of the previous and new cards (Agent Mail
    // Section 4.2); routes the operator no longer allows are reported.
    const targets = [...routes];
    for (const route of previous?.event.payload.routes ?? []) {
      if (!targets.includes(route)) targets.push(route);
    }
    const failed: RouteError[] = [];
    const allowed: string[] = [];
    for (const route of targets) {
      try {
        this.requireAllowedHost(route);
        allowed.push(route);
      } catch (error) {
        failed.push(routeError(route, error));
      }
    }
    if (allowed.length === 0) throw permissionDenied();
    let card = this.signMailCard(payload);
    let resynced = false;
    let published: string[];
    let errors: [string, unknown][];
    for (;;) {
      published = [];
      errors = [];
      let resync = false;
      for (const route of allowed) {
        try {
          await this.mailClient(route).publish(card);
          published.push(route);
        } catch (error) {
          if (!resynced && this.resyncNonce(error)) {
            resync = true;
            break;
          }
          errors.push([route, error]);
        }
      }
      if (!resync) break;
      // One re-signed card, published to every route again.
      resynced = true;
      card = this.signMailCard(payload);
    }
    failed.push(...errors.map(([route, error]) => routeError(route, error)));
    if (published.length === 0) throw errors[0]?.[1] ?? permissionDenied();
    if (newKey) this.mailKeys.set(newKey.publicKey(), newKey);
    const cards = this.state.mail.mailboxes.get(mailboxId) ?? [];
    cards.push(card);
    this.state.mail.mailboxes.set(mailboxId, cards);
    return { mailbox: this.mailboxView(mailboxId, card, unixTimeMillis()), published, failed };
  }

  private async mailSend(input: MailSendInput): Promise<unknown> {
    const now = unixTimeMillis();
    const parent = input.in_reply_to === undefined ? undefined : this.replyParent(input.in_reply_to, input.to);
    let owner: AgentId;
    let mailboxId: string;
    let routes: string[];
    if (input.to !== undefined) {
      const address = parseMailAddress(input.to);
      ({ owner, mailbox_id: mailboxId, routes } = address);
    } else if (parent) {
      const replyCard = parent.reply_card;
      if (replyCard === undefined) throw invalidPayload("the parent message carries no reply card; pass to");
      validateMailboxCard(replyCard);
      owner = replyCard.event.actor;
      mailboxId = replyCard.event.payload.mailbox_id;
      routes = replyCard.event.payload.routes;
    } else {
      throw invalidPayload("to or in_reply_to is required");
    }
    if (parent && parent.from !== owner) throw invalidPayload("a reply must be addressed to the parent's sender");
    const card = await this.mailCard(owner, mailboxId, routes, now);
    if (!card.event.payload.routes.some((route) => this.isAllowedHost(route))) throw permissionDenied();
    const replyCard = input.reply_mailbox_id === undefined ? undefined : this.openMailboxCard(input.reply_mailbox_id, now);

    const parts = [...(input.text === undefined ? [] : [mailTextPart(input.text)]), ...(input.parts ?? [])];
    if (parts.length === 0) throw invalidPayload("a message needs text or parts");
    const message = createMailMessage(this.agentId(), now, {
      to: owner,
      expires_at: input.expires_at ?? Math.min(now + MESSAGE_TTL_MS, card.event.payload.receive_until),
      thread_id: parent?.thread_id ?? newMailId(),
      parts,
      ...(input.subject === undefined ? {} : { subject: input.subject }),
      ...(parent === undefined ? {} : { in_reply_to: parent.message_id }),
      ...(replyCard === undefined ? {} : { reply_card: replyCard }),
    });
    if (parent) validateMailReply(message, parent);
    const stored: StoredMailMessage = { direction: "sent", message, mailbox_id: mailboxId, read: true };
    const status = await this.deliver(stored, card);
    const view = mailMessageView(stored, false);
    this.state.mail.messages.push(stored);
    return { status, message: view };
  }

  private async mailSync(input: MailSyncInput): Promise<unknown> {
    if (input.mailbox_id !== undefined && !this.state.mail.mailboxes.has(input.mailbox_id)) {
      throw invalidPayload("unknown mailbox");
    }
    const now = unixTimeMillis();
    const errors: RouteError[] = [];
    const { delivered, expired } = await this.retryQueued(now, errors);
    this.pruneMail(now);
    const received = await this.pollMailboxes(input.mailbox_id, errors);
    return {
      received,
      delivered,
      expired,
      queued: this.state.mail.messages.filter(isQueued).length,
      errors,
      pending_inbox_count: this.pendingInboxCount(),
    };
  }

  private mailList(input: MailListInput): unknown {
    const selected = this.state.mail.messages.filter((stored) =>
      (input.direction === undefined || stored.direction === input.direction) &&
      (input.mailbox_id === undefined || stored.mailbox_id === input.mailbox_id) &&
      (input.from === undefined || stored.message.from === input.from) &&
      (input.thread_id === undefined || stored.message.thread_id === input.thread_id) &&
      (input.message_id === undefined || stored.message.message_id === input.message_id) &&
      (!input.unread_only || isUnread(stored)));
    const result = page(selected, input.cursor, input.limit ?? 20);
    const messages = result.items.map((stored) => {
      const view = mailMessageView(stored, input.include_data === true);
      if (input.mark_read && stored.direction === "received") stored.read = true;
      return view;
    });
    // The page leaves the unread selection, so the next one starts at the same offset.
    const next_cursor = result.next_cursor !== undefined && input.unread_only && input.mark_read
      ? String(parseCursor(input.cursor))
      : result.next_cursor;
    const unread_count = this.state.mail.messages.filter(isUnread).length;
    return next_cursor === undefined
      ? { messages, unread_count }
      : { messages, next_cursor, unread_count };
  }

  private signMailCard(payload: MailboxCardPayload): MailboxCard {
    const createdAt = unixTimeMillis();
    const card = this.signer.signEvent(
      mailboxPublishEvent(this.agentId(), createdAt, this.nonces.nextNonce(createdAt), payload),
    );
    validateMailboxCard(card, this.agentId());
    return card;
  }

  private mailClient(route: string): MailClient {
    this.requireAllowedHost(route);
    return new MailClient(route, { fetch: this.fetchImpl });
  }

  /**
   * Reads the card from an allowed route — the given routes, or the pinned
   * card's — and pins it. A newer card that is closed or expired supersedes
   * older ones; when no route answers, a usable pin is used.
   */
  private async mailCard(owner: AgentId, mailboxId: string, routes: string[], now: number): Promise<MailboxCard> {
    const pins = this.state.mail.pins;
    const candidates = routes.length > 0 ? routes : pins.get(owner, mailboxId)?.event.payload.routes ?? [];
    let lastError: unknown;
    for (const route of candidates) {
      let record;
      try {
        record = await this.mailClient(route).card(mailboxId, owner);
      } catch (error) {
        lastError = error;
        continue;
      }
      let card: MailboxCard;
      try {
        card = pins.observe(record.envelope, owner, now, false);
      } catch (error) {
        lastError = error;
        continue;
      }
      validateMailSenderCard(card, owner, now);
      return card;
    }
    const pinned = pins.get(owner, mailboxId);
    if (pinned) {
      try {
        validateMailSenderCard(pinned, owner, now);
        return pinned;
      } catch {
        // An unusable pin falls through to the last route error.
      }
    }
    throw lastError ?? invalidPayload("no card is pinned for this mailbox; use a contact address with routes");
  }

  /**
   * Delivers a sent message to its card's allowed routes in order, sealing a
   * packet unless the stored one was sealed under this card. On `stale_card`
   * it reads the card again and seals under a newer pin once.
   */
  private async deliver(stored: StoredMailMessage, card: MailboxCard): Promise<"delivered" | "queued"> {
    const owner = stored.message.to;
    let refreshed = false;
    for (;;) {
      const now = unixTimeMillis();
      let packet = stored.packet;
      if (packet === undefined || packet.event.payload.header.card_hash !== card.hash) {
        packet = await sealMailPacket(stored.message, card, this.signer, this.nonces.nextNonce(now), now);
        stored.packet = packet;
      }
      let transient: RouteError | undefined;
      let permanent: [string, unknown] | undefined;
      let stale = false;
      for (const route of card.event.payload.routes) {
        if (!this.isAllowedHost(route)) continue;
        try {
          const result = await this.mailClient(route).deliver(packet);
          stored.delivery = {
            status: "delivered",
            route,
            packet_id: result.packet_id,
            accepted_at: result.accepted_at,
          };
          return "delivered";
        } catch (error) {
          stale ||= isHttpError(error, "stale_card");
          if (isTransient(error)) transient = routeError(route, error);
          else permanent ??= [route, error];
        }
      }
      if (stale && !refreshed) {
        refreshed = true;
        const fresh = await this.mailCard(owner, card.event.payload.mailbox_id, card.event.payload.routes, now);
        if (fresh.hash !== card.hash) {
          card = fresh;
          continue;
        }
      }
      const lastError = transient ?? (permanent === undefined ? undefined : routeError(permanent[0], permanent[1]));
      stored.delivery = { status: "queued", ...(lastError === undefined ? {} : { last_error: lastError }) };
      if (transient) return "queued";
      throw permanent?.[1] ?? permissionDenied();
    }
  }

  /** Retries queued messages with their stored packets. */
  private async retryQueued(now: number, errors: RouteError[]): Promise<{ delivered: string[]; expired: string[] }> {
    const delivered: string[] = [];
    const expired: string[] = [];
    for (const stored of this.state.mail.messages) {
      if (!isQueued(stored)) continue;
      if (now >= stored.message.expires_at) {
        expired.push(stored.message.message_id);
        continue;
      }
      const card = this.state.mail.pins.get(stored.message.to, stored.mailbox_id);
      if (!card) continue;
      try {
        if ((await this.deliver(stored, card)) === "delivered") delivered.push(stored.message.message_id);
      } catch {
        if (stored.delivery?.last_error) errors.push(stored.delivery.last_error);
      }
    }
    return { delivered, expired };
  }

  private async pollMailboxes(only: string | undefined, errors: RouteError[]): Promise<MailMessageView[]> {
    const owner = this.agentId();
    const keyring = this.mailKeyring();
    // Every route of every retained card: old routes keep queued packets until
    // they are retrieved or expire (Agent Mail Section 4.3).
    const targets: [string, string[]][] = [];
    for (const [mailboxId, cards] of this.state.mail.mailboxes) {
      if (only !== undefined && only !== mailboxId) continue;
      const routes: string[] = [];
      for (const card of [...cards].reverse()) {
        for (const route of card.event.payload.routes) if (!routes.includes(route)) routes.push(route);
      }
      targets.push([mailboxId, routes]);
    }
    const received: MailMessageView[] = [];
    for (const [mailboxId, routes] of targets) {
      for (const route of routes) {
        if (!this.isAllowedHost(route)) continue;
        const client = this.mailClient(route);
        const jwt = this.requestJwt(route);
        const deletions: string[] = [];
        let cursor: string | undefined;
        for (let pageCount = 0; pageCount < SYNC_MAX_PAGES; pageCount += 1) {
          let listed;
          try {
            listed = await client.list(mailboxId, owner, jwt, { limit: SYNC_PAGE_LIMIT, cursor });
          } catch (error) {
            errors.push({ ...routeError(route, error), mailbox_id: mailboxId });
            break;
          }
          const now = unixTimeMillis();
          for (const record of listed.result) {
            const outcome = await this.acceptPacket(keyring, mailboxId, record, now);
            if (outcome === "delete") deletions.push(record.packet_id);
            else if ("error" in outcome) {
              errors.push({ ...routeError(route, outcome.error), mailbox_id: mailboxId, packet_id: record.packet_id });
            } else received.push(outcome.stored);
          }
          cursor = listed.next_cursor;
          if (cursor === undefined) break;
        }
        for (const packetId of deletions) {
          try {
            await client.delete(mailboxId, packetId, owner, jwt);
          } catch (error) {
            errors.push({ ...routeError(route, error), mailbox_id: mailboxId, packet_id: packetId });
          }
        }
      }
    }
    return received;
  }

  /**
   * Recipient acceptance (Agent Mail Section 7.2) of one listed packet, whose
   * shape, hash, and signature the list already verified. A new message keeps
   * its relay copy until a later sync, after the host saved this call's state.
   */
  private async acceptPacket(
    keyring: MailKeyring,
    mailboxId: string,
    record: MailPacketRecord,
    now: number,
  ): Promise<"delete" | { error: unknown } | { stored: MailMessageView }> {
    const packet = record.packet;
    // Sender policy applies before decryption.
    if (this.state.mail.blockedSenders.has(packet.event.actor) || now >= packet.event.payload.header.expires_at) {
      return "delete";
    }
    let message: MailMessagePayload;
    try {
      message = await keyring.open(packet, now);
    } catch (error) {
      return { error };
    }
    const existing = this.state.mail.messages.find((stored) =>
      stored.direction === "received" &&
      stored.message.from === message.from &&
      stored.message.message_id === message.message_id);
    if (existing) {
      return sameMessage(existing.message, message)
        ? "delete"
        : { error: protocolError("invalid_event", "message ID reused for different content") };
    }
    if (message.reply_card !== undefined) {
      // Verified with the message; a card older than the pin is not used.
      try {
        this.state.mail.pins.observe(message.reply_card, message.from, now, false);
      } catch {
        // The pin stays.
      }
    }
    const stored: StoredMailMessage = { direction: "received", message, mailbox_id: mailboxId, received_at: now, read: false };
    this.insertInbox(mailInboxItem(message, now));
    this.state.mail.messages.push(stored);
    return { stored: mailMessageView(stored, false) };
  }

  /** The retained cards whose keys are loaded, for opening packets. */
  private mailKeyring(): MailKeyring {
    const keyring = new MailKeyring(this.agentId());
    for (const cards of this.state.mail.mailboxes.values()) {
      for (const card of cards) {
        const key = this.mailKeys.get(card.event.payload.public_key);
        if (key) keyring.add(card, key);
      }
    }
    return keyring;
  }

  /** Drops cards past `receive_until` with keys no retained card advertises, stale pins, and expired messages. */
  private pruneMail(now: number): void {
    const mail = this.state.mail;
    for (const [mailboxId, cards] of mail.mailboxes) {
      const kept = cards.filter((card) => now < card.event.payload.receive_until);
      if (kept.length === 0) mail.mailboxes.delete(mailboxId);
      else mail.mailboxes.set(mailboxId, kept);
    }
    const advertised = new Set([...mail.mailboxes.values()].flat().map((card) => card.event.payload.public_key));
    for (const [publicKey, key] of this.mailKeys) {
      if (!advertised.has(publicKey)) {
        key.destroy();
        this.mailKeys.delete(publicKey);
      }
    }
    mail.pins.prune(now);
    mail.messages = mail.messages.filter((stored) => now < stored.message.expires_at);
  }

  private replyParent(messageId: string, to: string | undefined): MailMessagePayload {
    const owner = to === undefined ? undefined : parseMailAddress(to).owner;
    const found = this.state.mail.messages.filter((stored) =>
      stored.direction === "received" &&
      stored.message.message_id === messageId &&
      (owner === undefined || stored.message.from === owner));
    if (found.length > 1) throw invalidPayload("several received messages share this message_id; pass to");
    if (found.length === 0) throw invalidPayload("no received message has this message_id");
    return found[0].message;
  }

  private openMailboxCard(mailboxId: string, now: number): MailboxCard {
    const card = this.state.mail.mailboxes.get(mailboxId)?.at(-1);
    if (!card) throw invalidPayload("unknown reply mailbox");
    try {
      validateMailSenderCard(card, this.agentId(), now);
    } catch {
      throw invalidPayload("the reply mailbox is not open");
    }
    return card;
  }

  private mailboxView(mailboxId: string, card: MailboxCard, now: number): MailboxView {
    const unread = this.state.mail.messages.filter((stored) => isUnread(stored) && stored.mailbox_id === mailboxId).length;
    return mailboxView(mailboxId, card, now, unread);
  }

  // ── Agent Knowledge (local connector Section 4.3).

  private async knowledgeSubmit(input: KnowledgeSubmitInput): Promise<unknown> {
    if (!Array.isArray(input.services) || input.services.length === 0 || input.services.length > MAX_KNOWLEDGE_SERVICES) {
      throw invalidPayload("services must name one to eight services");
    }
    const services: string[] = [];
    for (const service of input.services) {
      const origin = this.knowledgeOrigin(service);
      if (services.includes(origin)) throw invalidPayload("duplicate service");
      services.push(origin);
    }
    if (!(KNOWLEDGE_EVENT_TYPES as readonly string[]).includes(input.type)) {
      throw invalidPayload(`unknown Knowledge event type: ${input.type}`);
    }
    const createdAt = unixTimeMillis();
    const envelope = this.signer.signEvent(
      createEvent(KNOWLEDGE_PROTOCOL, input.type, this.agentId(), createdAt, this.nonces.nextNonce(createdAt), input.payload),
    ) as KnowledgeEnvelope;
    // A malformed contribution fails here, before anything is disclosed.
    validateKnowledgeEnvelope(envelope);
    const results: Record<string, unknown>[] = [];
    let firstError: unknown;
    let accepted = false;
    for (const service of services) {
      try {
        const client = await this.knowledge(service);
        const record = await client.submit(envelope, this.requestJwt(service));
        results.push({ service, item: knowledgeItem(record) });
        accepted = true;
      } catch (error) {
        results.push({ service, error: errorJson(error) });
        firstError ??= error;
      }
    }
    if (!accepted) throw firstError;
    return { id: envelope.hash, envelope, results };
  }

  private async knowledgeQuery(input: KnowledgeQueryInput): Promise<unknown> {
    const { service, ...query } = input;
    const response = await (await this.knowledge(service)).query(query);
    const result = scoped(response, { items: response.result.map(knowledgeItem) });
    return response.next_cursor === undefined ? result : { ...result, next_cursor: response.next_cursor };
  }

  private async knowledgeGet(input: KnowledgeGetInput): Promise<unknown> {
    const response = await (await this.knowledge(input.service)).batch(input.ids);
    return scoped(response, { items: response.result.map(knowledgeItem), missing: response.missing });
  }

  private async knowledgeSearch(input: KnowledgeSearchInput): Promise<unknown> {
    const { service, ...request } = input;
    const response = await (await this.knowledge(service)).search(request);
    const hits = response.result.map((hit) => ({
      item: knowledgeItem(hit.record),
      ...(hit.explanation === undefined ? {} : { explanation: hit.explanation }),
    }));
    return scoped(response, { hits, ranking: response.ranking, coverage: response.coverage });
  }

  /**
   * The lifecycle check of Agent Knowledge Section 9.6 at one service: the
   * event, then every page of `target={id}` within the page bound.
   */
  private async knowledgeStatus(input: KnowledgeStatusInput): Promise<unknown> {
    validateKnowledgeId(input.id, "invalid_request");
    const origin = this.knowledgeOrigin(input.service);
    const client = await this.knowledge(origin);
    const batch = await client.batch([input.id]);
    const record: KnowledgeRecord | undefined = batch.result[0];
    if (!record) throw protocolError("not_found", "event not found at this service");
    const target = record.envelope.event;

    const tracker = new KnowledgePageTracker(origin);
    const request: Record<string, unknown> = { target: input.id, limit: STATUS_PAGE_LIMIT };
    const links: KnowledgeRecord[] = [];
    let scope: KnowledgeQueryResponse | undefined;
    for (let pageCount = 0; pageCount < STATUS_MAX_PAGES; pageCount += 1) {
      const response = await client.query(request as KnowledgeQuery);
      tracker.accept(request as KnowledgeQuery, response);
      links.push(...response.result);
      scope ??= response;
      if (tracker.complete) break;
      request.cursor = response.next_cursor;
    }

    // The service checked target rules; same-author and nonce rules are
    // rechecked here so a hostile service cannot withdraw another's event.
    const laterByAuthor = (event: KnowledgeEnvelope["event"]) =>
      event.actor === target.actor && event.nonce > target.nonce;
    const retractions = new Set<string>();
    const successors = new Set<string>();
    const assessments = new Set<string>();
    for (const link of links) {
      const event = link.envelope.event;
      const payload = event.payload as unknown as Record<string, unknown>;
      if (event.type === "knowledge.retract" && payload.target === input.id && laterByAuthor(event)) {
        retractions.add(link.envelope.hash);
      } else if (event.type === "knowledge.assess" && payload.target === input.id) {
        assessments.add(link.envelope.hash);
      } else if (
        event.type === "knowledge.publish" &&
        laterByAuthor(event) &&
        Array.isArray(payload.relations) &&
        payload.relations.some((relation: { relation?: unknown; target?: unknown }) =>
          relation.relation === "supersedes" && relation.target === input.id)
      ) {
        successors.add(link.envelope.hash);
      }
    }
    const sorted = (ids: Set<string>) => [...ids].sort(compareStrings);
    const complete = tracker.complete;
    return scoped(scope!, {
      item: knowledgeItem(record),
      complete,
      ...(complete ? { status: retractions.size === 0 ? "active" : "retracted" } : {}),
      retractions: sorted(retractions),
      successors: sorted(successors),
      assessments: sorted(assessments),
    });
  }

  /** A service origin the operator allows. */
  private knowledgeOrigin(service: string): string {
    const origin = normalizeHost(service);
    validateOrigin(origin);
    this.requireAllowedHost(origin);
    return origin;
  }

  /** The service's client, built from its discovery document once per session. */
  private async knowledge(service: string): Promise<KnowledgeClient> {
    const origin = this.knowledgeOrigin(service);
    let client = this.knowledgeClients.get(origin);
    if (!client) {
      client = await KnowledgeClient.discover(origin, this.fetchImpl);
      this.knowledgeClients.set(origin, client);
    }
    return client;
  }

  private isAllowedHost(host: string): boolean {
    return this.state.hosts.get(normalizeHost(host))?.allowed === true;
  }

  // ── Internal helpers.

  private localRoom(key: RoomKey): LocalRoomState {
    const room = this.state.rooms.get(roomKeyString(key));
    if (!room) throw invalidPayload(`room is not open locally: ${key.roomId}`);
    return room;
  }

  private requireAllowedHost(host: string): void {
    const record = this.state.hosts.get(normalizeHost(host));
    if (!record || !record.allowed) throw permissionDenied();
  }

  /**
   * Operator policy for a service URL that is not a discourse host: its origin
   * must be an allowed host or the profile service of one.
   */
  private requireAllowedOrigin(url: string): void {
    const origin = serviceOrigin(url);
    if (this.state.hosts.get(origin)?.allowed) return;
    for (const host of this.state.hosts.values()) {
      if (host.allowed && host.profile_service !== undefined && serviceOrigin(host.profile_service) === origin) return;
    }
    throw permissionDenied();
  }

  private allowedRoomHost(key: RoomKey): string {
    const host = this.localRoom(key).host;
    this.requireAllowedHost(host);
    return host;
  }

  private ensureHost(host: string): void {
    if (!this.state.hosts.has(host)) {
      this.state.hosts.set(host, { host, allowed: false, features: [] });
    }
  }

  private insertInbox(item: InboxItem): void {
    if (!this.state.inbox.has(item.id)) {
      this.state.inbox.set(item.id, { item, state: { kind: "pending" } });
    }
  }

  private pendingInboxCount(roomId?: string): number {
    const now = unixTimeMillis();
    let count = 0;
    for (const entry of this.state.inbox.values()) {
      if (!inboxEntryReady(entry, now)) continue;
      if (roomId !== undefined && entry.item.room_id !== roomId) continue;
      count += 1;
    }
    return count;
  }

  private sortedHosts(): AgentProtocolsHost[] {
    return [...this.state.hosts.entries()]
      .sort((a, b) => compareStrings(a[0], b[0]))
      .map(([, host]) => host);
  }

  /**
   * The host's client, built from its discovery document on first use. The
   * host must be allowed before discovery, and on every use the allowlist
   * covers the discovered `rooms` origin too, since the connector signs for it.
   */
  private async discourse(host: string): Promise<DiscourseClient> {
    const key = normalizeHost(host);
    this.requireAllowedHost(key);
    let client = this.discourseClients.get(key);
    if (!client) {
      client = await DiscourseClient.discover(key, this.fetchImpl);
      this.discourseClients.set(key, client);
    }
    this.requireAllowedHost(serviceOrigin(client.roomsUrl));
    return client;
  }

  /**
   * Locates the profile endpoints from the service's discovery document; the
   * allowlist covers the discovered origin too, since the connector signs for it.
   */
  private async profileClient(url: string): Promise<ProfileClient> {
    const client = await ProfileClient.discover(url, this.fetchImpl);
    this.requireAllowedOrigin(client.profilesUrl);
    return client;
  }
}
