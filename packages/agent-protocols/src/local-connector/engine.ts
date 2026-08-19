// The stateful local connector engine. `LocalConnector` is transport-neutral:
// it signs on the active agent's behalf, calls an Agent Discourse host over
// HTTP, materializes local room state by projecting accepted records, derives
// an actionable inbox, and holds drafts on a room-head mismatch — all behind a
// single `callTool` dispatcher. The agent never sees the signing key or a
// reusable request JWT. This is one deep module; its methods are mutually
// recursive over `this`, so the class stays whole here while the data shapes
// and pure projection live in sibling submodules.

import {
  AgentStatus,
  AgentStatusInput,
  MessageCreatePayload,
  ReasonPayload,
  RoomCreatePayload,
  RoomJoinPayload,
  RoomJoinRequestInput,
  RoomJoinRequestStatus,
  RoomJoinReviewPayload,
  RoomMemberRemovePayload,
  RoomPolicy,
  RoomResponse,
  ServerRecord,
  Visibility,
  discourseEvent,
  eventType,
  roomCreateEvent,
  validateDiscourseEnvelope,
  validateRoomPath,
  verifyServerRecord,
} from "../discourse.js";
import {
  AgentId,
  AgentSigner,
  ClientNonceManager,
  DEFAULT_REQUEST_JWT_TTL_SECS,
  Envelope,
  createRequestBinding,
  createRequestJwtClaims,
  publicKeyBytes,
  serviceOrigin,
  unixTimeMillis,
  unixTimeSecs,
  withMentions,
} from "../identity.js";
import {
  DelegationClient,
  DiscourseClient,
  FetchLike,
  ProfileClient,
} from "../http-client.js";
import {
  DelegationGrantPayload,
  PrincipalDocument,
  delegationGrantEvent,
  delegationRevokeEvent,
  isPrincipalAlias,
  validateDelegationGrantPayload,
} from "../delegation.js";
import {
  AgentProfile,
  ProfileUpdatePayload,
  profileUpdateEvent,
} from "../profile.js";

import {
  TOOL_AGENT_STATUS_CLEAR,
  TOOL_AGENT_STATUS_GET,
  TOOL_AGENT_STATUS_LIST,
  TOOL_AGENT_STATUS_SET,
  TOOL_DRAFTS_LIST,
  TOOL_DRAFT_COMMIT,
  TOOL_DRAFT_DROP,
  TOOL_DRAFT_GET,
  TOOL_HOSTS_LIST,
  TOOL_IDENTITY_CURRENT,
  TOOL_INBOX_ACK,
  TOOL_INBOX_NEXT,
  TOOL_JOIN_REQUESTS_LIST,
  TOOL_JOIN_REQUEST_REVIEW,
  TOOL_PROFILE_UPDATE,
  TOOL_ROOMS_LIST,
  TOOL_PRINCIPAL_RESOLVE,
  TOOL_DELEGATION_CHECK,
  TOOL_DELEGATIONS_LIST,
  TOOL_DELEGATION_GRANT,
  TOOL_DELEGATION_REVOKE,
  TOOL_ROOMS_SEARCH,
  TOOL_ROOM_CREATE,
  TOOL_ROOM_JOIN,
  TOOL_ROOM_JOIN_REQUEST,
  TOOL_ROOM_JOIN_WHEN_APPROVED,
  TOOL_ROOM_LEAVE,
  TOOL_ROOM_MARK_READ,
  TOOL_ROOM_MEMBERS_LIST,
  TOOL_ROOM_MEMBER_GET,
  TOOL_ROOM_OPEN,
  TOOL_ROOM_SEND_MESSAGE,
  TOOL_ROOM_STATE,
  TOOL_ROOM_SUBMIT_EVENT,
  TOOL_ROOM_TIMELINE,
  TOOL_ROOM_UNREAD,
} from "./catalog.js";
import {
  invalidPayload,
  isRecord,
  normalizeHost,
  permissionDenied,
} from "./internal.js";
import {
  AgentStatusClearInput,
  AgentStatusGetInput,
  AgentStatusListInput,
  AgentStatusSetInput,
  DraftCommitInput,
  DraftDropInput,
  DraftGetInput,
  DraftsListInput,
  InboxAckInput,
  InboxNextInput,
  JoinRequestReviewInput,
  JoinRequestsListInput,
  ProfileUpdateInput,
  RoomCreateInput,
  RoomJoinInput,
  RoomJoinRequestToolInput,
  RoomJoinWhenApprovedInput,
  RoomLeaveInput,
  RoomMarkReadInput,
  RoomMemberGetInput,
  RoomMembersListInput,
  RoomOpenInput,
  RoomSendMessageInput,
  RoomStateInput,
  RoomSubmitEventInput,
  RoomTimelineInput,
  RoomUnreadInput,
  RoomsListInput,
  PrincipalResolveInput,
  DelegationCheckInput,
  DelegationsListInput,
  DelegationGrantInput,
  DelegationRevokeInput,
  RoomsSearchInput,
} from "./inputs.js";
import {
  applyRecordProjection,
  eventTypeAdvancesRoomHead,
  inboxEntryReady,
  isDuplicateRecord,
  materializeCreator,
  membershipFilter,
  recordAdvancesRoomHead,
  validateNextRecord,
  validateRecordBasePrecondition,
} from "./projection.js";
import { LocalConnectorState, LocalRoomState, RoomKey } from "./state.js";
import {
  AgentProtocolsHost,
  DraftAction,
  HeldDraft,
  InboxItem,
  RoomMemberProfile,
  RoomMemberView,
  RoomStateView,
  RoomSummary,
  RoomWriteResult,
  SyncState,
  TimelineItem,
  roomSummaryFromResponse,
  timelineItemFromRecord,
} from "./views.js";

interface HeadMismatchState {
  sync: SyncState;
  changes: TimelineItem[];
}

function roomKeyString(key: RoomKey): string {
  return `${key.host} ${key.roomId}`;
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
  return ["revise", "send_as_is", "stay_silent", "send_anyway"];
}

function profileToMemberProfile(profile: AgentProfile): RoomMemberProfile {
  return {
    name: profile.name,
    description: profile.description,
    avatar_url: profile.avatar_url,
  };
}

function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function parseCursor(cursor: string | undefined): number {
  if (cursor === undefined) return 0;
  const parsed = Number.parseInt(cursor, 10);
  return Number.isNaN(parsed) ? 0 : parsed;
}

function sortedAgentStatuses(
  statuses: Map<AgentId, AgentStatus>,
): AgentStatus[] {
  return [...statuses.entries()]
    .sort((a, b) => compareStrings(a[0], b[0]))
    .map(([, status]) => status);
}

export interface LocalConnectorOptions {
  /** Restore a previously persisted working set. Defaults to empty. */
  state?: LocalConnectorState;
  /** Injected `fetch`, e.g. for tests or a custom transport. */
  fetchImpl?: FetchLike;
}

export class LocalConnector {
  readonly state: LocalConnectorState;
  private readonly nonces = new ClientNonceManager();
  private readonly fetchImpl: FetchLike;

  constructor(
    private readonly signer: AgentSigner,
    options: LocalConnectorOptions = {},
  ) {
    this.state = options.state ?? new LocalConnectorState();
    this.fetchImpl = options.fetchImpl ?? fetch;
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
  applyRecord(record: ServerRecord): void {
    const key = this.resolveRoomKey(undefined, record.room_id);
    this.applyRecordTo(key, record);
  }

  /** Applies a verified record to the room on the given host. */
  applyHostRecord(host: string, record: ServerRecord): void {
    const key: RoomKey = { host: normalizeHost(host), roomId: record.room_id };
    this.applyRecordTo(key, record);
  }

  private applyRecordTo(key: RoomKey, record: ServerRecord): void {
    validateDiscourseEnvelope(record.envelope);
    validateRoomPath(record.envelope, record.room_id);
    verifyServerRecord(record);

    const activeAgent = this.agentId();
    const room = this.state.rooms.get(roomKeyString(key));
    if (!room) {
      throw invalidPayload(`room is not open locally: ${key.roomId}`);
    }
    if (isDuplicateRecord(room, record)) return;
    validateNextRecord(room, record);
    validateRecordBasePrecondition(room, record);

    const item = timelineItemFromRecord(record);
    const newInbox: InboxItem[] = [];
    applyRecordProjection(room, record, item, activeAgent, newInbox);

    let clearedStatus: AgentId | undefined;
    if (record.envelope.event.type === eventType.ROOM_MEMBER_REMOVE) {
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
      case TOOL_HOSTS_LIST:
        return this.hostsList();
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
      case TOOL_ROOMS_SEARCH:
        return this.roomsSearch(input as RoomsSearchInput);
      case TOOL_ROOMS_LIST:
        return this.roomsList(input as RoomsListInput);
      case TOOL_ROOM_OPEN:
        return this.roomOpen(input as RoomOpenInput);
      case TOOL_ROOM_STATE:
        return this.roomStateTool(input as RoomStateInput);
      case TOOL_ROOM_MEMBERS_LIST:
        return this.roomMembersList(input as RoomMembersListInput);
      case TOOL_ROOM_MEMBER_GET:
        return this.roomMemberGet(input as RoomMemberGetInput);
      case TOOL_AGENT_STATUS_LIST:
        return this.agentStatusList(input as AgentStatusListInput);
      case TOOL_AGENT_STATUS_GET:
        return this.agentStatusGet(input as AgentStatusGetInput);
      case TOOL_AGENT_STATUS_SET:
        return this.agentStatusSet(input as AgentStatusSetInput);
      case TOOL_AGENT_STATUS_CLEAR:
        return this.agentStatusClear(input as AgentStatusClearInput);
      case TOOL_ROOM_TIMELINE:
        return this.roomTimeline(input as RoomTimelineInput);
      case TOOL_ROOM_UNREAD:
        return this.roomUnread(input as RoomUnreadInput);
      case TOOL_ROOM_MARK_READ:
        return this.roomMarkRead(input as RoomMarkReadInput);
      case TOOL_INBOX_NEXT:
        return this.inboxNext(input as InboxNextInput);
      case TOOL_INBOX_ACK:
        return this.inboxAck(input as InboxAckInput);
      case TOOL_DRAFTS_LIST:
        return this.draftsList(input as DraftsListInput);
      case TOOL_DRAFT_GET:
        return this.draftGet(input as DraftGetInput);
      case TOOL_DRAFT_COMMIT:
        return this.draftCommit(input as DraftCommitInput);
      case TOOL_DRAFT_DROP:
        return this.draftDrop(input as DraftDropInput);
      case TOOL_PROFILE_UPDATE:
        return this.profileUpdate(input as ProfileUpdateInput);
      case TOOL_ROOM_CREATE:
        return this.roomCreate(input as RoomCreateInput);
      case TOOL_ROOM_JOIN:
        return this.roomJoin(input as RoomJoinInput);
      case TOOL_ROOM_JOIN_REQUEST:
        return this.roomJoinRequest(input as RoomJoinRequestToolInput);
      case TOOL_ROOM_JOIN_WHEN_APPROVED:
        return this.roomJoinWhenApproved(input as RoomJoinWhenApprovedInput);
      case TOOL_ROOM_LEAVE:
        return this.roomLeave(input as RoomLeaveInput);
      case TOOL_ROOM_SEND_MESSAGE:
        return this.roomSendMessage(input as RoomSendMessageInput);
      case TOOL_ROOM_SUBMIT_EVENT:
        return this.roomSubmitEvent(input as RoomSubmitEventInput);
      case TOOL_JOIN_REQUESTS_LIST:
        return this.joinRequestsList(input as JoinRequestsListInput);
      case TOOL_JOIN_REQUEST_REVIEW:
        return this.joinRequestReview(input as JoinRequestReviewInput);
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

  private hostsList(): unknown {
    return { hosts: this.sortedHosts() };
  }

  private async roomsSearch(input: RoomsSearchInput): Promise<unknown> {
    const host = normalizeHost(input.host);
    this.requireAllowedHost(host);
    const rooms = await this.discourse(host).publicRooms({
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
    for (const room of rooms) this.observeRoom(host, room);
    const summaries = rooms.map((room) => this.summaryForResponse(host, room));
    return { rooms: summaries };
  }

  private roomsList(input: RoomsListInput): unknown {
    const offset = parseCursor(input.cursor);
    const limit = input.limit ?? 50;
    const agentId = this.agentId();
    const rooms = [...this.state.rooms.values()]
      .sort(
        (a, b) =>
          compareStrings(a.host, b.host) ||
          compareStrings(a.room.id, b.room.id),
      )
      .filter((room) =>
        input.status !== undefined ? room.room.status === input.status : true,
      )
      .filter((room) => membershipFilter(room, agentId, input.membership))
      .slice(offset, offset + limit)
      .map((room) => this.summaryForRoom(room));
    return { rooms };
  }

  private async roomOpen(input: RoomOpenInput): Promise<unknown> {
    const host = normalizeHost(input.host);
    this.requireAllowedHost(host);
    const key: RoomKey = { host, roomId: input.room_id };
    const previousSeq =
      this.state.rooms.get(roomKeyString(key))?.syncedSeq ?? 0;
    if (input.refresh || previousSeq === 0) {
      const client = this.discourse(host);
      const room = await client.room(input.room_id);
      this.observeRoom(host, room);
      const jwt = this.requestJwt(host);
      const records = await client.events(input.room_id, {
        afterSeq: previousSeq > 0 ? previousSeq : undefined,
        jwt,
      });
      for (const record of records) this.applyHostRecord(host, record);
    }
    const opened = this.state.rooms.get(roomKeyString(key));
    if (opened) opened.subscribed = input.subscribe ?? false;
    const room = this.localRoom(key);
    return {
      room: this.roomStateView(room),
      sync: this.syncState(key),
      active_turn: room.activeTurn,
    };
  }

  private async roomStateTool(input: RoomStateInput): Promise<unknown> {
    void input.include_types;
    const key = this.resolveRoomKey(input.host, input.room_id);
    if (input.refresh) {
      const host = this.localRoom(key).host;
      return this.roomOpen({ host, room_id: input.room_id, refresh: true });
    }
    const room = this.localRoom(key);
    return { room: this.roomStateView(room), sync: this.syncState(key) };
  }

  private roomMembersList(input: RoomMembersListInput): unknown {
    const key = this.resolveRoomKey(input.host, input.room_id);
    const room = this.localRoom(key);
    const offset = parseCursor(input.cursor);
    const limit = input.limit ?? 100;
    const members = [...room.members.values()]
      .sort((a, b) => compareStrings(a.agent_id, b.agent_id))
      .filter((member) =>
        input.status !== undefined ? member.status === input.status : true,
      )
      .filter((member) =>
        input.role !== undefined ? member.role === input.role : true,
      )
      .slice(offset, offset + limit)
      .map((member) => ({ ...member }));
    if (input.include_profiles) {
      for (const member of members) {
        if (member.profile === undefined) {
          const profile = this.state.profiles.get(member.agent_id);
          if (profile) member.profile = profileToMemberProfile(profile);
        }
      }
    }
    return { members, sync: this.syncState(key) };
  }

  private roomMemberGet(input: RoomMemberGetInput): unknown {
    const key = this.resolveRoomKey(input.host, input.room_id);
    const room = this.localRoom(key);
    const found = room.members.get(input.agent_id);
    if (!found) throw invalidPayload("room member not found");
    const member = { ...found };
    if (input.include_profile && member.profile === undefined) {
      const profile = this.state.profiles.get(member.agent_id);
      if (profile) member.profile = profileToMemberProfile(profile);
    }
    const recent = input.include_recent_activity
      ? room.timeline
          .filter((item) => item.actor === input.agent_id)
          .slice(-10)
          .reverse()
      : [];
    return { member, recent, sync: this.syncState(key) };
  }

  private async agentStatusList(input: AgentStatusListInput): Promise<unknown> {
    const key = this.resolveRoomKey(input.host, input.room_id);
    const keyStr = roomKeyString(key);
    if (!input.refresh) {
      const cached = this.state.agentStatuses.get(keyStr);
      if (cached) {
        return {
          statuses: sortedAgentStatuses(cached),
          sync: this.syncState(key),
        };
      }
    }
    const host = this.allowedRoomHost(key);
    const jwt = this.requestJwt(host);
    const response = await this.discourse(host).agentStatuses(
      input.room_id,
      jwt,
    );
    const statuses = new Map<AgentId, AgentStatus>();
    for (const status of response.statuses) {
      statuses.set(status.agent_id, status);
    }
    this.state.agentStatuses.set(keyStr, statuses);
    return { statuses: sortedAgentStatuses(statuses), sync: this.syncState(key) };
  }

  private async agentStatusGet(input: AgentStatusGetInput): Promise<unknown> {
    const key = this.resolveRoomKey(input.host, input.room_id);
    const keyStr = roomKeyString(key);
    if (!input.refresh) {
      const cached = this.state.agentStatuses.get(keyStr)?.get(input.agent_id);
      if (cached) return { status: cached, sync: this.syncState(key) };
    }
    const host = this.allowedRoomHost(key);
    const jwt = this.requestJwt(host);
    const response = await this.discourse(host).agentStatus(
      input.room_id,
      input.agent_id,
      jwt,
    );
    let statuses = this.state.agentStatuses.get(keyStr);
    if (!statuses) {
      statuses = new Map();
      this.state.agentStatuses.set(keyStr, statuses);
    }
    statuses.set(response.status.agent_id, response.status);
    return { status: response.status, sync: this.syncState(key) };
  }

  private async agentStatusSet(input: AgentStatusSetInput): Promise<unknown> {
    const key = this.resolveRoomKey(input.host, input.room_id);
    const keyStr = roomKeyString(key);
    const host = this.allowedRoomHost(key);
    const jwt = this.requestJwt(host);
    const request: AgentStatusInput = {
      state: input.state,
      summary: input.summary,
      seen_seq: input.seen_seq,
      seen_hash: input.seen_hash,
      claim_id: input.claim_id,
      activity: input.activity,
      expires_at: input.expires_at,
      extra: input.extra,
    };
    const status = await this.discourse(host).setAgentStatus(
      input.room_id,
      jwt,
      request,
    );
    let statuses = this.state.agentStatuses.get(keyStr);
    if (!statuses) {
      statuses = new Map();
      this.state.agentStatuses.set(keyStr, statuses);
    }
    statuses.set(status.agent_id, status);
    return { status, sync: this.syncState(key) };
  }

  private async agentStatusClear(
    input: AgentStatusClearInput,
  ): Promise<unknown> {
    const key = this.resolveRoomKey(input.host, input.room_id);
    const host = this.allowedRoomHost(key);
    const jwt = this.requestJwt(host);
    const request: AgentStatusInput = {
      state: "away",
      expires_at: unixTimeMillis() - 1,
    };
    await this.discourse(host).setAgentStatus(input.room_id, jwt, request);
    this.state.agentStatuses.get(roomKeyString(key))?.delete(this.agentId());
    return { cleared: true, room_id: input.room_id };
  }

  private roomTimeline(input: RoomTimelineInput): unknown {
    void input.refresh;
    void input.include_records;
    const key = this.resolveRoomKey(input.host, input.room_id);
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
        input.actors !== undefined ? input.actors.includes(item.actor) : true,
      )
      .filter((item) => !input.unread_only || item.seq > room.readSeq)
      .slice(0, input.limit ?? 50);
    const nextAfterSeq =
      items.length > 0 ? items[items.length - 1].seq : undefined;
    return {
      items,
      sync: this.syncState(key),
      next_after_seq: nextAfterSeq,
    };
  }

  private roomUnread(input: RoomUnreadInput): unknown {
    const key = this.resolveRoomKey(input.host, input.room_id);
    const room = this.localRoom(key);
    let items = room.timeline
      .filter((item) => item.seq > room.readSeq)
      .slice(0, input.limit ?? 50);
    const throughSeq =
      items.length > 0 ? items[items.length - 1].seq : undefined;
    if (input.mark_read) {
      if (throughSeq !== undefined) room.readSeq = throughSeq;
      items =
        throughSeq !== undefined
          ? room.timeline.filter((item) => item.seq <= throughSeq)
          : [];
    }
    return {
      items,
      unread_count: unreadCount(room),
      sync: this.syncState(key),
    };
  }

  private roomMarkRead(input: RoomMarkReadInput): unknown {
    const key = this.resolveRoomKey(input.host, input.room_id);
    const room = this.localRoom(key);
    room.readSeq = Math.max(room.readSeq, input.through_seq);
    return {
      room_id: input.room_id,
      read_seq: room.readSeq,
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
        if (input.claim) entry.state = { kind: "claimed" };
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
    const offset = parseCursor(input.cursor);
    const limit = input.limit ?? 50;
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
      .slice(offset, offset + limit + 1)
      .map((entry) => entry.draft);
    let nextCursor: string | undefined;
    if (drafts.length > limit) {
      drafts.pop();
      nextCursor = String(offset + limit);
    }
    return { drafts, next_cursor: nextCursor };
  }

  private draftGet(input: DraftGetInput): unknown {
    const entry = this.state.drafts.get(input.draft_id);
    if (!entry) throw invalidPayload("draft not found");
    const key: RoomKey = {
      host: entry.draft.current_sync.host,
      roomId: entry.draft.room_id,
    };
    return {
      draft: entry.draft,
      changes: this.roomChangesSince(key, entry.draft.base_seq),
      sync: this.syncState(key),
    };
  }

  private async draftCommit(input: DraftCommitInput): Promise<unknown> {
    const entry = this.state.drafts.get(input.draft_id);
    if (!entry) throw invalidPayload("draft not found");

    if (input.action === "stay_silent") {
      this.state.drafts.delete(input.draft_id);
      return { status: "dropped", draft_id: input.draft_id };
    }

    let result: RoomWriteResult;
    if (entry.request.kind === "message") {
      const request: RoomSendMessageInput = { ...entry.request.input };
      if (input.action === "send_anyway") {
        request.base_seq = undefined;
        request.base_hash = undefined;
        request.on_head_mismatch = "send_anyway";
        result = await this.submitMessageUnchecked(request);
      } else {
        if (input.action === "revise") {
          if (input.content !== undefined) request.content = input.content;
          if (input.content_type !== undefined)
            request.content_type = input.content_type;
          if (input.mentions !== undefined) request.mentions = input.mentions;
          if (input.references !== undefined)
            request.references = input.references;
          if (input.extra !== undefined) request.extra = input.extra;
        }
        request.base_seq = input.base_seq;
        request.base_hash = input.base_hash;
        request.on_head_mismatch = input.on_head_mismatch;
        result = await this.roomSendMessage(request);
      }
    } else {
      const request: RoomSubmitEventInput = { ...entry.request.input };
      if (input.action === "send_anyway") {
        request.base_seq = undefined;
        request.base_hash = undefined;
        request.on_head_mismatch = "send_anyway";
        result = await this.submitEventUnchecked(request);
      } else {
        if (input.action === "revise") {
          if (input.type !== undefined) request.type = input.type;
          if (input.payload !== undefined) request.payload = input.payload;
          if (input.mentions !== undefined) request.mentions = input.mentions;
          if (input.references !== undefined)
            request.references = input.references;
        }
        request.base_seq = input.base_seq;
        request.base_hash = input.base_hash;
        request.on_head_mismatch = input.on_head_mismatch;
        result = await this.roomSubmitEvent(request);
      }
    }

    if (result.status === "sent" || result.status === "held") {
      this.state.drafts.delete(input.draft_id);
    }
    return result;
  }

  private draftDrop(input: DraftDropInput): unknown {
    this.state.drafts.delete(input.draft_id);
    return {
      status: "dropped",
      draft_id: input.draft_id,
      pending_count: this.state.drafts.size,
    };
  }

  /**
   * Resolves a principal per Agent Delegation Section 5.3 and reports whether
   * the requested URL is an alias the principal acknowledges. Any origin can
   * redirect to any principal, so an unlisted URL is never presented as a name
   * for it.
   */
  private async resolvePrincipal(
    url: string,
  ): Promise<{ document: PrincipalDocument; alias: boolean }> {
    const document = await this.delegationClient(url).principal(url);
    return {
      document,
      alias: document.id !== url && isPrincipalAlias(document, url),
    };
  }

  /**
   * Resolves the principal and refuses when the active Agent ID is not one of
   * its controller keys, so a grant that could never be accepted is not signed
   * or transmitted.
   */
  private async controllerPrincipal(
    principalId: string,
  ): Promise<PrincipalDocument> {
    const { document } = await this.resolvePrincipal(principalId);
    const active = this.agentId();
    if (!document.controllers.includes(active)) {
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
    const { document } = await this.resolvePrincipal(input.principal_id);
    // The authoritative service is the one the principal names, never one
    // supplied by whoever presented a credential.
    const queryUrl = document.delegation_query_url;
    if (queryUrl === undefined) {
      throw invalidPayload(
        `principal ${document.id} publishes no delegation_query_url`,
      );
    }
    const response = await this.delegationClient(queryUrl).queryDelegationsAt(
      queryUrl,
      {
        subject: input.subject ?? this.agentId(),
        principal_id: document.id,
        id: input.id,
        status: input.status,
      },
    );
    return {
      canonical_id: document.id,
      query_url: queryUrl,
      delegations: response.result,
    };
  }

  private async delegationsList(input: DelegationsListInput): Promise<unknown> {
    // Enumerating one subject requires authorization; the connector proves the
    // active identity and never enumerates anyone else.
    const jwt = this.requestJwt(input.delegation_service);
    const response = await this.delegationClient(
      input.delegation_service,
    ).queryDelegations(
      {
        subject: this.agentId(),
        status: input.status,
        limit: input.limit,
      },
      jwt,
    );
    return { delegations: response.result };
  }

  private async delegationGrant(input: DelegationGrantInput): Promise<unknown> {
    const principal = await this.controllerPrincipal(input.principal_id);
    const payload: DelegationGrantPayload = {
      id: input.id,
      principal: { id: principal.id },
      subject: input.subject,
      relationship: input.relationship,
      scopes: input.scopes,
      constraints: input.constraints,
      not_before: input.not_before,
      expires_at: input.expires_at,
    };
    const createdAt = unixTimeMillis();
    validateDelegationGrantPayload(payload, createdAt);
    const envelope = this.signer.signEvent(
      delegationGrantEvent(
        this.agentId(),
        createdAt,
        this.nonces.nextNonce(),
        payload,
      ),
    );
    const credential = await this.delegationClient(
      input.delegation_service,
    ).submitDelegationEvent(envelope);
    return { credential, envelope };
  }

  private async delegationRevoke(
    input: DelegationRevokeInput,
  ): Promise<unknown> {
    const principal = await this.controllerPrincipal(input.principal_id);
    const envelope = this.signer.signEvent(
      delegationRevokeEvent(this.agentId(), unixTimeMillis(), this.nonces.nextNonce(), {
        id: input.id,
        principal_id: principal.id,
        reason: input.reason,
      }),
    );
    const result = await this.delegationClient(
      input.delegation_service,
    ).submitDelegationEvent(envelope);
    return { result, envelope };
  }

  private async profileUpdate(input: ProfileUpdateInput): Promise<unknown> {
    if (!isRecord(input.profile)) {
      throw invalidPayload("profile must be an object");
    }
    const profile: Record<string, unknown> = { ...input.profile };
    // payload.id is always the active Agent ID; reject an input that names a
    // different agent instead of silently rewriting it.
    const activeId = this.agentId();
    if (profile.id === undefined) {
      profile.id = activeId;
    } else if (profile.id !== activeId) {
      throw invalidPayload("profile.id must be the active Agent ID");
    }
    const envelope = this.signProfileUpdate(
      profile as unknown as ProfileUpdatePayload,
    );
    const materialized = await this.profileClient(
      input.profile_service,
    ).submitProfileUpdate(envelope);
    this.state.profiles.set(materialized.id, materialized);
    return { profile: materialized, envelope };
  }

  private async roomCreate(input: RoomCreateInput): Promise<unknown> {
    const host = normalizeHost(input.host);
    this.requireAllowedHost(host);
    const payload: RoomCreatePayload = {
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
    };
    const envelope = this.signRoomCreate(payload);
    const room = await this.discourse(host).createRoom(envelope);
    if (!room.envelope) room.envelope = envelope;
    this.acceptRoomResponse(host, room);
    const key: RoomKey = { host, roomId: room.id };
    return {
      room: this.roomStateView(this.localRoom(key)),
      envelope,
      sync: this.syncState(key),
    };
  }

  private async roomJoin(input: RoomJoinInput): Promise<unknown> {
    const roomId = input.room_id;
    let key: RoomKey;
    if (input.host !== undefined) {
      const host = normalizeHost(input.host);
      this.requireAllowedHost(host);
      key = { host, roomId };
    } else {
      key = this.resolveRoomKey(undefined, roomId);
      this.requireAllowedHost(key.host);
    }
    const host = key.host;

    if (!this.state.rooms.has(roomKeyString(key))) {
      const room = await this.discourse(host).room(roomId);
      this.acceptRoomResponse(host, room);
    }

    if (input.request_id !== undefined) {
      const status = await this.approvedJoinRequest(
        host,
        roomId,
        input.request_id,
      );
      const approvedRole = status.approved_role ?? status.request.role;
      // The completion call signs room.join with the approved role; a differing
      // input role is a mismatch error, never a silent substitution.
      if (input.role !== approvedRole) {
        throw invalidPayload(
          `join_request_role_mismatch: approved role is ${approvedRole}`,
        );
      }
      const payload: RoomJoinPayload = {
        request_id: input.request_id,
        role: approvedRole,
      };
      return this.completeJoin(host, key, payload);
    }

    if (roomVisibility(this.localRoom(key).room) === "public") {
      const payload: RoomJoinPayload = {
        request_id: undefined,
        role: input.role,
        perspective: input.perspective,
      };
      return this.completeJoin(host, key, payload);
    }

    const jwt = this.requestJwt(host);
    const request: RoomJoinRequestInput = {
      role: input.role,
      perspective: input.perspective,
      reason: input.reason,
      extra: input.extra,
    };
    const status = await this.discourse(host).requestJoin(roomId, jwt, request);
    this.pushJoinRequest(key, status);
    let sync: SyncState | undefined;
    try {
      sync = this.syncState(key);
    } catch {
      sync = undefined;
    }
    return { status: "approval_required", join_request: status, sync };
  }

  private async roomJoinRequest(
    input: RoomJoinRequestToolInput,
  ): Promise<unknown> {
    const host = normalizeHost(input.host);
    this.requireAllowedHost(host);
    const jwt = this.requestJwt(host);
    const request: RoomJoinRequestInput = {
      role: input.role,
      perspective: input.perspective,
      reason: input.reason,
      extra: input.extra,
    };
    const status = await this.discourse(host).requestJoin(
      input.room_id,
      jwt,
      request,
    );
    this.pushJoinRequest({ host, roomId: input.room_id }, status);
    return { join_request: status };
  }

  private async roomJoinWhenApproved(
    input: RoomJoinWhenApprovedInput,
  ): Promise<unknown> {
    const key = this.resolveRoomKey(input.host, input.room_id);
    const host = this.allowedRoomHost(key);
    const status = await this.approvedJoinRequest(
      host,
      input.room_id,
      input.request_id,
    );
    const role = status.approved_role ?? status.request.role;
    const payload: RoomJoinPayload = {
      request_id: input.request_id,
      role,
    };
    const result = await this.completeJoin(host, key, payload);
    return { record: result.record, member: result.member, sync: result.sync };
  }

  private async roomLeave(input: RoomLeaveInput): Promise<unknown> {
    const key = this.resolveRoomKey(input.host, input.room_id);
    const host = this.allowedRoomHost(key);
    const payload: ReasonPayload = {
      reason: input.reason,
      references: [],
      extra: {},
    };
    const envelope = this.signRoomEvent(
      eventType.ROOM_LEAVE,
      key,
      undefined,
      undefined,
      [],
      payload,
    );
    const record = await this.discourse(host).leaveRoom(input.room_id, envelope);
    this.applyHostRecord(host, record as ServerRecord);
    return { record, sync: this.syncState(key) };
  }

  private async roomSendMessage(
    input: RoomSendMessageInput,
  ): Promise<RoomWriteResult> {
    const key = this.resolveRoomKey(input.host, input.room_id);
    const held = this.headMismatchMessageResult(key, input);
    if (held) return held;
    return this.submitMessageUnchecked(input);
  }

  private async submitMessageUnchecked(
    input: RoomSendMessageInput,
  ): Promise<RoomWriteResult> {
    const key = this.resolveRoomKey(input.host, input.room_id);
    const host = this.allowedRoomHost(key);
    const payload: MessageCreatePayload = {
      content_type: input.content_type ?? "text/plain",
      content: input.content,
    };
    if (input.references && input.references.length > 0) {
      payload.references = input.references;
    }
    if (input.extra && Object.keys(input.extra).length > 0) {
      payload.extra = input.extra;
    }
    const envelope = this.signRoomEvent(
      eventType.MESSAGE_CREATE,
      key,
      input.base_seq,
      input.base_hash,
      input.mentions ?? [],
      payload,
    );
    const record = await this.discourse(host).submitEvent(
      input.room_id,
      envelope,
    );
    this.applyHostRecord(host, record as ServerRecord);
    const item = this.timelineItemByEvent(key, record.envelope.hash);
    return {
      status: "sent",
      record: record as ServerRecord,
      item,
      sync: this.syncState(key),
    };
  }

  private async roomSubmitEvent(
    input: RoomSubmitEventInput,
  ): Promise<RoomWriteResult> {
    // For signal-kind writes — including the membership events — the base is
    // only an anchor: never hold the draft, ignore on_head_mismatch.
    const key = this.resolveRoomKey(input.host, input.room_id);
    const room = this.state.rooms.get(roomKeyString(key));
    const advancesHead = room
      ? eventTypeAdvancesRoomHead(room, input.type)
      : true;
    if (advancesHead) {
      const held = this.headMismatchEventResult(key, input);
      if (held) return held;
    }
    return this.submitEventUnchecked(input);
  }

  private async submitEventUnchecked(
    input: RoomSubmitEventInput,
  ): Promise<RoomWriteResult> {
    const key = this.resolveRoomKey(input.host, input.room_id);
    const host = this.allowedRoomHost(key);
    const payload = payloadWithReferences(input.payload, input.references ?? []);
    const envelope = this.signRoomEvent(
      input.type,
      key,
      input.base_seq,
      input.base_hash,
      input.mentions ?? [],
      payload,
    );
    const record = await this.discourse(host).submitEvent(
      input.room_id,
      envelope,
    );
    this.applyHostRecord(host, record as ServerRecord);
    const item = this.timelineItemByEvent(key, record.envelope.hash);
    return {
      status: "sent",
      record: record as ServerRecord,
      item,
      sync: this.syncState(key),
    };
  }

  private async joinRequestsList(
    input: JoinRequestsListInput,
  ): Promise<unknown> {
    const key = this.resolveRoomKey(input.host, input.room_id);
    const host = this.allowedRoomHost(key);
    const jwt = this.requestJwt(host);
    let requests = await this.discourse(host).joinRequests(input.room_id, jwt);
    if (input.status !== undefined) {
      requests = requests.filter((request) => request.status === input.status);
    }
    const offset = parseCursor(input.cursor);
    if (offset > 0) requests = requests.slice(offset);
    if (input.limit !== undefined) requests = requests.slice(0, input.limit);
    this.state.joinRequests.set(roomKeyString(key), requests);
    return { join_requests: requests };
  }

  private async joinRequestReview(
    input: JoinRequestReviewInput,
  ): Promise<unknown> {
    const key = this.resolveRoomKey(input.host, input.room_id);
    const host = this.allowedRoomHost(key);
    const jwt = this.requestJwt(host);
    const status = await this.discourse(host).joinRequest(
      input.room_id,
      input.request_id,
      jwt,
    );
    const payload: RoomJoinReviewPayload = {
      request: status.request,
      decision: input.decision,
      role: input.role,
      reason: input.reason,
      extra: {},
    };
    const envelope = this.signRoomEvent(
      eventType.ROOM_JOIN_REVIEW,
      key,
      undefined,
      undefined,
      [],
      payload,
    );
    const record = await this.discourse(host).submitEvent(
      input.room_id,
      envelope,
    );
    this.applyHostRecord(host, record as ServerRecord);
    return { record, sync: this.syncState(key) };
  }

  // ── Join helpers shared by the join tools.

  private async approvedJoinRequest(
    host: string,
    roomId: string,
    requestId: string,
  ): Promise<RoomJoinRequestStatus> {
    const jwt = this.requestJwt(host);
    const status = await this.discourse(host).joinRequest(
      roomId,
      requestId,
      jwt,
    );
    if (status.request.applicant !== this.agentId()) {
      throw invalidPayload("join request belongs to another agent");
    }
    if (status.status !== "approved") {
      throw invalidPayload("join request is not approved");
    }
    return status;
  }

  private async completeJoin(
    host: string,
    key: RoomKey,
    payload: RoomJoinPayload,
  ): Promise<{ status: "joined"; record: ServerRecord; member: RoomMemberView; sync: SyncState }> {
    const envelope = this.signRoomEvent(
      eventType.ROOM_JOIN,
      key,
      undefined,
      undefined,
      [],
      payload,
    );
    const record = await this.discourse(host).joinRoom(key.roomId, envelope);
    this.applyHostRecord(host, record as ServerRecord);
    const member = this.localRoom(key).members.get(this.agentId());
    if (!member) throw invalidPayload("joined member not materialized");
    return {
      status: "joined",
      record: record as ServerRecord,
      member,
      sync: this.syncState(key),
    };
  }

  private pushJoinRequest(key: RoomKey, status: RoomJoinRequestStatus): void {
    const keyStr = roomKeyString(key);
    const existing = this.state.joinRequests.get(keyStr);
    if (existing) existing.push(status);
    else this.state.joinRequests.set(keyStr, [status]);
  }

  // ── Signing.

  private signProfileUpdate(
    payload: ProfileUpdatePayload,
  ): Envelope<ProfileUpdatePayload> {
    const event = profileUpdateEvent(
      this.agentId(),
      unixTimeMillis(),
      this.nonces.nextNonce(),
      payload,
    );
    return this.signer.signEvent(event);
  }

  private signRoomCreate(
    payload: RoomCreatePayload,
  ): Envelope<RoomCreatePayload> {
    const event = roomCreateEvent(
      this.agentId(),
      unixTimeMillis(),
      this.nonces.nextNonce(),
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
    const [resolvedSeq, resolvedHash] = this.roomHeadForWrite(
      key,
      baseSeq,
      baseHash,
    );
    const event = withMentions(
      discourseEvent(
        type,
        this.agentId(),
        unixTimeMillis(),
        this.nonces.nextNonce(),
        key.roomId,
        resolvedSeq,
        resolvedHash,
        payload,
      ),
      mentions,
    );
    const envelope = this.signer.signEvent(event);
    validateDiscourseEnvelope(envelope);
    return envelope;
  }

  private roomHeadForWrite(
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
    if (baseSeq === undefined && baseHash === undefined) {
      const sync = this.syncState(key);
      if (sync.head_seq === 0 || sync.head_hash.trim() === "") {
        throw invalidPayload("current room head is not known locally");
      }
      return [sync.head_seq, sync.head_hash];
    }
    throw invalidPayload("base_seq and base_hash must be provided together");
  }

  private requestJwt(host: string): string {
    // The request JWT aud is always the origin of the host API.
    const audience = serviceOrigin(host);
    const claims = createRequestJwtClaims(
      this.agentId(),
      createRequestBinding(audience),
      unixTimeSecs(),
      DEFAULT_REQUEST_JWT_TTL_SECS,
    );
    return this.signer.signRequestJwt(claims);
  }

  // ── Head-mismatch handling and draft holding.

  private headMismatchMessageResult(
    key: RoomKey,
    input: RoomSendMessageInput,
  ): RoomWriteResult | undefined {
    const headMismatch = this.headMismatchWriteState(
      key,
      input.base_seq,
      input.base_hash,
    );
    if (!headMismatch) return undefined;
    switch (input.on_head_mismatch ?? "hold") {
      case "send_anyway":
        input.base_seq = undefined;
        input.base_hash = undefined;
        return undefined;
      case "reject":
        return this.rejectedHeadMismatchResult(headMismatch);
      default:
        return this.holdMessageDraft(input, headMismatch);
    }
  }

  private headMismatchEventResult(
    key: RoomKey,
    input: RoomSubmitEventInput,
  ): RoomWriteResult | undefined {
    const headMismatch = this.headMismatchWriteState(
      key,
      input.base_seq,
      input.base_hash,
    );
    if (!headMismatch) return undefined;
    switch (input.on_head_mismatch ?? "hold") {
      case "send_anyway":
        input.base_seq = undefined;
        input.base_hash = undefined;
        return undefined;
      case "reject":
        return this.rejectedHeadMismatchResult(headMismatch);
      default:
        return this.holdEventDraft(input, headMismatch);
    }
  }

  private headMismatchWriteState(
    key: RoomKey,
    baseSeq: number | undefined,
    baseHash: string | undefined,
  ): HeadMismatchState | undefined {
    if (baseSeq === undefined && baseHash === undefined) return undefined;
    const sync = this.syncState(key);
    const seqMismatch = baseSeq !== undefined && baseSeq !== sync.head_seq;
    const hashMismatch = baseHash !== undefined && sync.head_hash !== baseHash;
    if (!seqMismatch && !hashMismatch) return undefined;
    return { sync, changes: this.roomChangesSince(key, baseSeq) };
  }

  private rejectedHeadMismatchResult(
    headMismatch: HeadMismatchState,
  ): RoomWriteResult {
    return {
      status: "rejected",
      reason: "room_head_mismatch",
      changes: headMismatch.changes,
      sync: headMismatch.sync,
    };
  }

  private holdMessageDraft(
    input: RoomSendMessageInput,
    headMismatch: HeadMismatchState,
  ): RoomWriteResult {
    input.host = headMismatch.sync.host;
    const draftId = this.nextDraftId(input.room_id);
    const draft: HeldDraft = {
      id: draftId,
      room_id: input.room_id,
      kind: "message",
      created_at: unixTimeMillis(),
      base_seq: input.base_seq,
      base_hash: input.base_hash,
      current_sync: headMismatch.sync,
      draft: messageDraftValue(input),
      reason: "room_head_mismatch",
      options: heldDraftOptions(),
    };
    this.state.drafts.set(draftId, {
      draft,
      request: { kind: "message", input },
    });
    return {
      status: "held",
      reason: "room_head_mismatch",
      draft,
      changes: headMismatch.changes,
      sync: headMismatch.sync,
    };
  }

  private holdEventDraft(
    input: RoomSubmitEventInput,
    headMismatch: HeadMismatchState,
  ): RoomWriteResult {
    input.host = headMismatch.sync.host;
    const draftId = this.nextDraftId(input.room_id);
    const draft: HeldDraft = {
      id: draftId,
      room_id: input.room_id,
      kind: "event",
      created_at: unixTimeMillis(),
      base_seq: input.base_seq,
      base_hash: input.base_hash,
      current_sync: headMismatch.sync,
      draft: eventDraftValue(input),
      reason: "room_head_mismatch",
      options: heldDraftOptions(),
    };
    this.state.drafts.set(draftId, {
      draft,
      request: { kind: "event", input },
    });
    return {
      status: "held",
      reason: "room_head_mismatch",
      draft,
      changes: headMismatch.changes,
      sync: headMismatch.sync,
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
    return `draft_${room}_${this.state.drafts.size + 1}`;
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
      synced_seq: room.syncedSeq,
      remote_seq: Math.max(room.room.seq, room.syncedSeq),
      subscribed: room.subscribed,
      unread_count: unreadCount(room),
      pending_inbox_count: this.pendingInboxCount(key.roomId),
    };
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
      creator: room.room.envelope?.event.actor,
      created_at: room.room.envelope?.event.created_at,
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

  // ── Internal helpers.

  private localRoom(key: RoomKey): LocalRoomState {
    const room = this.state.rooms.get(roomKeyString(key));
    if (!room) throw invalidPayload(`room is not open locally: ${key.roomId}`);
    return room;
  }

  private requireAllowedHost(host: string): void {
    const record = this.state.hosts.get(host);
    if (!record || !record.allowed) throw permissionDenied();
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

  private discourse(host: string): DiscourseClient {
    return new DiscourseClient(host, this.fetchImpl);
  }

  private profileClient(url: string): ProfileClient {
    return new ProfileClient(url, this.fetchImpl);
  }

  private delegationClient(url: string): DelegationClient {
    return new DelegationClient(url, this.fetchImpl);
  }
}
