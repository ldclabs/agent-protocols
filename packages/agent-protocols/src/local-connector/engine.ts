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
import { base64UrlEncode } from "../encoding.js";
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
  HttpResponseError,
  ProfileClient,
} from "../http-client.js";
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
import {
  HeldDraftRequest,
  LocalConnectorState,
  LocalRoomState,
  RoomKey,
} from "./state.js";
import {
  AgentProtocolsHost,
  DraftAction,
  HeadMismatchPolicy,
  HeldDraft,
  InboxItem,
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
    const response = await this.discourse(host).publicRooms({
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
    const client = this.discourse(key.host);
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
        status = await this.discourse(host).agentStatus(input.room_id, input.agent_id, this.requestJwt(host));
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
    const response = await this.discourse(host).agentStatuses(input.room_id, this.requestJwt(host));
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
    const status = await this.discourse(host).setAgentStatus(
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

  /** The principal's authoritative delegation service, located from its `delegation_query_url`. */
  private async principalDelegationService(document: PrincipalDocument): Promise<DelegationClient> {
    const queryUrl = document.delegation_query_url;
    if (queryUrl === undefined) {
      throw invalidPayload(`principal ${document.id} publishes no delegation_query_url`);
    }
    const origin = serviceOrigin(queryUrl);
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
    const queryUrl = document.delegation_query_url!;
    const response = await service.queryDelegationsAt(queryUrl, {
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
    return { canonical_id: document.id, query_url: queryUrl, delegations };
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
    const client = this.profileClient(input.profile_service);
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
    const client = this.discourse(host);
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
      const current = await this.discourse(host).joinRequest(roomId, own.id, this.requestJwt(host));
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
        const room = await this.discourse(host).room(roomId, this.requestJwt(host));
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
          (envelope) => this.discourse(host).joinRoom(roomId, envelope),
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
      (envelope) => this.discourse(host).requestJoin(roomId, envelope),
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
          (envelope) => this.discourse(host).submitEvent(input.room_id, envelope),
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
    const response = await this.discourse(host).joinRequests(input.room_id, this.requestJwt(host), {
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
    const joinRequest = await this.discourse(host).joinRequest(
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
      (envelope) => this.discourse(host).submitEvent(input.room_id, envelope),
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

  private discourse(host: string): DiscourseClient {
    return new DiscourseClient(host, this.fetchImpl);
  }

  private profileClient(url: string): ProfileClient {
    return new ProfileClient(url, this.fetchImpl);
  }
}
