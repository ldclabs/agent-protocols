import canonicalize from "canonicalize";
import { createHash } from "node:crypto";

import { protocolError } from "./errors.js";
import {
  AgentId,
  Envelope,
  Event,
  createEvent,
  verifyEnvelope,
  withRoomId,
} from "./identity.js";

export const DISCOURSE_PROTOCOL = "agent-discourse/1.0";

export const eventType = {
  ROOM_CREATE: "room.create",
  ROOM_JOIN: "room.join",
  ROOM_JOIN_REVIEW: "room.join.review",
  ROOM_LEAVE: "room.leave",
  ROOM_MEMBER_ROLE_UPDATE: "room.member.role.update",
  ROOM_CLOSE: "room.close",
  ROOM_CANCEL: "room.cancel",
  MESSAGE_CREATE: "message.create",
  REACTION_CREATE: "reaction.create",
  MESSAGE_PROPOSAL_CREATE: "message.proposal.create",
  MESSAGE_POLL_CREATE: "message.poll.create",
  MESSAGE_POLL_VOTE: "message.poll.vote",
  MESSAGE_RESOLUTION_CREATE: "message.resolution.create",
  SOURCE_ADD: "source.add",
  TURN_UPDATE: "turn.update",
  QUESTION_CREATE: "question.create",
  ROOM_STEER: "room.steer",
  MAP_UPDATE: "map.update",
  ARTIFACT_CREATE: "artifact.create",
} as const;

export type EventType = (typeof eventType)[keyof typeof eventType];
export type RoomState = "scheduled" | "active" | "ended" | "cancelled";
export type Visibility = "public" | "restricted" | "private";
export type TurnPolicy = "free" | "round_robin" | "moderator_led";
export type Role = "moderator" | "expert" | "participant" | "observer";
export type JoinRequestStatus = "pending" | "approved" | "rejected" | "expired";
export type JoinDecision = "approve" | "reject";
export type MessageIntent =
  | "question"
  | "answer"
  | "clarification"
  | "critique"
  | "synthesis"
  | "follow_up"
  | "other";
export type MapOperation =
  | "upsert_node"
  | "move_node"
  | "delete_node"
  | "merge_nodes"
  | "replace_snapshot"
  | "mark_resolved";
export type MapNodeStatus = "open" | "resolved" | "closed";
export type ResolutionOutcome =
  | "accepted"
  | "rejected"
  | "deferred"
  | "superseded";

export interface RoomCreatePayload {
  topic: string;
  agenda?: string;
  visibility: Visibility;
  start_time: number;
  end_time: number;
  tags?: string[];
  language?: string;
  policy?: RoomPolicy;
  extensions?: Record<string, unknown>;
  extra?: Record<string, unknown>;
}

export interface RoomPolicy {
  turn_policy?: TurnPolicy;
  moderator_agent_ids?: AgentId[];
  max_participants?: number;
  observer_allowed?: boolean;
  observer_steering_allowed?: boolean;
  [key: string]: unknown;
}

export interface RoomResponse {
  id: string;
  status: RoomState;
  url: string;
  seq: number;
  pre_hash: string | null;
  hash: string;
  received_at: number;
  envelope?: Envelope<RoomCreatePayload>;
}

export interface RoomJoinPayload {
  request_id: string;
  role: Role;
  perspective?: string;
}

export interface RoomJoinRequestPayload {
  requested_role: Role;
  perspective?: string;
  reason?: string;
  extra?: Record<string, unknown>;
}

export interface RoomJoinRequest {
  id: string;
  room_id: string;
  applicant: AgentId;
  requested_role: Role;
  approved_role?: Role;
  perspective?: string;
  status: JoinRequestStatus;
  request_reason?: string;
  review_reason?: string;
  created_at: number;
  reviewed_by?: AgentId;
  reviewed_at?: number;
  expires_at?: number;
  extra?: Record<string, unknown>;
}

export interface RoomJoinReviewPayload {
  request_id: string;
  member: AgentId;
  decision: JoinDecision;
  role?: Role;
  reason?: string;
}

export interface RoomLeavePayload {
  reason?: string;
}

export interface RoleUpdatePayload {
  member: AgentId;
  role: Role;
  reason?: string;
}

export interface MessageCreatePayload {
  content_type: string;
  content: unknown;
  references?: string[];
}

export interface ProposalCreatePayload {
  proposal_id: string;
  title: string;
  body: string;
  content_type?: string;
  references?: string[];
  source_event_ids?: string[];
  extra?: Record<string, unknown>;
}

export interface PollOption {
  id: string;
  label: string;
  description?: string;
}

export interface PollCreatePayload {
  poll_id: string;
  question: string;
  options: PollOption[];
  min_choices?: number;
  max_choices?: number;
  closes_at?: number;
  references?: string[];
  extra?: Record<string, unknown>;
}

export interface PollVotePayload {
  event_id: string;
  option_ids: string[];
}

export interface ResolutionCreatePayload {
  resolution_id: string;
  outcome: ResolutionOutcome;
  summary: string;
  proposal_event_id?: string;
  poll_event_id?: string;
  references?: string[];
  extra?: Record<string, unknown>;
}

export interface ReactionCreatePayload {
  event_id: string;
  reaction: string;
  score?: number;
}

export interface SourceAddPayload {
  source_type: string;
  uri: string;
  title?: string;
  retrieved_at?: number;
  content_digest?: string;
  excerpt?: string;
  extra?: Record<string, unknown>;
}

export interface TurnUpdatePayload {
  turn_id: number;
  speaker: AgentId;
  intent?: MessageIntent;
  topic?: string;
  expires_at?: number;
  reason?: string;
}

export interface QuestionGeneratePayload {
  question: string;
  target_perspectives?: string[];
  basis?: string;
  source_event_ids?: string[];
  references?: string[];
  priority?: number;
}

export interface DiscourseSteerPayload {
  instruction: string;
  target: string;
  priority?: number;
  references?: string[];
}

export interface MapNode {
  id: string;
  parent_id?: string;
  title: string;
  summary?: string;
  status?: MapNodeStatus;
  source_event_ids?: string[];
  discussion_event_ids?: string[];
  children?: MapNode[];
  extra?: Record<string, unknown>;
}

export interface MapUpdatePayload {
  operation: MapOperation;
  node?: MapNode;
  extra?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface ArtifactCreatePayload {
  artifact_id: string;
  format: string;
  title: string;
  uri: string;
  content_digest?: string;
  source_event_ids?: string[];
  discussion_event_ids?: string[];
  map_event_id?: string;
}

export interface ServerRecord<P = unknown> {
  room_id: string;
  seq: number;
  pre_hash: string | null;
  hash: string;
  received_at: number;
  envelope: Envelope<P>;
}

export interface ServerRecordHashPayload {
  room_id: string;
  seq: number;
  pre_hash: string | null;
  envelope_hash: string;
  received_at: number;
}

export interface ProfileResolverMetadata {
  mode: string;
  service?: string;
  protocol?: string;
}

export interface DiscourseProtocolDiscovery {
  protocol: string;
  host: string;
  features?: string[];
  profile?: ProfileResolverMetadata;
  endpoints?: Record<string, string>;
}

export interface ArtifactManifest {
  artifact_id: string;
  type: string;
  format: string;
  uri: string;
  content_digest?: string;
}

export interface ArchiveManifest {
  protocol: string;
  type: "room.archive";
  host: string;
  room_id: string;
  url: string;
  generated_at: number;
  event_count: number;
  first_seq: number;
  last_seq: number;
  last_hash: string;
  events_sha3_256: string;
  archive_root: string;
  map_snapshot?: { event_id: string; digest: string };
  artifacts?: ArtifactManifest[];
  discourse_trace_quality_score?: number;
  formats?: Record<string, string>;
}

export interface PermissionContext {
  role?: Role;
  isCreator?: boolean;
  joinRequestApproved?: boolean;
  moderatorAuthorized?: boolean;
  expertPolicyAllowed?: boolean;
  participantPolicyAllowed?: boolean;
  observerSteeringAllowed?: boolean;
  observerPollVoteAllowed?: boolean;
}

export interface StateWriteOptions {
  postEndReactionAllowed?: boolean;
}

export function roomCreateEvent(
  actor: AgentId,
  createdAt: number,
  nonce: number,
  payload: RoomCreatePayload,
): Event<RoomCreatePayload> {
  return createEvent(
    DISCOURSE_PROTOCOL,
    eventType.ROOM_CREATE,
    actor,
    createdAt,
    nonce,
    payload,
  );
}

export function discourseEvent<P>(
  type: string,
  actor: AgentId,
  createdAt: number,
  nonce: number,
  roomId: string,
  payload: P,
): Event<P> {
  return withRoomId(
    createEvent(DISCOURSE_PROTOCOL, type, actor, createdAt, nonce, payload),
    roomId,
  );
}

export function validateDiscourseEnvelope(envelope: Envelope<unknown>): void {
  verifyEnvelope(envelope);
  const protocol = envelope.event.protocol;
  if (protocol !== DISCOURSE_PROTOCOL) {
    throw protocolError(
      "invalid_event_protocol",
      `expected ${DISCOURSE_PROTOCOL}, got ${protocol}`,
    );
  }
  if (
    eventRequiresRoomId(envelope.event.type) &&
    envelope.event.room_id === undefined
  ) {
    throw protocolError("missing_room_id", "event requires a room_id");
  }
}

export function validateRoomPath(
  envelope: Envelope<unknown>,
  pathRoomId: string,
): void {
  const actual = envelope.event.room_id;
  if (actual === undefined && envelope.event.type === eventType.ROOM_CREATE)
    return;
  if (actual === undefined)
    throw protocolError("missing_room_id", "event requires a room_id");
  if (actual !== pathRoomId)
    throw protocolError(
      "room_id_mismatch",
      `expected ${pathRoomId}, got ${actual}`,
    );
}

export function eventRequiresRoomId(type: string): boolean {
  return type !== eventType.ROOM_CREATE;
}

export function validateRoomCreatePayload(payload: RoomCreatePayload): void {
  if (payload.topic.trim() === "") {
    throw protocolError("invalid_room", "room topic must not be empty");
  }
  if (payload.start_time >= payload.end_time) {
    throw protocolError("invalid_room", "start_time must be before end_time");
  }
  const maxParticipants = payload.policy?.max_participants;
  if (
    maxParticipants !== undefined &&
    (!Number.isInteger(maxParticipants) || maxParticipants < 1)
  ) {
    throw protocolError(
      "invalid_room",
      "max_participants must be a positive integer",
    );
  }
}

export function validatePollCreatePayload(payload: PollCreatePayload): void {
  if (payload.poll_id.trim() === "" || payload.question.trim() === "") {
    throw protocolError("invalid_poll", "poll_id and question are required");
  }
  if (payload.options.length < 2) {
    throw protocolError("invalid_poll", "poll requires at least two options");
  }
  const optionIds = new Set<string>();
  for (const option of payload.options) {
    if (option.id.trim() === "" || option.label.trim() === "") {
      throw protocolError("invalid_poll", "option id and label are required");
    }
    if (optionIds.has(option.id)) {
      throw protocolError("invalid_poll", "poll option ids must be unique");
    }
    optionIds.add(option.id);
  }
  const minChoices = payload.min_choices ?? 1;
  const maxChoices = payload.max_choices ?? 1;
  if (minChoices < 1 || maxChoices < minChoices) {
    throw protocolError("invalid_poll", "invalid poll choice limits");
  }
}

export function validatePollVotePayload(
  payload: PollVotePayload,
  poll: PollCreatePayload,
  nowMs?: number,
): void {
  if (poll.closes_at !== undefined && nowMs !== undefined && nowMs > poll.closes_at) {
    throw protocolError("poll_closed", "poll is closed");
  }
  const minChoices = poll.min_choices ?? 1;
  const maxChoices = poll.max_choices ?? 1;
  const optionIds = new Set(poll.options.map((option) => option.id));
  const selected = new Set(payload.option_ids);
  if (selected.size !== payload.option_ids.length) {
    throw protocolError("invalid_poll_vote", "duplicate poll options");
  }
  if (selected.size < minChoices || selected.size > maxChoices) {
    throw protocolError("invalid_poll_vote", "invalid number of options");
  }
  for (const optionId of selected) {
    if (!optionIds.has(optionId)) {
      throw protocolError("invalid_poll_vote", "unknown poll option");
    }
  }
}

export function serverRecordHashPayload(
  roomId: string,
  seq: number,
  preHash: string | null | undefined,
  envelopeHash: string,
  receivedAt: number,
): ServerRecordHashPayload {
  return {
    room_id: roomId,
    seq,
    pre_hash: preHash ?? null,
    envelope_hash: envelopeHash,
    received_at: receivedAt,
  };
}

export function serverRecordHash(
  roomId: string,
  seq: number,
  preHash: string | null | undefined,
  envelopeHash: string,
  receivedAt: number,
): string {
  return hashCanonicalJson(
    serverRecordHashPayload(roomId, seq, preHash, envelopeHash, receivedAt),
  );
}

export function buildServerRecord<P>(
  roomId: string,
  seq: number,
  preHash: string | null | undefined,
  receivedAt: number,
  envelope: Envelope<P>,
): ServerRecord<P> {
  const normalizedPreHash = preHash ?? null;
  return {
    room_id: roomId,
    seq,
    pre_hash: normalizedPreHash,
    hash: serverRecordHash(
      roomId,
      seq,
      normalizedPreHash,
      envelope.hash,
      receivedAt,
    ),
    received_at: receivedAt,
    envelope,
  };
}

export function verifyServerRecord(record: ServerRecord): void {
  const expected = serverRecordHash(
    record.room_id,
    record.seq,
    record.pre_hash,
    record.envelope.hash,
    record.received_at,
  );
  if (record.hash !== expected) {
    throw protocolError(
      "invalid_record_hash",
      `invalid server record hash: expected ${expected}, got ${record.hash}`,
    );
  }
}

export function verifyServerRecordChain(records: ServerRecord[]): void {
  let previous: ServerRecord | undefined;
  for (const record of records) {
    verifyServerRecord(record);
    if (previous) {
      if (record.seq !== previous.seq + 1) {
        throw protocolError("invalid_record_chain", "seq must increase by 1");
      }
      if (record.pre_hash !== previous.hash) {
        throw protocolError("invalid_record_chain", "pre_hash mismatch");
      }
    } else if (record.seq !== 1) {
      throw protocolError("invalid_record_chain", "first seq must be 1");
    } else if (record.pre_hash !== null) {
      throw protocolError("invalid_record_chain", "first pre_hash must be null");
    }
    previous = record;
  }
}

export function archiveEventsDigest(records: ServerRecord[]): string {
  return hashCanonicalJson(records);
}

export function canSubmitEvent(
  type: string,
  context: PermissionContext,
): boolean {
  if (type === eventType.ROOM_CREATE) return true;
  if (type === eventType.ROOM_JOIN) return Boolean(context.joinRequestApproved);
  if (context.isCreator) return isKnownEventType(type);

  switch (context.role) {
    case "moderator":
      return moderatorCanSubmit(type, context.moderatorAuthorized ?? false);
    case "expert":
      return speakerCanSubmit(type, context.expertPolicyAllowed ?? false);
    case "participant":
      return speakerCanSubmit(type, context.participantPolicyAllowed ?? false);
    case "observer":
      return observerCanSubmit(type, context);
    default:
      return false;
  }
}

export function canWriteInState(
  type: string,
  state: RoomState,
  options: StateWriteOptions = {},
): boolean {
  switch (state) {
    case "scheduled":
      return eventTypeIn(type, [
        eventType.ROOM_JOIN,
        eventType.ROOM_JOIN_REVIEW,
        eventType.ROOM_CANCEL,
      ]);
    case "active":
      return type !== eventType.ROOM_CREATE && type !== eventType.ROOM_CANCEL;
    case "ended":
      return (
        Boolean(options.postEndReactionAllowed) &&
        type === eventType.REACTION_CREATE
      );
    case "cancelled":
      return false;
  }
}

export function canAcceptRoomWrite(
  type: string,
  state: RoomState,
  permission: PermissionContext,
  options: StateWriteOptions = {},
): boolean {
  return (
    canSubmitEvent(type, permission) && canWriteInState(type, state, options)
  );
}

export function validateRoomWrite(
  type: string,
  state: RoomState,
  permission: PermissionContext,
  options: StateWriteOptions = {},
): void {
  if (!canAcceptRoomWrite(type, state, permission, options)) {
    throw protocolError(
      "permission_denied",
      "actor lacks permission or state is not writable",
    );
  }
}

function moderatorCanSubmit(
  type: string,
  moderatorAuthorized: boolean,
): boolean {
  return (
    eventTypeIn(type, [
      eventType.ROOM_JOIN_REVIEW,
      eventType.ROOM_CLOSE,
      eventType.MESSAGE_CREATE,
      eventType.SOURCE_ADD,
      eventType.TURN_UPDATE,
      eventType.QUESTION_CREATE,
      eventType.ROOM_STEER,
      eventType.MAP_UPDATE,
      eventType.ARTIFACT_CREATE,
      eventType.MESSAGE_PROPOSAL_CREATE,
      eventType.MESSAGE_POLL_CREATE,
      eventType.MESSAGE_POLL_VOTE,
      eventType.MESSAGE_RESOLUTION_CREATE,
      eventType.REACTION_CREATE,
      eventType.ROOM_LEAVE,
    ]) ||
    (moderatorAuthorized &&
      eventTypeIn(type, [
        eventType.ROOM_MEMBER_ROLE_UPDATE,
        eventType.ROOM_CANCEL,
      ]))
  );
}

function speakerCanSubmit(type: string, policyAllowed: boolean): boolean {
  return (
    eventTypeIn(type, [
      eventType.MESSAGE_CREATE,
      eventType.SOURCE_ADD,
      eventType.ROOM_STEER,
      eventType.MESSAGE_PROPOSAL_CREATE,
      eventType.MESSAGE_POLL_CREATE,
      eventType.MESSAGE_POLL_VOTE,
      eventType.REACTION_CREATE,
      eventType.ROOM_LEAVE,
    ]) ||
    (policyAllowed &&
      eventTypeIn(type, [
        eventType.QUESTION_CREATE,
        eventType.MAP_UPDATE,
        eventType.ARTIFACT_CREATE,
        eventType.MESSAGE_RESOLUTION_CREATE,
      ]))
  );
}

function observerCanSubmit(type: string, context: PermissionContext): boolean {
  return (
    eventTypeIn(type, [eventType.REACTION_CREATE, eventType.ROOM_LEAVE]) ||
    (Boolean(context.observerSteeringAllowed) &&
      type === eventType.ROOM_STEER) ||
    (Boolean(context.observerPollVoteAllowed) &&
      type === eventType.MESSAGE_POLL_VOTE)
  );
}

function isKnownEventType(type: string): boolean {
  return eventTypeIn(type, Object.values(eventType));
}

function eventTypeIn(type: string, values: readonly string[]): boolean {
  return values.includes(type);
}

function hashCanonicalJson(value: unknown): string {
  const canonical = canonicalize(value);
  if (canonical === undefined) {
    throw protocolError(
      "canonical_json",
      "value cannot be represented as canonical JSON",
    );
  }
  return createHash("sha3-256").update(canonical).digest("base64url");
}
