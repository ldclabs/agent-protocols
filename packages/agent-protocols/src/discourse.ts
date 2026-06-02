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
export const LEGACY_DISCOURSE_PROTOCOL = "adp/1.0";

export const eventType = {
  ROOM_CREATE: "room.create",
  ROOM_JOIN: "room.join",
  ROOM_LEAVE: "room.leave",
  ROOM_MEMBER_ROLE_UPDATE: "room.member.role.update",
  ROOM_INVITE: "room.invite",
  ROOM_INVITE_REVOKE: "room.invite.revoke",
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
  SESSION_AUTH: "session.auth",
} as const;

export type EventType = (typeof eventType)[keyof typeof eventType];
export type RoomState = "scheduled" | "active" | "ended" | "cancelled";
export type Visibility = "public" | "private" | "unlisted";
export type TurnPolicy = "free" | "round_robin" | "moderator_led";
export type Role = "moderator" | "expert" | "participant" | "observer";
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

export interface RoomCreatePayload {
  topic: string;
  agenda?: string;
  visibility: Visibility;
  start_time: number;
  end_time: number;
  tags?: string[];
  language?: string;
  policy?: RoomPolicy;
  capabilities?: string[];
  extensions?: Record<string, unknown>;
  extra?: Record<string, unknown>;
}

export interface RoomPolicy {
  turn_policy?: TurnPolicy;
  moderator_agent_ids?: AgentId[];
  max_participants?: number;
  observer_allowed?: boolean;
  observer_steering_allowed?: boolean;
  participant_approval_required?: boolean;
  observer_approval_required?: boolean;
  [key: string]: unknown;
}

export interface RoomCreateResponse {
  room_id: string;
  status: RoomState;
  created_event_id: string;
  room_uri: string;
}

export interface RoomJoinPayload {
  role: Role;
  perspective?: string;
  invite?: unknown;
  webhook_url?: string;
}

export interface RoomLeavePayload {
  reason?: string;
}

export interface RoleUpdatePayload {
  member: AgentId;
  role: Role;
  reason?: string;
}

export interface RoomInvitePayload {
  invitee?: AgentId;
  role: Role;
  expires_at: number;
  max_uses?: number;
  approval_required?: boolean;
}

export interface InviteRevokePayload {
  invite_event_id: string;
  reason?: string;
}

export interface MessageCreatePayload {
  content_type: string;
  content: unknown;
  references?: string[];
}

export interface ReactionCreatePayload {
  target_event_id: string;
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
  turn_id: string;
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
  received_at: number;
  envelope: Envelope<P>;
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
  room_uri: string;
  generated_at: number;
  event_count: number;
  first_seq: number;
  last_seq: number;
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

export function validateDiscourseEnvelope(
  envelope: Envelope<unknown>,
  acceptLegacyProtocol = false,
): void {
  verifyEnvelope(envelope);
  const protocol = envelope.event.protocol;
  const ok =
    protocol === DISCOURSE_PROTOCOL ||
    (acceptLegacyProtocol && protocol === LEGACY_DISCOURSE_PROTOCOL);
  if (!ok) {
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

export function canSubmitEvent(
  type: string,
  context: PermissionContext,
): boolean {
  if (type === eventType.ROOM_CREATE || type === eventType.ROOM_JOIN)
    return true;
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
        eventType.ROOM_INVITE,
        eventType.ROOM_INVITE_REVOKE,
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
      eventType.ROOM_INVITE,
      eventType.ROOM_INVITE_REVOKE,
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
