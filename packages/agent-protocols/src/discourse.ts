/**
 * Agent Discourse Protocol 1.0: kernel types, the room type system, and
 * verification helpers.
 *
 * The protocol defines twelve built-in event types. Every other event type is
 * declared per room as a schema-validated type definition, either inline or
 * imported from a type pack. Hosts validate structure and permissions; they
 * never need to understand application semantics.
 */
import { Validator, type Schema } from "@cfworker/json-schema";
import canonicalize from "canonicalize";
import { createHash } from "node:crypto";

import { AgentProtocolError, protocolError } from "./errors.js";
import {
  AgentId,
  DiscoveryDocument,
  Envelope,
  Event,
  ListResponse,
  MAX_SAFE_NONCE,
  createEvent,
  validateAgentId,
  validateEventFields,
  verifyEnvelope,
  withRoomHead,
  withRoomId,
} from "./identity.js";

export const DISCOURSE_PROTOCOL = "agent-discourse/1.0";

/** The twelve built-in event types. All other types are room-defined. */
export const eventType = {
  ROOM_CREATE: "room.create",
  ROOM_UPDATE: "room.update",
  ROOM_JOIN: "room.join",
  ROOM_JOIN_REQUEST: "room.join.request",
  ROOM_JOIN_REVIEW: "room.join.review",
  ROOM_LEAVE: "room.leave",
  ROOM_MEMBER_ROLE_UPDATE: "room.member.role.update",
  ROOM_MEMBER_REMOVE: "room.member.remove",
  ROOM_CLOSE: "room.close",
  ROOM_CANCEL: "room.cancel",
  TYPE_DEFINE: "type.define",
  MESSAGE_CREATE: "message.create",
} as const;

export type BuiltinEventType = (typeof eventType)[keyof typeof eventType];

export const BUILTIN_EVENT_TYPES: readonly string[] = Object.values(eventType);

/**
 * Built-in membership events. They are `signal`-class: they anchor to an
 * accepted record but never contend for or advance the room head, so busy
 * rooms cannot starve joins, reviews, or other membership writes.
 */
export const MEMBERSHIP_EVENT_TYPES: readonly string[] = [
  eventType.ROOM_JOIN,
  eventType.ROOM_JOIN_REVIEW,
  eventType.ROOM_LEAVE,
  eventType.ROOM_MEMBER_ROLE_UPDATE,
  eventType.ROOM_MEMBER_REMOVE,
];

/**
 * Contract writes (Section 5.1): anchored like signals, so discussion traffic
 * cannot starve them, but head-advancing, so replies composed against the old
 * contract are rejected and re-read.
 */
export const CONTRACT_EVENT_TYPES: readonly string[] = [
  eventType.ROOM_UPDATE,
  eventType.ROOM_CLOSE,
  eventType.ROOM_CANCEL,
  eventType.TYPE_DEFINE,
];

/**
 * Class of an accepted record: its freshness class for built-in types
 * (Section 5.1) and its registry `kind` for custom types. `message` and
 * `control` records are head-bound.
 */
export type RecordClass = "genesis" | "contract" | "message" | "signal" | "control";

/** Class of a built-in type per the Section 12.2 table. */
export type BuiltinEventClass = "genesis" | "contract" | "signal" | "message";

/**
 * Section 12.2 class of a built-in type; `undefined` for room-defined types and
 * for `room.join.request`, which never becomes a record.
 */
export function builtinEventClass(
  type: string,
): BuiltinEventClass | undefined {
  switch (type) {
    case eventType.ROOM_CREATE:
      return "genesis";
    case eventType.ROOM_UPDATE:
    case eventType.ROOM_CLOSE:
    case eventType.ROOM_CANCEL:
    case eventType.TYPE_DEFINE:
      return "contract";
    case eventType.ROOM_JOIN:
    case eventType.ROOM_JOIN_REVIEW:
    case eventType.ROOM_LEAVE:
    case eventType.ROOM_MEMBER_ROLE_UPDATE:
    case eventType.ROOM_MEMBER_REMOVE:
      return "signal";
    case eventType.MESSAGE_CREATE:
      return "message";
    default:
      return undefined;
  }
}

/**
 * Record class of an event type; `undefined` for `room.join.request` and for
 * custom types absent from `registry`.
 */
export function recordClass(
  type: string,
  registry?: TypeRegistry | readonly TypeDef[],
): RecordClass | undefined {
  const builtin = builtinEventClass(type);
  if (builtin !== undefined) return builtin;
  if (isBuiltinEventType(type)) return undefined;
  const def = Array.isArray(registry)
    ? (registry as readonly TypeDef[]).find((d) => d.type === type)
    : (registry as TypeRegistry | undefined)?.get(type);
  return def?.kind;
}

/**
 * Whether an accepted record of this type advances the room head (Section
 * 5.1): every class except `signal`. Unknown custom types default to
 * head-advancing.
 */
export function eventAdvancesRoomHead(
  type: string,
  registry?: TypeRegistry | readonly TypeDef[],
): boolean {
  return recordClass(type, registry) !== "signal";
}

/**
 * Whether a write of this type must match the current room head (Section
 * 5.1): `message.create` and custom `message`/`control` kinds. Contract and
 * signal writes only anchor. Unknown custom types default to head-bound.
 */
export function eventRequiresRoomHead(
  type: string,
  registry?: TypeRegistry | readonly TypeDef[],
): boolean {
  const cls = recordClass(type, registry);
  if (cls === undefined) return !isBuiltinEventType(type);
  return cls === "message" || cls === "control";
}

/** ADP-specific error codes (Section 19); shared codes come from Agent Identity. */
export const DISCOURSE_ERROR_CODES: readonly string[] = [
  "room_not_found",
  "room_not_active",
  "room_ended",
  "host_mismatch",
  "approval_required",
  "join_request_not_found",
  "join_request_not_pending",
  "member_banned",
  "role_not_allowed",
  "max_speakers_exceeded",
  "membership_required",
  "room_head_mismatch",
  "base_record_mismatch",
  "agent_status_not_found",
  "type_not_defined",
  "type_disabled",
  "type_conflict",
  "invalid_type_schema",
  "payload_schema_violation",
  "pack_unavailable",
];

/** Hosts MUST reject events with more than this many `mentions` entries. */
export const MAX_MENTIONS = 32;

/** Room IDs are host-assigned and URL-safe (Section 6.1). */
export const ROOM_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

/** `<algorithm>:<base64url-digest>` content digests (Section 12.5). */
export const CONTENT_DIGEST_PATTERN = /^(sha256|sha3-256):[A-Za-z0-9_-]{43}$/;

/** Custom event types must not use these prefixes. */
export const RESERVED_TYPE_PREFIXES = ["room.", "type."] as const;

/** Registered type packs defined by the specification in `1.0.packs.json`. */
export const packId = {
  REACTIONS: "adp:reactions/1.0",
  DELIBERATION: "adp:deliberation/1.0",
  CURATION: "adp:curation/1.0",
  MODERATION: "adp:moderation/1.0",
  REALTIME: "adp:realtime/1.0",
} as const;

export const REGISTERED_PACK_IDS: readonly string[] = Object.values(packId);

export type RoomState = "scheduled" | "active" | "ended" | "cancelled";
export type Visibility = "public" | "restricted" | "private";
export type Role = "moderator" | "speaker" | "observer";
/** Permission class of an event type. */
export type TypeKind = "message" | "signal" | "control";
export type TypeStatus = "active" | "deprecated" | "disabled";
export type JoinRequestStatus = "pending" | "approved" | "rejected" | "expired";
export type JoinDecision = "approve" | "reject";

const ROLES = ["moderator", "speaker", "observer"] as const;
const TYPE_KINDS = ["message", "signal", "control"] as const;
const TYPE_STATUSES = ["active", "deprecated", "disabled"] as const;

export interface RoomCreatePayload {
  /** Origin of the host API the room is created on; binds the event to one host. */
  host: string;
  topic: string;
  agenda?: string;
  guidance?: string;
  visibility: Visibility;
  start_time: number;
  end_time: number;
  tags?: string[];
  language?: string;
  policy?: RoomPolicy;
  types?: TypeDeclaration[];
  extra?: Record<string, unknown>;
}

export interface RoomPolicy {
  /** Agent IDs pre-approved for direct `room.join` with exactly this role. */
  invites?: Record<AgentId, Role>;
  /** Roles anyone may take by direct `room.join` in a public room. */
  open_roles?: Role[];
  max_speakers?: number;
  observer_allowed?: boolean;
  extra?: Record<string, unknown>;
}

/**
 * Payload of `room.update`: a partial contract revision. A present field
 * replaces the current value entirely; an empty value clears an optional
 * field. `host` and `visibility` are not updatable, and the type registry
 * evolves only through `type.define`.
 */
export interface RoomUpdatePayload {
  topic?: string;
  agenda?: string;
  guidance?: string;
  tags?: string[];
  language?: string;
  policy?: RoomPolicy;
  start_time?: number;
  end_time?: number;
}

/** Payload of `room.member.remove`: removal and optional ban. */
export interface RoomMemberRemovePayload {
  member: AgentId;
  /** Defaults to `false`. `true` additionally bans the agent from the room. */
  ban?: boolean;
  reason?: string;
  references?: string[];
  extra?: Record<string, unknown>;
}

/** A room-scoped declaration of a custom event type. */
export interface TypeDef {
  type: string;
  kind: TypeKind;
  title: string;
  description?: string;
  /** JSON Schema for the event payload, following the type schema profile. */
  schema: Record<string, unknown>;
  roles?: Role[];
  instructions?: string;
  version?: string;
  status?: TypeStatus;
  rate_hint?: number;
  max_payload_hint?: number;
  extra?: Record<string, unknown>;
}

/** Per-type adjustments applied when importing a pack. */
export interface TypeOverride {
  roles?: Role[];
  instructions?: string;
  status?: TypeStatus;
  rate_hint?: number;
  max_payload_hint?: number;
}

/** Imports a registered pack (`use`) or an external pack (`pack` + `digest`). */
export interface PackImport {
  use?: string;
  pack?: string;
  digest?: string;
  types?: string[];
  overrides?: Record<string, TypeOverride>;
}

/** One entry of `room.create.payload.types` or a `type.define` payload. */
export type TypeDeclaration = TypeDef | PackImport;

export interface Pack {
  id: string;
  title: string;
  description?: string;
  types: TypeDef[];
  extra?: Record<string, unknown>;
}

/** The shape of `1.0.packs.json` and externally published pack documents. */
export interface PackDocument {
  protocol: string;
  description?: string;
  packs: Pack[];
}

/** Indexes the packs of a document by pack id for registry materialization. */
export function packMap(document: PackDocument): Record<string, Pack> {
  const packs: Record<string, Pack> = {};
  for (const pack of document.packs) packs[pack.id] = pack;
  return packs;
}

export interface RoomResponse {
  id: string;
  status: RoomState;
  url: string;
  creator?: AgentId;
  created_at?: number;
  topic?: string;
  agenda?: string;
  guidance?: string;
  visibility?: Visibility;
  start_time?: number;
  end_time?: number;
  tags?: string[];
  language?: string;
  policy?: RoomPolicy;
  /** Materialized type registry served by the host. */
  types?: TypeDef[];
  extra?: Record<string, unknown>;
  seq: number;
  pre_hash: string | null;
  hash: string;
  accepted_at: number;
  /** Latest accepted head-advancing record. Falls back to `seq`/`hash` on older hosts. */
  head?: RoomHead;
  envelope?: Envelope<RoomCreatePayload>;
}

export interface RoomHead {
  seq: number;
  hash: string;
}

/** Payload of a direct `room.join` (Section 9.2). */
export interface RoomJoinPayload {
  role: Role;
  perspective?: string;
}

/** Payload of a signed `room.join.request` (Section 10). */
export interface RoomJoinRequestPayload {
  role: Role;
  perspective?: string;
  reason?: string;
  extra?: Record<string, unknown>;
}

/** The join request resource: the signed request plus review state. */
export interface RoomJoinRequest {
  /** Event ID of the signed request. */
  id: string;
  request: Envelope<RoomJoinRequestPayload>;
  status: JoinRequestStatus;
  expires_at: number;
  reviewed_by?: AgentId | null;
  reviewed_at?: number | null;
  review_event_id?: string | null;
}

export interface AgentStatusInput {
  state: string;
  summary?: string;
  seen_seq?: number;
  seen_hash?: string;
  claim_id?: string;
  activity?: string;
  /** Optional: when omitted, the host assigns its maximum TTL. */
  expires_at?: number;
  extra?: Record<string, unknown>;
}

export interface AgentStatus {
  room_id: string;
  agent_id: AgentId;
  state: string;
  summary?: string;
  seen_seq?: number;
  seen_hash?: string;
  claim_id?: string;
  activity?: string;
  expires_at: number;
  updated_at: number;
  extra?: Record<string, unknown>;
}

export type AgentStatusListResponse = ListResponse<AgentStatus>;

export interface RoomJoinReviewPayload {
  /** The applicant's signed `room.join.request` envelope. */
  request: Envelope<RoomJoinRequestPayload>;
  decision: JoinDecision;
  /** Required when approving. */
  role?: Role;
  reason?: string;
  extra?: Record<string, unknown>;
}

export interface RoleUpdatePayload {
  member: AgentId;
  role: Role;
  reason?: string;
  extra?: Record<string, unknown>;
}

/** Shared payload of `room.leave`, `room.close`, and `room.cancel`. */
export interface ReasonPayload {
  reason?: string;
  references?: string[];
  extra?: Record<string, unknown>;
}

export type RoomLeavePayload = ReasonPayload;
export type RoomClosePayload = ReasonPayload;
export type RoomCancelPayload = ReasonPayload;

export interface MessageCreatePayload {
  content_type: string;
  /** A JSON string, or a JSON object for a JSON media type. */
  content: string | Record<string, unknown>;
  references?: string[];
  extra?: Record<string, unknown>;
}

export interface ServerRecord<P = unknown> {
  room_id: string;
  seq: number;
  pre_hash: string | null;
  hash: string;
  accepted_at: number;
  envelope: Envelope<P>;
}

/** Envelope of a redacted record (Section 14.1): its event ID and type only. */
export interface RedactedEnvelope {
  hash: string;
  redacted: true;
  type: string;
}

export interface RedactedServerRecord {
  room_id: string;
  seq: number;
  pre_hash: string | null;
  hash: string;
  accepted_at: number;
  envelope: RedactedEnvelope;
}

/** A record as it appears in history or an archive: signed or redacted. */
export type ArchiveRecord = ServerRecord | RedactedServerRecord;

export type RoomEventsResponse = ListResponse<ArchiveRecord>;

export interface ServerRecordHashPayload {
  room_id: string;
  seq: number;
  pre_hash: string | null;
  envelope_hash: string;
  accepted_at: number;
}

export interface ProfileResolverMetadata {
  mode: string;
  service?: string;
  protocol?: string;
}

export interface DiscourseProtocolDiscovery extends DiscoveryDocument {
  registered_packs?: string[];
  profile?: ProfileResolverMetadata;
}

export interface ArchiveManifest {
  protocol: string;
  type: "room.archive";
  room_id: string;
  url: string;
  generated_at: number;
  last_seq: number;
  /** Hash of the record at `last_seq`: the archive's commitment to every record. */
  last_hash: string;
  formats?: Record<string, string>;
  extra?: Record<string, unknown>;
}

/** Permission inputs for one actor in one room. */
export interface PermissionContext {
  role?: Role;
  isCreator?: boolean;
  /** The actor may take the requested role by direct `room.join` (see {@link canJoinDirectly}). */
  directJoinAllowed?: boolean;
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

/** A `room.join.request` carries `room_id` but no base: its author may not be able to read the room. */
export function roomJoinRequestEvent(
  actor: AgentId,
  createdAt: number,
  nonce: number,
  roomId: string,
  payload: RoomJoinRequestPayload,
): Event<RoomJoinRequestPayload> {
  return withRoomId(
    createEvent(
      DISCOURSE_PROTOCOL,
      eventType.ROOM_JOIN_REQUEST,
      actor,
      createdAt,
      nonce,
      payload,
    ),
    roomId,
  );
}

export function typeDefineEvent(
  actor: AgentId,
  createdAt: number,
  nonce: number,
  roomId: string,
  baseSeq: number,
  baseHash: string,
  declaration: TypeDeclaration,
): Event<TypeDeclaration> {
  return withRoomHead(
    withRoomId(
      createEvent(
        DISCOURSE_PROTOCOL,
        eventType.TYPE_DEFINE,
        actor,
        createdAt,
        nonce,
        declaration,
      ),
      roomId,
    ),
    baseSeq,
    baseHash,
  );
}

export function discourseEvent<P>(
  type: string,
  actor: AgentId,
  createdAt: number,
  nonce: number,
  roomId: string,
  baseSeq: number,
  baseHash: string,
  payload: P,
): Event<P> {
  return withRoomHead(
    withRoomId(
      createEvent(DISCOURSE_PROTOCOL, type, actor, createdAt, nonce, payload),
      roomId,
    ),
    baseSeq,
    baseHash,
  );
}

export function isBuiltinEventType(type: string): boolean {
  return BUILTIN_EVENT_TYPES.includes(type);
}

export function eventRequiresRoomId(type: string): boolean {
  return type !== eventType.ROOM_CREATE;
}

/** Whether events of this type carry `base_seq` / `base_hash`. */
export function eventRequiresBase(type: string): boolean {
  return type !== eventType.ROOM_CREATE && type !== eventType.ROOM_JOIN_REQUEST;
}

export function validateRoomId(roomId: unknown): asserts roomId is string {
  if (typeof roomId !== "string" || !ROOM_ID_PATTERN.test(roomId)) {
    throw protocolError("invalid_event", "room_id must match [A-Za-z0-9_-]{1,64}");
  }
}

export function validateDiscourseEnvelope(envelope: Envelope<unknown>): void {
  verifyEnvelope(envelope);
  validateDiscourseEventFields(envelope.event);
}

/** Section 5 event-shape rules: closed fields, room ID, base, and mentions. */
export function validateDiscourseEventFields(event: Event<unknown>): void {
  if (event.protocol !== DISCOURSE_PROTOCOL) {
    throw protocolError(
      "invalid_event_protocol",
      `expected ${DISCOURSE_PROTOCOL}, got ${event.protocol}`,
    );
  }
  if (event.type === eventType.ROOM_CREATE) {
    validateEventFields(event);
    return;
  }
  if (event.type === eventType.ROOM_JOIN_REQUEST) {
    validateEventFields(event, ["room_id"]);
    if (event.room_id === undefined) {
      throw protocolError("missing_room_id", "event requires a room_id");
    }
    validateRoomId(event.room_id);
    return;
  }
  validateEventFields(event, ["room_id", "base_seq", "base_hash", "mentions"]);
  if (event.room_id === undefined) {
    throw protocolError("missing_room_id", "event requires a room_id");
  }
  validateRoomId(event.room_id);
  validateRoomHeadPrecondition(event);
  validateMentions(event.mentions);
}

export function validateRoomPath(
  envelope: Envelope<unknown>,
  pathRoomId: string,
): void {
  validateDiscourseEventFields(envelope.event);
  if (envelope.event.type === eventType.ROOM_CREATE) return;
  const actual = envelope.event.room_id;
  if (actual !== pathRoomId)
    throw protocolError(
      "room_id_mismatch",
      `expected ${pathRoomId}, got ${actual}`,
    );
}

export function validateRoomHeadPrecondition(event: Event<unknown>): void {
  const baseSeq = event.base_seq;
  const baseHash = event.base_hash;
  if (
    !Number.isSafeInteger(baseSeq) ||
    (baseSeq as number) < 1 ||
    (baseSeq as number) > MAX_SAFE_NONCE
  ) {
    throw protocolError(
      "invalid_event",
      "base_seq must be a positive safe JSON integer",
    );
  }
  if (typeof baseHash !== "string" || baseHash.trim() === "") {
    throw protocolError("invalid_event", "base_hash must not be empty");
  }
}

function validateMentions(mentions: AgentId[] | undefined): void {
  if (mentions === undefined) return;
  if (!Array.isArray(mentions)) {
    throw protocolError("invalid_event", "mentions must be an Agent ID array");
  }
  if (mentions.length > MAX_MENTIONS) {
    throw protocolError(
      "invalid_event",
      `mentions must not exceed ${MAX_MENTIONS} entries`,
    );
  }
  if (new Set(mentions).size !== mentions.length) {
    throw protocolError("invalid_event", "mentions must be unique");
  }
  for (const mention of mentions) validateAgentId(mention);
}

/**
 * Checks the shape of a custom event type name: lowercase dot-separated, at
 * least two segments, not built-in, not under a reserved prefix.
 */
export function validateCustomEventTypeName(name: string): void {
  const segments = name.split(".");
  const validShape =
    segments.length >= 2 &&
    segments.every((segment) => /^[a-z0-9][a-z0-9_-]*$/.test(segment));
  if (!validShape) {
    throw protocolError("invalid_event", `invalid event type name: ${name}`);
  }
  if (isBuiltinEventType(name)) {
    throw protocolError("invalid_event", `${name} is a built-in event type`);
  }
  if (RESERVED_TYPE_PREFIXES.some((prefix) => name.startsWith(prefix))) {
    throw protocolError("invalid_event", `${name} uses a reserved type prefix`);
  }
}

export function isPackImport(
  declaration: TypeDeclaration,
): declaration is PackImport {
  return (
    typeof declaration === "object" &&
    declaration !== null &&
    ("use" in declaration || "pack" in declaration || "digest" in declaration)
  );
}

export function isTypeDef(declaration: TypeDeclaration): declaration is TypeDef {
  return (
    typeof declaration === "object" &&
    declaration !== null &&
    !isPackImport(declaration) &&
    "type" in declaration
  );
}

export function validateTypeDef(def: TypeDef): void {
  validateCustomEventTypeName(def.type);
  if (!includes(TYPE_KINDS, def.kind)) {
    throw protocolError("invalid_event", `invalid type kind: ${def.kind}`);
  }
  if (typeof def.title !== "string" || def.title.trim() === "") {
    throw protocolError(
      "invalid_event",
      "type definition title must not be empty",
    );
  }
  if (
    typeof def.schema !== "object" ||
    def.schema === null ||
    Array.isArray(def.schema)
  ) {
    throw protocolError(
      "invalid_type_schema",
      "type definition schema must be a JSON Schema object",
    );
  }
  try {
    validateTypeSchemaProfile(def.schema);
  } catch (error) {
    if (error instanceof AgentProtocolError) throw error;
    throw protocolError("invalid_type_schema", `invalid type schema: ${error}`);
  }
  compileSchema(def.schema);
  if (def.roles !== undefined) {
    if (
      !Array.isArray(def.roles) ||
      def.roles.length === 0 ||
      def.roles.some((role) => !includes(ROLES, role))
    ) {
      throw protocolError(
        "invalid_event",
        "type definition roles must be a non-empty role list",
      );
    }
  }
  if (def.status !== undefined && !includes(TYPE_STATUSES, def.status)) {
    throw protocolError("invalid_event", `invalid type status: ${def.status}`);
  }
  for (const hint of [def.rate_hint, def.max_payload_hint]) {
    if (hint !== undefined && (!Number.isInteger(hint) || hint < 1)) {
      throw protocolError(
        "invalid_event",
        "type definition hints must be positive integers",
      );
    }
  }
}

function includes<const T extends readonly string[]>(
  values: T,
  value: unknown,
): value is T[number] {
  return values.includes(value as T[number]);
}

export function validatePackImport(declaration: PackImport): void {
  const hasUse = declaration.use !== undefined;
  const hasExternal =
    declaration.pack !== undefined && declaration.digest !== undefined;
  if (hasUse) {
    if (declaration.pack !== undefined || declaration.digest !== undefined) {
      throw protocolError(
        "invalid_event",
        "pack import requires either use, or pack with digest",
      );
    }
    if (!isRegisteredPackId(declaration.use as string)) {
      throw protocolError(
        "invalid_event",
        `invalid registered pack id: ${declaration.use}`,
      );
    }
  } else if (hasExternal) {
    if (!/^https:\/\//.test(declaration.pack as string)) {
      throw protocolError("invalid_event", "external pack must be an HTTPS URL");
    }
    if (!CONTENT_DIGEST_PATTERN.test(declaration.digest as string)) {
      throw protocolError(
        "invalid_event",
        "external pack digest must be <sha256|sha3-256>:<base64url-digest>",
      );
    }
  } else {
    throw protocolError(
      "invalid_event",
      "pack import requires either use, or pack with digest",
    );
  }
  if (declaration.types !== undefined) {
    if (declaration.types.length === 0) {
      throw protocolError(
        "invalid_event",
        "pack import types subset must not be empty",
      );
    }
    if (new Set(declaration.types).size !== declaration.types.length) {
      throw protocolError("type_conflict", "pack import types subset has duplicates");
    }
  }
}

export function validateTypeDeclaration(declaration: TypeDeclaration): void {
  if (isPackImport(declaration)) {
    validatePackImport(declaration);
  } else if (isTypeDef(declaration)) {
    validateTypeDef(declaration);
  } else {
    throw protocolError(
      "invalid_event",
      "type declaration must be an inline definition or a pack import",
    );
  }
}

function isRegisteredPackId(id: string): boolean {
  return /^adp:[a-z0-9-]+\/[0-9]+\.[0-9]+$/.test(id);
}

// ── Type schema profile (Section 12.3.1).

const FORBIDDEN_SCHEMA_KEYWORDS = [
  "$dynamicRef",
  "$dynamicAnchor",
  "$recursiveRef",
  "$recursiveAnchor",
  "$vocabulary",
];
const SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema";
const ANNOTATION_KEYWORDS = ["format", "contentEncoding", "contentMediaType", "contentSchema"];
const SUBSCHEMA_KEYWORDS = [
  "items",
  "additionalProperties",
  "not",
  "if",
  "then",
  "else",
  "contains",
  "propertyNames",
  "unevaluatedItems",
  "unevaluatedProperties",
  "additionalItems",
];
const SUBSCHEMA_ARRAY_KEYWORDS = ["allOf", "anyOf", "oneOf", "prefixItems"];
const SUBSCHEMA_MAP_KEYWORDS = ["properties", "patternProperties", "$defs", "definitions", "dependentSchemas"];

/** Calls `visit` on every subschema object of `schema`, depth first. */
function walkSchema(
  schema: unknown,
  visit: (node: Record<string, unknown>) => void,
): void {
  if (typeof schema !== "object" || schema === null || Array.isArray(schema)) return;
  const node = schema as Record<string, unknown>;
  visit(node);
  for (const key of SUBSCHEMA_KEYWORDS) walkSchema(node[key], visit);
  for (const key of SUBSCHEMA_ARRAY_KEYWORDS) {
    if (Array.isArray(node[key])) for (const item of node[key] as unknown[]) walkSchema(item, visit);
  }
  for (const key of SUBSCHEMA_MAP_KEYWORDS) {
    const map = node[key];
    if (typeof map === "object" && map !== null && !Array.isArray(map)) {
      for (const value of Object.values(map)) walkSchema(value, visit);
    }
  }
}

/**
 * Enforces the type schema profile (Section 12.3.1): fragment-only `$ref`, no
 * dynamic or recursive references, the 2020-12 dialect, and portable
 * regular expressions.
 */
export function validateTypeSchemaProfile(schema: Record<string, unknown>): void {
  walkSchema(schema, (node) => {
    for (const keyword of FORBIDDEN_SCHEMA_KEYWORDS) {
      if (keyword in node) throw protocolError("invalid_type_schema", `${keyword} is not allowed`);
    }
    if ("$schema" in node && node.$schema !== SCHEMA_DIALECT) {
      throw protocolError("invalid_type_schema", "$schema must be the draft 2020-12 dialect");
    }
    if ("$ref" in node && (typeof node.$ref !== "string" || !node.$ref.startsWith("#"))) {
      throw protocolError("invalid_type_schema", "$ref must be a fragment inside the schema");
    }
    if ("pattern" in node) {
      if (typeof node.pattern !== "string") throw protocolError("invalid_type_schema", "pattern must be a string");
      validatePortablePattern(node.pattern);
    }
    const patternProperties = node.patternProperties;
    if (typeof patternProperties === "object" && patternProperties !== null) {
      for (const key of Object.keys(patternProperties)) validatePortablePattern(key);
    }
  });
}

/**
 * Checks that a pattern is an I-Regexp (RFC 9485) without `\p{…}`/`\P{…}`
 * and without `.` outside a character class, optionally anchored with a
 * leading `^` and a trailing `$` (Section 12.3.1).
 */
export function validatePortablePattern(pattern: string): void {
  const reject = (reason: string): never => {
    throw protocolError("invalid_type_schema", `pattern ${JSON.stringify(pattern)} is not portable: ${reason}`);
  };
  let body = pattern;
  if (body.startsWith("^")) body = body.slice(1);
  if (body.endsWith("$") && !body.endsWith("\\$")) body = body.slice(0, -1);
  const chars = [...body];
  let i = 0;
  let depth = 0;
  let canQuantify = false;
  const singleEscapes = "()*+-.?[\\]^{|}nrt";
  const readEscape = (): void => {
    const next = chars[i + 1];
    if (next === undefined) reject("dangling escape");
    if (!singleEscapes.includes(next)) reject(`escape \\${next}`);
    i += 2;
  };
  while (i < chars.length) {
    const ch = chars[i];
    if (ch === "\\") {
      readEscape();
      canQuantify = true;
    } else if (ch === "[") {
      i += 1;
      if (chars[i] === "^") i += 1;
      // A leading `]` is literal in some engines and an empty class in others.
      if (chars[i] === "]") reject("empty character class");
      while (i < chars.length && chars[i] !== "]") {
        if (chars[i] === "\\") readEscape();
        else if (chars[i] === "[") reject("nested character class");
        else i += 1;
      }
      if (chars[i] !== "]") reject("unterminated character class");
      i += 1;
      canQuantify = true;
    } else if (ch === "(") {
      if (chars[i + 1] === "?") reject("group modifiers");
      depth += 1;
      i += 1;
      canQuantify = false;
    } else if (ch === ")") {
      if (depth === 0) reject("unbalanced parenthesis");
      depth -= 1;
      i += 1;
      canQuantify = true;
    } else if (ch === "|") {
      i += 1;
      canQuantify = false;
    } else if (ch === "*" || ch === "+" || ch === "?") {
      if (!canQuantify) reject("quantifier without operand");
      i += 1;
      if (chars[i] === "?" || chars[i] === "+") reject("lazy or possessive quantifier");
      canQuantify = false;
    } else if (ch === "{") {
      if (!canQuantify) reject("quantifier without operand");
      const rest = chars.slice(i).join("");
      const match = /^\{[0-9]+(,[0-9]*)?\}/.exec(rest);
      if (!match) reject("malformed quantifier");
      i += [...match![0]].length;
      if (chars[i] === "?" || chars[i] === "+") reject("lazy or possessive quantifier");
      canQuantify = false;
    } else if (ch === ".") {
      reject("'.' outside a character class");
    } else if (ch === "^" || ch === "$") {
      reject("anchor inside the pattern");
    } else if (ch === "}" || ch === "]") {
      reject(`unescaped ${ch}`);
    } else {
      i += 1;
      canQuantify = true;
    }
  }
  if (depth !== 0) reject("unbalanced parenthesis");
}

/** A copy of `schema` without annotation-only keywords, which validators must not assert. */
function stripAnnotations(schema: unknown): unknown {
  const copy = structuredClone(schema);
  walkSchema(copy, (node) => {
    for (const keyword of ANNOTATION_KEYWORDS) delete node[keyword];
  });
  return copy;
}

const ROOM_POLICY_FIELDS = ["invites", "open_roles", "max_speakers", "observer_allowed", "extra"];

/** Section 8.3 rules for a room policy. */
export function validateRoomPolicy(policy: RoomPolicy | undefined): void {
  if (policy === undefined) return;
  if (typeof policy !== "object" || policy === null || Array.isArray(policy)) {
    throw protocolError("invalid_event", "policy must be an object");
  }
  for (const key of Object.keys(policy)) {
    if (!ROOM_POLICY_FIELDS.includes(key)) throw protocolError("invalid_event", `unknown policy field: ${key}`);
  }
  const maxSpeakers = policy.max_speakers;
  if (
    maxSpeakers !== undefined &&
    (!Number.isInteger(maxSpeakers) || maxSpeakers < 1)
  ) {
    throw protocolError(
      "invalid_event",
      "max_speakers must be a positive integer",
    );
  }
  const observerAllowed = policy.observer_allowed ?? true;
  if (policy.invites !== undefined) {
    if (typeof policy.invites !== "object" || policy.invites === null || Array.isArray(policy.invites)) {
      throw protocolError("invalid_event", "invites must be an object");
    }
    for (const [agentId, role] of Object.entries(policy.invites)) {
      validateAgentId(agentId);
      if (!includes(ROLES, role)) throw protocolError("invalid_event", `invalid invited role: ${role}`);
      if (role === "observer" && !observerAllowed) throw protocolError("role_not_allowed", "observers are not allowed");
    }
  }
  if (policy.open_roles !== undefined) {
    if (!Array.isArray(policy.open_roles) || new Set(policy.open_roles).size !== policy.open_roles.length) {
      throw protocolError("invalid_event", "open_roles must be a list of unique roles");
    }
    for (const role of policy.open_roles) {
      if (role !== "speaker" && role !== "observer") throw protocolError("invalid_event", `open_roles cannot contain ${role}`);
      if (role === "observer" && !observerAllowed) throw protocolError("role_not_allowed", "observers are not allowed");
    }
  }
}

/** The roles anyone may take by direct `room.join` in a public room. */
export function effectiveOpenRoles(policy: RoomPolicy | undefined): Role[] {
  if (policy?.open_roles !== undefined) return [...policy.open_roles];
  return policy?.observer_allowed === false ? ["speaker"] : ["speaker", "observer"];
}

/**
 * Section 9.2 direct-join eligibility: the actor is invited with exactly
 * `role`, or the room is public and `role` is open. Bans and quotas are
 * separate host checks.
 */
export function canJoinDirectly(
  visibility: Visibility,
  policy: RoomPolicy | undefined,
  actor: AgentId,
  role: Role,
): boolean {
  if (policy?.invites?.[actor] === role) return true;
  return visibility === "public" && effectiveOpenRoles(policy).includes(role);
}

export function validateRoomCreatePayload(payload: RoomCreatePayload): void {
  if (typeof payload.host !== "string" || !/^https:\/\/[^/?#@\s]+$/.test(payload.host)) {
    throw protocolError("invalid_event", "room.create host must be an HTTPS origin");
  }
  if (payload.topic.trim() === "") {
    throw protocolError("invalid_event", "room topic must not be empty");
  }
  if (payload.start_time >= payload.end_time) {
    throw protocolError("invalid_event", "start_time must be before end_time");
  }
  validateRoomPolicy(payload.policy);
  for (const declaration of payload.types ?? []) {
    validateTypeDeclaration(declaration);
  }
}

/** Host binding check (Section 8.1): `host` must be the receiving host's API origin. */
export function validateRoomCreateHost(payload: RoomCreatePayload, hostOrigin: string): void {
  if (payload.host !== hostOrigin) {
    throw protocolError("host_mismatch", `room.create names ${payload.host}, not ${hostOrigin}`);
  }
}

export function validateMessageCreatePayload(
  payload: MessageCreatePayload,
): void {
  if (typeof payload.content_type !== "string" || payload.content_type.trim() === "") {
    throw protocolError("invalid_event", "content_type must not be empty");
  }
  const content = payload.content as unknown;
  if (typeof content !== "string" && (typeof content !== "object" || content === null || Array.isArray(content))) {
    throw protocolError("invalid_event", "content must be a string or an object");
  }
}

export function validateRoomJoinPayload(payload: RoomJoinPayload): void {
  for (const key of Object.keys(payload)) {
    if (key !== "role" && key !== "perspective") {
      throw protocolError("invalid_event", `unknown room.join payload field: ${key}`);
    }
  }
  if (!includes(ROLES, payload.role)) {
    throw protocolError("invalid_event", `invalid room role: ${payload.role}`);
  }
}

export function validateRoomJoinRequestPayload(payload: RoomJoinRequestPayload): void {
  for (const key of Object.keys(payload)) {
    if (!["role", "perspective", "reason", "extra"].includes(key)) {
      throw protocolError("invalid_event", `unknown room.join.request payload field: ${key}`);
    }
  }
  if (!includes(ROLES, payload.role)) {
    throw protocolError("invalid_event", `invalid room role: ${payload.role}`);
  }
}

/**
 * Verifies a signed `room.join.request` envelope for embedding or review:
 * hash, signature, and shape — historical verification, without the live
 * time window or nonce check.
 */
export function validateJoinRequestEnvelope(
  envelope: Envelope<RoomJoinRequestPayload>,
  roomId?: string,
): void {
  validateDiscourseEnvelope(envelope);
  if (envelope.event.type !== eventType.ROOM_JOIN_REQUEST) {
    throw protocolError("invalid_event", "embedded request must be a room.join.request");
  }
  if (roomId !== undefined && envelope.event.room_id !== roomId) {
    throw protocolError("room_id_mismatch", "join request belongs to another room");
  }
  validateRoomJoinRequestPayload(envelope.event.payload);
}

/** Shape checks for `room.join.review`, including the embedded signed request. */
export function validateRoomJoinReviewPayload(
  payload: RoomJoinReviewPayload,
  roomId?: string,
): void {
  validateJoinRequestEnvelope(payload.request, roomId);
  if (payload.decision !== "approve" && payload.decision !== "reject") {
    throw protocolError("invalid_event", `invalid review decision: ${payload.decision}`);
  }
  if (payload.decision === "approve" && !includes(ROLES, payload.role)) {
    throw protocolError("invalid_event", "an approving review requires a role");
  }
}

const ROOM_UPDATE_FIELDS = [
  "topic",
  "agenda",
  "guidance",
  "tags",
  "language",
  "policy",
  "start_time",
  "end_time",
] as const;

/**
 * Shape checks for a `room.update` payload. State-dependent rules — room
 * status, effective time ordering against the current contract — remain
 * host-side.
 */
export function validateRoomUpdatePayload(payload: RoomUpdatePayload): void {
  const keys = Object.keys(payload);
  if (keys.length === 0) {
    throw protocolError("invalid_event", "room.update payload must not be empty");
  }
  for (const key of keys) {
    if (!includes(ROOM_UPDATE_FIELDS, key)) {
      throw protocolError(
        "invalid_event",
        `room.update payload field ${key} is not updatable`,
      );
    }
  }
  if (payload.topic !== undefined && payload.topic.trim() === "") {
    throw protocolError("invalid_event", "room topic must not be empty");
  }
  if (
    payload.start_time !== undefined &&
    payload.end_time !== undefined &&
    payload.start_time >= payload.end_time
  ) {
    throw protocolError("invalid_event", "start_time must be before end_time");
  }
  validateRoomPolicy(payload.policy);
}

/**
 * Shape checks for a `room.member.remove` payload. Creator, self, and
 * membership checks remain host-side.
 */
export function validateRoomMemberRemovePayload(
  payload: RoomMemberRemovePayload,
): void {
  validateAgentId(payload.member);
  if (payload.ban !== undefined && typeof payload.ban !== "boolean") {
    throw protocolError("invalid_event", "ban must be a boolean");
  }
}

/** The effective set of type definitions active in a room. */
export class TypeRegistry {
  private readonly types = new Map<string, TypeDef>();

  /**
   * Materializes a registry from the `room.create` declarations, resolving
   * pack imports from `packs`, keyed by registered pack id or external pack
   * URI. A type name may appear only once across these declarations.
   */
  static fromDeclarations(
    declarations: TypeDeclaration[],
    packs: Record<string, Pack> = {},
  ): TypeRegistry {
    const registry = new TypeRegistry();
    const declared = new Set<string>();
    for (const declaration of declarations) {
      for (const name of registry.apply(declaration, packs)) {
        if (declared.has(name)) {
          throw protocolError("type_conflict", `type ${name} is declared twice`);
        }
        declared.add(name);
      }
    }
    return registry;
  }

  /**
   * Applies one declaration — an inline definition or a pack import — and
   * returns the type names it declared. Declaring an existing type is a
   * redefinition: it must keep the type's kind, and the latest definition wins.
   */
  apply(declaration: TypeDeclaration, packs: Record<string, Pack> = {}): string[] {
    if (isPackImport(declaration)) {
      return this.import(declaration, packs);
    }
    if (isTypeDef(declaration)) {
      this.define(declaration);
      return [declaration.type];
    }
    throw protocolError(
      "invalid_event",
      "type declaration must be an inline definition or a pack import",
    );
  }

  define(def: TypeDef): void {
    validateTypeDef(def);
    const existing = this.types.get(def.type);
    if (existing && existing.kind !== def.kind) {
      throw protocolError(
        "type_conflict",
        `type ${def.type} cannot change kind from ${existing.kind} to ${def.kind}`,
      );
    }
    this.types.set(def.type, def);
  }

  private import(declaration: PackImport, packs: Record<string, Pack>): string[] {
    validatePackImport(declaration);
    const reference = declaration.use ?? (declaration.pack as string);
    const pack = packs[reference];
    if (!pack) {
      throw protocolError("pack_unavailable", `pack not available: ${reference}`);
    }
    const available = new Set<string>();
    for (const def of pack.types) {
      if (available.has(def.type)) {
        throw protocolError("type_conflict", `pack ${reference} defines ${def.type} twice`);
      }
      available.add(def.type);
    }
    for (const name of declaration.types ?? []) {
      if (!available.has(name)) {
        throw protocolError(
          "type_conflict",
          `type ${name} is not in pack ${reference}`,
        );
      }
    }
    const subset =
      declaration.types !== undefined ? new Set(declaration.types) : undefined;
    for (const name of Object.keys(declaration.overrides ?? {})) {
      const imported = subset ? subset.has(name) : available.has(name);
      if (!imported) {
        throw protocolError(
          "type_conflict",
          `override target ${name} is not imported from pack ${reference}`,
        );
      }
    }
    const declared: string[] = [];
    for (const def of pack.types) {
      if (subset && !subset.has(def.type)) continue;
      const override = declaration.overrides?.[def.type];
      this.define(override ? { ...def, ...override } : { ...def });
      declared.push(def.type);
    }
    return declared;
  }

  get(type: string): TypeDef | undefined {
    return this.types.get(type);
  }

  has(type: string): boolean {
    return this.types.has(type);
  }

  get size(): number {
    return this.types.size;
  }

  definitions(): TypeDef[] {
    return [...this.types.values()];
  }

  /** Validates a custom event payload against the type's schema and status. */
  validatePayload(type: string, payload: unknown): void {
    const def = this.types.get(type);
    if (!def) {
      throw protocolError("type_not_defined", type);
    }
    if ((def.status ?? "active") === "disabled") {
      throw protocolError("type_disabled", type);
    }
    const validator = compileSchema(def.schema);
    const result = validator.validate(payload);
    if (!result.valid) {
      const detail = result.errors
        .slice(0, 3)
        .map((error) => error.error)
        .join("; ");
      throw protocolError("payload_schema_violation", `${type}: ${detail}`);
    }
  }
}

/**
 * Validates an event payload: built-in payloads are accepted as-is (use the
 * typed validators for them); custom payloads must satisfy the registry.
 */
export function validateEventAgainstRegistry(
  type: string,
  payload: unknown,
  registry: TypeRegistry,
): void {
  if (isBuiltinEventType(type)) return;
  registry.validatePayload(type, payload);
}

function compileSchema(schema: Record<string, unknown>): Validator {
  try {
    // Annotation keywords are never asserted (Section 12.3.1).
    return new Validator(stripAnnotations(schema) as Schema, "2020-12", false);
  } catch (error) {
    throw protocolError("invalid_type_schema", `invalid type schema: ${error}`);
  }
}

/**
 * Verifies a `<algorithm>:<base64url-digest>` content digest over raw bytes.
 * Supports `sha256` and `sha3-256`.
 */
export function verifyPackDigest(bytes: Uint8Array, digest: string): void {
  if (!CONTENT_DIGEST_PATTERN.test(digest)) {
    throw protocolError("pack_unavailable", `invalid digest format: ${digest}`);
  }
  const separator = digest.indexOf(":");
  const algorithm = digest.slice(0, separator);
  const expected = digest.slice(separator + 1);
  const actual = createHash(algorithm)
    .update(bytes)
    .digest("base64url");
  if (actual !== expected) {
    throw protocolError("pack_unavailable", "pack digest mismatch");
  }
}

export function serverRecordHashPayload(
  roomId: string,
  seq: number,
  preHash: string | null | undefined,
  envelopeHash: string,
  acceptedAt: number,
): ServerRecordHashPayload {
  return {
    room_id: roomId,
    seq,
    pre_hash: preHash ?? null,
    envelope_hash: envelopeHash,
    accepted_at: acceptedAt,
  };
}

export function serverRecordHash(
  roomId: string,
  seq: number,
  preHash: string | null | undefined,
  envelopeHash: string,
  acceptedAt: number,
): string {
  return hashCanonicalJson(
    serverRecordHashPayload(roomId, seq, preHash, envelopeHash, acceptedAt),
  );
}

export function buildServerRecord<P>(
  roomId: string,
  seq: number,
  preHash: string | null | undefined,
  acceptedAt: number,
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
      acceptedAt,
    ),
    accepted_at: acceptedAt,
    envelope,
  };
}

export function isRedactedEnvelope(value: unknown): value is RedactedEnvelope {
  return typeof value === "object" && value !== null && (value as RedactedEnvelope).redacted === true;
}

export function isRedactedRecord(record: ArchiveRecord): record is RedactedServerRecord {
  return isRedactedEnvelope(record.envelope);
}

/**
 * Replaces a record's envelope with its redacted form (Section 14.1). Only
 * `message.create` and custom-type records may be redacted.
 */
export function redactServerRecord(record: ServerRecord): RedactedServerRecord {
  const type = record.envelope.event.type;
  if (isBuiltinEventType(type) && type !== eventType.MESSAGE_CREATE) {
    throw protocolError("invalid_event", `${type} records cannot be redacted`);
  }
  return { ...record, envelope: { hash: record.envelope.hash, redacted: true, type } };
}

export function verifyServerRecord(record: ArchiveRecord): void {
  const expected = serverRecordHash(
    record.room_id,
    record.seq,
    record.pre_hash,
    record.envelope.hash,
    record.accepted_at,
  );
  if (record.hash !== expected) {
    throw protocolError(
      "invalid_record_hash",
      `invalid server record hash: expected ${expected}, got ${record.hash}`,
    );
  }
  if (isRedactedRecord(record)) {
    const type = record.envelope.type;
    if (isBuiltinEventType(type) && type !== eventType.MESSAGE_CREATE) {
      throw protocolError("invalid_record_chain", `${type} records cannot be redacted`);
    }
  }
}

export function verifyServerRecordChain(records: ArchiveRecord[]): void {
  let previous: ArchiveRecord | undefined;
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

/**
 * Archive verification steps 1–3 (Section 18): a gap-free chain from seq 1 to
 * `last_seq` ending in `last_hash`, and a valid signature on every record that
 * is not redacted. Returns the sequence numbers of redacted records, which
 * verifiers must report. State replay (step 4) is the caller's.
 */
export function verifyArchiveRecords(
  manifest: ArchiveManifest,
  records: ArchiveRecord[],
): number[] {
  verifyServerRecordChain(records);
  const last = records[records.length - 1];
  if (!last || last.seq !== manifest.last_seq || last.hash !== manifest.last_hash) {
    throw protocolError("invalid_record_chain", "archive does not end at last_seq / last_hash");
  }
  const redacted: number[] = [];
  for (const record of records) {
    if (record.room_id !== manifest.room_id) {
      throw protocolError("invalid_record_chain", "record belongs to another room");
    }
    if (isRedactedRecord(record)) redacted.push(record.seq);
    else validateDiscourseEnvelope(record.envelope);
  }
  return redacted;
}

/** Default sender roles for each kind. The creator passes every role check. */
export function defaultKindRoles(kind: TypeKind): readonly Role[] {
  switch (kind) {
    case "message":
      return ["moderator", "speaker"];
    case "signal":
      return ["moderator", "speaker", "observer"];
    case "control":
      return ["moderator"];
  }
}

/**
 * Role check for one event type, using kind defaults and per-type overrides
 * from the room's type registry. State checks are separate.
 */
export function canSubmitEvent(
  type: string,
  context: PermissionContext,
  registry: TypeRegistry = new TypeRegistry(),
): boolean {
  switch (type) {
    case eventType.ROOM_CREATE:
      return true;
    case eventType.ROOM_JOIN:
      return Boolean(context.directJoinAllowed) && !context.isCreator && context.role === undefined;
    case eventType.ROOM_JOIN_REQUEST:
      return !context.isCreator && context.role === undefined;
    case eventType.ROOM_LEAVE:
      // The creator is a member until the room ends and cannot leave.
      return !context.isCreator && context.role !== undefined;
    case eventType.ROOM_UPDATE:
    case eventType.ROOM_JOIN_REVIEW:
    case eventType.ROOM_MEMBER_ROLE_UPDATE:
    case eventType.ROOM_MEMBER_REMOVE:
    case eventType.ROOM_CLOSE:
    case eventType.ROOM_CANCEL:
    case eventType.TYPE_DEFINE:
      return Boolean(context.isCreator) || context.role === "moderator";
    case eventType.MESSAGE_CREATE:
      return (
        Boolean(context.isCreator) ||
        context.role === "moderator" ||
        context.role === "speaker"
      );
    default: {
      const def = registry.get(type);
      if (!def || (def.status ?? "active") === "disabled") return false;
      if (context.isCreator) return true;
      if (context.role === undefined) return false;
      const roles = def.roles ?? defaultKindRoles(def.kind);
      return roles.includes(context.role);
    }
  }
}

export function canWriteInState(type: string, state: RoomState): boolean {
  switch (state) {
    case "scheduled":
      return (
        type === eventType.ROOM_JOIN_REQUEST ||
        type === eventType.ROOM_JOIN ||
        type === eventType.ROOM_JOIN_REVIEW ||
        type === eventType.ROOM_MEMBER_ROLE_UPDATE ||
        type === eventType.ROOM_MEMBER_REMOVE ||
        type === eventType.ROOM_LEAVE ||
        type === eventType.ROOM_UPDATE ||
        type === eventType.TYPE_DEFINE ||
        type === eventType.ROOM_CANCEL
      );
    case "active":
      return type !== eventType.ROOM_CREATE && type !== eventType.ROOM_CANCEL;
    case "ended":
    case "cancelled":
      return false;
  }
}

export function canAcceptRoomWrite(
  type: string,
  state: RoomState,
  permission: PermissionContext,
  registry: TypeRegistry = new TypeRegistry(),
): boolean {
  return canSubmitEvent(type, permission, registry) && canWriteInState(type, state);
}

export function validateRoomWrite(
  type: string,
  state: RoomState,
  permission: PermissionContext,
  registry: TypeRegistry = new TypeRegistry(),
): void {
  if (!canAcceptRoomWrite(type, state, permission, registry)) {
    throw protocolError(
      "permission_denied",
      "actor lacks permission or state is not writable",
    );
  }
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
