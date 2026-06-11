/**
 * Agent Discourse Protocol 1.0: kernel types, the room type system, and
 * verification helpers.
 *
 * The protocol defines nine built-in event types. Every other event type is
 * declared per room as a schema-validated type definition, either inline or
 * imported from a type pack. Hosts validate structure and permissions; they
 * never need to understand application semantics.
 */
import { Validator, type Schema } from "@cfworker/json-schema";
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

/** The nine built-in event types. All other types are room-defined. */
export const eventType = {
  ROOM_CREATE: "room.create",
  ROOM_JOIN: "room.join",
  ROOM_JOIN_REVIEW: "room.join.review",
  ROOM_LEAVE: "room.leave",
  ROOM_MEMBER_ROLE_UPDATE: "room.member.role.update",
  ROOM_CLOSE: "room.close",
  ROOM_CANCEL: "room.cancel",
  TYPE_DEFINE: "type.define",
  MESSAGE_CREATE: "message.create",
} as const;

export type BuiltinEventType = (typeof eventType)[keyof typeof eventType];

export const BUILTIN_EVENT_TYPES: readonly string[] = Object.values(eventType);

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

export interface RoomCreatePayload {
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
  moderator_agent_ids?: AgentId[];
  max_speakers?: number;
  observer_allowed?: boolean;
  extra?: Record<string, unknown>;
}

/** A room-scoped declaration of a custom event type. */
export interface TypeDef {
  type: string;
  kind: TypeKind;
  title: string;
  description?: string;
  /** Self-contained JSON Schema (draft 2020-12) for the event payload. */
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
  topic?: string;
  guidance?: string;
  visibility?: Visibility;
  start_time?: number;
  end_time?: number;
  policy?: RoomPolicy;
  /** Materialized type registry served by the host. */
  types?: TypeDef[];
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
  extra?: Record<string, unknown>;
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
  reviewed_by?: AgentId | null;
  reviewed_at?: number | null;
  expires_at?: number;
  extra?: Record<string, unknown>;
}

export interface RoomJoinReviewPayload {
  request_id: string;
  member: AgentId;
  decision: JoinDecision;
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
  content: unknown;
  references?: string[];
  extra?: Record<string, unknown>;
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
  registered_packs?: string[];
  profile?: ProfileResolverMetadata;
  endpoints?: Record<string, string>;
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
  formats?: Record<string, string>;
  extra?: Record<string, unknown>;
}

/** Permission inputs for one actor in one room. */
export interface PermissionContext {
  role?: Role;
  isCreator?: boolean;
  joinRequestApproved?: boolean;
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

export function typeDefineEvent(
  actor: AgentId,
  createdAt: number,
  nonce: number,
  roomId: string,
  declaration: TypeDeclaration,
): Event<TypeDeclaration> {
  return withRoomId(
    createEvent(
      DISCOURSE_PROTOCOL,
      eventType.TYPE_DEFINE,
      actor,
      createdAt,
      nonce,
      declaration,
    ),
    roomId,
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

export function isBuiltinEventType(type: string): boolean {
  return BUILTIN_EVENT_TYPES.includes(type);
}

export function eventRequiresRoomId(type: string): boolean {
  return type !== eventType.ROOM_CREATE;
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
  if (envelope.event.type === eventType.ROOM_CREATE) {
    if (envelope.event.room_id !== undefined) {
      throw protocolError(
        "invalid_event",
        "room.create must not include room_id",
      );
    }
  } else if (envelope.event.room_id === undefined) {
    throw protocolError("missing_room_id", "event requires a room_id");
  }
}

export function validateRoomPath(
  envelope: Envelope<unknown>,
  pathRoomId: string,
): void {
  const actual = envelope.event.room_id;
  if (envelope.event.type === eventType.ROOM_CREATE) {
    if (actual !== undefined) {
      throw protocolError(
        "invalid_event",
        "room.create must not include room_id",
      );
    }
    return;
  }
  if (actual === undefined)
    throw protocolError("missing_room_id", "event requires a room_id");
  if (actual !== pathRoomId)
    throw protocolError(
      "room_id_mismatch",
      `expected ${pathRoomId}, got ${actual}`,
    );
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
  if (!["message", "signal", "control"].includes(def.kind)) {
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
      "invalid_event",
      "type definition schema must be a JSON Schema object",
    );
  }
  compileSchema(def.schema);
  if (def.roles !== undefined && def.roles.length === 0) {
    throw protocolError(
      "invalid_event",
      "type definition roles must not be empty",
    );
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
    if ((declaration.digest as string).trim() === "") {
      throw protocolError(
        "invalid_event",
        "external pack digest must not be empty",
      );
    }
  } else {
    throw protocolError(
      "invalid_event",
      "pack import requires either use, or pack with digest",
    );
  }
  if (declaration.types !== undefined && declaration.types.length === 0) {
    throw protocolError(
      "invalid_event",
      "pack import types subset must not be empty",
    );
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

export function validateRoomCreatePayload(payload: RoomCreatePayload): void {
  if (payload.topic.trim() === "") {
    throw protocolError("invalid_event", "room topic must not be empty");
  }
  if (payload.start_time >= payload.end_time) {
    throw protocolError("invalid_event", "start_time must be before end_time");
  }
  const maxSpeakers = payload.policy?.max_speakers;
  if (
    maxSpeakers !== undefined &&
    (!Number.isInteger(maxSpeakers) || maxSpeakers < 1)
  ) {
    throw protocolError(
      "invalid_event",
      "max_speakers must be a positive integer",
    );
  }
  for (const declaration of payload.types ?? []) {
    validateTypeDeclaration(declaration);
  }
}

export function validateMessageCreatePayload(
  payload: MessageCreatePayload,
): void {
  if (payload.content_type.trim() === "") {
    throw protocolError("invalid_event", "content_type must not be empty");
  }
}

/** The effective set of type definitions active in a room. */
export class TypeRegistry {
  private readonly types = new Map<string, TypeDef>();

  /**
   * Materializes a registry from declarations, resolving pack imports from
   * `packs`, keyed by registered pack id or external pack URI.
   */
  static fromDeclarations(
    declarations: TypeDeclaration[],
    packs: Record<string, Pack> = {},
  ): TypeRegistry {
    const registry = new TypeRegistry();
    for (const declaration of declarations) {
      registry.apply(declaration, packs);
    }
    return registry;
  }

  /**
   * Applies one declaration: an inline definition or a pack import.
   * Redefining an existing type replaces it; the latest definition wins.
   */
  apply(declaration: TypeDeclaration, packs: Record<string, Pack> = {}): void {
    if (isPackImport(declaration)) {
      this.import(declaration, packs);
    } else if (isTypeDef(declaration)) {
      this.define(declaration);
    } else {
      throw protocolError(
        "invalid_event",
        "type declaration must be an inline definition or a pack import",
      );
    }
  }

  define(def: TypeDef): void {
    validateTypeDef(def);
    this.types.set(def.type, def);
  }

  private import(declaration: PackImport, packs: Record<string, Pack>): void {
    validatePackImport(declaration);
    const reference = declaration.use ?? (declaration.pack as string);
    const pack = packs[reference];
    if (!pack) {
      throw protocolError("pack_unavailable", `pack not available: ${reference}`);
    }
    const available = new Set(pack.types.map((def) => def.type));
    for (const name of declaration.types ?? []) {
      if (!available.has(name)) {
        throw protocolError(
          "pack_unavailable",
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
          "invalid_event",
          `override target ${name} is not imported from pack ${reference}`,
        );
      }
    }
    for (const def of pack.types) {
      if (subset && !subset.has(def.type)) continue;
      const override = declaration.overrides?.[def.type];
      this.define(override ? { ...def, ...override } : { ...def });
    }
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
    return new Validator(schema as Schema, "2020-12", false);
  } catch (error) {
    throw protocolError("invalid_event", `invalid type schema: ${error}`);
  }
}

/**
 * Verifies a `<algorithm>:<base64url-digest>` content digest over raw bytes.
 * Supports `sha256` and `sha3-256`.
 */
export function verifyPackDigest(bytes: Uint8Array, digest: string): void {
  const separator = digest.indexOf(":");
  if (separator < 0) {
    throw protocolError("pack_unavailable", `invalid digest format: ${digest}`);
  }
  const algorithm = digest.slice(0, separator);
  const expected = digest.slice(separator + 1);
  if (algorithm !== "sha256" && algorithm !== "sha3-256") {
    throw protocolError(
      "pack_unavailable",
      `unsupported digest algorithm: ${algorithm}`,
    );
  }
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
      return Boolean(context.joinRequestApproved);
    case eventType.ROOM_LEAVE:
      return Boolean(context.isCreator) || context.role !== undefined;
    case eventType.ROOM_JOIN_REVIEW:
    case eventType.ROOM_MEMBER_ROLE_UPDATE:
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
        type === eventType.ROOM_JOIN ||
        type === eventType.ROOM_JOIN_REVIEW ||
        type === eventType.ROOM_MEMBER_ROLE_UPDATE ||
        type === eventType.ROOM_LEAVE ||
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
