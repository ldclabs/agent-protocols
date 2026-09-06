import { protocolError } from "./errors.js";
import {
  AgentId,
  Envelope,
  Event,
  createEvent,
  validateAgentId,
  verifyEnvelope,
} from "./identity.js";

export const DELEGATION_PROTOCOL = "agent-delegation/1.0";
export const DELEGATION_GRANT = "delegation.grant";
export const DELEGATION_REVOKE = "delegation.revoke";

export type DelegationEventType =
  | typeof DELEGATION_GRANT
  | typeof DELEGATION_REVOKE;

export type DelegationStatus =
  | "active"
  | "suspended"
  | "expired"
  | "revoked";

export interface PrincipalLink {
  name: string;
  url: string;
  rel: string;
}

export interface PrincipalDescriptor {
  id: string;
  type?: string;
  name?: string;
}

/** The same record is used in current and retired controller lists. */
export interface Controller {
  id: AgentId;
  source: string;
  valid_from: number;
  name?: string;
  delegation?: "*" | { scopes: string[]; audiences: string[] };
  retired_at?: number;
  invalid_from?: number;
}

export interface DelegationAcceptance {
  event_id: string;
  accepted_at: number;
}

export interface PrincipalDocument extends PrincipalDescriptor {
  description?: string;
  avatar_url?: string;
  /** Other HTTPS URLs that lead to this principal. Aliases are not identities. */
  aliases?: string[];
  links?: PrincipalLink[];
  protocol: typeof DELEGATION_PROTOCOL;
  controllers: Controller[];
  retired_controllers?: Controller[];
  /** Delegation query endpoint for this principal; answers existence checks. */
  delegation_query_url?: string;
  updated_at: number;
  extra?: Record<string, unknown>;
}

export interface DelegationGrantPayload {
  id: string;
  principal: PrincipalDescriptor;
  subject: AgentId;
  relationship?: string;
  scopes: string[];
  audiences: string[];
  constraints?: Record<string, unknown>;
  not_before?: number;
  expires_at?: number;
}

export interface DelegationRevokePayload {
  id: string;
  principal_id: string;
  reason?: string;
}

export type DelegationPayload =
  | DelegationGrantPayload
  | DelegationRevokePayload;

export interface DelegationCredential {
  id: string;
  protocol: typeof DELEGATION_PROTOCOL;
  principal: PrincipalDescriptor;
  controller: AgentId;
  owner_controller: AgentId;
  grant_event_id: string;
  accepted_at: number;
  subject: AgentId;
  relationship?: string;
  scopes: string[];
  audiences: string[];
  constraints?: Record<string, unknown>;
  not_before?: number;
  expires_at?: number;
  status: DelegationStatus;
  updated_at: number;
  event_id: string;
}

export interface DelegationStatusDocument {
  protocol: typeof DELEGATION_PROTOCOL;
  grant_event_id: string;
  accepted_at: number;
  id: string;
  status: DelegationStatus;
  checked_at: number;
  expires_at?: number;
  event_id: string;
}

export interface DelegationServiceEndpoints {
  delegations: string;
  query?: string;
}

export interface DelegationServiceDiscovery {
  protocol: typeof DELEGATION_PROTOCOL;
  service: string;
  endpoints: DelegationServiceEndpoints;
  features?: string[];
}

export interface DelegationQueryRequest {
  subject?: AgentId;
  principal_id?: string;
  id?: string;
  status?: DelegationStatus;
  limit?: number;
}

export interface DelegationSummary {
  id: string;
  subject: AgentId;
  principal: PrincipalDescriptor;
  scopes: string[];
  status: DelegationStatus;
}

export interface DelegationQueryResponse {
  result: DelegationSummary[];
}

export interface DelegationEventsResponse {
  result: Envelope<DelegationPayload>[];
  acceptances: DelegationAcceptance[];
}

export function delegationGrantEvent(
  actor: AgentId,
  createdAt: number,
  nonce: number,
  payload: DelegationGrantPayload,
): Event<DelegationGrantPayload> {
  return createEvent(
    DELEGATION_PROTOCOL,
    DELEGATION_GRANT,
    actor,
    createdAt,
    nonce,
    payload,
  );
}

export function delegationRevokeEvent(
  actor: AgentId,
  createdAt: number,
  nonce: number,
  payload: DelegationRevokePayload,
): Event<DelegationRevokePayload> {
  return createEvent(
    DELEGATION_PROTOCOL,
    DELEGATION_REVOKE,
    actor,
    createdAt,
    nonce,
    payload,
  );
}

export function validateController(controller: Controller, retired = false): void {
  if (!isRecord(controller)) fail("controller must be an object");
  validateAgentId(controller.id);
  if (controller.source !== "local") validateOrigin(controller.source);
  timestamp(controller.valid_from, "valid_from");
  if (controller.name !== undefined) validateNonEmpty(controller.name, "name");
  if (controller.delegation !== undefined && controller.delegation !== "*") {
    const policy = controller.delegation;
    if (!isRecord(policy) || Object.keys(policy).sort().join(",") !== "audiences,scopes") fail("invalid delegation policy");
    stringList(policy.scopes, "scopes");
    stringList(policy.audiences, "audiences");
    for (const origin of policy.audiences) validateOrigin(origin);
  }
  if (retired) {
    timestamp(controller.retired_at, "retired_at");
    if (controller.retired_at! < controller.valid_from) fail("retired_at precedes valid_from");
    if (controller.invalid_from !== undefined) {
      timestamp(controller.invalid_from, "invalid_from");
      if (controller.invalid_from < controller.valid_from || controller.invalid_from > controller.retired_at!) fail("invalid compromise interval");
    }
  } else if (controller.retired_at !== undefined || controller.invalid_from !== undefined) fail("current controller has retirement fields");
}

export function validatePrincipalDocument(document: PrincipalDocument): void {
  if (!isRecord(document)) fail("principal must be an object");
  validateHttpsUrl(document.id, "principal.id");
  if (document.protocol !== DELEGATION_PROTOCOL) fail("invalid principal protocol");
  timestamp(document.updated_at, "updated_at");
  if (!Array.isArray(document.controllers) || (document.retired_controllers !== undefined && !Array.isArray(document.retired_controllers))) fail("controllers must be arrays");
  const seen = new Set<string>();
  for (const [records, retired] of [[document.controllers, false], [document.retired_controllers ?? [], true]] as const) {
    for (const record of records) {
      validateController(record, retired);
      if (seen.has(record.id)) fail("duplicate controller key");
      seen.add(record.id);
      if (record.valid_from > document.updated_at || (record.retired_at !== undefined && record.retired_at > document.updated_at)) fail("controller timestamp exceeds document update");
    }
  }
  if (document.aliases !== undefined) {
    stringList(document.aliases, "aliases", true);
    for (const alias of document.aliases) validateHttpsUrl(alias, "alias");
  }
  if (document.avatar_url !== undefined) validateHttpsUrl(document.avatar_url, "avatar_url");
  if (document.delegation_query_url !== undefined) validateHttpsUrl(document.delegation_query_url, "delegation_query_url");
}

/**
 * Checks the authoritative-read rule of Agent Delegation Section 3: a
 * principal document binds controller keys only when it is read at its own
 * `id`. A document served anywhere else is a copy; its `controllers` MUST be
 * discarded and `document.id` resolved instead.
 */
export function validatePrincipalResolution(
  document: PrincipalDocument,
  resolvedUrl: string,
): void {
  if (document.id !== resolvedUrl) {
    throw protocolError(
      "invalid_principal",
      `principal document id ${document.id} was served at ${resolvedUrl}`,
    );
  }
}

/**
 * Reports whether `url` is an alias the principal itself acknowledges. Any
 * origin can redirect to any principal, so an alias MUST NOT be shown as a
 * name for the principal unless it is listed here.
 */
export function isPrincipalAlias(
  document: PrincipalDocument,
  url: string,
): boolean {
  return document.aliases?.includes(url) ?? false;
}

export function validateDelegationGrantPayload(
  payload: DelegationGrantPayload,
  createdAt?: number,
): void {
  if (!isRecord(payload)) fail("payload must be an object");
  validateDelegationId(payload.id);
  validatePrincipalDescriptor(payload.principal);
  validateAgentId(payload.subject);
  stringList(payload.scopes, "scopes");
  stringList(payload.audiences, "audiences");
  for (const origin of payload.audiences) validateOrigin(origin);
  if (createdAt !== undefined) timestamp(createdAt, "created_at");
  if (payload.not_before !== undefined) timestamp(payload.not_before, "not_before");
  if (payload.expires_at !== undefined) timestamp(payload.expires_at, "expires_at");
  if (payload.constraints !== undefined && !isRecord(payload.constraints)) {
    throw protocolError("invalid_delegation", "constraints must be an object");
  }
  if (payload.expires_at !== undefined) {
    if (
      payload.not_before !== undefined &&
      payload.expires_at <= payload.not_before
    ) {
      throw protocolError(
        "invalid_delegation",
        "expires_at must be greater than not_before",
      );
    }
    if (createdAt !== undefined && payload.expires_at <= createdAt) {
      throw protocolError(
        "invalid_delegation",
        "expires_at must be greater than created_at",
      );
    }
  }
}

/**
 * A public delegation query is an existence check and MUST include both
 * `subject` and `principal_id`. Omitting either side makes it an enumeration
 * query, which services MUST authorize before answering; pass
 * `allowEnumeration` when building such an authorized request. `limit`
 * defaults to 20; services SHOULD cap it at 100.
 */
export function validateDelegationQueryRequest(
  request: DelegationQueryRequest,
  options: { allowEnumeration?: boolean } = {},
): void {
  if (options.allowEnumeration) {
    if (request.subject === undefined && request.principal_id === undefined) {
      throw protocolError(
        "invalid_delegation",
        "query must include at least one of subject or principal_id",
      );
    }
  } else if (request.subject === undefined || request.principal_id === undefined) {
    throw protocolError(
      "invalid_delegation",
      "public query must include both subject and principal_id",
    );
  }
  if (request.id !== undefined) validateDelegationId(request.id);
  if (request.status !== undefined && !["active", "suspended", "expired", "revoked"].includes(request.status)) fail("invalid status");
  if (request.subject !== undefined) validateAgentId(request.subject);
  if (request.principal_id !== undefined) {
    validateHttpsUrl(request.principal_id, "principal_id");
  }
  if (
    request.limit !== undefined &&
    (!Number.isSafeInteger(request.limit) || request.limit < 1)
  ) {
    throw protocolError(
      "invalid_delegation",
      "limit must be a positive integer",
    );
  }
}

export function validateDelegationRevokePayload(
  payload: DelegationRevokePayload,
): void {
  if (!isRecord(payload)) fail("payload must be an object");
  validateDelegationId(payload.id);
  validateHttpsUrl(payload.principal_id, "principal_id");
}

export function validateDelegationId(value: unknown): asserts value is string {
  validateNonEmpty(value, "delegation id");
  if (value === "." || value === "..") fail("delegation id cannot be a dot segment");
}

export function validateDelegationEnvelope(
  envelope: Envelope<DelegationPayload>,
): void {
  verifyEnvelope(envelope);
  if (envelope.event.protocol !== DELEGATION_PROTOCOL) {
    throw protocolError(
      "invalid_event_protocol",
      `expected ${DELEGATION_PROTOCOL}, got ${envelope.event.protocol}`,
    );
  }
  if (envelope.event.type === DELEGATION_GRANT) {
    validateDelegationGrantPayload(
      envelope.event.payload as DelegationGrantPayload,
      envelope.event.created_at,
    );
  } else if (envelope.event.type === DELEGATION_REVOKE) {
    validateDelegationRevokePayload(
      envelope.event.payload as DelegationRevokePayload,
    );
  } else {
    throw protocolError(
      "invalid_event_type",
      `expected ${DELEGATION_GRANT} or ${DELEGATION_REVOKE}, got ${envelope.event.type}`,
    );
  }
}

/** Materializes an already accepted event. The caller supplies trusted previous state
 * and the service's actual acceptance time; this function does not authorize it. */
export function materializeDelegationCredential(
  envelope: Envelope<DelegationPayload>,
  options: { acceptedAt: number; previous?: DelegationCredential; status?: DelegationStatus; updatedAt?: number },
): DelegationCredential {
  validateDelegationEnvelope(envelope);
  timestamp(options.acceptedAt, "accepted_at");
  const event = envelope.event;
  const previous = options.previous;
  checkPrevious(event, previous);
  if (previous && options.acceptedAt < previous.accepted_at) fail("acceptance order reversed");
  const updatedAt = options.updatedAt ?? options.acceptedAt;
  timestamp(updatedAt, "updated_at");
  if (updatedAt < options.acceptedAt) fail("updated_at precedes acceptance");
  if (event.type === DELEGATION_REVOKE) {
    if (!previous) fail("revocation requires previous credential");
    return { ...structuredClone(previous!), controller: event.actor, status: "revoked", event_id: envelope.hash, accepted_at: options.acceptedAt, updated_at: updatedAt };
  }
  const payload = event.payload as DelegationGrantPayload;
  if (payload.expires_at !== undefined && payload.expires_at <= options.acceptedAt) fail("grant expired at acceptance");
  const status = options.status ?? "active";
  if (!["active", "suspended", "expired", "revoked"].includes(status)) fail("invalid status");
  return { ...structuredClone(payload), protocol: DELEGATION_PROTOCOL, controller: event.actor,
    owner_controller: previous?.owner_controller ?? event.actor, status, updated_at: updatedAt,
    event_id: envelope.hash, grant_event_id: envelope.hash, accepted_at: options.acceptedAt };
}

/** Pre-signing authority check. Input previous state and document must be trusted.
 * This does not verify signatures, fetch HTTPS, check cache age, or enforce nonce/time windows. */
export function validateDelegationEventAuthority(event: Event<DelegationPayload>, document: PrincipalDocument,
  acceptedAt: number, previous?: DelegationCredential): void {
  checkAuthority(event, document, acceptedAt, previous, false);
}

/** Online acceptance checks over a document read at resolvedUrl. Services must also
 * enforce fresh resolution, Identity live replay rules, and atomic persistence. */
export function validateDelegationAcceptance(envelope: Envelope<DelegationPayload>, document: PrincipalDocument,
  resolvedUrl: string, acceptedAt: number, previous?: DelegationCredential): void {
  validateDelegationEnvelope(envelope);
  validatePrincipalResolution(document, resolvedUrl);
  checkAuthority(envelope.event, document, acceptedAt, previous, false);
}

/** Uses caller-trusted acceptance evidence, never an event's self-reported time as proof.
 * Current status, evidence authenticity and application constraints are separate checks. */
export function validateHistoricalDelegation(envelope: Envelope<DelegationPayload>, acceptance: DelegationAcceptance,
  document: PrincipalDocument, resolvedUrl: string, previous?: DelegationCredential): void {
  validateDelegationEnvelope(envelope);
  if (acceptance.event_id !== envelope.hash) fail("acceptance hash mismatch");
  validatePrincipalResolution(document, resolvedUrl);
  checkAuthority(envelope.event, document, acceptance.accepted_at, previous, true);
}

/** Per-result enumeration check; the caller authenticates actor and resolves the document. */
export function validateControllerEnumeration(document: PrincipalDocument, actor: AgentId, now: number, owner: AgentId): void {
  validatePrincipalDocument(document); timestamp(now, "now"); validateAgentId(owner);
  const controller = document.controllers.find(c => c.id === actor);
  if (!controller || now < controller.valid_from || controller.delegation === undefined) fail("controller cannot enumerate");
  if (controller!.delegation !== "*" && owner !== actor) fail("controller does not own credential");
}

/** Checks audience/status/time only, after cryptographic and historical verification.
 * The application still authenticates the subject and enforces scopes and constraints. */
export function validateDelegationUse(credential: DelegationCredential, audience: string, now: number): void {
  validateOrigin(audience); timestamp(now, "now");
  validateDelegationGrantPayload(credential);
  if (credential.protocol !== DELEGATION_PROTOCOL || credential.status !== "active" ||
      !credential.audiences.includes(audience) || (credential.not_before !== undefined && now < credential.not_before) ||
      (credential.expires_at !== undefined && now >= credential.expires_at)) fail("delegation is not usable");
}

function checkPrevious(event: Event<DelegationPayload>, previous?: DelegationCredential): void {
  if (!previous) { if (event.type === DELEGATION_REVOKE) fail("revocation requires previous credential"); return; }
  validateAgentId(previous.owner_controller); timestamp(previous.accepted_at, "previous.accepted_at");
  const principal = event.type === DELEGATION_GRANT ? (event.payload as DelegationGrantPayload).principal.id : (event.payload as DelegationRevokePayload).principal_id;
  if (previous.id !== event.payload.id || previous.principal.id !== principal || previous.protocol !== DELEGATION_PROTOCOL) fail("previous credential identity mismatch");
}

function checkAuthority(event: Event<DelegationPayload>, document: PrincipalDocument, acceptedAt: number,
  previous: DelegationCredential | undefined, historical: boolean): void {
  validatePrincipalDocument(document); timestamp(acceptedAt, "accepted_at"); timestamp(event.created_at, "created_at"); validateAgentId(event.actor);
  if (event.protocol !== DELEGATION_PROTOCOL) fail("invalid event protocol");
  const grant = event.type === DELEGATION_GRANT;
  if (grant) validateDelegationGrantPayload(event.payload as DelegationGrantPayload, event.created_at);
  else if (event.type === DELEGATION_REVOKE) validateDelegationRevokePayload(event.payload as DelegationRevokePayload);
  else fail("invalid event type");
  const principal = grant ? (event.payload as DelegationGrantPayload).principal.id : (event.payload as DelegationRevokePayload).principal_id;
  if (principal !== document.id) fail("principal mismatch");
  const records = historical ? [...document.controllers, ...document.retired_controllers ?? []] : document.controllers;
  const controller = records.find(c => c.id === event.actor);
  if (!controller || controller.delegation === undefined) fail("actor has no delegation authority");
  const c = controller!;
  for (const time of [event.created_at, acceptedAt]) {
    if (time < c.valid_from || (c.retired_at !== undefined && time >= c.retired_at) || (c.invalid_from !== undefined && time >= c.invalid_from)) fail("outside controller authority interval");
  }
  checkPrevious(event, previous);
  if (previous && acceptedAt < previous.accepted_at) fail("acceptance order reversed");
  if (previous && c.delegation !== "*" && previous.owner_controller !== event.actor) fail("controller does not own credential");
  if (grant) {
    const payload = event.payload as DelegationGrantPayload;
    if (payload.expires_at !== undefined && payload.expires_at <= acceptedAt) fail("grant expired at acceptance");
    if (c.delegation !== "*") {
      const policy = c.delegation!;
      if (payload.scopes.some(x => !policy.scopes.includes(x)) || payload.audiences.some(x => !policy.audiences.includes(x))) fail("grant exceeds controller delegation policy");
    }
  }
}

function fail(message: string): never { throw protocolError("invalid_delegation", message); }
function timestamp(value: unknown, field: string): void {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) fail(`${field} must be a non-negative safe integer`);
}
function stringList(value: unknown, field: string, empty = false): asserts value is string[] {
  if (!Array.isArray(value) || (!empty && value.length === 0)) fail(`${field} must be a non-empty array`);
  for (const item of value) { validateNonEmpty(item, field); if (item === "*") fail(`${field} cannot contain wildcard`); }
  if (new Set(value).size !== value.length) fail(`${field} contains duplicates`);
}
function validateOrigin(value: unknown): void {
  validateHttpsUrl(value, "origin");
  const url = new URL(value as string);
  if (url.origin !== value) fail("origin must be a serialized HTTPS origin");
}

function validatePrincipalDescriptor(principal: PrincipalDescriptor): void {
  if (!isRecord(principal)) {
    throw protocolError("invalid_principal", "principal must be an object");
  }
  validateHttpsUrl(principal.id, "principal.id");
}

function validateHttpsUrl(value: unknown, field: string): void {
  if (typeof value !== "string") {
    throw protocolError("invalid_url", `${field} must be an HTTPS URL`);
  }
  try {
    const url = new URL(value);
    if (url.protocol !== "https:") throw new Error("not https");
  } catch {
    throw protocolError("invalid_url", `${field} must be an HTTPS URL`);
  }
}

function validateNonEmpty(value: unknown, field: string): void {
  if (typeof value !== "string" || value.trim() === "") {
    throw protocolError("invalid_delegation", `${field} must not be empty`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
