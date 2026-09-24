import canonicalize from "canonicalize";

import { protocolError } from "./errors.js";
import {
  AGENT_ID_PREFIX,
  AcceptedRecord,
  AgentId,
  Envelope,
  Event,
  ListResponse,
  createEvent,
  validateAgentId,
  validateEventFields,
  validateOrigin,
  verifyEnvelope,
} from "./identity.js";

export const DELEGATION_PROTOCOL = "agent-delegation/1.0";
export const DELEGATION_GRANT = "delegation.grant";
export const DELEGATION_REVOKE = "delegation.revoke";

/** Delegation IDs are unreserved URL characters: no percent-encoding, no look-alikes. */
export const DELEGATION_ID_PATTERN = /^[A-Za-z0-9._~-]{1,128}$/;

/** Delegation-specific error codes (Agent Delegation Section 9.7). */
export const DELEGATION_ERROR_CODES: readonly string[] = [
  "principal_unresolvable",
  "principal_not_canonical",
  "controller_not_current",
  "delegation_not_permitted",
  "delegation_ceiling_exceeded",
  "not_owner_controller",
  "credential_not_found",
  "credential_identity_mismatch",
  "grant_expired",
];

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

/** Display descriptor of a principal, used by Agent Profile delegation hints. */
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
  /** Earlier controllers of this principal whose credentials this key may manage. */
  supersedes?: AgentId[];
  retired_at?: number;
  invalid_from?: number;
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
  /** Delegation query endpoint; required when any controller carries `delegation`. */
  delegation_query_url?: string;
  updated_at: number;
  extra?: Record<string, unknown>;
}

export interface DelegationGrantPayload {
  id: string;
  principal_id: string;
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
  principal_id: string;
  subject: AgentId;
  relationship?: string;
  scopes: string[];
  audiences: string[];
  constraints?: Record<string, unknown>;
  not_before?: number;
  expires_at?: number;
  status: DelegationStatus;
  controller: AgentId;
  owner_controller: AgentId;
  grant_event_id: string;
  event_id: string;
  accepted_at: number;
  checked_at: number;
}

export type DelegationRecord = AcceptedRecord<DelegationPayload>;

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
  cursor?: string;
}

/** Agent Identity list of full credentials. */
export type DelegationQueryResponse = ListResponse<DelegationCredential>;

/** Agent Identity list of accepted records in service acceptance order. */
export type DelegationEventsResponse = ListResponse<DelegationRecord>;

/** Result of {@link verifyDelegationCredential}. */
export interface DelegationVerdict {
  credential: DelegationCredential;
  /** Latest-grant signature, controller, ceiling, and consistency checks passed. */
  verified: boolean;
  /** Verified, and usable for the audience now: active, in its window, audience listed. */
  usable: boolean;
  /** Every failed check. */
  reasons: string[];
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
    for (const audience of policy.audiences) validateAudience(audience);
  }
  if (controller.supersedes !== undefined) {
    stringList(controller.supersedes, "supersedes");
    for (const id of controller.supersedes) validateAgentId(id);
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
  const records = new Map<string, Controller>();
  let delegates = false;
  for (const [list, retired] of [[document.controllers, false], [document.retired_controllers ?? [], true]] as const) {
    for (const record of list) {
      validateController(record, retired);
      if (records.has(record.id)) fail("duplicate controller key");
      records.set(record.id, record);
      if (record.delegation !== undefined) delegates = true;
      if (record.valid_from > document.updated_at || (record.retired_at !== undefined && record.retired_at > document.updated_at)) fail("controller timestamp exceeds document update");
    }
  }
  // Succession (Section 5.1): each entry names another, earlier record.
  for (const record of records.values()) {
    for (const id of record.supersedes ?? []) {
      const predecessor = records.get(id);
      if (!predecessor || id === record.id || predecessor.valid_from >= record.valid_from) fail("invalid supersedes entry");
    }
  }
  if (document.aliases !== undefined) {
    stringList(document.aliases, "aliases", true);
    for (const alias of document.aliases) validateHttpsUrl(alias, "alias");
  }
  if (document.avatar_url !== undefined) validateHttpsUrl(document.avatar_url, "avatar_url");
  if (document.delegation_query_url !== undefined) validateHttpsUrl(document.delegation_query_url, "delegation_query_url");
  else if (delegates) fail("delegation_query_url is required when a controller carries delegation");
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

/**
 * The lineage of a controller (Section 5.1): its own ID plus, transitively,
 * every record it supersedes. A restricted controller owns a credential whose
 * `owner_controller` is in its lineage.
 */
export function controllerLineage(document: PrincipalDocument, controllerId: AgentId): Set<AgentId> {
  const records = new Map<string, Controller>();
  for (const record of [...document.controllers, ...document.retired_controllers ?? []]) records.set(record.id, record);
  const lineage = new Set<AgentId>();
  const pending = [controllerId];
  while (pending.length > 0) {
    const id = pending.pop()!;
    if (lineage.has(id)) continue;
    lineage.add(id);
    pending.push(...(records.get(id)?.supersedes ?? []));
  }
  return lineage;
}

export function validateDelegationGrantPayload(
  payload: DelegationGrantPayload,
  createdAt?: number,
): void {
  if (!isRecord(payload)) fail("payload must be an object");
  validateDelegationId(payload.id);
  validateHttpsUrl(payload.principal_id, "principal_id");
  validateAgentId(payload.subject);
  stringList(payload.scopes, "scopes");
  stringList(payload.audiences, "audiences");
  for (const audience of payload.audiences) validateAudience(audience);
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
        "grant_expired",
        "expires_at must be greater than not_before",
      );
    }
    if (createdAt !== undefined && payload.expires_at <= createdAt) {
      throw protocolError(
        "grant_expired",
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
        "invalid_request",
        "query must include at least one of subject or principal_id",
      );
    }
  } else if (request.subject === undefined || request.principal_id === undefined) {
    throw protocolError(
      "invalid_request",
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
      "invalid_request",
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
  if (typeof value !== "string" || !DELEGATION_ID_PATTERN.test(value) || value === "." || value === "..") {
    fail("delegation id must match [A-Za-z0-9._~-]{1,128} and not be a dot segment");
  }
}

export function validateDelegationEnvelope(
  envelope: Envelope<DelegationPayload>,
): void {
  verifyEnvelope(envelope);
  // Delegation events carry only the six Agent Identity event fields.
  validateEventFields(envelope.event);
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
  options: { acceptedAt: number; previous?: DelegationCredential; status?: DelegationStatus; checkedAt?: number },
): DelegationCredential {
  validateDelegationEnvelope(envelope);
  timestamp(options.acceptedAt, "accepted_at");
  const event = envelope.event;
  const previous = options.previous;
  checkPrevious(event, previous);
  if (previous && options.acceptedAt < previous.accepted_at) fail("acceptance order reversed");
  const checkedAt = options.checkedAt ?? options.acceptedAt;
  timestamp(checkedAt, "checked_at");
  if (checkedAt < options.acceptedAt) fail("checked_at precedes acceptance");
  if (event.type === DELEGATION_REVOKE) {
    if (!previous) fail("revocation requires previous credential");
    return { ...structuredClone(previous!), controller: event.actor, status: "revoked", event_id: envelope.hash, accepted_at: options.acceptedAt, checked_at: checkedAt };
  }
  const payload = event.payload as DelegationGrantPayload;
  if (payload.expires_at !== undefined && payload.expires_at <= options.acceptedAt) {
    throw protocolError("grant_expired", "grant expired at acceptance");
  }
  const status = options.status ?? "active";
  if (!["active", "suspended", "expired", "revoked"].includes(status)) fail("invalid status");
  return { ...structuredClone(payload), protocol: DELEGATION_PROTOCOL, controller: event.actor,
    owner_controller: previous?.owner_controller ?? event.actor, status,
    event_id: envelope.hash, grant_event_id: envelope.hash, accepted_at: options.acceptedAt, checked_at: checkedAt };
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
export function validateHistoricalDelegation(record: DelegationRecord,
  document: PrincipalDocument, resolvedUrl: string, previous?: DelegationCredential): void {
  validateDelegationEnvelope(record.envelope);
  validatePrincipalResolution(document, resolvedUrl);
  checkAuthority(record.envelope.event, document, record.accepted_at, previous, true);
}

/** Per-result enumeration check; the caller authenticates actor and resolves the document. */
export function validateControllerEnumeration(document: PrincipalDocument, actor: AgentId, now: number, owner: AgentId): void {
  validatePrincipalDocument(document); timestamp(now, "now"); validateAgentId(owner);
  const controller = document.controllers.find(c => c.id === actor);
  if (!controller || now < controller.valid_from) throw protocolError("controller_not_current", "controller cannot enumerate");
  if (controller.delegation === undefined) throw protocolError("delegation_not_permitted", "controller cannot enumerate");
  if (controller.delegation !== "*" && !controllerLineage(document, actor).has(owner)) {
    throw protocolError("not_owner_controller", "controller does not own credential");
  }
}

/** Checks audience/status/time only, after cryptographic and historical verification.
 * The application still authenticates the subject and enforces scopes and constraints. */
export function validateDelegationUse(credential: DelegationCredential, audience: string, now: number): void {
  validateAudience(audience); timestamp(now, "now");
  validateDelegationGrantPayload(credential);
  if (credential.protocol !== DELEGATION_PROTOCOL || credential.status !== "active" ||
      !credential.audiences.includes(audience) || (credential.not_before !== undefined && now < credential.not_before) ||
      (credential.expires_at !== undefined && now >= credential.expires_at)) fail("delegation is not usable");
}

/** Grant fields a credential carries from its latest grant. */
const GRANT_FIELDS = [
  "id", "principal_id", "subject", "relationship", "scopes", "audiences",
  "constraints", "not_before", "expires_at",
] as const;

/**
 * Verifies a credential under Agent Delegation Section 8 with the online
 * service-trusting evidence policy: checks the accepted record of its latest
 * grant — signature, Controller binding, ceiling, and authority interval —
 * confirms that the grant matches the credential, and then checks use for
 * `audience` at `now`. Ownership and `supersedes` lineage govern management,
 * which the service enforced at acceptance; auditors replay them with
 * {@link auditDelegationHistory}. Relying parties still enforce scopes and
 * constraints and authenticate the subject.
 */
export function verifyDelegationCredential(
  credential: DelegationCredential,
  records: readonly DelegationRecord[],
  document: PrincipalDocument,
  resolvedUrl: string,
  audience: string,
  now: number,
): DelegationVerdict {
  const reasons: string[] = [];
  try {
    const record = records.find((candidate) => candidate.envelope.hash === credential.grant_event_id);
    if (!record) fail("latest grant record is missing");
    validateHistoricalDelegation(record!, document, resolvedUrl);
    if (record!.envelope.event.type !== DELEGATION_GRANT) fail("grant_event_id does not name a grant");
    const grant = record!.envelope.event.payload as DelegationGrantPayload;
    if (credential.protocol !== DELEGATION_PROTOCOL ||
        GRANT_FIELDS.some((field) => canonicalize(grant[field]) !== canonicalize(credential[field]))) {
      fail("credential does not match its latest grant");
    }
    if (credential.event_id === credential.grant_event_id) {
      if (credential.accepted_at !== record!.accepted_at || credential.controller !== record!.envelope.event.actor ||
          credential.status === "revoked") {
        fail("credential does not match its latest grant");
      }
    } else if (credential.status !== "revoked") {
      fail("a credential last changed by a revocation must be revoked");
    }
  } catch (error) {
    reasons.push(error instanceof Error ? error.message : String(error));
  }
  const verified = reasons.length === 0;
  if (credential.status !== "active") reasons.push(`status is ${credential.status}`);
  if (!credential.audiences?.includes(audience)) reasons.push(`audience ${audience} is not granted`);
  if (credential.not_before !== undefined && now < credential.not_before) reasons.push("not yet valid");
  if (credential.expires_at !== undefined && now >= credential.expires_at) reasons.push("expired");
  return { credential, verified, usable: reasons.length === 0, reasons };
}

/**
 * Auditor check (Section 8): replays every accepted record of a credential
 * against the authoritative principal document — signatures, controller
 * intervals, ceilings, and ownership lineage — and confirms that the replay
 * matches the credential. Relying parties use {@link verifyDelegationCredential}.
 */
export function auditDelegationHistory(
  credential: DelegationCredential,
  records: readonly DelegationRecord[],
  document: PrincipalDocument,
  resolvedUrl: string,
): void {
  if (records.length === 0) fail("no accepted records");
  let replayed: DelegationCredential | undefined;
  for (const record of records) {
    validateHistoricalDelegation(record, document, resolvedUrl, replayed);
    replayed = materializeDelegationCredential(record.envelope, { acceptedAt: record.accepted_at, previous: replayed });
  }
  const r = replayed!;
  // Only status and the service's check time may differ from event replay.
  const fields = [
    ...GRANT_FIELDS, "protocol", "event_id", "grant_event_id", "owner_controller", "controller", "accepted_at",
  ] as const;
  if (fields.some((field) => canonicalize(r[field]) !== canonicalize(credential[field])) ||
      (r.status === "revoked") !== (credential.status === "revoked")) {
    fail("credential does not match its accepted records");
  }
}

/** A relying-party audience (Section 5): an origin for a relying application, or an Agent ID for a relying agent. */
export function validateAudience(value: unknown): void {
  if (typeof value === "string" && value.startsWith(AGENT_ID_PREFIX)) {
    validateAgentId(value);
    return;
  }
  validateOrigin(value);
}

function eventIdentity(event: Event<DelegationPayload>): { id: string; principalId: string } {
  const payload = event.payload as DelegationGrantPayload | DelegationRevokePayload;
  return { id: payload.id, principalId: payload.principal_id };
}

function checkPrevious(event: Event<DelegationPayload>, previous?: DelegationCredential): void {
  if (!previous) {
    if (event.type === DELEGATION_REVOKE) throw protocolError("credential_not_found", "revocation requires previous credential");
    return;
  }
  validateAgentId(previous.owner_controller); timestamp(previous.accepted_at, "previous.accepted_at");
  const { id, principalId } = eventIdentity(event);
  const sameSubject = event.type !== DELEGATION_GRANT || (event.payload as DelegationGrantPayload).subject === previous.subject;
  if (previous.id !== id || previous.principal_id !== principalId || previous.protocol !== DELEGATION_PROTOCOL || !sameSubject) {
    throw protocolError("credential_identity_mismatch", "credential principal, subject, and protocol are immutable");
  }
}

function checkAuthority(event: Event<DelegationPayload>, document: PrincipalDocument, acceptedAt: number,
  previous: DelegationCredential | undefined, historical: boolean): void {
  validatePrincipalDocument(document); timestamp(acceptedAt, "accepted_at"); timestamp(event.created_at, "created_at"); validateAgentId(event.actor);
  if (event.protocol !== DELEGATION_PROTOCOL) fail("invalid event protocol");
  const grant = event.type === DELEGATION_GRANT;
  if (grant) validateDelegationGrantPayload(event.payload as DelegationGrantPayload, event.created_at);
  else if (event.type === DELEGATION_REVOKE) validateDelegationRevokePayload(event.payload as DelegationRevokePayload);
  else fail("invalid event type");
  if (eventIdentity(event).principalId !== document.id) throw protocolError("principal_not_canonical", "principal mismatch");
  const records = historical ? [...document.controllers, ...document.retired_controllers ?? []] : document.controllers;
  const controller = records.find(c => c.id === event.actor);
  if (!controller) throw protocolError("controller_not_current", "actor is not a controller of the principal");
  if (controller.delegation === undefined) throw protocolError("delegation_not_permitted", "actor has no delegation authority");
  for (const time of [event.created_at, acceptedAt]) {
    if (time < controller.valid_from || (controller.retired_at !== undefined && time >= controller.retired_at) || (controller.invalid_from !== undefined && time >= controller.invalid_from)) {
      throw protocolError("controller_not_current", "outside controller authority interval");
    }
  }
  checkPrevious(event, previous);
  if (previous && acceptedAt < previous.accepted_at) fail("acceptance order reversed");
  if (previous && controller.delegation !== "*" && !controllerLineage(document, event.actor).has(previous.owner_controller)) {
    throw protocolError("not_owner_controller", "controller does not own credential");
  }
  if (grant) {
    const payload = event.payload as DelegationGrantPayload;
    if (payload.expires_at !== undefined && payload.expires_at <= acceptedAt) throw protocolError("grant_expired", "grant expired at acceptance");
    if (controller.delegation !== "*") {
      const policy = controller.delegation;
      if (payload.scopes.some(x => !policy.scopes.includes(x)) || payload.audiences.some(x => !policy.audiences.includes(x))) {
        throw protocolError("delegation_ceiling_exceeded", "grant exceeds controller delegation policy");
      }
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
