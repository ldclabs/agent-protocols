import { protocolError } from "./errors.js";
import {
  AgentId,
  Envelope,
  Event,
  ListResponse,
  createEvent,
  validateAgentId,
  validateEventFields,
  verifyEnvelope,
} from "./identity.js";
import { validateDelegationId, type PrincipalDescriptor } from "./delegation.js";

export const PROFILE_PROTOCOL = "agent-profile/1.0";
export const PROFILE_UPDATE = "profile.update";

export interface ServiceEndpoint {
  type: string;
  url: string;
  protocols?: string[];
}

/**
 * Defined link relationships. `rel` is an open vocabulary: clients accept other
 * non-empty values and may render them as generic links.
 */
export type ProfileLinkRel =
  | "homepage"
  | "documentation"
  | "source_code"
  | "social"
  | "browser"
  | (string & {});

export interface ProfileLink {
  name: string;
  url: string;
  rel: ProfileLinkRel;
}

/**
 * Discovery hint only. It carries no service URLs: the publishing agent is the
 * party whose claim is checked, so clients resolve the principal document at
 * `principal.id` and query the service it names.
 */
export interface ProfileDelegationHint {
  id?: string;
  principal: PrincipalDescriptor;
  relationship?: string;
  scopes?: string[];
}

export interface ProfileUpdatePayload {
  id: AgentId;
  name: string;
  description?: string;
  avatar_url?: string;
  provider?: string;
  capabilities?: string[];
  service_endpoints?: ServiceEndpoint[];
  links?: ProfileLink[];
  delegations?: ProfileDelegationHint[];
  extra?: Record<string, unknown>;
}

export interface AgentProfile {
  id: AgentId;
  name: string;
  description?: string;
  avatar_url?: string;
  provider?: string;
  capabilities?: string[];
  service_endpoints?: ServiceEndpoint[];
  links?: ProfileLink[];
  delegations?: ProfileDelegationHint[];
  extra?: Record<string, unknown>;
  updated_at: number;
  event_id: string;
}

export interface ProfileBatchReadRequest {
  ids: AgentId[];
}

/** Agent Identity list of profile documents; never carries `next_cursor`. */
export type ProfileBatchReadResponse = ListResponse<AgentProfile>;

/** Agent Identity list of accepted updates, newest first by `nonce`. */
export type ProfileEventsResponse = ListResponse<Envelope<ProfileUpdatePayload>>;

export interface ProfileServiceEndpoints {
  profiles: string;
  profile_batch?: string;
}

export interface ProfileServiceDiscovery {
  protocol: string;
  service: string;
  endpoints: ProfileServiceEndpoints;
  features?: string[];
}

export function profileUpdateEvent(
  actor: AgentId,
  createdAt: number,
  nonce: number,
  payload: ProfileUpdatePayload,
): Event<ProfileUpdatePayload> {
  return createEvent(
    PROFILE_PROTOCOL,
    PROFILE_UPDATE,
    actor,
    createdAt,
    nonce,
    payload,
  );
}

export function validateProfileUpdate(
  envelope: Envelope<ProfileUpdatePayload>,
): void {
  verifyEnvelope(envelope);
  // Profile events carry only the six Agent Identity event fields.
  validateEventFields(envelope.event);
  if (envelope.event.protocol !== PROFILE_PROTOCOL) {
    throw protocolError(
      "invalid_event_protocol",
      `expected ${PROFILE_PROTOCOL}, got ${envelope.event.protocol}`,
    );
  }
  if (envelope.event.type !== PROFILE_UPDATE) {
    throw protocolError(
      "invalid_event_type",
      `expected ${PROFILE_UPDATE}, got ${envelope.event.type}`,
    );
  }
  validateProfilePayload(envelope.event.payload, envelope.event.actor);
}

const PAYLOAD_FIELDS = [
  "id", "name", "description", "avatar_url", "provider", "capabilities",
  "service_endpoints", "links", "delegations", "extra",
];

/**
 * Section 4.1 rules for a closed `profile.update` payload: only defined
 * fields, `id` equal to the signing `actor`, and the field rules for names,
 * URLs, uniqueness, and delegation hints.
 */
export function validateProfilePayload(payload: unknown, actor: AgentId): asserts payload is ProfileUpdatePayload {
  if (!isRecord(payload)) invalid("payload must be an object");
  if (!payload.id || payload.id !== actor) {
    throw protocolError("invalid_actor", "profile update actor must match payload.id");
  }
  validateAgentId(payload.id as string);
  for (const key of Object.keys(payload)) {
    if (!PAYLOAD_FIELDS.includes(key)) invalid(`undefined profile field: ${key}`);
  }
  if (typeof payload.name !== "string" || payload.name === "") invalid("name must be a non-empty string");
  for (const field of ["description", "provider"]) {
    if (payload[field] !== undefined && typeof payload[field] !== "string") invalid(`${field} must be a string`);
  }
  if (payload.avatar_url !== undefined) requireUrl(payload.avatar_url, ["https:"], "avatar_url");
  if (payload.extra !== undefined && !isRecord(payload.extra)) invalid("extra must be an object");
  uniqueStrings(payload.capabilities, "capabilities");
  const endpoints = new Set<string>();
  for (const endpoint of list(payload.service_endpoints, "service_endpoints")) {
    closed(endpoint, ["type", "url", "protocols"], "service endpoint");
    if (typeof endpoint.type !== "string" || endpoint.type === "") invalid("service endpoint type must not be empty");
    requireUrl(endpoint.url, ["https:"], "service endpoint url");
    uniqueStrings(endpoint.protocols, "service endpoint protocols");
    const key = JSON.stringify([endpoint.type, endpoint.url]);
    if (endpoints.has(key)) invalid("service endpoints must be unique by type and url");
    endpoints.add(key);
  }
  const links = new Set<string>();
  for (const link of list(payload.links, "links")) {
    closed(link, ["name", "url", "rel"], "link");
    if (typeof link.name !== "string" || link.name === "" || typeof link.rel !== "string" || link.rel === "") {
      invalid("link name and rel must not be empty");
    }
    requireUrl(link.url, ["http:", "https:"], "link url");
    const key = JSON.stringify([link.url, link.rel]);
    if (links.has(key)) invalid("links must be unique by url and rel");
    links.add(key);
  }
  for (const hint of list(payload.delegations, "delegations")) {
    closed(hint, ["id", "principal", "relationship", "scopes"], "delegation hint");
    if (hint.id !== undefined) validateDelegationId(hint.id as string);
    if (!isRecord(hint.principal)) invalid("delegation hint requires a principal");
    requireUrl(hint.principal.id, ["https:"], "delegation principal id");
    if (hint.relationship !== undefined && typeof hint.relationship !== "string") invalid("relationship must be a string");
    uniqueStrings(hint.scopes, "delegation hint scopes");
  }
}

function invalid(message: string): never {
  throw protocolError("invalid_event", message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function list(value: unknown, field: string): Record<string, unknown>[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || !value.every(isRecord)) invalid(`${field} must be an array of objects`);
  return value as Record<string, unknown>[];
}

function closed(value: Record<string, unknown>, fields: readonly string[], name: string): void {
  for (const key of Object.keys(value)) {
    if (!fields.includes(key)) invalid(`undefined ${name} field: ${key}`);
  }
}

function requireUrl(value: unknown, protocols: readonly string[], field: string): void {
  let url: URL | undefined;
  try {
    url = typeof value === "string" ? new URL(value) : undefined;
  } catch {
    url = undefined;
  }
  if (!url || !protocols.includes(url.protocol) || url.hostname === "") {
    invalid(`${field} must be an ${protocols.map((p) => p.slice(0, -1)).join(" or ")} URL`);
  }
}

function uniqueStrings(value: unknown, field: string): void {
  if (value === undefined) return;
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || item === "")) {
    invalid(`${field} entries must be non-empty strings`);
  }
  if (new Set(value).size !== value.length) invalid(`${field} entries must be unique`);
}

export function materializeProfile(
  envelope: Envelope<ProfileUpdatePayload>,
): AgentProfile {
  validateProfileUpdate(envelope);
  const payload = envelope.event.payload;
  return {
    id: payload.id,
    name: payload.name,
    description: payload.description,
    avatar_url: payload.avatar_url,
    provider: payload.provider,
    capabilities: payload.capabilities ?? [],
    service_endpoints: payload.service_endpoints ?? [],
    links: payload.links ?? [],
    delegations: payload.delegations ?? [],
    extra: payload.extra ?? {},
    updated_at: envelope.event.created_at,
    event_id: envelope.hash,
  };
}

/**
 * Durable ordering check for a new update (Agent Profile Section 6): its nonce
 * must exceed the nonce of the latest accepted update for the same Agent ID,
 * independent of the replay cache. `latestNonce` is the stored latest nonce.
 */
export function validateProfileSuccession(
  envelope: Envelope<ProfileUpdatePayload>,
  latestNonce: number | undefined,
): void {
  if (latestNonce !== undefined && envelope.event.nonce <= latestNonce) {
    throw protocolError(
      "nonce_not_greater",
      `nonce must be greater than the latest accepted profile nonce ${latestNonce}`,
      { max_nonce: latestNonce },
    );
  }
}

/**
 * Selects the latest profile state from accepted update envelopes. Nonces are
 * strictly monotonic per Agent ID, so the latest profile is defined as the
 * accepted `profile.update` with the greatest `nonce` — deterministic and
 * independently checkable from event history alone.
 */
export function latestProfileUpdate(
  envelopes: readonly Envelope<ProfileUpdatePayload>[],
): Envelope<ProfileUpdatePayload> | undefined {
  let latest: Envelope<ProfileUpdatePayload> | undefined;
  for (const envelope of envelopes) {
    if (!latest || envelope.event.nonce > latest.event.nonce) {
      latest = envelope;
    }
  }
  return latest;
}
