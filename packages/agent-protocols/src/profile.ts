import { protocolError } from "./errors.js";
import {
  AgentId,
  Envelope,
  Event,
  createEvent,
  verifyEnvelope,
} from "./identity.js";
import type { PrincipalDescriptor } from "./delegation.js";

export const PROFILE_PROTOCOL = "agent-profile/1.0";
export const PROFILE_UPDATE = "profile.update";

export interface ServiceEndpoint {
  type: string;
  url: string;
  protocols?: string[];
}

export type ProfileLinkRel =
  | "homepage"
  | "documentation"
  | "source_code"
  | "social"
  | "browser";

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

export interface ProfileBatchReadResponse {
  result: AgentProfile[];
}

export interface ProfileEventsResponse {
  result: Envelope<ProfileUpdatePayload>[];
}

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
  if (
    !envelope.event.payload.id ||
    envelope.event.actor !== envelope.event.payload.id
  ) {
    throw protocolError(
      "invalid_actor",
      "profile update actor must match payload.id",
    );
  }
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
