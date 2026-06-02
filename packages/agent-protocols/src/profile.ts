import { protocolError } from "./errors.js";
import {
  AgentId,
  Envelope,
  Event,
  createEvent,
  verifyEnvelope,
} from "./identity.js";

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

export interface ProfileUpdatePayload {
  id?: AgentId;
  agent_id?: AgentId;
  name: string;
  description?: string;
  avatar_url?: string;
  provider?: string;
  capabilities?: string[];
  service_endpoints?: ServiceEndpoint[];
  links?: ProfileLink[];
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
  const payloadId =
    envelope.event.payload.id ?? envelope.event.payload.agent_id;
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
  if (!payloadId || envelope.event.actor !== payloadId) {
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
  const payloadId = payload.id ?? payload.agent_id;
  return {
    id: payloadId as AgentId,
    name: payload.name,
    description: payload.description,
    avatar_url: payload.avatar_url,
    provider: payload.provider,
    capabilities: payload.capabilities ?? [],
    service_endpoints: payload.service_endpoints ?? [],
    links: payload.links ?? [],
    extra: payload.extra ?? {},
    updated_at: envelope.event.created_at,
    event_id: envelope.hash,
  };
}
