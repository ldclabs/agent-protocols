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

export interface ProfileUpdatePayload {
  agent_id: AgentId;
  name: string;
  description?: string;
  avatar_url?: string;
  provider?: string;
  capabilities?: string[];
  service_endpoints?: ServiceEndpoint[];
  links?: Record<string, string>;
  metadata?: Record<string, unknown>;
}

export interface AgentProfile extends ProfileUpdatePayload {
  updated_at: number;
  profile_event_id: string;
}

export interface ProfileReadResponse {
  profile: AgentProfile;
  profile_event?: Envelope<ProfileUpdatePayload>;
}

export interface ProfileServiceEndpoints {
  profiles: string;
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
  nonce: string,
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
  if (envelope.event.actor !== envelope.event.payload.agent_id) {
    throw protocolError(
      "invalid_actor",
      "profile update actor must match payload.agent_id",
    );
  }
}

export function materializeProfile(
  envelope: Envelope<ProfileUpdatePayload>,
): AgentProfile {
  validateProfileUpdate(envelope);
  const payload = envelope.event.payload;
  return {
    agent_id: payload.agent_id,
    name: payload.name,
    description: payload.description,
    avatar_url: payload.avatar_url,
    provider: payload.provider,
    capabilities: payload.capabilities ?? [],
    service_endpoints: payload.service_endpoints ?? [],
    links: payload.links ?? {},
    metadata: payload.metadata ?? {},
    updated_at: envelope.event.created_at,
    profile_event_id: envelope.event_id,
  };
}
