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

export interface PrincipalDocument extends PrincipalDescriptor {
  description?: string;
  avatar_url?: string;
  links?: PrincipalLink[];
  controllers: AgentId[];
  delegations_url?: string;
  updated_at?: number;
  extra?: Record<string, unknown>;
}

export interface DelegationGrantPayload {
  id: string;
  principal: PrincipalDescriptor;
  subject: AgentId;
  relationship?: string;
  scopes: string[];
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
  subject: AgentId;
  relationship?: string;
  scopes: string[];
  constraints?: Record<string, unknown>;
  not_before?: number;
  expires_at?: number;
  status: DelegationStatus;
  status_url?: string;
  updated_at: number;
  event_id: string;
}

export interface DelegationStatusDocument {
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
  status?: DelegationStatus;
  limit?: number;
}

export interface DelegationSummary {
  id: string;
  subject: AgentId;
  principal: PrincipalDescriptor;
  scopes?: string[];
  status: DelegationStatus;
  status_url?: string;
}

export interface DelegationQueryResponse {
  result: DelegationSummary[];
}

export interface DelegationEventsResponse {
  result: Envelope<DelegationPayload>[];
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

export function validatePrincipalDocument(document: PrincipalDocument): void {
  validateHttpsUrl(document.id, "principal.id");
  if (!Array.isArray(document.controllers) || document.controllers.length === 0) {
    throw protocolError(
      "invalid_principal",
      "principal document controllers must be non-empty",
    );
  }
  for (const controller of document.controllers) validateAgentId(controller);
  if (document.delegations_url !== undefined) {
    validateHttpsUrl(document.delegations_url, "delegations_url");
  }
}

export function validateDelegationGrantPayload(
  payload: DelegationGrantPayload,
  createdAt?: number,
): void {
  validateNonEmpty(payload.id, "payload.id");
  validatePrincipalDescriptor(payload.principal);
  validateAgentId(payload.subject);
  if (!Array.isArray(payload.scopes) || payload.scopes.length === 0) {
    throw protocolError("invalid_delegation", "delegation scopes must be non-empty");
  }
  for (const scope of payload.scopes) validateNonEmpty(scope, "scope");
  if (payload.constraints !== undefined && !isRecord(payload.constraints)) {
    throw protocolError("invalid_delegation", "constraints must be an object");
  }
  if (payload.expires_at !== undefined) {
    const notBefore = payload.not_before ?? createdAt;
    if (notBefore !== undefined && payload.expires_at <= notBefore) {
      throw protocolError(
        "invalid_delegation",
        "expires_at must be greater than not_before or created_at",
      );
    }
  }
}

export function validateDelegationRevokePayload(
  payload: DelegationRevokePayload,
): void {
  validateNonEmpty(payload.id, "payload.id");
  validateHttpsUrl(payload.principal_id, "principal_id");
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

export function materializeDelegationCredential(
  envelope: Envelope<DelegationGrantPayload>,
  options: {
    status?: DelegationStatus;
    statusUrl?: string;
    updatedAt?: number;
  } = {},
): DelegationCredential {
  validateDelegationEnvelope(envelope as Envelope<DelegationPayload>);
  if (envelope.event.type !== DELEGATION_GRANT) {
    throw protocolError(
      "invalid_event_type",
      "delegation credential materialization requires a grant event",
    );
  }
  const payload = envelope.event.payload;
  return {
    id: payload.id,
    protocol: DELEGATION_PROTOCOL,
    principal: payload.principal,
    controller: envelope.event.actor,
    subject: payload.subject,
    relationship: payload.relationship,
    scopes: payload.scopes,
    constraints: payload.constraints,
    not_before: payload.not_before,
    expires_at: payload.expires_at,
    status: options.status ?? "active",
    status_url: options.statusUrl,
    updated_at: options.updatedAt ?? envelope.event.created_at,
    event_id: envelope.hash,
  };
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
