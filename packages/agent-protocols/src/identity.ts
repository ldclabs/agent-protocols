import canonicalize from "canonicalize";
import bs58 from "bs58";
import { createHash, randomBytes } from "node:crypto";
import nacl from "tweetnacl";

import { protocolError } from "./errors.js";

export const AGENT_ID_PREFIX = "did:agent:";
export const EVENT_ID_PREFIX = "evt_";
export const DEFAULT_LIVE_WRITE_WINDOW_MS = 300_000;
export const DEFAULT_REQUEST_JWT_TTL_SECS = 300;
const REQUEST_AUTH_REPLAY_SCOPE = "agent-identity/request-auth";

export type AgentId = string;

export interface Event<P = unknown> {
  protocol: string;
  type: string;
  actor: AgentId;
  created_at: number;
  nonce: string;
  room_id?: string;
  payload: P;
  [key: string]: unknown;
}

export interface Envelope<P = unknown> {
  event_id: string;
  event: Event<P>;
  signature: string;
}

export type NonceScopeKind = "actor_protocol" | "actor_room";

export interface NonceScope {
  actor: AgentId;
  protocol: string;
  room_id?: string;
  nonce: string;
}

export interface NonceStore {
  checkAndInsert(scope: NonceScope): void;
}

export interface LiveWriteOptions {
  nowMs?: number;
  windowMs?: number;
  nonceScope?: NonceScopeKind;
}

export interface RequestJwtHeader {
  alg: "EdDSA";
  typ: "JWT";
  kid: AgentId;
}

export interface RequestBinding {
  audience: string;
}

export interface RequestJwtClaims {
  iss: AgentId;
  sub: AgentId;
  aud: string;
  iat: number;
  exp: number;
  jti: string;
}

export interface RequestAuthContext extends RequestBinding {
  nowSecs?: number;
  maxTtlSecs?: number;
}

export class AgentSigner {
  private constructor(private readonly keyPair: nacl.SignKeyPair) {}

  static generate(): AgentSigner {
    return new AgentSigner(nacl.sign.keyPair());
  }

  static fromSeed(seed: Uint8Array): AgentSigner {
    if (seed.byteLength !== 32) {
      throw protocolError(
        "invalid_private_key",
        `seed must be 32 bytes, got ${seed.byteLength}`,
      );
    }
    return new AgentSigner(nacl.sign.keyPair.fromSeed(seed));
  }

  agentId(): AgentId {
    return agentIdFromPublicKey(this.keyPair.publicKey);
  }

  publicKey(): Uint8Array {
    return new Uint8Array(this.keyPair.publicKey);
  }

  signEvent<P>(event: Event<P>): Envelope<P> {
    return {
      event_id: eventId(event),
      event,
      signature: signEvent(this.keyPair.secretKey, event),
    };
  }

  signRequestJwt(claims: RequestJwtClaims): string {
    const agentId = this.agentId();
    if (claims.iss !== agentId || claims.sub !== agentId) {
      throw protocolError(
        "invalid_jwt_claim",
        "iss and sub must match the signing agent id",
      );
    }

    const header: RequestJwtHeader = { alg: "EdDSA", typ: "JWT", kid: agentId };
    const encodedHeader = base64UrlEncode(
      new TextEncoder().encode(JSON.stringify(header)),
    );
    const encodedPayload = base64UrlEncode(
      new TextEncoder().encode(JSON.stringify(claims)),
    );
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const signature = nacl.sign.detached(
      new TextEncoder().encode(signingInput),
      this.keyPair.secretKey,
    );
    return `${signingInput}.${base64UrlEncode(signature)}`;
  }
}

export class MemoryNonceStore implements NonceStore {
  private readonly seen = new Set<string>();

  checkAndInsert(scope: NonceScope): void {
    const key = JSON.stringify([
      scope.actor,
      scope.protocol,
      scope.room_id ?? null,
      scope.nonce,
    ]);
    if (this.seen.has(key)) {
      throw protocolError(
        "nonce_reused",
        "nonce was already used in this replay scope",
      );
    }
    this.seen.add(key);
  }
}

export function createEvent<P>(
  protocol: string,
  type: string,
  actor: AgentId,
  createdAt: number,
  nonce: string,
  payload: P,
): Event<P> {
  validateAgentId(actor);
  return {
    protocol,
    type,
    actor,
    created_at: createdAt,
    nonce,
    payload,
  };
}

export function withRoomId<P>(event: Event<P>, roomId: string): Event<P> {
  return {
    ...event,
    room_id: roomId,
  };
}

export function agentIdFromPublicKey(publicKey: Uint8Array): AgentId {
  if (publicKey.byteLength !== 32) {
    throw protocolError(
      "invalid_public_key",
      `public key must be 32 bytes, got ${publicKey.byteLength}`,
    );
  }
  return `${AGENT_ID_PREFIX}${base58BtcEncode(publicKey)}`;
}

export function publicKeyBytes(agentId: AgentId): Uint8Array {
  const encoded = agentId.startsWith(AGENT_ID_PREFIX)
    ? agentId.slice(AGENT_ID_PREFIX.length)
    : undefined;
  if (!encoded) {
    throw protocolError(
      "invalid_agent_id",
      "agent id must start with did:agent:",
    );
  }
  const bytes = base58BtcDecode(encoded);
  if (bytes.byteLength !== 32) {
    throw protocolError(
      "invalid_public_key",
      `agent id public key must be 32 bytes, got ${bytes.byteLength}`,
    );
  }
  return bytes;
}

export function validateAgentId(agentId: AgentId): AgentId {
  publicKeyBytes(agentId);
  return agentId;
}

export function canonicalEventBytes(event: Event<unknown>): Uint8Array {
  const canonical = canonicalize(event);
  if (canonical === undefined) {
    throw protocolError(
      "canonical_json",
      "event cannot be represented as canonical JSON",
    );
  }
  return new TextEncoder().encode(canonical);
}

export function eventId(event: Event<unknown>): string {
  const digest = createHash("sha256")
    .update(canonicalEventBytes(event))
    .digest();
  return `${EVENT_ID_PREFIX}${base58BtcEncode(digest)}`;
}

export function signEvent(
  secretKey: Uint8Array,
  event: Event<unknown>,
): string {
  if (secretKey.byteLength !== 64) {
    throw protocolError(
      "invalid_private_key",
      `secret key must be 64 bytes, got ${secretKey.byteLength}`,
    );
  }
  return base64UrlEncode(
    nacl.sign.detached(canonicalEventBytes(event), secretKey),
  );
}

export function verifyEventId(envelope: Envelope<unknown>): void {
  const expected = eventId(envelope.event);
  if (expected !== envelope.event_id) {
    throw protocolError(
      "invalid_event_id",
      `invalid event id: expected ${expected}, got ${envelope.event_id}`,
    );
  }
}

export function verifySignature(envelope: Envelope<unknown>): void {
  const signature = base64UrlDecode(envelope.signature);
  if (signature.byteLength !== 64) {
    throw protocolError(
      "invalid_signature",
      `signature must be 64 bytes, got ${signature.byteLength}`,
    );
  }
  const ok = nacl.sign.detached.verify(
    canonicalEventBytes(envelope.event),
    signature,
    publicKeyBytes(envelope.event.actor),
  );
  if (!ok) {
    throw protocolError("invalid_signature", "signature verification failed");
  }
}

export function verifyEnvelope(envelope: Envelope<unknown>): void {
  verifyEventId(envelope);
  verifySignature(envelope);
}

export function verifyTimestamp(
  createdAt: number,
  nowMs: number,
  windowMs: number,
): void {
  if (windowMs < 0 || Math.abs(createdAt - nowMs) > windowMs) {
    throw protocolError(
      "timestamp_out_of_window",
      "timestamp is outside the allowed live-write window",
    );
  }
}

export function nonceScopeForEvent(
  event: Event<unknown>,
  kind: NonceScopeKind = "actor_protocol",
): NonceScope {
  return {
    actor: event.actor,
    protocol: event.protocol,
    room_id: kind === "actor_room" ? event.room_id : undefined,
    nonce: event.nonce,
  };
}

export function verifyLiveEnvelope(
  envelope: Envelope<unknown>,
  nonceStore: NonceStore,
  options: LiveWriteOptions = {},
): void {
  verifyEnvelope(envelope);
  verifyTimestamp(
    envelope.event.created_at,
    options.nowMs ?? unixTimeMillis(),
    options.windowMs ?? DEFAULT_LIVE_WRITE_WINDOW_MS,
  );
  nonceStore.checkAndInsert(
    nonceScopeForEvent(envelope.event, options.nonceScope),
  );
}

export function createRequestBinding(audience: string): RequestBinding {
  return {
    audience,
  };
}

export function createRequestJwtClaims(
  agentId: AgentId,
  binding: RequestBinding,
  issuedAt: number,
  ttlSecs: number,
  jti: string,
): RequestJwtClaims {
  return {
    iss: agentId,
    sub: agentId,
    aud: binding.audience,
    iat: issuedAt,
    exp: issuedAt + ttlSecs,
    jti,
  };
}

export function verifyRequestJwt(
  token: string,
  context: RequestAuthContext,
): RequestJwtClaims {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw protocolError("invalid_jwt", "expected three compact JWS parts");
  }

  const header = JSON.parse(
    new TextDecoder().decode(base64UrlDecode(parts[0])),
  ) as RequestJwtHeader;
  const claims = JSON.parse(
    new TextDecoder().decode(base64UrlDecode(parts[1])),
  ) as RequestJwtClaims;
  const signature = base64UrlDecode(parts[2]);
  const signingInput = `${parts[0]}.${parts[1]}`;

  if (header.alg !== "EdDSA") {
    throw protocolError("invalid_jwt_claim", "alg must be EdDSA");
  }
  if (header.typ !== "JWT") {
    throw protocolError("invalid_jwt_claim", "typ must be JWT");
  }
  if (header.kid !== claims.iss || claims.iss !== claims.sub) {
    throw protocolError(
      "invalid_jwt_claim",
      "kid, iss, and sub must identify the same Agent ID",
    );
  }
  if (
    !nacl.sign.detached.verify(
      new TextEncoder().encode(signingInput),
      signature,
      publicKeyBytes(header.kid),
    )
  ) {
    throw protocolError(
      "invalid_signature",
      "JWT signature verification failed",
    );
  }

  if (claims.aud !== context.audience)
    throw protocolError("invalid_jwt_claim", "aud mismatch");

  const nowSecs = context.nowSecs ?? unixTimeSecs();
  const maxTtlSecs = context.maxTtlSecs ?? DEFAULT_REQUEST_JWT_TTL_SECS;
  if (claims.iat > nowSecs || claims.exp < nowSecs) {
    throw protocolError(
      "invalid_jwt_claim",
      "iat/exp outside valid time window",
    );
  }
  if (claims.exp - claims.iat > maxTtlSecs) {
    throw protocolError("invalid_jwt_claim", "JWT ttl exceeds maximum");
  }

  return claims;
}

export function verifyRequestJwtLive(
  token: string,
  context: RequestAuthContext,
  nonceStore: NonceStore,
): RequestJwtClaims {
  const claims = verifyRequestJwt(token, context);
  nonceStore.checkAndInsert({
    actor: claims.iss,
    protocol: REQUEST_AUTH_REPLAY_SCOPE,
    nonce: claims.jti,
  });
  return claims;
}

export function unixTimeMillis(): number {
  return Date.now();
}

export function unixTimeSecs(): number {
  return Math.floor(Date.now() / 1000);
}

export function randomNonce(prefix = "n_"): string {
  return `${prefix}${base64UrlEncode(randomBytes(16))}`;
}

function base58BtcEncode(bytes: Uint8Array): string {
  return `z${bs58.encode(bytes)}`;
}

function base58BtcDecode(value: string): Uint8Array {
  if (!value.startsWith("z")) {
    throw protocolError(
      "invalid_encoding",
      "expected base58btc multibase value",
    );
  }
  return bs58.decode(value.slice(1));
}

function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function base64UrlDecode(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64url"));
}
