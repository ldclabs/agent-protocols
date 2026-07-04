import canonicalize from "canonicalize";
import { createHash } from "node:crypto";
import nacl from "tweetnacl";

import { protocolError } from "./errors.js";

export const AGENT_ID_PREFIX = "did:agent:";
export const DEFAULT_LIVE_WRITE_WINDOW_MS = 300_000;
export const DEFAULT_NONCE_TTL_MS = 300_000;
export const DEFAULT_REQUEST_JWT_TTL_SECS = 300;
export const MAX_NONCE_HEADER = "Max-Seen-Nonce";
export const MAX_SAFE_NONCE = Number.MAX_SAFE_INTEGER;

export type AgentId = string;

export interface Event<P = unknown> {
  protocol: string;
  type: string;
  actor: AgentId;
  created_at: number;
  nonce: number;
  room_id?: string;
  base_seq?: number;
  base_hash?: string;
  mentions?: AgentId[];
  payload: P;
  [key: string]: unknown;
}

export interface Envelope<P = unknown> {
  hash: string;
  event: Event<P>;
  signature: string;
}

export interface NonceRecord {
  maxNonce: number;
  expiresAt: number;
}

export interface NonceStore {
  checkAndUpdate(
    actor: AgentId,
    nonce: number,
    nowMs: number,
    ttlMs: number,
  ): number;
  maxNonce(actor: AgentId, nowMs: number): number | undefined;
}

export interface LiveWriteOptions {
  nowMs?: number;
  windowMs?: number;
  nonceTtlMs?: number;
}

export interface RequestJwtHeader {
  alg: "EdDSA";
  typ: "JWT";
  kid: AgentId;
}

export interface RequestBinding {
  /** The origin of the receiving service, e.g. `https://api.example.com`. */
  audience: string;
}

export interface RequestJwtClaims {
  iss: AgentId;
  sub: AgentId;
  /**
   * Origin of the receiving service: scheme, host, and non-default port with
   * no path. All Agent Protocols endpoints on one origin share this value.
   */
  aud: string;
  iat: number;
  exp: number;
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
    const hashBytes = eventHashBytes(event);
    return {
      hash: base64UrlEncode(hashBytes),
      event,
      signature: signEventHash(this.keyPair.secretKey, hashBytes),
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
  private readonly records = new Map<AgentId, NonceRecord>();

  checkAndUpdate(
    actor: AgentId,
    nonce: number,
    nowMs: number,
    ttlMs: number,
  ): number {
    validateNonce(nonce);
    if (ttlMs < 0) {
      throw protocolError(
        "invalid_nonce",
        "nonce cache ttl must be non-negative",
      );
    }
    const record = this.records.get(actor);
    if (record && record.expiresAt > nowMs && nonce <= record.maxNonce) {
      // Services rejecting for this reason MUST return the effective maximum
      // in the `Max-Seen-Nonce` response header; `data.max_nonce` carries it.
      throw protocolError(
        "nonce_not_greater",
        `nonce must be greater than accepted max nonce ${record.maxNonce}`,
        { max_nonce: record.maxNonce },
      );
    }
    this.records.set(actor, { maxNonce: nonce, expiresAt: nowMs + ttlMs });
    return nonce;
  }

  maxNonce(actor: AgentId, nowMs: number): number | undefined {
    const record = this.records.get(actor);
    return record && record.expiresAt > nowMs ? record.maxNonce : undefined;
  }
}

export class ClientNonceManager {
  constructor(private nextNonceValue = 1) {
    validateNonce(nextNonceValue);
  }

  peek(): number {
    return this.nextNonceValue;
  }

  nextNonce(): number {
    const nonce = this.nextNonceValue;
    validateNonce(nonce);
    this.nextNonceValue = nonce + 1;
    return nonce;
  }

  observeMaxNonce(maxNonce: number | string | null | undefined): void {
    if (maxNonce === null || maxNonce === undefined || maxNonce === "") return;
    const parsed = typeof maxNonce === "string" ? Number(maxNonce) : maxNonce;
    validateNonce(parsed);
    if (parsed >= this.nextNonceValue) {
      this.nextNonceValue = parsed + 1;
    }
  }
}

export function createEvent<P>(
  protocol: string,
  type: string,
  actor: AgentId,
  createdAt: number,
  nonce: number,
  payload: P,
): Event<P> {
  validateAgentId(actor);
  validateNonce(nonce);
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

export function withRoomHead<P>(
  event: Event<P>,
  baseSeq: number,
  baseHash: string,
): Event<P> {
  validateNonce(baseSeq);
  if (baseHash.trim() === "") {
    throw protocolError("invalid_event", "base_hash must not be empty");
  }
  return {
    ...event,
    base_seq: baseSeq,
    base_hash: baseHash,
  };
}

export function withMentions<P>(
  event: Event<P>,
  mentions: AgentId[],
): Event<P> {
  for (const mention of mentions) validateAgentId(mention);
  return {
    ...event,
    mentions: [...mentions],
  };
}

export function withMention<P>(event: Event<P>, agentId: AgentId): Event<P> {
  validateAgentId(agentId);
  return {
    ...event,
    mentions: [...(event.mentions ?? []), agentId],
  };
}

export function agentIdFromPublicKey(publicKey: Uint8Array): AgentId {
  if (publicKey.byteLength !== 32) {
    throw protocolError(
      "invalid_public_key",
      `public key must be 32 bytes, got ${publicKey.byteLength}`,
    );
  }
  return `${AGENT_ID_PREFIX}${base64UrlEncode(publicKey)}`;
}

export function publicKeyBytes(agentId: AgentId): Uint8Array {
  if (typeof agentId !== "string") {
    throw protocolError("invalid_agent_id", "agent id must be a string");
  }
  const encoded = agentId.startsWith(AGENT_ID_PREFIX)
    ? agentId.slice(AGENT_ID_PREFIX.length)
    : undefined;
  if (!encoded) {
    throw protocolError(
      "invalid_agent_id",
      "agent id must start with did:agent:",
    );
  }
  const bytes = base64UrlDecode(encoded);
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

export function eventHash(event: Event<unknown>): string {
  return base64UrlEncode(eventHashBytes(event));
}

export function eventHashBytes(event: Event<unknown>): Uint8Array {
  validateNonce(event.nonce);
  return new Uint8Array(
    createHash("sha3-256")
      .update(canonicalEventBytes(event))
      .digest(),
  );
}

export function signEvent(
  secretKey: Uint8Array,
  event: Event<unknown>,
): string {
  return signEventHash(secretKey, eventHashBytes(event));
}

/**
 * Signs a precomputed 32-byte event hash. Signing a digest supplied by
 * another component without seeing the event it commits to (blind signing) is
 * NOT RECOMMENDED: `actor` and all event content are inside the digest, so a
 * blind signer can be tricked into signing arbitrary events attributed to its
 * key. Prefer `signEvent`, which canonicalizes and hashes the event itself.
 */
export function signEventHash(
  secretKey: Uint8Array,
  eventHash: Uint8Array,
): string {
  if (secretKey.byteLength !== 64) {
    throw protocolError(
      "invalid_private_key",
      `secret key must be 64 bytes, got ${secretKey.byteLength}`,
    );
  }
  return base64UrlEncode(
    nacl.sign.detached(validEventHashBytes(eventHash), secretKey),
  );
}

export function verifyEventHash(envelope: Envelope<unknown>): void {
  const expected = eventHash(envelope.event);
  if (expected !== envelope.hash) {
    throw protocolError(
      "invalid_event_hash",
      `invalid event hash: expected ${expected}, got ${envelope.hash}`,
    );
  }
}

export function verifySignature(envelope: Envelope<unknown>): void {
  verifyEventHashSignature(
    publicKeyBytes(envelope.event.actor),
    eventHashBytes(envelope.event),
    envelope.signature,
  );
}

export function verifyEventHashSignature(
  publicKey: Uint8Array,
  eventHash: Uint8Array,
  encodedSignature: string,
): void {
  if (publicKey.byteLength !== 32) {
    throw protocolError(
      "invalid_public_key",
      `public key must be 32 bytes, got ${publicKey.byteLength}`,
    );
  }
  const signature = base64UrlDecode(encodedSignature);
  if (signature.byteLength !== 64) {
    throw protocolError(
      "invalid_signature",
      `signature must be 64 bytes, got ${signature.byteLength}`,
    );
  }
  const ok = nacl.sign.detached.verify(
    validEventHashBytes(eventHash),
    signature,
    publicKey,
  );
  if (!ok) {
    throw protocolError("invalid_signature", "signature verification failed");
  }
}

export function verifyEnvelope(envelope: Envelope<unknown>): void {
  verifyEventHash(envelope);
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

export function verifyLiveEnvelope(
  envelope: Envelope<unknown>,
  nonceStore: NonceStore,
  options: LiveWriteOptions = {},
): number {
  const nowMs = options.nowMs ?? unixTimeMillis();
  verifyEnvelope(envelope);
  verifyTimestamp(
    envelope.event.created_at,
    nowMs,
    options.windowMs ?? DEFAULT_LIVE_WRITE_WINDOW_MS,
  );
  return nonceStore.checkAndUpdate(
    envelope.event.actor,
    envelope.event.nonce,
    nowMs,
    options.nonceTtlMs ?? DEFAULT_NONCE_TTL_MS,
  );
}

export function createRequestBinding(audience: string): RequestBinding {
  return {
    audience,
  };
}

/**
 * Derives the request JWT `aud` from a request URL: the service origin —
 * scheme, host, and non-default port, with no path (Agent Identity Section 8).
 */
export function serviceOrigin(url: string): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw protocolError("invalid_url", `not a valid URL: ${url}`);
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw protocolError("invalid_url", `not an HTTP(S) URL: ${url}`);
  }
  return parsed.origin;
}

export function createRequestJwtClaims(
  agentId: AgentId,
  binding: RequestBinding,
  issuedAt: number,
  ttlSecs: number,
): RequestJwtClaims {
  return {
    iss: agentId,
    sub: agentId,
    aud: binding.audience,
    iat: issuedAt,
    exp: issuedAt + ttlSecs,
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
  if (claims.exp <= claims.iat) {
    throw protocolError("invalid_jwt_claim", "exp must be greater than iat");
  }
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

export function unixTimeMillis(): number {
  return Date.now();
}

export function unixTimeSecs(): number {
  return Math.floor(Date.now() / 1000);
}

export function validateNonce(nonce: number): void {
  if (!Number.isSafeInteger(nonce) || nonce < 1 || nonce > MAX_SAFE_NONCE) {
    throw protocolError(
      "invalid_nonce",
      "nonce must be a positive safe integer",
    );
  }
}

function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/**
 * Canonical base64url decoding: URL-safe alphabet, no padding, zero trailing
 * bits. Receivers MUST reject non-canonical encodings, otherwise one value
 * gains multiple distinct string forms and corrupts string-keyed comparisons.
 */
function base64UrlDecode(value: string): Uint8Array {
  const bytes = new Uint8Array(Buffer.from(value, "base64url"));
  if (Buffer.from(bytes).toString("base64url") !== value) {
    throw protocolError(
      "invalid_encoding",
      "expected canonical base64url without padding",
    );
  }
  return bytes;
}

function validEventHashBytes(eventHash: Uint8Array): Uint8Array {
  if (eventHash.byteLength !== 32) {
    throw protocolError(
      "invalid_event_hash",
      `event hash must be 32 bytes, got ${eventHash.byteLength}`,
    );
  }
  return eventHash;
}
