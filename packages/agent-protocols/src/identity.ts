import canonicalize from "canonicalize";
import { createHash } from "node:crypto";
import nacl from "tweetnacl";

import { protocolError } from "./errors.js";

export const AGENT_ID_PREFIX = "did:agent:";
export const DEFAULT_LIVE_WRITE_WINDOW_MS = 300_000;
/**
 * Nonce cache validity (Agent Identity Section 6.2): at least twice the
 * live-write window, because an envelope signed up to one window ahead of the
 * receiver's clock stays inside the window for two windows after acceptance.
 */
export const DEFAULT_NONCE_TTL_MS = 2 * DEFAULT_LIVE_WRITE_WINDOW_MS;
export const DEFAULT_REQUEST_JWT_TTL_SECS = 300;
export const MAX_NONCE_HEADER = "Max-Seen-Nonce";
export const MAX_SAFE_NONCE = Number.MAX_SAFE_INTEGER;
/**
 * Largest jump a single `Max-Seen-Nonce` header may cause beyond
 * `max(nextNonce, now)` (Agent Identity Section 6.2). The nonce sequence is
 * shared by every service an agent uses, so one hostile service must not be
 * able to exhaust it.
 */
export const MAX_NONCE_JUMP = 2 ** 32;

/** The six Agent Identity event fields; protocols add their own on top. */
export const IDENTITY_EVENT_FIELDS: readonly string[] = [
  "protocol",
  "type",
  "actor",
  "created_at",
  "nonce",
  "payload",
];

/** Error codes shared by every Agent Protocols service (Section 8.1). */
export const SHARED_ERROR_CODES: readonly string[] = [
  "invalid_request",
  "invalid_event",
  "invalid_event_hash",
  "invalid_signature",
  "invalid_actor",
  "timestamp_out_of_window",
  "nonce_not_greater",
  "invalid_token",
  "permission_denied",
  "not_found",
  "rate_limited",
  "payload_too_large",
];

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

/** Error response body shared by every Agent Protocols service (Section 8.1). */
export interface ErrorResponse {
  error: {
    code: string;
    message: string;
    data?: Record<string, unknown>;
  };
}

/** List response shape (Section 8.2). `next_cursor` is present exactly when more items follow. */
export interface ListResponse<T> {
  result: T[];
  next_cursor?: string;
}

/** An accepted envelope with the service's acceptance time (Section 8.3). */
export interface AcceptedRecord<P = unknown> {
  envelope: Envelope<P>;
  accepted_at: number;
}

/** Discovery document skeleton served at `/.well-known/{protocol-name}` (Section 8.4). */
export interface DiscoveryDocument {
  protocol: string;
  service: string;
  endpoints?: Record<string, string>;
  features?: string[];
  [key: string]: unknown;
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

export interface SubmissionOptions extends LiveWriteOptions {
  /** Reports whether an envelope with this hash is in durable accepted history. */
  isAccepted?: (hash: string) => boolean;
}

/**
 * Outcome of {@link verifySubmission}: an exact resubmission of an accepted
 * envelope, or a new live write with the nonce now recorded.
 */
export type SubmissionResult =
  | { kind: "resubmission" }
  | { kind: "accepted"; maxNonce: number };

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

  /**
   * Signs an Agent Delegation controller registration challenge (Section 4.3)
   * over its exact UTF-8 bytes. Any other string is refused, so the signer
   * never becomes an arbitrary-message signing oracle.
   */
  signControllerChallenge(challenge: string): string {
    validateControllerChallenge(challenge);
    const signature = nacl.sign.detached(
      new TextEncoder().encode(challenge),
      this.keyPair.secretKey,
    );
    return base64UrlEncode(signature);
  }
}

/** Prefix of an Agent Delegation controller registration challenge (Section 4.3). */
export const CONTROLLER_CHALLENGE_PREFIX = "agent-delegation/1.0:controller-registration:";
const CONTROLLER_CHALLENGE_PATTERN =
  /^agent-delegation\/1\.0:controller-registration:[A-Za-z0-9_-]{43}$/;

/** The prefix followed by 43 opaque base64url characters, 88 in all. */
export function isControllerChallenge(value: string): boolean {
  return CONTROLLER_CHALLENGE_PATTERN.test(value);
}

function validateControllerChallenge(value: string): void {
  if (typeof value !== "string" || !isControllerChallenge(value)) {
    throw protocolError(
      "invalid_request",
      "not an agent-delegation/1.0 controller registration challenge",
    );
  }
}

/**
 * Verifies a controller registration proof (Agent Delegation Section 4.3):
 * `signature` over the challenge's exact UTF-8 bytes under the strict rules of
 * Section 3.1. Throws on failure. Matching the challenge to what the provider
 * issued, and its expiry, remain the provider's checks.
 */
export function verifyControllerChallenge(
  agentId: AgentId,
  challenge: string,
  signature: string,
): void {
  validateControllerChallenge(challenge);
  if (
    !verifyEd25519Strict(
      new TextEncoder().encode(challenge),
      base64UrlDecode(signature),
      publicKeyBytes(agentId),
    )
  ) {
    throw protocolError("invalid_signature", "signature verification failed");
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

/**
 * Client-side nonce sequence for one Agent ID (Agent Identity Section 6.2).
 * Pass the event's `created_at` to derive clock-based nonces,
 * `max(last + 1, created_at)`, which stay monotonic across restarts, restores,
 * and devices sharing a key; without it the manager is a plain counter.
 */
export class ClientNonceManager {
  constructor(private nextNonceValue = 1) {
    validateNonce(nextNonceValue);
  }

  peek(): number {
    return this.nextNonceValue;
  }

  nextNonce(createdAt?: number): number {
    const nonce =
      createdAt !== undefined && createdAt > this.nextNonceValue
        ? createdAt
        : this.nextNonceValue;
    validateNonce(nonce);
    this.nextNonceValue = nonce + 1;
    return nonce;
  }

  /**
   * Applies a `Max-Seen-Nonce` header. A value more than {@link MAX_NONCE_JUMP}
   * beyond `max(nextNonce, nowMs)` is rejected rather than applied.
   */
  observeMaxNonce(
    maxNonce: number | string | null | undefined,
    nowMs: number = unixTimeMillis(),
  ): void {
    if (maxNonce === null || maxNonce === undefined || maxNonce === "") return;
    const parsed = typeof maxNonce === "string" ? Number(maxNonce) : maxNonce;
    validateNonce(parsed);
    if (parsed > Math.max(this.nextNonceValue, nowMs) + MAX_NONCE_JUMP) {
      throw protocolError(
        "invalid_nonce",
        `Max-Seen-Nonce ${parsed} jumps too far beyond the local sequence`,
      );
    }
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

/**
 * Enforces the closed event object (Section 5.1): the event may carry only the
 * six Agent Identity fields plus `extraFields` the protocol defines.
 */
export function validateEventFields(
  event: Event<unknown>,
  extraFields: readonly string[] = [],
): void {
  if (typeof event !== "object" || event === null || Array.isArray(event)) {
    throw protocolError("invalid_event", "event must be an object");
  }
  for (const field of IDENTITY_EVENT_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(event, field)) {
      throw protocolError("invalid_event", `event requires ${field}`);
    }
  }
  for (const key of Object.keys(event)) {
    if (!IDENTITY_EVENT_FIELDS.includes(key) && !extraFields.includes(key)) {
      throw protocolError("invalid_event", `unknown event field: ${key}`);
    }
  }
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
  if (!verifyEd25519Strict(validEventHashBytes(eventHash), signature, publicKey)) {
    throw protocolError("invalid_signature", "signature verification failed");
  }
}

// p = 2^255 - 19 and L = 2^252 + 27742317777372353535851937790883648493.
const FIELD_P = (1n << 255n) - 19n;
const GROUP_L = (1n << 252n) + 27742317777372353535851937790883648493n;
/** y-coordinates (sign bit cleared) of every small-order point (Appendix B). */
const SMALL_ORDER_Y: readonly bigint[] = [
  0n,
  1n,
  FIELD_P - 1n,
  littleEndian(Buffer.from("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "hex")),
  littleEndian(Buffer.from("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "hex")),
];

function littleEndian(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) value = (value << 8n) | BigInt(bytes[i]);
  return value;
}

function pointY(encoding: Uint8Array): bigint {
  const bytes = new Uint8Array(encoding);
  bytes[31] &= 0x7f;
  return littleEndian(bytes);
}

/** Canonical encoding (y < p) of a point that is not of small order. */
function isStrictPoint(encoding: Uint8Array): boolean {
  const y = pointY(encoding);
  return y < FIELD_P && !SMALL_ORDER_Y.includes(y);
}

/**
 * Ed25519 verification under the deterministic rules of Agent Identity
 * Section 3.1: canonical, non-small-order `A` and `R`, reduced `S`, and the
 * cofactorless equation (which tweetnacl implements by recomputing `R`).
 */
export function verifyEd25519Strict(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  if (signature.byteLength !== 64 || publicKey.byteLength !== 32) return false;
  if (!isStrictPoint(publicKey) || !isStrictPoint(signature.subarray(0, 32))) {
    return false;
  }
  if (littleEndian(signature.subarray(32)) >= GROUP_L) return false;
  return nacl.sign.detached.verify(message, signature, publicKey);
}

export function verifyEnvelope(envelope: Envelope<unknown>): void {
  verifyEventHash(envelope);
  verifySignature(envelope);
}

/**
 * Parses signed JSON strictly (Agent Identity Section 4.1): rejects duplicate
 * member names, unpaired surrogates, and integers outside the safe range. Use
 * it on raw request bodies before hashing, because `JSON.parse` silently keeps
 * the last of two duplicate names.
 */
export function parseStrictJson(text: string): unknown {
  return new StrictJsonParser(text).parseDocument();
}

/** {@link parseStrictJson} for a signed envelope, checking its outer shape. */
export function parseEnvelopeJson<P = unknown>(text: string): Envelope<P> {
  const value = parseStrictJson(text);
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    typeof (value as Envelope).hash !== "string" ||
    typeof (value as Envelope).signature !== "string" ||
    typeof (value as Envelope).event !== "object" ||
    (value as Envelope).event === null
  ) {
    throw protocolError("invalid_event", "envelope must contain hash, event, and signature");
  }
  for (const key of Object.keys(value)) {
    if (key !== "hash" && key !== "event" && key !== "signature") {
      throw protocolError("invalid_event", `unknown envelope field: ${key}`);
    }
  }
  return value as Envelope<P>;
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      i += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

class StrictJsonParser {
  private index = 0;

  constructor(private readonly text: string) {}

  parseDocument(): unknown {
    this.skipWhitespace();
    const value = this.parseValue(0);
    this.skipWhitespace();
    if (this.index !== this.text.length) this.fail("trailing characters");
    return value;
  }

  private fail(message: string): never {
    throw protocolError("invalid_event", `invalid JSON at ${this.index}: ${message}`);
  }

  private skipWhitespace(): void {
    while (this.index < this.text.length && " \t\n\r".includes(this.text[this.index])) {
      this.index += 1;
    }
  }

  private parseValue(depth: number): unknown {
    if (depth > 256) this.fail("nesting too deep");
    const ch = this.text[this.index];
    if (ch === "{") return this.parseObject(depth);
    if (ch === "[") return this.parseArray(depth);
    if (ch === '"') return this.parseString();
    if (ch === "-" || (ch >= "0" && ch <= "9")) return this.parseNumber();
    for (const [literal, value] of [["true", true], ["false", false], ["null", null]] as const) {
      if (this.text.startsWith(literal, this.index)) {
        this.index += literal.length;
        return value;
      }
    }
    return this.fail("unexpected token");
  }

  private parseObject(depth: number): Record<string, unknown> {
    const result: Record<string, unknown> = Object.create(null);
    const seen = new Set<string>();
    this.index += 1;
    this.skipWhitespace();
    if (this.text[this.index] === "}") {
      this.index += 1;
      return { ...result };
    }
    for (;;) {
      this.skipWhitespace();
      if (this.text[this.index] !== '"') this.fail("expected member name");
      const key = this.parseString();
      if (seen.has(key)) this.fail(`duplicate member name ${JSON.stringify(key)}`);
      seen.add(key);
      this.skipWhitespace();
      if (this.text[this.index] !== ":") this.fail("expected ':'");
      this.index += 1;
      this.skipWhitespace();
      result[key] = this.parseValue(depth + 1);
      this.skipWhitespace();
      const next = this.text[this.index];
      this.index += 1;
      if (next === "}") break;
      if (next !== ",") this.fail("expected ',' or '}'");
    }
    // Define own data properties, including __proto__, without invoking setters.
    return { ...result };
  }

  private parseArray(depth: number): unknown[] {
    const result: unknown[] = [];
    this.index += 1;
    this.skipWhitespace();
    if (this.text[this.index] === "]") {
      this.index += 1;
      return result;
    }
    for (;;) {
      this.skipWhitespace();
      result.push(this.parseValue(depth + 1));
      this.skipWhitespace();
      const next = this.text[this.index];
      this.index += 1;
      if (next === "]") break;
      if (next !== ",") this.fail("expected ',' or ']'");
    }
    return result;
  }

  private parseString(): string {
    const start = this.index;
    this.index += 1;
    for (;;) {
      const ch = this.text[this.index];
      if (ch === undefined) this.fail("unterminated string");
      if (ch === '"') break;
      if (ch === "\\") {
        this.index += 2;
        continue;
      }
      if (ch.charCodeAt(0) < 0x20) this.fail("control character in string");
      this.index += 1;
    }
    this.index += 1;
    let value: string;
    try {
      value = JSON.parse(this.text.slice(start, this.index)) as string;
    } catch {
      return this.fail("invalid string escape");
    }
    if (hasUnpairedSurrogate(value)) this.fail("unpaired surrogate in string");
    return value;
  }

  private parseNumber(): number {
    const match = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(
      this.text.slice(this.index),
    );
    if (!match) this.fail("invalid number");
    this.index += match[0].length;
    const value = Number(match[0]);
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      this.fail("integer outside the safe range");
    }
    if (!Number.isFinite(value)) this.fail("number out of range");
    return value;
  }
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

/**
 * Agent Identity Section 6.1 for one submission: verifies the envelope, answers
 * an exact resubmission of an accepted envelope before the time window and
 * nonce checks (Section 6.3), and otherwise enforces both.
 */
export function verifySubmission(
  envelope: Envelope<unknown>,
  nonceStore: NonceStore,
  options: SubmissionOptions = {},
): SubmissionResult {
  verifyEnvelope(envelope);
  if (options.isAccepted?.(envelope.hash)) return { kind: "resubmission" };
  const nowMs = options.nowMs ?? unixTimeMillis();
  verifyTimestamp(
    envelope.event.created_at,
    nowMs,
    options.windowMs ?? DEFAULT_LIVE_WRITE_WINDOW_MS,
  );
  const maxNonce = nonceStore.checkAndUpdate(
    envelope.event.actor,
    envelope.event.nonce,
    nowMs,
    options.nonceTtlMs ?? DEFAULT_NONCE_TTL_MS,
  );
  return { kind: "accepted", maxNonce };
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
 * Checks that `value` is a serialized HTTPS origin (Agent Identity Section
 * 4.4): WHATWG URL parsing and origin serialization must reproduce it exactly.
 */
export function validateOrigin(value: unknown): asserts value is string {
  let parsed: URL | undefined;
  if (typeof value === "string") {
    try {
      parsed = new URL(value);
    } catch {
      parsed = undefined;
    }
  }
  if (!parsed || parsed.protocol !== "https:" || parsed.origin !== value) {
    throw protocolError("invalid_url", `origin must be a serialized HTTPS origin: ${String(value)}`);
  }
}

/**
 * Derives the request JWT `aud` from a request URL: the service origin —
 * scheme, host, and non-default port, with no path (Agent Identity Section 7).
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
    !verifyEd25519Strict(
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
