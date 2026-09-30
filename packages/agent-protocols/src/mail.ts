/** Agent Mail 1.0. State helpers are process-local; persist snapshots before acknowledging delivery. */
import { CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { sha3_256 } from "@noble/hashes/sha3.js";
import { Validator, type Schema } from "@cfworker/json-schema";
import canonicalize from "canonicalize";
import nacl from "tweetnacl";
import { base64UrlDecodeCanonical, base64UrlEncode } from "./encoding.js";
import { protocolError } from "./errors.js";
import {
  MemoryNonceStore,
  createEvent,
  parseStrictJson,
  validateAgentId,
  validateOrigin,
  verifyEnvelope,
  verifyRequestJwt,
  verifyTimestamp,
  type NonceStore,
  type Event,
  type Envelope,
  type AcceptedRecord,
  type ListResponse,
  type RequestJwtClaims,
} from "./identity.js";
import { MAIL_SCHEMA } from "./mail-schema.js";
export { MAIL_SCHEMA } from "./mail-schema.js";

export const MAIL_PROTOCOL = "agent-mail/1.0";
export const MAIL_MAX_TTL_MS = 30 * 86400000;
export const MAIL_FUTURE_SKEW_MS = 300000;
export const MAIL_MAX_PACKET_BYTES = 1048576;
export interface MailboxCardPayload {
  mailbox_id: string;
  expires_at: number;
  receive_until: number;
  public_key: string;
  routes: string[];
  max_packet_bytes: number;
}
export type MailboxCard = Envelope<MailboxCardPayload>;
export interface MailPart {
  media_type: string;
  data: string;
  name?: string;
}
export interface MailMessagePayload {
  to: string;
  expires_at: number;
  thread_id: string;
  parts: MailPart[];
  subject?: string;
  in_reply_to?: string;
  reply_card?: MailboxCard;
}
export type MailLetter = Envelope<MailMessagePayload>;
export interface MailPacketHeader {
  protocol: typeof MAIL_PROTOCOL;
  mailbox_id: string;
  card_hash: string;
  expires_at: number;
}
export interface MailPacket {
  header: MailPacketHeader;
  enc: string;
  ciphertext: string;
}
export interface MailDeliveryResult {
  packet_id: string;
  accepted_at: number;
}
export interface MailPacketRecord extends MailDeliveryResult {
  packet: MailPacket;
  seq: number;
}
export interface MailDiscovery {
  protocol: typeof MAIL_PROTOCOL;
  service: string;
  features?: string[];
  [key: string]: unknown;
}
export type MailCardRecord = AcceptedRecord<MailboxCardPayload>;
export type MailPacketList = ListResponse<MailPacketRecord> & {
  [key: string]: unknown;
};
const encoder = new TextEncoder();
const INFO = encoder.encode(MAIL_PROTOCOL);
const clone = <T>(v: T): T => structuredClone(v);
const validators = new Map<string, Validator>();
const LONE_SURROGATE =
  /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
function requireMail(ok: unknown, code: string, message = code): asserts ok {
  if (!ok) throw protocolError(code, message);
}
function safeTime(now: number): void {
  requireMail(
    Number.isSafeInteger(now) && now >= 0,
    "invalid_request",
    "clock must be nonnegative safe milliseconds",
  );
}
function strictString(value: string): void {
  requireMail(!LONE_SURROGATE.test(value), "invalid_event", "lone surrogate");
}
function jsonValue(value: unknown, seen = new Set<object>()): void {
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "string") return strictString(value);
  if (typeof value === "number") {
    requireMail(
      Number.isFinite(value) &&
        (!Number.isInteger(value) || Number.isSafeInteger(value)),
      "invalid_event",
      "invalid JSON number",
    );
    return;
  }
  requireMail(typeof value === "object", "invalid_event", "non-JSON value");
  requireMail(!seen.has(value), "invalid_event", "cyclic JSON");
  requireMail(
    Array.isArray(value) ||
      Object.getPrototypeOf(value) === Object.prototype ||
      Object.getPrototypeOf(value) === null,
    "invalid_event",
    "expected plain JSON object",
  );
  seen.add(value);
  if (Array.isArray(value)) for (const child of value) jsonValue(child, seen);
  else
    for (const [key, child] of Object.entries(value)) {
      strictString(key);
      requireMail(child !== undefined, "invalid_event", "undefined member");
      jsonValue(child, seen);
    }
  seen.delete(value);
}
/** Canonical, strict I-JSON bytes. This never silently drops undefined members. */
export function mailCanonicalBytes(value: unknown): Uint8Array {
  jsonValue(value);
  return encoder.encode(canonicalize(value)!);
}
export function validateMailSchema(
  value: unknown,
  definition = "envelope",
): void {
  jsonValue(value);
  let validator = validators.get(definition);
  if (!validator) {
    requireMail(
      Object.hasOwn(MAIL_SCHEMA.$defs, definition),
      "invalid_request",
      "unknown Mail schema definition",
    );
    validator = new Validator(
      {
        $ref: `#/$defs/${definition}`,
        $defs: MAIL_SCHEMA.$defs,
      } as unknown as Schema,
      "2020-12",
    );
    validators.set(definition, validator);
  }
  requireMail(
    validator.validate(value).valid,
    "invalid_event",
    `${definition} schema violation`,
  );
}
export function decodeMailBytes(value: string, length?: number): Uint8Array {
  requireMail(typeof value === "string", "invalid_encoding");
  const bytes = base64UrlDecodeCanonical(value);
  requireMail(
    bytes !== undefined && (length === undefined || bytes.length === length),
    "invalid_encoding",
    "invalid canonical base64url or byte length",
  );
  return bytes;
}
function pathId(value: string, length: number): void {
  const bytes =
    typeof value === "string" ? base64UrlDecodeCanonical(value) : undefined;
  requireMail(bytes?.length === length, "invalid_request", "invalid path ID");
}
export function newMailId(): string {
  return base64UrlEncode(nacl.randomBytes(16));
}
export function mailTextPart(text: string, name?: string): MailPart {
  strictString(text);
  return {
    media_type: "text/plain",
    data: base64UrlEncode(encoder.encode(text)),
    ...(name === undefined ? {} : { name }),
  };
}
/** Returns inert text only; does not render markup or perform network/file actions. */
export function mailPartText(part: MailPart): string {
  validateMailSchema(part, "part");
  requireMail(
    part.media_type.startsWith("text/"),
    "invalid_event",
    "part is not text",
  );
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
      decodeMailBytes(part.data),
    );
  } catch {
    throw protocolError("invalid_event", "invalid UTF-8 text part");
  }
}
function lifetime(created: number, expires: number): void {
  requireMail(
    created < expires && expires - created <= MAIL_MAX_TTL_MS,
    "invalid_event",
    "invalid lifetime",
  );
}
function usableX25519(publicKey: string): void {
  const key = decodeMailBytes(publicKey, 32);
  // A public, disposable scalar detects all low-order peers; no shared secret is used for encryption.
  requireMail(
    nacl.scalarMult(new Uint8Array(32).fill(42), key).some((x) => x !== 0),
    "invalid_event",
    "unusable X25519 public key",
  );
}
/** Historical verification: shape, signature, owner, intrinsic times, routes, and key. */
export function validateMailboxCard(
  card: unknown,
  owner?: string,
): asserts card is MailboxCard {
  validateMailSchema(card, "mailboxCardEnvelope");
  const c = card as MailboxCard;
  verifyEnvelope(c);
  if (owner !== undefined)
    requireMail(
      c.event.actor === owner,
      "invalid_actor",
      "card owner mismatch",
    );
  const p = c.event.payload;
  lifetime(c.event.created_at, p.expires_at);
  requireMail(
    p.expires_at <= p.receive_until &&
      p.receive_until - p.expires_at <= MAIL_MAX_TTL_MS,
    "invalid_event",
    "invalid receive_until",
  );
  p.routes.forEach(validateOrigin);
  usableX25519(p.public_key);
}
/** A card usable for new encryption: not future-dated, open (non-empty routes), unexpired. */
export function validateMailSenderCard(
  card: unknown,
  owner: string,
  now = Date.now(),
): asserts card is MailboxCard {
  safeTime(now);
  validateMailboxCard(card, owner);
  const c = card as MailboxCard;
  requireMail(
    c.event.created_at <= now + MAIL_FUTURE_SKEW_MS,
    "timestamp_out_of_window",
    "card is future-dated",
  );
  requireMail(
    c.event.payload.routes.length > 0,
    "mailbox_unavailable",
    "mailbox closed",
  );
  requireMail(now < c.event.payload.expires_at, "stale_card", "card expired");
}
/** Historical verification of a signed letter; never advances live nonce state. */
export function validateMailLetter(
  letter: unknown,
): asserts letter is MailLetter {
  validateMailSchema(letter, "messageEnvelope");
  const l = letter as MailLetter;
  verifyEnvelope(l);
  const p = l.event.payload;
  lifetime(l.event.created_at, p.expires_at);
  for (const part of p.parts) {
    decodeMailBytes(part.data);
    if (part.media_type.startsWith("text/")) mailPartText(part);
  }
  if (p.reply_card !== undefined)
    validateMailboxCard(p.reply_card, l.event.actor);
}
export function mailboxPublishEvent(
  actor: string,
  createdAt: number,
  nonce: number,
  payload: MailboxCardPayload,
): Event<MailboxCardPayload> {
  return createEvent(
    MAIL_PROTOCOL,
    "mailbox.publish",
    actor,
    createdAt,
    nonce,
    clone(payload),
  );
}
export function mailMessageEvent(
  actor: string,
  createdAt: number,
  nonce: number,
  payload: MailMessagePayload,
): Event<MailMessagePayload> {
  return createEvent(
    MAIL_PROTOCOL,
    "mail.message",
    actor,
    createdAt,
    nonce,
    clone(payload),
  );
}
/** Bind a reply to a known parent: participants, parent letter ID, and thread. */
export function validateMailReply(reply: MailLetter, parent: MailLetter): void {
  validateMailLetter(reply);
  validateMailLetter(parent);
  requireMail(
    reply.event.payload.in_reply_to === parent.hash &&
      reply.event.payload.thread_id === parent.event.payload.thread_id &&
      reply.event.actor === parent.event.payload.to &&
      reply.event.payload.to === parent.event.actor,
    "invalid_event",
    "reply participants/thread binding mismatch",
  );
}
/** Validate a packet and return its canonical bytes, computed once for ID and size checks. */
function packetBytes(packet: unknown, expectedId?: string): Uint8Array {
  validateMailSchema(packet, "packet");
  const p = packet as MailPacket;
  decodeMailBytes(p.enc, 32);
  const ct = decodeMailBytes(p.ciphertext);
  requireMail(
    ct.length >= 1040 && ct.length % 1024 === 16,
    "invalid_packet",
    "invalid ciphertext length",
  );
  const bytes = mailCanonicalBytes(p);
  requireMail(
    bytes.length <= MAIL_MAX_PACKET_BYTES,
    "payload_too_large",
    "packet exceeds 1 MiB",
  );
  if (expectedId !== undefined)
    requireMail(
      base64UrlEncode(sha3_256(bytes)) === expectedId,
      "invalid_packet",
      "packet ID mismatch",
    );
  return bytes;
}
export function validateMailPacket(
  packet: unknown,
  expectedId?: string,
): asserts packet is MailPacket {
  packetBytes(packet, expectedId);
}
export function mailPacketId(packet: MailPacket): string {
  return base64UrlEncode(sha3_256(mailCanonicalBytes(packet)));
}
export function frameMailBytes(bytes: Uint8Array): Uint8Array {
  requireMail(
    bytes.length > 0 && bytes.length <= MAIL_MAX_PACKET_BYTES,
    "invalid_packet",
    "invalid frame input length",
  );
  const frame = new Uint8Array(1024 * Math.ceil((4 + bytes.length) / 1024));
  new DataView(frame.buffer).setUint32(0, bytes.length, false);
  frame.set(bytes, 4);
  return frame;
}
export function unframeMailLetter(frame: Uint8Array): MailLetter {
  requireMail(
    frame.length >= 1024 &&
      frame.length <= MAIL_MAX_PACKET_BYTES &&
      frame.length % 1024 === 0,
    "invalid_packet",
    "invalid frame length",
  );
  const n = new DataView(
    frame.buffer,
    frame.byteOffset,
    frame.byteLength,
  ).getUint32(0, false);
  requireMail(
    n > 0 &&
      n <= frame.length - 4 &&
      frame.length === 1024 * Math.ceil((4 + n) / 1024),
    "invalid_packet",
    "invalid/nonminimal frame length",
  );
  requireMail(
    frame.subarray(4 + n).every((x) => x === 0),
    "invalid_packet",
    "nonzero padding",
  );
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
      frame.subarray(4, 4 + n),
    );
  } catch {
    throw protocolError("invalid_packet", "invalid UTF-8 frame");
  }
  const letter = parseStrictJson(text);
  requireMail(
    canonicalize(letter) === text,
    "invalid_packet",
    "noncanonical letter JSON",
  );
  validateMailLetter(letter);
  return letter;
}
const hpke = () =>
  new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Chacha20Poly1305(),
  });
/** Independent raw X25519 secret. Never derive this from an Identity signing key. */
export class MailEncryptionKey {
  private secret: Uint8Array;
  private destroyed = false;
  private constructor(secret: Uint8Array) {
    requireMail(secret.length === 32, "invalid_private_key");
    this.secret = new Uint8Array(secret);
  }
  static generate(): MailEncryptionKey {
    return new MailEncryptionKey(nacl.randomBytes(32));
  }
  static fromBytes(secret: Uint8Array): MailEncryptionKey {
    return new MailEncryptionKey(secret);
  }
  publicKey(): string {
    requireMail(!this.destroyed, "invalid_private_key", "key destroyed");
    return base64UrlEncode(nacl.scalarMult.base(this.secret));
  }
  /** Sensitive backup material: store only in an owner-controlled encrypted key store. */
  exportSecret(): Uint8Array {
    requireMail(!this.destroyed, "invalid_private_key", "key destroyed");
    return new Uint8Array(this.secret);
  }
  destroy(): void {
    this.secret.fill(0);
    this.destroyed = true;
  }
}
/** Stateless encryption with fresh HPKE randomness. Pin the card with MailCardCache first. */
export async function sealMailPacket(
  letter: MailLetter,
  card: MailboxCard,
  now = Date.now(),
): Promise<MailPacket> {
  letter = clone(letter);
  card = clone(card);
  validateMailLetter(letter);
  validateMailSenderCard(card, letter.event.payload.to, now);
  requireMail(
    letter.event.created_at <= now + MAIL_FUTURE_SKEW_MS &&
      now < letter.event.payload.expires_at,
    "packet_expired",
    "letter is expired or future-dated",
  );
  const c = card.event.payload;
  requireMail(
    letter.event.payload.expires_at <= c.receive_until,
    "invalid_packet",
    "letter exceeds receive_until",
  );
  const header: MailPacketHeader = {
    protocol: MAIL_PROTOCOL,
    mailbox_id: c.mailbox_id,
    card_hash: card.hash,
    expires_at: letter.event.payload.expires_at,
  };
  const plaintext = frameMailBytes(mailCanonicalBytes(letter));
  // Check base64/JSON overhead before allocating an HPKE context.
  const estimate: MailPacket = {
    header,
    enc: base64UrlEncode(new Uint8Array(32)),
    ciphertext: base64UrlEncode(new Uint8Array(plaintext.length + 16)),
  };
  requireMail(
    mailCanonicalBytes(estimate).length <= c.max_packet_bytes,
    "payload_too_large",
    "packet exceeds card limit",
  );
  const suite = hpke();
  const sender = await suite.createSenderContext({
    recipientPublicKey: await suite.kem.deserializePublicKey(
      decodeMailBytes(c.public_key, 32),
    ),
    info: INFO,
  });
  try {
    const ct = await sender.seal(plaintext, mailCanonicalBytes(header));
    return {
      header,
      enc: base64UrlEncode(new Uint8Array(sender.enc)),
      ciphertext: base64UrlEncode(new Uint8Array(ct)),
    };
  } finally {
    plaintext.fill(0);
  } // Context is never reused; JS cannot guarantee erasure of provider-owned/GC copies.
}
/** Verify/decrypt a queued letter; expiration of new acceptance is checked by MailInbox. */
export async function openMailPacket(
  packet: MailPacket,
  card: MailboxCard,
  key: MailEncryptionKey,
  owner: string,
  now = Date.now(),
  expectedId?: string,
): Promise<MailLetter> {
  packet = clone(packet);
  card = clone(card);
  safeTime(now);
  const bytes = packetBytes(packet, expectedId);
  validateMailboxCard(card, owner);
  return openVerified(packet, bytes, card, key, owner, now);
}
/** Open with a card that was already verified for `owner` (the keyring verifies at `add`). */
async function openVerified(
  packet: MailPacket,
  bytes: Uint8Array,
  card: MailboxCard,
  key: MailEncryptionKey,
  owner: string,
  now: number,
): Promise<MailLetter> {
  const c = card.event.payload,
    h = packet.header;
  requireMail(
    h.card_hash === card.hash && h.mailbox_id === c.mailbox_id,
    "invalid_packet",
    "card/header binding mismatch",
  );
  requireMail(
    bytes.length <= c.max_packet_bytes,
    "payload_too_large",
    "packet exceeds card limit",
  );
  requireMail(
    h.expires_at <= c.receive_until,
    "invalid_packet",
    "packet exceeds receive_until",
  );
  requireMail(
    key.publicKey() === c.public_key,
    "invalid_private_key",
    "recipient secret does not match card",
  );
  const secret = key.exportSecret();
  let plaintext: Uint8Array;
  try {
    const suite = hpke();
    const ctx = await suite.createRecipientContext({
      recipientKey: await suite.kem.deserializePrivateKey(secret),
      enc: decodeMailBytes(packet.enc, 32),
      info: INFO,
    });
    plaintext = new Uint8Array(
      await ctx.open(decodeMailBytes(packet.ciphertext), mailCanonicalBytes(h)),
    );
  } catch {
    throw protocolError("invalid_packet", "HPKE opening failed");
  } finally {
    secret.fill(0);
  }
  try {
    const letter = unframeMailLetter(plaintext);
    requireMail(
      letter.event.payload.to === owner,
      "invalid_packet",
      "letter recipient mismatch",
    );
    requireMail(
      letter.event.payload.expires_at === h.expires_at,
      "invalid_packet",
      "letter/header expiration mismatch",
    );
    requireMail(
      letter.event.created_at <= now + MAIL_FUTURE_SKEW_MS,
      "timestamp_out_of_window",
      "future letter",
    );
    return letter;
  } finally {
    plaintext.fill(0);
  }
}

export interface MailCardCacheSnapshot {
  version: 1;
  pins: MailboxCard[];
}
/**
 * Sender-side card pins: the greatest-nonce card seen per (owner, mailbox),
 * including closed or expired cards. Persist the snapshot after every observe,
 * even one that throws because the new pin is unusable.
 */
export class MailCardCache {
  private readonly pins = new Map<string, MailboxCard>();
  constructor(snapshot?: MailCardCacheSnapshot) {
    if (snapshot) {
      requireMail(snapshot.version === 1, "invalid_request");
      for (const card of snapshot.pins) {
        validateMailSchema(card, "mailboxCardEnvelope");
        this.pins.set(
          this.id(card.event.actor, card.event.payload.mailbox_id),
          clone(card),
        );
      }
    }
  }
  private id(owner: string, mailbox: string): string {
    return owner + ":" + mailbox;
  }
  snapshot(): MailCardCacheSnapshot {
    return { version: 1, pins: clone([...this.pins.values()]) };
  }
  /** Pin a verified card, then (by default) require that it is usable for new encryption. */
  observe(
    card: MailboxCard,
    owner: string,
    now = Date.now(),
    requireUsable = true,
  ): MailboxCard {
    card = clone(card);
    safeTime(now);
    validateMailboxCard(card, owner);
    requireMail(
      card.event.created_at <= now + MAIL_FUTURE_SKEW_MS,
      "timestamp_out_of_window",
      "card is future-dated",
    );
    const id = this.id(owner, card.event.payload.mailbox_id),
      pin = this.pins.get(id);
    if (pin && pin.hash !== card.hash)
      requireMail(
        card.event.nonce > pin.event.nonce,
        "stale_card",
        "card is older than or conflicts with the pinned card",
      );
    this.pins.set(id, card);
    if (requireUsable) validateMailSenderCard(card, owner, now);
    return clone(card);
  }
  /** Drop pins old enough that every earlier card of the mailbox has expired. */
  prune(now = Date.now()): void {
    safeTime(now);
    for (const [id, pin] of this.pins)
      if (now >= pin.event.created_at + MAIL_MAX_TTL_MS + MAIL_FUTURE_SKEW_MS)
        this.pins.delete(id);
  }
  async seal(
    letter: MailLetter,
    card: MailboxCard,
    now = Date.now(),
  ): Promise<MailPacket> {
    return sealMailPacket(
      letter,
      this.observe(card, letter.event.payload.to, now),
      now,
    );
  }
}
export interface MailKeyringSnapshot {
  version: 1;
  owner: string;
  entries: { card: MailboxCard; secret: string }[];
}
/** Retained verified cards and their secrets, looked up by card hash until receive_until. */
export class MailKeyring {
  private readonly entries = new Map<
    string,
    { card: MailboxCard; key: MailEncryptionKey }
  >();
  constructor(readonly owner: string) {
    validateAgentId(owner);
  }
  add(card: MailboxCard, key: MailEncryptionKey): void {
    card = clone(card);
    validateMailboxCard(card, this.owner);
    requireMail(
      key.publicKey() === card.event.payload.public_key,
      "invalid_private_key",
      "recipient secret does not match card",
    );
    this.entries.get(card.hash)?.key.destroy();
    this.entries.set(card.hash, {
      card,
      key: MailEncryptionKey.fromBytes(key.exportSecret()),
    });
  }
  /** Sensitive snapshot, including raw encryption secrets. Protect it separately from logs and application data. */
  exportSnapshot(): MailKeyringSnapshot {
    return {
      version: 1,
      owner: this.owner,
      entries: [...this.entries.values()].map((x) => ({
        card: clone(x.card),
        secret: base64UrlEncode(x.key.exportSecret()),
      })),
    };
  }
  static restore(snapshot: MailKeyringSnapshot): MailKeyring {
    requireMail(snapshot.version === 1, "invalid_request");
    const r = new MailKeyring(snapshot.owner);
    for (const x of snapshot.entries)
      r.add(x.card, MailEncryptionKey.fromBytes(decodeMailBytes(x.secret, 32)));
    return r;
  }
  prune(now = Date.now()): void {
    safeTime(now);
    for (const [hash, x] of this.entries)
      if (now >= x.card.event.payload.receive_until) {
        x.key.destroy();
        this.entries.delete(hash);
      }
  }
  async open(
    packet: MailPacket,
    now = Date.now(),
    expectedId?: string,
  ): Promise<MailLetter> {
    packet = clone(packet);
    safeTime(now);
    const bytes = packetBytes(packet, expectedId);
    const x = this.entries.get(packet.header.card_hash);
    requireMail(x, "invalid_packet", "unknown retained card");
    return openVerified(packet, bytes, x.card, x.key, this.owner, now);
  }
}
export interface MailInboxSnapshot {
  version: 1;
  owner: string;
  /** Accepted letter IDs and their signed expirations. */
  accepted: [string, number][];
}
/**
 * Cross-route letter deduplication. The application stores accepted letters;
 * persist the snapshot with them before deleting relay copies or acting.
 */
export class MailInbox {
  private readonly accepted = new Map<string, number>();
  constructor(
    readonly keyring: MailKeyring,
    snapshot?: MailInboxSnapshot,
  ) {
    if (snapshot) {
      requireMail(
        snapshot.version === 1 && snapshot.owner === keyring.owner,
        "invalid_request",
      );
      for (const [id, expires] of snapshot.accepted)
        this.accepted.set(id, expires);
    }
  }
  snapshot(): MailInboxSnapshot {
    return {
      version: 1,
      owner: this.keyring.owner,
      accepted: [...this.accepted],
    };
  }
  has(letterId: string): boolean {
    return this.accepted.has(letterId);
  }
  async accept(
    packet: MailPacket,
    now = Date.now(),
    expectedId?: string,
  ): Promise<{ kind: "accepted" | "duplicate"; letter: MailLetter }> {
    const letter = await this.keyring.open(packet, now, expectedId);
    // No await between lookup and commit: concurrent decryptions cannot both accept.
    if (this.accepted.has(letter.hash)) return { kind: "duplicate", letter };
    requireMail(
      now < letter.event.payload.expires_at,
      "packet_expired",
      "expired new letter",
    );
    this.accepted.set(letter.hash, letter.event.payload.expires_at);
    return { kind: "accepted", letter };
  }
  /** Forget letters whose signed expiration has passed; they can no longer be newly accepted. */
  prune(now = Date.now()): void {
    safeTime(now);
    for (const [id, expires] of this.accepted)
      if (now >= expires) this.accepted.delete(id);
  }
}
export function validateMailDiscovery(
  value: unknown,
  service: string,
): asserts value is MailDiscovery {
  validateMailSchema(value, "discoveryDocument");
  validateOrigin(service);
  requireMail(
    (value as MailDiscovery).service === service,
    "invalid_response",
    "discovery origin mismatch",
  );
}
function ownerClaims(
  token: string,
  service: string,
  now: number,
): RequestJwtClaims {
  safeTime(now);
  try {
    return verifyRequestJwt(token, {
      audience: service,
      nowSecs: Math.floor(now / 1000),
    });
  } catch {
    throw protocolError("invalid_token", "invalid mailbox owner JWT");
  }
}
/** Identity request JWT for this relay origin whose subject is the mailbox owner. */
export function validateMailOwnerJwt(
  token: string,
  service: string,
  owner: string,
  now = Date.now(),
): void {
  validateOrigin(service);
  validateAgentId(owner);
  requireMail(
    ownerClaims(token, service, now).iss === owner,
    "permission_denied",
    "not mailbox owner",
  );
}
export function validateMailCardRecord(
  value: unknown,
  owner?: string,
  mailboxId?: string,
  hash?: string,
): asserts value is MailCardRecord {
  validateMailSchema(value, "cardAcceptedRecord");
  const r = value as MailCardRecord;
  validateMailboxCard(r.envelope, owner);
  requireMail(
    (mailboxId === undefined ||
      r.envelope.event.payload.mailbox_id === mailboxId) &&
      (hash === undefined || r.envelope.hash === hash),
    "invalid_response",
    "card record mismatch",
  );
}
export function validateMailDeliveryResult(
  value: unknown,
  packet?: MailPacket,
): asserts value is MailDeliveryResult {
  validateMailSchema(value, "deliveryResult");
  const r = value as MailDeliveryResult;
  if (packet !== undefined)
    requireMail(
      r.packet_id === mailPacketId(packet) &&
        r.accepted_at < packet.header.expires_at,
      "invalid_response",
      "delivery result mismatch",
    );
}
export function validateMailPacketRecord(
  value: unknown,
  mailboxId?: string,
): asserts value is MailPacketRecord {
  validateMailSchema(value, "packetRecord");
  const r = value as MailPacketRecord;
  validateMailPacket(r.packet, r.packet_id);
  requireMail(
    r.accepted_at < r.packet.header.expires_at &&
      (mailboxId === undefined || r.packet.header.mailbox_id === mailboxId),
    "invalid_response",
    "packet record mismatch",
  );
}
export function validateMailPacketList(
  value: unknown,
  mailboxId: string,
  limit = 100,
): asserts value is MailPacketList {
  validateMailSchema(value, "packetList");
  const p = value as MailPacketList;
  requireMail(
    p.result.length <= limit && (!p.next_cursor || p.result.length > 0),
    "invalid_response",
    "invalid page size",
  );
  let seq = 0;
  for (const r of p.result) {
    validateMailPacketRecord(r, mailboxId);
    requireMail(r.seq > seq, "invalid_response", "unordered packets");
    seq = r.seq;
  }
}

interface RelayMailbox {
  current: MailCardRecord;
  lastSeq: number;
  bytes: number;
  packets: Map<string, { record: MailPacketRecord; size: number }>;
  tombstones: Map<string, { accepted_at: number; expires_at: number }>;
}
export interface MailRelaySnapshot {
  version: 1;
  origin: string;
  mailboxes: {
    current: MailCardRecord;
    last_seq: number;
    packets: MailPacketRecord[];
    tombstones: {
      packet_id: string;
      accepted_at: number;
      expires_at: number;
    }[];
  }[];
}
export interface MailRelayOptions {
  clock?: () => number;
  /** Service-wide Identity nonce cache, shared with other live-write protocols at this origin. */
  nonceStore?: NonceStore;
  /** Per-mailbox limits on retained packets. */
  maxPackets?: number;
  maxBytes?: number;
  snapshot?: MailRelaySnapshot;
}
/**
 * Synchronous process-local relay model. All validation precedes mutation;
 * persist the snapshot atomically before emitting a successful HTTP response.
 * The short-lived nonce cache is not part of the snapshot.
 */
export class MailRelayStore {
  private readonly boxes = new Map<string, RelayMailbox>();
  private readonly nonces: NonceStore;
  private readonly clock: () => number;
  private readonly maxPackets: number;
  private readonly maxBytes: number;
  constructor(
    readonly origin: string,
    options: MailRelayOptions = {},
  ) {
    validateOrigin(origin);
    this.nonces = options.nonceStore ?? new MemoryNonceStore();
    this.clock = options.clock ?? Date.now;
    this.maxPackets = options.maxPackets ?? 10000;
    this.maxBytes = options.maxBytes ?? 64 * MAIL_MAX_PACKET_BYTES;
    requireMail(
      Number.isSafeInteger(this.maxPackets) &&
        this.maxPackets > 0 &&
        Number.isSafeInteger(this.maxBytes) &&
        this.maxBytes > 0,
      "invalid_request",
      "invalid quota",
    );
    const s = options.snapshot;
    if (s) {
      requireMail(
        s.version === 1 && s.origin === origin,
        "invalid_request",
        "snapshot origin mismatch",
      );
      for (const m of s.mailboxes) {
        const box: RelayMailbox = {
          current: clone(m.current),
          lastSeq: m.last_seq,
          bytes: 0,
          packets: new Map(),
          tombstones: new Map(),
        };
        for (const record of m.packets) {
          const size = mailCanonicalBytes(record.packet).length;
          box.packets.set(record.packet_id, { record: clone(record), size });
          box.bytes += size;
        }
        for (const t of m.tombstones)
          box.tombstones.set(t.packet_id, {
            accepted_at: t.accepted_at,
            expires_at: t.expires_at,
          });
        this.boxes.set(m.current.envelope.event.payload.mailbox_id, box);
      }
    }
  }
  snapshot(): MailRelaySnapshot {
    return {
      version: 1,
      origin: this.origin,
      mailboxes: [...this.boxes.values()].map((b) => ({
        current: clone(b.current),
        last_seq: b.lastSeq,
        packets: [...b.packets.values()].map((p) => clone(p.record)),
        tombstones: [...b.tombstones].map(([packet_id, t]) => ({
          packet_id,
          ...t,
        })),
      })),
    };
  }
  discovery(): MailDiscovery {
    return { protocol: MAIL_PROTOCOL, service: this.origin };
  }
  publish(card: MailboxCard, now = this.clock()): MailCardRecord {
    card = clone(card);
    safeTime(now);
    validateMailboxCard(card);
    const p = card.event.payload,
      b = this.boxes.get(p.mailbox_id);
    if (b) {
      const current = b.current.envelope;
      requireMail(
        current.event.actor === card.event.actor,
        "mailbox_conflict",
        "mailbox belongs to another owner",
      );
      if (current.hash === card.hash) return clone(b.current);
      if (card.event.nonce <= current.event.nonce)
        throw protocolError(
          "nonce_not_greater",
          "card nonce does not advance",
          {
            max_nonce: current.event.nonce,
          },
        );
    } else
      requireMail(
        p.routes.includes(this.origin),
        "permission_denied",
        "first card must list this relay",
      );
    verifyTimestamp(card.event.created_at, now, MAIL_FUTURE_SKEW_MS);
    // The final fallible step, so a rejected card consumes no nonce.
    this.nonces.checkAndUpdate(
      card.event.actor,
      card.event.nonce,
      now,
      2 * MAIL_FUTURE_SKEW_MS,
    );
    const record: MailCardRecord = { envelope: card, accepted_at: now };
    if (b) b.current = record;
    else
      this.boxes.set(p.mailbox_id, {
        current: record,
        lastSeq: 0,
        bytes: 0,
        packets: new Map(),
        tombstones: new Map(),
      });
    return clone(record);
  }
  card(mailboxId: string): MailCardRecord {
    pathId(mailboxId, 16);
    const b = this.boxes.get(mailboxId);
    requireMail(b, "mailbox_unavailable");
    return clone(b.current);
  }
  publishJson(text: string, now = this.clock()): MailCardRecord {
    requireMail(
      encoder.encode(text).length <= MAIL_MAX_PACKET_BYTES,
      "payload_too_large",
    );
    return this.publish(parseStrictJson(text) as MailboxCard, now);
  }
  deliverJson(
    mailboxId: string,
    text: string,
    now = this.clock(),
  ): MailDeliveryResult {
    requireMail(
      encoder.encode(text).length <= MAIL_MAX_PACKET_BYTES,
      "payload_too_large",
    );
    return this.deliver(mailboxId, parseStrictJson(text) as MailPacket, now);
  }
  deliver(
    mailboxId: string,
    packet: MailPacket,
    now = this.clock(),
  ): MailDeliveryResult {
    packet = clone(packet);
    safeTime(now);
    pathId(mailboxId, 16);
    const bytes = packetBytes(packet),
      size = bytes.length;
    const h = packet.header;
    requireMail(
      h.mailbox_id === mailboxId,
      "invalid_packet",
      "path mailbox mismatch",
    );
    const b = this.boxes.get(mailboxId);
    requireMail(b, "mailbox_unavailable");
    const id = base64UrlEncode(sha3_256(bytes)),
      prior = b.tombstones.get(id);
    if (prior) return { packet_id: id, accepted_at: prior.accepted_at };
    const c = b.current.envelope,
      p = c.event.payload;
    requireMail(p.routes.includes(this.origin), "mailbox_unavailable");
    requireMail(h.card_hash === c.hash && now < p.expires_at, "stale_card");
    requireMail(now < h.expires_at, "packet_expired");
    requireMail(
      h.expires_at <= p.receive_until &&
        h.expires_at - now <= MAIL_MAX_TTL_MS + MAIL_FUTURE_SKEW_MS,
      "invalid_packet",
      "packet lifetime exceeds bound",
    );
    requireMail(
      size <= p.max_packet_bytes,
      "payload_too_large",
      "packet exceeds card limit",
    );
    this.dropExpired(b, now);
    requireMail(
      b.packets.size < this.maxPackets &&
        b.bytes + size <= this.maxBytes &&
        b.lastSeq < Number.MAX_SAFE_INTEGER,
      "rate_limited",
      "mailbox storage quota exhausted",
    );
    b.lastSeq += 1;
    b.packets.set(id, {
      record: { packet_id: id, packet, accepted_at: now, seq: b.lastSeq },
      size,
    });
    b.bytes += size;
    b.tombstones.set(id, { accepted_at: now, expires_at: h.expires_at });
    return { packet_id: id, accepted_at: now };
  }
  private ownerBox(mailboxId: string, jwt: string, now: number): RelayMailbox {
    pathId(mailboxId, 16);
    const claims = ownerClaims(jwt, this.origin, now);
    const b = this.boxes.get(mailboxId);
    requireMail(b, "mailbox_unavailable");
    requireMail(
      claims.iss === b.current.envelope.event.actor,
      "permission_denied",
      "not mailbox owner",
    );
    return b;
  }
  list(
    mailboxId: string,
    jwt: string,
    options: { limit?: number; cursor?: string; now?: number } = {},
  ): MailPacketList {
    const now = options.now ?? this.clock();
    safeTime(now);
    const b = this.ownerBox(mailboxId, jwt, now),
      limit = options.limit ?? 100,
      cursor = options.cursor;
    requireMail(
      Number.isSafeInteger(limit) && limit >= 1 && limit <= 1000,
      "invalid_request",
      "invalid limit",
    );
    // The cursor is the last returned seq; ownership is checked by the JWT.
    requireMail(
      cursor === undefined ||
        (/^(0|[1-9][0-9]*)$/.test(cursor) &&
          Number.isSafeInteger(Number(cursor))),
      "invalid_request",
      "invalid cursor",
    );
    const after = cursor === undefined ? 0 : Number(cursor);
    const rows = [...b.packets.values()]
      .map((x) => x.record)
      .filter((r) => r.seq > after && now < r.packet.header.expires_at);
    const result = clone(rows.slice(0, limit));
    return rows.length > limit
      ? { result, next_cursor: String(result.at(-1)!.seq) }
      : { result };
  }
  delete(
    mailboxId: string,
    packetId: string,
    jwt: string,
    now = this.clock(),
  ): void {
    const b = this.ownerBox(mailboxId, jwt, now);
    pathId(packetId, 32);
    const stored = b.packets.get(packetId);
    if (stored) {
      b.packets.delete(packetId);
      b.bytes -= stored.size;
    }
  }
  /** Drop expired packets and tombstones, then forget mailboxes whose current card's `receive_until` passed. */
  prune(now = this.clock()): void {
    safeTime(now);
    for (const [mailboxId, b] of this.boxes) {
      this.dropExpired(b, now);
      for (const [id, t] of b.tombstones)
        if (now >= t.expires_at) b.tombstones.delete(id);
      if (now >= b.current.envelope.event.payload.receive_until)
        this.boxes.delete(mailboxId);
    }
  }
  private dropExpired(b: RelayMailbox, now: number): void {
    for (const [id, x] of b.packets)
      if (now >= x.record.packet.header.expires_at) {
        b.packets.delete(id);
        b.bytes -= x.size;
      }
  }
}
