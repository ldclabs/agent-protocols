/** Agent Mail 1.0. Process-local reference state; persist snapshots before acknowledging delivery. */
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
} from "./identity.js";
import { MAIL_SCHEMA } from "./mail-schema.js";
export { MAIL_SCHEMA } from "./mail-schema.js";

export const MAIL_PROTOCOL = "agent-mail/1.0";
export const MAIL_MAX_TTL_MS = 30 * 86400000;
export const MAIL_FUTURE_SKEW_MS = 300000;
export const MAIL_MAX_PACKET_BYTES = 1048576;
export interface MailboxCardPayload {
  mailbox_id: string;
  enabled: boolean;
  expires_at: number;
  receive_until: number;
  key_id: string;
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
  receipt_requested?: boolean;
}
export interface MailReceiptPayload {
  to: string;
  expires_at: number;
  message_hash: string;
  status: "received";
}
export type MailMessage = Envelope<MailMessagePayload>;
export type MailReceipt = Envelope<MailReceiptPayload>;
export type MailLetter = Envelope<MailMessagePayload | MailReceiptPayload>;
export interface MailPacketHeader {
  protocol: typeof MAIL_PROTOCOL;
  mailbox_id: string;
  card_hash: string;
  key_id: string;
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
  seq: number;
}
export interface MailPacketRecord extends MailDeliveryResult {
  packet: MailPacket;
}
export interface MailDiscovery {
  protocol: typeof MAIL_PROTOCOL;
  service: string;
  endpoints?: { mailboxes?: string };
  features?: string[];
  [key: string]: unknown;
}
export type MailCardRecord = AcceptedRecord<MailboxCardPayload>;
export type MailPacketList = ListResponse<MailPacketRecord> & {
  [key: string]: unknown;
};
const encoder = new TextEncoder();
const clone = <T>(v: T): T => structuredClone(v);
const validators = new Map<string, Validator>();
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
function jsonValue(value: unknown, seen = new Set<object>()): void {
  if (value === null || typeof value === "boolean" || typeof value === "string")
    return;
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
  seen.add(value);
  requireMail(
    Array.isArray(value) ||
      Object.getPrototypeOf(value) === Object.prototype ||
      Object.getPrototypeOf(value) === null,
    "invalid_event",
    "expected plain JSON object",
  );
  for (const child of Array.isArray(value) ? value : Object.values(value))
    jsonValue(child, seen);
  seen.delete(value);
}
/** Canonical, strict I-JSON bytes. This never silently drops undefined members. */
export function mailCanonicalBytes(value: unknown): Uint8Array {
  jsonValue(value);
  const text = canonicalize(value);
  requireMail(text !== undefined, "invalid_event");
  parseStrictJson(text);
  return encoder.encode(text);
}
export function validateMailSchema(
  value: unknown,
  definition = "envelope",
): void {
  mailCanonicalBytes(value);
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
export function newMailId(): string {
  return base64UrlEncode(nacl.randomBytes(16));
}
export function mailTextPart(text: string, name?: string): MailPart {
  mailCanonicalBytes(text);
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
function usableX25519(publicKey: string): Uint8Array {
  const key = decodeMailBytes(publicKey, 32);
  // A public, disposable scalar detects all low-order peers; no shared secret is used for encryption.
  requireMail(
    nacl.scalarMult(new Uint8Array(32).fill(42), key).some((x) => x !== 0),
    "invalid_event",
    "unusable X25519 public key",
  );
  return key;
}
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
      "permission_denied",
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
    c.event.payload.enabled,
    "mailbox_unavailable",
    "mailbox disabled",
  );
  requireMail(now < c.event.payload.expires_at, "stale_card", "card expired");
}
export function validateMailLetter(
  letter: unknown,
): asserts letter is MailLetter {
  validateMailSchema(letter, "letterEnvelope");
  const l = letter as MailLetter;
  verifyEnvelope(l);
  lifetime(l.event.created_at, l.event.payload.expires_at);
  if (l.event.type === "mail.message") {
    const p = l.event.payload as MailMessagePayload;
    for (const part of p.parts) {
      decodeMailBytes(part.data);
      if (part.media_type.startsWith("text/")) mailPartText(part);
    }
    if (p.reply_card !== undefined)
      validateMailboxCard(p.reply_card, l.event.actor);
  }
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
export function mailReceiptEvent(
  actor: string,
  createdAt: number,
  nonce: number,
  payload: MailReceiptPayload,
): Event<MailReceiptPayload> {
  return createEvent(
    MAIL_PROTOCOL,
    "mail.receipt",
    actor,
    createdAt,
    nonce,
    clone(payload),
  );
}
export function validateMailReceipt(
  receipt: unknown,
  original: MailMessage,
): asserts receipt is MailReceipt {
  validateMailLetter(receipt);
  validateMailLetter(original);
  const r = receipt as MailReceipt;
  requireMail(
    r.event.type === "mail.receipt" &&
      original.event.type === "mail.message" &&
      r.event.actor === original.event.payload.to &&
      r.event.payload.to === original.event.actor &&
      r.event.payload.message_hash === original.hash,
    "invalid_event",
    "receipt binding mismatch",
  );
}
export function validateMailReply(
  reply: MailMessage,
  parent: MailMessage,
): void {
  validateMailLetter(reply);
  validateMailLetter(parent);
  requireMail(
    reply.event.type === "mail.message" &&
      parent.event.type === "mail.message" &&
      reply.event.payload.in_reply_to === parent.hash &&
      reply.event.payload.thread_id === parent.event.payload.thread_id &&
      reply.event.actor === parent.event.payload.to &&
      reply.event.payload.to === parent.event.actor,
    "invalid_event",
    "reply participants/thread binding mismatch",
  );
}
export function validateMailPacket(
  packet: unknown,
  expectedId?: string,
): asserts packet is MailPacket {
  validateMailSchema(packet, "packet");
  const p = packet as MailPacket;
  decodeMailBytes(p.enc, 32);
  const ct = decodeMailBytes(p.ciphertext);
  requireMail(
    ct.length >= 1040 && ct.length % 1024 === 16,
    "invalid_packet",
    "invalid ciphertext length",
  );
  requireMail(
    mailCanonicalBytes(p).length <= MAIL_MAX_PACKET_BYTES,
    "payload_too_large",
    "packet exceeds 1 MiB",
  );
  if (expectedId !== undefined)
    requireMail(
      mailPacketId(p) === expectedId,
      "invalid_packet",
      "packet ID mismatch",
    );
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
    new TextDecoder().decode(mailCanonicalBytes(letter)) === text,
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
function packetInfo(header: MailPacketHeader): Uint8Array {
  const prefix = encoder.encode(MAIL_PROTOCOL + "\0");
  const bytes = new Uint8Array(prefix.length + 32);
  bytes.set(prefix);
  bytes.set(decodeMailBytes(header.card_hash, 32), prefix.length);
  return bytes;
}
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
/** Stateless encryption. Observe the card with MailCardCache before every send. Uses fresh HPKE randomness. */
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
    key_id: c.key_id,
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
  const key = await suite.kem.deserializePublicKey(
    decodeMailBytes(c.public_key, 32),
  );
  const sender = await suite.createSenderContext({
    recipientPublicKey: key,
    info: packetInfo(header),
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
/** Verify/decrypt an asynchronous letter; expiration is checked by MailRecipient after duplicate lookup. */
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
  validateMailPacket(packet, expectedId);
  validateMailboxCard(card, owner);
  const c = card.event.payload,
    h = packet.header;
  requireMail(c.enabled, "invalid_packet", "encryption card was disabled");
  requireMail(
    h.card_hash === card.hash &&
      h.mailbox_id === c.mailbox_id &&
      h.key_id === c.key_id,
    "invalid_packet",
    "card/header binding mismatch",
  );
  requireMail(
    mailCanonicalBytes(packet).length <= c.max_packet_bytes,
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
    const recipientKey = await suite.kem.deserializePrivateKey(secret);
    const ctx = await suite.createRecipientContext({
      recipientKey,
      enc: decodeMailBytes(packet.enc, 32),
      info: packetInfo(h),
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

export interface MailCardPin {
  owner: string;
  mailbox_id: string;
  nonce: number;
  hash: string;
  equivocation: boolean;
  keys: Record<string, string>;
  card: MailboxCard;
}
export interface MailCardCacheSnapshot {
  version: 1;
  pins: MailCardPin[];
}
/** Rollback state has no automatic expiry. Persist snapshot even when observe reports disabled/expired/equivocation. */
export class MailCardCache {
  private readonly pins = new Map<string, MailCardPin>();
  constructor(snapshot?: MailCardCacheSnapshot) {
    if (snapshot) {
      requireMail(snapshot.version === 1, "invalid_request");
      for (const pin of snapshot.pins) {
        validateMailboxCard(pin.card, pin.owner);
        requireMail(
          pin.mailbox_id === pin.card.event.payload.mailbox_id &&
            pin.nonce === pin.card.event.nonce &&
            pin.hash === pin.card.hash &&
            typeof pin.equivocation === "boolean",
          "invalid_request",
          "invalid pin snapshot",
        );
        for (const [id, key] of Object.entries(pin.keys)) {
          decodeMailBytes(id, 16);
          usableX25519(key);
        }
        requireMail(
          pin.keys[pin.card.event.payload.key_id] ===
            pin.card.event.payload.public_key,
          "invalid_request",
        );
        const k = this.id(pin.owner, pin.mailbox_id);
        requireMail(!this.pins.has(k), "invalid_request", "duplicate pin");
        this.pins.set(k, clone(pin));
      }
    }
  }
  private id(owner: string, mailbox: string): string {
    return owner + ":" + mailbox;
  }
  snapshot(): MailCardCacheSnapshot {
    return { version: 1, pins: clone([...this.pins.values()]) };
  }
  observe(
    card: MailboxCard,
    owner: string,
    now = Date.now(),
    requireUsable = true,
  ): MailboxCard {
    card = clone(card);
    validateMailboxCard(card, owner);
    safeTime(now);
    requireMail(
      card.event.created_at <= now + MAIL_FUTURE_SKEW_MS,
      "timestamp_out_of_window",
    );
    const p = card.event.payload,
      id = this.id(owner, p.mailbox_id),
      prior = this.pins.get(id);
    if (prior) {
      requireMail(
        !prior.keys[p.key_id] || prior.keys[p.key_id] === p.public_key,
        "mailbox_conflict",
        "encryption key ID reused",
      );
      // Preserve authenticated historical key bindings, including lower-nonce cards.
      prior.keys[p.key_id] = p.public_key;
      requireMail(
        card.event.nonce >= prior.nonce,
        "stale_card",
        "card rollback",
      );
      if (card.event.nonce === prior.nonce) {
        if (card.hash !== prior.hash) prior.equivocation = true;
        requireMail(
          !prior.equivocation,
          "mailbox_conflict",
          "card equivocation",
        );
      }
    }
    if (!prior || card.event.nonce > prior.nonce)
      this.pins.set(id, {
        owner,
        mailbox_id: p.mailbox_id,
        nonce: card.event.nonce,
        hash: card.hash,
        equivocation: false,
        keys: { ...prior?.keys, [p.key_id]: p.public_key },
        card,
      });
    if (requireUsable) validateMailSenderCard(card, owner, now);
    return clone(card);
  }
  /** Explicit trust reset loses all rollback/equivocation/key-history protection for this mailbox. */
  resetTrust(owner: string, mailboxId: string): void {
    this.pins.delete(this.id(owner, mailboxId));
  }
  async seal(
    letter: MailLetter,
    card: MailboxCard,
    now = Date.now(),
  ): Promise<MailPacket> {
    const verified = this.observe(card, letter.event.payload.to, now);
    const packet = await sealMailPacket(letter, verified, now);
    this.observe(verified, letter.event.payload.to, now);
    return packet;
  }
}
export interface MailKeyringSnapshot {
  version: 1;
  owner: string;
  entries: { card: MailboxCard; secret: string }[];
  keys: Record<string, string>;
}
export class MailKeyring {
  private readonly entries = new Map<
    string,
    { card: MailboxCard; key: MailEncryptionKey }
  >();
  private readonly keys: Record<string, string> = Object.create(null);
  constructor(readonly owner: string) {
    validateAgentId(owner);
  }
  add(card: MailboxCard, key: MailEncryptionKey): void {
    card = clone(card);
    validateMailboxCard(card, this.owner);
    const p = card.event.payload,
      k = p.mailbox_id + ":" + p.key_id;
    requireMail(
      key.publicKey() === p.public_key,
      "invalid_private_key",
      "recipient secret does not match card",
    );
    requireMail(
      !this.keys[k] || this.keys[k] === p.public_key,
      "mailbox_conflict",
      "encryption key ID reused",
    );
    this.keys[k] = p.public_key;
    const previous = this.entries.get(card.hash);
    previous?.key.destroy();
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
      keys: clone(this.keys),
    };
  }
  static restore(snapshot: MailKeyringSnapshot): MailKeyring {
    requireMail(snapshot.version === 1, "invalid_request");
    const r = new MailKeyring(snapshot.owner);
    for (const [id, key] of Object.entries(snapshot.keys)) {
      const parts = id.split(":");
      requireMail(parts.length === 2, "invalid_request");
      parts.forEach((p) => decodeMailBytes(p, 16));
      usableX25519(key);
      r.keys[id] = key;
    }
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
    validateMailPacket(packet, expectedId);
    const x = this.entries.get(packet.header.card_hash);
    requireMail(x, "invalid_private_key", "unknown historical card/key");
    return openMailPacket(packet, x.card, x.key, this.owner, now, expectedId);
  }
}
export interface MailRecipientSnapshot {
  version: 1;
  owner: string;
  letters: MailLetter[];
  outgoing: MailMessage[];
}
/** Process-local inbox. Persist snapshot before deleting relay copies or acting; no automatic receipts/actions. */
export class MailRecipient {
  private readonly accepted = new Map<string, MailLetter>();
  private readonly outgoing = new Map<string, MailMessage>();
  constructor(
    readonly keyring: MailKeyring,
    snapshot?: MailRecipientSnapshot,
  ) {
    if (snapshot) {
      requireMail(
        snapshot.version === 1 && snapshot.owner === keyring.owner,
        "invalid_request",
      );
      for (const l of snapshot.outgoing) this.rememberOutgoing(l);
      for (const l of snapshot.letters) {
        validateMailLetter(l);
        requireMail(l.event.payload.to === keyring.owner, "invalid_request");
        if (l.event.type === "mail.receipt") {
          const original = this.outgoing.get(
            (l.event.payload as MailReceiptPayload).message_hash,
          );
          requireMail(
            original,
            "invalid_event",
            "receipt has no outgoing original",
          );
          validateMailReceipt(l, original);
        }
        this.accepted.set(l.hash, clone(l));
      }
    }
  }
  /** Record an actual send attempt, including an ambiguous transport outcome; do not register unsent drafts. */
  rememberOutgoing(letter: MailMessage): void {
    validateMailLetter(letter);
    requireMail(
      letter.event.type === "mail.message" &&
        letter.event.actor === this.keyring.owner,
      "invalid_event",
      "outgoing owner mismatch",
    );
    this.outgoing.set(letter.hash, clone(letter));
  }
  snapshot(): MailRecipientSnapshot {
    return {
      version: 1,
      owner: this.keyring.owner,
      letters: this.letters(),
      outgoing: clone([...this.outgoing.values()]),
    };
  }
  letters(): MailLetter[] {
    return clone([...this.accepted.values()]);
  }
  async accept(
    packet: MailPacket,
    now = Date.now(),
    expectedId?: string,
  ): Promise<{ kind: "accepted" | "duplicate"; letter: MailLetter }> {
    const letter = await this.keyring.open(packet, now, expectedId);
    // No await between dedup and commit: concurrent decryptions cannot create duplicate inbox items.
    if (this.accepted.has(letter.hash))
      return {
        kind: "duplicate",
        letter: clone(this.accepted.get(letter.hash)!),
      };
    requireMail(
      now < letter.event.payload.expires_at,
      "packet_expired",
      "expired new letter",
    );
    if (letter.event.type === "mail.receipt") {
      const original = this.outgoing.get(
        (letter.event.payload as MailReceiptPayload).message_hash,
      );
      requireMail(
        original,
        "invalid_event",
        "receipt has no outgoing original",
      );
      validateMailReceipt(letter, original);
    }
    this.accepted.set(letter.hash, clone(letter));
    return { kind: "accepted", letter: clone(letter) };
  }
}
export function validateMailDiscovery(
  value: unknown,
  service: string,
  card?: MailboxCard,
): asserts value is MailDiscovery {
  validateMailSchema(value, "discoveryDocument");
  validateOrigin(service);
  const d = value as MailDiscovery;
  validateOrigin(d.service);
  requireMail(
    d.service === service,
    "invalid_response",
    "discovery origin mismatch",
  );
  if (card) {
    validateMailboxCard(card);
    requireMail(
      card.event.payload.routes.includes(service),
      "invalid_response",
      "relay not authorized by card",
    );
  }
  if (d.endpoints?.mailboxes !== undefined) {
    const e = d.endpoints.mailboxes;
    let u: URL;
    try {
      u = new URL(e);
    } catch {
      throw protocolError("invalid_response", "invalid endpoint");
    }
    requireMail(
      u.origin === service &&
        !u.username &&
        !u.password &&
        !u.search &&
        !u.hash &&
        !e.includes("?") &&
        !e.includes("#") &&
        !e.includes("\\") &&
        !e.endsWith("/") &&
        u.href === e,
      "invalid_response",
      "unsafe endpoint",
    );
  }
}
export function validateMailOwnerJwt(
  token: string,
  service: string,
  owner: string,
  now = Date.now(),
): void {
  safeTime(now);
  validateOrigin(service);
  validateAgentId(owner);
  try {
    const parts = token.split(".");
    requireMail(parts.length === 3, "invalid_token");
    const header = parseStrictJson(
      new TextDecoder("utf-8", { fatal: true }).decode(
        decodeMailBytes(parts[0]),
      ),
    ) as Record<string, unknown>;
    const claims = parseStrictJson(
      new TextDecoder("utf-8", { fatal: true }).decode(
        decodeMailBytes(parts[1]),
      ),
    ) as Record<string, unknown>;
    requireMail(
      header &&
        claims &&
        typeof header === "object" &&
        typeof claims === "object" &&
        !Array.isArray(header) &&
        !Array.isArray(claims),
      "invalid_token",
    );
    requireMail(
      Number.isSafeInteger(claims.iat) &&
        Number.isSafeInteger(claims.exp) &&
        (claims.iat as number) >= 0 &&
        (claims.exp as number) > Math.floor(now / 1000),
      "invalid_token",
    );
    verifyRequestJwt(token, {
      audience: service,
      nowSecs: Math.floor(now / 1000),
    });
    requireMail(
      claims.iss === owner && claims.sub === owner,
      "permission_denied",
      "not mailbox owner",
    );
  } catch (e) {
    if ((e as { code?: string })?.code === "permission_denied") throw e;
    throw protocolError("invalid_token", "invalid mailbox owner JWT");
  }
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
  if (mailboxId !== undefined)
    requireMail(
      r.envelope.event.payload.mailbox_id === mailboxId,
      "invalid_response",
      "mailbox mismatch",
    );
  if (hash !== undefined)
    requireMail(
      r.envelope.hash === hash,
      "invalid_response",
      "card hash mismatch",
    );
}
export function validateMailDeliveryResult(
  value: unknown,
  packetId?: string,
): asserts value is MailDeliveryResult {
  validateMailSchema(value, "deliveryResult");
  if (packetId !== undefined)
    requireMail(
      (value as MailDeliveryResult).packet_id === packetId,
      "invalid_response",
      "delivery packet mismatch",
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
    r.accepted_at < r.packet.header.expires_at,
    "invalid_response",
    "relay claims acceptance after packet expiration",
  );
  if (mailboxId !== undefined)
    requireMail(
      r.packet.header.mailbox_id === mailboxId,
      "invalid_response",
      "packet mailbox mismatch",
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
    p.result.length <= limit,
    "invalid_response",
    "page exceeds limit",
  );
  let seq = 0;
  const ids = new Set<string>();
  for (const r of p.result) {
    validateMailPacketRecord(r, mailboxId);
    requireMail(
      r.seq > seq && !ids.has(r.packet_id),
      "invalid_response",
      "unordered/duplicate packets",
    );
    seq = r.seq;
    ids.add(r.packet_id);
  }
  requireMail(
    !p.next_cursor || p.result.length > 0,
    "invalid_response",
    "empty cursor page",
  );
}

interface MailboxState {
  owner: string;
  current: MailCardRecord;
  cards: MailCardRecord[];
  keys: Record<string, string>;
  last_seq: number;
  packets: MailPacketRecord[];
  tombstones: (MailDeliveryResult & { expires_at: number })[];
}
interface MailCursor {
  token: string;
  owner: string;
  mailbox_id: string;
  after_seq: number;
}
export interface MailRelaySnapshot {
  version: 1;
  service: string;
  external_nonce_store: boolean;
  mailboxes: MailboxState[];
  nonces: { actor: string; maxNonce: number; expiresAt: number }[];
  cursors: MailCursor[];
}
export interface MailRelayOptions {
  clock?: () => number;
  nonceStore?: NonceStore;
  maxPackets?: number;
  maxBytes?: number;
  snapshot?: MailRelaySnapshot;
}
/**
 * Synchronous process-local relay model. All validation precedes mutations;
 * persist snapshot atomically before emitting a successful HTTP response. An
 * injected nonce store must share the same storage transaction in a real service.
 */
export class MailRelayStore {
  private readonly boxes = new Map<string, MailboxState>();
  private readonly cursors = new Map<string, MailCursor>();
  private readonly nonceRecords = new Map<
    string,
    { maxNonce: number; expiresAt: number }
  >();
  private readonly nonces: NonceStore;
  private readonly externalNonceStore: boolean;
  private readonly clock: () => number;
  private readonly maxPackets: number;
  private readonly maxBytes: number;
  constructor(
    readonly service: string,
    options: MailRelayOptions = {},
  ) {
    validateOrigin(service);
    this.externalNonceStore = options.nonceStore !== undefined;
    this.clock = options.clock ?? Date.now;
    this.maxPackets = options.maxPackets ?? 10000;
    this.maxBytes = options.maxBytes ?? 64 * 1048576;
    requireMail(
      Number.isSafeInteger(this.maxPackets) &&
        this.maxPackets > 0 &&
        Number.isSafeInteger(this.maxBytes) &&
        this.maxBytes > 0,
      "invalid_request",
      "invalid quota",
    );
    this.nonces = options.nonceStore ?? {
      maxNonce: (actor, now) => {
        const r = this.nonceRecords.get(actor);
        return r && r.expiresAt > now ? r.maxNonce : undefined;
      },
      checkAndUpdate: (actor, nonce, now, ttl) => {
        const max = this.nonces.maxNonce(actor, now);
        requireMail(
          max === undefined || nonce > max,
          "nonce_not_greater",
          "nonce not greater",
        );
        this.nonceRecords.set(actor, { maxNonce: nonce, expiresAt: now + ttl });
        return nonce;
      },
    };
    if (options.snapshot) {
      const s = clone(options.snapshot);
      requireMail(
        typeof s.external_nonce_store === "boolean" &&
          (!s.external_nonce_store || options.nonceStore !== undefined),
        "invalid_request",
        "restore the externally shared nonce store with this snapshot",
      );
      requireMail(
        s.version === 1 && s.service === service,
        "invalid_request",
        "snapshot service mismatch",
      );
      for (const b of s.mailboxes) {
        validateMailCardRecord(b.current, b.owner);
        const id = b.current.envelope.event.payload.mailbox_id;
        requireMail(
          !this.boxes.has(id) &&
            Number.isSafeInteger(b.last_seq) &&
            b.last_seq >= 0,
          "invalid_request",
          "invalid mailbox snapshot",
        );
        for (const c of b.cards) {
          validateMailCardRecord(c, b.owner, id);
          requireMail(
            c.envelope.event.payload.routes.includes(service),
            "invalid_request",
            "snapshot route mismatch",
          );
          requireMail(
            c.envelope.event.nonce <= b.current.envelope.event.nonce,
            "invalid_request",
            "snapshot card rollback",
          );
          const p = c.envelope.event.payload;
          requireMail(
            b.keys[p.key_id] === p.public_key,
            "invalid_request",
            "snapshot key conflict",
          );
        }
        requireMail(
          b.cards.some((c) => c.envelope.hash === b.current.envelope.hash),
          "invalid_request",
          "current card missing",
        );
        for (const [key, pub] of Object.entries(b.keys)) {
          decodeMailBytes(key, 16);
          usableX25519(pub);
        }
        const tombs = new Set<string>(),
          seqs = new Set<number>();
        for (const t of b.tombstones) {
          validateMailDeliveryResult({
            packet_id: t.packet_id,
            accepted_at: t.accepted_at,
            seq: t.seq,
          });
          safeTime(t.expires_at);
          requireMail(
            t.seq <= b.last_seq && !tombs.has(t.packet_id) && !seqs.has(t.seq),
            "invalid_request",
            "invalid tombstone",
          );
          tombs.add(t.packet_id);
          seqs.add(t.seq);
        }
        const live = new Set<string>();
        for (const r of b.packets) {
          validateMailPacketRecord(r, id);
          requireMail(
            !live.has(r.packet_id),
            "invalid_request",
            "duplicate stored packet",
          );
          live.add(r.packet_id);
          const t = b.tombstones.find((t) => t.packet_id === r.packet_id);
          requireMail(
            t &&
              t.seq === r.seq &&
              t.accepted_at === r.accepted_at &&
              t.expires_at === r.packet.header.expires_at,
            "invalid_request",
            "packet missing tombstone",
          );
          const card = b.cards.find(
            (c) => c.envelope.hash === r.packet.header.card_hash,
          );
          requireMail(
            card &&
              card.envelope.event.payload.key_id === r.packet.header.key_id &&
              card.envelope.event.payload.enabled &&
              r.packet.header.expires_at <=
                card.envelope.event.payload.receive_until &&
              mailCanonicalBytes(r.packet).length <=
                card.envelope.event.payload.max_packet_bytes,
            "invalid_request",
            "packet card missing or invalid",
          );
        }
        this.boxes.set(id, b);
      }
      for (const n of s.nonces) {
        validateAgentId(n.actor);
        requireMail(
          Number.isSafeInteger(n.maxNonce) && n.maxNonce > 0,
          "invalid_request",
        );
        safeTime(n.expiresAt);
        this.nonceRecords.set(n.actor, {
          maxNonce: n.maxNonce,
          expiresAt: n.expiresAt,
        });
      }
      for (const c of s.cursors) {
        decodeMailBytes(c.token, 16);
        requireMail(
          this.boxes.get(c.mailbox_id)?.owner === c.owner &&
            Number.isSafeInteger(c.after_seq) &&
            c.after_seq >= 0,
          "invalid_request",
          "invalid cursor snapshot",
        );
        this.cursors.set(c.token, c);
      }
    }
  }
  snapshot(): MailRelaySnapshot {
    return {
      version: 1,
      service: this.service,
      external_nonce_store: this.externalNonceStore,
      mailboxes: clone([...this.boxes.values()]),
      nonces: [...this.nonceRecords].map(([actor, r]) => ({ actor, ...r })),
      cursors: clone([...this.cursors.values()]),
    };
  }
  discovery(): MailDiscovery {
    return {
      protocol: MAIL_PROTOCOL,
      service: this.service,
      endpoints: { mailboxes: this.service + "/v1/mailboxes" },
    };
  }
  maxSeenNonce(actor: string, now = this.clock()): number | undefined {
    return this.nonces.maxNonce(actor, now);
  }
  publish(card: MailboxCard, now = this.clock()): MailCardRecord {
    card = clone(card);
    safeTime(now);
    validateMailboxCard(card);
    const p = card.event.payload;
    requireMail(
      p.routes.includes(this.service),
      "permission_denied",
      "relay absent from signed routes",
    );
    const b = this.boxes.get(p.mailbox_id);
    requireMail(
      !b || b.owner === card.event.actor,
      "mailbox_conflict",
      "mailbox belongs to another owner",
    );
    const prior = b?.cards.find((x) => x.envelope.hash === card.hash);
    if (prior) return clone(prior);
    requireMail(
      !b || !b.keys[p.key_id] || b.keys[p.key_id] === p.public_key,
      "mailbox_conflict",
      "key ID reused",
    );
    if (b && card.event.nonce <= b.current.envelope.event.nonce)
      throw protocolError("nonce_not_greater", "card nonce does not advance", {
        max_nonce: b.current.envelope.event.nonce,
      });
    verifyTimestamp(card.event.created_at, now, MAIL_FUTURE_SKEW_MS);
    const max = this.nonces.maxNonce(card.event.actor, now);
    if (max !== undefined && card.event.nonce <= max)
      throw protocolError(
        "nonce_not_greater",
        "service-wide nonce does not advance",
        { max_nonce: max },
      );
    // This is the final fallible operation, after all mailbox and card checks.
    this.nonces.checkAndUpdate(
      card.event.actor,
      card.event.nonce,
      now,
      2 * MAIL_FUTURE_SKEW_MS,
    );
    const result: MailCardRecord = { envelope: card, accepted_at: now };
    if (b) {
      b.current = result;
      b.cards.push(result);
      b.keys[p.key_id] = p.public_key;
    } else
      this.boxes.set(p.mailbox_id, {
        owner: card.event.actor,
        current: result,
        cards: [result],
        keys: { [p.key_id]: p.public_key },
        last_seq: 0,
        packets: [],
        tombstones: [],
      });
    return clone(result);
  }
  card(mailboxId: string): MailCardRecord {
    decodeMailBytes(mailboxId, 16);
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
    decodeMailBytes(mailboxId, 16);
    validateMailPacket(packet);
    requireMail(
      packet.header.mailbox_id === mailboxId,
      "invalid_packet",
      "path mailbox mismatch",
    );
    const b = this.boxes.get(mailboxId);
    requireMail(b, "mailbox_unavailable");
    const id = mailPacketId(packet),
      prior = b.tombstones.find((x) => x.packet_id === id);
    if (prior)
      return {
        packet_id: prior.packet_id,
        accepted_at: prior.accepted_at,
        seq: prior.seq,
      };
    const c = b.current.envelope,
      p = c.event.payload,
      h = packet.header;
    requireMail(p.enabled, "mailbox_unavailable");
    requireMail(
      h.card_hash === c.hash && h.key_id === p.key_id && now < p.expires_at,
      "stale_card",
    );
    requireMail(now < h.expires_at, "packet_expired");
    requireMail(
      h.expires_at <= p.receive_until &&
        h.expires_at - now <= MAIL_MAX_TTL_MS + MAIL_FUTURE_SKEW_MS,
      "invalid_packet",
      "packet lifetime exceeds bound",
    );
    const size = mailCanonicalBytes(packet).length;
    requireMail(
      size <= p.max_packet_bytes,
      "payload_too_large",
      "packet exceeds card limit",
    );
    const live = b.packets.filter((x) => now < x.packet.header.expires_at);
    requireMail(
      live.length < this.maxPackets &&
        live.reduce((n, x) => n + mailCanonicalBytes(x.packet).length, 0) +
          size <=
          this.maxBytes,
      "quota_exceeded",
    );
    requireMail(
      b.last_seq < Number.MAX_SAFE_INTEGER,
      "quota_exceeded",
      "sequence exhausted",
    );
    const result: MailDeliveryResult = {
      packet_id: id,
      accepted_at: now,
      seq: b.last_seq + 1,
    };
    const record = { ...result, packet };
    b.last_seq = result.seq;
    b.packets = [...live, record];
    b.tombstones.push({ ...result, expires_at: h.expires_at });
    return clone(result);
  }
  private ownerBox(mailboxId: string, jwt: string, now: number): MailboxState {
    decodeMailBytes(mailboxId, 16);
    const b = this.boxes.get(mailboxId);
    requireMail(b, "mailbox_unavailable");
    validateMailOwnerJwt(jwt, this.service, b.owner, now);
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
      limit = options.limit ?? 100;
    requireMail(
      Number.isSafeInteger(limit) && limit >= 1 && limit <= 1000,
      "invalid_request",
      "invalid limit",
    );
    let after = 0;
    if (options.cursor !== undefined) {
      const c = this.cursors.get(options.cursor);
      requireMail(
        c && c.owner === b.owner && c.mailbox_id === mailboxId,
        "invalid_cursor",
      );
      after = c.after_seq;
    }
    const all = b.packets.filter(
        (r) => r.seq > after && now < r.packet.header.expires_at,
      ),
      result = clone(all.slice(0, limit));
    let next_cursor: string | undefined;
    if (all.length > limit) {
      next_cursor = newMailId();
      this.cursors.set(next_cursor, {
        token: next_cursor,
        owner: b.owner,
        mailbox_id: mailboxId,
        after_seq: result.at(-1)!.seq,
      });
    }
    return { result, ...(next_cursor === undefined ? {} : { next_cursor }) };
  }
  delete(
    mailboxId: string,
    packetId: string,
    jwt: string,
    now = this.clock(),
  ): void {
    const b = this.ownerBox(mailboxId, jwt, now);
    decodeMailBytes(packetId, 32);
    b.packets = b.packets.filter((r) => r.packet_id !== packetId);
  }
  prune(now = this.clock()): void {
    safeTime(now);
    for (const b of this.boxes.values()) {
      b.packets = b.packets.filter((r) => now < r.packet.header.expires_at);
      b.tombstones = b.tombstones.filter((r) => now < r.expires_at);
    }
  }
}
