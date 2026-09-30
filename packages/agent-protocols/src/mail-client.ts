/** Same-origin Mail HTTP client. Packet delivery is anonymous; read/delete require owner-bound JWTs. */
import { parseStrictJson } from "./identity.js";
import { protocolError } from "./errors.js";
import { HttpResponseError, type FetchLike } from "./http-client.js";
import { validateOrigin } from "./identity.js";
import {
  MAIL_MAX_PACKET_BYTES,
  MailCardCache,
  decodeMailBytes,
  mailCanonicalBytes,
  mailPacketId,
  validateMailboxCard,
  validateMailCardRecord,
  validateMailDeliveryResult,
  validateMailDiscovery,
  validateMailOwnerJwt,
  validateMailPacket,
  validateMailPacketList,
  type MailboxCard,
  type MailCardRecord,
  type MailDeliveryResult,
  type MailDiscovery,
  type MailPacket,
  type MailPacketList,
} from "./mail.js";
export interface MailClientOptions {
  fetch?: FetchLike;
  discovery?: MailDiscovery;
  clock?: () => number;
  maxResponseBytes?: number;
  /** Reuse and persist this cache across services and client restarts. */
  cardCache?: MailCardCache;
  /** Apply DNS/private-network policy in the supplied fetch transport too. */ allowUrl?: (
    url: string,
  ) => boolean | Promise<boolean>;
}
export class MailClient {
  readonly cardCache: MailCardCache;
  private readonly fetchImpl: FetchLike;
  private readonly base: string;
  private readonly clock: () => number;
  private readonly maxResponseBytes: number;
  constructor(
    readonly service: string,
    private readonly options: MailClientOptions = {},
  ) {
    validateOrigin(service);
    this.cardCache = options.cardCache ?? new MailCardCache();
    this.fetchImpl = options.fetch ?? fetch;
    this.clock = options.clock ?? Date.now;
    this.maxResponseBytes =
      options.maxResponseBytes ?? 128 * MAIL_MAX_PACKET_BYTES;
    if (
      !Number.isSafeInteger(this.maxResponseBytes) ||
      this.maxResponseBytes < 1
    )
      throw protocolError("invalid_request", "invalid response limit");
    if (options.discovery) validateMailDiscovery(options.discovery, service);
    this.base =
      options.discovery?.endpoints?.mailboxes ?? service + "/v1/mailboxes";
  }
  static async discover(
    service: string,
    options: MailClientOptions = {},
    card?: MailboxCard,
  ): Promise<MailClient> {
    const c = new MailClient(service, options),
      d = await c.protocol(card);
    return new MailClient(service, {
      ...options,
      discovery: d,
      cardCache: c.cardCache,
    });
  }
  async protocol(card?: MailboxCard): Promise<MailDiscovery> {
    const d = await this.request(
      this.service + "/.well-known/agent-mail",
      "GET",
      200,
    );
    validateMailDiscovery(d, this.service, card);
    return d;
  }
  async card(mailboxId: string, owner: string): Promise<MailCardRecord> {
    decodeMailBytes(mailboxId, 16);
    const r = await this.request(`${this.base}/${mailboxId}/card`, "GET", 200);
    validateMailCardRecord(r, owner, mailboxId);
    if (!r.envelope.event.payload.routes.includes(this.service))
      throw protocolError("invalid_response", "card does not authorize relay");
    // An authentic disabled/expired response must still advance rollback state.
    this.cardCache.observe(r.envelope, owner, this.clock(), false);
    return r;
  }
  async publish(card: MailboxCard): Promise<MailCardRecord> {
    card = structuredClone(card);
    validateMailboxCard(card);
    if (!card.event.payload.routes.includes(this.service))
      throw protocolError("invalid_request", "relay not in card routes");
    const r = await this.request(this.base, "POST", 200, card);
    validateMailCardRecord(
      r,
      card.event.actor,
      card.event.payload.mailbox_id,
      card.hash,
    );
    return r;
  }
  async deliver(
    packet: MailPacket,
    card: MailboxCard,
  ): Promise<MailDeliveryResult> {
    packet = structuredClone(packet);
    card = structuredClone(card);
    validateMailPacket(packet);
    validateMailboxCard(card);
    const p = card.event.payload,
      h = packet.header;
    if (
      !p.enabled ||
      !p.routes.includes(this.service) ||
      card.hash !== h.card_hash ||
      p.mailbox_id !== h.mailbox_id ||
      p.key_id !== h.key_id ||
      mailCanonicalBytes(packet).length > p.max_packet_bytes ||
      h.expires_at > p.receive_until
    )
      throw protocolError(
        "invalid_request",
        "packet/card/relay binding mismatch",
      );
    const r = await this.request(
      `${this.base}/${h.mailbox_id}/packets`,
      "POST",
      202,
      packet,
    );
    validateMailDeliveryResult(r, mailPacketId(packet));
    if (r.accepted_at >= h.expires_at)
      throw protocolError(
        "invalid_response",
        "relay claims acceptance after packet expiration",
      );
    return r;
  }
  async list(
    mailboxId: string,
    owner: string,
    jwt: string,
    options: { limit?: number; cursor?: string } = {},
  ): Promise<MailPacketList> {
    decodeMailBytes(mailboxId, 16);
    validateMailOwnerJwt(jwt, this.service, owner, this.clock());
    const limit = options.limit ?? 100;
    if (
      !Number.isSafeInteger(limit) ||
      limit < 1 ||
      limit > 1000 ||
      (options.cursor !== undefined &&
        (typeof options.cursor !== "string" || !options.cursor))
    )
      throw protocolError("invalid_request", "invalid pagination");
    const u = new URL(`${this.base}/${mailboxId}/packets`);
    u.searchParams.set("limit", String(limit));
    if (options.cursor !== undefined)
      u.searchParams.set("cursor", options.cursor);
    const r = await this.request(u.href, "GET", 200, undefined, jwt);
    validateMailPacketList(r, mailboxId, limit);
    return r;
  }
  async *pages(
    mailboxId: string,
    owner: string,
    jwt: () => string,
    limit = 100,
  ): AsyncGenerator<MailPacketList> {
    let cursor: string | undefined,
      seq = 0;
    const cursors = new Set<string>(),
      ids = new Set<string>();
    do {
      const page = await this.list(mailboxId, owner, jwt(), { limit, cursor });
      for (const r of page.result) {
        if (r.seq <= seq || ids.has(r.packet_id))
          throw protocolError(
            "invalid_response",
            "duplicate or reordered page",
          );
        seq = r.seq;
        ids.add(r.packet_id);
      }
      cursor = page.next_cursor;
      if (cursor !== undefined) {
        if (cursors.has(cursor))
          throw protocolError("invalid_response", "cursor cycle");
        cursors.add(cursor);
      }
      yield page;
    } while (cursor !== undefined);
  }
  async delete(
    mailboxId: string,
    packetId: string,
    owner: string,
    jwt: string,
  ): Promise<void> {
    decodeMailBytes(mailboxId, 16);
    decodeMailBytes(packetId, 32);
    validateMailOwnerJwt(jwt, this.service, owner, this.clock());
    await this.request(
      `${this.base}/${mailboxId}/packets/${packetId}`,
      "DELETE",
      204,
      undefined,
      jwt,
    );
  }
  private async request(
    url: string,
    method: string,
    status: number,
    body?: unknown,
    jwt?: string,
  ): Promise<unknown> {
    const target = new URL(url);
    if (
      target.origin !== this.service ||
      target.username ||
      target.password ||
      target.hash
    )
      throw protocolError("invalid_request", "unsafe Mail URL");
    if (this.options.allowUrl && !(await this.options.allowUrl(url)))
      throw protocolError(
        "permission_denied",
        "URL denied by local network policy",
      );
    const response = await this.fetchImpl(url, {
      method,
      redirect: "error",
      credentials: "omit",
      referrerPolicy: "no-referrer",
      headers: {
        accept: "application/json",
        ...(body === undefined ? {} : { "content-type": "application/json" }),
        ...(jwt === undefined ? {} : { authorization: `Bearer ${jwt}` }),
      },
      ...(body === undefined
        ? {}
        : { body: new TextDecoder().decode(mailCanonicalBytes(body)) }),
    });
    if (
      response.redirected ||
      (response.status >= 300 && response.status < 400) ||
      (response.url && response.url !== url)
    )
      throw protocolError(
        "invalid_response",
        "redirect or response URL mismatch",
      );
    const declared = response.headers.get("content-length");
    if (declared !== null && Number(declared) > this.maxResponseBytes)
      throw protocolError("invalid_response", "response too large");
    const reader = response.body?.getReader();
    const chunks: Uint8Array[] = [];
    let count = 0;
    if (reader) {
      try {
        for (;;) {
          const r = await reader.read();
          if (r.done) break;
          count += r.value.length;
          if (count > this.maxResponseBytes) {
            await reader.cancel();
            throw protocolError("invalid_response", "response too large");
          }
          chunks.push(r.value);
        }
      } finally {
        reader.releaseLock();
      }
    }
    const bytes = new Uint8Array(count);
    let at = 0;
    for (const c of chunks) {
      bytes.set(c, at);
      at += c.length;
    }
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
        bytes,
      );
    } catch {
      throw protocolError("invalid_response", "response is not UTF-8");
    }
    if (!response.ok)
      throw new HttpResponseError(
        response.status,
        text,
        response.headers.get("Max-Seen-Nonce") ?? undefined,
      );
    if (response.status !== status)
      throw protocolError(
        "invalid_response",
        `Mail response requires HTTP ${status}`,
      );
    if (status === 204) {
      if (text)
        throw protocolError(
          "invalid_response",
          "DELETE response must be empty",
        );
      return undefined;
    }
    if (
      !/^application\/json(?:\s*;|$)/i.test(
        response.headers.get("content-type") ?? "",
      )
    )
      throw protocolError(
        "invalid_response",
        "response must be application/json",
      );
    try {
      return parseStrictJson(text);
    } catch {
      throw protocolError(
        "invalid_response",
        "response violates strict I-JSON",
      );
    }
  }
}
